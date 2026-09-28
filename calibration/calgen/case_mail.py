"""Case invoice-fraud: a supplier's bank details changed by e-mail, from a
finance clerk's mailbox export and browser history.

What the case plants, by kind (the values come from the seed):

- correlation: the message that changed the bank details shows the
  supplier's own address, while its Return-Path, Reply-To, Received chain
  and DMARC result name a look-alike domain and its server;
- hard present, encoded: the new IBAN is only in a PDF attached in base64;
- hard present, deleted: the clerk's visit to the credential-phishing page,
  cleared from the browser history ("last hour") and left in the SQLite
  file's free space, its time in Chromium's 1601-based microseconds;
- misleading clues: the supplier's genuine domain and old IBAN, the
  phishing e-mail's arrival time, the invoice amount in the supplier's
  reminder, and a temporary password from the IT helpdesk;
- absent: the password the clerk typed into the phishing page (no source
  records it), and malware (the phishing carried a credential form, and
  nothing points at an infection);
- missing: what was paid to the new account and when, which needs the
  finance system's payment records;
- late: the finance system's payment-run export.

The History file is written through the host's SQLite. Its layout is the
same for the same SQLite version; the header's library-version fields are
set to fixed values so the file does not say which version wrote it.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
import sqlite3
import tempfile
from typing import Dict, List, Optional, Tuple

from .common import (
    UTC, CaseOutput, Probe, amount_pattern, at, chrome_time, fact, goal_document, human_date, iban, iban_pattern,
    ip_pattern, iso_z, minute_pattern, person, question, rx, word_pattern,
)
from .rng import Rng

CASE_ID = "invoice-fraud"

ORGS = [("Aldergrove Instruments", "aldergrove"), ("Bellmont Packaging", "bellmont"), ("Corvid Analytics", "corvid"),
        ("Duneholm Foods", "duneholm"), ("Everly Textiles", "everly")]
SUPPLIERS = [("Nordlicht Metall GmbH", "nordlicht-metall", "Nordlicht"), ("Kaskade Logistics AB", "kaskade-logistics", "Kaskade"),
             ("Pellham Components Ltd", "pellham-components", "Pellham"), ("Ostrava Casting s.r.o.", "ostrava-casting", "Ostrava"),
             ("Vireo Fluidtechnik GmbH", "vireo-fluidtechnik", "Vireo")]
BANKS = [("Fjord Direktbank", "FJDBDEFFXXX"), ("Lindwurm Privatbank", "LWPBDEMMXXX"), ("Aster Handelsbank", "ASHBDEHHXXX")]
OLD_BANKS = [("Sparkasse Oberland", "SPOBDE71XXX"), ("Rheinufer Volksbank", "RUVBDE33XXX")]
PHISH_WORDS = ["secure-owa", "mailbox-verify", "m365-portal", "outlook-auth"]
PHISH_HOSTING = ["pages-app", "web-host", "cdn-edge", "static-site"]


def _eu_offset(t: dt.datetime) -> dt.timedelta:
    """Central European time: +1, or +2 from the last Sunday of March to the last Sunday of October, 01:00 UTC."""
    def last_sunday(year: int, month: int) -> dt.datetime:
        d = dt.date(year, month + 1, 1) - dt.timedelta(days=1)
        while d.weekday() != 6:
            d -= dt.timedelta(days=1)
        return dt.datetime(d.year, d.month, d.day, 1, tzinfo=UTC)

    u = t.astimezone(UTC)
    return dt.timedelta(hours=2) if last_sunday(u.year, 3) <= u < last_sunday(u.year, 10) else dt.timedelta(hours=1)


def _local(t: dt.datetime) -> dt.datetime:
    off = _eu_offset(t)
    return t.astimezone(dt.timezone(off))


def _rfc2822(t: dt.datetime) -> str:
    lt = _local(t)
    off = lt.utcoffset() or dt.timedelta(0)
    sign = "+" if off >= dt.timedelta(0) else "-"
    mins = int(abs(off).total_seconds() // 60)
    return lt.strftime("%a, %d %b %Y %H:%M:%S ") + f"{sign}{mins // 60:02d}{mins % 60:02d}"


def _from_line(t: dt.datetime) -> str:
    u = t.astimezone(UTC)
    return u.strftime("%a %b ") + f"{u.day:2d}" + u.strftime(" %H:%M:%S %Y")


def _pdf(lines: List[str]) -> bytes:
    """A one-page PDF whose text is in an uncompressed content stream; no dates, no ids."""
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content = "BT /F1 11 Tf 14 TL 72 770 Td\n" + "".join(f"({esc(line)}) '\n" for line in lines) + "ET\n"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(content.encode('latin-1'))} >>\nstream\n{content}endstream",
    ]
    out = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{o:010d} 00000 n \n" for o in offsets).encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def _b64_lines(data: bytes) -> str:
    s = base64.b64encode(data).decode("ascii")
    return "\n".join(s[i:i + 76] for i in range(0, len(s), 76))


class _Mail:
    def __init__(self, rng: Rng, org_domain: str) -> None:
        self.rng = rng
        self.org_domain = org_domain
        self.messages: List[Tuple[dt.datetime, str]] = []

    def add(self, t: dt.datetime, *, sender: str, envelope: str, to: str, subject: str, body: str, folder: str = "Inbox",
            received: Optional[List[str]] = None, auth: Optional[str] = None, reply_to: Optional[str] = None,
            attachment: Optional[Tuple[str, str, bytes]] = None, html: bool = False) -> str:
        rng = self.rng
        mid = f"<{rng.hex(16)}.{rng.hex(8)}@{envelope.split('@')[1]}>"
        h = [f"From {envelope} {_from_line(t)}", f"Return-Path: <{envelope}>"]
        for r in received or []:
            h.append(r)
        if auth:
            h.append(f"Authentication-Results: {auth}")
        h += [f"Message-ID: {mid}", f"Date: {_rfc2822(t)}", f"From: {sender}", f"To: {to}"]
        if reply_to:
            h.append(f"Reply-To: {reply_to}")
        h += [f"Subject: {subject}", "MIME-Version: 1.0", f"X-Folder: {folder}"]
        ctype = "text/html" if html else "text/plain"
        if attachment:
            boundary = f"----=_Part_{rng.digits(6)}_{rng.digits(9)}.{rng.digits(13)}"
            name, mime, data = attachment
            h.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
            parts = [
                f"--{boundary}", f"Content-Type: {ctype}; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", body.rstrip("\n"), "",
                f"--{boundary}", f'Content-Type: {mime}; name="{name}"', "Content-Transfer-Encoding: base64",
                f'Content-Disposition: attachment; filename="{name}"', "", _b64_lines(data), "", f"--{boundary}--", "",
            ]
            text = "\n".join(h) + "\n\n" + "\n".join(parts)
        else:
            h += [f"Content-Type: {ctype}; charset=utf-8", "Content-Transfer-Encoding: 8bit"]
            text = "\n".join(h) + "\n\n" + body.rstrip("\n") + "\n\n"
        self.messages.append((t, text))
        return mid

    def mbox(self) -> bytes:
        return "".join(text for _, text in sorted(self.messages, key=lambda m: m[0])).encode("utf-8")


def _received(rng: Rng, from_host: str, from_ip: str, org_domain: str, clerk: str, t: dt.datetime) -> List[str]:
    t_mx = t - dt.timedelta(seconds=rng.between(1, 4))
    t_out = t_mx - dt.timedelta(seconds=rng.between(1, 3))
    return [
        f"Received: from mx1.{org_domain} (10.1.4.20) by mbx02.{org_domain} (10.1.4.31) with ESMTPS id {rng.hex(10).upper()};\n\t{_rfc2822(t)}",
        f"Received: from {from_host} ({from_host} [{from_ip}])\n\tby mx1.{org_domain} (Postfix) with ESMTPS id {rng.hex(10).upper()}\n\tfor <{clerk}>; {_rfc2822(t_mx)}",
        f"Received: from localhost (localhost [127.0.0.1]) by {from_host} with ESMTPSA id {rng.hex(12)};\n\t{_rfc2822(t_out)}",
    ]


def build(seed: str) -> CaseOutput:
    rng = Rng(seed, CASE_ID)
    taken: List[str] = []
    clerk_p = person(rng, taken)
    manager = person(rng, taken)
    helpdesk = person(rng, taken)
    contact = person(rng, taken)
    colleague = person(rng, taken)
    org, org_slug = rng.choice(ORGS)
    org_domain = f"{org_slug}.example"
    sup_name, sup_slug, sup_short = rng.choice(SUPPLIERS)
    sup_domain = f"{sup_slug}.example"
    typo = _typo(rng, sup_slug)
    look_domain = f"{typo}.example"
    clerk = f"{clerk_p['first'].lower()}.{clerk_p['last'].lower()}@{org_domain}"
    mgr = f"{manager['first'].lower()}.{manager['last'].lower()}@{org_domain}"
    sup_contact = f"{contact['first'].lower()}.{contact['last'].lower()}@{sup_domain}"
    phish_host = f"{rng.choice(PHISH_WORDS)}-{rng.hex(4)}.{rng.choice(PHISH_HOSTING)}.example"
    phish_ms = f"m365-notify-{rng.hex(3)}.example"
    sup_ip = f"192.0.2.{rng.between(10, 250)}"
    look_ip = f"198.51.100.{rng.between(10, 250)}"
    phish_ip = f"198.18.{rng.between(0, 255)}.{rng.between(1, 254)}"
    new_bank, new_bic = rng.choice(BANKS)
    old_bank, old_bic = rng.choice(OLD_BANKS)
    old_iban, new_iban = iban(rng), iban(rng)
    inv_old = f"{sup_short[:2].upper()}-{rng.between(24000, 25999)}"
    inv_n = int(inv_old.split("-")[1])
    inv2 = f"{sup_short[:2].upper()}-{inv_n + rng.between(40, 90)}"
    inv3 = f"{sup_short[:2].upper()}-{inv_n + rng.between(91, 140)}"
    amt_old = rng.between(900_000, 6_000_000)
    amt2 = rng.between(1_800_000, 9_900_000)
    amt3 = rng.between(700_000, 4_000_000)
    paid_total = amt2 + amt3
    temp_pw = f"{rng.choice(['Winter', 'Spring', 'Summer', 'Autumn'])}{rng.between(2025, 2026)}-{rng.digits(3)}!"

    # The BEC arrives on a Tuesday to Friday; the phishing the working day before.
    base = dt.date(2026, 2, 3) + dt.timedelta(days=7 * rng.between(0, 20) + rng.between(0, 3))
    d_bec = base
    d_phish = d_bec - dt.timedelta(days=1)
    d_run = d_bec + dt.timedelta(days=2 if d_bec.weekday() < 3 else 4)
    d_reminder = d_bec + dt.timedelta(days=9)
    while d_reminder.weekday() > 4:
        d_reminder += dt.timedelta(days=1)
    d_collect = d_reminder + dt.timedelta(days=1)
    while d_collect.weekday() > 4:
        d_collect += dt.timedelta(days=1)

    def us() -> int:
        return rng.between(0, 999999)

    def local_at(day: dt.date, hh: int, mm: int, ss: int = 0) -> dt.datetime:
        """A local wall-clock time on `day`, as a UTC instant."""
        guess = at(day, hh, mm, ss)
        return guess - _eu_offset(guess)

    def workday(day: dt.date) -> dt.date:
        while day.weekday() > 4:
            day += dt.timedelta(days=1)
        return day

    phish_mail_at = local_at(d_phish, 9, rng.between(5, 20), rng.between(0, 59))
    click_at = phish_mail_at + dt.timedelta(minutes=rng.between(12, 25), seconds=rng.between(0, 59), microseconds=us())
    submit_at = click_at + dt.timedelta(seconds=rng.between(35, 90), microseconds=us())
    clear_at = submit_at + dt.timedelta(minutes=rng.between(6, 14), seconds=rng.between(0, 59))
    bec_at = local_at(d_bec, 10, rng.between(0, 15), rng.between(0, 59))
    reply_at = bec_at + dt.timedelta(minutes=rng.between(20, 50), seconds=rng.between(0, 59))
    run_at = local_at(d_run, 14, rng.between(0, 30), rng.between(0, 59))

    # --- the mailbox ------------------------------------------------------------------------------
    m = _Mail(rng, org_domain)
    clerk_to = f"{clerk_p['full']} <{clerk}>"
    sup_from = f"{sup_name} Accounts <accounts@{sup_domain}>"
    t_inv1 = local_at(workday(d_bec - dt.timedelta(days=40)), 11, rng.between(0, 59), rng.between(0, 59))
    m.add(t_inv1, sender=sup_from, envelope=f"accounts@{sup_domain}", to=clerk_to, subject=f"Invoice {inv_old}",
          received=_received(rng, f"mail.{sup_domain}", sup_ip, org_domain, clerk, t_inv1),
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom={sup_domain}; dkim=pass header.d={sup_domain}; dmarc=pass header.from={sup_domain}",
          body=f"Dear {clerk_p['first']},\n\nplease find our invoice {inv_old} over EUR {amt_old / 100:,.2f} for your order.\n"
               f"Payment within 30 days to:\n\n  {old_bank}\n  IBAN {old_iban}\n  BIC {old_bic}\n\nKind regards,\n"
               f"{contact['full']}\nAccounts Receivable, {sup_name}\n")
    t_sched = local_at(workday(d_bec - dt.timedelta(days=33)), 9, rng.between(0, 59), rng.between(0, 59))
    m.add(t_sched, sender=f"{manager['full']} <{mgr}>", envelope=mgr, to=clerk_to, subject="Supplier payments schedule",
          body=f"Hi {clerk_p['first']},\n\nfrom next month treasury releases the supplier payment runs twice a week. Please have\n"
               f"the invoices approved in the ERP the evening before.\n\nThanks,\n{manager['first']}\n")
    t_news = local_at(workday(d_bec - dt.timedelta(days=20)), 7, rng.between(0, 59), rng.between(0, 59))
    m.add(t_news, sender="Treasury Weekly <news@treasury-weekly.example>", envelope="bounce-7731@treasury-weekly.example",
          to=clerk_to, subject="Treasury Weekly: payment fraud trends this quarter",
          received=_received(rng, "out.treasury-weekly.example", f"192.0.2.{rng.between(10, 250)}", org_domain, clerk, t_news),
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom=treasury-weekly.example; dkim=pass; dmarc=pass",
          body="This week: why supplier bank-detail changes should always be confirmed by phone, and more.\n")
    t_pw = local_at(workday(d_bec - dt.timedelta(days=12)), 8, rng.between(0, 59), rng.between(0, 59))
    m.add(t_pw, sender=f"IT Service Desk <servicedesk@{org_domain}>", envelope=f"servicedesk@{org_domain}", to=clerk_to,
          subject="Your password has been reset",
          body=f"Hello {clerk_p['first']},\n\nas requested by phone, your password has been reset. Your temporary password is:\n\n"
               f"    {temp_pw}\n\nYou will be asked to change it at your next sign-in.\n\n{helpdesk['full']}\nIT Service Desk\n")
    t_inv2 = local_at(workday(d_bec - dt.timedelta(days=9)), 10, rng.between(0, 59), rng.between(0, 59))
    m.add(t_inv2, sender=sup_from, envelope=f"accounts@{sup_domain}", to=clerk_to, subject=f"Invoice {inv2}",
          received=_received(rng, f"mail.{sup_domain}", sup_ip, org_domain, clerk, t_inv2),
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom={sup_domain}; dkim=pass header.d={sup_domain}; dmarc=pass header.from={sup_domain}",
          body=f"Dear {clerk_p['first']},\n\nplease find our invoice {inv2} over EUR {amt2 / 100:,.2f}.\nPayment within 30 days to "
               f"our usual account ({old_bank}, IBAN {old_iban}).\n\nKind regards,\n{contact['full']}\nAccounts Receivable, {sup_name}\n")
    quota_html = (f'<html><body><form action="https://{phish_host}/owa/auth" method="post"><p>Microsoft 365</p>'
                  f'<p>Your mailbox {clerk} is 99% full. Sign in to keep receiving mail.</p>'
                  f'<input type="hidden" name="u" value="{clerk}"><input type="password" name="p">'
                  f'<button>Continue</button></form></body></html>\n').encode("utf-8")
    link = f"https://{phish_host}/owa/?id={base64.urlsafe_b64encode(clerk.encode()).decode().rstrip('=')}"
    m.add(phish_mail_at, sender=f"Microsoft 365 <no-reply@{phish_ms}>", envelope=f"no-reply@{phish_ms}", to=clerk_to,
          subject="Action required: your mailbox storage is full",
          received=_received(rng, f"smtp.{phish_ms}", phish_ip, org_domain, clerk, phish_mail_at),
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom={phish_ms}; dkim=none; dmarc=none header.from={phish_ms}",
          html=True, attachment=("Mailbox_Storage_Notice.html", "text/html", quota_html),
          body=f'<html><body><p>Your mailbox has reached its storage limit.</p><p><a href="{link}">Review storage</a> '
               f'within 24 hours to avoid losing incoming messages.</p></body></html>')
    letter = _pdf([
        sup_name, "Accounts Receivable", "",
        f"To our valued customer {org}", "",
        "Notification of change of bank details", "",
        "Following our annual audit, our bank account has changed with immediate effect.",
        "Please update your records and use the account below for all open and future invoices:", "",
        f"Bank: {new_bank}", f"IBAN: {new_iban}", f"BIC: {new_bic}", "",
        "The previous account will be closed at the end of the month.", "",
        f"{contact['full']}", "Accounts Receivable",
    ])
    bec_rcv = _received(rng, f"mail.{look_domain}", look_ip, org_domain, clerk, bec_at)
    m.add(bec_at, sender=sup_from, envelope=f"billing@{look_domain}", to=clerk_to, reply_to=f"accounts@{look_domain}",
          subject=f"RE: Invoice {inv2} - updated bank details",
          received=bec_rcv,
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom={look_domain}; dkim=none (message not signed) header.d=none; "
               f"dmarc=fail action=none header.from={sup_domain}",
          attachment=(f"Bank_Details_Update_{sup_short}.pdf", "application/pdf", letter),
          body=f"Dear {clerk_p['first']},\n\nfollowing our annual audit our bank details have changed with immediate effect.\n"
               f"Please update your records using the attached letter and use the new account for invoice {inv2}\n"
               f"and all future payments.\n\nKind regards,\n{contact['full']}\nAccounts Receivable, {sup_name}\n")
    m.add(reply_at, sender=clerk_to, envelope=clerk, to=f"accounts@{look_domain}", folder="Sent Items",
          subject=f"RE: Invoice {inv2} - updated bank details",
          body=f"Dear {contact['first']},\n\nthank you, the bank details are updated. Invoice {inv2} will be paid in our next\n"
               f"payment run.\n\nBest regards,\n{clerk_p['full']}\n{org}\n")
    t_run_mail = run_at + dt.timedelta(minutes=rng.between(20, 60))
    m.add(t_run_mail, sender=f"{manager['full']} <{mgr}>", envelope=mgr, to=clerk_to, subject="Payment run done",
          body=f"Hi {clerk_p['first']},\n\ntoday's supplier payment run is released. Thanks for getting everything approved in time.\n\n{manager['first']}\n")
    t_meet = local_at(workday(d_bec + dt.timedelta(days=3)), 16, rng.between(0, 59), rng.between(0, 59))
    m.add(t_meet, sender=f"{colleague['full']} <{colleague['first'].lower()}.{colleague['last'].lower()}@{org_domain}>",
          envelope=f"{colleague['first'].lower()}.{colleague['last'].lower()}@{org_domain}", to=clerk_to, subject="Month-end close",
          body="Hi,\n\ncan we go through the month-end accruals on Monday at 10?\n\nThanks\n")
    reminder_at = local_at(d_reminder, 9, rng.between(0, 59), rng.between(0, 59))
    m.add(reminder_at, sender=f"{contact['full']} <{sup_contact}>", envelope=sup_contact, to=clerk_to,
          subject=f"Reminder: invoice {inv2} overdue",
          received=_received(rng, f"mail.{sup_domain}", sup_ip, org_domain, clerk, reminder_at),
          auth=f"mx1.{org_domain}; spf=pass smtp.mailfrom={sup_domain}; dkim=pass header.d={sup_domain}; dmarc=pass header.from={sup_domain}",
          body=f"Dear {clerk_p['first']},\n\nwe have not yet received payment for invoice {inv2} over EUR {amt2 / 100:,.2f}.\n"
               f"Could you please check? Our bank details are unchanged ({old_bank}, IBAN {old_iban}).\n\n"
               f"Kind regards,\n{contact['full']}\n{sup_name}\n")
    mbox = m.mbox()

    # --- the browser history ----------------------------------------------------------------------
    history, deleted_visits = _history(rng, org_domain, d_bec, d_collect, local_at, link, phish_host, click_at, submit_at, clear_at)

    collect_at = local_at(d_collect, 11, rng.between(0, 40))
    inputs: Dict[str, bytes] = {
        f"{clerk_p['user']}/mailbox-export.mbox": mbox,
        f"{clerk_p['user']}/browser/Default/History": history,
    }
    inputs["CASE.md"] = f"""# Intake note

Client: {org}
Requested by: {manager['full']}, Head of Finance
Received: {human_date(d_collect)}

## Background

On {human_date(d_reminder)} the supplier {sup_name} reminded {org} that invoice
{inv2} was unpaid, and said its bank details had never changed. Finance had
changed the supplier's bank details after an e-mail. The finance clerk
{clerk_p['full']} ({clerk}) handled the supplier's invoices.

## What was collected

| Item | Description | Collected by | When (UTC) |
| --- | --- | --- | --- |
| `{clerk_p['user']}/mailbox-export.mbox` | Export of the clerk's mailbox (Inbox and Sent Items), one mbox file | IT, {helpdesk['full']} | {iso_z(collect_at)} |
| `{clerk_p['user']}/browser/Default/History` | The clerk's Chromium-based browser history database, copied from the profile with the browser closed | IT, {helpdesk['full']} | {iso_z(collect_at)} |

SHA-256 of every file is in `inputs.json`.

## Notes

The clerk works in the {org} office; the workstation and the mail server keep
their clocks in local time (Central European Time) and synchronise with NTP.
""".encode("utf-8")

    late_name = "late/erp-payment-run-export.csv"
    late = {late_name: _erp_export(rng, d_run, run_at, sup_name, inv2, amt2, inv3, amt3, new_iban)}

    goal = goal_document(
        meta={"title": "Supplier bank details changed by e-mail", "summary": "A finance clerk's mailbox and browser history after a supplier payment went astray",
              "evidence": "mailbox, files", "os": "any", "toolbox": "dfir", "more_evidence": "ask"},
        goal=f"""{org} paid a supplier invoice to a bank account the supplier, {sup_name}, says is not theirs.
The finance clerk {clerk_p['full']} changed the supplier's bank details after an e-mail. IT exported the clerk's
mailbox and copied the browser's history database. Establish how the bank details came to be changed, whether
the clerk's account was compromised, what was paid, and say plainly where the evidence ends.

The evidence is under `inputs/` (read-only; call `inputs` to list it, and read `inputs.json` for the
manifest). `inputs/CASE.md` is the intake note: what was collected, when and by whom. If `SWARM.md` has an
"Evidence catalog" section, the kickoff already ran the first pass into `catalog/`; read it before running
the same commands again.""",
        objectives=["Establish how the supplier's bank details were changed and who was behind the change.",
                    "Establish whether the clerk's account was compromised, and what the fraud cost."],
        questions=[
            "The message: which e-mail led to the change of the supplier's bank details, when did it arrive (UTC), and where did it really come from (sending domain, server and address), as opposed to what it shows?",
            "The account: which bank account (IBAN, bank) did that message give, and where in the evidence is it?",
            "The clerk's credentials: did the clerk open a credential-phishing page, and if so which page and when (UTC)?",
            "The loss: how much was paid to the new account, and when?",
            "The password: which password did the clerk enter on the phishing page?",
            "Malware: which malware did the phishing e-mail install on the clerk's computer?",
            "The timeline of the events above, merged from every source and cited to `ledger/ledger.md`; the hypotheses tested; what remains uncertain and what additional evidence would resolve it.",
        ],
        existence=[],
        timeline_rows=10,
        events=8,
    )

    questions = [
        question("1", "The message that changed the bank details, its arrival, its true origin.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"'RE: Invoice {inv2} - updated bank details', {iso_z(bec_at)}: shows {sup_domain}, sent from {look_domain} (Return-Path billing@, Reply-To accounts@), via mail.{look_domain} [{look_ip}], DMARC fail."},
                 facts=[
                     fact("F1.1", "hard_present", "The look-alike domain behind the displayed supplier address.", [word_pattern(look_domain)], subkind="correlation", where="mbox headers"),
                     fact("F1.2", "present", "The sending server's address.", [ip_pattern(look_ip)]),
                     fact("F1.3", "decoy", "The supplier's genuine domain, shown in From:.", [word_pattern(sup_domain)]),
                 ]),
        question("2", "The new bank account.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{new_bank}, IBAN {new_iban}, BIC {new_bic}: only in the PDF attached in base64 to the message."},
                 facts=[
                     fact("F2.1", "hard_present", "The new IBAN, only inside the base64-encoded PDF attachment.", [iban_pattern(new_iban)], subkind="encoded", where="mbox attachment"),
                     fact("F2.2", "decoy", "The supplier's genuine IBAN, in its own e-mails.", [iban_pattern(old_iban)]),
                 ]),
        question("3", "The phishing page and when the clerk opened it.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{link} at {iso_z(click_at)}, form posted to https://{phish_host}/owa/auth at {iso_z(submit_at)}; the visits were cleared from the history at about {iso_z(clear_at)} and survive in the database's free space."},
                 facts=[
                     fact("F3.1", "hard_present", "The visit's time, only in deleted records of the history database.", [minute_pattern(click_at), minute_pattern(submit_at)], subkind="deleted", where="History, free pages"),
                     fact("F3.2", "present", "The phishing host (also in the phishing e-mail).", [word_pattern(phish_host)]),
                     fact("F3.3", "decoy", "The phishing e-mail's arrival, not the visit.", [minute_pattern(phish_mail_at)]),
                 ]),
        question("4", "How much was paid to the new account, and when.", kind="missing",
                 expected={"result": "not_determinable", "accept_results": ["not_determinable"],
                           "summary": "Not in the mailbox or the history: the payment run's records (the ERP's payment export or the bank statement) are needed."},
                 facts=[
                     fact("F4.1", "missing", "The payment is recorded only in the finance system, which was not collected."),
                     fact("F4.2", "decoy", "The invoice amount in the supplier's reminder.", [amount_pattern(amt2)]),
                 ],
                 acquisition={"accept": [rx("erp|payment (run|record|export|log)|bank statement|accounts payable|finance system|sap|treasury")]},
                 late={"item": late_name,
                       "expected": {"result": "established", "accept_results": ["established", "partial"],
                                    "summary": f"EUR {paid_total / 100:,.2f} ({inv2} EUR {amt2 / 100:,.2f} and {inv3} EUR {amt3 / 100:,.2f}) to {new_iban}, value date {d_run.isoformat()}."},
                       "facts": [fact("F4.3", "late", "The total paid to the new account.", [amount_pattern(paid_total), amount_pattern(amt3)]),
                                 fact("F4.4", "late", "The value date.", [rx(d_run.isoformat())], subkind="time")]}),
        question("5", "The password entered on the phishing page.", kind="absent",
                 expected={"result": "not_determinable", "accept_results": ["not_determinable"],
                           "summary": "Not in the evidence: a browser history records no form contents, and nothing else captured it."},
                 facts=[
                     fact("F5.1", "absent", "What was typed into the form is recorded nowhere."),
                     fact("F5.2", "decoy", "The helpdesk's temporary password from twelve days earlier.", [temp_pw]),
                 ]),
        question("6", "The malware installed.", kind="absent",
                 expected={"result": "premise_not_supported", "accept_results": ["premise_not_supported", "bounded_negative", "not_determinable"],
                           "summary": "No malware: the phishing e-mail carried a credential form (HTML) and a link; the history shows no download. Whether anything else ran on the computer is outside this evidence."},
                 facts=[
                     fact("F6.1", "absent", "Nothing in the evidence shows malware."),
                     fact("F6.2", "decoy", "The HTML attachment taken for malware.", [rx("Mailbox_Storage_Notice")]),
                 ]),
        question("7", "The timeline, the hypotheses and what remains open.", kind="present", scored=False,
                 expected={"result": "established", "accept_results": ["established", "partial"], "summary": "Not scored."}, facts=[]),
    ]

    live_urls = _live_urls(history)
    probes = [
        Probe("F1.1", "the look-alike domain is in the headers, the supplier's own in From:",
              lambda: f"Return-Path: <billing@{look_domain}>".encode() in mbox and f"From: {sup_from}".encode() in mbox),
        Probe("F2.1", "the new IBAN is only in the base64 attachment, never as text",
              lambda: new_iban.encode() not in mbox and new_iban.replace(" ", "").encode() not in mbox
              and new_iban.encode() in letter and _b64_lines(letter).encode() in mbox),
        Probe("F3.1", "the phishing visits are not in the live tables, and their bytes are in the file",
              lambda: not any(phish_host in u for u in live_urls)
              and phish_host.encode() in history and all(chrome_time(t).to_bytes(8, "big") in history for t in deleted_visits)),
        Probe("F3.2", "the phishing host is in the mailbox", lambda: phish_host.encode() in mbox),
        Probe("F4.1", "the second invoice paid to the new account is in no input, only in the late item",
              lambda: inv3.encode() not in mbox and f"{amt3 / 100:,.2f}".encode() not in mbox
              and f"{inv3},{amt3 / 100:.2f}".encode() in late[late_name] and new_iban.replace(" ", "").encode() in late[late_name]),
        Probe("F4.2", "the invoice amount is in the supplier's e-mails", lambda: f"EUR {amt2 / 100:,.2f}".encode() in mbox),
        Probe("F5.2", "the temporary password is in the mailbox", lambda: temp_pw.encode() in mbox),
        Probe("F6.1", "no executable is attached or downloaded", lambda: b"application/x-msdownload" not in mbox and b"TVqQ" not in mbox),
    ]
    context = {
        "org": org, "clerk": clerk, "supplier": {"name": sup_name, "domain": sup_domain, "lookalike": look_domain, "look_ip": look_ip},
        "iban": {"new": new_iban, "old": old_iban, "bank": new_bank}, "phishing": {"host": phish_host, "link": link},
        "invoices": {inv2: amt2, inv3: amt3}, "paid_total_cents": paid_total, "temp_password_decoy": temp_pw,
        "times": {"phish_mail": iso_z(phish_mail_at), "click": iso_z(click_at), "submit": iso_z(submit_at), "cleared": iso_z(clear_at),
                  "bec": iso_z(bec_at), "reply": iso_z(reply_at), "payment_run": iso_z(run_at), "collected": iso_z(collect_at)},
    }
    mtimes = {k: collect_at for k in inputs}
    mtimes[late_name] = collect_at + dt.timedelta(days=1)
    return CaseOutput(case_id=CASE_ID, title="Supplier bank details changed by e-mail", inputs=inputs, late=late, goal=goal,
                      questions=questions, probes=probes, context=context, mtimes=mtimes, late_for={late_name: ["4"]},
                      late_what={late_name: "The finance system's export of the supplier payment run that followed, as finance would supply it on request."})


def _typo(rng: Rng, slug: str) -> str:
    kind = rng.below(4)
    if kind == 0 and "l" in slug:
        i = slug.index("l")
        return slug[:i] + "1" + slug[i + 1:]
    if kind == 1:
        i = rng.between(2, len(slug) - 3)
        return slug[:i] + slug[i] + slug[i:]
    if kind == 2:
        return slug + "-invoices"
    i = rng.between(2, len(slug) - 3)
    return slug[:i] + slug[i + 1] + slug[i] + slug[i + 2:]


def _history(rng: Rng, org_domain: str, d_bec: dt.date, d_collect: dt.date, local_at, link: str, phish_host: str,
             click_at: dt.datetime, submit_at: dt.datetime, clear_at: dt.datetime) -> Tuple[bytes, List[dt.datetime]]:
    """A Chromium History database, with an hour of visits cleared and left in the free space."""
    sites = [
        (f"https://erp.{org_domain}/ap/invoices", "Accounts payable - Invoices"),
        (f"https://erp.{org_domain}/ap/vendors", "Accounts payable - Vendors"),
        (f"https://erp.{org_domain}/ap/payment-runs", "Accounts payable - Payment runs"),
        (f"https://intranet.{org_domain}/", "Intranet"),
        ("https://online.corporate-bank.example/business/", "Business Online Banking"),
        ("https://news.northwind.example/", "Northwind News"),
        ("https://weather.skyline.example/", "Weather"),
        ("https://outlook.office.example/mail/", "Mail - Outlook"),
    ]
    visits: List[Tuple[dt.datetime, str, str, int]] = []
    day = d_bec - dt.timedelta(days=10)
    while day <= d_collect:
        if day.weekday() < 5:
            t = local_at(day, 8, rng.between(0, 40))
            end = local_at(day, 17, rng.between(0, 30))
            while t < end:
                url, title = rng.choice(sites)
                visits.append((t, url, title, 805306368 if rng.chance(1, 2) else 805306369))
                t += dt.timedelta(minutes=rng.between(6, 55), seconds=rng.between(0, 59), microseconds=rng.between(0, 999999))
        day += dt.timedelta(days=1)
    visits.append((click_at, link, "Sign in to your account", 805306368))
    visits.append((submit_at, f"https://{phish_host}/owa/auth", "Sign in to your account", 805306375))
    visits.append((submit_at + dt.timedelta(seconds=2, microseconds=rng.between(0, 999999)), "https://outlook.office.example/mail/", "Mail - Outlook", 805306368))
    visits.sort()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "History")
        con = sqlite3.connect(path)
        con.execute("PRAGMA secure_delete=0")
        con.execute("PRAGMA journal_mode=DELETE")
        con.executescript("""
            CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
            CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
                from_visit INTEGER, external_referrer_url TEXT, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0 NOT NULL, incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,
                opener_visit INTEGER, originator_cache_guid TEXT, originator_visit_id INTEGER, originator_from_visit INTEGER,
                originator_opener_visit INTEGER, is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,
                consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL, visited_link_id INTEGER DEFAULT 0 NOT NULL,
                app_id TEXT);
            CREATE INDEX visits_url_index ON visits (url);
            CREATE INDEX visits_time_index ON visits (visit_time);
            CREATE INDEX urls_url_index ON urls (url);
            CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL,
                normalized_term LONGVARCHAR NOT NULL);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL,
                target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, danger_type INTEGER NOT NULL,
                interrupt_reason INTEGER NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
                last_access_time INTEGER NOT NULL, referrer VARCHAR NOT NULL, tab_url VARCHAR NOT NULL,
                mime_type VARCHAR(255) NOT NULL);
        """)
        con.executemany("INSERT INTO meta VALUES (?, ?)", [("mmap_status", "-1"), ("version", "70"), ("last_compatible_version", "16")])
        ids: Dict[str, int] = {}
        prev: Optional[int] = None
        for t, url, title, tr in visits:
            ct = chrome_time(t)
            if url not in ids:
                cur = con.execute("INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?, ?, 0, 0, ?, 0)",
                                  (url, title, ct))
                ids[url] = int(cur.lastrowid)
            con.execute("UPDATE urls SET visit_count = visit_count + 1, last_visit_time = ?, typed_count = typed_count + ? WHERE id = ?",
                        (ct, 1 if tr & 0xFF == 1 else 0, ids[url]))
            cur = con.execute("INSERT INTO visits(url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?, ?, ?, ?, 0, ?)",
                              (ids[url], ct, prev if tr & 0xFF == 7 else 0, tr, rng.between(1, 600) * 1_000_000))
            prev = int(cur.lastrowid)
        con.commit()
        lo, hi = chrome_time(clear_at - dt.timedelta(hours=1)), chrome_time(clear_at)
        cleared = [t for t, *_ in visits if lo <= chrome_time(t) <= hi]
        affected = [r[0] for r in con.execute("SELECT DISTINCT url FROM visits WHERE visit_time BETWEEN ? AND ?", (lo, hi))]
        # Visits first, then the counts of the pages still visited, and the
        # rows left with no visit last: nothing is written after a row is
        # freed, so its cell stays in the page's free space as a clear leaves it.
        con.execute("DELETE FROM visits WHERE visit_time BETWEEN ? AND ?", (lo, hi))
        for uid in affected:
            con.execute("UPDATE urls SET visit_count = (SELECT count(*) FROM visits WHERE url = ?), "
                        "last_visit_time = (SELECT max(visit_time) FROM visits WHERE url = ?) "
                        "WHERE id = ? AND EXISTS (SELECT 1 FROM visits WHERE url = ?)", (uid, uid, uid, uid))
        con.execute("DELETE FROM urls WHERE id NOT IN (SELECT DISTINCT url FROM visits)")
        con.commit()
        con.close()
        with open(path, "rb") as fh:
            data = bytearray(fh.read())
    # The header's library-version fields, fixed: 92-95 version-valid-for (the change counter), 96-99 the library.
    data[92:96] = data[24:28]
    data[96:100] = (3046001).to_bytes(4, "big")
    return bytes(data), cleared


def _erp_export(rng: Rng, d_run: dt.date, run_at: dt.datetime, sup_name: str, inv2: str, amt2: int, inv3: str, amt3: int,
                new_iban: str) -> bytes:
    vendors = [("Harrow Office Supply", None), ("Brightline Energy", None), ("Castor Freight", None), ("Nimbus Cleaning", None),
               ("Quarry Stone Works", None), ("Tellus Telecom", None)]
    rows = ["payment_run,value_date,vendor_id,vendor_name,invoice_no,amount_eur,currency,beneficiary_iban,status,released_by,released_at"]
    run_id = f"PR-{d_run.strftime('%Y%m%d')}-{rng.digits(2)}"
    entries = []
    for name, _ in vendors:
        entries.append((f"V{rng.digits(5)}", name, f"{rng.hex(2).upper()}-{rng.digits(5)}", rng.between(20_000, 2_500_000), iban(rng)))
    vid = f"V{rng.digits(5)}"
    entries.append((vid, sup_name, inv2, amt2, new_iban))
    entries.append((vid, sup_name, inv3, amt3, new_iban))
    entries = rng.shuffled(entries)
    for v, name, inv, amt, ib in entries:
        rows.append(f"{run_id},{d_run.isoformat()},{v},\"{name}\",{inv},{amt / 100:.2f},EUR,{ib.replace(' ', '')},released,"
                    f"treasury,{iso_z(run_at)}")
    return ("\n".join(rows) + "\n").encode("utf-8")


def _live_urls(history: bytes) -> List[str]:
    """The urls a reader of the live tables sees."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "History")
        with open(path, "wb") as fh:
            fh.write(history)
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return [r[0] for r in con.execute("SELECT url FROM urls")]
        finally:
            con.close()
