"""Case usb-departure: a USB flash drive found after a resignation, and the
logs of the workstation it was used on.

What the case plants, by kind (the values come from the seed):

- hard present, deleted: the customer export, deleted from the drive, its
  directory entry marked 0xE5 and its clusters intact;
- hard present, unallocated: the price list, gzip-compressed, deleted and its
  directory slots taken by a later file, so only its clusters remain, with
  the original name inside the gzip header;
- hard present, slack: the intended recipient, in the tail of an older
  version of notes.txt left after the file was saved shorter in place;
- hard present, secondary source: the evening session and the first
  connection, only in the rotated, compressed auth.log.2.gz and syslog.2.gz;
- correlation: the drive's volume serial number in the mount path of the
  workstation's syslog, the mount's uid, and the uid's account in auth.log;
- misleading clues: the brief's suspect, whose own drive of the same model
  appears in the logs, a colleague named in notes.txt, a file-sharing
  address written in notes.txt, and a shredder's archive on the drive;
- absent: when the customer list was first made on the source system (the
  copy's creation time is the near miss), and which wiping tool was used
  (nothing was wiped);
- missing: where the data went, which needs the web gateway's records;
- late: the web gateway's export for the workstation, which shows the
  upload and settles the missing question.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import zipfile
from typing import Dict, List, Tuple

from .common import (
    CaseOutput, Probe, at, fact, goal_document, human_date, iso_z, minute_pattern, naive_utc, person,
    question, rfc3339_us, rx, word_pattern,
)
from .deflate import gzip_bytes
from .fat import Fat16, fat_date, fat_time, lfn_slots, read_volume
from .rng import Rng

CASE_ID = "usb-departure"

ORGS = [
    ("Kestrel Fasteners", "kestrel-fasteners"), ("Norrland Hydraulics", "norrland-hydraulics"),
    ("Vantor Industrial Supply", "vantor-supply"), ("Brightwell Bearings", "brightwell-bearings"),
    ("Calder Valve Works", "calder-valve"), ("Meridian Tooling", "meridian-tooling"),
]
RECIPIENT_ORGS = ["Halvard Trading", "Pinecrest Distribution", "Oberon Supply Partners", "Greyfield Components",
                  "Tamsin & Rowe Industrial"]
SHARE_SERVICES = ["dropnest", "fileharbor", "sendcove", "boxmoth", "quicklocker", "parcelcloud", "sharewell"]
COMPANY_WORDS_A = ["Nordic", "Alpine", "Coastal", "Granite", "Summit", "Harbor", "Pioneer", "Silver", "Linden",
                   "Aurora", "Falcon", "Maple", "Orion", "Redwood", "Sterling", "Beacon"]
COMPANY_WORDS_B = ["Machining", "Logistics", "Components", "Engineering", "Fabrication", "Automation", "Robotics",
                   "Assembly", "Systems", "Metals", "Plastics", "Electrics"]
COMPANY_SUFFIX = ["GmbH", "AB", "Ltd", "BV", "Oy", "AS", "SA", "Srl"]
ARTICLES = ["hex bolt M8x40 A2", "hex nut M8 A4", "washer DIN125 M10", "threaded rod M12 1m", "socket screw M6x20",
            "anchor bolt M10x90", "rivet 4.8x12 alu", "spring washer M8", "wing nut M6", "eye bolt M10",
            "coach screw 8x80", "flange nut M8", "set screw M5x10", "dowel pin 6x30", "circlip 20mm"]

JPEG_HEAD = bytes.fromhex("ffd8ffe000104a46494600010100004800480000")


def _vsn_str(vsn: int) -> str:
    return f"{vsn >> 16:04X}-{vsn & 0xFFFF:04X}"


def _unix(t: dt.datetime) -> int:
    return int(t.timestamp())


class _Log:
    """Lines of one log family (auth or syslog), cut into weekly files at rotation."""

    def __init__(self) -> None:
        self.lines: List[Tuple[dt.datetime, int, str]] = []
        self._n = 0

    def add(self, t: dt.datetime, text: str) -> None:
        self._n += 1
        self.lines.append((t, self._n, text))

    def between(self, a: dt.datetime, b: dt.datetime) -> List[Tuple[dt.datetime, str]]:
        return [(t, s) for t, _, s in sorted(self.lines) if a <= t < b]


def build(seed: str) -> CaseOutput:
    rng = Rng(seed, CASE_ID)
    taken: List[str] = []
    suspect = person(rng, taken)
    colleague = person(rng, taken)
    named = person(rng, taken)
    recipient = person(rng, taken)
    hr = person(rng, taken)
    it_person = person(rng, taken)
    examiner = person(rng, taken)
    org, org_slug = rng.choice(ORGS)
    org_domain = f"{org_slug}.example"
    recipient_org = rng.choice(RECIPIENT_ORGS)
    decoy_service, true_service = rng.sample(SHARE_SERVICES, 2)
    decoy_host = f"{decoy_service}.example"
    true_host = f"up.{true_service}.example"
    share_token = rng.hex(12)
    host = f"ws-{rng.between(3, 41):02d}"
    ws_ip = f"10.{rng.between(10, 40)}.{rng.between(1, 9)}.{rng.between(20, 220)}"
    admin_ip = f"10.{rng.between(41, 60)}.0.{rng.between(5, 30)}"
    gw_ip = ws_ip.rsplit(".", 1)[0] + ".1"
    uid = {suspect["user"]: 1001, colleague["user"]: 1002, "itadmin": 1000}

    d0 = dt.date(2026, 1, 5) + dt.timedelta(days=7 * rng.between(0, 20))  # a Monday
    w1, w2, w3 = d0, d0 + dt.timedelta(days=7), d0 + dt.timedelta(days=14)
    copy_day = w1 + dt.timedelta(days=1)
    cleanup_day = w3 + dt.timedelta(days=2)
    last_day = w3 + dt.timedelta(days=3)
    found_day = w3 + dt.timedelta(days=4)
    handover_day = w3 + dt.timedelta(days=4)
    year = d0.year
    quarter = (d0.month - 1) // 3 + 1
    format_day = d0 - dt.timedelta(days=rng.between(190, 260))
    photos_day = format_day + dt.timedelta(days=rng.between(20, 60))
    photos_gone = photos_day + dt.timedelta(days=rng.between(10, 40))

    vsn = rng.u64() & 0xFFFFFFFF
    vsn_other = rng.u64() & 0xFFFFFFFF
    serial = rng.hex(24).upper()
    serial_other = rng.hex(24).upper()

    # --- the copy session and the cleanup session, to the second -----------------------------
    b_login = at(copy_day, 18, rng.between(36, 41), rng.between(0, 59), rng.between(0, 999999))
    plug1 = b_login + dt.timedelta(minutes=4, seconds=rng.between(0, 50))
    mount1 = plug1 + dt.timedelta(seconds=2, microseconds=rng.between(0, 999999))
    t_csv = mount1 + dt.timedelta(minutes=1, seconds=rng.between(30, 50), microseconds=rng.between(0, 999999))
    t_notes = t_csv + dt.timedelta(minutes=2, seconds=rng.between(0, 30), microseconds=rng.between(0, 999999))
    t_gz = t_notes + dt.timedelta(seconds=rng.between(40, 80), microseconds=rng.between(0, 999999))
    t_gz_deleted = t_gz + dt.timedelta(minutes=2, seconds=rng.between(0, 40))
    unmount1 = t_gz_deleted + dt.timedelta(minutes=1, seconds=rng.between(10, 50))
    upload1 = unmount1 + dt.timedelta(minutes=rng.between(12, 16), seconds=rng.between(0, 59))
    upload2 = upload1 + dt.timedelta(minutes=1, seconds=rng.between(5, 50))
    b_logout = upload2 + dt.timedelta(minutes=rng.between(6, 9), seconds=rng.between(0, 59))

    a_lunch_out = at(cleanup_day, 12, rng.between(33, 44), rng.between(0, 59))
    b2_login = at(cleanup_day, 13, rng.between(0, 3), rng.between(0, 59))
    plug2 = b2_login + dt.timedelta(minutes=2, seconds=rng.between(0, 40))
    mount2 = plug2 + dt.timedelta(seconds=2, microseconds=rng.between(0, 999999))
    t_zip = mount2 + dt.timedelta(minutes=1, seconds=rng.between(10, 40), microseconds=rng.between(0, 999999))
    blocked = t_zip + dt.timedelta(minutes=1, seconds=rng.between(10, 40))
    t_csv_deleted = t_zip + dt.timedelta(minutes=3, seconds=rng.between(0, 40))
    t_rewrite = t_csv_deleted + dt.timedelta(minutes=2, seconds=rng.between(0, 30))
    unmount2 = t_rewrite + dt.timedelta(minutes=2, seconds=rng.between(10, 50))
    b2_logout = unmount2 + dt.timedelta(minutes=rng.between(5, 8), seconds=rng.between(0, 59))
    a_back = at(cleanup_day, 14, rng.between(2, 9), rng.between(0, 59))

    other_plugs = [
        at(w2 + dt.timedelta(days=3), 10, rng.between(10, 20), rng.between(0, 59)),
        at(w3 + dt.timedelta(days=1), 9, rng.between(45, 55), rng.between(0, 59)),
    ]

    # --- the files ------------------------------------------------------------------------------
    csv_src_mtime = at(copy_day, 16, rng.between(0, 9), rng.between(0, 59))
    csv_name = f"{org_slug.split('-')[0]}_customers_{year}{d0.month:02d}.csv"
    rows = ["customer_id;company;contact;email;phone;segment;annual_revenue_eur"]
    n_rows = rng.between(180, 320)
    for i in range(n_rows):
        co = f"{rng.choice(COMPANY_WORDS_A)} {rng.choice(COMPANY_WORDS_B)} {rng.choice(COMPANY_SUFFIX)}"
        first, last = rng.choice(_FIRSTS), rng.choice(_LASTS)
        slug = co.split()[0].lower() + co.split()[1].lower()[:4]
        rows.append(";".join([
            f"C-{10000 + i * 7 + rng.between(0, 6)}", co, f"{first} {last}", f"{first.lower()}.{last.lower()}@{slug}.example",
            f"+44 20 7946 0{rng.digits(3)}", rng.choice(["A", "A", "B", "B", "B", "C"]), str(rng.between(40, 9000) * 1000),
        ]))
    csv_bytes = ("\n".join(rows) + "\n").encode("utf-8")

    doc_id = f"PL-{year}-{rng.digits(4)}"
    pl_src_mtime = at(w1, 11, rng.between(0, 59), rng.between(0, 59))
    price_rows = [f"# {doc_id} {org} internal price list {year} - do not distribute",
                  "article_no;description;list_price_eur;discount_group"]
    for i in range(rng.between(260, 420)):
        price_rows.append(f"{rng.between(100000, 999999)};{rng.choice(ARTICLES)};{rng.between(3, 9000) / 100:.2f};"
                          f"{rng.choice(['D1', 'D2', 'D3', 'D4'])}")
    pricelist = ("\n".join(price_rows) + "\n").encode("utf-8")
    pl_inner = f"pricelist_{year}_final.csv"
    gz_name = pl_inner + ".gz"
    gz_bytes = gzip_bytes(pricelist, name=pl_inner, mtime=_unix(pl_src_mtime))

    q_next = quarter % 4 + 1
    notes_old = (
        f"todo before {last_day.day:02d}.{last_day.month:02d}.\n"
        f"- export customer list from CRM - done\n"
        f"- price list {year} final - done\n"
        f"- ask {named['full']} about the Q{q_next} targets\n"
        f"- upload the rest to https://{decoy_host}/s/{share_token}\n"
        f"- hand over the stick to {recipient['full']} ({recipient_org}) on Friday "
        f"{handover_day.day:02d}.{handover_day.month:02d}.\n"
        f"- clear the stick afterwards\n"
    ).encode("utf-8")
    notes_new = (
        f"todo\n"
        f"- ask {named['full']} about the Q{q_next} targets\n"
        f"- upload the rest to https://{decoy_host}/s/{share_token}\n"
        f"- clear the stick\n"
    ).encode("utf-8")
    if len(notes_new) > notes_old.index(b"- hand over"):
        raise AssertionError("the recipient's line must lie past the new end of notes.txt")
    zip_name = "ShredPro_Portable_v3.2_x64.zip"
    zip_mtime = at(w3 - dt.timedelta(days=rng.between(20, 60)), 21, rng.between(0, 59), rng.between(0, 59))
    zip_bytes = _shredder_zip(naive_utc(zip_mtime))

    # --- the drive ------------------------------------------------------------------------------
    fs = Fat16(volume_sectors=16384, sectors_per_cluster=2, part_start=2048, vsn=vsn, label=None,
               disk_signature=rng.u64() & 0xFFFFFFFF)
    t_dcim = at(photos_day, 15, rng.between(0, 59), rng.between(0, 59))
    dcim = fs.add_dir(None, "DCIM", created=t_dcim)
    photo_base = rng.between(2600, 3400)
    photos = []
    hint = photo_base
    for k in range(3):
        size = rng.between(38, 64) * 1024 + rng.between(0, 1023)
        body = JPEG_HEAD + rng.bytes(size - len(JPEG_HEAD) - 2) + b"\xff\xd9"
        t_photo = t_dcim + dt.timedelta(minutes=5 * k + rng.between(0, 4), seconds=rng.between(0, 59))
        run = fs.alloc_next(fs.clusters_for(len(body)), hint)
        hint = run[-1] + 1
        photos.append(fs.add_file(dcim, f"IMG_{4100 + rng.between(0, 800) + 17 * k:04d}.JPG", body, run,
                                  created=t_photo, modified=t_photo, accessed=photos_day))
    for p in photos:
        fs.delete(p)

    csv_e = fs.add_file(None, csv_name, csv_bytes, fs.alloc_next(fs.clusters_for(len(csv_bytes)), 3),
                        created=t_csv, modified=csv_src_mtime, accessed=copy_day)
    notes_e = fs.add_file(None, "notes.txt", notes_old, fs.alloc_next(1, csv_e.clusters[-1] + 1),
                          created=t_notes, modified=t_notes, accessed=copy_day)
    gz_e = fs.add_file(None, gz_name, gz_bytes, fs.alloc_next(fs.clusters_for(len(gz_bytes)), notes_e.clusters[-1] + 1),
                       created=t_gz, modified=pl_src_mtime, accessed=copy_day)
    fs.delete(gz_e)
    if len(gz_e.slots) != lfn_slots(zip_name):
        raise AssertionError("the shredder archive must take exactly the price list's directory slots")
    zip_run = fs.alloc_next(fs.clusters_for(len(zip_bytes)), gz_e.clusters[-1] + 1 + rng.between(1, 6))
    zip_e = fs.add_file(None, zip_name, zip_bytes, zip_run, created=t_zip, modified=zip_mtime, accessed=cleanup_day,
                        slots=gz_e.slots)
    fs.delete(csv_e)
    fs.rewrite(notes_e, notes_new, modified=t_rewrite, accessed=cleanup_day)
    image = fs.image()
    sectors = len(image) // 512

    # --- the workstation's logs -----------------------------------------------------------------
    auth, sysl = _Log(), _Log()
    pid = [rng.between(1400, 2100)]

    def next_pid(step: int = 40) -> int:
        pid[0] += rng.between(3, step)
        return pid[0]

    start = at(w1, 0, 0, 0)
    export_at = at(found_day, 10, rng.between(2, 9), rng.between(0, 59))
    logind = rng.between(700, 760)
    udisks = rng.between(1000, 1100)
    nm = rng.between(780, 820)
    session = [rng.between(40, 60)]
    usb_dev = [rng.between(3, 6)]

    def us() -> int:
        return rng.between(0, 999999)

    day = w1
    while at(day, 0, 0) < export_at:
        for hh in range(24):
            t = at(day, hh, 17, 1, us())
            if t >= export_at:
                break
            p = next_pid(30)
            auth.add(t, f"CRON[{p}]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)")
            sysl.add(t + dt.timedelta(microseconds=900), f"CRON[{p}]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)")
            auth.add(t + dt.timedelta(microseconds=2500), f"CRON[{p}]: pam_unix(cron:session): session closed for user root")
        t = at(day, 6, 25, 1, us())
        if t < export_at:
            p = next_pid(30)
            sysl.add(t, f"CRON[{p}]: (root) CMD (test -x /usr/sbin/anacron || {{ cd / && run-parts --report /etc/cron.daily; }})")
            sysl.add(at(day, 6, rng.between(30, 50), rng.between(0, 59), us()), "systemd[1]: Starting apt-daily-upgrade.service - Daily apt upgrade and clean activities...")
            sysl.add(at(day, 6, 52, rng.between(0, 59), us()), "systemd[1]: apt-daily-upgrade.service: Deactivated successfully.")
        if day.weekday() < 5 and not (day == found_day):
            t_dhcp = at(day, 8, rng.between(5, 15), rng.between(0, 59), us())
            sysl.add(t_dhcp, f"NetworkManager[{nm}]: <info>  [{_unix(t_dhcp)}.{rng.between(1000, 9999)}] dhcp4 (enp0s31f6): state changed new lease, address={ws_ip}")
            login = at(day, 8, rng.between(20, 45), rng.between(0, 59), us())
            if day == last_day:
                logout = at(day, 16, rng.between(5, 15), rng.between(0, 59), us())
            else:
                logout = at(day, 17, rng.between(2, 45), rng.between(0, 59), us())
            spans = [(login, logout)]
            if day == cleanup_day:
                spans = [(login, a_lunch_out), (a_back, logout)]
            for li, lo in spans:
                _session(auth, li, lo, suspect["user"], uid[suspect["user"]], session, logind, rng)
        day += dt.timedelta(days=1)

    _session(auth, b_login, b_logout, colleague["user"], uid[colleague["user"]], session, logind, rng)
    _session(auth, b2_login, b2_logout, colleague["user"], uid[colleague["user"]], session, logind, rng)

    ssh_day = w2 + dt.timedelta(days=2)
    s_in = at(ssh_day, 11, rng.between(0, 5), rng.between(0, 59), us())
    sp = next_pid(60)
    auth.add(s_in, f"sshd[{sp}]: Accepted publickey for itadmin from {admin_ip} port {rng.between(40000, 60000)} ssh2: ED25519 SHA256:{rng.hex(43)}")
    auth.add(s_in + dt.timedelta(milliseconds=40), f"sshd[{sp}]: pam_unix(sshd:session): session opened for user itadmin(uid=1000) by itadmin(uid=0)")
    auth.add(s_in + dt.timedelta(milliseconds=90), f"systemd-logind[{logind}]: New session {session[0]} of user itadmin.")
    s_no = session[0]
    session[0] += 1
    for k, cmd in enumerate(["/usr/bin/apt update", "/usr/bin/apt -y upgrade", "/usr/bin/systemctl restart cups"]):
        tk = s_in + dt.timedelta(minutes=1 + 4 * k, seconds=rng.between(0, 59))
        auth.add(tk, f"sudo: itadmin : TTY=pts/0 ; PWD=/home/itadmin ; USER=root ; COMMAND={cmd}")
        auth.add(tk + dt.timedelta(milliseconds=5), "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by itadmin(uid=1000)")
        auth.add(tk + dt.timedelta(seconds=rng.between(3, 90)), "sudo: pam_unix(sudo:session): session closed for user root")
    s_out = s_in + dt.timedelta(minutes=rng.between(16, 22), seconds=rng.between(0, 59))
    auth.add(s_out, f"sshd[{sp}]: pam_unix(sshd:session): session closed for user itadmin")
    auth.add(s_out + dt.timedelta(milliseconds=30), f"systemd-logind[{logind}]: Removed session {s_no}.")

    def plug_in(t: dt.datetime, dev_serial: str, blocks: int, user: str, vol: int) -> dt.datetime:
        usb_dev[0] += 1
        n = usb_dev[0]
        lines = [
            f"usb 1-2: new high-speed USB device number {n} using xhci_hcd",
            "usb 1-2: New USB device found, idVendor=0951, idProduct=1666, bcdDevice= 1.10",
            "usb 1-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3",
            "usb 1-2: Product: DataTraveler 3.0",
            "usb 1-2: Manufacturer: Kingston",
            f"usb 1-2: SerialNumber: {dev_serial}",
            "usb-storage 1-2:1.0: USB Mass Storage device detected",
            "scsi host6: usb-storage 1-2:1.0",
            "scsi 6:0:0:0: Direct-Access     Kingston DataTraveler 3.0 PMAP PQ: 0 ANSI: 6",
            f"sd 6:0:0:0: [sdb] {blocks} 512-byte logical blocks: ({_size_text(blocks)})",
            "sd 6:0:0:0: [sdb] Write Protect is off",
            " sdb: sdb1",
            "sd 6:0:0:0: [sdb] Attached SCSI removable disk",
        ]
        tt = t
        for s in lines:
            sysl.add(tt, f"kernel: {s}")
            tt += dt.timedelta(microseconds=rng.between(900, 250000))
        mt = tt + dt.timedelta(seconds=1, microseconds=rng.between(0, 999999))
        sysl.add(mt, f"udisksd[{udisks}]: Mounted /dev/sdb1 at /media/{user}/{_vsn_str(vol)} on behalf of uid {uid[user]}")
        return mt

    def plug_out(t: dt.datetime, user: str) -> None:
        sysl.add(t, f"udisksd[{udisks}]: Unmounted /dev/sdb1 on behalf of uid {uid[user]}")
        sysl.add(t + dt.timedelta(seconds=rng.between(3, 20), microseconds=rng.between(0, 999999)),
                 f"kernel: usb 1-2: USB disconnect, device number {usb_dev[0]}")

    m = plug_in(plug1, serial, sectors, colleague["user"], vsn)
    mount1 = m
    plug_out(unmount1, colleague["user"])
    other_mounts = []
    for t in other_plugs:
        mo = plug_in(t, serial_other, 15133248, suspect["user"], vsn_other)
        other_mounts.append(mo)
        plug_out(mo + dt.timedelta(minutes=rng.between(8, 25), seconds=rng.between(0, 59), microseconds=rng.between(0, 999999) - mo.microsecond), suspect["user"])
    phone = at(w2, 12, rng.between(20, 40), rng.between(0, 59))
    usb_dev[0] += 1
    for k, s in enumerate([f"usb 1-3: new high-speed USB device number {usb_dev[0]} using xhci_hcd",
                           "usb 1-3: New USB device found, idVendor=05ac, idProduct=12a8, bcdDevice= 8.01",
                           "usb 1-3: Product: iPhone", "usb 1-3: Manufacturer: Apple Inc.",
                           f"usb 1-3: SerialNumber: {rng.hex(40)}"]):
        sysl.add(phone + dt.timedelta(milliseconds=120 * k), f"kernel: {s}")
    sysl.add(phone + dt.timedelta(minutes=rng.between(30, 90)), f"kernel: usb 1-3: USB disconnect, device number {usb_dev[0]}")
    m2 = plug_in(plug2, serial, sectors, colleague["user"], vsn)
    mount2 = m2
    plug_out(unmount2, colleague["user"])

    rot2 = at(w2, 0, 0, 1, us())
    rot3 = at(w3, 0, 0, 1, us())
    for t in (rot2, rot3):
        sysl.add(t, f'rsyslogd: [origin software="rsyslogd" swVersion="8.2312.0" x-pid="{rng.between(800, 900)}" '
                    f'x-info="https://www.rsyslog.com"] rsyslogd was HUPed')

    def render(log: _Log, a: dt.datetime, b: dt.datetime) -> bytes:
        return "".join(f"{rfc3339_us(t)} {host} {s}\n" for t, s in log.between(a, b)).encode("utf-8")

    auth_w1, auth_w2, auth_w3 = render(auth, start, rot2), render(auth, rot2, rot3), render(auth, rot3, export_at)
    sys_w1, sys_w2, sys_w3 = render(sysl, start, rot2), render(sysl, rot2, rot3), render(sysl, rot3, export_at)
    last1 = max(t for t, _ in auth.between(start, rot2))
    last1s = max(t for t, _ in sysl.between(start, rot2))

    inputs: Dict[str, bytes] = {
        "usb.dd": image,
        f"{host}/var/log/auth.log": auth_w3,
        f"{host}/var/log/auth.log.1": auth_w2,
        f"{host}/var/log/auth.log.2.gz": gzip_bytes(auth_w1, name="auth.log.2", mtime=_unix(last1)),
        f"{host}/var/log/syslog": sys_w3,
        f"{host}/var/log/syslog.1": sys_w2,
        f"{host}/var/log/syslog.2.gz": gzip_bytes(sys_w1, name="syslog.2", mtime=_unix(last1s)),
    }
    image_sha = hashlib.sha256(image).hexdigest()
    imaged_at = at(found_day, 11, rng.between(10, 40), 0)
    case_md = f"""# Intake note

Client: {org}
Requested by: {hr['full']}, Human Resources
Received: {human_date(found_day)}

## Background

{suspect['full']} (sales; account `{suspect['user']}` on the sales office
workstation `{host}`) resigned; the last working day was {human_date(last_day)}.
On the morning of {human_date(found_day)} HR found a USB flash drive in the
drawer of {suspect['first']}'s desk and asked the lab to establish whether
company data was copied and taken out of the company.

## What was collected

| Item | Description | Collected by | When (UTC) | SHA-256 |
| --- | --- | --- | --- | --- |
| `usb.dd` | Raw image of the USB flash drive (Kingston DataTraveler 3.0, USB serial {serial}), taken through a hardware write blocker | {examiner['full']} | {iso_z(imaged_at)} | `{image_sha}` |
| `{host}/var/log/` | `auth.log`, `auth.log.1`, `auth.log.2.gz`, `syslog`, `syslog.1`, `syslog.2.gz`, exported from `{host}` by IT | {it_person['full']} | {iso_z(export_at)} | per file in `inputs.json` |

## Notes

`{host}` runs Ubuntu 24.04 in the open-plan sales office. Its clock is UTC,
synchronised by NTP. It was {suspect['first']}'s assigned workstation.
""".encode("utf-8")
    inputs["CASE.md"] = case_md

    # --- the late item: the web gateway's export for the workstation ----------------------------
    late_name = f"late/swg-export-{host}.csv"
    swg = _gateway_export(rng, ws_ip, suspect["user"], colleague["user"], org_domain, start, export_at, auth,
                          suspect["user"], [(upload1, len(csv_bytes)), (upload2, len(gz_bytes))], true_host, blocked,
                          decoy_host, share_token, b_login, b_logout)
    late = {late_name: swg}

    # --- the goal -------------------------------------------------------------------------------
    goal = goal_document(
        meta={
            "title": "USB drive after a resignation",
            "summary": "A USB flash drive image and a Linux workstation's logs; what was copied, by whom, and where it went",
            "evidence": "disk-image, logs",
            "os": "linux",
            "toolbox": "dfir",
            "more_evidence": "ask",
        },
        goal=f"""{org} asks the lab to examine a USB flash drive and the logs of the sales office workstation
`{host}` after {suspect['full']} resigned. HR found the drive in {suspect['first']}'s desk drawer; the concern is
that customer and pricing data left the company before the last working day. Establish what the evidence
shows about the drive, the data on it, who put it there and where it went, and say plainly where the
evidence ends.

The evidence is under `inputs/` (read-only; call `inputs` to list it, and read `inputs.json` for the
manifest). `inputs/CASE.md` is the intake note: what was collected, when, by whom, with the acquisition
hash. If `SWARM.md` has an "Evidence catalog" section, the kickoff already ran the first pass into
`catalog/`; read it before running the same commands again.""",
        objectives=[
            "Establish what company data was placed on the drive, when, and by which account.",
            "Establish whether, how and where the data left the company.",
        ],
        questions=[
            f"The drive: its partitioning and file system, its volume serial number, and every time the evidence shows it connected to `{host}` (UTC), with the account on whose behalf it was mounted each time.",
            "The data: every company file the drive holds or has held, with names, sizes, times and what each contains (the kind of data and a record count, not the records).",
            f"The account: which `{host}` account copied the company files to the drive, in which session (login and logout, UTC), and how that is established.",
            "The destination: was the data sent outside the company (e-mail, web upload, file sharing), and if so to which service or host, when, and by which account?",
            "The recipient: is there any indication of whom the data was intended for? Name the person or organisation and where the indication is.",
            "The origin: when was the customer list first created on the company system it came from?",
            "The cleanup: which wiping or anti-forensic tool was used on the drive, and what did it remove?",
            "The timeline of the events above, merged from every source and cited to `ledger/ledger.md`; the hypotheses tested; what remains uncertain and what additional evidence would resolve it.",
        ],
        existence=[],
        timeline_rows=10,
        events=8,
        # What the brief above states as given, and nothing a question asks: who
        # copied, when, where the data went and whose drive it is are the questions'.
        premises=[
            f"`{host}` is {org}'s sales office workstation; the evidence is a USB flash drive and that workstation's logs. [scope: entities {host}, the USB flash drive]",
            f"{suspect['full']} resigned from {org}. [scope: entities {suspect['full']}]",
            f"HR found the drive in {suspect['first']}'s desk drawer. [scope: entities the USB flash drive, {suspect['full']}]",
        ],
        # What each question takes as happened, from its own words, whatever the
        # truth: which account copied (3), when the list was first created (6), which
        # tool was used (7). Questions 1, 2, 4 and 5 ask whether, or ask for what the
        # evidence shows, and presume nothing; 8 asks for the timeline.
        presumes={
            3: f"Company files were copied to the drive by an account of `{host}`.",
            6: "The customer list was first created on a company system it came from.",
            7: "A wiping or anti-forensic tool was used on the drive.",
        },
    )

    # --- the truth ------------------------------------------------------------------------------
    vs = _vsn_str(vsn)
    vs_other = _vsn_str(vsn_other)
    csv_stem = csv_name[:-4]
    questions = [
        question("1", "The drive: partitioning, file system, volume serial number, every connection to the workstation, and the mounting account.",
                 kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"MBR, one FAT16 partition at sector 2048, volume serial {vs}; connected {iso_z(mount1)} and {iso_z(mount2)}, both mounted on behalf of uid {uid[colleague['user']]} ({colleague['user']})."},
                 facts=[
                     fact("F1.1", "present", "The volume serial number.", [rx(f"{vs[:4]}-?{vs[5:]}"), rx(f"0x{vsn:08x}")], where="usb.dd boot sector"),
                     fact("F1.2", "hard_present", "The first connection, on the evening of the copy, recorded only in the rotated, compressed syslog.", [minute_pattern(mount1)], subkind="secondary", where="syslog.2.gz"),
                     fact("F1.3", "present", "The later connection, matched by the volume serial in the mount path.", [minute_pattern(mount2)], subkind="correlation", where="syslog"),
                     fact("F1.4", "decoy", "The suspect's own drive of the same model and vendor, with another volume serial and USB serial, connected on other days.", [rx(f"{vs_other[:4]}-?{vs_other[5:]}")] + [minute_pattern(t) for t in other_mounts]),
                 ]),
        question("2", "The company files the drive holds or held, including deleted ones.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{csv_name} (deleted, {len(csv_bytes)} bytes, {n_rows} records, recoverable), {gz_name} (deleted, its directory slots reused; only its clusters remain, gzip with the name {pl_inner} inside), notes.txt, {zip_name}."},
                 facts=[
                     fact("F2.1", "hard_present", "The customer export, deleted from the drive and recoverable from its 0xE5 directory entry.", [word_pattern(csv_stem)], subkind="deleted", where=f"usb.dd root directory, clusters {csv_e.clusters[0]}-{csv_e.clusters[-1]}"),
                     fact("F2.2", "hard_present", "The price list: a gzip stream in unallocated clusters, no directory entry pointing at it, its original name and a document id inside.", [word_pattern(pl_inner[:-4]), word_pattern(doc_id)], subkind="unallocated", where=f"usb.dd clusters {gz_e.clusters[0]}-{gz_e.clusters[-1]}"),
                     fact("F2.3", "present", "notes.txt, allocated.", [word_pattern("notes.txt")]),
                 ]),
        question("3", "The account that copied the files, and its session.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{colleague['user']} (uid {uid[colleague['user']]}), gdm session {iso_z(b_login)} to {iso_z(b_logout)}: the FAT creation times fall in it, the mount was on behalf of uid {uid[colleague['user']]}, and {suspect['user']} had logged out."},
                 facts=[
                     fact("F3.1", "hard_present", "The colleague's account, from the rotated auth log's session and the mount's uid.", [word_pattern(colleague["user"])], subkind="correlation", where="auth.log.2.gz, syslog.2.gz, usb.dd"),
                     fact("F3.2", "hard_present", "The session's login time.", [minute_pattern(b_login)], subkind="secondary", where="auth.log.2.gz"),
                     fact("F3.3", "decoy", "The suspect named in the brief, whose sessions end before the copy.", [word_pattern(suspect["user"]), word_pattern(suspect["last"])]),
                 ]),
        question("4", "Whether and where the data was sent outside the company.", kind="missing",
                 expected={"result": "not_determinable", "accept_results": ["not_determinable"],
                           "summary": "Not determinable from the drive and the workstation's auth and syslog: an upload leaves no trace there. The web gateway's (or mail gateway's) records for the workstation are needed."},
                 facts=[
                     fact("F4.1", "missing", "An outbound transfer is recorded only by the web gateway, which was not collected."),
                     fact("F4.2", "decoy", "The file-sharing link written in notes.txt: an intention, not a record of a transfer.", [word_pattern(decoy_host)]),
                 ],
                 acquisition={"accept": [rx("proxy|gateway|web filter|firewall|swg|netflow|mail (server|gateway|log)|dlp|outbound")]},
                 late={"item": late_name,
                       "expected": {"result": "established", "accept_results": ["established", "partial"],
                                    "summary": f"Uploaded to {true_host} by {colleague['user']} at {iso_z(upload1)} and {iso_z(upload2)}; an attempt to reach {decoy_host} at {iso_z(blocked)} was blocked."},
                       "facts": [
                           fact("F4.3", "late", "The host the files were uploaded to.", [word_pattern(true_host), word_pattern(f"{true_service}.example")]),
                           fact("F4.4", "late", "The first upload's time.", [minute_pattern(upload1)], subkind="time"),
                       ]}),
        question("5", "Whom the data was intended for.", kind="present",
                 expected={"result": "established", "accept_results": ["established", "partial"],
                           "summary": f"{recipient['full']} ({recipient_org}): in the slack of notes.txt, the tail of the version written at {iso_z(t_notes)}."},
                 facts=[
                     fact("F5.1", "hard_present", "The recipient, in file slack only.", [word_pattern(recipient["last"]), word_pattern(recipient_org)], subkind="slack", where=f"usb.dd cluster {notes_e.clusters[0]}, after byte {len(notes_new)}"),
                     fact("F5.2", "decoy", "A colleague named in the live notes.txt.", [word_pattern(named["last"])]),
                 ]),
        question("6", "When the customer list was first created on the source system.", kind="absent",
                 expected={"result": "not_determinable", "accept_results": ["not_determinable", "partial"],
                           "summary": f"Not in the evidence. The copy's creation time ({iso_z(t_csv)}) records the copy; its modification time ({iso_z(csv_src_mtime)}), carried over, bounds the source file's last change at most. The CRM was not collected."},
                 facts=[
                     fact("F6.1", "absent", "The source system's creation time is nowhere in the evidence."),
                     fact("F6.2", "decoy", "The copy's FAT creation time.", [minute_pattern(t_csv)]),
                 ]),
        question("7", "Which wiping tool was used.", kind="absent",
                 expected={"result": "premise_not_supported", "accept_results": ["premise_not_supported", "bounded_negative"],
                           "summary": f"No wiping: the deleted files' clusters are intact and recoverable, and the shredder's archive ({zip_name}) holds no program and shows no sign of having been run."},
                 facts=[
                     fact("F7.1", "absent", "Nothing on the drive was wiped."),
                     fact("F7.2", "decoy", "The shredder's archive copied to the drive in the cleanup session.", [rx("shred ?pro")]),
                 ]),
        question("8", "The timeline, the hypotheses and what remains open.", kind="present", scored=False,
                 expected={"result": "established", "accept_results": ["established", "partial"], "summary": "Not scored."},
                 facts=[]),
    ]

    # --- the probes: every planted fact held to the bytes ----------------------------------------
    found, free, data_off, csize = read_volume(image, 2048)
    by_name = {f.path: f for f in found}
    auth_plain = auth_w3 + auth_w2
    sys_plain = sys_w3 + sys_w2
    all_inputs = b"".join(inputs.values()) + auth_w1 + sys_w1

    def raw_cluster(c: int) -> bytes:
        o = data_off + (c - 2) * csize
        return image[o:o + csize]

    def orphan_clusters_unreferenced() -> bool:
        gz_set = set(gz_e.clusters)
        for f in found:
            if f.is_dir or not f.start:
                continue
            span = set(range(f.start, f.start + max(1, (f.size + csize - 1) // csize)))
            if span & gz_set:
                return False
        return all(c in free for c in gz_set)

    notes_found = by_name.get("notes.txt")
    probes = [
        Probe("F1.1", "the boot sector holds the volume serial", lambda: image[2048 * 512 + 39:2048 * 512 + 43] == vsn.to_bytes(4, "little")),
        Probe("F1.2", "the first connection's mount line is in syslog.2.gz and in no plain log",
              lambda: f"{rfc3339_us(mount1)} {host} udisksd".encode() in sys_w1 and vs.encode() not in sys_w2 and rfc3339_us(mount1).encode() not in sys_plain),
        Probe("F1.3", "the later connection's mount path names the volume serial", lambda: f"/media/{colleague['user']}/{vs} on behalf of uid 1002".encode() in sys_w3),
        Probe("F1.4", "the other drive's serial is in the plain syslogs and never this drive's", lambda: vs_other.encode() in sys_w2 and vs_other.encode() in sys_w3 and vs_other != vs),
        Probe("F2.1", "the customer export's entry is deleted, and its contiguous clusters hold it whole",
              lambda: (f := by_name.get(csv_name)) is not None and f.deleted and f.size == len(csv_bytes)
              and b"".join(raw_cluster(c) for c in range(f.start, f.start + len(csv_e.clusters)))[:f.size] == csv_bytes),
        Probe("F2.2", "no directory entry, live or deleted, names or covers the price list; its clusters are free and hold the gzip",
              lambda: gz_name not in by_name and pl_inner not in [f.path for f in found] and orphan_clusters_unreferenced()
              and gzip.decompress(b"".join(raw_cluster(c) for c in gz_e.clusters)[:len(gz_bytes)]) == pricelist),
        Probe("F2.2", "the price list's document id is nowhere in the image as plain bytes", lambda: doc_id.encode() not in image),
        Probe("F3.1", "the colleague's evening session is only in auth.log.2.gz",
              lambda: f"session opened for user {colleague['user']}(uid=1002)".encode() in auth_w1
              and rfc3339_us(b_login).encode() not in auth_plain),
        Probe("F3.3", "the suspect's sessions on the copy day end before the copy",
              lambda: all(t < mount1 for t, s in auth.between(at(copy_day, 0, 0), at(copy_day, 23, 59)) if f"closed for user {suspect['user']}" in s)),
        Probe("F4.1", "the upload host is in no input, only in the late item", lambda: true_service.encode() not in all_inputs and true_host.encode() in swg),
        Probe("F4.2", "the decoy share host is in the live notes.txt", lambda: notes_found is not None and decoy_host.encode() in notes_found.data),
        Probe("F5.1", "the recipient is in notes.txt's slack and not in its live bytes, and nowhere else in the evidence",
              lambda: notes_found is not None and recipient["last"].encode() not in notes_found.data
              and recipient["last"].encode() in raw_cluster(notes_e.clusters[0])[len(notes_new):]
              and all_inputs.count(recipient["last"].encode()) == 1),
        Probe("F6.2", "the customer export's directory entry carries the copy time as its creation time",
              lambda: image[csv_e.slots[-1] + 14:csv_e.slots[-1] + 18] == fat_time(naive_utc(t_csv)).to_bytes(2, "little") + fat_date(naive_utc(t_csv)).to_bytes(2, "little")),
        Probe("F7.1", "the deleted files are intact (not overwritten by a wipe pattern)",
              lambda: raw_cluster(csv_e.clusters[0])[:len(rows[0])] == rows[0].encode()),
        Probe("F7.2", "the shredder archive is live and holds no program",
              lambda: (z := by_name.get(zip_name)) is not None and not z.deleted
              and not any(n.lower().endswith((".exe", ".dll")) for n in zipfile.ZipFile(io.BytesIO(zip_bytes)).namelist())),
    ]

    context = {
        "people": {"suspect": suspect, "copier": colleague, "named_colleague": named, "recipient": recipient,
                   "recipient_org": recipient_org},
        "workstation": {"host": host, "ip": ws_ip, "uids": uid},
        "drive": {"vsn": vs, "usb_serial": serial, "other_vsn": vs_other, "other_usb_serial": serial_other},
        "hosts": {"upload": true_host, "decoy": decoy_host},
        "times": {"copy_login": iso_z(b_login), "mount1": iso_z(mount1), "csv_created": iso_z(t_csv),
                  "gz_deleted": iso_z(t_gz_deleted), "upload1": iso_z(upload1), "upload2": iso_z(upload2),
                  "mount2": iso_z(mount2), "zip_created": iso_z(t_zip), "csv_deleted": iso_z(t_csv_deleted),
                  "notes_rewritten": iso_z(t_rewrite)},
        "files": {"customers": csv_name, "customers_records": n_rows, "customers_sha256": hashlib.sha256(csv_bytes).hexdigest(),
                  "pricelist": pl_inner, "pricelist_doc": doc_id, "pricelist_sha256": hashlib.sha256(pricelist).hexdigest(),
                  "shredder": zip_name},
    }
    mtimes = {k: export_at for k in inputs if k.startswith(host)}
    mtimes["usb.dd"] = imaged_at
    mtimes["CASE.md"] = imaged_at
    mtimes[late_name] = export_at + dt.timedelta(days=3)
    return CaseOutput(case_id=CASE_ID, title="USB drive after a resignation", inputs=inputs, late=late, goal=goal,
                      questions=questions, probes=probes, context=context, mtimes=mtimes,
                      late_for={late_name: ["4"]},
                      late_what={late_name: f"The web gateway's export of the requests from {host} over the weeks the logs cover, as IT would supply it on request."})


_FIRSTS = ["Anna", "Ben", "Clara", "David", "Eva", "Felix", "Gina", "Henrik", "Iris", "Jan", "Kim", "Lena", "Max",
           "Nina", "Otto", "Paula", "Rolf", "Sara", "Tom", "Uma", "Vera", "Will", "Xenia", "Yusuf", "Zoe"]
_LASTS = ["Adler", "Becker", "Coles", "Dietz", "Engel", "Frey", "Graf", "Hahn", "Imhof", "Jung", "Kraus", "Lorenz",
          "Maier", "Neumann", "Otten", "Pohl", "Reuter", "Stein", "Thiel", "Ulrich", "Vogt", "Wolff", "Zander"]


def _size_text(blocks: int) -> str:
    b = blocks * 512
    if b >= 1_000_000_000:
        return f"{b / 1e9:.2f} GB/{b / 2**30:.2f} GiB"
    return f"{b / 1e6:.2f} MB/{b / 2**20:.2f} MiB"


def _session(auth: _Log, login: dt.datetime, logout: dt.datetime, user: str, uid: int, session: List[int], logind: int,
             rng: Rng) -> None:
    n = session[0]
    session[0] += 1
    auth.add(login, "gdm-password]: gkr-pam: unable to locate daemon control file")
    auth.add(login + dt.timedelta(milliseconds=rng.between(5, 40)),
             f"gdm-password]: pam_unix(gdm-password:session): session opened for user {user}(uid={uid}) by (uid=0)")
    auth.add(login + dt.timedelta(milliseconds=rng.between(50, 120)), f"systemd-logind[{logind}]: New session {n} of user {user}.")
    auth.add(login + dt.timedelta(milliseconds=rng.between(900, 1900)), "gdm-password]: gkr-pam: gnome-keyring-daemon started properly and unlocked keyring")
    auth.add(logout, f"systemd-logind[{logind}]: Session {n} logged out. Waiting for processes to exit.")
    auth.add(logout + dt.timedelta(milliseconds=rng.between(20, 80)), f"gdm-password]: pam_unix(gdm-password:session): session closed for user {user}")
    auth.add(logout + dt.timedelta(milliseconds=rng.between(200, 900)), f"systemd-logind[{logind}]: Removed session {n}.")


def _shredder_zip(mtime: dt.datetime) -> bytes:
    buf = io.BytesIO()
    date_time = (mtime.year, mtime.month, mtime.day, mtime.hour, mtime.minute, mtime.second - mtime.second % 2)
    files = [
        ("ShredPro/README.txt",
         "ShredPro Portable 3.2 (x64)\r\n\r\nSecure file and free-space shredder. Unpack the archive to a folder of "
         "your choice and start ShredPro.exe. No installation is needed.\r\n\r\nMethods: zero fill, random fill, "
         "DoD 5220.22-M (3 passes), Gutmann (35 passes).\r\n"),
        ("ShredPro/LICENSE.txt", "ShredPro is freeware for private use. Redistribution of the portable package is "
                                 "permitted unchanged.\r\n"),
        ("ShredPro/ShredPro.ini", "[General]\r\nMethod=2\r\nVerify=0\r\nLanguage=en\r\nPortable=1\r\n"),
    ]
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        for name, text in files:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, text.encode("ascii"))
    return buf.getvalue()


_SITES = ["news.northwind.example", "weather.skyline.example", "maps.atlas.example", "shop.harbor.example",
          "video.stream.example", "docs.office.example"]


def _gateway_export(rng: Rng, ws_ip: str, a_user: str, b_user: str, org_domain: str, start: dt.datetime,
                    end: dt.datetime, auth: _Log, suspect: str, uploads: List[Tuple[dt.datetime, int]], true_host: str,
                    blocked: dt.datetime, decoy_host: str, token: str, b_login: dt.datetime,
                    b_logout: dt.datetime) -> bytes:
    """A secure web gateway's CSV export: the suspect's working-day browsing,
    the colleague's upload on the evening of the copy, and the blocked visit
    to the share named in notes.txt."""
    rows: List[Tuple[dt.datetime, str]] = []
    opened = [t for t, s in auth.between(start, end) if f"session opened for user {suspect}(" in s]
    closed = [t for t, s in auth.between(start, end) if f"session closed for user {suspect}" in s]
    ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    for a, b in zip(opened, closed):
        t = a + dt.timedelta(minutes=rng.between(1, 4))
        while t < b:
            site = rng.choice([f"crm.{org_domain}", f"mail.{org_domain}", f"intranet.{org_domain}"] + _SITES)
            path = rng.choice(["/", "/index", "/api/list", "/inbox", "/search?q=" + rng.hex(6), "/static/app.js"])
            status = rng.choice([200, 200, 200, 200, 304, 302])
            rows.append((t, f"{iso_z(t)},{ws_ip},{a_user},allowed,GET,https://{site}{path},{status},{rng.between(300, 2400)},"
                            f"{rng.between(800, 250000)},{'Business' if org_domain in site else 'General'},{ua}"))
            t += dt.timedelta(minutes=rng.between(3, 24), seconds=rng.between(0, 59))
    t = b_login + dt.timedelta(minutes=rng.between(2, 5))
    while t < b_logout:
        if not any(abs((t - u).total_seconds()) < 120 for u, _ in uploads):
            site = rng.choice([f"mail.{org_domain}"] + _SITES)
            rows.append((t, f"{iso_z(t)},{ws_ip},{b_user},allowed,GET,https://{site}/,200,{rng.between(300, 1200)},"
                            f"{rng.between(900, 90000)},General,{ua}"))
        t += dt.timedelta(minutes=rng.between(4, 9), seconds=rng.between(0, 59))
    first = uploads[0][0] - dt.timedelta(seconds=rng.between(20, 50))
    rows.append((first, f"{iso_z(first)},{ws_ip},{b_user},allowed,GET,https://{true_host}/,200,{rng.between(400, 900)},"
                        f"{rng.between(20000, 60000)},File Sharing,{ua}"))
    for when, size in uploads:
        rows.append((when, f"{iso_z(when)},{ws_ip},{b_user},allowed,POST,https://{true_host}/api/v2/upload,200,"
                           f"{size + rng.between(600, 900)},{rng.between(300, 700)},File Sharing,{ua}"))
    rows.append((blocked, f"{iso_z(blocked)},{ws_ip},{b_user},blocked,GET,https://{decoy_host}/s/{token},403,"
                          f"{rng.between(400, 900)},0,File Sharing,{ua}"))
    rows.sort(key=lambda r: r[0])
    head = "timestamp,client_ip,username,action,method,url,status,bytes_sent,bytes_received,category,user_agent\n"
    return (head + "".join(line + "\n" for _, line in rows)).encode("utf-8")
