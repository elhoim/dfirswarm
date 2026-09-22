#!/usr/bin/env bash
# The parsers the platform packs carry, against data built from the documented
# formats rather than from the parsers themselves.
#
# Each case builds its input by hand from the format's specification, so a test
# passing means the parser reads the format — not that it agrees with itself.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
P="$ROOT/packs"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "skip - no python3"; exit 0; }

run() { "$PY" "$P/$1/run.py"; }

"$PY" - "$P" <<'EOF' || fail "a pack parser did not read its format"
import datetime, gzip, json, os, random, socket, sqlite3, struct, subprocess, sys, tempfile

PACKS = sys.argv[1]
WORK = tempfile.mkdtemp()
failures = []


def tool(pack_tool, args):
    out = subprocess.run([sys.executable, os.path.join(PACKS, pack_tool, "run.py")],
                         input=json.dumps(args), capture_output=True, text=True)
    try:
        return json.loads(out.stdout)
    except ValueError:
        return {"_stdout": out.stdout[:400], "_stderr": out.stderr[-400:]}


def check(name, condition, detail=""):
    if condition:
        print("ok - %s" % name)
    else:
        failures.append("%s %s" % (name, detail))
        print("FAIL: %s %s" % (name, detail))


# --- linux-forensics/utmp_parse: the glibc struct, built from its own layout ---
def utmp(kind, user, line, host, ip, when, pid=1234):
    b = bytearray(384)
    struct.pack_into("<hxxi", b, 0, kind, pid)
    b[0x008:0x008 + len(line)] = line.encode()
    b[0x02C:0x02C + len(user)] = user.encode()
    b[0x04C:0x04C + len(host)] = host.encode()
    struct.pack_into("<ii", b, 0x154, when, 0)
    if ip:
        b[0x15C:0x160] = socket.inet_aton(ip)
    return bytes(b)


stamp = int(datetime.datetime(2026, 2, 14, 9, 30, tzinfo=datetime.timezone.utc).timestamp())
path = os.path.join(WORK, "wtmp")
open(path, "wb").write(utmp(2, "reboot", "~", "6.8.0", None, stamp - 3600, 0)
                       + utmp(7, "root", "pts/1", "203.0.113.9", "203.0.113.9", stamp))
got = tool("linux-forensics/tools/utmp_parse", {"path": path})
check("utmp_parse reads a boot record and a session with its source address",
      got.get("boots") == 1
      and [r["user"] for r in got.get("records", [])] == ["reboot", "root"]
      and got["records"][1]["address"] == "203.0.113.9"
      and got["records"][1]["time"] == "2026-02-14T09:30:00Z", got.get("error", ""))

# --- linux-forensics/auth_log: the year syslog does not record -----------------
d = os.path.join(WORK, "log"); os.makedirs(d, exist_ok=True)
with gzip.open(os.path.join(d, "auth.log.1.gz"), "wt") as fh:
    fh.write("Dec 31 23:58:01 web01 sshd[1]: Failed password for invalid user a from 203.0.113.9 port 1 ssh2\n"
             "Jan  1 00:02:11 web01 sshd[2]: Accepted publickey for deploy from 10.0.0.7 port 2 ssh2: RSA SHA256:zz\n")
open(os.path.join(d, "auth.log"), "w").write(
    "Jan  1 00:05:44 web01 sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/id\n")
import time
os.utime(os.path.join(d, "auth.log.1.gz"), (time.time(), time.mktime((2026, 1, 1, 0, 0, 0, 0, 0, 0))))
os.utime(os.path.join(d, "auth.log"), (time.time(), time.mktime((2026, 1, 2, 0, 0, 0, 0, 0, 0))))
got = tool("linux-forensics/tools/auth_log", {"path": d})
times = [r["time"] for r in got.get("records", [])]
check("auth_log follows the rotation and crosses new year correctly",
      times == ["2025-12-31T23:58:01", "2026-01-01T00:02:11", "2026-01-01T00:05:44"], str(times))

# --- macos-forensics/fsevents_parse: a gzip page of DLS records ----------------
def fsevent(path_, eid, flags, node):
    return path_.encode() + b"\x00" + struct.pack("<QI", eid, flags) + struct.pack("<Q", node)


body = fsevent("Users/a/payroll.xlsx", 1001, 0x01000000 | 0x00008000, 12) \
     + fsevent("Users/a/payroll.xlsx", 1042, 0x02000000 | 0x00008000, 12)
page = b"2SLD" + b"\x00" * 4 + struct.pack("<I", 12 + len(body)) + body
fs = os.path.join(WORK, ".fseventsd"); os.makedirs(fs, exist_ok=True)
with gzip.open(os.path.join(fs, "0000000000000fff"), "wb") as fh:
    fh.write(page)
got = tool("macos-forensics/tools/fsevents_parse", {"path": fs})
check("fsevents_parse decodes the flags and keeps the event id order",
      got.get("record_count") == 2
      and got["records"][0]["flags"] == ["FileEvent", "Created"]
      and got["records"][1]["flags"] == ["FileEvent", "Removed"]
      and got["event_id_range"] == [1001, 1042], got.get("error", ""))

# --- mobile-forensics/sqlite_freespace: a row SQLite no longer lists -----------
db = os.path.join(WORK, "sms.db")
con = sqlite3.connect(db)
# Some distributions compile SQLite with secure delete on, which zeroes a freed
# cell instead of leaving it. That is a property of the build, not of the parser,
# so ask for it off and say which it was if the row does not survive.
con.execute("PRAGMA secure_delete=OFF")
secure_delete = con.execute("PRAGMA secure_delete").fetchone()[0]
con.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, handle TEXT, text TEXT)")
con.executemany("INSERT INTO message (handle, text) VALUES (?,?)",
                [("+1", "lunch at one"), ("+2", "burn the drive at midnight"), ("+3", "see you")])
con.commit(); con.execute("DELETE FROM message WHERE id = 2"); con.commit(); con.close()
got = tool("mobile-forensics/tools/sqlite_freespace", {"db": db, "contains": "burn"})
recovered = got.get("fragment_count", 0) >= 1 and \
    "burn the drive" in (got.get("fragments") or [{}])[0].get("text", "")
if not recovered and secure_delete:
    print("skip - sqlite_freespace: this SQLite is built with secure delete (%s), so a freed "
          "cell is zeroed and there is nothing for any parser to recover" % secure_delete)
else:
    check("sqlite_freespace recovers a deleted row from the page freeblock chain", recovered,
          "secure_delete=%s fragments=%s"
          % (secure_delete, json.dumps(got.get("fragments", []))[:200]))

# --- network-forensics/pcap_summary and beacon_score ---------------------------
def packet(src, dst, sport, dport, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip


cap = os.path.join(WORK, "c.pcap")
base = 1771070000
with open(cap, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i in range(6):
        for when, body in ((base + i * 60, packet("10.0.0.5", "203.0.113.7", 50000 + i, 443, 0x02)),
                           (base + i * 60 + 0.2, packet("203.0.113.7", "10.0.0.5", 443, 50000 + i, 0x18, b"x" * 120))):
            fh.write(struct.pack("<IIII", int(when), int((when % 1) * 1e6), len(body), len(body)))
            fh.write(body)
got = tool("network-forensics/tools/pcap_summary",
           {"path": cap, "group": "endpoint", "with_starts": True})
conversation = (got.get("conversations") or [{}])[0]
check("pcap_summary reads a classic pcap and groups a service endpoint",
      got.get("packets") == 12 and conversation.get("service_port") == 443
      and conversation.get("connection_starts") == 6, got.get("error", ""))
got2 = tool("network-forensics/tools/beacon_score",
            {"timestamps": conversation.get("starts", []), "label": "t"})
check("beacon_score calls a fixed sixty-second interval a fixed timer",
      got2.get("median_interval_seconds") == 60.0 and got2.get("shape") == "fixed timer",
      json.dumps({k: got2.get(k) for k in ("median_interval_seconds", "shape", "error")}))

# --- encrypted-containers/crypto_id: a LUKS1 header with three enabled slots ---
h = bytearray(4096)
h[0:6] = b"LUKS\xba\xbe"; struct.pack_into(">H", h, 6, 1)
h[8:11] = b"aes"; h[40:51] = b"xts-plain64"; h[72:78] = b"sha256"
struct.pack_into(">I", h, 108, 64)
for i in range(8):
    struct.pack_into(">IIII", h, 208 + i * 48, 0x00AC71F3 if i < 3 else 0x0000DEAD, 1000, 0, 4000)
luks = os.path.join(WORK, "luks.img"); open(luks, "wb").write(bytes(h))
got = tool("encrypted-containers/tools/crypto_id", {"path": luks})
check("crypto_id reads a LUKS1 key slot table with no key",
      got.get("scheme") == "LUKS1" and got.get("enabled_slots") == 3
      and got.get("cipher") == "aes", got.get("error", ""))

# --- ransomware-response/encrypted_survey: the shared family marker ------------
random.seed(11)
share = os.path.join(WORK, "share"); os.makedirs(share, exist_ok=True)
for i in range(6):
    open(os.path.join(share, "f%d.xlsx.LOCKD" % i), "wb").write(
        bytes(random.getrandbits(8) for _ in range(120000)) + b"\xde\xad\xbe\xefKEYBLOB1")
got = tool("ransomware-response/tools/encrypted_survey", {"root": share})
suffix = (got.get("shared_file_suffix") or {}).get("suffix_hex")
check("encrypted_survey finds the bytes every encrypted file ends with",
      suffix == b"\xde\xad\xbe\xefKEYBLOB1".hex()
      and got.get("appended_extensions", [{}])[0].get("extension") == ".lockd", str(suffix))

# --- triage-collection/collection_index: the stream a collector renamed --------
coll = os.path.join(WORK, "kape", "C", "Users", "a"); os.makedirs(coll, exist_ok=True)
for name in ("report.txt_Zone.Identifier", "holiday_photos.jpg"):
    open(os.path.join(coll, name), "wb").write(b"x")
got = tool("triage-collection/tools/collection_index",
           {"root": os.path.join(WORK, "kape")})
streams = got.get("possible_renamed_streams") or []
paths = {e["in_collection"]: e["original_path"] for e in got.get("entries", [])}
check("collection_index maps a path back and spots a renamed stream",
      len(streams) == 1 and streams[0]["possible_original"] == "report.txt:Zone.Identifier"
      and paths.get(os.path.join("C", "Users", "a", "holiday_photos.jpg")) == r"C:\Users\a\holiday_photos.jpg",
      json.dumps(streams))

# --- mobile-forensics/protobuf_peek: the wire format, built by hand ------------
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


inner = varint((1 << 3) | 2) + varint(len(b"com.example.beacon")) + b"com.example.beacon"
blob = varint((1 << 3) | 2) + varint(len(inner)) + inner + varint((3 << 3) | 0) + varint(42)
got = tool("mobile-forensics/tools/protobuf_peek", {"hex": blob.hex()})
check("protobuf_peek unwraps a nested message without a schema",
      got.get("looks_like_protobuf") is True
      and got.get("strings", [{}])[0].get("text") == "com.example.beacon",
      json.dumps(got.get("problems", []))[:200])

# --- computer-forensics-base/timestamp_decode ---------------------------------
got = tool("computer-forensics-base/tools/timestamp_decode", {"value": "133502964000000000"})
readings = {r["epoch"]: r["when"] for r in got.get("readings", [])}
check("timestamp_decode reads a FILETIME as a FILETIME",
      readings.get("FILETIME (100 ns)") == "2024-01-21T07:40:00Z", json.dumps(readings))

raise SystemExit(1 if failures else 0)
EOF
echo "pack-parsers: all checks passed"
