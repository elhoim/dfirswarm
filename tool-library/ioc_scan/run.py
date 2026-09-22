#!/usr/bin/env python3
import json, sys, os, re
from collections import defaultdict

args = json.load(sys.stdin)
path = args.get("path") or "inputs/[UNALLOCATED]"
needles = args.get("needles")  # list of ascii strings, or pipe-separated string
if isinstance(needles, str):
    needles = [n for n in needles.split("|") if n]
if not needles:
    needles = [
        "http://", "https://", "ftp://",
        "powershell", "cmd.exe", "rundll32", "mshta", "wscript", "cscript",
        "schtasks", "bitsadmin", "certutil", "regsvr32",
        "Invoke-", "IEX(", "-enc ", "FromBase64",
        "HKEY_", "CurrentVersion\\Run", "UserInit",
        "mimikatz", "meterpreter", "cobalt", "beacon",
        ".onion", "bitcoin", "ransom", "wallet",
        "psexec", "procexp", "sysinternals", "tcpview", "autoruns",
        "IEUser", "@gmail", "@yahoo", "@hotmail",
        "password", "Password", "C2", "user-agent", "User-Agent",
        ".exe", ".ps1", ".bat", ".vbs", ".js",
        "AppData\\", "\\Temp\\", "Downloads\\",
        "From:", "Subject:", "mailto:",
        "192.168.", "10.0.", "172.16.",
    ]
max_hits = int(args.get("max_hits") or 80)
context = int(args.get("context") or 96)
start = int(args.get("start") or 0)
length = args.get("length")
chunk = int(args.get("chunk") or 8 * 1024 * 1024)
overlap = 256
skip_zeros = bool(args.get("skip_zeros", True))
unique_only = bool(args.get("unique_only", True))

needles_b = []
for n in needles:
    b = n.encode("utf-8", "ignore")
    if b:
        needles_b.append(("ascii", n, b))
        needles_b.append(("utf16", n, n.encode("utf-16le")))

size = os.path.getsize(path)
end = size if length is None else min(size, start + int(length))
hits = []
seen = set()
counts = defaultdict(int)

def add_hit(kind, name, off, blob, local):
    # extract a readable snippet around the match
    i = local
    s = max(0, i - 16)
    e = min(len(blob), i + len(name.encode("utf-8")) + context)
    raw = blob[s:e]
    # prefer ascii printable
    snip = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
    key = (name.lower(), snip[:80])
    counts[name] += 1
    if unique_only and key in seen:
        return
    if unique_only:
        seen.add(key)
    if len(hits) < max_hits:
        hits.append({
            "offset": off,
            "needle": name,
            "enc": kind,
            "snippet": snip[:200],
        })

with open(path, "rb") as f:
    f.seek(start)
    pos = start
    prev = b""
    while pos < end:
        want = min(chunk, end - pos)
        data = f.read(want)
        if not data:
            break
        if skip_zeros and data.count(0) > len(data) * 0.98:
            pos += len(data)
            prev = data[-overlap:] if len(data) >= overlap else data
            continue
        blob = prev + data
        base = pos - len(prev)
        for kind, name, nb in needles_b:
            start_i = 0
            while True:
                i = blob.find(nb, start_i)
                if i < 0:
                    break
                abs_off = base + i
                if abs_off >= pos or not prev:  # avoid double-count in overlap except first chunk
                    add_hit(kind, name, abs_off, blob, i)
                start_i = i + max(1, len(nb))
                if counts[name] > 50000:
                    break
        prev = data[-overlap:] if len(data) >= overlap else data
        pos += len(data)

print(json.dumps({
    "path": path,
    "scanned_start": start,
    "scanned_end": end,
    "size": size,
    "hit_count_returned": len(hits),
    "counts": dict(sorted(counts.items(), key=lambda kv: -kv[1])[:80]),
    "hits": hits,
}, indent=2))
