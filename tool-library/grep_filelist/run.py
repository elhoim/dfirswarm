#!/usr/bin/env python3
"""Search the catalog filelist. Pattern is data for re.search, never eval'd."""
import json
import re
import sys

FILELIST = "catalog/AF-Case2.E01/p0/filelist.txt"
LIMIT = 100


def fail(msg, **extra):
    print(json.dumps({"error": msg, **extra}))
    sys.exit(1)


d = json.load(sys.stdin)
pattern = d.get("pattern", "")
if not isinstance(pattern, str):
    fail("pattern must be a string")
# Compiling once names a bad pattern as a bad pattern, instead of raising
# re.error on the first line and handing the agent a traceback.
try:
    rx = re.compile(pattern, re.IGNORECASE)
except re.error as exc:
    fail("pattern is not a valid regular expression", pattern=pattern, reason=str(exc))
results = []
matched = 0
try:
    with open(FILELIST, "r", errors="replace") as f:
        for line in f:
            if rx.search(line):
                matched += 1
                if len(results) < LIMIT:
                    results.append(line.rstrip("\n"))
except OSError as exc:
    fail("cannot read the catalog filelist", path=FILELIST, reason=exc.strerror or str(exc))
# The cap stays, but silently dropping the rest would let an agent read
# "100 hits" as "all the hits"; say so on stderr, which the trace keeps.
if matched > len(results):
    sys.stderr.write(f"{matched} lines matched; showing the first {len(results)}\n")
print(json.dumps(results))
