import json, sys

args = json.load(sys.stdin)
path = args.get("ledger_path", "ledger/entries.jsonl")

events = []
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") == "event":
            events.append(e)

events.sort(key=lambda e: (e.get("ts", ""), e.get("seq", 0)))

out = []
out.append(f"events={len(events)}")
for e in events:
    ts = e.get("ts", "?").replace("|", "\\|")
    value = e.get("value", "").replace("|", "\\|")
    seq = e.get("seq", "?")
    source = (e.get("source", "") or "").replace("|", "\\|")
    out.append(f"| {ts} | {value} | {seq} | `{source}` |")

print("\n".join(out))
