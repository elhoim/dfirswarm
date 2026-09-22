import json, sys
d = json.load(sys.stdin)
hexstr = d["hex"].strip().replace(" ", "")
raw = bytes.fromhex(hexstr)

def params_from_sum(s):
    a = 2 * (s % 137) + 1
    b = s % 89 + 1
    inv = None
    for i in range(256):
        if (a * i) % 256 == 1:
            inv = i
            break
    return a, b, inv

def decrypt(raw, s):
    a, b, inv = params_from_sum(s)
    if inv is None:
        return None
    return bytes((inv * ((c - b) % 256)) % 256 for c in raw)

key = d.get("key")
s = d.get("sum")
if key is not None:
    s = sum(ord(c) for c in str(key))
if s is None:
    # brute residue classes 0..137*89-1, return best printable
    best = []
    for cand in range(137 * 89):
        out = decrypt(raw, cand)
        if out is None:
            continue
        pr = sum(32 <= c < 127 or c in (9, 10, 13) for c in out) / max(1, len(out))
        if pr < 0.9:
            continue
        try:
            t = out.decode("utf-8")
        except Exception:
            continue
        if sum(ch.isalpha() or ch.isspace() or ch in ".,!?:;-'" for ch in t) / len(t) > 0.7:
            best.append({"sum": cand, "text": t})
    print(json.dumps({"n": len(best), "hits": best[:20]}))
else:
    out = decrypt(raw, int(s))
    try:
        text = out.decode("utf-8") if out else None
    except Exception:
        text = None
    print(json.dumps({"sum": int(s), "text": text, "hex_preview": out.hex()[:64] if out else None}))
