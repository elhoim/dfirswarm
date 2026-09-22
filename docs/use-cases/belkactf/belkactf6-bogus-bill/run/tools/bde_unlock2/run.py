#!/usr/bin/env python3
import json, sys, struct, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def rec_key(rp):
    s = rp.replace("-", "").replace(" ", "")
    out = b""
    for i in range(8):
        n = int(s[i * 6 : i * 6 + 6])
        if n % 11:
            raise ValueError("group %d not div11" % i)
        out += struct.pack("<H", n // 11)
    return out

def stretch(initial, salt, rounds=1048576):
    h = initial
    if len(h) < 32:
        h = h + b"\x00" * (32 - len(h))
    for i in range(rounds):
        ctx = hashlib.sha256()
        ctx.update(h)
        ctx.update(salt)
        ctx.update(struct.pack("<Q", i))
        h = ctx.digest()
    return h

def parse_hhhh(buf):
    pos = 0
    out = []
    while pos + 8 <= len(buf):
        size, etype, vtype, ver = struct.unpack_from("<HHHH", buf, pos)
        if size < 8 or pos + size > len(buf):
            break
        out.append((etype, vtype, ver, buf[pos + 8 : pos + size]))
        pos += size
    return out

def parse_ihh(buf):
    pos = 0
    out = []
    while pos + 8 <= len(buf):
        size, ntype, nflags = struct.unpack_from("<IHH", buf, pos)
        if size < 8 or pos + size > len(buf):
            break
        out.append((ntype, nflags, buf[pos + 8 : pos + size]))
        pos += size
    return out

def try_ccm(key, blob):
    if len(blob) < 29:
        return None
    variants = [
        ("n12_mac16_data", blob[:12], blob[12:28], blob[28:]),
        ("n12_data_mac16", blob[:12], blob[-16:], blob[12:-16]),
    ]
    keys = [("k16", key[:16])]
    if len(key) >= 32:
        keys.append(("k32", key[:32]))
    for lname, nonce, mac, ct in variants:
        if len(nonce) != 12 or len(mac) != 16 or len(ct) < 1:
            continue
        for kname, k in keys:
            try:
                pt = AESCCM(k, tag_length=16).decrypt(nonce, ct + mac, None)
                return {"ok": True, "layout": lname, "k": kname, "pt": pt.hex(), "pt_len": len(pt)}
            except Exception:
                continue
    return None

def main():
    args = json.load(sys.stdin)
    path = args.get("path", "work/extracted/s821c08/vault.vhdx")
    rp = args.get("recovery", "590238-514580-359986-088242-029766-319495-410509-636911")
    meta_off = int(args.get("meta_off", "0x8400000"), 0)
    with open(path, "rb") as f:
        f.seek(meta_off)
        blk = f.read(65536)
    if blk[:8] != b"-FVE-FS-":
        raise SystemExit("no FVE header")
    meta = blk[64:]
    md_size, ver, hdr_size, copy_size = struct.unpack_from("<IIII", meta, 0)
    entries = parse_hhhh(meta[hdr_size:md_size])
    rk = rec_key(rp)
    results = []
    for etype, vtype, ver, payload in entries:
        rec = {"etype": etype, "vtype": vtype, "plen": len(payload)}
        if etype != 2:
            results.append(rec)
            continue
        guid = payload[:16]
        prot = struct.unpack_from("<H", payload, 26)[0]
        nested = payload[28:]
        rec.update({"guid": guid.hex(), "prot": hex(prot)})
        nested_ents = parse_ihh(nested)
        salt = None
        ccms = []
        for ntype, nflags, pl in nested_ents:
            rec.setdefault("nested", []).append({"t": hex(ntype), "n": len(pl)})
            if ntype == 3:
                meth = struct.unpack_from("<I", pl, 0)[0] if len(pl) >= 4 else 0
                salt = pl[4:20]
                rec["stretch_meth"] = hex(meth)
                rec["salt"] = salt.hex()
                rest = pl[20:]
                inner = parse_hhhh(rest)
                if not inner:
                    inner = [(t, 0, 0, p) for t, f, p in parse_ihh(rest)]
                for t2, v2, ve2, pl2 in inner:
                    rec.setdefault("stretch_inner", []).append({"t": hex(t2), "v": hex(v2), "n": len(pl2), "head": pl2[:16].hex()})
                    ccms.append(("stretch_"+hex(t2), pl2))
            elif ntype in (5, 0x12):
                ccms.append(("sib_"+hex(ntype), pl))
        rec["n_ccm"] = len(ccms)
        rec["ccm_lens"] = [len(c[1]) for c in ccms]
        if salt is None or not ccms:
            results.append(rec)
            continue
        keys_try = [
            ("pad32", stretch(rk, salt)),
            ("sha256", stretch(hashlib.sha256(rk).digest(), salt)),
            ("dsha256", stretch(hashlib.sha256(hashlib.sha256(rk).digest()).digest(), salt)),
        ]
        for label, key in keys_try:
            for src, ccm in ccms:
                r = try_ccm(key, ccm)
                if r:
                    rec["unlocked"] = True
                    rec["method"] = label
                    rec["src"] = src
                    rec.update(r)
                    break
            if rec.get("unlocked"):
                break
        results.append(rec)
    json.dump({"rk": rk.hex(), "md_size": md_size, "results": results}, sys.stdout)
    print()

if __name__ == "__main__":
    main()
