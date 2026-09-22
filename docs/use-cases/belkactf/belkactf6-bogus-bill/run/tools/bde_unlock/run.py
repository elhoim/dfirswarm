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

def parse_entries_hhhh(buf):
    pos = 0
    out = []
    while pos + 8 <= len(buf):
        size, etype, vtype, ver = struct.unpack_from("<HHHH", buf, pos)
        if size < 8 or pos + size > len(buf):
            break
        out.append((etype, vtype, buf[pos + 8 : pos + size]))
        pos += size
    return out

def main():
    args = json.load(sys.stdin)
    path = args["path"]
    rp = args["recovery"]
    meta_off = int(args.get("meta_off", "0x8400000"), 0)
    with open(path, "rb") as f:
        f.seek(meta_off)
        blk = f.read(4096)
    if blk[:8] != b"-FVE-FS-":
        raise SystemExit("no FVE header")
    meta = blk[64:]
    md_size, ver, hdr_size, copy_size = struct.unpack_from("<IIII", meta, 0)
    entries = parse_entries_hhhh(meta[hdr_size:md_size])
    rk = rec_key(rp)
    results = []
    for etype, vtype, payload in entries:
        if etype != 2:
            continue
        guid = payload[:16]
        prot = struct.unpack_from("<H", payload, 26)[0]
        nested = payload[28:]
        # nested may be IHH then payload
        info = {"prot": hex(prot), "guid": guid.hex(), "nested_len": len(nested)}
        salt = None
        ccms = []
        pos = 0
        while pos + 8 <= len(nested):
            size32, ntype, nflags = struct.unpack_from("<IHH", nested, pos)
            if size32 < 8 or pos + size32 > len(nested):
                size, ntype2, vtype2, ver2 = struct.unpack_from("<HHHH", nested, pos)
                if size < 8 or pos + size > len(nested):
                    break
                pl = nested[pos + 8 : pos + size]
                ntype, size32 = ntype2, size
            else:
                pl = nested[pos + 8 : pos + size32]
            if ntype == 3:  # stretch key
                meth = struct.unpack_from("<I", pl, 0)[0]
                salt = pl[4:20]
                rest = pl[20:]
                info["stretch_meth"] = hex(meth)
                info["salt"] = salt.hex()
                # remaining encrypted keys inside stretch
                p2 = 0
                while p2 + 8 <= len(rest):
                    s2, t2, f2 = struct.unpack_from("<IHH", rest, p2)
                    if s2 < 8 or p2 + s2 > len(rest):
                        break
                    pl2 = rest[p2 + 8 : p2 + s2]
                    if t2 == 5:
                        ccms.append(pl2)
                    p2 += s2
            elif ntype == 5:
                ccms.append(pl)
            pos += size32
        info["n_ccm"] = len(ccms)
        if salt is None:
            results.append(info)
            continue
        keys_try = []
        keys_try.append(("pad32", stretch(rk, salt)))
        keys_try.append(("sha256", stretch(hashlib.sha256(rk).digest(), salt)))
        keys_try.append(("dsha256", stretch(hashlib.sha256(hashlib.sha256(rk).digest()).digest(), salt)))
        for label, key in keys_try:
            for i, ccm in enumerate(ccms):
                nonce = ccm[:12]
                mac = ccm[-16:]
                ct = ccm[12:-16]
                try:
                    aes = AESCCM(key[:16], tag_length=16)
                    pt = aes.decrypt(nonce, ct + mac, None)
                    info["unlocked"] = True
                    info["method"] = label
                    info["ccm_index"] = i
                    info["plaintext_hex"] = pt.hex()
                    info["pt_len"] = len(pt)
                    break
                except Exception as e:
                    info.setdefault("errors", []).append("%s/%d:%s" % (label, i, type(e).__name__))
            if info.get("unlocked"):
                break
        results.append(info)
    json.dump({"rk": rk.hex(), "results": results}, sys.stdout)
    print()

if __name__ == "__main__":
    main()
