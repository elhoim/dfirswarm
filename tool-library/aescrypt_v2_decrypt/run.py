#!/usr/bin/env python3
import json, os, sys
from hashlib import sha256
from hmac import new as hmac_new, compare_digest
from pathlib import Path

def kdf(pwb, iv, n=8192):
    digest = iv + b"\x00" * 16
    for _ in range(n):
        digest = sha256(digest + pwb).digest()
    return digest

def aes_cbc_decrypt(key, iv, data):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()
    except ImportError:
        sys.stderr.write("cryptography required\n")
        sys.exit(2)

def fail(msg, **extra):
    print(json.dumps({"ok": False, "error": msg, **extra}))
    sys.exit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place a decrypted secret
    must never appear -- a later integrity check would report the evidence
    as modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest

def main():
    args = json.load(sys.stdin)
    path = Path(args["path"])
    password = args.get("password")
    if not isinstance(password, str) or not password:
        fail("password is required")
    agent = os.environ.get("AGENT_ID") or "agent"
    out = args.get("output")
    if not out:
        stem = path.name[:-4] if path.name.endswith(".aes") else path.name
        out = f"work/extracted/{agent}/{stem}"
    dest = resolve_output(str(out))
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail("cannot read file", path=str(path), reason=exc.strerror or str(exc))
    if data[:3] != b"AES":
        fail("not AES magic")
    # Extension headers: a big-endian uint16 length, then that many bytes,
    # terminated by a zero length. A truncated file must be named as such
    # rather than indexed past its end, which would raise where the harness
    # can only report a traceback.
    off = 5
    while True:
        if off + 2 > len(data):
            fail("truncated extension headers", size=len(data))
        ln = int.from_bytes(data[off:off+2], "big")
        off += 2
        if ln == 0:
            break
        off += ln
    # From here: IV (16), the encrypted IV+key (48), its HMAC (32), then the
    # ciphertext, the last block's valid byte count (1) and its HMAC (32).
    if off + 96 + 33 > len(data):
        fail("truncated AES Crypt file", size=len(data), header_end=off)
    iv1 = data[off:off+16]
    enc = data[off+16:off+64]
    mac1 = data[off+64:off+96]
    rest = data[off+96:]
    mac2 = rest[-32:]
    last_size = rest[-33]
    ct = rest[:-33]
    if len(ct) % 16:
        fail("ciphertext is not a whole number of AES blocks", ciphertext=len(ct))
    pwb = password.encode("utf-16-le")
    key1 = kdf(pwb, iv1)
    hmac1_ok = compare_digest(hmac_new(key1, enc, sha256).digest(), mac1)
    if not hmac1_ok:
        fail("HMAC failed", hmac1=False)
    ivkey = aes_cbc_decrypt(key1, iv1, enc)
    iv0, key0 = ivkey[:16], ivkey[16:48]
    hmac2_ok = compare_digest(hmac_new(key0, ct, sha256).digest(), mac2)
    if not hmac2_ok:
        fail("HMAC failed", hmac1=True, hmac2=False)
    pt = aes_cbc_decrypt(key0, iv0, ct)
    # 0 means the last block is full; 1..15 is how many of its bytes count.
    if 1 <= last_size <= 15:
        pt = pt[: -(16 - last_size)]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(pt)
    print(json.dumps({
        "ok": True,
        "hmac1": True,
        "hmac2": True,
        "last_size": last_size,
        "size": len(pt),
        "sha256": sha256(pt).hexdigest(),
        "output": out,
        "preview": pt.decode("utf-8", "replace")[:500],
    }))

if __name__ == "__main__":
    main()
