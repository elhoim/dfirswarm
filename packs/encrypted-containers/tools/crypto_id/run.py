#!/usr/bin/env python3
"""Name the scheme before anybody spends an hour on it.

Every one of these leaves a signature except the one whose entire purpose is not
leaving one, and telling them apart costs a single read of the first few
kilobytes. The output also answers the question worth asking before any other:
whether the metadata alone says it can be opened without a secret.

    BitLocker        "-FVE-FS-" at offset 3 of the volume
    BitLocker To Go  a FAT header with an FVE metadata block behind it
    LUKS1 / LUKS2    "LUKS\\xba\\xbe" at offset 0, then the version
    FileVault        an Apple Core Storage signature, or an encrypted APFS volume
    VeraCrypt        nothing at all: high entropy from byte zero, no magic

LUKS1 key slots are readable from the header without any key, and the count is a
finding on its own: each enabled slot is a separate passphrase that opens the
volume, so a machine that should have one and has three has been given access by
somebody.
"""
import json
import math
import os
import struct
import sys

LUKS_MAGIC = b"LUKS\xba\xbe"
SLOT_ENABLED = 0x00AC71F3
SLOT_DISABLED = 0x0000DEAD


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def entropy(blob):
    if not blob:
        return 0.0
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    out, total = 0.0, len(blob)
    for count in counts:
        if count:
            p = count / total
            out -= p * math.log2(p)
    return round(out, 3)


def text(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def read_luks(head):
    version, = struct.unpack_from(">H", head, 6)
    out = {"scheme": "LUKS%d" % version, "version": version}
    if version == 1:
        out["cipher"] = text(head[8:40])
        out["cipher_mode"] = text(head[40:72])
        out["hash"] = text(head[72:104])
        out["key_bytes"], = struct.unpack_from(">I", head, 108)
        out["uuid"] = text(head[168:208])
        slots = []
        for i in range(8):
            at = 208 + i * 48
            if at + 48 > len(head):
                break
            active, iterations, _salt_at, stripes = struct.unpack_from(">IIII", head, at)
            slots.append({"slot": i,
                          "state": "enabled" if active == SLOT_ENABLED else
                                   ("disabled" if active == SLOT_DISABLED else hex(active)),
                          "iterations": iterations, "stripes": stripes})
        out["key_slots"] = slots
        out["enabled_slots"] = sum(1 for s in slots if s["state"] == "enabled")
    else:
        out["note"] = ("LUKS2 keeps its metadata as JSON after the binary header; "
                       "cryptsetup luksDump reads the slots and any tokens.")
        out["uuid"] = text(head[24:64])
    return out


def identify(head, sample):
    if head[3:11] == b"-FVE-FS-":
        return {"scheme": "BitLocker",
                "can_metadata_say_more": True,
                "next": "bdeinfo lists every key protector, including a clear key, with no secret"}
    if head[0:6] == LUKS_MAGIC:
        return read_luks(head)
    if head[3:11] == b"MSWIN4.1" and b"-FVE-FS-" in head[:4096]:
        return {"scheme": "BitLocker To Go",
                "next": "the plain FAT discovery volume is why this can look unencrypted"}
    if head[0:2] == b"\x43\x53" or head[88:96] == b"CS\x00\x00\x00\x00\x00\x00":
        return {"scheme": "Apple Core Storage, possibly FileVault"}
    if head[32:36] == b"NXSB":
        return {"scheme": "APFS container",
                "next": "fsapfsinfo says whether any volume inside it is encrypted"}
    if head[0:4] == b"\x50\x4b\x03\x04":
        return {"scheme": "ZIP container", "next": "archive_probe says whether it is protected"}
    if head[0:6] == b"7z\xbc\xaf\x27\x1c":
        return {"scheme": "7-Zip container", "next": "archive_probe says whether it is protected"}
    if head[0:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {"scheme": "OLE compound file",
                "next": "an EncryptionInfo stream inside it means the document is protected"}
    if head[0:5] == b"%PDF-":
        return {"scheme": "PDF", "next": "archive_probe reads its encryption dictionary"}
    value = entropy(sample)
    if value >= 7.9 and not any(head[:16]):
        return {"scheme": "no signature, high entropy, header zeroed",
                "entropy": value,
                "candidates": ["VeraCrypt", "a detached-header LUKS volume", "wiped space"],
                "next": "VeraCrypt leaves nothing on purpose; the exhibit list and the volume's "
                        "size usually settle which of these it is"}
    if value >= 7.9:
        return {"scheme": "no signature, high entropy", "entropy": value,
                "candidates": ["VeraCrypt", "a detached-header LUKS volume", "compressed data"],
                "next": "high entropy alone is not encryption: an archive reads the same way"}
    return {"scheme": "not encrypted, or not a scheme this tool knows", "entropy": value}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a volume image, a partition or a file")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    offset = args.get("offset", 0) or 0
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        fail("offset must be a byte offset, not a sector offset", offset=args.get("offset"))
    window = args.get("entropy_sample", 65536)
    if not isinstance(window, int) or isinstance(window, bool) or window < 1024:
        fail("entropy_sample must be an integer of at least 1024")

    size = os.path.getsize(path)
    if offset >= size:
        fail("the offset is past the end of the file", offset=offset, bytes=size)
    with open(path, "rb") as fh:
        fh.seek(offset)
        head = fh.read(8192)
        fh.seek(offset)
        sample = fh.read(window)

    body = identify(head, sample)
    print(json.dumps({
        "path": path, "offset_bytes": offset, "bytes": size,
        **body,
        "head_hex": head[:32].hex(),
        "note": "An unreadable volume is not necessarily encrypted: rule out a logical volume "
                "manager, a damaged partition table and a wrong offset first, because those are "
                "cheaper to fix and far more common. Note the unit: this tool takes a BYTE offset, "
                "where mmls and the Sleuth Kit work in sectors.",
    }, indent=2))


if __name__ == "__main__":
    main()
