#!/usr/bin/env python3
"""Parse BitLocker FVE metadata from a volume (raw image or partition).

BitLocker stores three metadata *byte* offsets in the volume header
(typically 0xA0, 0xA8, 0xB0). Each block is kilobytes and begins with
``-FVE-FS-``. The three 512-byte sectors after the boot sector are not
the metadata.

Field offsets follow the on-disk layout libbde documents: a 64-byte block
header, then a 48-byte metadata header, then variable-size entries. Every
offset here is named against that document rather than found by reading a
volume, because a parser tuned to one image prints plausible nonsense for
every other one.
"""
from __future__ import annotations

import json
import struct
import sys
import uuid
from pathlib import Path

FVE_SIG = b"-FVE-FS-"
# libbde / Microsoft encryption method codes.
ENCRYPTION = {
    0x8000: "AES-CBC 128 + Elephant diffuser",
    0x8001: "AES-CBC 256 + Elephant diffuser",
    0x8002: "AES-CBC 128",
    0x8003: "AES-CBC 256",
    0x8004: "AES-XTS 128",
    0x8005: "AES-XTS 256",
}
# VMK protection types: uint16 26 bytes into a VMK entry's data, which is
# 34 bytes into the entry (the 8-byte entry header, a 16-byte key GUID, an
# 8-byte modification time and 2 unknown bytes come first).
PROTECTORS = {
    0x0000: "cleared",
    0x0100: "TPM",
    0x0200: "startup key",
    0x0500: "TPM+PIN",
    0x0800: "recovery password",
    0x2000: "password",
}
VMK_ENTRY_TYPE = 0x0002
VMK_PROTECTION_TYPE_AT = 34
# An entry has to reach past that field for it to mean anything.
VMK_MIN_ENTRY_SIZE = VMK_PROTECTION_TYPE_AT + 2

# Volume header: three little-endian uint64 byte offsets.
METADATA_OFFSETS_IN_HEADER = (0xA0, 0xA8, 0xB0)
BLOCK_HEADER_SIZE = 64
METADATA_HEADER_SIZE = 48
# Encryption method, uint32, 36 bytes into the metadata header.
ENCRYPTION_METHOD_AT = 36
MAX_METADATA = 1_048_576


def fail(msg: str, **extra: object) -> None:
    print(json.dumps({"error": msg, **extra}))
    raise SystemExit(1)


def read_at(path: Path, offset: int, n: int) -> bytes:
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(n)
    if len(data) < n:
        fail("short read", offset=offset, wanted=n, got=len(data))
    return data


def parse_block(path: Path, volume_base: int, meta_off: int) -> dict | None:
    if meta_off == 0:
        return None
    abs_off = volume_base + meta_off
    head = read_at(path, abs_off, BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE)
    if head[:8] != FVE_SIG:
        return None
    # The metadata header follows the block header. Its first field is the
    # size of the metadata -- that header and every entry, block header
    # excluded -- and the field 12 bytes in repeats it. Checking the two
    # against each other is what separates a correct read from a coincidence:
    # the block header's own size field at +8 is 64, not the metadata size,
    # and reading it as the metadata size yields a number that passes a
    # plausibility check and then walks entries over arbitrary bytes.
    size, _version, header_size, size_copy = struct.unpack_from("<IIII", head, BLOCK_HEADER_SIZE)
    if size != size_copy:
        fail(
            "FVE metadata size disagrees with its copy",
            offset=abs_off,
            size=size,
            size_copy=size_copy,
        )
    if size < METADATA_HEADER_SIZE or size > MAX_METADATA:
        fail("implausible FVE metadata size", offset=abs_off, size=size)
    if header_size < METADATA_HEADER_SIZE or header_size > size:
        fail(
            "implausible FVE metadata header size",
            offset=abs_off,
            header_size=header_size,
            size=size,
        )
    meta = read_at(path, abs_off + BLOCK_HEADER_SIZE, size)
    guid = str(uuid.UUID(bytes_le=meta[16:32]))
    enc = struct.unpack_from("<I", meta, ENCRYPTION_METHOD_AT)[0]
    protectors: list[str] = []
    cursor = header_size
    while cursor + 8 <= len(meta):
        entry_size, entry_type, _value_type, _ver = struct.unpack_from("<HHHH", meta, cursor)
        # A zero or undersized length would loop forever or read the next
        # entry's header as data; stop rather than guess where the next one is.
        if entry_size < 8 or cursor + entry_size > len(meta):
            break
        if entry_type == VMK_ENTRY_TYPE and entry_size >= VMK_MIN_ENTRY_SIZE:
            ptype = struct.unpack_from("<H", meta, cursor + VMK_PROTECTION_TYPE_AT)[0]
            protectors.append(PROTECTORS.get(ptype, f"0x{ptype:04x}"))
        cursor += entry_size
    return {
        "offset": abs_off,
        "volume_guid": guid,
        "encryption_method": ENCRYPTION.get(enc, hex(enc)),
        "encryption_code": enc,
        "key_protectors": protectors,
        "recovery_password_protector": "recovery password" in protectors,
    }


def main() -> None:
    args = json.load(sys.stdin)
    path = Path(args.get("path") or "")
    volume_base = int(args.get("raw_offset") or 0)
    if not path.is_file():
        fail("image not found", path=str(path))
    boot = read_at(path, volume_base, 512)
    if FVE_SIG not in boot:
        fail("No -FVE-FS- signature found", offset=volume_base, first_bytes=boot[:32].hex())
    blocks = []
    for loc in METADATA_OFFSETS_IN_HEADER:
        meta_off = struct.unpack_from("<Q", boot, loc)[0]
        parsed = parse_block(path, volume_base, meta_off)
        if parsed:
            blocks.append(parsed)
    if not blocks:
        fail(
            "volume header has -FVE-FS- but no FVE metadata blocks at the 0xA0/0xA8/0xB0 offsets",
            offset=volume_base,
        )
    primary = blocks[0]
    print(
        json.dumps(
            {
                "volume_guid": primary["volume_guid"],
                "encryption_method": primary["encryption_method"],
                "key_protectors": primary["key_protectors"],
                "recovery_password_protector": primary["recovery_password_protector"],
                "metadata_blocks": blocks,
            }
        )
    )


if __name__ == "__main__":
    main()
