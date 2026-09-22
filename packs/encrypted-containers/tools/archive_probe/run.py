#!/usr/bin/env python3
"""Say what kind of protection a container carries, and what is readable anyway.

The question people ask is "can we open it". The question that decides an
exfiltration case is usually different: **are the file names readable**. A
standard ZIP or 7-Zip archive leaves its central directory in the clear, so the
list of names, sizes and timestamps is available with no password at all — and a
list of names is often the whole answer. Header encryption hides that too, and
the difference is worth reporting explicitly.

The other distinction that matters: a PDF has two passwords. The user password
opens it; the owner password restricts printing and copying. A PDF with an empty
user password and only an owner password set is not meaningfully encrypted — it
opens with nothing, and the restriction is advisory. Reporting one as a
protected document is a mistake this tool exists to prevent.
"""
import json
import os
import re
import struct
import sys
import zipfile

ZIP_ENCRYPTED = 0x0001
ZIP_STRONG = 0x0040


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def probe_zip(path, limit):
    out = {"container": "ZIP", "entries": [], "encrypted_entries": 0, "schemes": set()}
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return {"container": "ZIP", "error": str(exc)}
    with archive:
        for info in archive.infolist()[:limit]:
            encrypted = bool(info.flag_bits & ZIP_ENCRYPTED)
            scheme = None
            if encrypted:
                out["encrypted_entries"] += 1
                if info.compress_type == 99:
                    scheme = "AES (WinZip)"
                elif info.flag_bits & ZIP_STRONG:
                    scheme = "strong encryption"
                else:
                    scheme = "ZipCrypto (legacy, weak)"
                out["schemes"].add(scheme)
            out["entries"].append({"name": info.filename, "bytes": info.file_size,
                                   "compressed": info.compress_size,
                                   "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
                                   "encrypted": encrypted, "scheme": scheme})
    out["schemes"] = sorted(out["schemes"])
    out["names_readable"] = True
    out["protected"] = out["encrypted_entries"] > 0
    if "ZipCrypto (legacy, weak)" in out["schemes"]:
        out["note"] = ("ZipCrypto is weak, and where a known file from the same archive is "
                       "available it is breakable outright by known-plaintext. AES-256 is not.")
    return out


def probe_7z(blob):
    # The 7-Zip start header is 32 bytes; an encrypted header makes the names unreadable.
    out = {"container": "7-Zip", "names_readable": None, "protected": None}
    out["note"] = ("7-Zip encrypts the data by default and can encrypt the header as well. "
                   "Where the header is encrypted, even the file names need the password: "
                   "7z l on the file answers in one command, and asks for a password when it "
                   "cannot read the names.")
    readable = re.findall(rb"[\x20-\x7e]{6,}", blob[:4096])
    out["strings_in_header"] = [r.decode("ascii", "replace") for r in readable[:10]]
    return out


def probe_rar(blob):
    version = 5 if blob[:8] == b"Rar!\x1a\x07\x01\x00" else 4
    return {"container": "RAR%d" % version,
            "protected": None,
            "note": "RAR carries a per-file check value, which is enough to verify a password "
                    "without extracting. RAR5 can encrypt the file names as well; where it has, "
                    "unrar l asks for a password before listing anything."}


def probe_pdf(blob):
    encrypt = b"/Encrypt" in blob
    out = {"container": "PDF", "protected": encrypt}
    if not encrypt:
        out["note"] = "No encryption dictionary: this document opens with nothing."
        return out
    # The encryption dictionary is usually an indirect object, so /V and /R are not
    # beside /Encrypt. Read them from wherever in the file they are declared.
    version = re.search(rb"/V\s+(\d+)", blob)
    revision = re.search(rb"/R\s+(\d+)", blob)
    if version:
        out["v"] = int(version.group(1))
    if revision:
        out["r"] = int(revision.group(1))
    if out.get("r"):
        out["scheme"] = {2: "40-bit RC4", 3: "128-bit RC4", 4: "128-bit RC4 or AES-128",
                         5: "AES-256 (older draft)", 6: "AES-256"}.get(out["r"], "revision %d" % out["r"])
    permissions = re.search(rb"/P\s+(-?\d+)", blob)
    if permissions:
        out["permissions_flags"] = int(permissions.group(1))
    out["note"] = ("A PDF has two passwords. The user password opens it; the owner password only "
                   "restricts printing and copying. Try opening it with an EMPTY user password "
                   "first: a document with only an owner password set opens with nothing, and the "
                   "restriction is advisory. Do not report that one as protected.")
    return out


def probe_ole(blob):
    protected = b"EncryptionInfo" in blob or b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n" in blob
    return {"container": "OLE compound file", "protected": protected,
            "note": "An EncryptionInfo stream names the algorithm and the key derivation. The "
                    "2007-era scheme and the 2013-and-later one differ by orders of magnitude in "
                    "cost, and an older .doc may use 40-bit RC4, which is trivially breakable."
            if protected else "No EncryptionInfo stream: this document is not encrypted."}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: an archive or a document")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit", 200)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")

    with open(path, "rb") as fh:
        blob = fh.read(8 << 20)
    head = blob[:8]
    if head[:4] == b"PK\x03\x04":
        body = probe_zip(path, limit)
    elif head[:6] == b"7z\xbc\xaf\x27\x1c":
        body = probe_7z(blob)
    elif head[:4] == b"Rar!":
        body = probe_rar(blob)
    elif head[:5] == b"%PDF-":
        body = probe_pdf(blob)
    elif head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        body = probe_ole(blob)
    else:
        fail("this is not a container this tool reads", path=path, head_hex=head.hex(),
             reads=["ZIP", "7-Zip", "RAR", "PDF", "OLE compound file"])

    print(json.dumps({
        "path": path, "bytes": os.path.getsize(path), **body,
        "reminder": "Whether the file NAMES are readable is often the whole answer to an "
                    "exfiltration question, and it is a different question from whether the data "
                    "can be decrypted. Report both.",
    }, indent=2))


if __name__ == "__main__":
    main()
