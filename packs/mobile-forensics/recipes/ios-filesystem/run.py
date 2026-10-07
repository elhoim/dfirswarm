#!/usr/bin/env python3
"""Catalogue the forensic structures in an iOS full file-system tar.

The recipe is deliberately structural. It reads every tar header and no member
body, so the catalogue says which parser targets exist without turning a path
into a finding or extracting protected content.

Names are kept as the archive spelled them. A member name is never trimmed
(a leading dot or slash is part of it): `path` shows it with tabs, newlines,
backslashes and bytes that are not UTF-8 escaped, and `path_b64` is its exact
bytes. `n` is the member's position in the archive, from 0, so two members of
one name are two rows, and a database that occurs twice keeps both sizes and
both positions (sqlite.tsv: sizes joined with `|`, `members` listing
role=position). The classification of a name reads a lower-cased copy; the copy
is never what is written.

The database families are grouped in a scratch SQLite file under the output
(deleted when the run ends), so a very large archive does not hold them in
memory, and the artefact rows are written as they are met.
"""
import argparse
import base64
import datetime
import json
import os
import sqlite3
import sys
import tarfile


IOS_MARKERS = (
    "private/var/mobile/",
    "private/var/containers/",
    "system/library/coreservices/systemversion.plist",
)
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata")
ROLES = ("db", "wal", "shm", "journal")


def target_of(value):
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    target = json.loads(text)
    paths = target.get("paths") or []
    if not paths or not isinstance(paths[0], str):
        raise ValueError("the target names no path")
    return target, paths[0]


def escaped(value):
    """One line, one field, nothing hidden; a byte that is not UTF-8 shows as \\xNN."""
    out = []
    for ch in value:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def b64(value):
    return base64.b64encode(value.encode("utf-8", "surrogateescape")).decode("ascii")


def utc(value):
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def classify(path):
    low = "/" + path.lower().strip("/")
    base = low.rsplit("/", 1)[-1]
    if base in ("sms.db", "callhistory.storedata", "addressbook.sqlitedb"):
        return "communications"
    if base == "knowledgec.db" or "/coreduet/knowledge/" in low:
        return "knowledge"
    if "/biome/" in low or "/biomestreams/" in low or base.endswith(".segb"):
        return "biome-segb"
    if ("/uuidtext/" in low or "/timesync/" in low or "/logd/" in low
            or base.endswith(".tracev3") or ".logarchive/" in low):
        return "unified-log"
    if "/keychains/" in low or base in ("keychain-2.db", "keychain-backup.plist"):
        return "keychain"
    if base == "photos.sqlite" or "/photodata/" in low:
        return "photos"
    if (base == ".com.apple.mobile_container_manager.metadata.plist"
            or "/mobileinstallation/" in low or base == "applicationstate.db"):
        return "app-container-map"
    if base in ("systemversion.plist", "lastbuildinfo.plist"):
        return "device-info"
    return None


def sqlite_base(path):
    low = path.lower()
    for suffix in ("-wal", "-shm", "-journal"):
        if low.endswith(suffix):
            return path[:-len(suffix)], suffix[1:]
    if low.endswith(SQLITE_SUFFIXES):
        return path, "db"
    return None, None


def tar_mode(path):
    """How to open the tar: a compressed one by its magic, in stream mode, and
    a plain one header to header. tarfile's "r:*" tries every decompressor in
    turn, and the LZMA one reads a run of zeros as a stream: 64 MiB of them
    took it half a minute, and the census asks this recipe about every input,
    disk and memory images that start with zeros included."""
    with open(path, "rb") as fh:
        head = fh.read(6)
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        return "r|*"
    return "r:"


def open_tar(path):
    return tarfile.open(path, tar_mode(path), encoding="utf-8", errors="surrogateescape")


def detect(path):
    if not os.path.isfile(path):
        return False, "not a readable file"
    try:
        with open_tar(path) as archive:
            for member in archive:
                low = member.name.lower()
                if any(marker in low for marker in IOS_MARKERS):
                    return True, "tar members have an iOS full file-system root"
    except (tarfile.TarError, OSError) as exc:
        return False, "not a readable tar: %s" % exc
    return False, "tar has no iOS full file-system marker"


def run(path, out):
    os.makedirs(out, exist_ok=True)
    artifacts_path = os.path.join(out, "artifacts.tsv")
    sqlite_path = os.path.join(out, "sqlite.tsv")
    scratch = os.path.join(out, "sqlite-families.work.db")
    if os.path.lexists(scratch):
        os.unlink(scratch)
    work = sqlite3.connect(scratch)
    work.execute("CREATE TABLE m (base BLOB NOT NULL, role TEXT NOT NULL, size INTEGER NOT NULL, n INTEGER NOT NULL)")
    members = 0
    families_rows = 0
    categories = {}
    artifact_rows = 0
    errors = []
    try:
        with open(artifacts_path, "w", encoding="utf-8", newline="\n") as artifacts:
            artifacts.write("category\tpath\tbytes\tmtime_utc\ttype\tn\tpath_b64\n")
            try:
                with open_tar(path) as archive:
                    for member in archive:
                        name = member.name
                        category = classify(name)
                        if category:
                            categories[category] = categories.get(category, 0) + 1
                            artifact_rows += 1
                            artifacts.write("%s\t%s\t%d\t%s\t%s\t%d\t%s\n" % (
                                category, escaped(name), member.size, utc(member.mtime),
                                "file" if member.isfile() else "other", members, b64(name)))
                        base, role = sqlite_base(name)
                        if base is not None:
                            work.execute("INSERT INTO m VALUES (?,?,?,?)", (base.encode("utf-8", "surrogateescape"), role, member.size, members))
                            families_rows += 1
                        members += 1
                        archive.members = []
            except (tarfile.TarError, EOFError, OSError) as exc:
                errors.append("tar traversal stopped: %s" % exc)
        work.execute("CREATE INDEX m_base ON m (base, n)")
        work.commit()
        databases = 0
        with open(sqlite_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\tpath_b64\tmembers\n")
            bases = [row[0] for row in work.execute("SELECT DISTINCT base FROM m ORDER BY base")]
            for base in bases:
                sizes = {role: [] for role in ROLES}
                where = []
                for role, size, n in work.execute("SELECT role, size, n FROM m WHERE base = ? ORDER BY n", (base,)):
                    sizes[role].append(str(size))
                    where.append("%s=%d" % (role, n))
                name = base.decode("utf-8", "surrogateescape")
                handle.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    escaped(name), "|".join(sizes["db"]), "|".join(sizes["wal"]), "|".join(sizes["shm"]),
                    "|".join(sizes["journal"]), base_to_b64(base), ",".join(where)))
                databases += 1
    finally:
        work.close()
        try:
            os.unlink(scratch)
        except OSError:
            pass
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("file\twhat\n")
        handle.write("artifacts.tsv\tiOS forensic structures by category, path, size, archive mtime and member position (path_b64 is the exact name)\n")
        handle.write("sqlite.tsv\tSQLite-family files grouped with WAL, SHM and rollback-journal companions: every occurrence's size and member position (| joins repeats)\n")
    coverage = {
        "recipe": "ios-filesystem",
        "status": "partial" if errors else "complete",
        "covered": "%d tar members; %d forensic structures; %d SQLite families" % (members, artifact_rows, databases),
        "categories": dict(sorted(categories.items())),
        "not_covered": "artifact contents, deleted data, decryption, semantic findings, nested archives",
        "limits_hit": [],
        "errors": errors,
    }
    with open(os.path.join(out, "coverage.json"), "w", encoding="utf-8") as handle:
        json.dump(coverage, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return coverage


def base_to_b64(base):
    return base64.b64encode(base).decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "run"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--out")
    # The kickoff's census asks every detect step with --probe-out DIR, a
    # place for what the probe wants kept (evidence_catalog.py). Refused here,
    # it was a usage error (exit 2) for every input of a run, and a phone's
    # tar was catalogued as a member list only. Detect reads tar headers
    # and keeps nothing, so the directory is taken and left empty.
    parser.add_argument("--probe-out")
    args = parser.parse_args()
    try:
        _, path = target_of(args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    if args.command == "detect":
        applies, why = detect(path)
        print(json.dumps({"applies": applies, "why": why}))
        return 0 if applies else 1
    if not args.out:
        print(json.dumps({"ok": False, "error": "run needs --out DIR"}))
        return 2
    applies, why = detect(path)
    if not applies:
        print(json.dumps({"ok": False, "status": "unsupported", "why": why}))
        return 2
    coverage = run(path, args.out)
    print(json.dumps({"ok": True, "status": coverage["status"], "artifacts": sum(coverage["categories"].values())}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
