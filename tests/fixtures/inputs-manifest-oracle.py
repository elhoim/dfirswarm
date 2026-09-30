# The Python program swarm.sh carried as write_inputs_manifest, kept verbatim
# as the oracle scripts/inputs-manifest.ts is held to, byte for byte
# (tests/inputs-manifest.test.sh). Not run by the harness.
import base64, hashlib, json, os, stat as _stat, sys, time
sandbox, src, enforce, guard, held, verify, quarantine = sys.argv[1:8]
root = os.path.join(sandbox, "inputs")
# (name, source, where it is under inputs/): one set is inputs/ itself.
pairs = sys.argv[8:]
sets = [(pairs[i], pairs[i + 1], os.path.join(root, pairs[i])) for i in range(0, len(pairs) - 1, 2)] or [(None, src, root)]

def named(entry, key, value):
    # A name is bytes on disk. One that is not UTF-8 (a Windows-1254 or
    # Latin-1 name from an archive, on ext4) is kept exactly as base64 in
    # `<key>_b64`, with a readable `<key>` beside it; a reader opens the
    # bytes. Written as the text Python decoded it to, the name was a
    # different one to every reader in another language, and untouched
    # evidence was "missing" and "added" at once.
    raw = os.fsencode(value)
    try:
        entry[key] = raw.decode("utf-8")
    except UnicodeDecodeError:
        entry[key] = raw.decode("utf-8", "replace")
        entry[key + "_b64"] = base64.b64encode(raw).decode("ascii")

def rel(abs_path):
    return os.path.relpath(abs_path, sandbox).replace(os.sep, "/")

files, total = [], 0
# Each set's entries in `files`, [from, to), and its bytes.
spans = []
for set_name, set_src, set_root in sets:
    start, start_total = len(files), total
    # A set held in place is the link at inputs/<name> (or inputs/ itself):
    # the walk starts through it.
    for dirpath, dirnames, filenames in os.walk(set_root):
        dirnames.sort()
        # A link inside the evidence — to a file or to a directory — is recorded
        # as the link it is, with its target, and never followed: the same rule
        # the agents' check, the pack's check_inputs and host custody apply, so
        # a link that was there at the start is never reported as changed.
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            abs_path = os.path.join(dirpath, name)
            if os.path.islink(abs_path):
                target = os.readlink(abs_path)
                entry = {}
                named(entry, "path", rel(abs_path))
                entry["bytes"] = 0
                entry["sha256"] = hashlib.sha256(b"link:" + os.fsencode(target)).hexdigest()
                named(entry, "link", target)
                files.append(entry)
                continue
            if not os.path.isfile(abs_path):
                # A FIFO, a socket or a device node (an extracted Linux root has
                # them): recorded by its kind and never opened, so every walk —
                # the VMs' probe, the agents' check, custody — counts the same
                # names and a change of kind is a change.
                mode = os.lstat(abs_path).st_mode
                kind = "fifo" if _stat.S_ISFIFO(mode) else "socket" if _stat.S_ISSOCK(mode) else "char" if _stat.S_ISCHR(mode) else "block" if _stat.S_ISBLK(mode) else None
                if kind:
                    entry = {}
                    named(entry, "path", rel(abs_path))
                    entry["bytes"] = 0
                    entry["sha256"] = hashlib.sha256(("special:" + kind).encode()).hexdigest()
                    entry["special"] = kind
                    files.append(entry)
                continue
            # The three digests a court and an imager's log speak in, from one
            # read: SHA-256 is what every check here compares; MD5 and SHA-1 are
            # for matching the acquisition hashes an imager recorded.
            sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
            with open(abs_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha256.update(chunk)
                    sha1.update(chunk)
                    md5.update(chunk)
            st = os.stat(abs_path)
            total += st.st_size
            entry = {}
            named(entry, "path", rel(abs_path))
            entry.update({
                "bytes": st.st_size,
                "sha256": sha256.hexdigest(),
                "sha1": sha1.hexdigest(),
                "md5": md5.hexdigest(),
                # The stat after the chmod (copy) or as found (bind, image); the
                # harness trusts the sha while these hold.
                "mtime_ms": st.st_mtime_ns // 1_000_000,
                "ctime_ms": st.st_ctime_ns // 1_000_000,
            })
            if held != "copy":
                entry["mode"] = oct(st.st_mode & 0o777)[2:]
                entry["links"] = st.st_nlink
            files.append(entry)
    spans.append((start, len(files), total - start_total))

# A copy is checked against its source, name by name, kind and size: a
# case-sensitive source (ext4, an SMB share) with File.txt and file.txt, or
# the two Unicode forms of one name, merged silently on a case-insensitive
# volume, and a short read on a network volume went unnoticed — the manifest
# then vouched for what survived. The source's names are walked as the copy
# was made: links as links, a top-level link to the file or directory it
# names.
problems = []
if held == "copy":
    def kind_size(st):
        if _stat.S_ISLNK(st.st_mode):
            return ("link", 0)
        if _stat.S_ISREG(st.st_mode):
            return ("file", st.st_size)
        if _stat.S_ISDIR(st.st_mode):
            return ("dir", 0)
        return ("special", 0)
    def walk(top):
        seen = {}
        for dirpath, dirnames, filenames in os.walk(top):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                seen[os.fsencode(os.path.relpath(p, top))] = kind_size(os.lstat(p))
        return seen
    # Each set against its own source; a name is said under inputs/, with
    # its set's name in front when there are several.
    for set_name, set_src, set_root in sets:
        under = b"" if set_name is None else os.fsencode(set_name) + b"/"
        source = {}
        for name in os.listdir(set_src):
            p = os.path.join(set_src, name)
            key = os.fsencode(name)
            if os.path.islink(p) and os.path.isdir(p):
                source[key] = ("dir", 0)
                for sub, ks in walk(p).items():
                    source[key + b"/" + sub] = ks
            elif os.path.islink(p) and os.path.isfile(p):
                source[key] = kind_size(os.stat(p))
            else:
                source[key] = kind_size(os.lstat(p))
                if source[key][0] == "dir":
                    for sub, ks in walk(p).items():
                        source[key + b"/" + sub] = ks
        copy = walk(set_root)
        for key in sorted(source):
            if key not in copy:
                problems.append("not in the copy: " + (under + key).decode("utf-8", "replace"))
            elif copy[key] != source[key]:
                problems.append("differs from its source (%s %d, copied as %s %d): %s" % (source[key] + copy[key] + ((under + key).decode("utf-8", "replace"),)))
        for key in sorted(set(copy) - set(source)):
            problems.append("in the copy but not in the source: " + (under + key).decode("utf-8", "replace"))

def disp(value):
    return os.fsencode(value).decode("utf-8", "replace")

# And, unless --no-verify-copy, by content: each copied file's source is
# read again and its SHA-256 compared with the copy's in the manifest. A
# copy that differs from its source by content (a source still being
# written, a short read on a network volume, a bad block) is the manifest
# vouching for bytes the source never had.
content_check = None
if held == "copy" and verify == "1" and not problems:
    started = time.time()
    # Each regular file with its set's source and where that set is under
    # the sandbox: inputs/, or inputs/<name>/.
    regular = []
    for (set_name, set_src, set_root), (lo, hi, _) in zip(sets, spans):
        under = b"inputs/" if set_name is None else b"inputs/" + os.fsencode(set_name) + b"/"
        regular += [(e, os.fsencode(set_src), under) for e in files[lo:hi] if "special" not in e and "link" not in e and "link_b64" not in e]
    want_bytes = sum(e["bytes"] for e, _, _ in regular)
    done_bytes, next_note, hashed, differ = 0, 2 << 30, 0, []
    for e, set_src_b, under in regular:
        raw = base64.b64decode(e["path_b64"]) if "path_b64" in e else e["path"].encode("utf-8")
        source_path = os.path.join(set_src_b, raw[len(under):])
        digest = hashlib.sha256()
        try:
            with open(source_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
                    done_bytes += len(chunk)
                    if want_bytes > (2 << 30) and done_bytes >= next_note:
                        sys.stderr.write("Copy check:   %.1f of %.1f GiB read again from the source\n" % (done_bytes / (1 << 30), want_bytes / (1 << 30)))
                        next_note += 2 << 30
        except OSError as err:
            differ.append("could not be read again from its source (%s): %s" % (err.strerror or err, disp(raw)))
            continue
        hashed += 1
        if digest.hexdigest() != e["sha256"]:
            differ.append("differs from its source by content: " + disp(raw))
    content_check = {"by": "content", "files": hashed, "mismatches": len(differ), "seconds": round(time.time() - started, 1)}
    problems.extend(differ)

# Several sets: `source` names every one, for a reader that shows one line,
# and `sets` says which set each name under inputs/ is, and where it came from.
manifest = {"source": disp(src) if sets[0][0] is None else ", ".join(disp(set_src) for _, set_src, _ in sets)}
if sets[0][0] is not None:
    manifest["sets"] = [
        {"name": set_name, "path": "inputs/" + set_name, "source": disp(set_src), "files": hi - lo, "bytes": set_bytes}
        for (set_name, set_src, _), (lo, hi, set_bytes) in zip(sets, spans)]
manifest.update({
    "copied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "files": files,
    "bytes": total,
    "enforce": enforce,
    "guard": guard,
    "digests": ["sha256", "sha1", "md5"],
    "quarantine": quarantine == "1"})
if held == "copy":
    if problems:
        manifest["source_checked"] = "MISMATCH" if content_check is None else dict(content_check)
    else:
        manifest["source_checked"] = content_check if content_check is not None else "names, kinds and sizes"
# How the evidence is held, always said: every reader words its custody
# line from this (a copy, in place, an attached image).
manifest["held"] = held
if held == "bind":
    manifest["bound"] = True
elif held == "image":
    manifest["attached"] = True
# A manifest left read-only by an earlier kickoff is replaced, not written through.
out_path = os.path.join(sandbox, "inputs.json")
if os.path.lexists(out_path):
    os.unlink(out_path)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
if problems:
    sys.stderr.write("BLOCKER: the copy of the evidence in %s does not match its source %s (%d name%s):\n" % (root, manifest["source"], len(problems), "" if len(problems) == 1 else "s"))
    for line in problems:
        sys.stderr.write("  %s\n" % line)
    sys.stderr.write("A case-insensitive volume merges names that differ only in case or Unicode form, and a short read leaves a file short. Put the run on a volume that keeps the source's names (a case-sensitive APFS volume or the source's own file system), or use --inputs-bind to hold the evidence in place.\n")
    if content_check is not None and content_check["mismatches"]:
        sys.stderr.write("A file that differs by content was changed while it was copied, or read short: make sure nothing writes to the source, and copy again.\n")
    sys.exit(4)
