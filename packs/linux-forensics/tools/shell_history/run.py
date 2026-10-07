#!/usr/bin/env python3
"""Collect the shell and client history files under a tree, record by record, in the order the program wrote them.

A history file is not a log. It is written by the shell into the user's own home directory, so clearing
/var/log does nothing to it. It is also not a record of what ran: it holds what the program saved, when it
saved it (a killed shell may never have written its last session; concurrent sessions interleave and
overwrite; HISTCONTROL, HISTIGNORE and an unset HISTFILE leave nothing). Each record says how its
boundaries were found, because they are not the same everywhere:

    bash   with HISTTIMEFORMAT: a `#<epoch>` line, then the entry up to the next such line (a command that
           spans lines is one record). Without it each physical line is a record and a line that ends in
           a backslash is flagged: whether the next line continues it is not in the file.
    zsh    EXTENDED_HISTORY: `: <epoch>:<elapsed>;<command>`; a trailing backslash is read as zsh's
           escape for a newline inside the command, so a command that really ended in a backslash cannot
           be told from one that continues. A line with no header is a plain entry of that file. Bytes zsh
           stores in its Meta encoding (0x83 then the byte xor 0x20) are decoded and flagged.
    fish   `- cmd: <command>` with `when: <epoch>` and an optional `paths:` list; fish writes a newline in
           a command as the two characters \\n and a backslash as \\\\, both decoded.
    plain  every other client history (python, mysql, psql, redis-cli, node, sh, ash): one entry per
           physical line, no time. A client may escape characters its own way (the mysql client writes a
           space as \\040); the line is kept as written.

The directory a file is in is not the account that owns it. `user` is `unknown` unless the evidence's own
etc/passwd (read from the root given, when it holds one, or from `passwd`) says that exactly one account has
that home; the directory's name is `home_basename`, and is said to be only that.

THE SECRET-SAFE OUTPUT PATTERN (docs/packs.md, "Secrets and sensitive output"). A command line can hold a
password, a token or a key (mysql -p..., curl -H "Authorization: ...", an export of a secret). The answer
therefore carries locators (file, physical lines, byte offset), the time, the program and the length of each
command, and never the command: `write_commands: true` writes every record's text to a file under $OUT
(mode 0600) and `preview_commands: true` puts it in the answer, each only in a job, which the skill says to
run with secret_output: true. Outside a job both are refused. No command is hashed or shortened.

A tool that fails loudly: a directory it could not open, a file it could not read to its end, a link it did
not follow, a top-level directory it left out and a file it knows and does not parse are each named; one
bad file never stops the sweep and never becomes an empty result.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

TOOL = "shell_history"
PARSER = "shell_history/4"
DEFAULT_LIMIT = 200
FIRST_FAILURES = 20
MAX_PIECE = 8 << 20          # a physical line longer than this is read in pieces, none dropped
MAX_RECORD = 8 << 20         # a record longer than this is continued in the next one, none dropped
DEFAULT_SECONDS = 100.0
TEXT_NAME = "shell-history-commands.jsonl"

# file name -> (format, the program that writes it)
NAMES = {
    ".bash_history": ("bash", "bash"), ".zsh_history": ("zsh", "zsh"), "fish_history": ("fish", "fish"),
    ".sh_history": ("plain", "sh"), ".ash_history": ("plain", "ash"), ".history": ("plain", "shell or client"),
    ".python_history": ("plain", "python"), ".mysql_history": ("plain", "mysql"), ".psql_history": ("plain", "psql"),
    ".rediscli_history": ("plain", "redis-cli"), ".node_repl_history": ("plain", "node"),
}
# Known files that are not command histories: named, not read as if they were.
NOT_PARSED = {".lesshst": "less's own state file (search patterns, shell commands, marks): not a command history"}
ZSH = re.compile(rb"^:\s*(\d+):(\d+);(.*)$", re.S)
BASH_STAMP = re.compile(rb"^#(\d{9,})$")
FISH_CMD = re.compile(rb"^- cmd: ?(.*)$", re.S)
FISH_WHEN = re.compile(rb"^  when: ?(\d+)\s*$")
SKIP_TOP = ("proc", "sys", "dev")


# ---- The parts every tool of this pack that pages or keeps text copies (a tool is standalone; none imports another) ----


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def describe(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def want_flag(args, key):
    value = args.get(key, False)
    if not isinstance(value, bool):
        fail("%s must be true or false" % key)
    return value


def want_limit(args):
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        fail("limit must be a positive integer")
    return limit


# Lossless paging (the same in every library tool that pages): the page an agent reads stays small, and when
# there are more rows the whole result is written as JSON Lines under work/<agent>/tool-output (in a job,
# $OUT/tool-output) and named. The file name is a digest of the page's key (a path), never of a value.
class LosslessPage:
    def __init__(self, tool, key, limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page = []
        self.total = 0
        self._out = None
        self._tmp = None
        digest = hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        name = "%s-%s.jsonl" % (self.tool, digest)
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool")
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row):
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row):
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".%s-" % self.path.name)
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self):
        result = {"matched": self.total, "returned": len(self.page), "truncated": self.total > len(self.page)}
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def require_job(flag):
    """What leaves a record's text is held to the secret-safe output pattern (docs/packs.md, "Secrets and
    sensitive output"): the text goes into the answer or into a file only in a job, whose output the skill
    says to seal with secret_output: true. Outside a job the request is refused and nothing is written."""
    if not in_job():
        fail("%s is refused outside a job: a command line, a message or an environment value written or "
             "printed here would be an ordinary file or an ordinary answer, not a sealed output. Run this as "
             "job_run tool=%s with secret_output: true, and ask again there. Nothing was written." % (flag, TOOL))


class TextRefused(Exception):
    pass


class TextFile:
    """Where the text of a tool's records goes when, and only when, the caller asked for it.

    The secret-safe output pattern of recovery_key_scan's SecretValues, for rows. With `enabled` false it
    writes nothing and `summary()` says so. Enabled, it is refused outside a job; inside one the file is
    created before anything is read (mode 0600, exclusively: a file or a link already at that name is
    refused by name) under $OUT, and the answer names it and says it may hold secrets.
    """

    def __init__(self, name, enabled, what, flag="write_text"):
        self.enabled = enabled
        self.written = 0
        self.what = what
        self._fh = None
        self.path = None
        self.shown = None
        if not enabled:
            return
        job, out = os.environ.get("JOB_ID") or "", os.environ.get("OUT") or ""
        if not (job and out):
            raise TextRefused("%s is refused outside a job: the text of the records written here would be an "
                              "ordinary file, not a sealed output. Run this as job_run tool=%s with secret_output: "
                              "true, and ask again there. Nothing was written." % (flag, TOOL))
        self.path = Path(out) / name
        self.shown = "store/jobs/%s/out/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            raise TextRefused("the text file already exists: %s" % self.path)
        except OSError as exc:
            raise TextRefused("the text file could not be created: %s (%s)" % (self.path, describe(exc)))
        self._fh = os.fdopen(fd, "wb")

    def add(self, row):
        if self._fh is None:
            return
        self._fh.write(json.dumps(row, ensure_ascii=False, default=str).encode("utf-8", "replace") + b"\n")
        self.written += 1

    def add_bytes(self, data):
        """One record exactly as its source wrote it (a native export's line, newline included)."""
        if self._fh is None:
            return
        self._fh.write(data)
        self.written += 1

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    def summary(self):
        if not self.enabled:
            return {"requested": False, "written": 0, "file": None, "contains_text_that_may_hold_secrets": False,
                    "hint": "No text of any record is in this answer or in a file. write_text: true, in a job run with "
                            "secret_output: true, keeps the whole of each record in a private file under $OUT."}
        return {"requested": True, "written": self.written, "file": self.shown,
                "contains_text_that_may_hold_secrets": self.written > 0,
                "format": self.what}


def when(epoch):
    """(ISO 8601 UTC time, error) for an epoch-seconds string; the raw value is kept beside it by the caller."""
    try:
        value = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(epoch))
        return value.isoformat() + "Z", None
    except (ValueError, OverflowError):
        return None, "epoch %s is outside the range of a date" % epoch


def unmetafy(data):
    """zsh stores a byte it treats specially as 0x83 followed by the byte xor 0x20."""
    if b"\x83" not in data:
        return data, False
    out, i, changed = bytearray(), 0, False
    while i < len(data):
        if data[i] == 0x83 and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
            changed = True
        else:
            out.append(data[i])
            i += 1
    return bytes(out), changed


def text_of(data):
    return data.decode("utf-8", "replace")


def physical(path):
    """(line number, byte offset, bytes without the newline, continues) for each physical line.

    A line longer than MAX_PIECE comes in pieces that share its number, `continues` true on all but the
    last; nothing is dropped. A read error is raised to the caller, which has the records so far."""
    with open(path, "rb") as fh:
        number, offset = 1, 0
        while True:
            chunk = fh.readline(MAX_PIECE)
            if not chunk:
                return
            ended = chunk.endswith(b"\n")
            yield number, offset, chunk.rstrip(b"\n").rstrip(b"\r") if ended else chunk, not ended and len(chunk) == MAX_PIECE
            offset += len(chunk)
            if ended:
                number += 1


class Record:
    __slots__ = ("start", "end", "offset", "lines", "time_raw", "time", "time_error", "elapsed", "basis", "time_basis",
                 "uncertain", "meta", "split", "continues_previous")

    def __init__(self, start, offset, basis):
        self.start, self.end, self.offset, self.basis = start, start, offset, basis
        self.lines, self.time_raw, self.time, self.time_error, self.elapsed = [], None, None, None, None
        self.time_basis, self.uncertain, self.meta, self.split, self.continues_previous = None, False, False, False, False

    def size(self):
        return sum(len(x) for x in self.lines)


def stamp(rec, raw, basis):
    rec.time_raw = raw
    rec.time, rec.time_error = when(raw)
    rec.time_basis = basis


def bash_records(path, counters):
    """Bash: stamped entries run to the next stamp; with no stamp, each physical line is a record."""
    rec, saw_stamp_before = None, False
    for number, offset, data, _more in physical(path):
        counters["physical"] += 1
        if not data.strip():
            counters["blank"] += 1
            if rec is not None and rec.basis == "bash timestamp line":
                rec.lines.append(data)       # a blank line inside a stamped entry belongs to it
                rec.end = number
            continue
        if ZSH.match(data):
            counters["other_format"]["zsh extended history"] = counters["other_format"].get("zsh extended history", 0) + 1
        found = BASH_STAMP.match(data)
        if found:
            if rec is not None:
                yield rec
            rec = Record(number, offset, "bash timestamp line")
            rec.lines.append(data)
            stamp(rec, text_of(found.group(1)), "bash timestamp line")
            rec.meta = True            # no command line yet
            saw_stamp_before = True
            continue
        if rec is not None and rec.basis == "bash timestamp line":
            if rec.size() >= MAX_RECORD:
                yield rec
                nxt = Record(number, offset, "bash timestamp line")
                nxt.continues_previous, nxt.split = True, True
                rec = nxt
            rec.lines.append(data)
            rec.end = number
            rec.meta = False
            continue
        if rec is not None:
            yield rec
        rec = Record(number, offset, "physical line")
        rec.lines.append(data)
        rec.uncertain = data.endswith(b"\\")
        yield rec
        rec = None
    if rec is not None:
        yield rec


def zsh_records(path, counters):
    rec = None
    for number, offset, data, _more in physical(path):
        counters["physical"] += 1
        if not data.strip():
            counters["blank"] += 1
            continue
        if rec is not None and rec.lines[-1].endswith(b"\\"):
            rec.lines.append(data)
            rec.end = number
            continue
        if rec is not None:
            yield rec
            rec = None
        found = ZSH.match(data)
        if found:
            rec = Record(number, offset, "zsh extended header")
            rec.lines.append(data)
            stamp(rec, text_of(found.group(1)), "zsh extended header")
            rec.elapsed = int(found.group(2))
        else:
            rec = Record(number, offset, "physical line (no zsh header)")
            rec.lines.append(data)
    if rec is not None:
        yield rec


def fish_records(path, counters):
    rec = None
    for number, offset, data, _more in physical(path):
        counters["physical"] += 1
        if not data.strip():
            counters["blank"] += 1
            continue
        found = FISH_CMD.match(data)
        if found:
            if rec is not None:
                yield rec
            rec = Record(number, offset, "fish entry")
            rec.lines.append(data)
            continue
        if rec is None:
            counters["other_lines"] += 1
            continue
        rec.lines.append(data)
        rec.end = number
        when_line = FISH_WHEN.match(data)
        if when_line:
            stamp(rec, text_of(when_line.group(1)), "fish when")
    if rec is not None:
        yield rec


def plain_records(path, counters):
    for number, offset, data, _more in physical(path):
        counters["physical"] += 1
        if not data.strip():
            counters["blank"] += 1
            continue
        rec = Record(number, offset, "physical line")
        rec.lines.append(data)
        yield rec


READERS = {"bash": bash_records, "zsh": zsh_records, "fish": fish_records, "plain": plain_records}


def command_of(fmt, rec):
    """The command a record holds, decoded as its format says, and whether bytes were decoded."""
    changed = False
    if fmt == "bash":
        lines = [x for x in rec.lines if not (rec.basis == "bash timestamp line" and BASH_STAMP.match(x))]
        return "\n".join(text_of(x) for x in lines), False
    if fmt == "zsh":
        first = rec.lines[0]
        found = ZSH.match(first)
        parts = [found.group(3) if found else first] + rec.lines[1:]
        parts = [p[:-1] if i < len(parts) - 1 and p.endswith(b"\\") else p for i, p in enumerate(parts)]
        joined, changed = unmetafy(b"\n".join(parts))
        return text_of(joined), changed
    if fmt == "fish":
        found = FISH_CMD.match(rec.lines[0])
        raw = text_of(found.group(1)) if found else text_of(rec.lines[0])
        return re.sub(r"\\(n|\\)", lambda m: "\n" if m.group(1) == "n" else "\\", raw), False
    return text_of(rec.lines[0]), False


def command_line_count(fmt, command):
    return command.count("\n") + 1 if command else 0


def home_of(dirpath):
    suffix = os.sep + os.path.join(".local", "share", "fish")
    return dirpath[: -len(suffix)] if dirpath.endswith(suffix) else dirpath


def read_passwd(path):
    """{home: [(name, line number)]} from a passwd file."""
    homes = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            fields = line.rstrip("\n").split(":")
            if len(fields) >= 6 and fields[0] and not line.startswith("#"):
                homes.setdefault(fields[5].rstrip("/") or "/", []).append((fields[0], number))
    return homes


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    root = args.get("root")
    if not isinstance(root, str) or not root:
        fail("root is required: a home directory or an extracted file system root")
    if os.path.islink(root):
        fail("refusing a symlink root: pass the extracted evidence directory", root=root, target=os.readlink(root))
    if not os.path.isdir(root):
        fail("no such directory", root=root)
    limit = want_limit(args)
    write_text, preview = want_flag(args, "write_commands"), want_flag(args, "preview_commands")
    if preview:
        require_job("preview_commands")
    pattern = None
    if args.get("contains"):
        try:
            pattern = re.compile(args["contains"], re.I)
        except re.error as exc:
            fail("contains is not a valid regex", reason=str(exc))
    only_user = args.get("user")
    seconds = args.get("max_seconds", DEFAULT_SECONDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
        fail("max_seconds must be a positive number")
    deadline = time.monotonic() + seconds

    # The evidence's own account database, when there is one to read.
    passwd_notes, homes, passwd_path, fs_root = [], {}, None, False
    explicit = args.get("passwd")
    candidate = explicit or os.path.join(root, "etc", "passwd")
    if explicit is not None and not isinstance(explicit, str):
        fail("passwd must be the path of a passwd file")
    if os.path.lexists(candidate):
        if os.path.islink(candidate):
            passwd_notes.append("%s is a link and was not followed" % candidate)
        elif not os.path.isfile(candidate):
            passwd_notes.append("%s is not a file" % candidate)
        else:
            try:
                homes, passwd_path = read_passwd(candidate), candidate
                fs_root = explicit is None
            except OSError as exc:
                passwd_notes.append("%s could not be read: %s" % (candidate, describe(exc)))
    elif explicit is not None:
        passwd_notes.append("%s does not exist" % explicit)
    if passwd_path and not fs_root:
        passwd_notes.append("a passwd file was given but root is not read as a file system root: a home directory's path in the "
                            "tree cannot be mapped to a home in it, so no owner is named")

    try:
        text = TextFile(TEXT_NAME, write_text, "JSON Lines, mode 0600: the record's id and locator as in the answer, "
                        "with `command` (decoded as its format says) and `record_lines` (the physical lines exactly)",
                        flag="write_commands")
    except TextRefused as exc:
        fail(str(exc))
    page = LosslessPage(TOOL, ["records", root, str(pattern.pattern if pattern else ""), only_user, preview], limit)

    files, walk_errors, skipped_symlinks, excluded, not_parsed, read_failures = [], [], [], [], [], []
    seen, seq, matched, with_time, partial_reason = 0, 0, 0, 0, None

    def on_error(exc):
        walk_errors.append({"path": getattr(exc, "filename", None), "error": describe(exc)})

    for dirpath, dirs, names in os.walk(root, onerror=on_error):
        if time.monotonic() > deadline:
            partial_reason = "the walk stopped at max_seconds (%s); directories after %s were not visited" % (seconds, dirpath)
            break
        for name in list(dirs):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
                dirs.remove(name)
            elif dirpath == root and name in SKIP_TOP:
                excluded.append({"path": full, "reason": "the top of the tree's %s: a mounted root's, not evidence (only the top is left out; "
                                                          "a directory of that name deeper in the tree is read)" % name})
                dirs.remove(name)
        for name in sorted(names):
            full = os.path.join(dirpath, name)
            if name in NOT_PARSED:
                not_parsed.append({"file": full, "reason": NOT_PARSED[name]})
                continue
            if name not in NAMES:
                continue
            if os.path.islink(full):
                skipped_symlinks.append({"file": full, "target": os.readlink(full)})
                continue
            fmt, program = NAMES[name]
            home = home_of(dirpath)
            owners = homes.get("/" + os.path.relpath(home, root).replace(os.sep, "/") if home != root else "/", []) if fs_root else []
            if len(owners) == 1:
                user, user_source = owners[0][0], "%s:%d" % ("etc/passwd" if explicit is None else explicit, owners[0][1])
            elif len(owners) > 1:
                user, user_source = "ambiguous", "%d accounts have this home: %s" % (len(owners), ", ".join(o[0] for o in owners))
            else:
                user, user_source = "unknown", None
            base = os.path.basename(home) or home
            if only_user and only_user != (user if user not in ("unknown", "ambiguous") else base):
                continue
            seen += 1
            try:
                stat = os.stat(full)
                size, last = stat.st_size, datetime.datetime.fromtimestamp(stat.st_mtime, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except OSError:
                size, last = None, None
            info = {"file": full, "program": program, "format": fmt, "home": home, "home_basename": base, "user": user,
                    "user_source": user_source, "size": size, "last_written": last, "records": 0, "physical_lines": 0,
                    "blank_lines": 0, "with_timestamps": 0, "timestamps_out_of_order": 0, "partial": False}
            counters = {"physical": 0, "blank": 0, "other_lines": 0, "other_format": {}}
            previous, index = None, 0
            try:
                for rec in READERS[fmt](full, counters):
                    if fmt == "bash" and rec.meta:
                        info["stamps_without_command"] = info.get("stamps_without_command", 0) + 1
                        continue
                    command, decoded = command_of(fmt, rec)
                    index += 1
                    info["records"] += 1
                    if rec.time:
                        info["with_timestamps"] += 1
                        if previous is not None and rec.time < previous:
                            info["timestamps_out_of_order"] += 1
                        previous = rec.time
                    if pattern and not pattern.search(command):
                        continue
                    seq += 1
                    matched += 1
                    if rec.time:
                        with_time += 1
                    command_bytes = len(command.encode("utf-8", "replace"))
                    row = {"id": "H%06d" % seq, "parser": PARSER, "file": full, "program": program, "format": fmt,
                           "home": home, "home_basename": base, "user": user, "index": index,
                           "line_start": rec.start, "line_end": rec.end, "byte_offset": rec.offset,
                           "time_raw": rec.time_raw, "time": rec.time, "time_basis": rec.time_basis,
                           "boundary_basis": rec.basis, "command_bytes": command_bytes,
                           "command_lines": command_line_count(fmt, command)}
                    if user_source:
                        row["user_source"] = user_source
                    if rec.elapsed is not None:
                        row["elapsed_seconds"] = rec.elapsed
                    if rec.time_error:
                        row["time_error"] = rec.time_error
                    if rec.uncertain:
                        row["continuation_uncertain"] = True
                    if decoded:
                        row["unmetafied"] = True
                    if rec.split:
                        row["split_at_cap"] = True
                    text.add({**row, "command": command, "record_lines": [text_of(x) for x in rec.lines]})
                    page.add({**row, "command": command} if preview else row)
            except OSError as exc:
                info["error"] = describe(exc)
                info["partial"] = True
                read_failures.append({"file": full, "error": describe(exc)})
            info["physical_lines"], info["blank_lines"] = counters["physical"], counters["blank"]
            if counters["other_lines"]:
                info["lines_outside_an_entry"] = counters["other_lines"]
            wrong = [k for k, v in counters["other_format"].items() if v]
            if wrong and fmt != "zsh":
                info["looks_like_other_format"] = wrong[0]
            files.append(info)
    text.close()
    pages = {"records": page.finish()}
    all_read = not read_failures and not walk_errors and partial_reason is None
    print(json.dumps({
        "parser": PARSER,
        "root": root,
        "files": files,
        "file_count": len(files),
        "passwd": {"file": passwd_path, "notes": passwd_notes},
        "records_in_files": sum(f["records"] for f in files),
        "record_count": matched,
        "with_timestamps": with_time,
        "records": page.page,
        "pages": pages,
        "text": text.summary(),
        "all_files_read": all_read,
        "partial_reason": partial_reason,
        "read_failures": read_failures,
        "walk_errors": walk_errors,
        "excluded_dirs": excluded,
        "skipped_symlinks": skipped_symlinks,
        "not_parsed_files": not_parsed,
        "truncated": pages["records"]["truncated"],
        "note": "Records are in the order the program wrote them, and each says how its boundaries were found "
                "(boundary_basis). A record with no time has order only: say so, and do not imply a sequence in time; "
                "stamps need not rise from one record to the next (concurrent sessions, a merge or a changed clock; "
                "timestamps_out_of_order counts them). A history file is what the program saved, not a record of what "
                "ran: a killed session may never have been written, HISTCONTROL and HISTIGNORE drop entries, and the "
                "file's last_written is when it last changed, which is an extraction time on a copied tree. `user` is "
                "an account only when the evidence's passwd says one account has that home; home_basename is a "
                "directory's name. The answer carries no command: write_commands or preview_commands, in a job run "
                "with secret_output: true, is how the text is read.",
    }, indent=2))


if __name__ == "__main__":
    main()
