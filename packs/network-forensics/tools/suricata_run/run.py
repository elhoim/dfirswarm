#!/usr/bin/env python3
"""Run local Suricata rules offline over a capture, and say exactly what ran.

What is recorded, so that the run can be repeated and its coverage judged:

  * The engine: `suricata --build-info`, kept whole in out_dir, and its version line.
  * The configuration. By default the tool writes suricata.yaml into out_dir (an explicit file: eve-log with its
    types listed by name and `tls: extended: yes`, the TLS fingerprint settings by key under app-layer) and records
    its path and SHA-256; nothing is addressed by list position. Everything the file does not set is the engine's
    own default, not your distribution's suricata.yaml: pass `config` (a local file, never one from inputs/) to use
    a configuration of your own. Whether a build accepts the keys written here is decided by the engine, not
    assumed: the configuration is tested with `suricata -T` BEFORE the run, and when that fails nothing is run and
    the diagnostic is returned whole.
  * The rules: path, SHA-256, size and the number of rule lines in the file (a count of lines, not of rules the
    engine loaded). The numbers Suricata itself prints about loading rules ("N rules successfully loaded, M rules
    failed") are read from its own output when they are there, and a failure to load is a failure of the run.
  * The checksum mode (-k) and the command.

TLS fingerprints are three different facts and are kept apart: ja3_enabled and ja4_enabled are what the written
configuration asks for (not read from a configuration you supply); tls_events is the TLS events the engine logged
(the traffic that could carry a fingerprint); tls_with_ja3 and tls_with_ja4 are the events that do. An event with no
fingerprint is not evidence that the build lacks the feature, and a build may ignore a key it does not know. No
default and no version fact about Suricata is stated here: read the version the evidence was run with.

EVE is read line by line. A line that is not JSON, or is JSON but not an object, is counted with its line number
(the line itself stays in eve.json), and an object with no event_type is counted apart. eve.json is the whole result.

SENSITIVE OUTPUT. EVE can carry URLs, host names, SNI, DNS names, file names and payload excerpts. The directory is
private (mode 0700, every file 0600, including what Suricata writes) and the answer says to run the tool as a job
with secret_output: true. Inline alerts carry addresses, ports and the rule's signature only.
"""
import collections
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

TOOL = {"name": "suricata_run", "version": 3}
PARSER = "suricata_run/3"
TEST_SECONDS = 120
PREFLIGHT_SECONDS = 30
MAX_LINE = 16 << 20
MAX_SIGNATURES = 10_000
LOADED = re.compile(r"(\d+) rules? successfully loaded, (\d+) rules? failed")

# BEGIN SHARED WITHHOLDING
# The same text is in pcap_extract, zeek_run, suricata_run and network_log_summary, so that the four tools withhold
# the same strings; tests/pack-network-withholding.test.ts holds the copies equal. An identifier-shaped string is
# withheld wherever the tool would print one: a name, a path component, a URL, a message that quotes either.
COUNTS = {"names": 0, "urls": 0, "text": 0}
_RUN = re.compile(r"[A-Za-z0-9_+=-]{20,}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_PREFIXED = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                       r"|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}"
                       r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_USERINFO = re.compile(r"(?<=://)[^/?#\s@]+(?=@)")


def _withheld(what, length, kind):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    return ("<%s withheld %d characters>" % (what, length)) if what else ("<withheld %d characters>" % length)


def _token_run(run):
    """Is this run of name characters shaped like a token, and not like words, dates or versions?"""
    if _HEX.search(run):
        return True
    chunks = [(m.group()[0].isdigit(), m.start(), m.end()) for m in re.finditer(r"[A-Za-z]+|[0-9]+", run)]
    # digits packed between letters ("a9b2c7"), which words, dates and versions do not do
    packed = 0
    for i, (is_digit, start, end) in enumerate(chunks):
        if not is_digit or end - start > 3:
            continue
        before = i > 0 and not chunks[i - 1][0] and chunks[i - 1][2] == start
        after = i + 1 < len(chunks) and not chunks[i + 1][0] and chunks[i + 1][1] == end
        packed += 1 if before or after else 0
    if packed >= 3:
        return True
    letters = [c for c in run if c.isalpha()]
    case_flips = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    if len(letters) >= 20 and case_flips >= max(8, 0.4 * len(letters)):
        return True
    if run.endswith("=") and len(run) >= 24:
        return True
    return len(run) >= 40 and run.isalnum() and any(c.isdigit() for c in run) and any(c.isalpha() for c in run)


def token_spans(text):
    spans = [m.span() for m in _PREFIXED.finditer(text)]
    for m in _RUN.finditer(text):
        if _token_run(m.group()):
            spans.append(m.span())
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def token_shaped(text):
    return bool(token_spans(text))


def scrub(text, kind="text"):
    """The text with every token-shaped run and every URL's user-info withheld."""
    text = _USERINFO.sub(lambda m: _withheld("userinfo", len(m.group()), kind), text)
    out, last = [], 0
    for start, end in token_spans(text):
        out.append(text[last:start])
        out.append(_withheld("token-shaped text", end - start, kind))
        last = end
    out.append(text[last:])
    return "".join(out)


def redact_url(url):
    """A URL or request target without its user-info, its token-shaped path text, its query values or its fragment."""
    rest, fragment = (url.split("#", 1) + [None])[:2]
    rest, query = (rest.split("?", 1) + [None])[:2]
    scheme = authority = ""
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/]*)(.*)$", rest, re.S)
    if m:
        scheme, authority, rest = m.group(1), m.group(2), m.group(3)
        if "@" in authority:
            userinfo, authority = authority.rsplit("@", 1)
            authority = _withheld("userinfo", len(userinfo), "urls") + "@" + authority
    out = scheme + authority + "/".join(scrub(s, "urls") for s in rest.split("/"))
    if query is not None:
        pairs = []
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            pairs.append(scrub(name, "urls") + (eq + _withheld("", len(value), "urls") if eq else ""))
        out += "?" + "&".join(pairs)
    if fragment is not None:
        out += "#" + _withheld("", len(fragment), "urls")
    return out


def cell(value):
    """Text for one tab-separated cell or one printed path: no tab or line break, and a byte that was not UTF-8
    (a lone surrogate) written as \\xNN, so that no writer raises on it."""
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)
# END SHARED WITHHOLDING


def describe(exc):
    code = errno.errorcode.get(exc.errno, "") if getattr(exc, "errno", None) else ""
    return scrub("%s%s: %s" % (type(exc).__name__, " " + code if code else "", getattr(exc, "strerror", None) or str(exc)))


def in_job():
    return bool(os.environ.get("JOB_ID") and os.environ.get("OUT"))


def fail(message, **extra):
    print(json.dumps({"error": scrub(message), "tool": TOOL, **extra}))
    raise SystemExit(1)


def resolve_output(out, what="output"):
    """Where `out` really lands, as a path under the run directory; a place outside it, the run directory itself,
    or anything under inputs/ is refused, and in a job so is anything outside $OUT, the one place a job writes.

    A string check is not enough: `work/../inputs/x`, an absolute path and a symlink that points out all name a
    place the tool must not write. Resolving first and comparing directories is what holds, and the read-only
    inputs are the one place Suricata's logs must never appear: a later integrity check would report the evidence
    as modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest == root or root not in dest.parents:
        fail("%s must stay inside the run directory" % what, **{what: str(out)})
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("%s cannot be under inputs/" % what, **{what: str(out)})
    if in_job():
        job_out = Path(os.environ["OUT"]).resolve()
        if dest != job_out and job_out not in dest.parents:
            fail("in a job %s is a directory under $OUT, the one place a job writes" % what, **{what: str(out), "out": str(job_out)})
    return str(dest.relative_to(root))


ACTIVE = []


def kill_group(proc):
    """Kill the process and everything it started."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _on_term(signum, _frame):
    for proc in list(ACTIVE):
        kill_group(proc)
    os._exit(128 + signum)


def preflight(argv, seconds):
    """Run a short program, bounded; (exit code or None, stdout bytes, stderr bytes)."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        return None, b"", describe(exc).encode("utf-8", "replace")
    ACTIVE.append(proc)
    try:
        out, err = proc.communicate(timeout=seconds)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        kill_group(proc)
        out, err = proc.communicate()
        return None, out, err
    finally:
        ACTIVE.remove(proc)


def run_to_files(argv, stdout_path, stderr_path, seconds):
    """(exit code, timed out): the program in its own process group, its output in files, killed at `seconds`."""
    with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        ACTIVE.append(proc)
        try:
            return proc.wait(timeout=seconds), False
        except subprocess.TimeoutExpired:
            kill_group(proc)
            proc.wait()
            return None, True
        finally:
            ACTIVE.remove(proc)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rule_load_counts(*paths):
    """What Suricata itself printed about loading rules, or None when it printed nothing of the kind."""
    found = None
    for path in paths:
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    m = LOADED.search(raw.decode("utf-8", "replace"))
                    if m:
                        found = {"loaded": int(m.group(1)), "failed": int(m.group(2)), "from": os.path.basename(path)}
        except OSError:
            continue
    return found


def configuration(out_dir):
    """The explicit configuration the tool writes: every setting by key, none by position."""
    return (
        "%YAML 1.1\n---\n"
        "# Written by suricata_run (network-forensics pack). Settings not named here are the engine's own defaults.\n"
        "default-log-dir: " + json.dumps(os.path.abspath(out_dir)) + "\n"
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        "      filename: eve.json\n"
        "      types:\n"
        "        - alert\n"
        "        - anomaly\n"
        "        - dns\n"
        "        - http\n"
        "        - tls:\n"
        "            extended: yes\n"
        "        - files\n"
        "        - flow\n"
        "app-layer:\n"
        "  protocols:\n"
        "    tls:\n"
        "      enabled: yes\n"
        "      ja3-fingerprints: yes\n"
        "      ja4-fingerprints: yes\n"
    )


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    if not isinstance(args, dict):
        fail("arguments must be a JSON object")
    path, rules, out_dir = args.get("path"), args.get("rules"), args.get("out_dir")
    for label, value in (("path", path), ("rules", rules)):
        if not isinstance(value, str) or not os.path.isfile(value):
            fail("%s must name a readable file" % label, **{label: value if isinstance(value, str) else None})
    if not isinstance(out_dir, str) or not out_dir:
        fail("out_dir is required: an empty directory under work/ (in a job, under $OUT)")
    out_dir = resolve_output(out_dir, "out_dir")
    try:
        if os.path.exists(out_dir) and os.listdir(out_dir):
            fail("out_dir already holds files", out_dir=out_dir)
    except OSError as exc:
        fail("out_dir cannot be listed (%s)" % describe(exc), out_dir=out_dir)
    limit = args.get("return_alerts", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        fail("return_alerts must be a non-negative integer")
    timeout = args.get("timeout_seconds", 900)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 10:
        fail("timeout_seconds must be an integer of at least 10")
    checksum_mode = str(args.get("checksum_mode") or "none").lower()
    if checksum_mode not in ("none", "all"):
        fail("checksum_mode must be none or all", checksum_mode=checksum_mode)
    config_arg = args.get("config")
    if config_arg is not None:
        if not isinstance(config_arg, str) or not os.path.isfile(config_arg):
            fail("config must name a readable file", config=config_arg if isinstance(config_arg, str) else None)
        resolved = Path(config_arg).resolve()
        inputs = Path.cwd().resolve() / "inputs"
        if resolved == inputs or inputs in resolved.parents:
            fail("a configuration from inputs/ is refused: a configuration can load scripts and rule files, and this one would be code the evidence supplied", config=config_arg)
    binary = shutil.which("suricata")
    if not binary:
        fail("suricata is not on PATH")

    os.umask(0o077)
    try:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        os.chmod(out_dir, 0o700)
    except OSError as exc:
        fail("the output directory could not be created (%s)" % describe(exc), out_dir=out_dir)
    signal.signal(signal.SIGTERM, _on_term)

    build_code, build_out, build_err = preflight([binary, "--build-info"], PREFLIGHT_SECONDS)
    build_path = os.path.join(out_dir, "suricata-build-info.txt")
    try:
        fd = os.open(build_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(build_out + (b"\n--- stderr ---\n" + build_err if build_err else b""))
    except OSError as exc:
        fail("the build information could not be written (%s)" % describe(exc), out_dir=out_dir)
    version_line = None
    for line in build_out.decode("utf-8", "replace").splitlines():
        if re.search(r"(?i)\bversion\b", line):
            version_line = line.strip()
            break

    generated = config_arg is None
    config_path = os.path.join(out_dir, "suricata.yaml") if generated else config_arg
    if generated:
        try:
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(configuration(out_dir))
        except OSError as exc:
            fail("the configuration could not be written (%s)" % describe(exc), out_dir=out_dir)
    try:
        config_sha, rules_sha = file_sha256(config_path), file_sha256(rules)
        with open(rules, "rb") as fh:
            rule_lines = sum(1 for raw in fh if raw.strip() and not raw.lstrip().startswith(b"#"))
        rules_bytes = os.path.getsize(rules)
    except OSError as exc:
        fail("a configuration or rules file could not be read (%s)" % describe(exc))

    common = ["-c", os.path.abspath(config_path), "-S", os.path.abspath(rules), "-l", os.path.abspath(out_dir), "-k", checksum_mode, "-v"]
    test_argv = [binary, "-T"] + common
    test_out, test_err = os.path.join(out_dir, "suricata-test.stdout"), os.path.join(out_dir, "suricata-test.stderr")
    test_code, test_timed_out = run_to_files(test_argv, test_out, test_err, TEST_SECONDS)
    if test_code != 0:
        fail("the configuration test (suricata -T) %s, so nothing was run" % ("did not finish in time" if test_timed_out else "failed with exit code %s" % test_code),
             exit_code=test_code, command=test_argv, config=config_path, config_sha256=config_sha, config_generated=generated,
             suricata_version=version_line, build_info=build_path, stdout=test_out, stderr=test_err,
             note="The configuration is tested before any capture is read. Read the diagnostic; if the written configuration does not suit the "
                  "installed build, pass config with a file of your own.")

    argv = [binary, "-r", os.path.abspath(path)] + common
    stdout_path, stderr_path = os.path.join(out_dir, "suricata.stdout"), os.path.join(out_dir, "suricata.stderr")
    code, timed_out = run_to_files(argv, stdout_path, stderr_path, timeout)
    for name in os.listdir(out_dir):
        full = os.path.join(out_dir, name)
        try:
            if not os.path.islink(full):
                os.chmod(full, 0o700 if os.path.isdir(full) else 0o600)
        except OSError:
            pass
    if timed_out:
        fail("suricata did not finish in time and was killed with everything it had started", after_seconds=timeout, command=argv,
             partial_output=out_dir, stdout=stdout_path, stderr=stderr_path)
    eve = os.path.join(out_dir, "eve.json")
    if not os.path.isfile(eve):
        fail("suricata wrote no eve.json", exit_code=code, command=argv, stdout=stdout_path, stderr=stderr_path, out_dir=out_dir)

    event_types, signatures = collections.Counter(), collections.Counter()
    alerts, bad_lines, not_objects, no_type, too_long = [], [], 0, 0, []
    invalid = 0
    tls_events = tls_ja3 = tls_ja4 = 0
    signature_overflow = 0
    lines = 0
    with open(eve, "rb") as fh:
        while True:
            raw = fh.readline(MAX_LINE + 1)
            if not raw:
                break
            lines += 1
            if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                while True:
                    more = fh.readline(MAX_LINE)
                    if not more or more.endswith(b"\n"):
                        break
                if len(too_long) < 10:
                    too_long.append(lines)
                continue
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8", "surrogateescape"))
            except ValueError:
                invalid += 1
                if len(bad_lines) < 10:
                    bad_lines.append({"line": lines, "why": "not valid JSON"})
                continue
            if not isinstance(event, dict):
                not_objects += 1
                if len(bad_lines) < 10:
                    bad_lines.append({"line": lines, "why": "valid JSON that is not an object"})
                continue
            kind = event.get("event_type")
            if not isinstance(kind, str) or not kind:
                no_type += 1
                kind = "no_event_type"
            event_types[kind] += 1
            if kind == "alert":
                alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
                label = str(alert.get("signature") or alert.get("signature_id") or "unknown")
                if label in signatures or len(signatures) < MAX_SIGNATURES:
                    signatures[label] += 1
                else:
                    signature_overflow += 1
                if len(alerts) < limit:
                    alerts.append({"line": lines, "timestamp": event.get("timestamp"), "flow_id": event.get("flow_id"),
                                   "src_ip": event.get("src_ip"), "src_port": event.get("src_port"),
                                   "dest_ip": event.get("dest_ip"), "dest_port": event.get("dest_port"),
                                   "proto": event.get("proto"), "signature_id": alert.get("signature_id"), "signature": alert.get("signature")})
            elif kind == "tls":
                tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
                tls_events += 1
                tls_ja3 += int(bool(tls.get("ja3")))
                tls_ja4 += int(bool(tls.get("ja4")))

    loads = {"configuration_test": rule_load_counts(test_out, test_err), "run": rule_load_counts(stdout_path, stderr_path)}
    load_failed = any(v and v["failed"] for v in loads.values())
    problems = []
    if code != 0:
        problems.append("suricata exited with code %s" % code)
    if load_failed:
        problems.append("Suricata reported rules that failed to load")
    if invalid or not_objects or too_long:
        problems.append("%d EVE lines were not read as events" % (invalid + not_objects + len(too_long)))
    ok = not problems
    print(json.dumps({
        "tool": TOOL, "parser": PARSER,
        "path": path, "out_dir": out_dir, "eve_json": eve,
        "suricata_version": version_line, "build_info": build_path, "build_info_exit_code": build_code,
        "command": argv,
        "configuration": {"path": config_path, "sha256": config_sha, "generated_by_this_tool": generated,
                          "tested_with": "suricata -T", "test_exit_code": test_code, "test_stdout": test_out, "test_stderr": test_err,
                          "note": ("written by this tool: only the keys it names are set, the rest are the engine's own defaults" if generated else
                                   "supplied by the caller and not read by this tool")},
        "rules": {"path": rules, "sha256": rules_sha, "bytes": rules_bytes, "rule_lines": rule_lines,
                  "rule_lines_note": "lines that are neither empty nor comments; not the number of rules the engine loaded"},
        "rule_load": {**loads, "note": "read from Suricata's own output when it printed the numbers, and None when it did not: None is not a count of zero"},
        "checksum_mode": checksum_mode,
        "exit_code": code,
        "event_types": dict(event_types),
        "events": sum(event_types.values()),
        "alert_count": event_types.get("alert", 0), "alerts_returned": len(alerts), "alerts_omitted": event_types.get("alert", 0) - len(alerts),
        "alerts": alerts, "signatures": dict(signatures), "signatures_over_cap": signature_overflow,
        "tls_fingerprints": {
            "ja3_enabled": "yes (asked of the engine in the written configuration)" if generated else "not read: the configuration is the caller's",
            "ja4_enabled": "yes (asked of the engine in the written configuration)" if generated else "not read: the configuration is the caller's",
            "tls_events": tls_events, "tls_with_ja3": tls_ja3, "tls_with_ja4": tls_ja4,
            "note": "enabled is what the configuration asks for, tls_events is the traffic that could carry a fingerprint, the other two are what was produced. "
                    "An event with none does not show the build lacks the feature, and a build may ignore a key it does not know.",
        },
        "tls_with_ja3": tls_ja3, "tls_with_ja4": tls_ja4,
        "eve_lines": lines, "invalid_eve_lines": invalid, "eve_lines_not_objects": not_objects, "events_without_event_type": no_type,
        "eve_lines_over_limit": too_long, "eve_line_problems": bad_lines,
        "stdout": stdout_path, "stderr": stderr_path,
        "problems": problems,
        "ok": ok,
        "withheld": dict(COUNTS),
        "out_dir_contains_secret_values": True,
        "out_dir_note": ("EVE can carry URLs, host names, SNI, DNS names, file names and payload excerpts. The directory is private (mode 0700, files "
                         "0600). Run this tool as a job with secret_output: true so the job output is sealed. Inline alerts carry addresses, ports "
                         "and the rule's signature only."),
        "note": ("Inline alerts are bounded and eve.json is the whole result; it, the configuration, the build information and Suricata's complete "
                 "stdout and stderr are named above. An alert is a rule match on the traffic as the engine reassembled it, not a finding: the rules are "
                 "the caller's, and no ruleset ships with this pack. Checksum validation defaults to none because capture offload commonly leaves "
                 "invalid TCP checksums; use all to test integrity. JA3 and JA4 are pivots, not unique identities of a program."),
    }, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never a traceback, never a clean answer for a failure
        fail("unexpected failure: %s" % describe(exc))
