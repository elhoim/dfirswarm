#!/usr/bin/env bash
# The links between a pack's skills, its tools and the programs it requires.
#
# tests/pack-tools.test.sh holds what a skill's front matter says it uses (a
# tool or a skill that nothing in the resolved set carries). This suite holds
# the other half: what a skill's text names against what its front matter lists,
# and whether everything a pack ships is reached by a skill. The rules are
# docs/packs.md, "Writing a pack that holds up": its Links, and Requires and images.
#
# Bug checks, which fail. Each runs per skill, over its pack's dependency closure
# (the pack, its `depends`, and theirs):
#   closure   the body names a tool, a program or a Python package that only a pack
#             outside the closure carries; or `requires_host:` lists a program no
#             pack of the closure requires;
#   unused    a `tools:` or `requires_host:` entry of the front matter that the body
#             never names;
#   unlisted  the body names a tool of the closure, or a program of a closure's
#             requires/host.json, that the front matter does not list;
#   mentions  a `mentions:` entry that no pack carries or requires, or one that is
#             also in `tools:` or `requires_host:`.
# `mentions: [names]` is for what a skill discusses and cannot depend on (a base
# skill saying what a Windows tool reads, where the tool exists only when the
# Windows pack is loaded). A mentioned name is exempt from closure, unlisted and
# unused, and counts as no naming for the report rules below.
# Also always failing: a `depends` id that is no pack of packs/, and a `needs:`,
# `tools:`, `requires_host:` or `mentions:` that is not a [list].
#
# Report rules, which fail like the bug checks. PACK_LINKS_STRICT=0 turns them into
# reports that print and do not fail (for a local experiment; CI runs the default, 1):
#   - every bundled tool is named by a skill of its pack or of a pack that loads
#     it (one that has the pack in its closure);
#   - every program (requires/host.json) and Python package (requires/python.txt)
#     is named by such a skill, or is listed in pack.json's optional
#     `unreferenced_ok: [{"name": ..., "why": ...}]` with the reason no skill
#     names it (a library only a tool imports);
#   - every skill names at least one tool, program or package of its own pack, or
#     is listed in pack.json's optional `method_only: [{"path": "skills/x/y.md",
#     "why": ...}]` (a method leaf that names none on purpose). The two keys are
#     symmetric: a path that is no skill of the pack, an entry with no why, a path
#     twice, and a listed skill that does name something of its pack are findings,
#     the last as the report "method_only entries ... after all".
#
# How a name is matched, and where that is wrong. A name is found by a whole-word,
# case-sensitive match on the skill's text. Letters, digits, `_` and `-` are part
# of a name, and so is a `.` between two of them: `icat` is not found in
# `icat_extract`, `fls` not in `fls-x`, `target` not in `dissect.target`, `log` not
# in `a.log`; `fls.` ending a sentence, and `vol.py` or `MFTECmd.exe` (the
# extensions exe, py, pl, sh, ps1 and jar) do find the name. That is a name, not a
# use, so:
#   - a program whose name is also an English word (`log`, `make`, `strings`: the
#     set PLAIN_WORDS below) counts only as a command in code. Code is an inline
#     span, a line indented four spaces, and a fenced block that is a command block:
#     no language, or sh, bash, zsh, shell, console, powershell, pwsh, ps1, cmd or
#     bat (a block tagged text, json and the like is output, and what it prints is
#     no use; an indented block that prints a result can pass for a command). A
#     command comes first in the line or the span, or after a pipe, `;`, `&`, `(`,
#     `$(`, `$ `, `sudo`, `xargs`, `time`, `nice`, `env`, `then` or `do`, and may be
#     given by an absolute path through a bin directory (`/usr/bin/make`); it is
#     not part of a path or a file name (`/var/log`, `log.txt`). A new program with
#     an ordinary name is added to PLAIN_WORDS; any other name is found wherever it
#     stands;
#   - a name in prose that does not tell the agent to use it (a collector the
#     evidence came from, a tool of another pack named as the other pack's) is
#     found all the same, and a bug check reports it: reword it, list the pack
#     that carries it in `depends`, or put the name in `mentions:`;
#   - a program an agent runs under another name (`python3 -m x`, a wrapper
#     script), or a Python package imported as its module, is found only by the
#     name requires/ gives it, so such a package is usually listed in
#     `unreferenced_ok`;
#   - the report rules read a skill's whole file, front matter included (without
#     `mentions:`, `id:` and `needs:`: an id is a path and `id: aws/cloudtrail` does
#     not name the program `aws`, and neither does a body that cites a skill of its
#     own pack by that id: a router cites every leaf), since a `tools:` list is a naming too, and the
#     `unused` check makes sure the body agrees; but a plain-word program in a
#     front matter list is no command in code, so a `requires_host: [make]` names
#     nothing;
#   - the closure follows `depends`; a version range is not read.
# Recipes and goal templates are not read: only a skill names a tool here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The report rules fail by default; PACK_LINKS_STRICT=0 only prints them.
STRICT="${PACK_LINKS_STRICT:-1}"
case "$STRICT" in 0|1) ;; *) fail "PACK_LINKS_STRICT is 0 or 1, not '$STRICT'" ;; esac

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || fail "$PY is required"
command -v jq >/dev/null || fail "jq is required"

cat > "$WORK/links.py" <<'EOF'
import json, os, re, sys

root, strict = sys.argv[1], sys.argv[2] == "1"

# A program whose name is also an ordinary word counts only as a command in code.
PLAIN_WORDS = {"log", "make", "strings"}
# A fenced block is a command block when its language is none or one of these.
SHELL_FENCES = {"", "sh", "bash", "zsh", "shell", "console", "powershell", "pwsh", "ps1", "cmd", "bat"}
LISTS = ("needs", "tools", "requires_host", "mentions")
FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
# The front matter keys that hold no naming: `mentions:` is a discussion, and `id:` and
# `needs:` hold skill ids, which are paths and may spell a program (`aws/cloudtrail`).
NOT_NAMING = ("mentions:", "id:", "needs:")

# A name's characters are letters, digits, `_` and `-`, and a `.` between two of
# them; `.exe`, `.py` and the like after a program are its file name.
NAME = r"A-Za-z0-9_-"
EXTS = "exe|py|pl|sh|ps1|jar"
_rx = {}
def whole(name):
    if name not in _rx:
        _rx[name] = re.compile(r"(?<![%s])(?<![%s]\.)%s(?![%s])(?!\.(?!(?:%s)\b)[%s])"
                               % (NAME, NAME, re.escape(name), NAME, EXTS, NAME))
    return _rx[name]

CMD_PREFIX = r"(?:^|[|;&(]|\$\(|\$ |sudo |xargs |time |nice |env |then |do )\s*"
BIN_PATH = r"(?:/(?:[\w.+-]+/)*s?bin/)?"
def command(name):
    key = "cmd:" + name
    if key not in _rx:
        _rx[key] = re.compile(CMD_PREFIX + BIN_PATH + re.escape(name) + r"(?![A-Za-z0-9_./:\\-])")
    return _rx[key]

def code_lines(text):
    """What counts as code: command blocks, lines indented four spaces, inline spans."""
    out, fenced, is_command = [], False, False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            if not fenced:
                lang = re.match(r"[A-Za-z0-9_+-]*", re.sub(r"^[{.\s]+", "", stripped.lstrip("`~").strip()))
                is_command = lang.group(0).lower() in SHELL_FENCES
            fenced = not fenced
        elif fenced:
            if is_command:
                out.append(line)
        elif line.startswith(("    ", "\t")):
            out.append(line)
        else:
            out += re.findall(r"`([^`\n]+)`", line)
    return out

class Text:
    """A piece of a skill, with its code kept for the names that need it."""
    def __init__(self, text):
        self.text, self._code = text, None
    def names(self, name, program=False):
        if program and name in PLAIN_WORDS:
            if self._code is None:
                self._code = code_lines(self.text)
            rx = command(name)
            return any(rx.search(line) for line in self._code)
        return whole(name).search(self.text) is not None

def fields_of(block):
    out = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        out[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()] \
            if v.startswith("[") and v.endswith("]") else v
    return out

structural, packs = [], {}
for pid in sorted(os.listdir(root)):
    pj = os.path.join(root, pid, "pack.json")
    if not os.path.isfile(pj):
        continue
    meta = json.load(open(pj, encoding="utf-8"))
    tdir = os.path.join(root, pid, "tools")
    tools = sorted(n for n in os.listdir(tdir) if os.path.isdir(os.path.join(tdir, n))) if os.path.isdir(tdir) else []
    bins, pys = [], []
    hj = os.path.join(root, pid, "requires", "host.json")
    if os.path.isfile(hj):
        bins = [b["name"] for b in json.load(open(hj, encoding="utf-8")).get("binaries", [])]
    py = os.path.join(root, pid, "requires", "python.txt")
    if os.path.isfile(py):
        for line in open(py, encoding="utf-8"):
            line = line.split("#")[0].strip()
            if line:
                pys.append(re.split(r"[<>=!~ \[;]", line)[0])
    skills = {}
    for dirpath, _d, files in os.walk(os.path.join(root, pid, "skills")):
        for f in sorted(files):
            if not f.endswith(".md") or f == "INDEX.md":
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, os.path.join(root, pid))
            text = open(path, encoding="utf-8").read()
            m = FM.match(text)
            if not m:
                structural.append("%s: %s has no front matter" % (pid, rel))
                continue
            fm = fields_of(m.group(1))
            for key in LISTS:
                if key in fm and not isinstance(fm[key], list):
                    structural.append("%s: %s: %s: is not a [list]" % (pid, rel, key))
                    fm[key] = []
            # A mention is no naming, and neither is an id: the report rules read
            # the file without `mentions:`, `id:` and `needs:` (`id: aws/cloudtrail`
            # does not name the program `aws`).
            kept = "\n".join(l for l in m.group(1).splitlines() if not l.startswith(NOT_NAMING))
            skills[rel] = {"fm": fm, "kept": kept, "text": text, "end": m.end()}
    # A skill cited by its id names nothing: an id is a path, and `aws/cloudtrail` is not the
    # program `aws`. Only a pack's own skill ids are blanked, and only whole (a router cites them all).
    own_ids = sorted((r[len("skills/"):-3].replace(os.sep, "/") for r in skills), key=len, reverse=True)
    cited = re.compile(r"(?<![A-Za-z0-9_./-])(?:%s)(?![A-Za-z0-9_/-])" % "|".join(re.escape(i) for i in own_ids)) if own_ids else None
    for rel, s in skills.items():
        text, end, kept = s.pop("text"), s.pop("end"), s.pop("kept")
        whole_file, body = "---\n" + kept + "\n---\n" + text[end:], text[end:]
        if cited:
            whole_file, body = cited.sub("<skill>", whole_file), cited.sub("<skill>", body)
        s["all"], s["body"] = Text(whole_file), Text(body)
    packs[pid] = {"meta": meta, "tools": tools, "bins": bins, "pys": pys, "skills": skills,
                  "depends": [re.split(r"[<>=!~ ]", d)[0].strip() for d in meta.get("depends") or []]}

for pid, P in sorted(packs.items()):
    for d in P["depends"]:
        if d not in packs:
            structural.append("%s depends on %r, which is not in packs/" % (pid, d))

def closure(pid):
    seen, queue = set(), [pid]
    while queue:
        x = queue.pop()
        if x in seen or x not in packs:
            continue
        seen.add(x)
        queue += packs[x]["depends"]
    return seen
clo = {pid: closure(pid) for pid in packs}
# A pack's dependants: the packs that load it, itself included.
users = {pid: {q for q in packs if pid in clo[q]} for pid in packs}

owner_tool, owner_prog, owner_bin = {}, {}, {}
for pid, P in packs.items():
    for t in P["tools"]:
        owner_tool.setdefault(t, set()).add(pid)
    for n in P["bins"]:
        owner_bin.setdefault(n, set()).add(pid)
        owner_prog.setdefault(n, set()).add(pid)
    for n in P["pys"]:
        owner_prog.setdefault(n, set()).add(pid)

# --- the bug checks ---------------------------------------------------------
found = {}   # "pack kind path name" -> what to say
def add(pid, kind, rel, name, text):
    found.setdefault("%s %s %s %s" % (pid, kind, rel, name), text)

for pid, P in packs.items():
    C = clo[pid]
    for rel, s in sorted(P["skills"].items()):
        body, fm = s["body"], s["fm"]
        listed_tools, listed_host = fm.get("tools", []), fm.get("requires_host", [])
        mentioned = set(fm.get("mentions", []))
        where = "%s: %s" % (pid, rel)
        for name in sorted(mentioned):
            if name not in owner_tool and name not in owner_prog:
                add(pid, "mentions", rel, name, "%s mentions %s, which no pack carries or requires" % (where, name))
            elif name in listed_tools or name in listed_host:
                add(pid, "mentions", rel, name, "%s lists %s in mentions: and in tools: or requires_host:" % (where, name))
        for name, owners in sorted(owner_tool.items()):
            if name in mentioned:
                continue
            if not owners & C and body.names(name):
                add(pid, "closure", rel, name, "%s names the tool %s, which only %s carries" % (where, name, ", ".join(sorted(owners))))
            elif owners & C and body.names(name) and name not in listed_tools:
                add(pid, "unlisted", rel, name, "%s names the tool %s, which tools: does not list" % (where, name))
        for name, owners in sorted(owner_prog.items()):
            if name not in mentioned and not owners & C and body.names(name, True):
                add(pid, "closure", rel, name, "%s names %s, which only %s requires" % (where, name, ", ".join(sorted(owners))))
        for name, owners in sorted(owner_bin.items()):
            if name not in mentioned and owners & C and body.names(name, True) and name not in listed_host:
                add(pid, "unlisted", rel, name, "%s names the program %s, which requires_host: does not list" % (where, name))
        for t in listed_tools:
            if not body.names(t):
                add(pid, "unused", rel, t, "%s lists the tool %s in tools:, and the body never names it" % (where, t))
        for h in listed_host:
            if not owner_bin.get(h, set()) & C:
                add(pid, "closure", rel, h, "%s lists %s in requires_host:, which no pack of its closure requires" % (where, h))
            if not body.names(h, True):
                add(pid, "unused", rel, h, "%s lists %s in requires_host:, and the body never names it" % (where, h))

errors = list(structural)

for line, text in sorted(found.items()):
    errors.append(text)

# --- the report rules -------------------------------------------------------
excused = {}
for pid, P in packs.items():
    raw = P["meta"].get("unreferenced_ok")
    if raw is None:
        continue
    required = set(P["bins"]) | set(P["pys"])
    if not isinstance(raw, list):
        errors.append("%s: unreferenced_ok is a list of {name, why}" % pid)
        continue
    for e in raw:
        ok = isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"] \
            and isinstance(e.get("why"), str) and e["why"].strip()
        if not ok:
            errors.append("%s: an unreferenced_ok entry needs a name and a why" % pid)
        elif e["name"] not in required:
            errors.append("%s: unreferenced_ok names %r, which requires/ does not list" % (pid, e["name"]))
        elif e["name"] in excused.get(pid, {}):
            errors.append("%s: unreferenced_ok names %r twice" % (pid, e["name"]))
        else:
            excused.setdefault(pid, {})[e["name"]] = e["why"]

# method_only: skills that name nothing of their own pack on purpose.
exempt = {}   # pack -> {path: why}
for pid, P in packs.items():
    raw = P["meta"].get("method_only")
    if raw is None:
        continue
    if not isinstance(raw, list):
        errors.append("%s: method_only is a list of {path, why}" % pid)
        continue
    for e in raw:
        ok = isinstance(e, dict) and isinstance(e.get("path"), str) and e["path"] \
            and isinstance(e.get("why"), str) and e["why"].strip()
        if not ok:
            errors.append("%s: a method_only entry needs a path and a why" % pid)
        elif e["path"] not in P["skills"]:
            errors.append("%s: method_only names %r, which is no skill of the pack (a path like skills/reporting/x.md)" % (pid, e["path"]))
        elif e["path"] in exempt.get(pid, {}):
            errors.append("%s: method_only names %r twice" % (pid, e["path"]))
        else:
            exempt.setdefault(pid, {})[e["path"]] = e["why"]

def named_by_users(pid, name, program):
    return any(s["all"].names(name, program) for q in users[pid] for s in packs[q]["skills"].values())

no_tool, no_prog, stale, no_names, stale_method = [], [], [], [], []
n_tools = n_progs = 0
for pid, P in sorted(packs.items()):
    for t in P["tools"]:
        n_tools += 1
        if not named_by_users(pid, t, False):
            no_tool.append((pid, t))
    for n in P["bins"] + P["pys"]:
        n_progs += 1
        named = named_by_users(pid, n, True)
        if not named and n not in excused.get(pid, {}):
            no_prog.append((pid, n))
        if named and n in excused.get(pid, {}):
            stale.append((pid, n))
    for rel, s in sorted(P["skills"].items()):
        names = any(s["all"].names(t) for t in P["tools"]) \
            or any(s["all"].names(n, True) for n in P["bins"] + P["pys"])
        if not names and rel not in exempt.get(pid, {}):
            no_names.append((pid, rel))
        if names and rel in exempt.get(pid, {}):
            stale_method.append((pid, rel))

def by_pack(pairs):
    out = {}
    for pid, x in pairs:
        out.setdefault(pid, []).append(x)
    return ["    %s: %s" % (pid, ", ".join(xs)) for pid, xs in sorted(out.items())]

n_skills = sum(len(P["skills"]) for P in packs.values())
print("checked %d packs: %d skills, %d tools, %d programs and packages" % (len(packs), n_skills, n_tools, n_progs))
print("bug checks: %d finding(s)" % len(found))
reports = [
    ("tools no skill of their pack or a dependant names", no_tool),
    ("programs and packages no such skill names, with no unreferenced_ok", no_prog),
    ("unreferenced_ok entries a skill names after all", stale),
    ("skills that name nothing of their own pack, with no method_only", no_names),
    ("method_only entries whose skill names a tool or program of its pack after all", stale_method),
]
for title, items in reports:
    print("report - %d %s" % (len(items), title))
    for line in by_pack(items):
        print(line)
    if strict:
        errors += ["%s: %s: %s" % (x[0], title, x[1]) for x in items]
for e in errors:
    print("  " + e)
raise SystemExit(1 if errors else 0)
EOF

# --- the shipped packs ------------------------------------------------------
"$PY" "$WORK/links.py" "$ROOT/packs" "$STRICT" > "$WORK/shipped.out" 2>&1
rc=$?
cat "$WORK/shipped.out"
[[ $rc -eq 0 ]] || fail "a skill's text and its front matter disagree, or a pack ships what no skill reaches (above)"
pass "the shipped packs hold to the link checks$([[ "$STRICT" == 1 ]] && echo ' (strict)')"

# PACK_LINKS_STRICT is 0 or 1, and anything else is said, not read as one of them.
if PACK_LINKS_STRICT=2 bash "${BASH_SOURCE[0]}" >"$WORK/strict2.out" 2>&1; then
  fail "PACK_LINKS_STRICT=2 was accepted"
fi
grep -q "PACK_LINKS_STRICT is 0 or 1, not '2'" "$WORK/strict2.out" || fail "PACK_LINKS_STRICT=2 failed without saying why"
pass "PACK_LINKS_STRICT other than 0 or 1 is refused"

# --- the checks themselves, on packs built to break each rule ---------------
# Each case builds a small set of packs (a base, a pack that depends on it and
# a pack that depends on nothing) with one change, and says what the checks
# answer, in the default run and in strict.
cat > "$WORK/fx.py" <<'EOF'
import json, os, sys

dest, mutations = sys.argv[1], sys.argv[2:]

def pack(depends=(), tools=(), bins=(), pys=(), skills=None, **extra):
    return dict(depends=list(depends), tools=list(tools), bins=list(bins), pys=list(pys),
                skills=skills or {}, extra=extra)

def skill(tools=(), host=(), body="", mentions=None, tools_raw=None, needs=()):
    return dict(tools=list(tools), host=list(host), body=body, mentions=mentions, tools_raw=tools_raw, needs=list(needs))

packs = {
    "base": pack(tools=["alpha", "alpha_tool"], bins=["fls", "make", "log"], pys=["somepkg"], skills={
        "s/one": skill(["alpha", "alpha_tool"], ["fls", "make", "log"],
                       "Run `fls -r image` and read it with alpha and alpha_tool.\n\n    make carve\n    log show --archive x\n\nsomepkg reads the rest.\n")}),
    "child": pack(depends=["base"], tools=["child_tool"], skills={
        "c/one": skill(["child_tool", "alpha_tool"], ["fls"],
                       "Call child_tool on what alpha_tool gave you, after `fls -r image`.\n")}),
    "other": pack(tools=["other_tool"], skills={"o/one": skill(["other_tool"], [], "Call other_tool.\n")}),
}

def edit(pid, sid, f):
    f(packs[pid]["skills"][sid])
def child(f): edit("child", "c/one", f)
def more(extra): return lambda s: s.update(body=s["body"] + extra)

M = {
    # a body names a tool that only a pack outside the closure carries
    "closure": lambda: child(more("Then other_tool.\n")),
    # the same name inside a longer name is not a mention
    "longer": lambda: child(more("Then other_tool_x and other-tool-y.\n")),
    # front matter lists a tool the body only has as part of a longer name
    "unused": lambda: child(lambda s: s.update(tools=s["tools"] + ["alpha"], body=s["body"] + "Also alpha_tool_two.\n")),
    "unused-host": lambda: child(lambda s: s.update(host=s["host"] + ["make"])),
    "unlisted-tool": lambda: child(lambda s: s.update(tools=["child_tool"])),
    "unlisted-host": lambda: child(lambda s: s.update(host=[])),
    # a program that no pack of the closure requires, named and listed
    "ghostbin": lambda: child(lambda s: s.update(host=s["host"] + ["ghostbin"], body=s["body"] + "Run `ghostbin` too.\n")),
    # a plain-word program: prose, a path, a file name, an output block are not the program
    "plain-prose": lambda: child(more("You make a copy first. Read /var/log/auth.log and the log of the run; `/var/log/x`, `/var/log`, `x.log`, `log.txt` too.\n"
                                      "\n```text\nmake carve\n```\n")),
    "plain-code": lambda: child(more("Build it with `make` and read it.\n")),
    "plain-pipe": lambda: child(more("\n    cat x | make y\n")),
    "plain-prefix": lambda: child(more("\n    time make y\n")),
    "plain-abs": lambda: child(more("\n    /usr/bin/make y\n")),
    "plain-fence": lambda: child(more("\n```sh\nmake y\n```\n")),
    "plain-fence-bare": lambda: child(more("\n```\nmake y\n```\n")),
    # a dotted name is one name: dissect.target is not `target`; vol.py is `vol`
    "dotted": lambda: (packs["base"]["bins"].append("target"),
                       edit("base", "s/one", lambda s: s.update(host=s["host"] + ["target"], body=s["body"] + "Run `target -h`.\n")),
                       child(more("Read it with dissect.target and dissect.util.\n"))),
    "ext": lambda: (packs["base"]["bins"].append("vol"),
                    edit("base", "s/one", lambda s: s.update(host=s["host"] + ["vol"], body=s["body"] + "Run `vol -h`.\n")),
                    child(more("Run vol.py on it.\n"))),
    "lonely-tool": lambda: packs["base"]["tools"].append("lonely_tool"),
    "shared-tool": lambda: (packs["base"]["tools"].append("shared_tool"),
                            child(lambda s: s.update(tools=s["tools"] + ["shared_tool"], body=s["body"] + "And shared_tool.\n"))),
    "lonely-bin": lambda: packs["base"]["bins"].append("lonely_bin"),
    "lonely-pkg": lambda: packs["base"]["pys"].append("lonelypkg"),
    "excuse": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "lonely_bin", "why": "a tool of the pack calls it"}]),
    "excuse-unknown": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "nothing_here", "why": "x"}]),
    "excuse-no-why": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "lonely_bin"}]),
    "excuse-named": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "fls", "why": "x"}]),
    "bare-skill": lambda: packs["child"]["skills"].update({"c/bare": skill([], [], "Nothing here names a thing.\n")}),
    # method_only: a skill that names nothing of its pack on purpose
    "method": lambda: (packs["child"]["skills"].update({"c/bare": skill([], [], "Nothing here names a thing.\n")}),
                       packs["child"]["extra"].update(method_only=[{"path": "skills/c/bare.md", "why": "a method leaf"}])),
    "method-stale": lambda: packs["child"]["extra"].update(method_only=[{"path": "skills/c/one.md", "why": "said once"}]),
    "method-unknown": lambda: packs["child"]["extra"].update(method_only=[{"path": "skills/c/nowhere.md", "why": "x"}]),
    "method-no-why": lambda: (packs["child"]["skills"].update({"c/bare": skill([], [], "Nothing here names a thing.\n")}),
                              packs["child"]["extra"].update(method_only=[{"path": "skills/c/bare.md", "why": " "}])),
    "method-twice": lambda: (packs["child"]["skills"].update({"c/bare": skill([], [], "Nothing here names a thing.\n")}),
                             packs["child"]["extra"].update(method_only=[{"path": "skills/c/bare.md", "why": "x"}, {"path": "skills/c/bare.md", "why": "y"}])),
    "method-bare": lambda: packs["child"]["extra"].update(method_only="skills/c/bare.md"),
    "method-closure-tool": lambda: (packs["child"]["skills"].update({"c/dep": skill(["alpha_tool"], [], "Call alpha_tool.\n")}),
                                    packs["child"]["extra"].update(method_only=[{"path": "skills/c/dep.md", "why": "reads a dependency's tool"}])),
    # an id or a needs entry is no naming of a program
    "id-spells-program": lambda: (packs["base"]["bins"].append("idbin"),
                                  packs["base"]["skills"].update({"idbin/x": skill([], [], "Nothing here.\n")})),
    "id-cited-spells-program": lambda: (packs["base"]["bins"].append("idbin"),
                                        packs["base"]["skills"].update({"idbin/x": skill([], [], "Nothing here.\n")}),
                                        edit("base", "s/one", more("See `idbin/x` too.\n"))),
    "needs-spells-program": lambda: (packs["base"]["bins"].append("needsbin"),
                                     packs["child"]["skills"].update({"c/two": skill(["child_tool"], [], "Call child_tool.\n", needs=["needsbin"])})),
    # a finding in a pack of its own
    "other-unused": lambda: edit("other", "o/one", lambda s: s.update(body="Nothing.\n")),
    # mentions
    "mention": lambda: child(lambda s: s.update(mentions=["other_tool"], body=s["body"] + "Then other_tool.\n")),
    "mention-unread": lambda: child(lambda s: s.update(mentions=["other_tool"])),
    "mention-unlisted": lambda: child(lambda s: s.update(mentions=["alpha"], body=s["body"] + "And alpha.\n")),
    "mention-bin": lambda: (packs["other"]["bins"].append("otherbin"),
                            edit("other", "o/one", lambda s: s.update(host=["otherbin"], body="Call other_tool and `otherbin`.\n")),
                            child(lambda s: s.update(mentions=["otherbin"], body=s["body"] + "Then `otherbin`.\n"))),
    "mention-nowhere": lambda: child(lambda s: s.update(mentions=["nowhere_tool"])),
    "mention-and-tool": lambda: child(lambda s: s.update(mentions=["alpha_tool"])),
    "mention-bare": lambda: child(lambda s: s.update(mentions="other_tool")),
    "mention-only-front": lambda: (packs["base"]["tools"].append("front_tool"),
                                   edit("base", "s/one", lambda s: s.update(mentions=["front_tool"]))),
    # structural
    "ghostdep": lambda: packs["child"]["depends"].append("ghost"),
    "bare-tools": lambda: child(lambda s: s.update(tools_raw="child_tool")),
}
for m in mutations:
    M[m]()

for pid, p in packs.items():
    d = os.path.join(dest, pid)
    os.makedirs(os.path.join(d, "requires"))
    meta = dict(id=pid, name=pid, version="1.0.0", description="x", licence="AGPL-3.0-or-later",
                depends=p["depends"], requires={"host": "requires/host.json", "python": "requires/python.txt"}, **p["extra"])
    json.dump(meta, open(os.path.join(d, "pack.json"), "w"))
    open(os.path.join(d, "LICENCE"), "w").write("Test pack.\n")
    for t in p["tools"]:
        os.makedirs(os.path.join(d, "tools", t))
        json.dump({"name": t, "description": "x", "params": {}, "runtime": "python3", "entry": "run.py"},
                  open(os.path.join(d, "tools", t, "manifest.json"), "w"))
        open(os.path.join(d, "tools", t, "run.py"), "w").write("print('{}')\n")
    json.dump({"binaries": [{"name": n, "why": "x", "licence": "MIT", "redistributable": False} for n in p["bins"]]},
              open(os.path.join(d, "requires", "host.json"), "w"))
    open(os.path.join(d, "requires", "python.txt"), "w").write("".join("%s==1.0  # x\n" % n for n in p["pys"]))
    for sid, s in p["skills"].items():
        path = os.path.join(d, "skills", sid + ".md")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tools_line = s["tools_raw"] if s["tools_raw"] is not None else "[%s]" % ", ".join(s["tools"])
        mentions_line = "" if s["mentions"] is None else "mentions: %s\n" % (
            s["mentions"] if isinstance(s["mentions"], str) else "[%s]" % ", ".join(s["mentions"]))
        open(path, "w").write("---\nid: %s\ntitle: t\nwhen: w\nneeds: [%s]\ntools: %s\nrequires_host: [%s]\n%s---\n\n%s"
                              % (sid, ", ".join(s["needs"]), tools_line, ", ".join(s["host"]), mentions_line, s["body"]))
EOF

case_n=0
# links_case <label> <rc with PACK_LINKS_STRICT=0> <rc by default> <pattern the output has> <mutations...>
links_case() {
  local label="$1" want_report="$2" want="$3" pattern="$4"; shift 4
  case_n=$((case_n + 1))
  local dir="$WORK/fx$case_n" got rc
  mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" "$@" || fail "could not build the packs for: $label"
  got="$("$PY" "$WORK/links.py" "$dir" 0 2>&1)"; rc=$?
  [[ $rc -eq $want_report ]] || fail "$label (reports only): expected exit $want_report, got $rc:
$got"
  [[ -z "$pattern" ]] || grep -qE -- "$pattern" <<<"$got" || fail "$label: the output lacks /$pattern/:
$got"
  got="$("$PY" "$WORK/links.py" "$dir" 1 2>&1)"; rc=$?
  [[ $rc -eq $want ]] || fail "$label (default): expected exit $want, got $rc:
$got"
}

links_case "a clean set of packs" 0 0 "checked 3 packs: 3 skills, 4 tools, 4 programs and packages" 
links_case "a tool of a pack outside the closure" 1 1 "child: skills/c/one.md names the tool other_tool, which only other carries" closure
links_case "a name inside a longer name is no mention" 0 0 "" longer
links_case "a tool listed and not named (alpha is not alpha_tool)" 1 1 "lists the tool alpha in tools:, and the body never names it" unused
links_case "a program listed and not named" 1 1 "lists make in requires_host:, and the body never names it" unused-host
links_case "a tool named and not listed" 1 1 "names the tool alpha_tool, which tools: does not list" unlisted-tool
links_case "a program named and not listed" 1 1 "names the program fls, which requires_host: does not list" unlisted-host
links_case "a requires_host entry no pack of the closure requires" 1 1 "lists ghostbin in requires_host:, which no pack of its closure requires" ghostbin
links_case "a plain word in prose, a path, a file name or an output block is not the program" 0 0 "" plain-prose
links_case "a plain word in code is the program" 1 1 "names the program make, which requires_host: does not list" plain-code
links_case "a plain word after a pipe is the program" 1 1 "names the program make, which requires_host: does not list" plain-pipe
links_case "a plain word after time is the program" 1 1 "names the program make, which requires_host: does not list" plain-prefix
links_case "a plain word by an absolute path is the program" 1 1 "names the program make, which requires_host: does not list" plain-abs
links_case "a plain word in a shell block is the program" 1 1 "names the program make, which requires_host: does not list" plain-fence
links_case "a plain word in a block with no language is the program" 1 1 "names the program make, which requires_host: does not list" plain-fence-bare
links_case "dissect.target is not target" 0 0 "" dotted
links_case "vol.py is vol" 1 1 "names the program vol, which requires_host: does not list" ext
links_case "a tool no skill names is a report" 0 1 "report - 1 tools no skill of their pack or a dependant names" lonely-tool
links_case "a pack that depends on the pack names its tool" 0 0 "report - 0 tools no skill" shared-tool
links_case "a program no skill names is a report" 0 1 "base: lonely_bin" lonely-bin
links_case "a package no skill names is a report" 0 1 "base: lonelypkg" lonely-pkg
links_case "unreferenced_ok answers a program" 0 0 "report - 0 programs and packages" lonely-bin excuse
links_case "unreferenced_ok for what the pack does not require" 1 1 "unreferenced_ok names 'nothing_here', which requires/ does not list" excuse-unknown
links_case "unreferenced_ok without a why" 1 1 "an unreferenced_ok entry needs a name and a why" lonely-bin excuse-no-why
links_case "unreferenced_ok for a program a skill names" 0 1 "report - 1 unreferenced_ok entries a skill names after all" excuse-named
links_case "a skill that names nothing of its pack is a report" 0 1 "child: skills/c/bare.md" bare-skill

# method_only: a skill that names nothing of its own pack, on purpose
links_case "method_only answers a skill that names nothing of its pack" 0 0 "report - 0 skills that name nothing" method
links_case "method_only for a skill that names its pack's tool" 0 1 "report - 1 method_only entries whose skill names a tool or program of its pack after all" method-stale
links_case "method_only for a skill that names only a dependency's tool" 0 0 "report - 0 method_only entries" method-closure-tool
links_case "method_only for a skill the pack does not have" 1 1 "method_only names 'skills/c/nowhere.md', which is no skill of the pack" method-unknown
links_case "method_only without a why" 1 1 "a method_only entry needs a path and a why" method-no-why
links_case "method_only naming a skill twice" 1 1 "method_only names 'skills/c/bare.md' twice" method-twice
links_case "method_only that is no list" 1 1 "child: method_only is a list of" method-bare
# an id or a needs entry is no naming (`id: aws/cloudtrail` does not name the program aws)
links_case "a skill id that spells a program names nothing" 0 1 "base: idbin" id-spells-program
links_case "a needs entry that spells a program names nothing" 0 1 "base: needsbin" needs-spells-program
links_case "a skill cited by its id names nothing, though the id spells a program" 0 1 "base: idbin" id-cited-spells-program

# mentions: what a skill discusses and cannot depend on
links_case "a mention is exempt from the closure" 0 0 "" mention
links_case "a mention need not be in the body" 0 0 "" mention-unread
links_case "a mention is exempt from the list" 0 0 "" mention-unlisted
links_case "a mentioned program is exempt too" 0 0 "" mention-bin
links_case "a mention no pack knows" 1 1 "mentions nowhere_tool, which no pack carries or requires" mention-nowhere
links_case "a mention that is also listed" 1 1 "lists alpha_tool in mentions: and in tools: or requires_host:" mention-and-tool
links_case "a mention is no naming for the report rules" 0 1 "base: front_tool" mention-only-front
links_case "mentions that is no list" 1 1 "child: skills/c/one.md: mentions: is not a .list." mention-bare

# structural
links_case "a depends id that is no pack" 1 1 "child depends on 'ghost', which is not in packs/" ghostdep
links_case "tools without brackets" 1 1 "child: skills/c/one.md: tools: is not a .list." bare-tools

pass "the checks catch a closure break, an unused, an unlisted or a mentioned name, and report the unreachable; mentions, method_only and unreferenced_ok behave"

# --- a pack carrying unreferenced_ok, method_only and mentions seals, installs and verifies -
# The three keys are the pack's own: seal keeps them and says nothing, the index
# comes out, and install and verify take the pack as sealed. The packs are the
# fixtures' (a base, and a child that depends on it and mentions a program of a
# pack it does not load), not a shipped pack.
"$PY" "$WORK/fx.py" "$WORK/seal" mention-bin || fail "could not build the packs to seal"
jq '.unreferenced_ok = [{"name": "somepkg", "why": "a test of the field"}]' "$WORK/seal/base/pack.json" > "$WORK/pj" && mv "$WORK/pj" "$WORK/seal/base/pack.json"
said="$(bash "$ROOT/scripts/pack.sh" seal "$WORK/seal/base" 2>&1 >/dev/null)" || fail "a pack with unreferenced_ok does not seal: $said"
[[ -z "$said" ]] || fail "a pack with unreferenced_ok seals with a warning: $said"
[[ "$(jq -c '.unreferenced_ok' "$WORK/seal/base/pack.json")" == '[{"name":"somepkg","why":"a test of the field"}]' ]] || fail "seal dropped unreferenced_ok"
grep -q '^mentions: \[otherbin\]' "$WORK/seal/child/skills/c/one.md" || fail "the pack to seal carries no mentions"
jq '.method_only = [{"path": "skills/c/one.md", "why": "a test of the field"}]' "$WORK/seal/child/pack.json" > "$WORK/pj" && mv "$WORK/pj" "$WORK/seal/child/pack.json"
said="$(bash "$ROOT/scripts/pack.sh" seal "$WORK/seal/child" 2>&1 >/dev/null)" || fail "a pack with a mentions key does not seal: $said"
[[ -z "$said" ]] || fail "a pack with a mentions key seals with a warning: $said"
[[ "$(jq -c '.method_only' "$WORK/seal/child/pack.json")" == '[{"path":"skills/c/one.md","why":"a test of the field"}]' ]] || fail "seal dropped method_only"
grep -q 'c/one' "$WORK/seal/child/skills/INDEX.md" || fail "the index lacks the skill that carries mentions"
export DFIRSWARM_HOME="$WORK/home"
said="$(bash "$ROOT/scripts/pack.sh" install "$WORK/seal/base" 2>&1)" || fail "the sealed base does not install: $said"
said="$(bash "$ROOT/scripts/pack.sh" install "$WORK/seal/child" 2>&1)" || fail "a pack with a mentions key does not install: $said"
said="$(bash "$ROOT/scripts/pack.sh" verify child 2>&1)" || fail "an installed pack with a mentions key does not verify: $said"
pass "a pack with unreferenced_ok and method_only and a skill with mentions seals without a warning, keeps them, and installs and verifies"
