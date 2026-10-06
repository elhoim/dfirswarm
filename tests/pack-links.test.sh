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
#             outside the closure carries;
#   unused    a `tools:` or `requires_host:` entry of the front matter that the body
#             never names;
#   unlisted  the body names a tool of the closure, or a program of a closure's
#             requires/host.json, that the front matter does not list.
#
# Report rules, which print and do not fail by default (PACK_LINKS_STRICT=1 fails
# them; the change that brings the last pack up to the standard makes 1 the
# default below):
#   - every bundled tool is named by a skill of its pack or of a pack that loads
#     it (one that has the pack in its closure);
#   - every program (requires/host.json) and Python package (requires/python.txt)
#     is named by such a skill, or is listed in pack.json's optional
#     `unreferenced_ok: [{"name": ..., "why": ...}]` with the reason no skill
#     names it (a library only a tool imports);
#   - every skill names at least one tool, program or package of its own pack.
#
# A pack that does not yet hold to the bug checks is listed in
# tests/pack-links.pending, one id per line. Its findings are printed as counts
# (PACK_LINKS_VERBOSE=1 lists them) and do not fail; a listed pack with no finding
# left fails, so the list only shrinks, and a pack's own change takes its line out.
# PACK_LINKS_STRICT=1 ignores the list.
#
# How a name is matched, and where that is wrong. A name is found by a whole-word,
# case-sensitive match on the skill's text: the characters either side are not
# letters, digits, `_` or `-`, so `icat` is not found in `icat_extract`, nor
# `fls` in `fls-x`. That is a name, not a use, so:
#   - a program whose name is also an English word (`log`, `make`, `strings`: the
#     set PLAIN_WORDS below) counts only as a command in code (backticks, a fenced
#     block or a line indented four spaces): first in the line or the span, or
#     after a pipe, `;`, `&&`, `$(`, `sudo` or `xargs`, and not part of a path or
#     a file name (`/var/log`, `a.log`). A new program with an ordinary name is
#     added to PLAIN_WORDS; any other name is found wherever it stands;
#   - a name in prose that does not tell the agent to use it (a collector the
#     evidence came from, a tool of another pack named as the other pack's) is
#     found all the same, and a bug check reports it: reword it, or have the pack
#     that carries it listed in `depends`;
#   - a program an agent runs under another name (`python3 -m x`, a wrapper
#     script), or a Python package imported as its module, is found only by the
#     name requires/ gives it, so such a package is usually listed in
#     `unreferenced_ok`;
#   - the report rules read a skill's whole file, front matter included, since a
#     `tools:` list is a naming too; the `unused` check makes sure the body agrees,
#     so with both holding a name is in the body;
#   - the closure follows `depends`; a version range is not read.
# Recipes and goal templates are not read: only a skill names a tool here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The change that brings the last pack up to the standard changes the 0 to a 1.
STRICT="${PACK_LINKS_STRICT:-0}"
PENDING="$ROOT/tests/pack-links.pending"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "skip - no python3"; exit 0; }
command -v jq >/dev/null || { echo "skip - no jq"; exit 0; }

cat > "$WORK/links.py" <<'EOF'
import json, os, re, sys

root, strict, pending_path = sys.argv[1], sys.argv[2] == "1", sys.argv[3]
verbose = os.environ.get("PACK_LINKS_VERBOSE") == "1"

# A program whose name is also an ordinary word counts only in code.
PLAIN_WORDS = {"log", "make", "strings"}
FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)

_rx = {}
def whole(name):
    if name not in _rx:
        _rx[name] = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
    return _rx[name]

def command(name):
    # a plain word as a command: first in a line, after a pipe, `;`, `&&`, `$(`,
    # `$ `, `sudo` or `xargs`, and not part of a path or a file name
    key = "cmd:" + name
    if key not in _rx:
        _rx[key] = re.compile(r"(?:^|[|;&(]|\$\(|\$ |sudo |xargs )\s*" + re.escape(name) + r"(?![A-Za-z0-9_./:\\-])")
    return _rx[key]

def code_lines(text):
    """What is code: fenced blocks, lines indented four spaces, inline spans."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif fenced or line.startswith(("    ", "\t")):
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
            skills[rel] = {"fm": fields_of(m.group(1)), "all": Text(text), "body": Text(text[m.end():])}
    packs[pid] = {"meta": meta, "tools": tools, "bins": bins, "pys": pys, "skills": skills,
                  "depends": [re.split(r"[<>=!~ ]", d)[0].strip() for d in meta.get("depends") or []]}

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
found = {pid: [] for pid in packs}   # pack -> [(kind, text)]
for pid, P in packs.items():
    C = clo[pid]
    for rel, s in sorted(P["skills"].items()):
        body, fm = s["body"], s["fm"]
        listed_tools, listed_host = fm.get("tools", []), fm.get("requires_host", [])
        where = "%s: %s" % (pid, rel)
        for name, owners in sorted(owner_tool.items()):
            if not owners & C and body.names(name):
                found[pid].append(("closure", "%s names the tool %s, which only %s carries" % (where, name, ", ".join(sorted(owners)))))
            elif owners & C and body.names(name) and name not in listed_tools:
                found[pid].append(("unlisted", "%s names the tool %s, which tools: does not list" % (where, name)))
        for name, owners in sorted(owner_prog.items()):
            if not owners & C and body.names(name, True):
                found[pid].append(("closure", "%s names %s, which only %s requires" % (where, name, ", ".join(sorted(owners)))))
        for name, owners in sorted(owner_bin.items()):
            if owners & C and body.names(name, True) and name not in listed_host:
                found[pid].append(("unlisted", "%s names the program %s, which requires_host: does not list" % (where, name)))
        for t in listed_tools:
            if not body.names(t):
                found[pid].append(("unused", "%s lists the tool %s in tools:, and the body never names it" % (where, t)))
        for h in listed_host:
            if not body.names(h, True):
                found[pid].append(("unused", "%s lists %s in requires_host:, and the body never names it" % (where, h)))

pending = set()
if os.path.isfile(pending_path):
    for line in open(pending_path, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if line:
            pending.add(line)
errors = list(structural)
for p in sorted(pending - set(packs)):
    errors.append("%s is listed in the pending file and is not a pack in packs/" % p)

n_found = sum(len(v) for v in found.values())
n_held, held = 0, []
for pid in sorted(packs):
    fs = found[pid]
    if pid in pending and not strict:
        if not fs:
            errors.append("%s is listed in the pending file and has no finding left: remove its line" % pid)
            continue
        n_held += len(fs)
        kinds = {}
        for k, _t in fs:
            kinds[k] = kinds.get(k, 0) + 1
        held.append("pending - %s: %d finding(s) (%s)" % (pid, len(fs), ", ".join("%s %d" % kv for kv in sorted(kinds.items()))))
        if verbose:
            held += ["    " + t for _k, t in fs]
    else:
        errors += [t for _k, t in fs]

# --- the report rules -------------------------------------------------------
excused, bad_excuse = {}, []
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

def named_by_users(pid, name, program):
    return any(s["all"].names(name, program) for q in users[pid] for s in packs[q]["skills"].values())

no_tool, no_prog, stale, no_names = [], [], [], []
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
        if not any(s["all"].names(t) for t in P["tools"]) \
                and not any(s["all"].names(n, True) for n in P["bins"] + P["pys"]):
            no_names.append((pid, rel))

def by_pack(pairs):
    out = {}
    for pid, x in pairs:
        out.setdefault(pid, []).append(x)
    return ["    %s: %s" % (pid, ", ".join(xs)) for pid, xs in sorted(out.items())]

n_skills = sum(len(P["skills"]) for P in packs.values())
print("checked %d packs: %d skills, %d tools, %d programs and packages" % (len(packs), n_skills, n_tools, n_progs))
print("bug checks: %d finding(s), %d of them in packs the pending file lists" % (n_found, n_held))
for line in held:
    print(line)
reports = [
    ("tools no skill of their pack or a dependant names", no_tool),
    ("programs and packages no such skill names, with no unreferenced_ok", no_prog),
    ("unreferenced_ok entries a skill names after all", stale),
    ("skills that name nothing of their own pack", no_names),
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
"$PY" "$WORK/links.py" "$ROOT/packs" "$STRICT" "$PENDING" > "$WORK/shipped.out" 2>&1
rc=$?
cat "$WORK/shipped.out"
[[ $rc -eq 0 ]] || fail "a skill's text and its front matter disagree, or a pack ships what no skill reaches (above)"
pass "the shipped packs hold to the link checks$([[ "$STRICT" == 1 ]] && echo ' (strict)')"

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

def skill(tools=(), host=(), body=""):
    return dict(tools=list(tools), host=list(host), body=body)

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
    s = packs[pid]["skills"][sid]
    f(s)

M = {
    # a body names a tool that only a pack outside the closure carries
    "closure": lambda: edit("child", "c/one", lambda s: s.update(body=s["body"] + "Then other_tool.\n")),
    # the same name inside a longer name is not a mention
    "longer": lambda: edit("child", "c/one", lambda s: s.update(body=s["body"] + "Then other_tool_x and other-tool-y.\n")),
    # front matter lists a tool the body only has as part of a longer name
    "unused": lambda: edit("child", "c/one", lambda s: s.update(tools=s["tools"] + ["alpha"], body=s["body"] + "Also alpha_tool_two.\n")),
    "unused-host": lambda: edit("child", "c/one", lambda s: s.update(host=s["host"] + ["make"])),
    "unlisted-tool": lambda: edit("child", "c/one", lambda s: s.update(tools=["child_tool"])),
    "unlisted-host": lambda: edit("child", "c/one", lambda s: s.update(host=[])),
    # a plain-word program: prose, a path, a file name are not the program
    "plain-prose": lambda: edit("child", "c/one", lambda s: s.update(
        body=s["body"] + "You make a copy first. Read /var/log/auth.log and the log of the run; `/var/log/x` and `x.log`, `log.txt` too.\n")),
    "plain-code": lambda: edit("child", "c/one", lambda s: s.update(body=s["body"] + "Build it with `make` and read it.\n")),
    "plain-pipe": lambda: edit("child", "c/one", lambda s: s.update(body=s["body"] + "\n    cat x | make y\n")),
    "lonely-tool": lambda: packs["base"]["tools"].append("lonely_tool"),
    "shared-tool": lambda: (packs["base"]["tools"].append("shared_tool"),
                            edit("child", "c/one", lambda s: s.update(tools=s["tools"] + ["shared_tool"], body=s["body"] + "And shared_tool.\n"))),
    "lonely-bin": lambda: packs["base"]["bins"].append("lonely_bin"),
    "lonely-pkg": lambda: packs["base"]["pys"].append("lonelypkg"),
    "excuse": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "lonely_bin", "why": "a tool of the pack calls it"}]),
    "excuse-unknown": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "nothing_here", "why": "x"}]),
    "excuse-no-why": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "lonely_bin"}]),
    "excuse-named": lambda: packs["base"]["extra"].update(unreferenced_ok=[{"name": "fls", "why": "x"}]),
    "bare-skill": lambda: packs["child"]["skills"].update({"c/bare": skill([], [], "Nothing here names a thing.\n")}),
}
for m in mutations:
    M[m]()

for pid, p in packs.items():
    d = os.path.join(dest, pid)
    os.makedirs(os.path.join(d, "requires"))
    meta = dict(id=pid, name=pid, version="1.0.0", description="x", licence="AGPL-3.0-or-later",
                depends=p["depends"], **p["extra"])
    json.dump(meta, open(os.path.join(d, "pack.json"), "w"))
    for t in p["tools"]:
        os.makedirs(os.path.join(d, "tools", t))
        open(os.path.join(d, "tools", t, "manifest.json"), "w").write("{}")
    json.dump({"binaries": [{"name": n} for n in p["bins"]]}, open(os.path.join(d, "requires", "host.json"), "w"))
    open(os.path.join(d, "requires", "python.txt"), "w").write("".join("%s==1.0  # x\n" % n for n in p["pys"]))
    for sid, s in p["skills"].items():
        path = os.path.join(d, "skills", sid + ".md")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write("---\nid: %s\ntitle: t\nwhen: w\nneeds: []\ntools: [%s]\nrequires_host: [%s]\n---\n\n%s"
                              % (sid, ", ".join(s["tools"]), ", ".join(s["host"]), s["body"]))
EOF

case_n=0
# links_case <label> <default rc> <strict rc> <pattern the output has> <pending ids, comma separated or -> <mutations...>
links_case() {
  local label="$1" want="$2" want_strict="$3" pattern="$4" pending="$5"; shift 5
  case_n=$((case_n + 1))
  local dir="$WORK/fx$case_n" got rc
  mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" "$@" || fail "could not build the packs for: $label"
  : > "$dir.pending"
  [[ "$pending" == "-" ]] || printf '%s\n' ${pending//,/ } > "$dir.pending"
  got="$("$PY" "$WORK/links.py" "$dir" 0 "$dir.pending" 2>&1)"; rc=$?
  [[ $rc -eq $want ]] || fail "$label: expected exit $want, got $rc:
$got"
  [[ -z "$pattern" ]] || grep -qE -- "$pattern" <<<"$got" || fail "$label: the output lacks /$pattern/:
$got"
  got="$("$PY" "$WORK/links.py" "$dir" 1 "$dir.pending" 2>&1)"; rc=$?
  [[ $rc -eq $want_strict ]] || fail "$label (strict): expected exit $want_strict, got $rc:
$got"
}

links_case "a clean set of packs" 0 0 "checked 3 packs: 3 skills, 4 tools, 4 programs and packages" -
links_case "a tool of a pack outside the closure" 1 1 "child: skills/c/one.md names the tool other_tool, which only other carries" - closure
links_case "a name inside a longer name is no mention" 0 0 "" - longer
links_case "a tool listed and not named (alpha is not alpha_tool)" 1 1 "lists the tool alpha in tools:, and the body never names it" - unused
links_case "a program listed and not named" 1 1 "lists make in requires_host:, and the body never names it" - unused-host
links_case "a tool named and not listed" 1 1 "names the tool alpha_tool, which tools: does not list" - unlisted-tool
links_case "a program named and not listed" 1 1 "names the program fls, which requires_host: does not list" - unlisted-host
links_case "a plain word in prose, a path or a file name is not the program" 0 0 "" - plain-prose
links_case "a plain word in code is the program" 1 1 "names the program make, which requires_host: does not list" - plain-code
links_case "a plain word after a pipe is the program" 1 1 "names the program make, which requires_host: does not list" - plain-pipe
links_case "a pack the pending file lists does not fail the default run" 0 1 "pending - child: 1 finding.s. .closure 1." child closure
links_case "a pending pack with nothing left is named" 1 0 "child is listed in the pending file and has no finding left" child
links_case "a pending id that is no pack" 1 1 "ghost is listed in the pending file and is not a pack" ghost
links_case "a tool no skill names is a report" 0 1 "report - 1 tools no skill of their pack or a dependant names" - lonely-tool
links_case "a pack that depends on the pack names its tool" 0 0 "report - 0 tools no skill" - shared-tool
links_case "a program no skill names is a report" 0 1 "base: lonely_bin" - lonely-bin
links_case "a package no skill names is a report" 0 1 "base: lonelypkg" - lonely-pkg
links_case "unreferenced_ok answers a program" 0 0 "report - 0 programs and packages" - lonely-bin excuse
links_case "unreferenced_ok for what the pack does not require" 1 1 "unreferenced_ok names 'nothing_here', which requires/ does not list" - excuse-unknown
links_case "unreferenced_ok without a why" 1 1 "an unreferenced_ok entry needs a name and a why" - lonely-bin excuse-no-why
links_case "unreferenced_ok for a program a skill names" 0 1 "report - 1 unreferenced_ok entries a skill names after all" - excuse-named
links_case "a skill that names nothing of its pack is a report" 0 1 "child: skills/c/bare.md" - bare-skill
pass "the checks catch a closure break, an unused or an unlisted name, and report the unreachable; pending and unreferenced_ok behave"

# --- a pack.json that carries unreferenced_ok still seals --------------------
# The field is the pack's own: seal keeps it, says nothing, and the pack stays as sealed.
cp -R "$ROOT/packs/computer-forensics-base" "$WORK/seal-base"
jq '.unreferenced_ok = [{"name": "steghide", "why": "a test of the field"}]' "$WORK/seal-base/pack.json" > "$WORK/pj" && mv "$WORK/pj" "$WORK/seal-base/pack.json"
said="$(bash "$ROOT/scripts/pack.sh" seal "$WORK/seal-base" 2>&1 >/dev/null)" || fail "a pack with unreferenced_ok does not seal: $said"
[[ -z "$said" ]] || fail "a pack with unreferenced_ok seals with a warning: $said"
[[ "$(jq -c '.unreferenced_ok' "$WORK/seal-base/pack.json")" == '[{"name":"steghide","why":"a test of the field"}]' ]] || fail "seal dropped unreferenced_ok"
pass "a pack.json with unreferenced_ok seals without a warning and keeps the field"
