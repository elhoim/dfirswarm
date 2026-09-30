#!/usr/bin/env python3
"""Generate the synthetic calibration cases, and their truth, apart.

    python3 calibration/generate.py --out ~/DFIR/Calibration --truth-dir ~/secret/calibration-truth \\
        [--seed SEED] [--cases usb-departure,web-intrusion,invoice-fraud] [--force]

Per case it writes, under --out/<case>/:
  inputs/     the evidence a run is given (--inputs <case>/inputs)
  late/       an evidence item held back, for the operator to add while the run goes on
  goal.md     the goal document (--goal-file <case>/goal.md)
  case.json   what was written and its digests; no seed, no truth
and --truth-dir/<case>.truth.json: the seed, the expected result of every
question, which facts are hard to find, absent, decoys, missing or late,
and the generator's own proof that each planted fact is where it says.

The truth must stay outside the repository and outside every run: a truth
path inside a dfirswarm checkout, inside --out, or inside a run's sandbox is
refused before anything is written. The same seed gives the same bytes on
any host (no zlib, no mkfs, no clock: everything is drawn from the seed);
without --seed a fresh one is drawn and kept in the truth file only.

Python 3.8 or later, standard library only. See calibration/README.md.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from calgen import GENERATOR_VERSION  # noqa: E402
from calgen import case_mail, case_usb, case_web  # noqa: E402
from calgen.common import CaseOutput, pattern_matches  # noqa: E402

CASES: Dict[str, Callable[[str], CaseOutput]] = {
    case_usb.CASE_ID: case_usb.build,
    case_web.CASE_ID: case_web.build,
    case_mail.CASE_ID: case_mail.build,
}
TRUTH_FORMAT = "dfirswarm-calibration-truth/1"
CASE_FORMAT = "dfirswarm-calibration-case/1"


class Refused(Exception):
    pass


def _real(p: Path) -> Path:
    """The path with every existing part resolved, links included; the rest appended as given."""
    p = Path(os.path.abspath(os.path.expanduser(str(p))))
    tail: List[str] = []
    cur = p
    while not cur.exists() and cur != cur.parent:
        tail.insert(0, cur.name)
        cur = cur.parent
    return Path(os.path.realpath(str(cur))).joinpath(*tail)


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_checkout(d: Path) -> bool:
    """A dfirswarm checkout, of any version: the kickoff script and the extensions beside it."""
    return (d / "scripts" / "swarm.sh").is_file() and (d / "extensions").is_dir()


def _checkout_above(p: Path) -> Optional[Path]:
    """A dfirswarm checkout that holds p: this generator's own, or any directory
    above p that is one (another clone, the checkout a worktree lives in)."""
    own = HERE.parent
    if _is_checkout(own) and _within(p, _real(own)):
        return own
    cur = p
    while True:
        if _is_checkout(cur):
            return cur
        if cur == cur.parent:
            return None
        cur = cur.parent


def _run_above(p: Path) -> Optional[Path]:
    """A run's sandbox (SWARM.md beside team.json) or a runs directory (registry.json) that holds p."""
    cur = p
    while True:
        if (cur / "SWARM.md").is_file() and (cur / "team.json").is_file():
            return cur
        if (cur / "registry.json").is_file() and cur.name == "runs":
            return cur
        if cur == cur.parent:
            return None
        cur = cur.parent


def check_paths(out: Path, truth_dir: Path) -> None:
    out_r, truth_r = _real(out), _real(truth_dir)
    repo = _checkout_above(truth_r)
    if repo:
        raise Refused(f"the truth directory {truth_dir} is inside the dfirswarm checkout {repo}; "
                      "the truth must stay outside the repository and outside every run")
    run = _run_above(truth_r)
    if run:
        raise Refused(f"the truth directory {truth_dir} is inside the run {run}; the truth must stay outside every run")
    if _within(truth_r, out_r) or _within(out_r, truth_r):
        raise Refused(f"the truth directory {truth_dir} and the cases directory {out} overlap; "
                      "a run given a case's inputs must never be able to reach its truth")
    repo = _checkout_above(out_r)
    if repo:
        raise Refused(f"the cases directory {out} is inside the dfirswarm checkout {repo}; "
                      "generate the cases outside the repository (the repository holds the generator only)")
    run = _run_above(out_r)
    if run:
        raise Refused(f"the cases directory {out} is inside the run {run}")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _check_truth(c: CaseOutput) -> List[str]:
    """The truth's own consistency: every pattern reads, and no value a question
    needs the late item for is already in the inputs (a time is exempt: a
    minute can coincide with an unrelated line)."""
    problems = []
    texts = []
    for name, data in c.inputs.items():
        texts.append((gzip.decompress(data) if name.endswith(".gz") else data).decode("utf-8", "replace"))
    blob = "\n".join(texts)
    for q in c.questions:
        facts = list(q.get("facts", [])) + list((q.get("late") or {}).get("facts", []))
        for f in facts:
            for p in f.get("accept", []) or []:
                try:
                    pattern_matches(p, "")
                except Exception as err:  # noqa: BLE001
                    problems.append(f"{c.case_id} {f['id']}: pattern {p!r} does not read: {err}")
            if f["category"] == "late" and f.get("subkind") != "time":
                hits = [p for p in f.get("accept", []) if pattern_matches(p, blob)]
                if hits:
                    problems.append(f"{c.case_id} {f['id']}: the late fact already matches the inputs ({hits})")
        # Each part is settled by facts of its own question that a scorer can find.
        findable = {f["id"] for f in facts if f.get("accept")}
        for p in q.get("parts", []) or []:
            for fid in list(p.get("settled_by", [])) + list(p.get("after_late", []) or []):
                if fid not in findable:
                    problems.append(f"{c.case_id} Q{q['id']} part {p['id']}: {fid} is not a fact of the question with patterns")
        if q.get("scored") and q.get("kind") == "present" and not q.get("parts"):
            problems.append(f"{c.case_id} Q{q['id']}: a scored present question names its parts")
    return problems


def write_case(c: CaseOutput, seed: str, out: Path, truth_dir: Path, force: bool) -> Dict[str, object]:
    failed = [f"{p.fact}: {p.claim}" for p in c.probes if not _safe(p.check)]
    if failed:
        raise RuntimeError(f"{c.case_id}: the generated evidence does not hold what the truth says:\n  " + "\n  ".join(failed))
    problems = _check_truth(c)
    if problems:
        raise RuntimeError("\n".join(problems))
    case_dir = out / c.case_id
    if case_dir.exists():
        if not force:
            raise Refused(f"{case_dir} exists; pass --force to replace it")
        if not (case_dir / "case.json").is_file():
            raise Refused(f"{case_dir} exists and was not written by this generator (no case.json); not replacing it")
        _chmod_writable(case_dir)
        shutil.rmtree(case_dir)
    files: List[dict] = []
    late: List[dict] = []
    for rel in sorted(c.inputs):
        data = c.inputs[rel]
        _write(case_dir / "inputs" / rel, data, c.mtimes.get(rel))
        files.append({"path": rel, "sha256": _sha(data), "bytes": len(data)})
    for rel in sorted(c.late):
        data = c.late[rel]
        _write(case_dir / rel, data, c.mtimes.get(rel))
        late.append({"id": Path(rel).name, "path": rel, "sha256": _sha(data), "bytes": len(data),
                     "questions": c.late_for.get(rel, []), "what": c.late_what.get(rel, "")})
    goal = c.goal.encode("utf-8")
    _write(case_dir / "goal.md", goal, None)
    case_json = {
        "format": CASE_FORMAT,
        "case": c.case_id,
        "title": c.title,
        "generator_version": GENERATOR_VERSION,
        "inputs": files,
        "late": [{k: v for k, v in item.items() if k != "questions"} for item in late],
        "goal": {"path": "goal.md", "sha256": _sha(goal)},
        "note": "The truth for this case is kept elsewhere, by whoever generated it. Nothing here says what it is.",
    }
    _write(case_dir / "case.json", (json.dumps(case_json, indent=2, ensure_ascii=False) + "\n").encode("utf-8"), None)
    truth = {
        "format": TRUTH_FORMAT,
        "warning": "Owner-only ground truth. Keep it outside the repository and outside every run; never give it, "
                   "or anything derived from it, to a swarm.",
        "generator": {"script": "calibration/generate.py", "version": GENERATOR_VERSION},
        "seed": seed,
        "case": {"id": c.case_id, "title": c.title, "dir": str(case_dir.resolve()), "inputs": "inputs", "goal": "goal.md"},
        "inputs": files,
        "late": late,
        "questions": c.questions,
        "probes": [{"fact": p.fact, "claim": p.claim, "ok": True} for p in c.probes],
        "context": c.context,
    }
    truth_path = truth_dir / f"{c.case_id}.truth.json"
    truth_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(truth_dir, 0o700)
    tmp = truth_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(truth, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, truth_path)
    return {"case": c.case_id, "dir": str(case_dir), "truth": str(truth_path), "inputs": len(files),
            "bytes": sum(f["bytes"] for f in files), "late": len(late), "probes": len(c.probes)}


def _safe(check: Callable[[], bool]) -> bool:
    try:
        return bool(check())
    except Exception:  # noqa: BLE001
        return False


def _chmod_writable(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for n in filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.chmod(p, 0o644)


def _write(path: Path, data: bytes, mtime: Optional[dt.datetime]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mtime is not None:
        ts = mtime.timestamp()
        os.utime(path, (ts, ts))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the synthetic calibration cases and their truth, apart.")
    ap.add_argument("--out", required=True, help="where the cases go: <out>/<case>/{inputs,late,goal.md,case.json}")
    ap.add_argument("--truth-dir", required=True, help="where the truth goes: <truth-dir>/<case>.truth.json; outside the repository and every run")
    ap.add_argument("--seed", help="the seed every value is drawn from; a fresh one when left out (kept in the truth only)")
    ap.add_argument("--cases", help=f"comma-separated, from {','.join(CASES)} (default: all)")
    ap.add_argument("--force", action="store_true", help="replace a case directory this generator wrote before")
    args = ap.parse_args(argv)
    wanted = [c.strip() for c in (args.cases or ",".join(CASES)).split(",") if c.strip()]
    unknown = [c for c in wanted if c not in CASES]
    if unknown:
        print(f"generate.py: unknown case(s): {', '.join(unknown)} (there are {', '.join(CASES)})", file=sys.stderr)
        return 2
    out, truth_dir = Path(args.out).expanduser(), Path(args.truth_dir).expanduser()
    try:
        check_paths(out, truth_dir)
    except Refused as err:
        print(f"generate.py: refused: {err}", file=sys.stderr)
        return 2
    seed = args.seed if args.seed is not None else secrets.token_hex(16)
    written = []
    try:
        for cid in wanted:
            written.append(write_case(CASES[cid](seed), seed, out, truth_dir, args.force))
    except Refused as err:
        print(f"generate.py: refused: {err}", file=sys.stderr)
        return 2
    except RuntimeError as err:
        print(f"generate.py: {err}", file=sys.stderr)
        return 1
    for w in written:
        print(f"{w['case']}: {w['inputs']} input files ({w['bytes']} bytes), {w['late']} late item(s), "
              f"{w['probes']} planted facts checked")
        print(f"  case:  {w['dir']}")
        print(f"  truth: {w['truth']}")
    print("The seed is in the truth files and nowhere else. Keep them outside the repository and every run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
