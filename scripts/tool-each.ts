/**
 * A directory given to a one-file reader (IMPROVEMENT-PLAN-2 item D4). Most
 * pack tools that read a file read one a call, and seats gave them a
 * directory (a profile's folder, a log directory) and learned from the
 * refusal. The job service runs such a call once per file instead: the
 * files of the directory the tool's manifest says it reads (its `use`: an
 * extension, first bytes or a name; every regular file for a manifest that
 * says nothing), one after another in the same job, each with its own
 * output directory, and the job's answer lists every run with its status.
 *
 * Nothing here knows a tool. A parameter is a one-file parameter when its
 * name is one the manifests give a path (path, hive, image, ...) and its
 * description does not say it takes a directory. A directory that holds no
 * file the tool reads, more than EACH_MAX of them, or more entries than can
 * be listed, is refused before the job runs, with what to do: never cut.
 */
import { lstatSync, openSync, readSync, closeSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { matchTool, type ToolUse } from "./library-hint.ts";

/** The most files one call runs the tool over. */
export const EACH_MAX = 64;
/** The most entries listed under the directory (files and directories, every level). */
export const EACH_WALK_MAX = 5000;
/** The deepest level below the directory that is listed. */
export const EACH_DEPTH_MAX = 6;
/** The bytes of a file's head read for a manifest's magic. */
const HEAD_MAX = 4096;

/** The names manifests give a parameter that is a path. */
const PATHLIKE = new Set(["path", "hive", "image", "source", "file", "db", "database", "capture", "archive", "dump", "evidence"]);
/** A description that says the parameter takes a directory (or a tree a tool walks itself). */
const TAKES_DIR = /director|folder|collection|\bwalk|\btree\b|\broot\b|logarchive|bundle/i;

type Param = { type?: string; description?: string };

/** One call run once per file: which parameter, the directory it named, and the files (run-relative), in name order. */
export type EachSpec = { param: string; directory: string; files: string[] };

export type EachResult = { ok: true; each: EachSpec | null } | { ok: false; reason: string };

/** The parameters of a manifest that take one file. */
export function oneFileParams(params: Record<string, Param> | undefined): string[] {
  return Object.entries(params ?? {})
    .filter(([key, p]) => p && typeof p === "object" && (p.type ?? "string") === "string" && PATHLIKE.has(key) && !TAKES_DIR.test(String(p.description ?? "")))
    .map(([key]) => key);
}

function head(abs: string): Buffer | null {
  let fd: number | null = null;
  try {
    fd = openSync(abs, "r");
    const b = Buffer.alloc(HEAD_MAX);
    const n = readSync(fd, b, 0, HEAD_MAX, 0);
    return b.subarray(0, n);
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

/**
 * Whether this call is one to run once per file: the first one-file
 * parameter whose value names a directory of the run (not a link) makes it
 * so. `args` are the arguments after references were resolved (paths
 * relative to the run's directory `S`).
 */
export function eachOf(S: string, tool: string, args: Record<string, unknown>, man: { params?: Record<string, Param>; use?: ToolUse; description?: string }): EachResult {
  const root = resolve(S);
  for (const param of oneFileParams(man.params)) {
    const v = args[param];
    if (typeof v !== "string" || !v.trim() || v.includes("{OUT}")) continue;
    const abs = resolve(root, v);
    if (abs !== root && !abs.startsWith(`${root}/`)) continue;
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      continue;
    }
    if (!st.isDirectory()) continue;
    const dir = relative(root, abs) || ".";
    const files: string[] = [];
    let listed = 0;
    let unread = 0;
    const walk = (d: string, depth: number): boolean => {
      let names: string[];
      try {
        names = readdirSync(d).sort();
      } catch {
        unread += 1;
        return true;
      }
      for (const name of names) {
        listed += 1;
        if (listed > EACH_WALK_MAX) return false;
        const p = join(d, name);
        let s;
        try {
          s = lstatSync(p);
        } catch {
          unread += 1;
          continue;
        }
        if (s.isDirectory()) {
          if (depth >= EACH_DEPTH_MAX) {
            unread += 1;
            continue;
          }
          if (!walk(p, depth + 1)) return false;
          continue;
        }
        if (!s.isFile()) continue;
        const rel = relative(root, p);
        const use = man.use && typeof man.use === "object" ? man.use : null;
        const hit = !use || matchTool({ use }, { input: rel, path: p, head: use.magic?.length ? head(p) : null }).length > 0;
        if (hit) files.push(rel);
      }
      return true;
    };
    const whole = walk(abs, 1);
    const form = `give ${param} one file, or a directory that holds at most ${EACH_MAX} files it reads`;
    if (!whole) return { ok: false, reason: `tool ${tool}: ${param} names the directory ${dir}, which holds more than ${EACH_WALK_MAX} entries (files and directories, every level); ${tool} reads one file a call: ${form} (a listing of the directory finds them)` };
    if (unread) return { ok: false, reason: `tool ${tool}: ${param} names the directory ${dir}, and ${unread} of its entries could not be listed or lie deeper than ${EACH_DEPTH_MAX} levels; ${tool} reads one file a call: ${form}` };
    if (!files.length) {
      const what = man.use ? "file its manifest says it reads (by extension, first bytes or name)" : "regular file";
      return { ok: false, reason: `tool ${tool}: ${param} names the directory ${dir}, which holds no ${what}; ${tool} reads one file a call: give ${param} the file itself` };
    }
    if (files.length > EACH_MAX) return { ok: false, reason: `tool ${tool}: ${param} names the directory ${dir}, which holds ${files.length} files it reads (${files.slice(0, 3).join(", ")}, ...); one call runs it over at most ${EACH_MAX}: name a narrower directory, or one file a call` };
    return { ok: true, each: { param, directory: dir, files } };
  }
  return { ok: true, each: null };
}

/** What a job's answer says of a call run once per file, in one sentence. */
export function eachWords(each: EachSpec): string {
  return `${each.param} named the directory ${each.directory}, so the tool was run once for each of the ${each.files.length} file(s) in it it reads, each with its own output directory each/<n>/ (its answer in each/<n>/answer.json); the job's stdout lists every run and its status.`;
}

/**
 * The worker's side: runs the tool once per file, in order, under one
 * clock, and prints one answer. Each run has its own session, its own
 * output directory and its own answer file; a stop signal ends the run in
 * progress (its session only) and the answer names what was not run. The
 * answer is complete only when every file was run, every run exited 0, and
 * no run's answer said it was not complete.
 */
export const EACH_SCRIPT = String.raw`import json, os, signal, subprocess, sys, time
plan = json.load(open(sys.argv[1]))
base = os.environ["OUT"]
start = time.monotonic()
deadline = start + max(5.0, float(plan["seconds"]) - 15.0)
INLINE_ONE = 256 * 1024
INLINE_ALL = 2 * 1024 * 1024
state = {"child": None, "stopped": None}
def stop(sig, frame):
    state["stopped"] = state["stopped"] or ("signal %d" % sig)
    c = state["child"]
    if c is not None:
        try:
            os.killpg(c.pid, signal.SIGKILL)
        except Exception:
            pass
for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(s, stop)
runs, not_run, basis, inline = [], [], [], 0
def settled(ans):
    if not isinstance(ans, dict):
        return False
    st = ans.get("status")
    if isinstance(st, str) and st.lower() not in ("complete", "ok", "success", "done"):
        return False
    if ans.get("complete") is False or ans.get("partial") is True or ans.get("ok") is False:
        return False
    return True
for n, r in enumerate(plan["runs"], 1):
    if state["stopped"] or time.monotonic() >= deadline:
        not_run.append(r["file"])
        continue
    out = os.path.join(base, "each", str(n))
    os.makedirs(out, exist_ok=True)
    apath = os.path.join(out, "answer.json")
    env = dict(os.environ)
    env["OUT"] = out
    row = {"file": r["file"], "out": "each/%d" % n, "answer": "each/%d/answer.json" % n}
    with open(r["args"], "rb") as fin, open(apath, "wb") as fout, open(os.path.join(out, "stderr.log"), "wb") as ferr:
        try:
            c = subprocess.Popen(plan["argv"], stdin=fin, stdout=fout, stderr=ferr, env=env, start_new_session=True)
        except Exception as e:
            row.update({"exit": None, "status": "not_started", "why": str(e)[:200]})
            runs.append(row)
            continue
        state["child"] = c
        if state["stopped"]:
            stop(signal.SIGTERM, None)
        try:
            c.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            state["stopped"] = state["stopped"] or "clock"
            try:
                os.killpg(c.pid, signal.SIGKILL)
            except Exception:
                pass
            c.wait()
            row["stopped_by"] = "clock"
        state["child"] = None
    row["exit"] = c.returncode
    ans = None
    size = -1
    try:
        size = os.path.getsize(apath)
        if size <= 8 * 1024 * 1024:
            ans = json.loads(open(apath, "rb").read() or b"null")
    except Exception:
        ans = None
    if isinstance(ans, dict) and isinstance(ans.get("status"), str):
        row["status"] = ans["status"]
    ok = c.returncode == 0 and settled(ans) and "stopped_by" not in row
    row["settled"] = ok
    if not ok:
        basis.append("%s: %s" % (r["file"], "exit %s" % c.returncode if c.returncode != 0 else ("stopped" if "stopped_by" in row else "its answer is not complete")))
    if ans is not None and 0 <= size <= INLINE_ONE and inline + size <= INLINE_ALL:
        row["result"] = ans
        inline += size
    runs.append(row)
if not_run:
    basis.append("%d file(s) not run (%s)" % (len(not_run), state["stopped"] or "clock"))
answer = {
    "tool": plan["tool"],
    "each": {"param": plan["param"], "directory": plan["directory"], "files": len(plan["runs"]), "ran": len(runs)},
    "status": "complete" if not basis else "partial",
    "runs": runs,
}
if basis:
    answer["status_basis"] = basis[:32]
if not_run:
    answer["not_run"] = not_run
sys.stdout.write(json.dumps(answer, indent=1) + "\n")
sys.stdout.flush()
sys.exit(0 if any(x.get("exit") == 0 for x in runs) else 1)
`;

/** The plan the worker's script reads: the tool's command and each file's arguments file. */
export function eachPlan(tool: string, each: EachSpec, argv: string[], seconds: number, argsFile: (n: number) => string): Record<string, unknown> {
  return { tool, param: each.param, directory: each.directory, argv, seconds, runs: each.files.map((file, k) => ({ file, args: argsFile(k + 1) })) };
}


/** One run of a tool, as the seat's own runner gives it (protocol-core.ts runForgedTool). */
export type EachRun = { ok: boolean; exit_code: number | null; stdout: string; stderr: string; timed_out: boolean; duration_ms?: number };

/**
 * The seat's side of a call run once per file (a pack tool called directly,
 * IMPROVEMENT-PLAN-2 D4): the same plan and the same one answer as the
 * worker's script (EACH_SCRIPT), the runs one after another under one clock
 * of `seconds`. `runOne` runs the tool with one file's arguments and the
 * seconds left. The answer is complete only when every file was run, every
 * run exited 0, and no run's answer said it was not complete.
 */
export async function runEachDirect(tool: string, each: EachSpec, args: Record<string, unknown>, seconds: number, runOne: (args: Record<string, unknown>, secondsLeft: number) => Promise<EachRun>): Promise<EachRun> {
  const started = Date.now();
  const deadline = started + Math.max(5, seconds) * 1000;
  const runs: Array<Record<string, unknown>> = [];
  const notRun: string[] = [];
  const basis: string[] = [];
  let inline = 0;
  let stopped = "";
  for (const [k, file] of each.files.entries()) {
    const left = Math.floor((deadline - Date.now()) / 1000);
    if (stopped || left < 1) {
      stopped ||= "clock";
      notRun.push(file);
      continue;
    }
    const r = await runOne({ ...args, [each.param]: file }, left);
    let ans: unknown = null;
    try {
      ans = r.stdout.length <= 8 * 1024 * 1024 ? JSON.parse(r.stdout.trim() || "null") : null;
    } catch {
      ans = null;
    }
    const row: Record<string, unknown> = { file, n: k + 1, exit: r.exit_code };
    if (ans && typeof ans === "object" && !Array.isArray(ans) && typeof (ans as { status?: unknown }).status === "string") row.status = (ans as { status: string }).status;
    if (r.timed_out) {
      row.stopped_by = "clock";
      stopped = "clock";
    }
    const a = ans as { status?: unknown; complete?: unknown; partial?: unknown; ok?: unknown } | null;
    const settled = Boolean(a && typeof a === "object" && !Array.isArray(a) && !(typeof a.status === "string" && !["complete", "ok", "success", "done"].includes(a.status.toLowerCase())) && a.complete !== false && a.partial !== true && a.ok !== false);
    const ok = r.exit_code === 0 && settled && !r.timed_out;
    row.settled = ok;
    if (!ok) basis.push(`${file}: ${r.exit_code !== 0 ? `exit ${r.exit_code}` : r.timed_out ? "stopped" : "its answer is not complete"}`);
    const size = Buffer.byteLength(r.stdout);
    if (ans !== null && size <= 256 * 1024 && inline + size <= 2 * 1024 * 1024) {
      row.result = ans;
      inline += size;
    } else if (r.stdout.trim()) row.output = `${r.stdout.slice(0, 2000)}${r.stdout.length > 2000 ? "…" : ""}`;
    if (!ok && r.stderr.trim()) row.stderr = r.stderr.trim().split("\n").slice(-3).join("\n").slice(0, 600);
    runs.push(row);
  }
  if (notRun.length) basis.push(`${notRun.length} file(s) not run (${stopped || "clock"})`);
  const answer: Record<string, unknown> = { tool, each: { param: each.param, directory: each.directory, files: each.files.length, ran: runs.length }, status: basis.length ? "partial" : "complete", runs };
  if (basis.length) answer.status_basis = basis.slice(0, 32);
  if (notRun.length) answer.not_run = notRun;
  const anyOk = runs.some((x) => x.exit === 0);
  return { ok: anyOk, exit_code: anyOk ? 0 : 1, stdout: `${JSON.stringify(answer, null, 1)}\n`, stderr: "", timed_out: stopped === "clock", duration_ms: Date.now() - started };
}

/** What a direct call run once per file says of it, in one sentence (each run's answer is in the one answer, not in a directory of its own). */
export function eachDirectWords(each: EachSpec): string {
  return `${each.param} named the directory ${each.directory}, so the tool was run once for each of the ${each.files.length} file(s) in it it reads; its answer lists every run and its status.`;
}
