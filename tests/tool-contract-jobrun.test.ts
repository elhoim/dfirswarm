/**
 * Every pack tool called the way job_run calls it (IMPROVEMENT-PLAN-2 item E12). The job service (scripts/job-service.ts, `script` and
 * `workerSpecFor`) runs a tool in its worker as
 *
 *     cd <run root>; export OUT=<run root>/.jobs/<job>; <runtime> <run root>/tools/<name>/<entry> < /job/args.json
 *
 * with JOB_ID, OUT, AGENT_ID, SWARM_SANDBOX, TZ=UTC, LANG=C.UTF-8, PYTHONDONTWRITEBYTECODE=1 and NO_COLOR=1 in its environment (and
 * SECRET_OUTPUT=1 where the tool's manifest makes the job secret output, by the job service's own reading of it), and the
 * agent names an input relative to the run root (`inputs/...`). Here every tool of packs/*\/tools is copied into a run root's tools/ as the
 * kickoff seeds them, and for every parameter of its manifest that names an input path (a file, a directory, or a list of them), it is
 * given a relative path that holds a space and exists: a small file, or a directory with one file in it, by what the parameter says it
 * takes. The rest of the call is the manifest's own example (its other input paths taken out unless required, and then given the same
 * fixture). The answer must be one JSON object on stdout, no traceback on stderr, within the time, and it must not say that a path
 * which is there is not there: the tool reads the file, or refuses it in words of its own. That is judged twice: a message that says
 * not there and names the fixture itself, and the same call with the path not there (its twin), whose every not-there the answer must
 * not repeat.
 *
 * A tool whose Python module is not installed on this host (a traceback that is ModuleNotFoundError or an ImportError) is skipped, said
 * by name, as the other contract suites do. Every current failure is named in tests/tool-contract-allowed.json ("job_run_path") with
 * the item that removes it; the list may only shrink.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { declaredSecretOutput, parseSecretDeclaration, type SecretDeclaration } from "../scripts/output-hygiene.ts";
import { PYTHON3 } from "./host-gates.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIMIT_MS = 60_000;
const CONCURRENT = 8;

type Param = { type?: string; required?: boolean; description?: string; items?: { type?: string } };
type Manifest = { name: string; runtime?: string; entry?: string; timeout_seconds?: number; example?: string; params?: Record<string, Param>; secret_output?: unknown };
type Tool = { id: string; name: string; manifest: Manifest };
type Entry = { tool: string; item: string; why: string };

/** The names a parameter that takes an input path has in the manifests (an output path, a key or a pattern is not one). */
const INPUT_NAMES = /^(path|paths|root|image|source|sources|hive|db|db_path|dbpath|dir|file|files|inputs|archive|video|backup|target|login_data|local_state|ntuser|system|software|log1|log2|tasks_dir|recovered_root|ciphertext_root|overlay2_root|upper|storage_roots)$/;
/** What the parameter's description must say for the name to be taken as an input path. */
const SAYS_PATH = /\b(path|paths|file|files|director(y|ies)|folder|image|hive|database|tree|root)\b/i;
/** A path inside something else (a volume, a mount, the root, a list's patterns), which names no file of the run. */
const INSIDE = /\b(inside the (volume|mount|root|image)|relative to root|relative paths inside|patterns? matched|to lay out)\b/i;
/** A parameter that takes a directory: its name, or its description. */
const SAYS_DIR = /\b(director(y|ies)|folder|tree)\b/i;

export function inputParams(manifest: Manifest): Array<{ name: string; list: boolean; dir: boolean; required: boolean }> {
  const out: Array<{ name: string; list: boolean; dir: boolean; required: boolean }> = [];
  for (const [name, p] of Object.entries(manifest.params ?? {})) {
    if (!p || typeof p !== "object") continue;
    const list = p.type === "array";
    if (!(p.type === "string" || (list && (p.items?.type ?? "string") === "string"))) continue;
    if (!INPUT_NAMES.test(name) || !SAYS_PATH.test(p.description ?? "") || INSIDE.test(p.description ?? "")) continue;
    const dir = /^(root|dir|tasks_dir|recovered_root|ciphertext_root|overlay2_root|upper|storage_roots)$/.test(name) || (SAYS_DIR.test(p.description ?? "") && !/\bfile\b/i.test(p.description ?? ""));
    out.push({ name, list, dir, required: Boolean(p.required) });
  }
  return out;
}

async function bundledTools(): Promise<Tool[]> {
  const out: Tool[] = [];
  const packs = join(ROOT, "packs");
  for (const pack of (await readdir(packs)).sort()) {
    const tools = join(packs, pack, "tools");
    for (const name of await readdir(tools).catch(() => [] as string[])) {
      const manifest = await readFile(join(tools, name, "manifest.json"), "utf8").then((t) => JSON.parse(t) as Manifest, () => null);
      if (manifest) out.push({ id: `${pack}/${name}`, name, manifest });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** The fixtures: relative to the run root, each with a space in it; and the same call's twin, a path that is not there. */
export const FILE = "inputs/case files/sample file.bin";
export const DIR = "inputs/case files/a folder";
export const ABSENT_FILE = "inputs/case files/absent file.bin";
export const ABSENT_DIR = "inputs/case files/absent folder";
/** Another file of the run the call reads (a rules file, a candidates list, a second sample): the agent's own, under work/. */
export const COMPANION = "work/s1/companion file.bin";

/** The call: the manifest's example, the parameter under test given the fixture, every other input path taken out (or, when required, given the fixture too). */
export function callFor(manifest: Manifest, param: string, absent = false): Record<string, unknown> {
  let args: Record<string, unknown> = {};
  try {
    const ex = manifest.example ? JSON.parse(manifest.example) : {};
    if (ex && typeof ex === "object" && !Array.isArray(ex)) args = ex as Record<string, unknown>;
  } catch {
    args = {};
  }
  // Another value of the example that names a file of a run (work/..., store/...) to read is not there in this one: it is given the
  // agent's own companion file under work/, so that what the tool says is about the path under test. A path the tool writes (an output, a mount point) is kept.
  const RUN_PATH = /^(inputs|work|store|catalog|tools)\//;
  const WRITES = /^(out|output|out_dir|out_file|output_name|extract_to|results_to|symbols_out|mount|mount_dir)$/;
  const names = (v: unknown): boolean => (typeof v === "string" ? RUN_PATH.test(v) : Array.isArray(v) ? v.some(names) : v && typeof v === "object" ? Object.values(v).some(names) : false);
  const toFixture = (v: unknown): unknown => (typeof v === "string" ? (RUN_PATH.test(v) ? COMPANION : v) : Array.isArray(v) ? v.map(toFixture) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toFixture(x)])) : v);
  for (const [name, v] of Object.entries(args)) {
    if (name === param || !names(v)) continue;
    // In a job a tool writes under $OUT alone, and job_run takes {OUT}/<name> for it: the example's work/ path is the agent's spelling.
    if (WRITES.test(name)) args[name] = /^mount/.test(name) || typeof v !== "string" ? v : `{OUT}/${name}`;
    else args[name] = toFixture(v);
  }
  for (const [name, p] of Object.entries(manifest.params ?? {})) {
    if (args[name] !== undefined || !p?.required) continue;
    args[name] = p.type === "integer" || p.type === "number" ? 1 : p.type === "boolean" ? false : p.type === "array" ? [] : p.type === "object" ? {} : /out/.test(name) ? `{OUT}/${name}` : name === "inode" ? "5" : "x";
  }
  for (const ip of inputParams(manifest)) {
    if (ip.name !== param && !ip.required) {
      delete args[ip.name];
      continue;
    }
    const value = ip.name === param && absent ? (ip.dir ? ABSENT_DIR : ABSENT_FILE) : ip.dir ? DIR : FILE;
    args[ip.name] = ip.list ? [value] : value;
  }
  return args;
}

const NOT_THERE = /no such \w+|ENOENT|does not exist|doesn['’]t exist|not found|cannot be found|could not be found|could not find|can['’]t find|is not there|is missing/gi;
/**
 * Where an answer names the fixture itself (not a member of the directory, which need not be there): the whole path not followed by
 * "/", or the path cut at its space ("inputs/case" with no " files" after it), which is how a tool that splits on spaces names it.
 */
const OURS = new RegExp(`(${[FILE, DIR].map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(?![/\\w])|inputs/case(?! files)`, "g");

/** Every string of a JSON value, keys left out. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
}

/** Why an answer is not one a tool called as job_run calls it may give, or null. A path that is there said not to be is the failure E12 names. */
export function jobRunFailure(r: { stdout: string; stderr: string; killed: boolean; code: number | null }): string | null {
  if (r.killed) return `no answer in ${LIMIT_MS / 1000} s`;
  if (/Traceback \(most recent call last\)/.test(r.stderr)) return `a traceback: ${r.stderr.trim().split("\n").pop()?.slice(0, 160)}`;
  const text = r.stdout.trim();
  if (!text) return `no JSON on stdout (exit ${r.code})`;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return `stdout is not one JSON document (exit ${r.code})`;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "the answer is not a JSON object";
  // One message (a string of the answer, a line of stderr) that says not there and names the fixture itself.
  for (const said of [...strings(doc), ...r.stderr.split("\n")]) {
    NOT_THERE.lastIndex = 0;
    OURS.lastIndex = 0;
    if (NOT_THERE.test(said) && OURS.test(said)) return `says a path that is there is not ("${said.replace(/\s+/g, " ").slice(0, 240)}")`;
  }
  return null;
}

/**
 * The messages of an answer that say something is not there, each with the run's own names made one (the fixture and its absent twin,
 * the run root, the job's id), so that two answers can be compared.
 */
export function notThere(stdout: string, root: string): string[] {
  let doc: unknown;
  try {
    doc = JSON.parse(stdout.trim());
  } catch {
    return [];
  }
  const same = (t: string) =>
    [FILE, DIR, ABSENT_FILE, ABSENT_DIR, root].reduce((acc, p) => acc.split(p).join("<P>"), t).replace(/\bj\d{6}\b/g, "<JOB>").replace(/\s+/g, " ");
  return [...new Set(strings(doc).filter((x) => { NOT_THERE.lastIndex = 0; return NOT_THERE.test(x); }).map(same))].sort();
}

/**
 * The same call with the path there and with it not there: a tool that says of the path that is there every not-there it says of the
 * one that is not has not found it (a tool that resolves the path against something other than the run root, or splits it at its space).
 */
export function sameAsAbsent(present: string[], absent: string[]): string | null {
  if (!absent.length) return null;
  return absent.every((m) => present.includes(m)) ? `answers as it does for a path that is not there ("${absent[0]!.slice(0, 200)}")` : null;
}

/** A module the tool imports is not installed here: skipped, said, as the other contract suites do. */
export function missingModule(stderr: string): string | null {
  const m = /(ModuleNotFoundError|ImportError): (.*)$/m.exec(stderr);
  return m ? m[2]!.slice(0, 120) : null;
}

/** A tool that caught the ImportError and says so in its JSON answer ("the tool could not start: a library it needs is missing"): it reads no path on this host either. */
export function missingLibrary(stdout: string): string | null {
  for (const text of [stdout.trim(), stdout.trim().split("\n").pop() ?? ""]) {
    try {
      const a = JSON.parse(text) as { error?: unknown; status_basis?: unknown };
      if (a && typeof a === "object" && /a library it needs is missing/.test(String(a.status_basis ?? ""))) return String(a.error ?? "a library it needs is missing").slice(0, 120);
    } catch {
      // not one JSON document: the next form, or none
    }
  }
  return null;
}

type Run = { code: number | null; stdout: string; stderr: string; killed: boolean };

/** SECRET_OUTPUT=1 where the job service sets it: the manifest's declaration and these arguments (scripts/job-service.ts toolCheck). */
export function secretJob(manifest: Manifest, args: Record<string, unknown>): boolean {
  const d = parseSecretDeclaration(manifest.secret_output, manifest.params as Record<string, unknown> | undefined, Object.hasOwn(manifest, "secret_output"));
  return d.ok && declaredSecretOutput(d.declaration as SecretDeclaration | null, args);
}

function runAsJob(root: string, tool: Tool, jobId: string, args: Record<string, unknown>, extraEnv: Record<string, string> = {}): Promise<Run> {
  return new Promise((resolve) => {
    const out = join(root, ".jobs", jobId);
    const env: Record<string, string> = {
      ...extraEnv,
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: process.env.HOME ?? root,
      JOB_ID: jobId,
      OUT: out,
      AGENT_ID: "s1",
      SWARM_SANDBOX: root,
      TZ: "UTC",
      LANG: "C.UTF-8",
      PYTHONDONTWRITEBYTECODE: "1",
      NO_COLOR: "1",
      ...(secretJob(tool.manifest, args) ? { SECRET_OUTPUT: "1" } : {}),
    };
    const entry = join(root, "tools", tool.name, tool.manifest.entry ?? "run.py");
    const runtime = tool.manifest.runtime === "node" ? process.execPath : tool.manifest.runtime === "bash" ? "bash" : PYTHON3;
    void mkdir(out, { recursive: true }).then(() => {
      const child = spawn(runtime, [entry], { cwd: root, env, stdio: ["pipe", "pipe", "pipe"] });
      const o: Buffer[] = [];
      const e: Buffer[] = [];
      let killed = false;
      const limit = Math.min(LIMIT_MS, (tool.manifest.timeout_seconds ?? 60) * 1000);
      const timer = setTimeout(() => {
        killed = true;
        child.kill("SIGKILL");
      }, limit);
      child.stdout.on("data", (c: Buffer) => o.push(c));
      child.stderr.on("data", (c: Buffer) => e.push(c));
      child.on("error", () => undefined);
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ code, stdout: Buffer.concat(o).toString("utf8"), stderr: Buffer.concat(e).toString("utf8"), killed });
      });
      child.stdin.on("error", () => undefined);
      // A tool that writes files takes {OUT}, which the job service replaces with the job's directory before the tool reads its arguments.
      child.stdin.end(JSON.stringify(args).split("{OUT}").join(out));
    });
  });
}

async function pool<T>(items: T[], fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: CONCURRENT }, async () => {
    while (next < items.length) await fn(items[next++]!);
  }));
}

async function allowed(): Promise<Entry[]> {
  const all = JSON.parse(await readFile(join(ROOT, "tests", "tool-contract-allowed.json"), "utf8")) as Record<string, Entry[]>;
  const list = all.job_run_path;
  assert.ok(Array.isArray(list), 'tests/tool-contract-allowed.json has no list "job_run_path"');
  for (const e of list) assert.ok(e.tool && e.item && e.why && !/\n/.test(e.why), `an entry needs tool, item and a one-line why: ${JSON.stringify(e)}`);
  assert.equal(new Set(list.map((e) => e.tool)).size, list.length, "a tool twice");
  return list;
}

test("every pack tool with an input path, called as job_run calls it with a relative path that holds a space, reads it or refuses it in JSON", { timeout: 1_800_000 }, async () => {
  const tools = (await bundledTools()).filter((t) => inputParams(t.manifest).length);
  assert.ok(tools.length >= 100, `${tools.length} tools take an input path`);
  const top = await mkdtemp(join(tmpdir(), "jobrun-"));
  // The run root, as the job service's cd names it; its own name has no space, the input's does.
  const root = join(top, "run");
  const failures = new Map<string, string>();
  const skipped: string[] = [];
  let runs = 0;
  try {
    await mkdir(join(root, "work"), { recursive: true });
    await mkdir(join(root, DIR), { recursive: true });
    await writeFile(join(root, FILE), Buffer.concat([Buffer.from("not an artefact of any kind\n"), Buffer.alloc(512, 0x41)]));
    await writeFile(join(root, DIR, "one file.txt"), "not an artefact of any kind\n");
    await mkdir(dirname(join(root, COMPANION)), { recursive: true });
    await writeFile(join(root, COMPANION), "not an artefact of any kind\n");
    // The kickoff seeds every pack's tools into tools/<name>: a tool that reads a sibling finds it where it would in a run.
    for (const t of await bundledTools()) await cp(join(ROOT, "packs", t.id.split("/")[0]!, "tools", t.name), join(root, "tools", t.name), { recursive: true });
    const cases = tools.flatMap((tool) => inputParams(tool.manifest).map((p) => ({ tool, param: p.name })));
    let n = 0;
    await pool(cases, async ({ tool, param }) => {
      const jobId = `j${String(++n).padStart(6, "0")}`;
      const args = callFor(tool.manifest, param);
      const r = await runAsJob(root, tool, jobId, args);
      runs++;
      const missing = missingModule(r.stderr);
      const library = missingLibrary(r.stdout);
      if ((missing && /Traceback/.test(r.stderr)) || library) {
        skipped.push(`${tool.id} (${missing ?? library})`);
        return;
      }
      let why = jobRunFailure(r);
      if (!why) {
        // The twin: the same call, the path not there. Run only to compare what each says is not there.
        const twin = await runAsJob(root, tool, `j${String(++n).padStart(6, "0")}`, callFor(tool.manifest, param, true));
        runs++;
        why = sameAsAbsent(notThere(r.stdout, root), notThere(twin.stdout, root));
      }
      if (why && !failures.has(tool.id)) failures.set(tool.id, `${param}=${JSON.stringify(args[param])} in ${JSON.stringify(args)}: ${why}`);
    });
  } finally {
    await rm(top, { recursive: true, force: true });
  }
  console.log(`# ${runs} calls of ${tools.length} tools; ${failures.size} failing, ${skipped.length} skipped`);
  if (skipped.length) console.log(`# skipped, a module not installed here: ${skipped.sort().join("; ")}`);
  assert.ok(runs >= tools.length, `${runs} runs`);
  const list = await allowed();
  const known = new Set(list.map((e) => e.tool));
  const fresh = [...failures].filter(([tool]) => !known.has(tool)).map(([tool, why]) => `  ${tool}: ${why}`);
  assert.equal(fresh.length, 0, `${fresh.length} tool(s) fail as job_run calls them, with no entry in tests/tool-contract-allowed.json "job_run_path":\n${fresh.join("\n")}`);
  const skippedTools = new Set(skipped.map((s) => s.split(" ")[0]));
  const stale = list.filter((e) => !failures.has(e.tool) && !skippedTools.has(e.tool)).map((e) => `  ${e.tool} (${e.item})`);
  assert.equal(stale.length, 0, `${stale.length} entr(ies) of "job_run_path" no longer fail, remove them:\n${stale.join("\n")}`);
});

test("the input parameters are read from the manifest: a path, a list of paths, a directory; not an output, a key or a pattern", () => {
  const m: Manifest = {
    name: "t",
    example: '{"path": "inputs/x", "out_dir": "{OUT}/o", "pattern": "a"}',
    params: {
      path: { type: "string", required: true, description: "File to read, under inputs/." },
      paths: { type: "array", items: { type: "string" }, description: "Several files instead of path." },
      root: { type: "string", description: "The mounted root directory." },
      out_dir: { type: "string", description: "Directory to write to." },
      pattern: { type: "string", description: "A regular expression." },
      target: { type: "string", description: "A host name." },
      sources: { type: "array", description: "Paths inside the volume to copy, from its root." },
    },
  };
  assert.deepEqual(inputParams(m).map((p) => [p.name, p.list, p.dir]), [["path", false, false], ["paths", true, false], ["root", false, true]]);
  assert.deepEqual(callFor(m, "paths"), { path: FILE, out_dir: "{OUT}/o", pattern: "a", paths: [FILE] });
  const other: Manifest = { name: "o", example: '{"path": "inputs/x", "compare_to": "work/y", "sources": [{"candidates": "store/jobs/j1/out/c.jsonl"}], "n": 3}', params: { path: { type: "string", description: "The file." }, compare_to: { type: "string", description: "A second file." }, sources: { type: "array", required: true, description: "Where candidates are." }, n: { type: "integer" } } };
  assert.deepEqual(callFor(other, "path"), { path: FILE, compare_to: COMPANION, sources: [{ candidates: COMPANION }], n: 3 }, "another value that names a run's file to read is given the companion");
  const writes: Manifest = { name: "w", example: '{"path": "inputs/x", "out_dir": "work/s1/o"}', params: { path: { type: "string", description: "The file." }, out_dir: { type: "string", required: true, description: "Directory to write to." } } };
  assert.deepEqual(callFor(writes, "path"), { path: FILE, out_dir: "{OUT}/out_dir" }, "a path the tool writes is under {OUT}, as job_run takes it");
  assert.deepEqual(callFor(m, "root"), { path: FILE, out_dir: "{OUT}/o", pattern: "a", root: DIR });
});

test("the job_run check finds a path said not to be there, a traceback, a hang, no JSON, and takes a refusal of the content", () => {
  const ok = (stdout: string, stderr = ""): Run => ({ code: 0, stdout, stderr, killed: false });
  assert.equal(jobRunFailure(ok('{"status":"failed","status_basis":"inputs/case files/sample file.bin is not a registry hive"}')), null);
  assert.equal(jobRunFailure(ok('{"status":"complete","status_basis":"read","hits":[],"note":"no key found"}')), null);
  assert.match(jobRunFailure(ok('{"status":"failed","status_basis":"path not found: inputs/case"}')) ?? "", /a path that is there is not/);
  assert.match(jobRunFailure(ok('{"status":"failed","errors":["/opt/tools/x/inputs/case files/a folder does not exist"]}')) ?? "", /a path that is there is not/);
  assert.match(jobRunFailure(ok('{"error":"No such file or directory: \'/r/inputs/case files/sample file.bin\'"}')) ?? "", /a path that is there is not/);
  assert.equal(jobRunFailure(ok('{"root":"inputs/case files/a folder","problems":["var/lib/dpkg: No such file or directory: \'inputs/case files/a folder/var/lib/dpkg\'"]}')), null, "a member of the directory need not be there");
  assert.equal(jobRunFailure(ok('{"root":"inputs/case files/a folder","definitions":"not found"}')), null, "a not-found of another value is that value's");
  assert.match(jobRunFailure({ ...ok('{"status":"failed"}'), stderr: "open inputs/case: No such file or directory" }) ?? "", /a path that is there is not/);
  assert.match(jobRunFailure(ok("", "Traceback (most recent call last):\n  File x\nOSError: boom")) ?? "", /traceback/);
  assert.match(jobRunFailure(ok("")) ?? "", /no JSON/);
  assert.match(jobRunFailure(ok("{} {}")) ?? "", /not one JSON document/);
  assert.match(jobRunFailure({ ...ok("{}"), killed: true }) ?? "", /no answer/);
  assert.equal(missingModule("Traceback (most recent call last):\nModuleNotFoundError: No module named 'regipy'"), "No module named 'regipy'");
  assert.equal(missingModule("OSError: x"), null);
  const root = "/tmp/r";
  const absent = notThere(`{"status":"failed","error":"no such file or directory","path":"${ABSENT_FILE}"}`, root);
  assert.deepEqual(absent, ["no such file or directory"]);
  assert.match(sameAsAbsent(notThere(`{"status":"failed","error":"no such file or directory","path":"${FILE}"}`, root), absent) ?? "", /as it does for a path that is not there/);
  assert.equal(sameAsAbsent(notThere(`{"status":"failed","error":"not a hive","path":"${FILE}"}`, root), absent), null);
  // A not-there of another value, said in both, is that value's: the path's own is said only of the absent twin.
  const both = notThere(`{"errors":["definitions not found","${ABSENT_DIR} does not exist"]}`, root);
  assert.equal(sameAsAbsent(notThere('{"errors":["definitions not found"]}', root), both), null);
  assert.equal(sameAsAbsent(notThere('{"status":"complete"}', root), []), null);
});

// ---- E12: a valid input per tool family, so the code past the format check runs on the job's path ---------------------------------

/**
 * The calls above give every tool a file that is no artefact, so a tool refuses it at its format check and the code after it, where
 * the path is handed on (to a reader child, a second open, a directory walk), never runs: browser_storage gave its reader, which runs
 * with / as its working directory, the caller's relative path (0.3, I-11), and passed. Here a tool family whose input is cheap to make
 * whole is given one, at a run-relative path with spaces, and must read it: no traceback, one JSON answer, no member of the input said
 * not to be there (FileNotFoundError, ENOENT, "no such file"), and a status other than failed, unless the tool says its reader is not
 * on this host (unavailable) or a module it imports is missing.
 */
type Family = {
  name: string;
  /** The input, made under the run root; its path relative to the root has a space in it. */
  make: (root: string) => Promise<string>;
  /** The tools that read it, each with the parameter it goes in and the rest of the call. */
  calls: Array<{ tool: string; param: string; args?: Record<string, unknown> }>;
  /** What the run's environment needs for the family's reader (browser_storage's runs in a venv of its own). */
  env?: (root: string) => Promise<Record<string, string>>;
};

const pyMake = (code: string, ...argv: string[]) => {
  const r = spawnSync(PYTHON3, ["-c", code, ...argv], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
};

/** A stand-in for ccl_chromium_reader's process (tests/pack-base-job-call.test.ts): it opens each data file by the path the tool hands it, from the working directory the tool gives it. */
async function standInReader(root: string): Promise<Record<string, string>> {
  const src = join(root, "work", "reader src");
  const bin = join(src, "ccl_indexeddb_dump", ".venv", "bin");
  await mkdir(bin, { recursive: true });
  await writeFile(join(src, "reader.py"), [
    "import json, os, sys",
    "spec = json.load(sys.stdin)",
    "files = []",
    "for name, kind in spec['files']:",
    "    entry = {'name': name, 'kind': kind, 'size': None, 'records': 0, 'put': 0, 'delete': 0, 'unknown': 0, 'records_in_compressed_blocks': 0, 'status': 'read'}",
    "    try:",
    "        fd = os.open(os.path.join(spec['path'], name), os.O_RDONLY | os.O_NOFOLLOW)",
    "        entry['size'] = os.fstat(fd).st_size",
    "        os.close(fd)",
    "    except OSError as exc:",
    "        entry.update({'status': 'failed', 'stage': 'open', 'error_class': type(exc).__name__})",
    "    files.append(entry)",
    "print(json.dumps({'ok': True, 'versions': {}, 'files': files, 'format': 'leveldb', 'records_total': 0, 'counts': {}, 'previews': [], 'decode_errors': {}, 'leveldb': {}}))",
  ].join("\n") + "\n");
  // The tool starts it as <python> -I -c <the reader's code>, the specification on stdin: the stand-in takes the stdin and ignores the code.
  await writeFile(join(bin, "python"), `#!/bin/sh\nexec '${PYTHON3}' '${join(src, "reader.py")}'\n`);
  await chmod(join(bin, "python"), 0o755);
  return { DFIRSWARM_SRC_DIR: src };
}

export const FAMILIES: Family[] = [
  {
    name: "a Chromium LevelDB directory",
    make: async (root) => {
      const dir = "inputs/case files/Local Storage/leveldb";
      await mkdir(join(root, dir), { recursive: true });
      await writeFile(join(root, dir, "000003.log"), Buffer.alloc(64, 0));
      await writeFile(join(root, dir, "MANIFEST-000001"), Buffer.alloc(16, 0));
      return dir;
    },
    calls: [{ tool: "browser_storage", param: "path" }],
    env: standInReader,
  },
  {
    name: "a SQLite database",
    make: async (root) => {
      const db = "inputs/case files/a store.db";
      pyMake("import sqlite3,sys\nc=sqlite3.connect(sys.argv[1]);c.execute('create table t (a text)');c.execute(\"insert into t values ('x')\");c.commit();c.close()", join(root, db));
      return db;
    },
    calls: [
      { tool: "sqlite_query", param: "db_path", args: { sql: "select count(*) from t;" } },
      { tool: "sqlite_snapshot", param: "db_path", args: { out_dir: "{OUT}/snapshot" } },
      { tool: "sqlite_freespace", param: "db" },
    ],
  },
  {
    name: "a ZIP archive",
    make: async (root) => {
      const zip = "inputs/case files/an archive.zip";
      pyMake("import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1],'w');z.writestr('dir one/a member.txt','not an artefact\\n');z.close()", join(root, zip));
      return zip;
    },
    calls: [
      { tool: "archive_extract", param: "path", args: { out_dir: "{OUT}/members" } },
      { tool: "archive_probe", param: "path" },
      { tool: "archive_metadata", param: "path" },
    ],
  },
  {
    name: "a property list",
    make: async (root) => {
      const plist = "inputs/case files/com.example.agent.plist";
      pyMake("import plistlib,sys\nopen(sys.argv[1],'wb').write(plistlib.dumps({'Label':'com.example.agent','ProgramArguments':['/bin/true']}))", join(root, plist));
      return plist;
    },
    calls: [{ tool: "plist_read", param: "path" }],
  },
  {
    name: "a syslog authentication log",
    make: async (root) => {
      const log = "inputs/case files/var log/auth.log";
      await mkdir(dirname(join(root, log)), { recursive: true });
      await writeFile(join(root, log), "Mar  3 10:00:01 host sshd[101]: Accepted publickey for alice from 192.0.2.7 port 50000 ssh2\n");
      return log;
    },
    calls: [{ tool: "auth_log", param: "path", args: { year: 2026 } }],
  },
  {
    name: "a CloudTrail file",
    make: async (root) => {
      const file = "inputs/case files/cloud trail/events.json";
      await mkdir(dirname(join(root, file)), { recursive: true });
      await writeFile(join(root, file), JSON.stringify({ Records: [{ eventVersion: "1.08", eventTime: "2026-03-03T10:00:01Z", eventSource: "s3.amazonaws.com", eventName: "ListBuckets", awsRegion: "us-east-1", eventID: "00000000-0000-0000-0000-000000000001", userIdentity: { type: "IAMUser", arn: "arn:aws:iam::000000000000:user/example" } }] }));
      return file;
    },
    calls: [{ tool: "cloudtrail_parse", param: "path" }],
  },
  {
    name: "a home directory with a shell history",
    make: async (root) => {
      const tree = "inputs/case files/extracted root";
      await mkdir(join(root, tree, "home", "alice"), { recursive: true });
      await writeFile(join(root, tree, "home", "alice", ".bash_history"), "ls -la\nwhoami\n");
      return tree;
    },
    calls: [{ tool: "shell_history", param: "root" }],
  },
];

/** Why a tool's answer to a whole input it was given is not a reading of it, or null. */
export function validInputFailure(r: { stdout: string; stderr: string; killed: boolean; code: number | null }): string | null {
  const first = jobRunFailure(r);
  if (first) return first;
  const doc = JSON.parse(r.stdout.trim()) as Record<string, unknown>;
  for (const said of strings(doc)) if (/FileNotFoundError|NotADirectoryError|ENOENT|no such file/i.test(said)) return `says a member of a whole input is not there ("${said.slice(0, 160)}")`;
  if (doc.status === "failed" || doc.ok === false) return `status ${String(doc.status ?? "failed")}: ${String(doc.status_basis ?? doc.error ?? "").slice(0, 200)}`;
  return null;
}

/** The tool says its reader is not on this host (its program, or the venv it runs in): it cannot read the input here, said, not judged. */
const unavailable = (stdout: string): string | null => {
  try {
    const a = JSON.parse(stdout.trim()) as { unavailable?: unknown; status_basis?: unknown; error?: unknown };
    return a.unavailable === true ? String(a.status_basis ?? a.error ?? "unavailable").slice(0, 120) : null;
  } catch {
    return null;
  }
};

/** Every family, each tool as job_run calls it: what failed, and what this host could not run. */
async function familyRuns(toolsDir: (name: string) => string | null): Promise<{ failures: Map<string, string>; skipped: string[]; runs: number }> {
  const all = await bundledTools();
  const top = await mkdtemp(join(tmpdir(), "jobrun-valid-"));
  const root = join(top, "run");
  const failures = new Map<string, string>();
  const skipped: string[] = [];
  let runs = 0;
  try {
    await mkdir(join(root, "work"), { recursive: true });
    for (const t of all) await cp(toolsDir(t.name) ?? join(ROOT, "packs", t.id.split("/")[0]!, "tools", t.name), join(root, "tools", t.name), { recursive: true });
    let n = 0;
    for (const family of FAMILIES) {
      const input = await family.make(root);
      assert.match(input, / /, "the path holds a space");
      const env = family.env ? await family.env(root) : {};
      for (const c of family.calls) {
        const tool = all.find((t) => t.name === c.tool);
        assert.ok(tool, `${c.tool} is a bundled tool`);
        assert.ok(Object.hasOwn(tool.manifest.params ?? {}, c.param), `${c.tool} takes ${c.param}`);
        const args = { ...callFor(tool.manifest, c.param), ...(c.args ?? {}), [c.param]: input };
        const r = await runAsJob(root, tool, `j${String(++n).padStart(6, "0")}`, args, env);
        runs++;
        const missing = (/Traceback/.test(r.stderr) && missingModule(r.stderr)) || missingLibrary(r.stdout) || unavailable(r.stdout);
        if (missing) {
          skipped.push(`${c.tool} (${missing})`);
          continue;
        }
        const why = validInputFailure(r);
        if (why) failures.set(c.tool, `${family.name} at ${JSON.stringify(input)}: ${why}`);
      }
    }
  } finally {
    await rm(top, { recursive: true, force: true });
  }
  return { failures, skipped, runs };
}

test("a tool family with a cheap whole input reads it as job_run calls it, past its format check: a run-relative path with spaces reaches the code that opens it (E12)", { timeout: 600_000 }, async () => {
  const { failures, skipped, runs } = await familyRuns(() => null);
  console.log(`# ${runs} calls of ${FAMILIES.length} families; ${failures.size} failing, ${skipped.length} skipped${skipped.length ? `: ${skipped.join("; ")}` : ""}`);
  assert.equal(runs, FAMILIES.reduce((k, f) => k + f.calls.length, 0));
  assert.deepEqual([...failures].map(([t, why]) => `${t}: ${why}`), []);
});

test("the family check finds the 0.3 defect: browser_storage before 52c2b7dc, which handed its reader the relative path, fails it (E12)", { timeout: 300_000 }, async (t) => {
  // The tool as it was, read with git show (the commit's parent), never checked out. A clone without that history skips, said.
  const files = ["run.py", "manifest.json"].map((f) => spawnSync("git", ["show", `52c2b7dc^:packs/computer-forensics-base/tools/browser_storage/${f}`], { cwd: ROOT, encoding: "utf8", maxBuffer: 64 << 20 }));
  if (files.some((r) => r.status !== 0)) {
    t.skip("commit 52c2b7dc is not in this clone's history");
    return;
  }
  const old = await mkdtemp(join(tmpdir(), "browser-storage-0.3-"));
  try {
    await writeFile(join(old, "run.py"), files[0]!.stdout);
    await writeFile(join(old, "manifest.json"), files[1]!.stdout);
    const { failures } = await familyRuns((name) => (name === "browser_storage" ? old : null));
    assert.match(failures.get("browser_storage") ?? "", /a Chromium LevelDB directory at "inputs\/case files\/Local Storage\/leveldb": says a member of a whole input is not there \("FileNotFoundError"\)/);
    assert.deepEqual([...failures.keys()], ["browser_storage"], "the other tools of the families, as they are, still pass");
  } finally {
    await rm(old, { recursive: true, force: true });
  }
});

test("the valid-input check: a reading passes; a member said not there, a failed status, a traceback and no JSON fail", () => {
  const ok = (stdout: string, stderr = ""): Run => ({ code: 0, stdout, stderr, killed: false });
  assert.equal(validInputFailure(ok('{"status":"complete","files":[{"name":"000003.log","status":"read"}]}')), null);
  assert.equal(validInputFailure(ok('{"status":"partial","note":"a record was cut"}')), null);
  assert.match(validInputFailure(ok('{"status":"failed","status_basis":"no data file could be read","files":[{"name":"000003.log","status":"failed","error_class":"FileNotFoundError"}]}')) ?? "", /not there \("FileNotFoundError"\)/);
  assert.match(validInputFailure(ok('{"status":"failed","status_basis":"not a SQLite database"}')) ?? "", /status failed: not a SQLite database/);
  assert.match(validInputFailure(ok("", "Traceback (most recent call last):\nOSError: x")) ?? "", /traceback/);
  assert.match(validInputFailure(ok("")) ?? "", /no JSON/);
  assert.equal(unavailable('{"status":"failed","unavailable":true,"status_basis":"the venv is not installed"}'), "the venv is not installed");
});
