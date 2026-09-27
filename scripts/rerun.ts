#!/usr/bin/env node
/**
 * A sealed job run again, to see whether its outputs come out the same
 * (swarm.sh rerun <run> <job>).
 *
 * The job's recorded spec, as the store's journal accepted it, is run
 * through the job service's own worker path (the script it writes, the
 * mounts it gives, the worker it asks for) in the image the job ran in,
 * held to the digest the journal recorded: an image that is not that digest
 * here is refused, never substituted. A tool or a recipe is held to the
 * sha256 the job ran; one that differs is refused. The outputs go to a
 * rerun area beside the run (<sandbox>.reruns/<job>/<n>/), never into the
 * run's store, and each is compared with the sealed manifest by its bytes:
 * the files that are the same, the ones that differ (both hashes), the ones
 * missing and the ones added, and the job's stdout and stderr. A byte
 * mismatch is a mismatch.
 *
 * When asked (--normalise NAME@VERSION), and only then, a named, versioned
 * normalisation is applied to the text of the files that differ and the
 * ones that are then equal are reported apart, as equivalent under it: never
 * as reproduced. The normalisations are fixed here, each with its version
 * and exact definition, recorded in the rerun's record:
 *
 *   timestamps@1: in a text file (no NUL in its first 8 KiB), every ISO 8601
 *     date-time (2026-09-27T12:00:00, with a space for the T, fractions and
 *     a zone or Z optional) and every RFC 2822 date-time (Sun, 27 Sep 2026
 *     12:00:00 +0000) replaced by <TIME>.
 *
 * What is not reproduced by a rerun, and is said: which bytes the job read
 * (not measured), anything fetched over the network (the rerun has none
 * unless --network gives it the job's own), a live file an import copied
 * (an import is refused), and the model's reasoning that asked for the job.
 *
 *   node scripts/rerun.ts <sandbox> <job> [--run ID] [--runs DIR] [--normalise timestamps@1] [--network] [--json]
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { JobService, type JobRecord, type JobServiceOptions } from "./job-service.ts";
import { readManifest, verifyJournalText, type JournalLine } from "./evidence-store.ts";
import type { Mount, WorkerSpec } from "./vm.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** The normalisations a rerun may be compared under, when asked: each by name and version, with its definition. */
export const NORMALISATIONS: Record<string, { definition: string; apply: (text: string) => string }> = {
  "timestamps@1": {
    definition:
      "In a text file (no NUL in its first 8 KiB): every ISO 8601 date-time /\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?/ and every RFC 2822 date-time /(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \\d{4} \\d{2}:\\d{2}:\\d{2}( [+-]\\d{4}| GMT| UTC)?/ replaced by <TIME>.",
    apply: (text) =>
      text
        .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, "<TIME>")
        .replace(/(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2}(?: [+-]\d{4}| GMT| UTC)?/g, "<TIME>"),
  },
};

/** What the worker path is asked for: the job service's run, and how the image's digest is read here. */
export type RerunDeps = {
  runWorker: JobServiceOptions["runWorker"];
  destroyWorker: JobServiceOptions["destroyWorker"];
  /** The digest an image reference has on this host (msb's word), or null when it is not here. */
  imageDigest: (ref: string) => Promise<string | null>;
};

/**
 * The job service's internals this uses: the script it writes for a job,
 * the mounts it gives the worker, where $OUT is in the guest, the network.
 * They are the same functions a job ran through; they are private to it, so
 * they are named here once (a test fails if one is gone).
 */
type Internals = {
  script(job: JobRecord, ctl: string): Promise<{ lines: string[]; tool_sha256?: string }>;
  mounts(job: JobRecord, st: { out: string; ctl: string }): { mounts: Mount[]; accessible: Array<{ path: string; access: string }> };
  outPath(job: JobRecord): string;
  network(job: JobRecord): WorkerSpec["network"];
};

export type FileCompare = { path: string; original: string | null; rerun: string | null };

export type RerunRecord = {
  kind: "dfirswarm-rerun";
  run: string;
  job: string;
  n: number;
  at: string;
  original: { status: string | null; exit: number | null; image: string; image_digest: string; tool_sha256: string | null; manifest_sha256: string | null; files: number; network: string };
  rerun: { image_digest_here: string; worker_digest: string | null; exit: number | null; status: string; fenced: boolean; network: string; error: string | null };
  compare: { identical: string[]; differ: FileCompare[]; missing: string[]; added: string[]; logs: Array<{ name: string; original: string | null; rerun: string | null; same: boolean }> };
  verdict: string;
  normalised: null | { name: string; definition: string; equivalent: string[]; still_differ: string[]; note: string };
  not_reproduced: string[];
};

function jobLines(S: string): JournalLine[] {
  const path = join(S, "store", "journal.jsonl");
  if (!existsSync(path)) throw new Error("the run has no store journal: it ran no jobs");
  const j = verifyJournalText(readFileSync(path, "utf8"));
  if (j.error) throw new Error(`the store journal's chain does not hold (${j.error}): a job is not run again from a record that does not verify`);
  return j.lines;
}

function walkFiles(dir: string, base = dir, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    if (d.isDirectory()) walkFiles(p, base, out);
    else if (d.isFile()) out.push(relative(base, p).split("\\").join("/"));
  }
  return out.sort();
}

function isText(buf: Buffer): boolean {
  return !buf.subarray(0, 8192).includes(0);
}

/** The run's packs, where they are on this host, each held to the manifest sha256 the run recorded. */
function packDirsOf(rec: Record<string, unknown> | null): { dirs: string[]; problems: string[] } {
  const dirs: string[] = [];
  const problems: string[] = [];
  const home = process.env.DFIRSWARM_HOME || join(process.env.HOME ?? "", ".dfirswarm");
  for (const p of (Array.isArray(rec?.packs) ? rec.packs : []) as Array<{ id?: string; manifest_sha256?: string }>) {
    if (!p?.id || !/^[a-z0-9][a-z0-9-]*$/.test(p.id)) continue;
    const found = [join(home, "packs", p.id), join(ROOT, "packs", p.id)].find((d) => existsSync(join(d, "pack.json")));
    if (!found) {
      problems.push(`pack ${p.id} is not on this host`);
      continue;
    }
    const sha = sha256(readFileSync(join(found, "pack.json")));
    if (p.manifest_sha256 && sha !== p.manifest_sha256) problems.push(`pack ${p.id} here is not the one the run used (pack.json ${sha}, recorded ${p.manifest_sha256})`);
    dirs.push(found);
  }
  return { dirs, problems };
}

/**
 * Run a sealed job again and compare its outputs with the sealed ones.
 * Refused, before anything runs, for a job that is not committed, an
 * import, a job whose image digest was not recorded, an image whose digest
 * here is not the recorded one, a pack or tool that is not the one it ran.
 */
export async function rerunJob(o: { sandbox: string; job: string; run: string; rec?: Record<string, unknown> | null; normalise?: string; network?: boolean; deps: RerunDeps; say?: (s: string) => void }): Promise<RerunRecord> {
  const S = resolve(o.sandbox);
  const say = o.say ?? (() => undefined);
  if (!/^j\d{6}$/.test(o.job)) throw new Error(`${JSON.stringify(o.job)} is not a job id (j000123)`);
  if (o.normalise && !NORMALISATIONS[o.normalise]) throw new Error(`there is no normalisation ${o.normalise}: ${Object.keys(NORMALISATIONS).join(", ")}`);
  const lines = jobLines(S).filter((l) => l.job === o.job);
  const accepted = lines.find((l) => l.type === "job_accepted");
  if (!accepted) throw new Error(`the store journal has no job ${o.job}`);
  const committed = lines.filter((l) => l.type === "job_committed").at(-1);
  if (!committed) throw new Error(`job ${o.job} was never committed: there are no sealed outputs to compare with`);
  const started = lines.filter((l) => l.type === "job_started").at(-1);
  const finished = lines.filter((l) => l.type === "job_finished").at(-1);
  const spec = accepted.spec as JobRecord["spec"];
  if (spec.kind === "import") throw new Error(`job ${o.job} is an import: a copy of a live file as it was then; run again it would copy what is there now, which is not a re-execution`);
  const digest = String(finished?.image_digest ?? committed.image_digest ?? "");
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error(`no image digest was recorded for job ${o.job}: it cannot be run again in the image it ran in`);
  const image = String(started?.image ?? "");
  if (!image) throw new Error(`job ${o.job}'s image was not recorded`);
  const here = await o.deps.imageDigest(image);
  if (here !== digest) throw new Error(`the image ${image} here is ${here ?? "not present"}, not ${digest}, the digest job ${o.job} ran in: pull or restore that image; nothing else is run in its place`);
  const packs = packDirsOf(o.rec ?? null);
  if (packs.problems.length) throw new Error(`the run's packs are not as it used them: ${packs.problems.join("; ")}`);
  // The rerun area, beside the run and never in its store.
  const base = `${S}.reruns`;
  const jobDir = join(base, o.job);
  mkdirSync(jobDir, { recursive: true });
  let n = 1;
  while (existsSync(join(jobDir, String(n)))) n += 1;
  const dir = join(jobDir, String(n));
  const st = { out: join(dir, "out"), ctl: join(dir, "job") };
  mkdirSync(st.out, { recursive: true });
  mkdirSync(st.ctl, { recursive: true });
  const record: JobRecord = { id: o.job, attempt: Number(started?.attempt ?? 1), spec, requester: accepted.requester as JobRecord["requester"], state: "running", accepted_at: String(accepted.at) };
  const svc = new JobService({
    sandbox: S,
    run: o.run,
    image,
    workers: 1,
    workerCpus: Number(started?.cpus ?? 2),
    workerMemoryMib: Number(started?.memory_mib ?? 2048),
    allowHosts: o.network ? String(o.rec?.allow_hosts ?? "").split(/[\s,]+/).filter(Boolean) : [],
    openNet: false,
    packDirs: packs.dirs,
    forging: true,
    runWorker: o.deps.runWorker,
    destroyWorker: o.deps.destroyWorker,
    notify: async () => undefined,
    identity: async () => ({}),
  });
  const inner = svc as unknown as Internals;
  const script = await inner.script(record, st.ctl);
  const recordedTool = typeof started?.tool_sha256 === "string" ? started.tool_sha256 : null;
  if ((recordedTool || script.tool_sha256) && recordedTool !== (script.tool_sha256 ?? null)) throw new Error(`the ${spec.kind === "recipe" ? `recipe ${spec.recipe}` : `tool ${spec.tool}`} here (sha256 ${script.tool_sha256 ?? "none"}) is not the one job ${o.job} ran (${recordedTool ?? "none recorded"})`);
  writeFileSync(join(st.ctl, "run.sh"), `${script.lines.join("\n")}\n`);
  const { mounts } = inner.mounts(record, st);
  const originalNet = String(started?.network ?? (spec.network === "allowlist" ? "the run's allowlist" : "none"));
  const network: WorkerSpec["network"] = o.network ? inner.network(record) : { mode: "off" };
  const netText = network.mode === "off" ? "none" : network.mode === "public" ? "every public host" : `the run's allowlist (${network.hosts.join(", ")})`;
  say(`Rerun:        job ${o.job} (${spec.kind}) in ${image} (${digest}), into ${dir}`);
  const result = await o.deps.runWorker({
    name: `dfs-rerun-${o.run}-${o.job}-${n}`,
    image,
    run: o.run,
    job: o.job,
    attempt: record.attempt,
    cpus: Number(started?.cpus ?? 2),
    memoryMib: Number(started?.memory_mib ?? 2048),
    maxDurationSec: spec.timeout_seconds + 120,
    workdir: S,
    mounts,
    env: { JOB_ID: o.job, OUT: inner.outPath(record), AGENT_ID: record.requester.agent, SWARM_SANDBOX: S, TZ: "UTC", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1", NO_COLOR: "1" },
    network,
    command: ["bash", "/job/run.sh"],
  });
  let exit: number | null = null;
  try {
    exit = Number(readFileSync(join(st.ctl, "exit"), "utf8").trim());
    if (!Number.isFinite(exit)) exit = null;
  } catch {
    exit = null;
  }
  const status = exit === 124 || exit === 137 ? "timed_out" : exit === 0 ? "ok" : exit === null ? "no exit status" : "failed";
  // Compare, file by file, against the sealed manifest.
  const jobStore = join(S, "store", "jobs", o.job);
  const man = await readManifest(join(jobStore, "manifest.json"));
  const sealed = new Map((man?.manifest.files ?? []).map((f) => [f.path, f.sha256]));
  const now = new Map(walkFiles(st.out).map((p) => [p, sha256(readFileSync(join(st.out, p)))]));
  const identical: string[] = [];
  const differ: FileCompare[] = [];
  const missing: string[] = [];
  const added: string[] = [];
  for (const [p, h] of sealed) {
    const r = now.get(p);
    if (r === undefined) missing.push(p);
    else if (r === h) identical.push(p);
    else differ.push({ path: p, original: h, rerun: r });
  }
  for (const p of now.keys()) if (!sealed.has(p)) added.push(p);
  const logs = ["stdout.log", "stderr.log"].map((name) => {
    const original = existsSync(join(jobStore, name)) ? sha256(readFileSync(join(jobStore, name))) : null;
    const rerun = existsSync(join(st.ctl, name)) ? sha256(readFileSync(join(st.ctl, name))) : null;
    return { name, original, rerun, same: original === rerun };
  });
  const reproduced = !differ.length && !missing.length && !added.length && Boolean(man);
  const verdict = !man
    ? "NOT COMPARED: the job's sealed manifest cannot be read"
    : reproduced
      ? `reproduced byte for byte: ${identical.length} file(s), each with the sealed sha256${logs.every((l) => l.same) ? "; stdout and stderr the same too" : `; ${logs.filter((l) => !l.same).map((l) => l.name).join(" and ")} differ`}`
      : `NOT REPRODUCED: ${[differ.length ? `${differ.length} file(s) differ (${differ.map((d) => d.path).join(", ")})` : "", missing.length ? `${missing.length} not made (${missing.join(", ")})` : "", added.length ? `${added.length} made that were not sealed (${added.join(", ")})` : ""].filter(Boolean).join("; ")}; ${identical.length} the same`;
  // Equivalence under a normalisation: asked for, named, versioned, and apart from the verdict.
  let normalised: RerunRecord["normalised"] = null;
  if (o.normalise) {
    const nz = NORMALISATIONS[o.normalise];
    const equivalent: string[] = [];
    const still: string[] = [];
    for (const d of differ) {
      const a = readFileSync(join(jobStore, "out", d.path));
      const b = readFileSync(join(st.out, d.path));
      if (isText(a) && isText(b) && nz.apply(a.toString("utf8")) === nz.apply(b.toString("utf8"))) equivalent.push(d.path);
      else still.push(d.path);
    }
    normalised = { name: o.normalise, definition: nz.definition, equivalent, still_differ: still, note: `Equivalent under ${o.normalise}, asked for: the bytes differ, and are the same once the normalisation is applied to both. This is not a reproduction, and the verdict above stands.` };
  }
  const notReproduced = [
    "which bytes the job read: not measured, in the job or here",
    ...(spec.network === "allowlist" ? [o.network ? "the job had the network, and so did this rerun: what a host served then and now may differ" : `the job had the network (${originalNet}); this rerun had none: anything it fetched is not fetched here`] : []),
    ...(result.digest && result.digest !== digest ? [`the worker says it ran ${result.digest}, not ${digest}`] : []),
    "the reasoning that asked for the job: a model's, not reproducible",
  ];
  const rec: RerunRecord = {
    kind: "dfirswarm-rerun",
    run: o.run,
    job: o.job,
    n,
    at: new Date().toISOString(),
    original: { status: String(committed.status ?? finished?.status ?? "") || null, exit: typeof committed.exit === "number" ? committed.exit : null, image, image_digest: digest, tool_sha256: recordedTool, manifest_sha256: man?.sha256 ?? null, files: sealed.size, network: originalNet },
    rerun: { image_digest_here: here, worker_digest: result.digest ?? null, exit, status, fenced: result.fenced, network: netText, error: result.error ?? null },
    compare: { identical, differ, missing, added, logs },
    verdict,
    normalised,
    not_reproduced: notReproduced,
  };
  writeFileSync(join(dir, "rerun.json"), `${JSON.stringify(rec, null, 2)}\n`, { mode: 0o444 });
  return rec;
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv: string[]): Promise<number> {
  const positional = argv.filter((a, i) => !a.startsWith("--") && !["--run", "--runs", "--normalise"].includes(argv[i - 1] ?? ""));
  const [sandboxArg, job] = positional;
  if (!sandboxArg || !job) {
    console.error("usage: rerun.ts <sandbox> <job> [--run ID] [--runs DIR] [--normalise timestamps@1] [--network] [--json]");
    return 2;
  }
  const S = resolve(sandboxArg);
  const runsDir = opt(argv, "--runs") ?? process.env.SWARM_RUNS_DIR ?? dirname(S);
  let rec: Record<string, unknown> | null = null;
  try {
    const reg = JSON.parse(readFileSync(join(runsDir, "registry.json"), "utf8")) as { runs?: Array<Record<string, unknown>> };
    rec = (reg.runs ?? []).find((r) => r.id === opt(argv, "--run") || (typeof r.sandbox === "string" && resolve(r.sandbox) === S)) ?? null;
  } catch {
    rec = null;
  }
  const run = opt(argv, "--run") ?? (typeof rec?.id === "string" ? rec.id : "run");
  const vm = await import("./vm.ts");
  const r = await rerunJob({
    sandbox: S,
    job,
    run,
    rec,
    normalise: opt(argv, "--normalise"),
    network: argv.includes("--network"),
    deps: { runWorker: vm.runWorker, destroyWorker: vm.destroyWorker, imageDigest: vm.imageRefDigest },
    say: (s) => console.log(s),
  });
  if (argv.includes("--json")) console.log(JSON.stringify(r, null, 2));
  else {
    console.log(`Ran:          exit ${r.rerun.exit ?? "none"} (${r.rerun.status}); the job ${r.original.status ?? "?"} (exit ${r.original.exit ?? "none"}); network ${r.rerun.network}`);
    console.log(`Compared:     ${r.verdict}`);
    for (const d of r.compare.differ) console.log(`  differs:    ${d.path} (sealed ${d.original}, now ${d.rerun})`);
    for (const l of r.compare.logs) if (!l.same) console.log(`  ${l.name}:  sealed ${l.original ?? "none"}, now ${l.rerun ?? "none"}`);
    if (r.normalised) console.log(`Normalised:   under ${r.normalised.name} (asked for), ${r.normalised.equivalent.length} of the ${r.compare.differ.length} that differ are equivalent${r.normalised.equivalent.length ? ` (${r.normalised.equivalent.join(", ")})` : ""}; this is not a reproduction`);
    console.log(`Not re-run:   ${r.not_reproduced.join("; ")}`);
    console.log(`Record:       ${join(`${S}.reruns`, r.job, String(r.n), "rerun.json")}`);
  }
  return r.compare.differ.length || r.compare.missing.length || r.compare.added.length ? 4 : 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`BLOCKER: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    },
  );
}

