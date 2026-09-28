#!/usr/bin/env node
/**
 * Tool harvesting (B19, docs/adr/0016): the code agents wrote into command
 * jobs, ranked as candidates for the tool library.
 *
 *   node --experimental-strip-types scripts/tool-candidates.ts <sandbox> [--out DIR] [--min-lines N] [--library DIR]... [--json]
 *   scripts/swarm.sh tools <id> --candidates [--out DIR] [--min-lines N] [--library DIR]
 *
 * In the ctf12 round nearly all new code lived in one-off command jobs, and
 * make_tool was used once: nothing was folded back. This reads every command
 * job the agents ran (store/jobs/<id>/job.json, the store's journal for the
 * image profile) and takes out the code in it: each heredoc body, each inline
 * `-c`/`-e` script, the command itself, and each script of the agents' own
 * (work/…, tool-output/…) a job declared and ran. A script is substantial at
 * `--min-lines` lines or more (20). The same text (by its sha256, blank lines
 * at its ends and trailing spaces dropped) run by several jobs is one
 * candidate, and its reuse is how many distinct jobs ran it. Candidates are
 * ranked by lines times jobs, then by lines.
 *
 * Each is compared with the library the maintainer keeps (--library, the
 * repository's tool-library/ by default) and the run's own tools/: a tool
 * whose name the script uses, or whose manifest `use` matches what the jobs
 * declared (scripts/library-hint.ts). That is a pointer for the maintainer,
 * never a verdict.
 *
 * Every candidate's script is written whole to the output directory (the
 * run's sibling `<sandbox>.tool-candidates/` unless --out names one), one
 * file each, with candidates.json beside them: where each came from (the
 * jobs, their seats and profiles), its lines, its reuse and the library
 * matches. Nothing is shortened. Folding a candidate into the library is the
 * maintainer's work: generalised (no image, offset or name of the case
 * written in), a manifest with `requires` and `use`, and a test.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { matchTool, type readToolManifests } from "./library-hint.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

export const CANDIDATE_MIN_LINES = 20;

export type Lang = "python" | "shell" | "perl" | "node" | "ruby" | "text" | "unknown";

/** A piece of code taken out of a command, as written. */
export type Piece = { kind: "heredoc" | "inline" | "command" | "work file"; lang: Lang; text: string; source?: string; note?: string };

/** A script as a candidate counts it: blank lines at its ends and trailing spaces dropped, nothing else. */
export function normaliseScript(text: string): string {
  const lines = text.replace(/\r\n?/g, "\n").split("\n").map((l) => l.replace(/[ \t]+$/, ""));
  while (lines.length && !lines[0].trim()) lines.shift();
  while (lines.length && !lines.at(-1)?.trim()) lines.pop();
  return lines.join("\n");
}

/** What language a piece of code is, from how it was run, where it was written or its first line: never from its content otherwise. */
function langOf(opener: string, body: string): Lang {
  const target = /(?:>>?|\btee\s+(?:-a\s+)?)\s*(["']?)([^\s"'|;&]+)\1/.exec(opener)?.[2] ?? "";
  if (target) {
    const ext = /\.([A-Za-z0-9]+)$/.exec(target)?.[1]?.toLowerCase();
    if (ext === "py") return "python";
    if (ext === "sh" || ext === "bash") return "shell";
    if (ext === "pl") return "perl";
    if (ext === "js" || ext === "mjs") return "node";
    if (ext === "rb") return "ruby";
    if (ext) return "text";
  }
  const before = opener.split("<<")[0];
  if (/\bpython[0-9.]*\b/.test(before)) return "python";
  if (/\bnode\b/.test(before)) return "node";
  if (/\bperl\b/.test(before)) return "perl";
  if (/\bruby\b/.test(before)) return "ruby";
  if (/\b(ba|z|da)?sh\b/.test(before)) return "shell";
  const bang = /^#!\S*?(?:env\s+)?(\S+)/.exec(body.split("\n")[0] ?? "")?.[1] ?? "";
  if (/python/.test(bang)) return "python";
  if (/(ba|z)?sh$/.test(bang)) return "shell";
  if (/node/.test(bang)) return "node";
  if (/perl/.test(bang)) return "perl";
  return target ? "text" : "unknown";
}

/**
 * The code in one command: each heredoc body (with the language its opener
 * or its first line says), each inline script given to an interpreter with
 * -c or -e in single or double quotes, and the command itself with the
 * heredoc bodies taken out. Pure.
 */
export function piecesOf(command: string): Piece[] {
  const out: Piece[] = [];
  const lines = command.replace(/\r\n?/g, "\n").split("\n");
  const rest: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    rest.push(line);
    i += 1;
    // A heredoc's opener (never a here-string, <<<), each on the line in order.
    const openers = [...line.matchAll(/(?<!<)<<(?!<)(-?)\s*(?:(['"])([^'"\s]+)\2|\\?([A-Za-z_][A-Za-z0-9_]*))/g)];
    for (const m of openers) {
      const delim = m[3] ?? m[4];
      const strip = m[1] === "-";
      const body: string[] = [];
      while (i < lines.length && (strip ? lines[i].replace(/^\t+/, "") : lines[i]) !== delim) {
        body.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) {
        rest.push(lines[i]);
        i += 1;
      }
      const text = body.join("\n");
      if (text.trim()) out.push({ kind: "heredoc", lang: langOf(line.slice(0, (m.index ?? 0) + m[0].length), text), text });
    }
  }
  const command_ = rest.join("\n");
  for (const m of command_.matchAll(/\b(python[0-9.]*|perl|ruby|node)\s+(?:-[A-Za-z]+\s+)*-(?:c|e)\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g)) {
    const text = m[2] ?? (m[3] ?? "").replace(/\\(["\\$`])/g, "$1");
    const lang: Lang = /^python/.test(m[1]) ? "python" : m[1] === "node" ? "node" : m[1] === "perl" ? "perl" : "ruby";
    if (text.trim()) out.push({ kind: "inline", lang, text });
  }
  if (command_.trim()) out.push({ kind: "command", lang: "shell", text: command_ });
  return out;
}

type JobRecord = {
  id: string;
  spec?: { kind?: string; command?: string; inputs?: unknown; profile?: string };
  requester?: { agent?: string; name?: string };
  status?: string;
  state?: string;
  accepted_at?: string;
  image?: string;
  scope?: { manifest?: string };
};

/** One job's use of a script. */
export type Use = { job: string; seat: string; profile: string; status: string; at: string };

export type Candidate = {
  n: number;
  sha256: string;
  kind: Piece["kind"];
  lang: Lang;
  lines: number;
  bytes: number;
  /** Every job that ran this text, in the order they were accepted. */
  jobs: Use[];
  /** Distinct jobs after the first that ran the same text. */
  reuse: number;
  score: number;
  source?: string;
  note?: string;
  /** Library tools the maintainer may already have for it, and why each is named. */
  library: Array<{ tool: string; where: string; why: string }>;
  /** The file its script was written to, under the output directory. */
  file: string;
  text: string;
};

export type Harvest = { jobs: number; command_jobs: number; pieces: number; min_lines: number; candidates: Candidate[]; libraries: string[] };

async function readJson<T>(p: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(p, "utf8")) as T;
  } catch {
    return null;
  }
}

const EXT: Record<Lang, string> = { python: "py", shell: "sh", perl: "pl", node: "js", ruby: "rb", text: "txt", unknown: "txt" };

/**
 * The candidates of a run: every substantial script its agents' command jobs
 * ran, one per text, ranked by lines times jobs; each with the library tools
 * that may already cover it.
 */
export async function harvest(sandbox: string, o: { minLines?: number; libraries?: string[] } = {}): Promise<Harvest> {
  const S = resolve(sandbox);
  const minLines = o.minLines ?? CANDIDATE_MIN_LINES;
  const dir = join(S, "store", "jobs");
  const ids = (await readdir(dir).catch(() => [] as string[])).filter((n) => /^[a-z0-9-]{1,64}$/.test(n)).sort();
  // The profile each job ran in, from the journal (a job that named none was placed by the images' records).
  const profiles = new Map<string, string>();
  const journal = await readFile(join(S, "store", "journal.jsonl"), "utf8").catch(() => "");
  for (const line of journal.split("\n")) {
    if (!line.includes('"job_started"')) continue;
    try {
      const l = JSON.parse(line) as { type?: string; job?: string; profile?: string };
      if (l.type === "job_started" && l.job && l.profile) profiles.set(l.job, l.profile);
    } catch {
      // the journal's own check names it
    }
  }
  const byText = new Map<string, { piece: Piece; text: string; uses: Use[]; inputs: Array<{ input: string; path: string }> }>();
  let commandJobs = 0;
  let pieces = 0;
  for (const id of ids) {
    const job = await readJson<JobRecord>(join(dir, id, "job.json"));
    if (!job || job.spec?.kind !== "command" || typeof job.spec.command !== "string") continue;
    const seat = job.requester?.agent ?? "?";
    if (seat === "system" || seat === "derived") continue;
    commandJobs += 1;
    const use: Use = { job: id, seat, profile: job.spec.profile ?? profiles.get(id) ?? "the run's worker image", status: job.status ?? job.state ?? "unknown", at: job.accepted_at ?? "" };
    const found = piecesOf(job.spec.command);
    // A script of the agent's own the job declared and ran: its bytes now, held to the snapshot's sha256 the job read.
    const scope = job.scope?.manifest ? await readJson<{ accessible?: Array<{ path?: string; sha256?: string; hashed?: string }>; expanded?: Array<{ ref?: string; path?: string; shape?: string }> }>(join(S, job.scope.manifest)) : null;
    for (const e of scope?.accessible ?? []) {
      const p = String(e.path ?? "");
      if (!/^(work|tool-output)\/./.test(p) || !job.spec.command.includes(p)) continue;
      const bytes = await readFile(join(S, p)).catch(() => null);
      if (!bytes || bytes.subarray(0, 8192).includes(0)) continue;
      const now = sha256(bytes);
      found.push({ kind: "work file", lang: langOf(`> ${p}`, bytes.toString("utf8")), text: bytes.toString("utf8"), source: p, ...(e.sha256 && e.sha256 !== now ? { note: `${p} changed since job ${id} read it (the job read sha256 ${e.sha256}; this is ${now})` } : {}) });
    }
    const inputs = (scope?.expanded ?? []).filter((x) => x.shape === "file" && typeof x.path === "string").map((x) => ({ input: String(x.ref ?? x.path), path: String(x.path) }));
    for (const p of found) {
      if (p.lang === "text") continue;
      pieces += 1;
      const text = normaliseScript(p.text);
      if (text.split("\n").length < minLines) continue;
      const key = sha256(text);
      const slot = byText.get(key) ?? { piece: p, text, uses: [], inputs: [] };
      if (!slot.uses.some((u) => u.job === id)) slot.uses.push(use);
      for (const x of inputs) if (!slot.inputs.some((y) => y.path === x.path)) slot.inputs.push(x);
      byText.set(key, slot);
    }
  }
  // The libraries a candidate is compared with: the maintainer's, and the tools the run had.
  const libraries = [...new Set([...(o.libraries ?? [join(ROOT, "tool-library")]).map((d) => resolve(d)), join(S, "tools")])].filter((d) => existsSync(d));
  const manifests: Array<{ where: string; m: Awaited<ReturnType<typeof readToolManifests>>[number] }> = [];
  for (const lib of libraries) {
    for (const m of await readLibrary(lib)) manifests.push({ where: lib === join(S, "tools") ? "the run's tools" : lib, m });
  }
  const candidates = [...byText.entries()].map(([key, v]): Omit<Candidate, "n" | "file"> => {
    const lines = v.text.split("\n").length;
    const jobs = v.uses.sort((a, b) => a.at.localeCompare(b.at) || a.job.localeCompare(b.job));
    const library: Candidate["library"] = [];
    for (const { where, m } of manifests) {
      const name = String(m.name ?? "");
      if (!name) continue;
      const why: string[] = [];
      if (new RegExp(`(?<![\\w-])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`).test(v.text)) why.push("the script names it");
      const hits = v.inputs.flatMap((f) => matchTool(m, { ...f, head: null }).filter((h) => h.by !== "magic"));
      if (hits.length) why.push(`it reads what the jobs declared (${[...new Set(hits.map((h) => `${h.by} ${h.what}`))].join(", ")})`);
      if (why.length && !library.some((l) => l.tool === name && l.where === where)) library.push({ tool: name, where, why: why.join("; ") });
    }
    return { sha256: key, kind: v.piece.kind, lang: v.piece.lang, lines, bytes: Buffer.byteLength(v.text), jobs, reuse: jobs.length - 1, score: lines * jobs.length, ...(v.piece.source ? { source: v.piece.source } : {}), ...(v.piece.note ? { note: v.piece.note } : {}), library, text: v.text };
  });
  candidates.sort((a, b) => b.score - a.score || b.lines - a.lines || a.jobs[0].job.localeCompare(b.jobs[0].job));
  const width = String(candidates.length).length;
  return {
    jobs: ids.length,
    command_jobs: commandJobs,
    pieces,
    min_lines: minLines,
    libraries,
    candidates: candidates.map((c, i) => ({ ...c, n: i + 1, file: `${String(i + 1).padStart(Math.max(2, width), "0")}-${c.lang}-${c.sha256.slice(0, 12)}.${EXT[c.lang]}` })),
  };
}

/** A library directory's tools (<dir>/<name>/manifest.json), by name. */
async function readLibrary(dir: string): Promise<Awaited<ReturnType<typeof readToolManifests>>> {
  const out: Awaited<ReturnType<typeof readToolManifests>> = [];
  for (const name of (await readdir(dir).catch(() => [] as string[])).sort()) {
    const m = await readJson<Record<string, unknown>>(join(dir, name, "manifest.json"));
    if (m && typeof m === "object") out.push({ ...(m as object), name: typeof m.name === "string" ? m.name : name } as (typeof out)[number]);
  }
  return out;
}

/** The candidates written for the maintainer: each script whole, one file each, and candidates.json and README.txt beside them. */
export async function writeHarvest(h: Harvest, outDir: string, run: string): Promise<void> {
  await mkdir(outDir, { recursive: true });
  for (const c of h.candidates) await writeFile(join(outDir, c.file), c.text.endsWith("\n") ? c.text : `${c.text}\n`);
  const { candidates, ...rest } = h;
  await writeFile(
    join(outDir, "candidates.json"),
    `${JSON.stringify({ v: 1, run, ...rest, note: "Code the agents wrote into command jobs, as tool candidates for the library: each script whole in the file named, its sha256 over the text as counted (blank lines at its ends and trailing spaces dropped). jobs: every job that ran it; reuse: distinct jobs after the first; score: lines times jobs. library: tools that may already cover it, and why each is named: a pointer, never a verdict.", candidates: candidates.map(({ text: _t, ...c }) => c) }, null, 2)}\n`,
  );
  await writeFile(
    join(outDir, "README.txt"),
    [
      `Tool candidates from run ${run}`,
      "",
      `${h.candidates.length} script(s) of ${h.min_lines} lines or more, from ${h.command_jobs} command job(s), ranked by lines times the jobs that ran them.`,
      "Each file is a script as an agent wrote it into a job, whole. candidates.json says where each came from.",
      "",
      "To fold one into the tool library (tool-library/README.md, \"Folding a candidate\"): make it general",
      "(no image, offset, name or wording of the case written in), give it a manifest with its params,",
      "`requires` (the programs it runs) and `use` (what it reads: extensions, magic bytes, names), and a test.",
      "",
      ...h.candidates.map((c) => `${c.file}: ${c.lang} ${c.kind}, ${c.lines} lines, ${c.jobs.length} job(s) (${c.jobs.map((j) => `${j.job} by ${j.seat} in ${j.profile}`).join("; ")})${c.library.length ? `; library: ${c.library.map((l) => `${l.tool} (${l.why})`).join("; ")}` : "; no library tool matched"}`),
      "",
    ].join("\n"),
  );
}

/** One line per candidate, for the terminal. */
export function harvestLines(h: Harvest, outDir: string | null): string[] {
  const out = [`${h.candidates.length} candidate(s): scripts of ${h.min_lines} lines or more in ${h.command_jobs} command job(s) of ${h.jobs} job(s), ranked by lines times jobs.`];
  for (const c of h.candidates) {
    out.push(`${String(c.n).padStart(3)}. ${c.lang} ${c.kind}${c.source ? ` ${c.source}` : ""}, ${c.lines} lines, ${c.jobs.length} job(s)${c.reuse ? ` (reused ${c.reuse}×)` : ""}, score ${c.score}: ${c.jobs.map((j) => `${j.job} (${j.seat}, ${j.profile}, ${j.status})`).join(", ")}`);
    out.push(`     library: ${c.library.length ? c.library.map((l) => `${l.tool} in ${l.where}: ${l.why}`).join("; ") : "no tool matched"}${c.note ? `; ${c.note}` : ""}`);
  }
  if (outDir) out.push(`Written to ${outDir}: each script whole (${h.candidates.map((c) => c.file).join(", ") || "none"}), candidates.json and README.txt.`);
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name: string) => (args.indexOf(name) >= 0 ? args[args.indexOf(name) + 1] : undefined);
  const libraries = args.flatMap((a, i) => (a === "--library" && args[i + 1] ? [args[i + 1]] : []));
  const sandbox = args.find((a, i) => !a.startsWith("--") && !["--out", "--min-lines", "--library", "--run"].includes(args[i - 1] ?? ""));
  const minRaw = opt("--min-lines");
  if (!sandbox || (minRaw !== undefined && !/^[1-9]\d{0,4}$/.test(minRaw))) {
    console.error("usage: tool-candidates.ts <sandbox> [--out DIR] [--min-lines N] [--library DIR]... [--run ID] [--json]");
    process.exit(2);
  }
  const S = resolve(sandbox);
  if (!existsSync(join(S, "store", "jobs"))) {
    console.log("No job ran in this run: there is no job code to harvest.");
    process.exit(0);
  }
  const h = await harvest(S, { ...(minRaw ? { minLines: Number(minRaw) } : {}), ...(libraries.length ? { libraries } : {}) });
  const outDir = resolve(opt("--out") ?? `${S}.tool-candidates`);
  await writeHarvest(h, outDir, opt("--run") ?? basename(S));
  if (args.includes("--json")) console.log(JSON.stringify({ ...h, out: outDir, candidates: h.candidates.map(({ text: _t, ...c }) => c) }, null, 2));
  else console.log(harvestLines(h, outDir).join("\n"));
}
