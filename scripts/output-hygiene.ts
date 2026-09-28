/**
 * Output hygiene (docs/adr/0016): which sealed job outputs are sensitive,
 * and what follows from that for the jobs that read them, the ledger entries
 * that cite them and a package that hands them over.
 *
 * A job run with `secret_output: true` (one whose output may hold a secret:
 * a key, a credential or a decrypted value the evidence holds) has every
 * output marked sensitive when it is sealed, whatever it wrote: the harness does not read
 * the bytes to decide. A job that reads such an output (it declared it, by
 * path or digest, or a catalogue generation made from it; or, with no scope
 * declared, its command names the job) is sealed sensitive too, as derived,
 * with the jobs it was made from. A ledger entry whose refs reach a
 * sensitive output is recorded sensitive (protocol.ts appendLedgerEntry), so
 * the run's sensitivity rules (B9, redaction) hold its words from then on.
 *
 * The package side reads the same records: every sensitive output (and its
 * job's stdout and stderr) is withheld from a redacted package whole, named
 * with its sha256, and the whole package is scanned for what should not be
 * in it, the small text outputs of sensitive jobs included.
 *
 * Nothing here knows a tool or a format: sensitivity comes from what the
 * agent declared and what the job service recorded, and is matched by path,
 * digest and job id.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

export type Sensitivity = {
  /** secret_output: the job was run so; derived: made from a sensitive output. */
  why: "secret_output" | "derived";
  /** The sensitive jobs it was made from (derived). */
  from: string[];
  note: string;
};

/** A sealed output file, as its job's manifest lists it. */
export type OutputFile = { path: string; sha256: string; bytes: number };

export type SensitiveJob = { id: string; sensitivity: Sensitivity; status: string | null; files: OutputFile[] };

export type SensitiveIndex = {
  jobs: Map<string, SensitiveJob>;
  /** Every sensitive output file's sha256, to the job that sealed it. */
  digests: Map<string, string>;
};

/** A job's sensitivity for its own spec: secret_output, or null (derived sensitivity is decided at seal, from what it read). */
export function ownSensitivity(spec: { secret_output?: unknown }): Sensitivity | null {
  return spec.secret_output === true ? { why: "secret_output", from: [], note: "run with secret_output: every output it sealed is sensitive" } : null;
}

/**
 * The sensitive jobs a job was made from: each object it declared that is a
 * sensitive job's output (by its path under store/jobs/<id>/, by the digest
 * of one of its files, or a catalogue generation a sensitive job made), and,
 * for a job that declared no scope (it could read every object), each
 * sensitive job its command, arguments, source or targets name by id or by
 * its store path. Pure.
 */
export function derivedFrom(o: {
  objects: Array<{ path: string; sha256?: string }> | null;
  text: string;
  sensitive: ReadonlySet<string>;
  digestJob: (sha256: string) => string | null;
  generationJob: (generation: string) => string | null;
}): string[] {
  const out = new Set<string>();
  const add = (id: string | null) => {
    if (id && o.sensitive.has(id)) out.add(id);
  };
  for (const x of o.objects ?? []) {
    add(/^store\/jobs\/([a-z0-9-]{1,64})(?:\/|$)/.exec(x.path)?.[1] ?? null);
    const gen = /^catalog\/gen\/([a-z0-9-]+)(?:\/|$)/.exec(x.path)?.[1];
    if (gen) add(o.generationJob(gen));
    const sha = x.sha256 ?? /^store\/blobs\/([0-9a-f]{64})$/.exec(x.path)?.[1];
    if (sha) add(o.digestJob(sha));
  }
  if (o.objects === null) {
    for (const id of o.sensitive) {
      const re = new RegExp(`(?<![A-Za-z0-9_-])${id.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")}(?![A-Za-z0-9_-])`);
      if (re.test(o.text)) out.add(id);
    }
  }
  return [...out].sort();
}

export function derivedSensitivity(from: string[]): Sensitivity | null {
  return from.length ? { why: "derived", from, note: `made from the sensitive output of ${from.join(", ")}: every output it sealed is sensitive` } : null;
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return null;
  }
}

let cache: { key: string; index: SensitiveIndex } | null = null;

/**
 * The run's sensitive outputs, from the store's journal (every
 * job_committed line that says it is sensitive) and each such job's
 * manifest. Read again whenever the journal changes.
 */
export async function sensitiveIndex(sandbox: string): Promise<SensitiveIndex> {
  const S = resolve(sandbox);
  const journal = join(S, "store", "journal.jsonl");
  const st = await stat(journal).catch(() => null);
  const key = `${journal}:${st?.size ?? 0}:${st?.mtimeMs ?? 0}`;
  if (cache?.key === key) return cache.index;
  const jobs = new Map<string, SensitiveJob>();
  const digests = new Map<string, string>();
  const text = st ? await readFile(journal, "utf8").catch(() => "") : "";
  // A store with no journal (a run copied without it, a hand-made fixture): the jobs' own records say it.
  if (!st) {
    for (const id of await projectedSensitive(S)) {
      const j = await readJson<{ status?: string; sensitive?: Sensitivity }>(join(S, "store", "jobs", id, "job.json"));
      if (j?.sensitive) jobs.set(id, { id, sensitivity: j.sensitive, status: j.status ?? null, files: [] });
    }
  }
  for (const line of text.split("\n")) {
    if (!line.includes('"sensitive"') || !line.includes("job_committed")) continue;
    let l: { type?: string; job?: string; status?: string; sensitive?: Sensitivity };
    try {
      l = JSON.parse(line) as typeof l;
    } catch {
      continue;
    }
    if (l.type !== "job_committed" || !l.job || !l.sensitive) continue;
    jobs.set(l.job, { id: l.job, sensitivity: l.sensitive, status: l.status ?? null, files: [] });
  }
  for (const j of jobs.values()) {
    const m = await readJson<{ files?: Array<{ path?: string; sha256?: string; bytes?: number }> }>(join(S, "store", "jobs", j.id, "manifest.json"));
    j.files = (m?.files ?? []).map((f) => ({ path: String(f.path ?? ""), sha256: String(f.sha256 ?? ""), bytes: Number(f.bytes) || 0 }));
    for (const f of j.files) if (/^[0-9a-f]{64}$/.test(f.sha256) && !digests.has(f.sha256)) digests.set(f.sha256, j.id);
  }
  const index = { jobs, digests };
  cache = { key, index };
  return index;
}

/** The job a catalogue generation was made by (catalog/gen/<gen>/generation.json), or null. */
export async function generationJob(sandbox: string, gen: string): Promise<string | null> {
  if (!/^[a-z0-9-]+$/.test(gen)) return null;
  const g = await readJson<{ job?: unknown }>(join(resolve(sandbox), "catalog", "gen", gen, "generation.json"));
  return typeof g?.job === "string" ? g.job : null;
}

/** A ref that reaches a sensitive output: which ref, which job, and why that job's outputs are sensitive. */
export type SensitiveRef = { ref: string; job: string; why: Sensitivity["why"] };

/**
 * Which of an entry's refs reach a sensitive output: a job's file or its
 * logs (job:<id>…), a sealed file by digest (sha256:<hex>), or a member of a
 * catalogue generation a sensitive job made (member:<gen>#<n>).
 */
export async function sensitiveRefs(sandbox: string, refs: readonly string[]): Promise<SensitiveRef[]> {
  if (!refs.length) return [];
  const index = await sensitiveIndex(sandbox);
  if (!index.jobs.size) return [];
  const out: SensitiveRef[] = [];
  for (const ref of refs) {
    const r = ref.trim();
    let job: string | null = null;
    const j = /^job:([a-z0-9-]{1,64})(?:\/|$)/.exec(r)?.[1];
    if (j) job = j;
    const sha = /^sha256:([0-9a-fA-F]{64})$/.exec(r)?.[1]?.toLowerCase();
    if (sha) job = index.digests.get(sha) ?? null;
    const gen = /^member:([a-z0-9-]+)#\d+$/.exec(r)?.[1];
    if (gen) job = await generationJob(sandbox, gen);
    const hit = job ? index.jobs.get(job) : undefined;
    if (hit) out.push({ ref: r, job: hit.id, why: hit.sensitivity.why });
  }
  return out;
}

/**
 * Every ledger entry that is sensitive, and why: marked so by its author (or
 * by the harness when it cited a sensitive output), or citing a sensitive
 * output while not marked (an entry recorded before the harness marked such
 * entries): the second kind is named, so a package treats it as marked.
 */
export async function sensitiveEntries(sandbox: string, entries: ReadonlyArray<{ seq: number; sensitive?: boolean; refs?: string[] }>): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  for (const e of entries) {
    if (e.sensitive) {
      out.set(e.seq, "marked sensitive");
      continue;
    }
    const hits = await sensitiveRefs(sandbox, e.refs ?? []);
    if (hits.length) out.set(e.seq, `cites sensitive output (${hits.map((h) => `${h.ref}: job ${h.job}, ${h.why === "secret_output" ? "secret_output" : "derived"}`).join("; ")})`);
  }
  return out;
}

/** The largest sensitive output whose whole text is a scan word: a recovered secret is one short file, not a report. */
export const OUTPUT_WORD_MAX_BYTES = 256;

/**
 * Whether a small output's whole text is a word the scan looks for: one
 * line, and shaped like a secret rather than a status (six characters or
 * more with a digit or a sign in it, or ten or more of anything), so a
 * result file that says "none" or "success" does not take every such word
 * out of a package.
 */
export function secretShaped(text: string): boolean {
  if (!text || /[\r\n]/.test(text)) return false;
  return (text.length >= 6 && /[^\p{L}\s]/u.test(text)) || text.length >= 10;
}

/**
 * What a manifest-wide scan looks for beside the ledger's sensitive words:
 * the whole text of each small sensitive output (a file of at most 256 bytes
 * with no NUL, trimmed, secret-shaped), with the job it came from. Its sha256
 * names it in any report of a hit, never its text.
 */
export async function outputWords(sandbox: string): Promise<Array<{ token: string; job: string; path: string }>> {
  const S = resolve(sandbox);
  const index = await sensitiveIndex(S);
  const out: Array<{ token: string; job: string; path: string }> = [];
  for (const j of index.jobs.values()) {
    for (const f of j.files) {
      if (f.bytes > OUTPUT_WORD_MAX_BYTES) continue;
      const bytes = await readFile(join(S, "store", "jobs", j.id, "out", f.path)).catch(() => null);
      if (!bytes || bytes.includes(0)) continue;
      const token = bytes.toString("utf8").trim();
      if (secretShaped(token) && !out.some((x) => x.token === token)) out.push({ token, job: j.id, path: f.path });
    }
  }
  return out;
}

/** Every sensitive job's directory entries a package lays out (store/jobs/<id>/…): its outputs and its logs, withheld whole. */
export function withheldPaths(index: SensitiveIndex): Array<{ job: string; rel: RegExp; why: string }> {
  return [...index.jobs.values()].map((j) => ({
    job: j.id,
    rel: new RegExp(`^store/jobs/${j.id}/(out/.+|stdout\\.log|stderr\\.log|[^/]+\\.stdout\\.log|[^/]+\\.stderr\\.log)$`),
    why: j.sensitivity.why === "secret_output" ? `job ${j.id} ran with secret_output` : `job ${j.id} was made from the sensitive output of ${j.sensitivity.from.join(", ")}`,
  }));
}

/** The job ids under store/jobs whose job.json says they are sensitive (the projection; the journal is the record). */
export async function projectedSensitive(sandbox: string): Promise<string[]> {
  const dir = join(resolve(sandbox), "store", "jobs");
  const out: string[] = [];
  for (const id of (await readdir(dir).catch(() => [] as string[])).sort()) {
    const j = await readJson<{ sensitive?: unknown }>(join(dir, id, "job.json"));
    if (j?.sensitive) out.push(id);
  }
  return out;
}
