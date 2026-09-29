/**
 * The store sweep (docs/adr/0013, "After the round-13 scoring"): a negative
 * is checked against everything the run already holds, not only against the
 * sources its coverage record names.
 *
 * On the round-13 scoring runs, five answers were written not determinable
 * while the row that answered two of them sat in a parser export the run
 * itself had made half an hour before; each passed a review, because the
 * reviews checked the answer against its coverage record's two or three
 * sources, never against the store. A coverage record now names what a hit
 * would contain (`looked_for`: literal strings), and the hub searches every
 * output the run holds for them when the record is written: every sealed
 * job output and job log, every import (evidence added late included: an
 * import is an output the run holds), every capture, every whole output the
 * harness kept under tool-output/. Not the input images: the coverage record
 * is where they are searched. Bytes and strings only, case-insensitive for
 * ASCII, in UTF-8 and in UTF-16LE, every file streamed whole: no format
 * parser and no per-tool code (the harness stays tool-agnostic). A budget of
 * bytes and time bounds a sweep; what it did not reach is named, and the
 * sweep is partial, never clean.
 *
 * The record is immutable and the sweep is not instant, so the result is a
 * line of its own in ledger/sweeps.jsonl, chained like the attestations and
 * bound to the coverage record by its hash. A record with looked_for and no
 * sweep line is pending. The gate (protocol.ts ledgerGate) reads them.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { appendFile, lstat, mkdir, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { LedgerEntry } from "./protocol.ts";

export const LEDGER_SWEEPS = "ledger/sweeps.jsonl";
/** A looked_for string: at least this long (a shorter one matches everything), at most this long, at most this many. */
export const SWEEP_TERM_MIN = 3;
export const SWEEP_TERM_MAX = 200;
export const SWEEP_MAX_TERMS = 20;
/** The budget a sweep may spend, from the environment; past it the sweep is partial and names what it did not search. */
export function sweepBudget(env: NodeJS.ProcessEnv = process.env): { maxBytes: number; maxMs: number } {
  const num = (k: string, d: number) => {
    const v = Number(env[k]);
    return Number.isFinite(v) && v > 0 ? v : d;
  };
  return { maxBytes: num("SWARM_SWEEP_MAX_BYTES", 16 * 1024 ** 3), maxMs: num("SWARM_SWEEP_MAX_SEC", 1800) * 1000 };
}
/** A pending sweep older than this is taken to have been lost with its process, and is run again by whoever reads the gate. */
export function sweepOrphanMs(env: NodeJS.ProcessEnv = process.env): number {
  const v = Number(env.SWARM_SWEEP_ORPHAN_SEC);
  return (Number.isFinite(v) && v >= 0 ? v : 120) * 1000;
}

export type SweepHit = {
  /** The object it was found in (job:<id>/<path>, import:<id>/<path>, net:<k>/<n>/<file>, tool:<seat>/<file>). */
  ref: string;
  term: string;
  count: number;
  /** The byte offset of the first occurrence, in the object's own bytes. */
  first_offset: number;
  encodings: Array<"utf-8" | "utf-16le">;
  /** Other objects that hold the same bytes (one blob, several names). */
  also?: string[];
};
export type SweepState = "clean" | "hits" | "partial";
export type SweepRecord = {
  v: 1;
  /** The coverage record's seq and hash. */
  seq: number;
  target: string;
  state: SweepState;
  terms: string[];
  searched: { objects: number; bytes: number };
  /** In objects the record does not name (its refs, or the outputs among its result_refs): these hold the negative. */
  hits: SweepHit[];
  /** In objects the record names already: said, never holding; a reviewer checks the answer accounts for them. */
  named_hits: SweepHit[];
  /** What the budget did not reach, each named with why. */
  unsearched: Array<{ ref: string; why: string }>;
  started_at: string;
  at: string;
  prev?: string;
  hash?: string;
};

/** One object a sweep reads. */
type SweepObject = { ref: string; path: string; bytes: number; key: string };

/** Every output the run holds that is not an input image, sorted by ref; the same bytes under several names share a key. */
export async function sweepObjects(sandboxRoot: string): Promise<SweepObject[]> {
  const out: SweepObject[] = [];
  const dirs = async (p: string) => (await readdir(p, { withFileTypes: true }).catch(() => [])).filter((d) => d.isDirectory()).map((d) => d.name);
  const manifestFiles = async (dir: string): Promise<Array<{ path: string; sha256: string; bytes: number }> | null> => {
    try {
      const m = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as { files?: Array<{ path: string; sha256: string; bytes: number }> };
      return m.files ?? [];
    } catch {
      return null;
    }
  };
  const fileKey = async (path: string): Promise<{ key: string; bytes: number } | null> => {
    const st = await lstat(path).catch(() => null);
    return st?.isFile() ? { key: `ino:${st.dev}:${st.ino}`, bytes: st.size } : null;
  };
  // Sealed job outputs, and each job's logs (stdout.log is what job_status pages).
  const jobs = join(sandboxRoot, "store", "jobs");
  for (const id of (await dirs(jobs)).sort()) {
    const files = await manifestFiles(join(jobs, id));
    if (!files) continue;
    for (const f of files) out.push({ ref: `job:${id}/${f.path}`, path: join(jobs, id, "out", f.path), bytes: f.bytes, key: `sha256:${f.sha256}` });
    for (const log of ["stdout.log", "stderr.log"]) {
      const k = await fileKey(join(jobs, id, log));
      if (k && k.bytes) out.push({ ref: `job:${id}/${log}`, path: join(jobs, id, log), ...k });
    }
  }
  // Imports: evidence added late, supplied material, a brain's sealed output.
  const imports = join(sandboxRoot, "store", "imports");
  for (const id of (await dirs(imports)).sort()) {
    for (const f of (await manifestFiles(join(imports, id))) ?? []) out.push({ ref: `import:${id}/${f.path}`, path: join(imports, id, "out", f.path), bytes: f.bytes, key: `sha256:${f.sha256}` });
  }
  // Captures the fetch service sealed.
  const net = join(sandboxRoot, "store", "net");
  for (const k of (await dirs(net)).sort()) {
    for (const n of (await dirs(join(net, k))).sort()) {
      for (const f of (await manifestFiles(join(net, k, n))) ?? []) out.push({ ref: `net:${k}/${n}/${f.path}`, path: join(net, k, n, f.path), bytes: f.bytes, key: `sha256:${f.sha256}` });
    }
  }
  // The whole outputs the harness kept under tool-output/<seat>/.
  const tools = join(sandboxRoot, "tool-output");
  for (const seat of (await dirs(tools)).sort()) {
    const walk = async (dir: string, rel: string): Promise<void> => {
      for (const d of (await readdir(dir, { withFileTypes: true }).catch(() => [])).sort((a, b) => a.name.localeCompare(b.name))) {
        const p = join(dir, d.name);
        const r = rel ? `${rel}/${d.name}` : d.name;
        if (d.isDirectory()) await walk(p, r);
        else if (d.isFile()) {
          const k = await fileKey(p);
          if (k) out.push({ ref: `tool:${seat}/${r}`, path: p, ...k });
        }
      }
    };
    await walk(join(tools, seat), "");
  }
  return out.sort((a, b) => a.ref.localeCompare(b.ref));
}

/** ASCII letters folded to lower case, in a copy: the case-insensitive part of the byte search. */
function fold(b: Buffer): Buffer {
  const out = Buffer.from(b);
  for (let i = 0; i < out.length; i++) {
    const c = out[i]!;
    if (c >= 0x41 && c <= 0x5a) out[i] = c + 0x20;
  }
  return out;
}

type Pattern = { term: number; enc: "utf-8" | "utf-16le"; bytes: Buffer };

/** Each term in UTF-8 and UTF-16LE, as given, lower-cased and upper-cased (for letters outside ASCII), folded, each once. */
function patterns(terms: string[]): Pattern[] {
  const out: Pattern[] = [];
  terms.forEach((t, i) => {
    for (const v of new Set([t, t.toLowerCase(), t.toUpperCase()])) {
      for (const enc of ["utf-8", "utf-16le"] as const) {
        const bytes = fold(Buffer.from(v, enc === "utf-8" ? "utf8" : "utf16le"));
        if (!out.some((p) => p.term === i && p.enc === enc && p.bytes.equals(bytes))) out.push({ term: i, enc, bytes });
      }
    }
  });
  return out;
}

/** Count each pattern in one file, streamed whole: the count and the first offset of each term, by encoding. */
async function searchFile(path: string, pats: Pattern[]): Promise<Map<number, { count: number; first: number; encodings: Set<"utf-8" | "utf-16le"> }>> {
  const found = new Map<number, { count: number; first: number; encodings: Set<"utf-8" | "utf-16le"> }>();
  const keep = Math.max(0, ...pats.map((p) => p.bytes.length)) - 1;
  let tail = Buffer.alloc(0);
  let base = 0;
  for await (const raw of createReadStream(path, { highWaterMark: 1024 * 1024 })) {
    const chunk = fold(raw as Buffer);
    const buf = tail.length ? Buffer.concat([tail, chunk]) : chunk;
    for (const p of pats) {
      let i = buf.indexOf(p.bytes);
      while (i >= 0) {
        // A match that lies wholly in the carried tail was counted with the chunk before.
        if (i + p.bytes.length > tail.length) {
          const at = base - tail.length + i;
          const f = found.get(p.term) ?? { count: 0, first: at, encodings: new Set() };
          f.count += 1;
          f.first = Math.min(f.first, at);
          f.encodings.add(p.enc);
          found.set(p.term, f);
        }
        i = buf.indexOf(p.bytes, i + 1);
      }
    }
    base += chunk.length;
    tail = keep > 0 ? Buffer.from(buf.subarray(Math.max(0, buf.length - keep))) : Buffer.alloc(0);
  }
  return found;
}

/** Whether a coverage record's refs name an object: the ref itself, a directory of it (job:<id>, job:<id>/<dir>), or its bytes by sha256. */
export function refsName(refs: readonly string[], ref: string, key?: string): boolean {
  const norm = (r: string) => r.trim().replace(/^(job|import):([^/]+)\/out\//, "$1:$2/").replace(/\/+$/, "");
  const want = norm(ref);
  return refs.some((r) => {
    const n = norm(r);
    return n === want || want.startsWith(`${n}/`) || (key?.startsWith("sha256:") && n === key);
  });
}

/** Search every output the run holds for a coverage record's looked_for strings. Pure over the store; `now` and the budget are the caller's (tests fix them). */
export async function computeSweep(sandboxRoot: string, cov: Pick<LedgerEntry, "seq" | "hash" | "refs" | "result_refs" | "looked_for">, o: { maxBytes?: number; maxMs?: number; now?: () => number } = {}): Promise<Omit<SweepRecord, "prev" | "hash">> {
  const now = o.now ?? Date.now;
  const budget = { ...sweepBudget(), ...(o.maxBytes !== undefined ? { maxBytes: o.maxBytes } : {}), ...(o.maxMs !== undefined ? { maxMs: o.maxMs } : {}) };
  const started = now();
  const terms = [...(cov.looked_for ?? [])];
  const pats = patterns(terms);
  // What the record names: the objects it searched, and the outputs its search produced (a search's own
  // output echoes what it looked for; it was read as the search's result). A hit there is said, never holding.
  const refs = [...(cov.refs ?? []), ...(cov.result_refs ?? []).filter((r) => !/^E-\d+$/.test(r))];
  const objects = await sweepObjects(sandboxRoot);
  // The same bytes under several names are read once; a group is named when any of its names is.
  const groups = new Map<string, SweepObject[]>();
  for (const x of objects) groups.set(x.key, [...(groups.get(x.key) ?? []), x]);
  const hits: SweepHit[] = [];
  const namedHits: SweepHit[] = [];
  const unsearched: SweepRecord["unsearched"] = [];
  let searchedObjects = 0;
  let searchedBytes = 0;
  for (const [key, group] of groups) {
    const first = group[0]!;
    if (now() - started > budget.maxMs) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `the sweep's time budget (${Math.round(budget.maxMs / 1000)} s, SWARM_SWEEP_MAX_SEC) ran out before it` });
      continue;
    }
    if (searchedBytes + first.bytes > budget.maxBytes) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `its ${first.bytes} bytes would pass the sweep's byte budget (${budget.maxBytes}, SWARM_SWEEP_MAX_BYTES; ${searchedBytes} searched)` });
      continue;
    }
    let found: Awaited<ReturnType<typeof searchFile>>;
    try {
      found = await searchFile(first.path, pats);
    } catch (err) {
      for (const g of group) unsearched.push({ ref: g.ref, why: `it could not be read (${(err as Error).message})` });
      continue;
    }
    searchedObjects += group.length;
    searchedBytes += first.bytes;
    const named = group.some((g) => refsName(refs, g.ref, key));
    for (const [t, f] of [...found.entries()].sort((a, b) => a[0] - b[0])) {
      const hit: SweepHit = { ref: first.ref, term: terms[t]!, count: f.count, first_offset: f.first, encodings: [...f.encodings].sort(), ...(group.length > 1 ? { also: group.slice(1).map((g) => g.ref) } : {}) };
      (named ? namedHits : hits).push(hit);
    }
  }
  const state: SweepState = hits.length ? "hits" : unsearched.length ? "partial" : "clean";
  return { v: 1, seq: cov.seq, target: cov.hash ?? "", state, terms, searched: { objects: searchedObjects, bytes: searchedBytes }, hits, named_hits: namedHits, unsearched, started_at: new Date(started).toISOString(), at: new Date(now()).toISOString() };
}

/** A sweep line's hash: over the previous line's and its own fields, canonical. */
export function sweepHash(s: SweepRecord, prev: string): string {
  const { prev: _p, hash: _h, ...core } = s;
  return createHash("sha256").update(`${prev}\n${JSON.stringify(sortKeys(core))}`).digest("hex");
}
function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as Record<string, unknown>).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]));
  return v;
}

export async function readSweeps(sandboxRoot: string): Promise<SweepRecord[]> {
  const text = await readFile(join(sandboxRoot, LEDGER_SWEEPS), "utf8").catch(() => "");
  const out: SweepRecord[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as SweepRecord);
    } catch {
      // a torn line is the chain check's to name
    }
  }
  return out;
}

/** The sweeps' chain: every line's hash recomputed over its fields and chained to the one before; the head is the last line's hash. */
export function verifySweepChain(text: string): { ok: boolean; total: number; broken_at: number | null; reason: string | null; head: string | null } {
  let last = "genesis";
  let total = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let s: SweepRecord;
    try {
      s = JSON.parse(line) as SweepRecord;
    } catch {
      return { ok: false, total, broken_at: total, reason: "not json", head: null };
    }
    if (s.v !== 1) return { ok: false, total, broken_at: total, reason: `a sweep of version ${JSON.stringify(s.v)}, which this harness does not know`, head: null };
    if (s.prev !== last) return { ok: false, total, broken_at: total, reason: "prev does not name the line before it", head: null };
    if (s.hash !== sweepHash(s, last)) return { ok: false, total, broken_at: total, reason: "the line was rewritten", head: null };
    last = s.hash;
  }
  return { ok: true, total, broken_at: null, reason: null, head: total ? last : null };
}

/** The sweep recorded for a coverage record, by its hash: the latest line, or null (pending, when the record names looked_for). */
export function sweepOf(c: Pick<LedgerEntry, "hash">, sweeps: readonly SweepRecord[]): SweepRecord | null {
  return sweeps.filter((s) => s.target === c.hash).at(-1) ?? null;
}

/** A hit in words. */
export function hitWords(h: SweepHit): string {
  return `"${h.term}" in ${h.ref}${h.also?.length ? ` (the same bytes as ${h.also.join(", ")})` : ""}, ${h.count} time${h.count === 1 ? "" : "s"}, first at byte ${h.first_offset}${h.encodings.includes("utf-16le") ? ` (${h.encodings.join(" and ")})` : ""}`;
}

/** A sweep in words, for the ledger's rendering, the report and the review offer. */
export function sweepWords(s: SweepRecord | null, c: Pick<LedgerEntry, "looked_for">): string {
  if (!c.looked_for?.length) return "no store sweep (no looked_for strings)";
  if (!s) return "store sweep pending";
  const head = `store sweep ${s.state}: ${s.searched.objects} object(s), ${s.searched.bytes} bytes searched for ${s.terms.map((t) => `"${t}"`).join(", ")}`;
  return [
    head,
    s.hits.length ? `found outside the record's objects: ${s.hits.map(hitWords).join("; ")}` : "",
    s.named_hits.length ? `found in objects the record names (does the answer account for them?): ${s.named_hits.map(hitWords).join("; ")}` : "",
    s.unsearched.length ? `not searched: ${s.unsearched.map((u) => `${u.ref} (${u.why})`).join("; ")}` : "",
  ]
    .filter(Boolean)
    .join("; ");
}

const inflight = new Map<string, Promise<SweepRecord | null>>();

/**
 * Run a coverage record's sweep and record it, once per record: a sweep
 * already recorded, or running in this process, is not run again. Written
 * under the sweeps' lock, chained. Errors are the result's (null), never
 * thrown: the record stands and its sweep stays pending, to be run again.
 */
export function startSweep(sandboxRoot: string, cov: LedgerEntry, o: { maxBytes?: number; maxMs?: number } = {}): Promise<SweepRecord | null> {
  if (!cov.looked_for?.length || !cov.hash) return Promise.resolve(null);
  const key = `${sandboxRoot}\u0000${cov.hash}`;
  const running = inflight.get(key);
  if (running) return running;
  const p = (async (): Promise<SweepRecord | null> => {
    if (sweepOf(cov, await readSweeps(sandboxRoot))) return sweepOf(cov, await readSweeps(sandboxRoot));
    const result = await computeSweep(sandboxRoot, cov, o);
    const P = await import("./protocol.ts");
    const line = await P.withNamedLock(sandboxRoot, "sweeps", async () => {
      const text = await readFile(join(sandboxRoot, LEDGER_SWEEPS), "utf8").catch(() => "");
      const existing = (await readSweeps(sandboxRoot)).filter((s) => s.target === cov.hash).at(-1);
      if (existing) return existing;
      const lines = text.split("\n").filter((l) => l.trim());
      const prev = lines.length ? ((JSON.parse(lines.at(-1)!) as SweepRecord).hash ?? "genesis") : "genesis";
      const rec: SweepRecord = { ...result, prev };
      rec.hash = sweepHash(rec, prev);
      await mkdir(join(sandboxRoot, "ledger"), { recursive: true });
      await appendFile(join(sandboxRoot, LEDGER_SWEEPS), `${JSON.stringify(rec)}\n`, "utf8");
      return rec;
    });
    await P.renderLedger(sandboxRoot).catch(() => undefined);
    return line;
  })()
    .catch(() => null)
    .finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

/** Every sweep running in this process for a run, settled. */
export async function awaitSweeps(sandboxRoot: string): Promise<void> {
  await Promise.all([...inflight.entries()].filter(([k]) => k.startsWith(`${sandboxRoot}\u0000`)).map(([, p]) => p));
}

/**
 * The sweeps still pending on standing coverage records, run: those running
 * in this process are awaited, and those whose record is older than the
 * orphan bound (lost with the process that began them) are run here. The
 * finish gate and the answers check call it before they read the gate.
 */
export async function reconcileSweeps(sandboxRoot: string, o: { orphanMs?: number; maxBytes?: number; maxMs?: number; now?: number } = {}): Promise<number> {
  const P = await import("./protocol.ts");
  const entries = await P.readLedger(sandboxRoot).catch(() => [] as LedgerEntry[]);
  const replaced = P.supersededBy(entries);
  const sweeps = await readSweeps(sandboxRoot);
  const orphan = o.orphanMs ?? sweepOrphanMs();
  const now = o.now ?? Date.now();
  let ran = 0;
  for (const c of entries) {
    if (c.kind !== "coverage" || replaced.has(c.seq) || !c.looked_for?.length || sweepOf(c, sweeps)) continue;
    const key = `${sandboxRoot}\u0000${c.hash}`;
    if (!inflight.has(key) && now - Date.parse(c.at) < orphan) continue;
    await startSweep(sandboxRoot, c, o);
    ran += 1;
  }
  return ran;
}
