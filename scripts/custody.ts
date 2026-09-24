#!/usr/bin/env node
/**
 * What the host can say about a run once nothing is running any more.
 *
 * Every integrity check an agent reports about itself — its `inputs` check,
 * its done line — is the agent's word. This is the harness's, taken after
 * the agents (and, under --isolation microvm, their VMs) are gone, from the
 * host, reading every byte again:
 *
 *   - the evidence: every file inputs.json lists, hashed in full now and
 *     compared with the sha256 recorded when the run started; anything
 *     missing, changed or added is named. The manifest itself is compared
 *     with the sha256 the kickoff anchored outside the run, so a manifest
 *     rewritten inside the run is caught rather than trusted;
 *   - the sessions: every file under .pi-sessions/, with its sha256 — the
 *     agents' own transcripts, sealed as they were left;
 *   - the kept outputs: every whole tool output the trace points to
 *     (`tool-output/…` with a sha256), re-hashed; a file that is gone or no
 *     longer matches what the trace says was kept is named;
 *   - the trace: the hash chain and its anchor; every line outside the
 *     chain (the spills), parsed and attributed to the seat whose directory
 *     it sits in;
 *   - the ledger: its own chain;
 *   - the VMs: for a microVM run, each VM's image digest and, when its disk
 *     was kept, the snapshot re-hashed against its record and verified by
 *     msb's own integrity record; the kept logs hashed; a VM whose disk was
 *     not kept, or whose finish failed, named.
 *
 * Custody reads what agents wrote, so it trusts none of it: every file it
 * opens is opened as a regular file, never through a link and never waiting
 * on a FIFO or a device (O_NOFOLLOW | O_NONBLOCK, then fstat), every path it
 * takes from a trace line or a VM record must be under the run (or the
 * snapshot directory), the trace is read a line at a time whatever its size,
 * and every file is hashed in full — no size is too large to check — against
 * one deadline, checked inside the hashing, past which `custody.json` names
 * what was not checked and says it is incomplete instead of the stop hanging.
 * A second, hard deadline ends the process if anything still holds it.
 *
 * Writes `custody.json` at the sandbox root, adds its sha256 to the anchor
 * the kickoff wrote outside the run, and prints its summary line.
 *
 *   node --experimental-strip-types scripts/custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet]
 */
import { createHash } from "node:crypto";
import { constants as fsConstants, existsSync } from "node:fs";
import { lstat, mkdtemp, open, readdir, readFile, readlink, realpath, rename, rm, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { eventChainVerifier, readInputsManifest, specialKind, verifyLedgerChain } from "../extensions/protocol.ts";

type Handle = Awaited<ReturnType<typeof open>>;

export const CUSTODY_REL = "custody.json";
/** A sender clock this far from the collector's is named in the verdict. */
export const CLOCK_FLAG_SEC = 120;
/** A text custody holds whole (a VM record, the ledger, inputs.json): past this it is not one. */
const MAX_TEXT_BYTES = 256 * 1024 * 1024;
/** How far past the deadline the process may run before it ends itself. */
const HARD_GRACE_SEC = 120;

/**
 * The kickoff's own record of what the run started with, outside the run.
 * The kickoff names it by the sandbox's real parent (`pwd -P`); a sandbox
 * given through a link (/tmp on macOS) resolves to the same file.
 */
export function custodyAnchorPath(sandbox: string): string {
  return `${resolve(sandbox)}.custody-anchor.json`;
}

async function anchorPathFor(sandbox: string): Promise<string> {
  const parent = await realpath(dirname(resolve(sandbox))).catch(() => dirname(resolve(sandbox)));
  const real = join(parent, basename(resolve(sandbox)));
  return existsSync(`${real}.custody-anchor.json`) ? `${real}.custody-anchor.json` : custodyAnchorPath(sandbox);
}

class Deadline {
  private readonly until: number;
  constructor(seconds: number) {
    this.until = Date.now() + seconds * 1000;
  }
  get over(): boolean {
    return Date.now() > this.until;
  }
}

/**
 * A file opened the one way custody opens anything: as a regular file, not
 * through a link (O_NOFOLLOW), not waiting on a FIFO or a device someone left
 * in its place (O_NONBLOCK), and checked by fstat after the open, so a file
 * swapped in between is what is judged.
 */
export async function openRegular(path: string): Promise<{ handle: Handle; size: number } | { why: string }> {
  const lst = await lstat(path).catch(() => null);
  if (!lst) return { why: "missing" };
  if (lst.isSymbolicLink()) return { why: "a link" };
  if (!lst.isFile()) return { why: "not a regular file" };
  let handle: Handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { why: code === "ELOOP" ? "a link" : code === "ENOENT" ? "missing" : `unreadable (${code ?? "error"})` };
  }
  const st = await handle.stat();
  if (!st.isFile()) {
    await handle.close();
    return { why: "not a regular file" };
  }
  return { handle, size: st.size };
}

/** A regular file's text, whole; the reason when it is not one or is too large to hold. */
export async function readRegularText(path: string, maxBytes = MAX_TEXT_BYTES): Promise<{ text: string } | { why: string }> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  try {
    if (opened.size > maxBytes) return { why: `over ${maxBytes} bytes` };
    return { text: await opened.handle.readFile("utf8") };
  } finally {
    await opened.handle.close();
  }
}

/**
 * A regular file's sha256, read in full, with the deadline checked as it
 * goes: null when the deadline passed before the end (the file is then named
 * as not checked), the reason when it is not a regular file.
 */
async function hashRegular(path: string, deadline: Deadline): Promise<{ sha256: string; size: number } | { why: string } | null> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  try {
    const hash = createHash("sha256");
    for await (const chunk of opened.handle.createReadStream({ autoClose: false, highWaterMark: 4 * 1024 * 1024 })) {
      hash.update(chunk as Buffer);
      if (deadline.over) return null;
    }
    return { sha256: hash.digest("hex"), size: opened.size };
  } finally {
    await opened.handle.close();
  }
}

/** Each line of a regular file, streamed: a trace of any size is read without holding it. */
async function eachLine(path: string, onLine: (line: string) => void): Promise<{ lines: number } | { why: string }> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  let lines = 0;
  try {
    const rl = createInterface({ input: opened.handle.createReadStream({ autoClose: false, encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) {
      if (line === "") continue;
      lines += 1;
      onLine(line);
    }
  } finally {
    await opened.handle.close();
  }
  return { lines };
}

async function readlinkSafe(path: string): Promise<string | null> {
  const lst = await lstat(path).catch(() => null);
  if (!lst?.isSymbolicLink()) return null;
  return readlink(path).catch(() => null);
}

/** A regular file, by lstat (a link is not followed), or null with the reason. */
async function regular(path: string): Promise<{ size: number } | { why: string }> {
  const st = await lstat(path).catch(() => null);
  if (!st) return { why: "missing" };
  if (st.isSymbolicLink()) return { why: "a link" };
  if (!st.isFile()) return { why: "not a regular file" };
  return { size: st.size };
}

/**
 * Files under a directory, never through a link; what is not a regular file
 * or a directory (a link, a FIFO, a socket, a device) is listed in `other`
 * so it is named rather than silently passed over.
 */
async function walkAll(dir: string, base = dir): Promise<{ files: string[]; other: string[] }> {
  const files: string[] = [];
  const other: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      const sub = await walkAll(abs, base);
      files.push(...sub.files);
      other.push(...sub.other);
    } else if (entry.isFile()) files.push(abs);
    else other.push(relative(base, abs));
  }
  return { files: files.sort(), other: other.sort() };
}

async function walk(dir: string): Promise<string[]> {
  return (await walkAll(dir)).files;
}

/**
 * Names under the evidence, the way every walk over it does: a link is a
 * name of its own and is never followed (a loop would never end, and what
 * is under a directory link is another directory's); the top of the
 * evidence may itself be a link (--inputs in place).
 */
async function walkEvidence(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walkEvidence(abs)));
    else out.push(abs); // a file, a link, and anything else (a FIFO, a socket, a device) is a name
  }
  return out;
}

export type Custody = {
  at: string;
  run: string | null;
  inputs:
    | null
    | { unverifiable: string }
    | {
        files: number;
        bytes: number;
        unchanged: boolean;
        /** Every listed file was re-read in full before the deadline. */
        complete: boolean;
        changed: string[];
        missing: string[];
        added: string[];
        /** Files not re-read because the deadline passed: the verdict does not cover them. */
        skipped: string[];
        manifest_sha256: string;
        manifest_anchored: boolean | null;
      };
  sessions: { files: Array<{ path: string; bytes: number; sha256: string | null }>; digest: string; not_files: string[] };
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[]; refused: string[] };
  trace: {
    lines: number;
    intact: boolean;
    detail: string;
    unverified: number;
    disputed: number;
    spilled: Array<{ path: string; lines: number; agent: string | null; bad: number; duplicates: number; refused?: string }>;
    /** Per sending process, how many of its numbered lines are in neither the chain nor a spill. */
    gaps: Array<{ sid: string; agent: string; missing: number }>;
    /** Per agent, lines whose own clock (`ts`) was more than CLOCK_FLAG_SEC off the collector's (`recv_ts`). */
    clock: Array<{ agent: string; lines: number; max_skew_s: number }>;
  };
  ledger: {
    entries: number;
    chained: number;
    intact: boolean;
    detail: string;
    /** Entries whose hash the trace carries (the record tool's line, or the hub's) but the ledger does not: deleted. */
    missing_from_ledger: string[];
    /** Chained (v2) entries the trace never carried: written into the file without the tool. */
    not_on_trace: number[];
  } | null;
  vms:
    | null
    | Array<{
        agent: string;
        /** The sha256 of the VM's record as custody read it. */
        record_sha256: string;
        image: string | null;
        /** The digest the kickoff resolved for the run; null when it recorded none. */
        expected_image: string | null;
        stopped: boolean;
        kept: string | null;
        snapshot: null | { path: string; sha256: string; verified: boolean; msb_verified: boolean | null } | { error: string };
        logs: Array<{ path: string; sha256: string }>;
        /** Placeholders msb stopped on their way to a host their secret is not bound to (runtime.log). */
        secret_violations: SecretViolation[];
        /** Packages the VM held at stop that its image did not (vm.ts INVENTORY_SCRIPT), or why that is unknown. */
        installed_outside: { apt: string[]; venv: string[]; note: string | null };
        /** msb's version when the VM was made and when it was put away, when they differ. */
        runtime_changed: { from: string; to: string } | null;
      }>;
  incomplete: string | null;
  summary: string;
};

/** What a VM's stop-time inventory said: package names, or why there is none. */
function outsideOf(raw: unknown): { apt: string[]; venv: string[]; note: string | null } {
  if (!raw || typeof raw !== "object") return { apt: [], venv: [], note: "no inventory was taken (a VM put away before stop took one)" };
  const r = raw as { error?: string; baseline?: boolean; apt?: Record<string, string>; venv?: Record<string, string> };
  if (r.error) return { apt: [], venv: [], note: `the inventory failed: ${r.error}` };
  const fmt = (m?: Record<string, string>) => Object.entries(m ?? {}).map(([k, v]) => `${k} ${v}`);
  return { apt: fmt(r.apt), venv: fmt(r.venv), note: r.baseline === false ? "the image records no full package list, so apt installs cannot be told apart" : null };
}

export type SecretViolation = { at: string; env: string; host: string; method: string; path: string; action: string };

/**
 * msb's record of a placeholder it stopped: a WARN line in the VM's
 * runtime.log (measured, msb 0.7.2, secretViolationAction block-and-log):
 *   <ts>  WARN microsandbox_network::engine::secrets::handler: secret
 *   violation: placeholder detected for disallowed host action=block-and-log
 *   secret_env_var=K placeholder=… sni=… host=… method=GET path=/v1/models …
 * A request to a host outside the policy is not logged at all: its name does
 * not resolve and its address has no route. This is the one refusal msb
 * writes down, and the one that says a credential was aimed somewhere else.
 */
export function secretViolations(runtimeLog: string): SecretViolation[] {
  const out: SecretViolation[] = [];
  for (const line of runtimeLog.split("\n")) {
    const i = line.indexOf("secret violation:");
    if (i < 0) continue;
    const fields: Record<string, string> = {};
    for (const m of line.slice(i).matchAll(/(\w+)=(\S*)/g)) fields[m[1]] = m[2];
    out.push({
      at: line.slice(0, line.indexOf(" ")).trim(),
      env: fields.secret_env_var ?? "",
      host: fields.host || fields.sni || "",
      method: fields.method ?? "",
      path: fields.path ?? "",
      action: fields.action ?? "",
    });
  }
  return out;
}

/** Every `{path: "tool-output/…", sha256}` a trace line carries, wherever it sits in the line. */
export function keptOutputRefs(value: unknown, out: Map<string, string> = new Map()): Map<string, string> {
  if (Array.isArray(value)) {
    for (const v of value) keptOutputRefs(v, out);
  } else if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    if (typeof o.path === "string" && o.path.startsWith("tool-output/") && typeof o.sha256 === "string" && /^[0-9a-f]{64}$/.test(o.sha256)) {
      out.set(o.path, o.sha256);
    }
    for (const v of Object.values(o)) keptOutputRefs(v, out);
  }
  return out;
}

/** A path from a trace line, resolved: a regular file under `tool-output/` of the run, or the reason it is not. */
export async function confinedOutput(sandbox: string, rel: string): Promise<{ abs: string; size: number } | { why: string }> {
  if (!/^tool-output\/[a-z][a-z0-9_-]{0,31}\/[^/\0]+$/.test(rel)) return { why: "not a file directly under tool-output/<agent>/" };
  const root = await realpath(join(sandbox, "tool-output")).catch(() => null);
  if (!root) return { why: "no tool-output/" };
  const abs = join(sandbox, rel);
  const reg = await regular(abs);
  if ("why" in reg) return reg;
  const real = await realpath(abs).catch(() => null);
  if (!real || !real.startsWith(`${root}/`)) return { why: "outside tool-output/" };
  return { abs: real, size: reg.size };
}

/**
 * msb's own integrity check of a kept disk. `msb snapshot verify` reads a
 * snapshot directory, not the `.msb` archive stop keeps (measured: on the
 * archive it answers "snapshot not found: …/snapshot.json: Not a directory",
 * so this check used to fail every time). The archive is loaded into a
 * directory of its own, verified there — msb recomputes its merkle tree over
 * every file — and taken out of msb's index again. Null when msb is not
 * there to ask.
 */
async function msbSnapshotVerify(file: string): Promise<boolean | null> {
  const { msbBinary } = await import("./vm.ts");
  const msb = msbBinary();
  const run = (args: string[]) =>
    new Promise<{ code: number; out: string; missing: boolean }>((done) => {
      const child = execFile(msb, args, { timeout: 10 * 60_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) =>
        done({ code: err ? 1 : 0, out: `${stdout}${stderr}`, missing: (err as NodeJS.ErrnoException | null)?.code === "ENOENT" }),
      );
      child.stdin?.end();
    });
  const dest = await mkdtemp(join(tmpdir(), "dfs-verify-"));
  let digest = "";
  try {
    const loaded = await run(["snapshot", "load", "--dest", dest, file]);
    if (loaded.code !== 0) return loaded.missing ? null : false;
    digest = loaded.out.match(/sha256:[0-9a-f]{64}/)?.[0] ?? "";
    const dir = (await walk(dest)).find((p) => p.endsWith("/snapshot.json"));
    if (!dir) return false;
    const verified = await run(["snapshot", "verify", dirname(dir)]);
    return verified.code === 0 && /Verification:\s+verified/.test(verified.out);
  } catch {
    return null;
  } finally {
    if (digest) await run(["snapshot", "remove", "--force", "--quiet", digest]);
    await rm(dest, { recursive: true, force: true }).catch(() => undefined);
  }
}

export async function takeCustody(sandboxInput: string, options: { timeoutSec?: number; run?: string; progress?: (line: string) => void } = {}): Promise<Custody> {
  const sandbox = resolve(sandboxInput);
  const deadline = new Deadline(options.timeoutSec ?? 4 * 3600);
  let incomplete: string | null = null;
  const tooLate = (what: string) => {
    if (deadline.over && !incomplete) incomplete = `the deadline passed during ${what}`;
    return deadline.over;
  };
  const say = options.progress ?? (() => undefined);
  let anchor: { inputs_manifest_sha256?: string; run?: string } | null = null;
  const anchorFile = await anchorPathFor(sandbox);
  try {
    anchor = JSON.parse(await readFile(anchorFile, "utf8"));
  } catch {
    anchor = null;
  }
  const run = options.run ?? anchor?.run ?? null;

  // --- the evidence ---------------------------------------------------------
  let inputs: Custody["inputs"] = null;
  const manifestPath = join(sandbox, "inputs.json");
  const manifestReg = await regular(manifestPath);
  const manifest = "why" in manifestReg ? null : await readInputsManifest(sandbox).catch(() => null);
  const hasEvidence = existsSync(join(sandbox, "inputs")) || existsSync(join(sandbox, "inputs.device"));
  if (!manifest && "why" in manifestReg && manifestReg.why !== "missing") {
    inputs = { unverifiable: `inputs.json is ${manifestReg.why}` };
  } else if (!manifest && anchor?.inputs_manifest_sha256) {
    inputs = { unverifiable: "the kickoff anchored an inputs.json that is gone or unreadable now" };
  } else if (!manifest && hasEvidence) {
    inputs = { unverifiable: "the run has evidence but no readable inputs.json to compare it with" };
  } else if (manifest) {
    const manifestRead = await readRegularText(manifestPath);
    const manifestSha = createHash("sha256").update("text" in manifestRead ? manifestRead.text : "").digest("hex");
    const anchored = anchor?.inputs_manifest_sha256 ? anchor.inputs_manifest_sha256 === manifestSha : null;
    const changed: string[] = [];
    const missing: string[] = [];
    const skipped: string[] = [];
    const listed = new Set(manifest.files.map((f) => f.path));
    const evidenceRoot = await realpath(join(sandbox, "inputs")).catch(() => join(sandbox, "inputs"));
    let index = 0;
    let lastSaid = Date.now();
    for (const file of manifest.files) {
      index += 1;
      if (tooLate("the evidence re-hash")) {
        skipped.push(file.path);
        continue;
      }
      const abs = join(evidenceRoot, file.path.replace(/^inputs\//, ""));
      if (typeof file.link === "string") {
        // A link is checked as a link: its target, never followed.
        const target = await readlinkSafe(abs);
        if (target === null) missing.push(file.path);
        else if (target !== file.link) changed.push(file.path);
        continue;
      }
      const lst = await lstat(abs).catch(() => null);
      if (!lst) {
        missing.push(file.path);
        continue;
      }
      if (file.special) {
        // A FIFO, socket or device node is checked by its kind, never opened.
        if (specialKind(lst) !== file.special) changed.push(file.path);
        continue;
      }
      if (!lst.isFile()) {
        // A link, a FIFO or a device where a file was: not what was recorded.
        changed.push(file.path);
        continue;
      }
      // The size first: a file that grew or shrank has changed, whatever
      // its size, and needs no reading to say so.
      if (typeof file.bytes === "number" && lst.size !== file.bytes) {
        changed.push(file.path);
        continue;
      }
      if (lst.size > 256 * 1024 * 1024 || Date.now() - lastSaid > 30_000) {
        say(`custody: re-hashing ${file.path} (${index} of ${manifest.files.length}, ${lst.size} bytes)`);
        lastSaid = Date.now();
      }
      const hashed = await hashRegular(abs, deadline);
      if (hashed === null) {
        tooLate("the evidence re-hash");
        skipped.push(file.path);
        continue;
      }
      if ("why" in hashed) (hashed.why === "missing" ? missing : changed).push(file.path);
      else if (hashed.sha256 !== file.sha256) changed.push(file.path);
    }
    const added: string[] = [];
    const root = join(sandbox, "inputs");
    if (existsSync(root)) {
      const real = await realpath(root).catch(() => root);
      for (const abs of await walkEvidence(real)) {
        const key = `inputs/${relative(real, abs).split("\\").join("/")}`;
        if (!listed.has(key)) added.push(key);
      }
    }
    inputs = {
      files: manifest.files.length,
      bytes: manifest.bytes ?? manifest.files.reduce((n, f) => n + (f.bytes ?? 0), 0),
      unchanged: !changed.length && !missing.length && !added.length && !skipped.length && anchored !== false,
      complete: !skipped.length,
      changed,
      missing,
      added,
      skipped,
      manifest_sha256: manifestSha,
      manifest_anchored: anchored,
    };
  }

  // --- the sessions ----------------------------------------------------------
  const sessionFiles: Custody["sessions"]["files"] = [];
  const sessionWalk = await walkAll(join(sandbox, ".pi-sessions"));
  for (const abs of sessionWalk.files) {
    if (tooLate("the session seal")) {
      sessionFiles.push({ path: relative(sandbox, abs), bytes: (await lstat(abs).catch(() => null))?.size ?? 0, sha256: null });
      continue;
    }
    const hashed = await hashRegular(abs, deadline);
    if (hashed === null) tooLate("the session seal");
    sessionFiles.push({ path: relative(sandbox, abs), bytes: hashed && !("why" in hashed) ? hashed.size : 0, sha256: hashed && !("why" in hashed) ? hashed.sha256 : null });
  }
  const sessionsDigest = createHash("sha256").update(sessionFiles.map((f) => `${f.sha256 ?? "unhashed"}  ${f.path}`).join("\n")).digest("hex");

  // --- the trace and the kept outputs -----------------------------------------
  const refs = new Map<string, string>();
  let lines = 0;
  let unverified = 0;
  let disputed = 0;
  // Numbered lines, per sender: (agent, sid) and the seqs seen. Keyed by the
  // agent the line is attributed to as well as its sid, so a seat that
  // writes lines under another's sid cannot fill that sender's gaps.
  const numbered = new Map<string, { agent: string; sid: string; seqs: Set<number> }>();
  const note = (parsed: Record<string, unknown>) => {
    if (typeof parsed.sid !== "string" || typeof parsed.seq !== "number") return false;
    const agent = String(parsed.agent ?? "?");
    const key = `${agent}\u0000${parsed.sid}`;
    const entry = numbered.get(key) ?? { agent, sid: parsed.sid, seqs: new Set<number>() };
    numbered.set(key, entry);
    const had = entry.seqs.has(parsed.seq);
    entry.seqs.add(parsed.seq);
    return had;
  };
  // Every ledger entry's hash the trace carries: the record tool's own line,
  // and the hub's line for a record made from a VM.
  const recordHashes = new Set<string>();
  const noteRecord = (parsed: Record<string, unknown>) => {
    const result = parsed.result as Record<string, unknown> | undefined;
    const args = parsed.args as Record<string, unknown> | undefined;
    if (!result || result.ok !== true || typeof result.hash !== "string" || result.merged === true) return;
    if (parsed.tool === "record" || (parsed.tool === "hub_call" && args?.fn === "recordEntry")) recordHashes.add(result.hash);
  };
  // A sender's clock against the collector's: in a VM, the guest's against
  // the host's. The record orders by the collector's; a line whose own time
  // is far from it is said, because a reader of `ts` would be misled.
  const skewed = new Map<string, { lines: number; max: number }>();
  const clockOf = (parsed: Record<string, unknown>) => {
    if (typeof parsed.ts !== "string" || typeof parsed.recv_ts !== "string") return;
    const skew = (Date.parse(parsed.ts) - Date.parse(parsed.recv_ts)) / 1000;
    if (!Number.isFinite(skew) || Math.abs(skew) <= CLOCK_FLAG_SEC) return;
    const agent = String(parsed.agent ?? "?");
    const entry = skewed.get(agent) ?? { lines: 0, max: 0 };
    entry.lines += 1;
    if (Math.abs(skew) > Math.abs(entry.max)) entry.max = Math.round(skew);
    skewed.set(agent, entry);
  };
  // The chain is checked on the same pass, a line at a time: a trace of
  // any size is read without holding it whole.
  let traceAnchor = null;
  try {
    traceAnchor = JSON.parse(await readFile(`${sandbox}.trace-anchor.json`, "utf8"));
  } catch {
    traceAnchor = null;
  }
  const chainCheck = eventChainVerifier(traceAnchor);
  const traceRead = await eachLine(join(sandbox, "traces", "events.jsonl"), (line) => {
    chainCheck.push(line);
    if (!line.trim()) return;
    lines += 1;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      note(parsed);
      clockOf(parsed);
      keptOutputRefs(parsed, refs);
      noteRecord(parsed);
      if (parsed.agent_unverified === true) unverified += 1;
      // The collector's word on a line whose sender claimed another seat.
      if (parsed.claimed_agent) disputed += 1;
    } catch {
      // a line that does not parse is the chain check's business
    }
  });
  const traceProblem = "why" in traceRead && traceRead.why !== "missing" ? traceRead.why : null;
  // Lines the collector never took, kept rather than lost: the shared spill
  // on the host, each agent's own in a VM run, and the hub's own.
  const spills: Custody["trace"]["spilled"] = [];
  const spillPaths = ["work/.trace-spill.jsonl", "traces/system-spill.jsonl", "traces/hub-spill.jsonl", ...(await readdir(join(sandbox, "tool-output")).catch(() => [])).map((a) => `tool-output/${a}/trace-spill.jsonl`)];
  for (const rel of spillPaths) {
    // A seat can leave anything at its spill's path: a link to a host file,
    // a FIFO that would hold the read forever. Only a regular file is read.
    const owner = rel.match(/^tool-output\/([^/]+)\//)?.[1] ?? (rel.startsWith("traces/") ? "system" : null);
    let count = 0;
    let bad = 0;
    let duplicates = 0;
    const read = await eachLine(join(sandbox, rel), (l) => {
      if (!l.trim()) return;
      count += 1;
      try {
        const parsed = JSON.parse(l) as Record<string, unknown>;
        // A spilled line says whose it is; the directory it sits in says whose it can be.
        if (owner && owner !== "system" && parsed.agent !== owner) bad += 1;
        // Also in the chain: the collector took it after the sender gave up.
        if (note(parsed)) duplicates += 1;
        noteRecord(parsed);
      } catch {
        bad += 1;
      }
    });
    if ("why" in read) {
      if (read.why !== "missing") spills.push({ path: rel, lines: 0, agent: owner, bad: 0, duplicates: 0, refused: read.why });
      continue;
    }
    if (!count) continue;
    spills.push({ path: rel, lines: count, agent: owner, bad, duplicates });
  }
  // A process's numbered lines run 1..n; a number missing below its highest
  // is a line that reached neither the chain nor a spill.
  const gaps: Custody["trace"]["gaps"] = [];
  for (const entry of numbered.values()) {
    let top = 0;
    for (const n of entry.seqs) if (n > top) top = n;
    const missing = top - entry.seqs.size;
    if (missing > 0) gaps.push({ sid: entry.sid, agent: entry.agent, missing });
  }
  const clock = [...skewed].map(([agent, e]) => ({ agent, lines: e.lines, max_skew_s: e.max }));
  const missingOut: string[] = [];
  const mismatched: string[] = [];
  const refused: string[] = [];
  let verified = 0;
  for (const [path, sha] of refs) {
    if (tooLate("the kept-output check")) break;
    const where = await confinedOutput(sandbox, path);
    if ("why" in where) {
      (where.why === "missing" ? missingOut : refused).push(where.why === "missing" ? path : `${path} (${where.why})`);
      continue;
    }
    const hashed = await hashRegular(where.abs, deadline);
    if (hashed === null) {
      tooLate("the kept-output check");
      refused.push(`${path} (not checked: the deadline passed)`);
      continue;
    }
    if ("why" in hashed) refused.push(`${path} (${hashed.why})`);
    else if (hashed.sha256 !== sha) mismatched.push(path);
    else verified += 1;
  }
  const chain = chainCheck.finish();
  const chained = chain.ok && chain.chained > 0;
  const chainDetail = traceProblem
    ? `the trace is ${traceProblem}`
    : !lines
    ? "no trace"
    : chain.ok
      ? chain.chained > 0
        ? `chain intact, ${chain.chained} of ${chain.total} lines chained${traceAnchor ? ", anchor matches" : ", no anchor"}`
        : "unchained: no collector wrote this trace"
      : `chain broken at line ${chain.broken_at ?? "?"} (${chain.reason ?? "unknown"})`;

  // --- the ledger --------------------------------------------------------------
  let ledger: Custody["ledger"] = null;
  const ledgerRead = await readRegularText(join(sandbox, "ledger", "entries.jsonl"));
  const ledgerText = "text" in ledgerRead ? ledgerRead.text : "";
  if ("why" in ledgerRead && ledgerRead.why !== "missing") {
    ledger = { entries: 0, chained: 0, intact: false, detail: `the ledger is ${ledgerRead.why}`, missing_from_ledger: [], not_on_trace: [] };
  } else if (ledgerText.trim() || recordHashes.size) {
    const v = verifyLedgerChain(ledgerText);
    // The ledger held to the trace: an entry whose hash the trace carries
    // must be in it (a tail deleted from the file is caught here, which the
    // ledger's own chain cannot see), and a chained entry of this version
    // must be on the trace (one written into the file without the tool is).
    const inLedger = new Set(v.hashes);
    const missingFromLedger = [...recordHashes].filter((h) => !inLedger.has(h));
    const notOnTrace: number[] = [];
    if (recordHashes.size) {
      for (const line of ledgerText.split("\n")) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as { v?: number; seq?: number; hash?: string };
          if (e.v === 2 && e.hash && !recordHashes.has(e.hash)) notOnTrace.push(Number(e.seq));
        } catch {
          // the chain check names it
        }
      }
    }
    ledger = {
      entries: v.total,
      chained: v.chained,
      intact: v.ok && !missingFromLedger.length && !notOnTrace.length,
      detail: v.ok ? `${v.chained} of ${v.total} entries chained` : `broken at entry ${v.broken_at ?? "?"} (${v.reason ?? "unknown"})`,
      missing_from_ledger: missingFromLedger,
      not_on_trace: notOnTrace,
    };
  }

  // --- the VMs -----------------------------------------------------------------
  let vms: Custody["vms"] = null;
  const vmDir = join(sandbox, "vm");
  if (existsSync(vmDir)) {
    vms = [];
    const snapRoot = await realpath(`${sandbox}.vm-snapshots`).catch(() => null);
    for (const name of (await readdir(vmDir)).filter((n) => n.endsWith(".json")).sort()) {
      if (tooLate("the VM check")) break;
      let rec: Record<string, unknown>;
      let recordSha = "";
      const recText = await readRegularText(join(vmDir, name));
      if ("why" in recText) continue;
      try {
        rec = JSON.parse(recText.text);
        recordSha = createHash("sha256").update(recText.text).digest("hex");
      } catch {
        continue;
      }
      if (run && rec.run && rec.run !== run) continue; // another run's record in a reused sandbox
      const image = ((rec.image as Record<string, unknown> | undefined)?.manifest_digest as string | null) ?? null;
      const expectedImage = ((rec.image as Record<string, unknown> | undefined)?.expected_digest as string | undefined) ?? null;
      const snap = rec.snapshot as { path?: string; sha256?: string; error?: string } | undefined;
      let snapshot: NonNullable<Custody["vms"]>[number]["snapshot"] = null;
      if (snap?.error) snapshot = { error: snap.error };
      else if (snap?.path && snap.sha256) {
        // Only a file in the run's own snapshot directory, and only a regular one.
        const real = await realpath(snap.path).catch(() => null);
        const inPlace = !!real && !!snapRoot && real.startsWith(`${snapRoot}/`) && basename(real).endsWith(".msb");
        const hashed = inPlace ? await hashRegular(real as string, deadline) : null;
        if (inPlace && hashed === null) tooLate("the snapshot check");
        const ok = !!hashed && !("why" in hashed) && hashed.sha256 === snap.sha256;
        const msbOk = ok && !deadline.over ? await msbSnapshotVerify(real as string) : null;
        snapshot = { path: snap.path, sha256: snap.sha256, verified: ok, msb_verified: msbOk };
      }
      const logs: Array<{ path: string; sha256: string }> = [];
      let violations: SecretViolation[] = [];
      const logDir = typeof rec.logs === "string" ? await realpath(rec.logs).catch(() => null) : null;
      if (logDir && snapRoot && logDir.startsWith(`${snapRoot}/`)) {
        for (const abs of await walk(logDir)) {
          const hashed = await hashRegular(abs, deadline);
          if (hashed === null) tooLate("the VM log hash");
          logs.push({ path: relative(dirname(snapRoot), abs), sha256: hashed && !("why" in hashed) ? hashed.sha256 : "unhashed" });
          if (basename(abs) === "runtime.log") {
            let text = "";
            await eachLine(abs, (l) => {
              if (l.includes("secret violation:")) text += `${l}\n`;
            });
            violations = violations.concat(secretViolations(text));
          }
        }
      }
      vms.push({
        agent: String(rec.agent ?? name.replace(/\.json$/, "")),
        record_sha256: recordSha,
        image,
        expected_image: expectedImage,
        stopped: typeof rec.stopped_at === "string",
        kept: typeof rec.kept === "string" ? rec.kept : null,
        snapshot,
        logs,
        secret_violations: violations,
        installed_outside: outsideOf(rec.installed_outside_image),
        runtime_changed: rec.runtime_changed && typeof rec.runtime_changed === "object" ? (rec.runtime_changed as { from: string; to: string }) : null,
      });
    }
  }

  // --- the summary -------------------------------------------------------------
  const parts: string[] = [];
  if (inputs && "unverifiable" in inputs) parts.push(`EVIDENCE UNVERIFIABLE: ${inputs.unverifiable}`);
  else if (inputs) {
    const changedAny = inputs.changed.length || inputs.missing.length || inputs.added.length || inputs.manifest_anchored === false;
    parts.push(inputs.unchanged
      ? `evidence unchanged (${inputs.files} file${inputs.files === 1 ? "" : "s"} re-hashed in full${inputs.manifest_anchored === true ? ", manifest anchored" : inputs.manifest_anchored === null ? ", manifest not anchored" : ""})`
      : changedAny
        ? `EVIDENCE CHANGED: ${inputs.changed.length} changed, ${inputs.missing.length} missing, ${inputs.added.length} added${inputs.manifest_anchored === false ? ", MANIFEST REWRITTEN" : ""}${inputs.skipped.length ? `; ${inputs.skipped.length} NOT RE-READ` : ""}`
        : `EVIDENCE NOT FULLY RE-HASHED: ${inputs.files - inputs.skipped.length} of ${inputs.files} checked unchanged, ${inputs.skipped.length} not re-read before the deadline`);
  }
  parts.push(`${sessionFiles.length} session file${sessionFiles.length === 1 ? "" : "s"} sealed${sessionWalk.other.length ? `, ${sessionWalk.other.length} NOT A FILE (${sessionWalk.other.join(", ")})` : ""}`);
  parts.push(missingOut.length || mismatched.length || refused.length
    ? `KEPT OUTPUTS: ${verified}/${refs.size} verified, ${missingOut.length} missing, ${mismatched.length} not matching the trace, ${refused.length} refused`
    : `${verified}/${refs.size} kept outputs verified`);
  if (traceProblem) parts.push(`TRACE UNREADABLE: ${traceProblem}`);
  else if (!lines) parts.push("NO TRACE");
  else if (chained) parts.push(`trace ${lines} lines, chain intact${unverified ? `, ${unverified} unverified` : ""}${disputed ? `, ${disputed} disputed` : ""}`);
  else if (chain.ok) parts.push(`TRACE UNCHAINED (${lines} lines)`);
  else parts.push("TRACE CHAIN BROKEN");
  const spilled = spills.reduce((n, s) => n + s.lines, 0);
  const badSpill = spills.reduce((n, s) => n + s.bad, 0);
  const dupSpill = spills.reduce((n, s) => n + s.duplicates, 0);
  if (spilled) parts.push(`${spilled} trace line${spilled === 1 ? "" : "s"} outside the chain (spilled: ${spills.filter((s) => s.lines).map((s) => s.path).join(", ")})${dupSpill ? `, ${dupSpill} also in the chain` : ""}${badSpill ? `, ${badSpill} NOT ATTRIBUTABLE` : ""}`);
  const refusedSpills = spills.filter((s) => s.refused);
  if (refusedSpills.length) parts.push(`SPILL NOT READ: ${refusedSpills.map((s) => `${s.path} is ${s.refused}`).join("; ")}`);
  if (clock.length) parts.push(`sent with a clock more than ${CLOCK_FLAG_SEC} s off the host's: ${clock.map((c) => `${c.agent} ${c.lines} line${c.lines === 1 ? "" : "s"} (up to ${c.max_skew_s} s)`).join(", ")}; the record orders by the host's recv_ts`);
  const lost = gaps.reduce((n, g) => n + g.missing, 0);
  if (lost) parts.push(`${lost} TRACE LINE${lost === 1 ? "" : "S"} LOST (numbered but in neither the chain nor a spill: ${gaps.map((g) => `${g.agent} ${g.missing}`).join(", ")})`);
  if (ledger) {
    const chainedPart = ledger.chained === ledger.entries ? "all chained" : `${ledger.chained} of ${ledger.entries} chained`;
    if (ledger.intact) parts.push(`ledger ${ledger.entries} entries, ${chainedPart}, chain intact`);
    else if (ledger.missing_from_ledger.length || ledger.not_on_trace.length) {
      parts.push(`LEDGER DIFFERS FROM THE TRACE: ${ledger.missing_from_ledger.length} entr${ledger.missing_from_ledger.length === 1 ? "y" : "ies"} on the trace missing from the ledger, ${ledger.not_on_trace.length} in the ledger never on the trace${ledger.not_on_trace.length ? ` (seq ${ledger.not_on_trace.join(", ")})` : ""}${ledger.detail.startsWith("broken") ? `; LEDGER CHAIN BROKEN ${ledger.detail}` : ""}`);
    } else parts.push(`LEDGER CHAIN BROKEN (${ledger.detail})`);
  }
  if (vms) {
    const kept = vms.filter((v) => v.snapshot && "verified" in v.snapshot && v.snapshot.verified).length;
    const byMsb = vms.filter((v) => v.snapshot && "msb_verified" in v.snapshot && v.snapshot.msb_verified === true).length;
    const msbFailed = vms.filter((v) => v.snapshot && "msb_verified" in v.snapshot && v.snapshot.msb_verified === false);
    const failed = vms.filter((v) => (v.snapshot && "error" in v.snapshot) || v.kept || !v.stopped);
    parts.push(`${vms.length} VM${vms.length === 1 ? "" : "s"}, ${kept} of ${vms.length} snapshots verified against their record, ${byMsb} by msb's own integrity check${msbFailed.length ? `, ${msbFailed.length} FAILED MSB'S CHECK (${msbFailed.map((v) => v.agent).join(", ")})` : ""}${failed.length ? `, ${failed.length} NOT PUT AWAY (${failed.map((v) => v.agent).join(", ")})` : ""}`);
    const offImage = vms.filter((v) => v.expected_image && v.image && v.image !== v.expected_image);
    if (offImage.length) parts.push(`IMAGE DIGEST DIFFERS: ${offImage.map((v) => `${v.agent} booted ${v.image}, not ${v.expected_image}`).join("; ")}`);
    const moved = vms.filter((v) => v.runtime_changed);
    if (moved.length) parts.push(`MSB CHANGED DURING THE RUN: ${moved.map((v) => `${v.agent} ${v.runtime_changed?.from} → ${v.runtime_changed?.to}`).join("; ")}`);
    const outside = vms.filter((v) => v.installed_outside.apt.length || v.installed_outside.venv.length);
    if (outside.length) {
      parts.push(`INSTALLED OUTSIDE THE IMAGE AND THE TOOLCHAIN RECORD: ${outside.map((v) => `${v.agent} ${[...v.installed_outside.apt.map((p) => `apt ${p}`), ...v.installed_outside.venv.map((p) => `venv ${p}`)].join(", ")}`).join("; ")}`);
    }
    const sv = vms.flatMap((v) => v.secret_violations.map((x) => `${v.agent} ${x.env} → ${x.host} ${x.method} ${x.path}`.trim()));
    if (sv.length) parts.push(`${sv.length} SECRET PLACEHOLDER${sv.length === 1 ? "" : "S"} AIMED AT A HOST NOT ITS OWN, stopped by msb: ${sv.join("; ")}`);
  }
  if (incomplete) parts.push(`CUSTODY INCOMPLETE: ${incomplete}`);

  const custody: Custody = {
    at: new Date().toISOString(),
    run,
    inputs,
    sessions: { files: sessionFiles, digest: sessionsDigest, not_files: sessionWalk.other },
    tool_outputs: { referenced: refs.size, verified, missing: missingOut, mismatched, refused },
    trace: { lines, intact: chained, detail: chainDetail, unverified, disputed, spilled: spills, gaps, clock },
    ledger,
    vms,
    incomplete,
    summary: parts.join(" · "),
  };
  // Each stop's verdict is kept: the previous one goes beside it, dated.
  const file = join(sandbox, CUSTODY_REL);
  const previous = await readFile(file, "utf8").catch(() => "");
  if (previous) {
    try {
      const at = String((JSON.parse(previous) as { at?: string }).at ?? "previous").replace(/[^0-9A-Za-z]/g, "");
      await writeFile(join(sandbox, `custody.${at}.json`), previous);
    } catch {
      // an unreadable previous verdict is not worth keeping
    }
  }
  const text = `${JSON.stringify(custody, null, 2)}\n`;
  await writeFile(file, text);
  // The verdict's hash goes beside the kickoff's anchor, outside the run: a
  // custody.json edited after the stop no longer matches what stop wrote.
  await anchorVerdict(anchorFile, { at: custody.at, sha256: createHash("sha256").update(text).digest("hex"), summary: custody.summary, snapshots: (vms ?? []).flatMap((v) => (v.snapshot && "sha256" in v.snapshot ? [{ agent: v.agent, sha256: v.snapshot.sha256 }] : [])), sessions_digest: sessionsDigest }).catch(() => undefined);
  return custody;
}

/** Add a verdict to the anchor file outside the run; the kickoff's fields stay as they were. */
async function anchorVerdict(anchorFile: string, verdict: Record<string, unknown>): Promise<void> {
  let anchor: Record<string, unknown> = {};
  try {
    anchor = JSON.parse(await readFile(anchorFile, "utf8"));
  } catch {
    anchor = {};
  }
  const verdicts = Array.isArray(anchor.custody) ? (anchor.custody as unknown[]) : [];
  verdicts.push(verdict);
  const tmp = `${anchorFile}.tmp`;
  await rm(tmp, { force: true });
  await writeFile(tmp, `${JSON.stringify({ ...anchor, custody: verdicts }, null, 2)}\n`, { mode: 0o444 });
  await rename(tmp, anchorFile);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!sandbox || !existsSync(sandbox)) {
    console.error("usage: custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet]");
    process.exit(2);
  }
  const timeoutSec = opt("--timeout") ? Number(opt("--timeout")) : 4 * 3600;
  // The hard deadline: the soft one is checked between and inside reads, and
  // anything that still holds the process past it plus a grace period ends
  // it, so a stop is never held by custody.
  const hard = setTimeout(() => {
    console.error(`custody: CUSTODY INCOMPLETE: still running ${HARD_GRACE_SEC} s past its ${timeoutSec} s deadline; ended`);
    process.exit(3);
  }, (timeoutSec + HARD_GRACE_SEC) * 1000);
  hard.unref();
  takeCustody(sandbox, { timeoutSec, run: opt("--run"), progress: args.includes("--quiet") ? undefined : (line) => console.error(line) })
    .then((c) => {
      console.log(c.summary);
      process.exit(c.incomplete ? 3 : 0);
    })
    .catch((err) => {
      console.error(`custody: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    });
}
