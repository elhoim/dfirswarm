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
 * Custody reads what agents wrote, so it trusts none of it: every path it
 * takes from a trace line or a VM record is resolved and must be a regular
 * file under the run (or the snapshot directory), a file over the cap is
 * noted rather than read, and the whole check has a deadline, past which
 * `custody.json` says what was not finished instead of the stop hanging.
 *
 * Writes `custody.json` at the sandbox root and prints its summary line.
 *
 *   node --experimental-strip-types scripts/custody.ts <sandbox> [--timeout SEC] [--run ID]
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { lstat, readdir, readFile, readlink, realpath, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { readInputsManifest, verifyEventChain, verifyLedgerChain } from "../extensions/protocol.ts";

export const CUSTODY_REL = "custody.json";
/** A file past this is noted, not read: custody is a check, not a way to hang a stop. */
export const MAX_HASHED_BYTES = 8 * 1024 * 1024 * 1024;
/** The kickoff's own record of what the run started with, outside the run. */
export function custodyAnchorPath(sandbox: string): string {
  return `${resolve(sandbox)}.custody-anchor.json`;
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

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
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

/** Files under a directory, never through a link. */
async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) out.push(...(await walk(abs)));
    else if (entry.isFile()) out.push(abs);
  }
  return out.sort();
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
    if (entry.isSymbolicLink()) out.push(abs);
    else if (entry.isDirectory()) out.push(...(await walkEvidence(abs)));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

export type Custody = {
  at: string;
  run: string | null;
  inputs:
    | null
    | { unverifiable: string }
    | { files: number; bytes: number; unchanged: boolean; changed: string[]; missing: string[]; added: string[]; skipped: string[]; manifest_sha256: string; manifest_anchored: boolean | null };
  sessions: { files: Array<{ path: string; bytes: number; sha256: string | null }>; digest: string };
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[]; refused: string[] };
  trace: { lines: number; intact: boolean; detail: string; unverified: number; disputed: number; spilled: Array<{ path: string; lines: number; agent: string | null; bad: number }> };
  ledger: { entries: number; intact: boolean; detail: string } | null;
  vms:
    | null
    | Array<{
        agent: string;
        image: string | null;
        stopped: boolean;
        kept: string | null;
        snapshot: null | { path: string; sha256: string; verified: boolean; msb_verified: boolean | null } | { error: string };
        logs: Array<{ path: string; sha256: string }>;
      }>;
  incomplete: string | null;
  summary: string;
};

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

function msbSnapshotVerify(file: string): Promise<boolean | null> {
  const msb = process.env.MSB_BIN || join(dirname(new URL(import.meta.url).pathname), "..", "node_modules", ".bin", "msb");
  return new Promise((done) => {
    execFile(msb, ["snapshot", "verify", file], { timeout: 10 * 60_000 }, (err) => done(err ? false : true));
  }).catch(() => null) as Promise<boolean | null>;
}

export async function takeCustody(sandboxInput: string, options: { timeoutSec?: number; run?: string } = {}): Promise<Custody> {
  const sandbox = resolve(sandboxInput);
  const deadline = new Deadline(options.timeoutSec ?? 4 * 3600);
  let incomplete: string | null = null;
  const tooLate = (what: string) => {
    if (deadline.over && !incomplete) incomplete = `the deadline passed during ${what}`;
    return deadline.over;
  };
  let anchor: { inputs_manifest_sha256?: string; run?: string } | null = null;
  try {
    anchor = JSON.parse(await readFile(custodyAnchorPath(sandbox), "utf8"));
  } catch {
    anchor = null;
  }
  const run = options.run ?? anchor?.run ?? null;

  // --- the evidence ---------------------------------------------------------
  let inputs: Custody["inputs"] = null;
  const manifestPath = join(sandbox, "inputs.json");
  const manifest = await readInputsManifest(sandbox).catch(() => null);
  if (!manifest && (existsSync(join(sandbox, "inputs")) || existsSync(join(sandbox, "inputs.device")))) {
    inputs = { unverifiable: "the run has evidence but no readable inputs.json to compare it with" };
  } else if (manifest) {
    const manifestBytes = await readFile(manifestPath).catch(() => Buffer.alloc(0));
    const manifestSha = createHash("sha256").update(manifestBytes).digest("hex");
    const anchored = anchor?.inputs_manifest_sha256 ? anchor.inputs_manifest_sha256 === manifestSha : null;
    const changed: string[] = [];
    const missing: string[] = [];
    const skipped: string[] = [];
    const listed = new Set(manifest.files.map((f) => f.path));
    const evidenceRoot = await realpath(join(sandbox, "inputs")).catch(() => join(sandbox, "inputs"));
    for (const file of manifest.files) {
      if (tooLate("the evidence re-hash")) break;
      const abs = join(evidenceRoot, file.path.replace(/^inputs\//, ""));
      if (typeof file.link === "string") {
        // A link is checked as a link: its target, never followed.
        const target = await readlinkSafe(abs);
        if (target === null) missing.push(file.path);
        else if (target !== file.link) changed.push(file.path);
        continue;
      }
      const lst = await lstat(abs).catch(() => null);
      if (lst?.isSymbolicLink()) {
        changed.push(file.path);
        continue;
      }
      const st = await stat(abs).catch(() => null);
      if (!st || !st.isFile()) {
        missing.push(file.path);
        continue;
      }
      if (st.size > MAX_HASHED_BYTES) {
        skipped.push(file.path);
        continue;
      }
      if (st.size !== file.bytes && typeof file.bytes === "number") {
        changed.push(file.path);
        continue;
      }
      if ((await sha256File(abs)) !== file.sha256) changed.push(file.path);
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
      unchanged: !changed.length && !missing.length && !added.length && anchored !== false,
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
  for (const abs of await walk(join(sandbox, ".pi-sessions"))) {
    if (tooLate("the session seal")) break;
    const size = (await stat(abs)).size;
    sessionFiles.push({ path: relative(sandbox, abs), bytes: size, sha256: size > MAX_HASHED_BYTES ? null : await sha256File(abs) });
  }
  const sessionsDigest = createHash("sha256").update(sessionFiles.map((f) => `${f.sha256 ?? "unhashed"}  ${f.path}`).join("\n")).digest("hex");

  // --- the trace and the kept outputs -----------------------------------------
  const traceText = await readFile(join(sandbox, "traces", "events.jsonl"), "utf8").catch(() => "");
  const refs = new Map<string, string>();
  let lines = 0;
  let unverified = 0;
  let disputed = 0;
  for (const line of traceText.split("\n")) {
    if (!line.trim()) continue;
    lines += 1;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      keptOutputRefs(parsed, refs);
      if (parsed.agent_unverified === true) unverified += 1;
      if (parsed.agent_disputed === true || parsed.agent_claimed) disputed += 1;
    } catch {
      // a line that does not parse is the chain check's business
    }
  }
  // Lines the collector never took, kept rather than lost: the shared spill
  // on the host, each agent's own in a VM run, and the hub's own.
  const spills: Custody["trace"]["spilled"] = [];
  const spillPaths = ["work/.trace-spill.jsonl", "traces/hub-spill.jsonl", ...(await readdir(join(sandbox, "tool-output")).catch(() => [])).map((a) => `tool-output/${a}/trace-spill.jsonl`)];
  for (const rel of spillPaths) {
    const text = await readFile(join(sandbox, rel), "utf8").catch(() => "");
    const lines = text.split("\n").filter((l) => l.trim());
    if (!lines.length) continue;
    const owner = rel.match(/^tool-output\/([^/]+)\//)?.[1] ?? (rel.startsWith("traces/hub-") ? "system" : null);
    let bad = 0;
    for (const l of lines) {
      try {
        const parsed = JSON.parse(l) as Record<string, unknown>;
        // A spilled line says whose it is; the directory it sits in says whose it can be.
        if (owner && owner !== "system" && parsed.agent !== owner) bad += 1;
      } catch {
        bad += 1;
      }
    }
    spills.push({ path: rel, lines: lines.length, agent: owner, bad });
  }
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
    if (where.size > MAX_HASHED_BYTES) {
      refused.push(`${path} (over the size cap)`);
      continue;
    }
    if ((await sha256File(where.abs)) !== sha) mismatched.push(path);
    else verified += 1;
  }
  let traceAnchor = null;
  try {
    traceAnchor = JSON.parse(await readFile(`${sandbox}.trace-anchor.json`, "utf8"));
  } catch {
    traceAnchor = null;
  }
  const chain = verifyEventChain(traceText, traceAnchor);
  const chained = chain.ok && chain.chained > 0;
  const chainDetail = !lines
    ? "no trace"
    : chain.ok
      ? chain.chained > 0
        ? `chain intact, ${chain.chained} of ${chain.total} lines chained${traceAnchor ? ", anchor matches" : ", no anchor"}`
        : "unchained: no collector wrote this trace"
      : `chain broken at line ${chain.broken_at ?? "?"} (${chain.reason ?? "unknown"})`;

  // --- the ledger --------------------------------------------------------------
  let ledger: Custody["ledger"] = null;
  const ledgerText = await readFile(join(sandbox, "ledger", "entries.jsonl"), "utf8").catch(() => "");
  if (ledgerText.trim()) {
    const v = verifyLedgerChain(ledgerText);
    ledger = { entries: v.total, intact: v.ok, detail: v.ok ? `${v.chained} of ${v.total} entries chained` : `broken at entry ${v.broken_at ?? "?"} (${v.reason ?? "unknown"})` };
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
      try {
        rec = JSON.parse(await readFile(join(vmDir, name), "utf8"));
      } catch {
        continue;
      }
      if (run && rec.run && rec.run !== run) continue; // another run's record in a reused sandbox
      const image = ((rec.image as Record<string, unknown> | undefined)?.manifest_digest as string | null) ?? null;
      const snap = rec.snapshot as { path?: string; sha256?: string; error?: string } | undefined;
      let snapshot: NonNullable<Custody["vms"]>[number]["snapshot"] = null;
      if (snap?.error) snapshot = { error: snap.error };
      else if (snap?.path && snap.sha256) {
        // Only a file in the run's own snapshot directory, and only a regular one.
        const real = await realpath(snap.path).catch(() => null);
        const reg = real ? await regular(real) : { why: "missing" };
        const inPlace = !!real && !!snapRoot && real.startsWith(`${snapRoot}/`) && basename(real).endsWith(".msb");
        const ok = inPlace && !("why" in reg) && reg.size <= MAX_HASHED_BYTES && (await sha256File(real as string)) === snap.sha256;
        const msbOk = ok ? await msbSnapshotVerify(real as string) : null;
        snapshot = { path: snap.path, sha256: snap.sha256, verified: ok, msb_verified: msbOk };
      }
      const logs: Array<{ path: string; sha256: string }> = [];
      const logDir = typeof rec.logs === "string" ? await realpath(rec.logs).catch(() => null) : null;
      if (logDir && snapRoot && logDir.startsWith(`${snapRoot}/`)) {
        for (const abs of await walk(logDir)) logs.push({ path: relative(dirname(snapRoot), abs), sha256: (await stat(abs)).size > MAX_HASHED_BYTES ? "unhashed" : await sha256File(abs) });
      }
      vms.push({
        agent: String(rec.agent ?? name.replace(/\.json$/, "")),
        image,
        stopped: typeof rec.stopped_at === "string",
        kept: typeof rec.kept === "string" ? rec.kept : null,
        snapshot,
        logs,
      });
    }
  }

  // --- the summary -------------------------------------------------------------
  const parts: string[] = [];
  if (inputs && "unverifiable" in inputs) parts.push(`EVIDENCE UNVERIFIABLE: ${inputs.unverifiable}`);
  else if (inputs) {
    parts.push(inputs.unchanged
      ? `evidence unchanged (${inputs.files} file${inputs.files === 1 ? "" : "s"} re-hashed${inputs.manifest_anchored === true ? ", manifest anchored" : inputs.manifest_anchored === null ? ", manifest not anchored" : ""}${inputs.skipped.length ? `, ${inputs.skipped.length} over the size cap not re-read` : ""})`
      : `EVIDENCE CHANGED: ${inputs.changed.length} changed, ${inputs.missing.length} missing, ${inputs.added.length} added${inputs.manifest_anchored === false ? ", MANIFEST REWRITTEN" : ""}`);
  }
  parts.push(`${sessionFiles.length} session file${sessionFiles.length === 1 ? "" : "s"} sealed`);
  parts.push(missingOut.length || mismatched.length || refused.length
    ? `KEPT OUTPUTS: ${verified}/${refs.size} verified, ${missingOut.length} missing, ${mismatched.length} not matching the trace, ${refused.length} refused`
    : `${verified}/${refs.size} kept outputs verified`);
  if (!lines) parts.push("NO TRACE");
  else if (chained) parts.push(`trace ${lines} lines, chain intact${unverified ? `, ${unverified} unverified` : ""}${disputed ? `, ${disputed} disputed` : ""}`);
  else if (chain.ok) parts.push(`TRACE UNCHAINED (${lines} lines)`);
  else parts.push("TRACE CHAIN BROKEN");
  const spilled = spills.reduce((n, s) => n + s.lines, 0);
  const badSpill = spills.reduce((n, s) => n + s.bad, 0);
  if (spilled) parts.push(`${spilled} trace line${spilled === 1 ? "" : "s"} outside the chain (spilled: ${spills.map((s) => s.path).join(", ")})${badSpill ? `, ${badSpill} NOT ATTRIBUTABLE` : ""}`);
  if (ledger) parts.push(ledger.intact ? `ledger ${ledger.entries} entries, chain intact` : "LEDGER CHAIN BROKEN");
  if (vms) {
    const kept = vms.filter((v) => v.snapshot && "verified" in v.snapshot && v.snapshot.verified).length;
    const failed = vms.filter((v) => (v.snapshot && "error" in v.snapshot) || v.kept || !v.stopped);
    parts.push(`${vms.length} VM${vms.length === 1 ? "" : "s"}, ${kept} of ${vms.length} snapshots verified${failed.length ? `, ${failed.length} NOT PUT AWAY (${failed.map((v) => v.agent).join(", ")})` : ""}`);
  }
  if (incomplete) parts.push(`CUSTODY INCOMPLETE: ${incomplete}`);

  const custody: Custody = {
    at: new Date().toISOString(),
    run,
    inputs,
    sessions: { files: sessionFiles, digest: sessionsDigest },
    tool_outputs: { referenced: refs.size, verified, missing: missingOut, mismatched, refused },
    trace: { lines, intact: chained, detail: chainDetail, unverified, disputed, spilled: spills },
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
  await writeFile(file, `${JSON.stringify(custody, null, 2)}\n`);
  return custody;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!sandbox || !existsSync(sandbox)) {
    console.error("usage: custody.ts <sandbox> [--timeout SEC] [--run ID]");
    process.exit(2);
  }
  takeCustody(sandbox, { timeoutSec: opt("--timeout") ? Number(opt("--timeout")) : undefined, run: opt("--run") })
    .then((c) => {
      console.log(c.summary);
      process.exit(c.incomplete ? 3 : 0);
    })
    .catch((err) => {
      console.error(`custody: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    });
}
