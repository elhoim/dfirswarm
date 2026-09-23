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
 *     missing, changed or added is named;
 *   - the sessions: every file under .pi-sessions/, with its sha256 — the
 *     agents' own transcripts, sealed as they were left;
 *   - the kept outputs: every whole tool output the trace points to
 *     (`tool-output/…` with a sha256), re-hashed; a file that is gone or no
 *     longer matches what the trace says was kept is named;
 *   - the VMs: for a microVM run, each VM's image digest and, when its disk
 *     was kept, the snapshot's sha256 re-hashed against its record.
 *
 * Writes `custody.json` at the sandbox root and prints its summary line.
 *
 *   node --experimental-strip-types scripts/custody.ts <sandbox>
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { readInputsManifest, verifyEventChain } from "../extensions/protocol.ts";

export const CUSTODY_REL = "custody.json";

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(abs)));
    else if (entry.isFile()) out.push(abs);
  }
  return out.sort();
}

export type Custody = {
  at: string;
  inputs: null | { files: number; bytes: number; unchanged: boolean; changed: string[]; missing: string[]; added: string[] };
  sessions: { files: Array<{ path: string; bytes: number; sha256: string }>; digest: string };
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[] };
  trace: { lines: number; intact: boolean; detail: string; spilled: Array<{ path: string; lines: number }> };
  vms: null | Array<{ agent: string; image: string | null; snapshot: null | { path: string; sha256: string; verified: boolean } | { error: string } }>;
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

export async function takeCustody(sandboxInput: string): Promise<Custody> {
  const sandbox = resolve(sandboxInput);

  let inputs: Custody["inputs"] = null;
  const manifest = await readInputsManifest(sandbox).catch(() => null);
  if (manifest) {
    const changed: string[] = [];
    const missing: string[] = [];
    const listed = new Set(manifest.files.map((f) => f.path));
    for (const file of manifest.files) {
      const abs = join(sandbox, file.path);
      if (!existsSync(abs)) {
        missing.push(file.path);
        continue;
      }
      if ((await sha256File(abs)) !== file.sha256) changed.push(file.path);
    }
    const added: string[] = [];
    const root = join(sandbox, "inputs");
    const real = await stat(root).then(() => root).catch(() => "");
    if (real) {
      for (const abs of await walkFollow(root)) {
        const key = relative(sandbox, abs).split("\\").join("/");
        if (!listed.has(key)) added.push(key);
      }
    }
    inputs = {
      files: manifest.files.length,
      bytes: manifest.bytes ?? manifest.files.reduce((n, f) => n + (f.bytes ?? 0), 0),
      unchanged: !changed.length && !missing.length && !added.length,
      changed,
      missing,
      added,
    };
  }

  const sessionFiles: Custody["sessions"]["files"] = [];
  for (const abs of await walk(join(sandbox, ".pi-sessions"))) {
    sessionFiles.push({ path: relative(sandbox, abs), bytes: (await stat(abs)).size, sha256: await sha256File(abs) });
  }
  const sessionsDigest = createHash("sha256").update(sessionFiles.map((f) => `${f.sha256}  ${f.path}`).join("\n")).digest("hex");

  const traceText = await readFile(join(sandbox, "traces", "events.jsonl"), "utf8").catch(() => "");
  const refs = new Map<string, string>();
  let lines = 0;
  for (const line of traceText.split("\n")) {
    if (!line.trim()) continue;
    lines += 1;
    try {
      keptOutputRefs(JSON.parse(line), refs);
    } catch {
      // a line that does not parse is the chain check's business
    }
  }
  // Lines the collector never took, kept rather than lost: the shared spill
  // on the host, each agent's own in a VM run.
  const spills: Array<{ path: string; lines: number }> = [];
  for (const rel of ["work/.trace-spill.jsonl", ...(await readdir(join(sandbox, "tool-output")).catch(() => [])).map((a) => `tool-output/${a}/trace-spill.jsonl`)]) {
    const text = await readFile(join(sandbox, rel), "utf8").catch(() => "");
    const n = text.split("\n").filter((l) => l.trim()).length;
    if (n) spills.push({ path: rel, lines: n });
  }
  const missingOut: string[] = [];
  const mismatched: string[] = [];
  let verified = 0;
  for (const [path, sha] of refs) {
    const abs = join(sandbox, path);
    if (!existsSync(abs)) missingOut.push(path);
    else if ((await sha256File(abs)) !== sha) mismatched.push(path);
    else verified += 1;
  }
  let anchor = null;
  try {
    anchor = JSON.parse(await readFile(`${sandbox}.trace-anchor.json`, "utf8"));
  } catch {
    anchor = null;
  }
  const chain = verifyEventChain(traceText, anchor);
  const chainOk = chain.ok;
  const chainDetail = chain.ok
    ? `chain intact, ${chain.chained} of ${chain.total} lines chained${anchor ? ", anchor matches" : ""}`
    : `chain broken at line ${chain.broken_at ?? "?"} (${chain.reason ?? "unknown"})`;

  let vms: Custody["vms"] = null;
  const vmDir = join(sandbox, "vm");
  if (existsSync(vmDir)) {
    vms = [];
    for (const name of (await readdir(vmDir)).filter((n) => n.endsWith(".json")).sort()) {
      let rec: Record<string, unknown>;
      try {
        rec = JSON.parse(await readFile(join(vmDir, name), "utf8"));
      } catch {
        continue;
      }
      const image = ((rec.image as Record<string, unknown> | undefined)?.manifest_digest as string | null) ?? null;
      const snap = rec.snapshot as { path?: string; sha256?: string; error?: string } | undefined;
      let snapshot: NonNullable<Custody["vms"]>[number]["snapshot"] = null;
      if (snap?.error) snapshot = { error: snap.error };
      else if (snap?.path && snap.sha256) {
        const ok = existsSync(snap.path) && (await sha256File(snap.path)) === snap.sha256;
        snapshot = { path: snap.path, sha256: snap.sha256, verified: ok };
      }
      vms.push({ agent: String(rec.agent ?? name.replace(/\.json$/, "")), image, snapshot });
    }
  }

  const parts: string[] = [];
  if (inputs) {
    parts.push(inputs.unchanged
      ? `evidence unchanged (${inputs.files} file${inputs.files === 1 ? "" : "s"} re-hashed)`
      : `EVIDENCE CHANGED: ${inputs.changed.length} changed, ${inputs.missing.length} missing, ${inputs.added.length} added`);
  }
  parts.push(`${sessionFiles.length} session file${sessionFiles.length === 1 ? "" : "s"} sealed`);
  parts.push(missingOut.length || mismatched.length
    ? `KEPT OUTPUTS: ${verified}/${refs.size} verified, ${missingOut.length} missing, ${mismatched.length} not matching the trace`
    : `${verified}/${refs.size} kept outputs verified`);
  parts.push(chainOk ? `trace ${lines} lines, chain intact` : "TRACE CHAIN BROKEN");
  const spilled = spills.reduce((n, s) => n + s.lines, 0);
  if (spilled) parts.push(`${spilled} trace line${spilled === 1 ? "" : "s"} outside the chain (spilled: ${spills.map((s) => s.path).join(", ")})`);
  if (vms) {
    const kept = vms.filter((v) => v.snapshot && "verified" in v.snapshot && v.snapshot.verified).length;
    parts.push(`${vms.length} VM${vms.length === 1 ? "" : "s"}, ${kept} snapshot${kept === 1 ? "" : "s"} verified`);
  }

  const custody: Custody = {
    at: new Date().toISOString(),
    inputs,
    sessions: { files: sessionFiles, digest: sessionsDigest },
    tool_outputs: { referenced: refs.size, verified, missing: missingOut, mismatched },
    trace: { lines, intact: chainOk, detail: chainDetail, spilled: spills },
    vms,
    summary: parts.join(" · "),
  };
  await writeFile(join(sandbox, CUSTODY_REL), `${JSON.stringify(custody, null, 2)}\n`);
  return custody;
}

/** Files under a directory, following a top-level link the way the manifest's walk does. */
async function walkFollow(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    const st = await stat(abs).catch(() => null);
    if (!st) continue;
    if (st.isDirectory()) out.push(...(await walkFollow(abs)));
    else if (st.isFile()) out.push(abs);
  }
  return out;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const sandbox = process.argv[2];
  if (!sandbox || !existsSync(sandbox)) {
    console.error("usage: custody.ts <sandbox>");
    process.exit(2);
  }
  takeCustody(sandbox)
    .then((c) => console.log(c.summary))
    .catch((err) => {
      console.error(`custody: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    });
}
