/**
 * The host's own custody check, taken after a run, and the report lines a
 * microVM run adds. The check is the harness's word, not an agent's: it
 * re-reads every byte, and a change anywhere has to be named.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { keptOutputRefs, takeCustody } from "../scripts/custody.ts";
import {
  anchorGuarded,
  attributionLine,
  egressLine,
  evidenceArrival,
  herdrSocketLine,
  measuredGuardLine,
  vmRows,
  writeGuardLine,
} from "../scripts/report.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "custody-"));
  dirs.push(root);
  await mkdir(join(root, "inputs", "mail"), { recursive: true });
  await writeFile(join(root, "inputs", "notes.txt"), "notes\n");
  await writeFile(join(root, "inputs", "mail", "a.bin"), "attachment");
  await writeFile(join(root, "inputs.json"), JSON.stringify({
    source: "/evidence",
    copied_at: "2026-09-24T00:00:00Z",
    bytes: 16,
    enforce: "auto",
    guard: "microvm",
    held: "bind",
    files: [
      { path: "inputs/notes.txt", bytes: 6, sha256: sha("notes\n") },
      { path: "inputs/mail/a.bin", bytes: 10, sha256: sha("attachment") },
    ],
  }));
  await mkdir(join(root, ".pi-sessions", "a0"), { recursive: true });
  await writeFile(join(root, ".pi-sessions", "a0", "s.jsonl"), '{"type":"session"}\n');
  await mkdir(join(root, "tool-output", "a0"), { recursive: true });
  await writeFile(join(root, "tool-output", "a0", "x.out.log"), "whole output\n");
  await writeFile(join(root, "tool-output", "a0", "y.out.log"), "changed later\n");
  await mkdir(join(root, "traces"), { recursive: true });
  const lines = [
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, full_output: { path: "tool-output/a0/x.out.log", bytes: 13, lines: 1, sha256: sha("whole output\n") } } },
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, nested: [{ full_output: { path: "tool-output/a0/y.out.log", sha256: sha("as it was kept\n") } }] } },
    { ts: "t", agent: "a0", tool: "bash", args: {}, result: { ok: true, full_output: { path: "tool-output/a0/gone.log", sha256: sha("gone") } } },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return root;
}

test("every kept output the trace names is found, wherever in a line it sits", () => {
  const refs = keptOutputRefs({ a: { full_output: { path: "tool-output/a/1.log", sha256: "a".repeat(64) } }, b: [{ path: "tool-output/b/2.log", sha256: "b".repeat(64) }], c: { path: "work/x", sha256: "c".repeat(64) } });
  assert.deepEqual([...refs.keys()].sort(), ["tool-output/a/1.log", "tool-output/b/2.log"], "only the harness's kept outputs, not a work file");
});

test("custody names every kept output that is gone or no longer what the trace says", async () => {
  const root = await sandbox();
  const c = await takeCustody(root);
  assert.equal(c.inputs?.unchanged, true);
  assert.equal(c.inputs?.files, 2);
  assert.equal(c.sessions.files.length, 1);
  assert.equal(c.sessions.files[0].sha256, sha('{"type":"session"}\n'));
  assert.equal(c.tool_outputs.referenced, 3);
  assert.equal(c.tool_outputs.verified, 1);
  assert.deepEqual(c.tool_outputs.missing, ["tool-output/a0/gone.log"]);
  assert.deepEqual(c.tool_outputs.mismatched, ["tool-output/a0/y.out.log"]);
  assert.match(c.summary, /KEPT OUTPUTS: 1\/3 verified, 1 missing, 1 not matching the trace/);
  const onDisk = JSON.parse(await readFile(join(root, "custody.json"), "utf8"));
  assert.equal(onDisk.summary, c.summary, "the verdict is written where the report reads it");
});

test("custody re-hashes the evidence in full and says what changed, went missing or appeared", async () => {
  const root = await sandbox();
  await writeFile(join(root, "inputs", "notes.txt"), "notes, edited\n");
  await rm(join(root, "inputs", "mail", "a.bin"));
  await writeFile(join(root, "inputs", "planted.txt"), "new");
  const c = await takeCustody(root);
  assert.equal(c.inputs?.unchanged, false);
  assert.deepEqual(c.inputs?.changed, ["inputs/notes.txt"]);
  assert.deepEqual(c.inputs?.missing, ["inputs/mail/a.bin"]);
  assert.deepEqual(c.inputs?.added, ["inputs/planted.txt"]);
  assert.match(c.summary, /^EVIDENCE CHANGED: 1 changed, 1 missing, 1 added/);
});

test("custody checks a kept VM disk against its record, and counts lines the chain never took", async () => {
  const root = await sandbox();
  await mkdir(join(root, "vm"), { recursive: true });
  const snap = join(root, "a0.msb");
  await writeFile(snap, "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("disk bytes"), bytes: 10 } }));
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("other") } }));
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), '{"tool":"bash"}\n{"tool":"read"}\n');
  const c = await takeCustody(root);
  assert.deepEqual(c.vms?.map((v) => [v.agent, v.snapshot && "verified" in v.snapshot ? v.snapshot.verified : null]), [["a0", true], ["a1", false]]);
  assert.match(c.summary, /2 VMs, 1 snapshot verified/);
  assert.deepEqual(c.trace.spilled, [{ path: "tool-output/a0/trace-spill.jsonl", lines: 2 }]);
  assert.match(c.summary, /2 trace lines outside the chain/);
});

test("the report's custody lines know a microVM run", () => {
  assert.match(writeGuardLine("microvm"), /^enforced \(microVM/);
  assert.match(attributionLine("channel"), /^by channel/);
  assert.match(egressLine("microvm"), /^enforced \(microVM network policy/);
  assert.match(herdrSocketLine("unreachable"), /^out of reach/);
  assert.match(measuredGuardLine("microvm"), /probed at kickoff/);
  assert.equal(anchorGuarded("microvm", undefined), true, "the anchor is on the host, and the host is in no VM");
  assert.match(evidenceArrival({ source: "/ev", guard: "microvm", held: "bind" }), /mounted read-only/);
  assert.match(evidenceArrival({ source: "/ev", guard: "seatbelt", held: "bind" }), /linked to it/);
  assert.match(evidenceArrival({ source: "/ev", guard: "seatbelt" }), /^<p>Copied from/);
});

test("each agent's VM is a custody row: what it could write, reach and was given, and its disk", () => {
  const rows = vmRows([
    {
      agent: "a0",
      name: "dfs-r-a0",
      runtime: { name: "microsandbox", version: "0.7.2" },
      image: { ref: "ghcr.io/x/dfirswarm-memory@sha256:1", manifest_digest: "sha256:1" },
      cpus: 2,
      memory_mib: 2048,
      mounts: [{ host: "/r", guest: "/r", mode: "ro" }, { host: "/r/work", guest: "/r/work", mode: "rw" }, { host: "/r/work/quarantine", guest: "/r/work/quarantine", mode: "rw", noexec: true }],
      network: { default: "deny", allow_hosts: ["api.openai.com"], host_ports: [1234] },
      secrets: [{ name: "openai (API key)", hosts: ["api.openai.com"] }],
      snapshot: { path: "/r.vm-snapshots/a0.msb", sha256: "f".repeat(64) },
    },
  ]);
  assert.equal(rows[0][0], "Isolation");
  assert.match(rows[0][1], /microsandbox 0\.7\.2\), image ghcr\.io\/x\/dfirswarm-memory@sha256:1 \(sha256:1\)/);
  assert.equal(rows[1][0], "VM a0");
  assert.match(rows[1][1], /writable: \/r\/work, \/r\/work\/quarantine \(no-exec\)/);
  assert.match(rows[1][1], /could reach: api\.openai\.com:443, the host gateway :1234/);
  assert.match(rows[1][1], /openai \(API key\) → api\.openai\.com/);
  assert.match(rows[1][1], new RegExp(`kept, sha256 ${"f".repeat(64)}`));
  assert.deepEqual(vmRows([]), [], "a host run adds nothing");
});
