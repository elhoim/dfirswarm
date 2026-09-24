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
import { confinedOutput, custodyAnchorPath, keptOutputRefs, secretViolations, takeCustody, type Custody } from "../scripts/custody.ts";
import { ledgerHash, type LedgerEntry } from "../extensions/protocol.ts";
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
/** The evidence part of a verdict, for a run whose manifest was readable. */
const evidence = (c: Custody) => c.inputs as Exclude<Custody["inputs"], null | { unverifiable: string }>;

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
  assert.equal(evidence(c).unchanged, true);
  assert.equal(evidence(c).files, 2);
  assert.equal(evidence(c).manifest_anchored, null, "no anchor: said, not assumed");
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
  assert.equal(evidence(c).unchanged, false);
  assert.deepEqual(evidence(c).changed, ["inputs/notes.txt"]);
  assert.deepEqual(evidence(c).missing, ["inputs/mail/a.bin"]);
  assert.deepEqual(evidence(c).added, ["inputs/planted.txt"]);
  assert.match(c.summary, /^EVIDENCE CHANGED: 1 changed, 1 missing, 1 added/);
});

test("the manifest is checked against the kickoff's anchor outside the run: a rewritten manifest is caught, a missing one is said", async () => {
  const root = await sandbox();
  const manifest = await readFile(join(root, "inputs.json"));
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: "t1", inputs_manifest_sha256: createHash("sha256").update(manifest).digest("hex") }));
  let c = await takeCustody(root);
  assert.equal(evidence(c).manifest_anchored, true);
  assert.match(c.summary, /manifest anchored/);
  assert.equal(c.run, "t1", "the run id comes from the anchor");
  // An agent that could write the manifest could make custody compare
  // against its own list; the anchor says which list the kickoff wrote.
  const forged = JSON.parse(manifest.toString()) as { files: Array<{ path: string; sha256: string }> };
  await writeFile(join(root, "inputs", "notes.txt"), "notes, edited\n");
  forged.files[0].sha256 = sha("notes, edited\n");
  await writeFile(join(root, "inputs.json"), JSON.stringify(forged));
  c = await takeCustody(root);
  assert.equal(evidence(c).manifest_anchored, false);
  assert.equal(evidence(c).unchanged, false, "a rewritten manifest is not an unchanged evidence set");
  assert.match(c.summary, /MANIFEST REWRITTEN/);
  await rm(join(root, "inputs.json"));
  c = await takeCustody(root);
  assert.ok(c.inputs && "unverifiable" in c.inputs, "evidence with no manifest is unverifiable, not unchanged");
  assert.match(c.summary, /EVIDENCE UNVERIFIABLE/);
});

test("custody takes no path an agent wrote at face value: a kept-output reference is a regular file under tool-output/ or it is refused", async () => {
  const root = await sandbox();
  for (const bad of ["tool-output/../../etc/passwd", "tool-output/a0/../../inputs.json", "tool-output/a0", "work/x.log"]) {
    const where = await confinedOutput(root, bad);
    assert.ok("why" in where, `${bad} is refused`);
  }
  const { symlink, mkdir: mk } = await import("node:fs/promises");
  await symlink("/etc/hosts", join(root, "tool-output", "a0", "link.log"));
  await mk(join(root, "tool-output", "a0", "dir.log"));
  assert.deepEqual(await confinedOutput(root, "tool-output/a0/link.log"), { why: "a link" });
  assert.deepEqual(await confinedOutput(root, "tool-output/a0/dir.log"), { why: "not a regular file" });
  const ok = await confinedOutput(root, "tool-output/a0/x.out.log");
  assert.ok("abs" in ok && ok.size === 13);
  // A trace line that names a link is a refusal in the verdict, and the stop goes on.
  await writeFile(join(root, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: { full_output: { path: "tool-output/a0/link.log", sha256: "0".repeat(64) } } })}\n`);
  const c = await takeCustody(root, { timeoutSec: 60 });
  assert.deepEqual(c.tool_outputs.refused, ["tool-output/a0/link.log (a link)"]);
  assert.match(c.summary, /1 refused/);
});

test("custody has a deadline: past it the verdict says what was not finished instead of the stop hanging", async () => {
  const root = await sandbox();
  const c = await takeCustody(root, { timeoutSec: 0 });
  assert.ok(c.incomplete, "the deadline is on the record");
  assert.match(c.summary, /CUSTODY INCOMPLETE/);
});

test("the ledger's chain is verified: an entry rewritten after the fact breaks it", async () => {
  const root = await sandbox();
  await mkdir(join(root, "ledger"), { recursive: true });
  const e1: LedgerEntry = { seq: 1, kind: "event", ts: "2026-01-01T00:00:00Z", value: "first", source: "s", evidence: "e", by: "a0", authors: ["a0"], at: "2026-09-24T00:00:00Z" };
  e1.prev = "genesis";
  e1.hash = ledgerHash(e1, e1.prev);
  const e2: LedgerEntry = { seq: 2, kind: "finding", value: "second", source: "s", evidence: "e", by: "a1", authors: ["a1"], at: "2026-09-24T00:00:01Z" };
  e2.prev = e1.hash;
  e2.hash = ledgerHash(e2, e2.prev);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n`);
  let c = await takeCustody(root);
  assert.equal(c.ledger?.intact, true);
  assert.match(c.summary, /ledger 2 entries, chain intact/);
  await writeFile(join(root, "ledger", "entries.jsonl"), `${JSON.stringify({ ...e1, value: "first, reworded" })}\n${JSON.stringify(e2)}\n`);
  c = await takeCustody(root);
  assert.equal(c.ledger?.intact, false);
  assert.match(c.summary, /LEDGER CHAIN BROKEN/);
});

test("custody checks a kept VM disk against its record, and counts lines the chain never took", async () => {
  const root = await sandbox();
  await mkdir(join(root, "vm"), { recursive: true });
  await mkdir(`${root}.vm-snapshots`, { recursive: true });
  dirs.push(`${root}.vm-snapshots`);
  const snap = join(`${root}.vm-snapshots`, "a0.msb");
  await writeFile(snap, "disk bytes");
  await writeFile(join(root, "vm", "a0.json"), JSON.stringify({ agent: "a0", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("disk bytes"), bytes: 10 } }));
  await writeFile(join(root, "vm", "a1.json"), JSON.stringify({ agent: "a1", image: { manifest_digest: "sha256:abc" }, snapshot: { path: snap, sha256: sha("other") } }));
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), '{"tool":"bash"}\n{"tool":"read"}\n');
  const c = await takeCustody(root);
  assert.deepEqual(c.vms?.map((v) => [v.agent, v.snapshot && "verified" in v.snapshot ? v.snapshot.verified : null]), [["a0", true], ["a1", false]]);
  assert.match(c.summary, /2 VMs, 1 of 2 snapshots verified, 2 NOT PUT AWAY/, "a VM never recorded as stopped is named");
  assert.deepEqual(c.trace.spilled, [{ path: "tool-output/a0/trace-spill.jsonl", lines: 2, agent: "a0", bad: 2, duplicates: 0 }], "spilled lines that do not say whose they are cannot be attributed");
  assert.match(c.summary, /2 trace lines outside the chain .* 2 NOT ATTRIBUTABLE/);
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), '{"tool":"bash","agent":"a0"}\n{"tool":"read","agent":"a1"}\n');
  const again = await takeCustody(root);
  assert.equal(again.trace.spilled[0].bad, 1, "a line in a0's spill that claims to be a1's is not attributable");
});

test("the report's custody lines know a microVM run", () => {
  assert.match(writeGuardLine("microvm"), /^enforced \(microVM/);
  assert.match(attributionLine("channel"), /^by channel/);
  assert.match(egressLine("microvm"), /^enforced \(microVM network policy/);
  assert.match(egressLine("microvm-open"), /^OPEN \(--no-netguard/, "a VM run with the network open says so, not \"none\"");
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

test("numbered trace lines: a line in both the chain and a spill is counted once as a duplicate, and a missing number is a lost line", async () => {
  const root = await sandbox();
  const chainLines = [1, 2, 4].map((seq) => ({ ts: "t", agent: "a0", tool: "bash", args: {}, result: {}, sid: "abc", seq }));
  await writeFile(join(root, "traces", "events.jsonl"), chainLines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  await writeFile(join(root, "tool-output", "a0", "trace-spill.jsonl"), [2, 5].map((seq) => JSON.stringify({ ts: "t", agent: "a0", tool: "read", args: {}, result: {}, sid: "abc", seq })).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.equal(c.trace.spilled[0].duplicates, 1, "seq 2 reached the chain and the spill");
  assert.deepEqual(c.trace.gaps, [{ sid: "abc", agent: "a0", missing: 1 }], "seq 3 reached neither");
  assert.match(c.summary, /1 also in the chain/);
  assert.match(c.summary, /1 TRACE LINE LOST/);
});

test("a line whose own clock is far from the collector's is named, with how far", async () => {
  const root = await sandbox();
  const lines = [
    { ts: "2026-09-24T10:00:00.000Z", recv_ts: "2026-09-24T10:00:01.000Z", agent: "a0", tool: "bash", args: {}, result: {} },
    { ts: "2026-09-24T10:10:00.000Z", recv_ts: "2026-09-24T10:00:02.000Z", agent: "a1", tool: "bash", args: {}, result: {} },
    { ts: "2026-09-24T09:50:00.000Z", recv_ts: "2026-09-24T10:00:03.000Z", agent: "a1", tool: "read", args: {}, result: {} },
  ];
  await writeFile(join(root, "traces", "events.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  const c = await takeCustody(root);
  assert.deepEqual(c.trace.clock, [{ agent: "a1", lines: 2, max_skew_s: -603 }], "a0's one-second gap is not named; a1's ten minutes both ways are");
  assert.match(c.summary, /a1 2 lines \(up to -603 s\)/);
});

test("a placeholder msb stopped on its way to another host is read from the VM's runtime log", () => {
  const log = [
    "2026-09-24T07:03:09.080700Z  INFO microsandbox_runtime::runner::vm: sandbox starting sandbox=dfs-x",
    "2026-09-24T07:03:10.051819Z  WARN microsandbox_network::engine::secrets::handler: secret violation: placeholder detected for disallowed host action=block-and-log secret_env_var=K placeholder=dfirswarm-secret-probe-abc protocol=http/1.1 sni=api.openai.com host=api.openai.com method=GET path=/v1/models location=header match_form=raw guest_dst=172.66.0.243:443 http2_stream_id=",
  ].join("\n");
  assert.deepEqual(secretViolations(log), [{ at: "2026-09-24T07:03:10.051819Z", env: "K", host: "api.openai.com", method: "GET", path: "/v1/models", action: "block-and-log" }]);
  assert.deepEqual(secretViolations("nothing here\n"), []);
});
