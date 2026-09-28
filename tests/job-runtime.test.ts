/**
 * The runtime (Plan 3, WP4; docs/adr/0015): a running job seen from the
 * host by three signals, metadata only (B11: quiet healthy work, a busy
 * loop, missing telemetry, concurrent writes, a bounded walk that follows
 * no link and sanitises names); the regroup that nudges a running job's
 * holder before it asks everyone (B12); a program missing in a job's image
 * (B17); the seats' tokens renewed on the host with msb's live secret
 * rotation, only where it is live (B10).
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import * as L from "../extensions/leads.ts";
import * as T from "../scripts/job-telemetry.ts";
import { JobService, programMissing } from "../scripts/job-service.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { regroup } from "../scripts/leads-cli.ts";
import { renewSeatSecrets, validityMs, type ResolvedSecret, type VmSpec } from "../scripts/vm.ts";
import { localWorker } from "./job-service-worker.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const sample = (at: number, o: { files?: number; bytes?: number; newest?: number; out?: number; err?: number; cpu?: number | null; io?: number }): T.TelemetrySample => ({
  at,
  out: { files: o.files ?? 1, bytes: o.bytes ?? 10, newest_ms: o.newest ?? 1000, newest: "a.bin", bounded: false },
  stdout: { bytes: o.out ?? 0, mtime_ms: null },
  stderr: { bytes: o.err ?? 0, mtime_ms: null },
  cpu: o.cpu === null ? null : { source: "heartbeat", cpu: o.cpu ?? 100, io: o.io ?? 5, at },
});

test("B11: the three signals decide: moving, quiet (a busy loop or a silent pass), a suspected stall only when all are still and the timeout is not near, unknown without CPU and I/O", () => {
  const t0 = Date.parse("2026-09-28T10:00:00Z");
  const min = 60_000;
  const started = new Date(t0).toISOString();
  const at = (m: number) => t0 + m * min;
  // Output growing: moving.
  let p = T.assessJob([sample(at(0), { bytes: 10 }), sample(at(20), { bytes: 20 })], { started_at: started, timeout_seconds: 3600, now: at(20) });
  assert.equal(p.state, "moving");
  // A busy loop: nothing written for 20 min, the CPU moves: quiet, never a stall.
  p = T.assessJob([sample(at(0), { cpu: 1 }), sample(at(10), { cpu: 500 }), sample(at(20), { cpu: 900 })], { started_at: started, timeout_seconds: 3600, now: at(20) });
  assert.equal(p.state, "quiet");
  assert.match(p.why, /working without writing yet/);
  // All three still past the window, far from its timeout: suspected stall.
  p = T.assessJob([sample(at(0), {}), sample(at(5), {}), sample(at(15), {})], { started_at: started, timeout_seconds: 3600, now: at(15) });
  assert.equal(p.state, "suspected_stall");
  assert.match(p.why, /all been still for 15 min/);
  assert.equal(p.sealed, false);
  assert.match(p.hint, /not sealed and not citable.*keeps what it wrote; nothing is cancelled for you/);
  // Near its timeout: it ends by itself.
  p = T.assessJob([sample(at(0), {}), sample(at(15), {})], { started_at: started, timeout_seconds: 16 * 60, now: at(15) });
  assert.equal(p.state, "quiet");
  assert.match(p.why, /its timeout is \d+ s away/);
  // No CPU or I/O telemetry: unknown, whatever else is still.
  p = T.assessJob([sample(at(0), { cpu: null }), sample(at(15), { cpu: null })], { started_at: started, timeout_seconds: 3600, now: at(15) });
  assert.equal(p.state, "unknown");
  assert.match(p.why, /no CPU or I\/O telemetry.*silence alone proves nothing/);
  // No sample yet: unknown.
  assert.equal(T.assessJob([], { started_at: started, timeout_seconds: 3600, now: at(1) }).state, "unknown");
});

test("B11: a sample reads metadata only: files, bytes, the newest name sanitised, no link followed, a bounded walk that says so; concurrent writes show as movement", async () => {
  const base = await mkdtemp(join(tmpdir(), "telemetry-"));
  dirs.push(base);
  const out = join(base, "out");
  const ctl = join(base, "job");
  await mkdir(join(out, "sub"), { recursive: true });
  await mkdir(ctl, { recursive: true });
  await writeFile(join(out, "sub", "a\u0007b.txt"), "12345");
  await symlink("/etc", join(out, "link"));
  await writeFile(join(ctl, "stdout.log"), "x");
  await writeFile(join(ctl, "heartbeat"), "1790000000 42 7\n");
  const s1 = await T.sampleJob({ out, ctl });
  assert.deepEqual([s1.out.files, s1.out.bytes, s1.out.bounded, s1.out.newest], [1, 5, false, "sub/a?b.txt"], "the link is neither followed nor counted; the bell is sanitised");
  assert.deepEqual(s1.cpu, { source: "heartbeat", at: 1790000000000, cpu: 42, io: 7 });
  assert.equal(s1.stdout.bytes, 1);
  // msb's metrics win over the heartbeat when the host has them.
  const s2 = await T.sampleJob({ out, ctl }, { metrics: async () => ({ cpu_ns: 9, io_bytes: 8 }) });
  assert.deepEqual([s2.cpu?.source, s2.cpu?.cpu, s2.cpu?.io], ["msb", 9, 8]);
  // A writer growing a file between two samples: movement.
  await T.keepSample(base, s1);
  await appendFile(join(out, "sub", "a\u0007b.txt"), "more");
  await T.keepSample(base, await T.sampleJob({ out, ctl }));
  const kept = await T.readSamples(base);
  assert.equal(kept.length, 2);
  assert.equal(T.assessJob(kept, { started_at: new Date(kept[0].at).toISOString(), timeout_seconds: 3600, now: kept[1].at }).state, "moving");
  // The walk stops at its bound and says so.
  const many = join(base, "many");
  mkdirSync(many);
  for (let i = 0; i < T.OUT_WALK_MAX + 5; i++) writeFileSync(join(many, `f${i}`), "");
  const big = await T.sampleJob({ out: many, ctl });
  assert.equal(big.out.bounded, true);
  assert.equal(T.progressWords("j000001", T.assessJob([big], { started_at: undefined, timeout_seconds: 60 })).includes(`${big.out.files}+ file(s)`), true);
});

test("B11: a running job's progress is read from disk as the service sampled it; the header names only a suspected stall of the seat's own jobs", async () => {
  const base = await mkdtemp(join(tmpdir(), "progress-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "r1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30 });
  const t0 = Date.now() - 30 * 60_000;
  const jobDir = join(storePaths(S).jobs, "j000001");
  await mkdir(jobDir, { recursive: true });
  await writeFile(join(jobDir, "job.json"), JSON.stringify({ id: "j000001", attempt: 1, state: "running", started_at: new Date(t0).toISOString(), requester: { agent: "a0" }, spec: { kind: "command", timeout_seconds: 3600 } }));
  const staging = join(storePaths(S).staging, "j000001-1");
  await mkdir(staging, { recursive: true });
  for (const m of [0, 10, 25]) await T.keepSample(staging, sample(t0 + m * 60_000, {}));
  const p = await T.jobProgressOnDisk(S, "j000001");
  assert.equal(p?.state, "suspected_stall");
  const head = (await L.leadsDigest({ sandboxRoot: S, agentId: "a0" }, { mark: false })).text;
  assert.match(head, /Your running jobs that look stuck: j000001 SUSPECTED STALL .*cancel keeps what it wrote, and nothing cancels it for you/);
  assert.doesNotMatch((await L.leadsDigest({ sandboxRoot: S, agentId: "a1" }, { mark: false })).text, /look stuck/, "another seat's job is not in this seat's header");
});

test("B17: exit 127 or the shell's \"command not found\" is a program missing in the job's image, with its profile, on the record and in the reason", async () => {
  const ctl = await mkdtemp(join(tmpdir(), "pm-"));
  dirs.push(ctl);
  await writeFile(join(ctl, "stderr.log"), "/runs/s/.jobs/j000001/command.sh: line 3: volatility3: command not found\n");
  assert.equal(await programMissing(ctl, 127), "volatility3");
  await writeFile(join(ctl, "stderr.log"), "");
  assert.equal(await programMissing(ctl, 127), "?");
  await writeFile(join(ctl, "stderr.log"), "Traceback: KeyError\n");
  assert.equal(await programMissing(ctl, 1), null);
  // Through the service: the job, its journal line, and what the agent is told.
  const S = join(mkdtempSync(join(tmpdir(), "jobs-")), "run");
  dirs.push(join(S, ".."));
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [] }));
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const r = await svc.submit("a1", { kind: "command", command: "definitely_not_a_program_wp4 --version", inputs: ["all"] });
  assert.ok(r.ok, !r.ok ? r.reason : "");
  const end = Date.now() + 20_000;
  let job = svc.jobs.get(r.job.id)!;
  while (!["committed", "failed", "cancelled"].includes(job.state) && Date.now() < end) {
    await new Promise((res) => setTimeout(res, 50));
    job = svc.jobs.get(r.job.id)!;
  }
  assert.equal(job.status, "failed");
  assert.deepEqual([job.program_missing?.program, job.program_missing?.image], ["definitely_not_a_program_wp4", "img:test"]);
  assert.match(job.reason ?? "", /exit 127: a program it runs is not in its image: definitely_not_a_program_wp4/);
  const journal = await readFile(storePaths(S).journal, "utf8");
  assert.match(journal, /"type":"job_program_missing"/);
  await svc.stop("test over");
});

test("B12: nothing moving while a job runs under a lead: its holder is nudged first; a window later everyone is asked, job or not; with no job, everyone at once", async () => {
  const base = await mkdtemp(join(tmpdir(), "regroup-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "r2", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30 });
  const b = await P.readBudget(S);
  const t0 = Date.parse(b.started_at);
  await P.writeBudget(S, { ...b, until_solved: true, stall_minutes: 15 });
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: new Date().toISOString(), recv_ts: new Date().toISOString(), agent: "a0", tool: "bash", args: {}, result: { ok: true } })}\n`);
  const lead = await L.openLead({ sandboxRoot: S, agentId: "a0" }, { title: "Try the candidates", why: "part 3", take: true });
  assert.ok(lead.ok);
  const jobDir = join(storePaths(S).jobs, "j000001");
  await mkdir(jobDir, { recursive: true });
  await writeFile(join(jobDir, "job.json"), JSON.stringify({ id: "j000001", attempt: 1, state: "running", started_at: new Date(t0).toISOString(), requester: { agent: "a0" }, spec: { kind: "command", timeout_seconds: 1800 } }));
  assert.ok((await L.attachJob(S, "a0", "j000001", "L-1")).ok);
  const openAt = Date.parse((await L.leadsSnapshot(S)).state.events[0].at);
  const first = await regroup(S, openAt + 16 * 60_000);
  assert.equal(first.posted, true);
  assert.equal(first.posted && first.kind, "nudge");
  assert.deepEqual(first.posted && first.to, ["a0"]);
  const posts = async () => (await P.readInbox({ sandboxRoot: S, agentId: "a0" }, { markSeen: false })).posts;
  assert.ok((await posts()).some((p) => /^REGROUP NUDGE for a0: nothing has moved for \d+ minutes.*your job runs under L-1: j000001 .*Is it the route\?/s.test(p.body) && p.to === "a0"), JSON.stringify((await posts()).map((p) => [p.to, p.body.slice(0, 200)])));
  const again = await regroup(S, openAt + 20 * 60_000);
  assert.deepEqual([again.posted, !again.posted && again.why], [false, "the holders of the running jobs were nudged 4 min ago"]);
  const all = await regroup(S, openAt + 32 * 60_000);
  assert.equal(all.posted && all.kind, "all_hands", "a running job never holds the regroup off for ever");
  assert.ok((await posts()).some((p) => /^REGROUP 1:/.test(p.body) && /Jobs running under leads \(1\)/.test(p.body)));
  // A run with no job running under a lead: everyone at once.
  const base2 = await mkdtemp(join(tmpdir(), "regroup2-"));
  dirs.push(base2);
  const S2 = join(base2, "run");
  await P.initSandbox(S2, { swarmId: "r3", agentIds: ["a0"], capUsd: 5, wallClockMinutes: 30 });
  const b2 = await P.readBudget(S2);
  await P.writeBudget(S2, { ...b2, until_solved: true, stall_minutes: 15 });
  const direct = await regroup(S2, Date.parse(b2.started_at) + 16 * 60_000);
  assert.equal(direct.posted && direct.kind, "all_hands");
});

test("B10: the seats' tokens are renewed at half their validity, in place, only where msb says the rotation is live; never a value in what it returns", async () => {
  assert.equal(validityMs("12h"), 12 * 3_600_000);
  assert.equal(validityMs("90m"), 90 * 60_000);
  assert.equal(validityMs("soon"), null);
  const spec = { run: "s1", agents: [{ id: "a0", model: "openai-codex/x" }, { id: "a1", model: "openai-codex/x" }, { id: "a2", model: "anthropic/y" }], providers: [{ provider: "openai-codex", kind: "oauth", hosts: ["chatgpt.com"], api: "x" }, { provider: "anthropic", kind: "api_key", hosts: ["api.anthropic.com"], api: "y" }], min_token_validity: "12h" } as unknown as VmSpec;
  const secrets: ResolvedSecret[] = [
    { provider: "openai-codex", kind: "oauth", placeholder: "ph-codex", value: "SECRET-NEW-TOKEN", hosts: ["chatgpt.com"] },
    { provider: "anthropic", kind: "api_key", placeholder: "ph-anth", value: "SECRET-KEY", hosts: ["api.anthropic.com"] },
  ];
  const t0 = Date.parse("2026-09-28T00:00:00Z");
  const applied: Array<{ name: string; secrets: string[] }> = [];
  const loader = async () =>
    ({
      Sandbox: {
        get: async (name: string) => ({
          modify: async (o: { secrets: Record<string, { value: string }>; dryRun?: boolean }) => {
            const names = Object.keys(o.secrets);
            if (!o.dryRun) applied.push({ name, secrets: names });
            // a0's VM rotates live; a1's would need a restart; a2 holds no token.
            const disposition = name.endsWith("a1") ? "next start" : "live";
            return { status: "running", applied: !o.dryRun, policy: "no_restart", changes: names.map((n) => ({ kind: "secret", field: "secret", name: n, change: "rotated", disposition, allowHosts: ["chatgpt.com"] })), conflicts: [], warnings: [], resizeStatus: [] };
          },
        }),
      },
    }) as never;
  const early = await renewSeatSecrets(spec, { now: t0 + 5 * 3_600_000, created_at: t0, loader, mint: async () => secrets });
  assert.deepEqual([early.due, early.next_at], [false, new Date(t0 + 6 * 3_600_000).toISOString()], "not before half the validity");
  const r = await renewSeatSecrets(spec, { now: t0 + 6 * 3_600_000 + 1, created_at: t0, loader, mint: async () => secrets });
  assert.equal(r.due, true);
  assert.deepEqual(r.seats.map((x) => [x.agent, x.outcome]), [["a0", "rotated"], ["a1", "unsupported"], ["a2", "nothing"]]);
  assert.match(r.seats[1].why ?? "", /next start/);
  assert.deepEqual(applied.map((a) => a.name), ["dfs-s1-a0"], "applied only where it is live");
  assert.doesNotMatch(JSON.stringify(r), /SECRET-/, "no value leaves it");
  // A VM that does not hold the secret (a rotation would add it): left alone.
  const adds = async () => ({ Sandbox: { get: async () => ({ modify: async () => ({ status: "running", applied: false, policy: "no_restart", changes: [{ kind: "secret", field: "secret", name: "X", change: "added", disposition: "live", allowHosts: [] }], conflicts: [], warnings: [], resizeStatus: [] }) }) } }) as never;
  const none = await renewSeatSecrets(spec, { force: true, loader: adds, mint: async () => secrets });
  assert.deepEqual(none.seats.map((x) => x.outcome), ["nothing", "nothing", "nothing"]);
});
