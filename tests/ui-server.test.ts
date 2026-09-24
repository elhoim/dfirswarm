/**
 * Web app API against the fixture sandbox. No model, no Herdr, no keys.
 * Kickoff uses `swarm.sh start --no-start`, so the real registry writer runs.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { createUiApp, defaultRunsDir, type UiApp } from "../scripts/ui/app.ts";
import { ActionRunner, allowEntryOfUrl, checkReadiness, isHostName, isLocalHost, listModels, listPacks, parseModelList, parseModelTeam, readLocalProviders, startArgv, validateStart, vmProviderHosts, vmReadiness } from "../scripts/ui/actions.ts";
import { resolveInputSet } from "../scripts/ui/inputs.ts";
import { ChangeBus, classifyPath, SUPPRESSED_KINDS, type BusMessage } from "../scripts/ui/watch.ts";
import { activitySeries, deriveCallsign, derivePhase, hubsParent, listSwarmRows, queryTraces, readCustody, vmHealth } from "../scripts/ui/model.ts";
import { seedFixtureRuns } from "../scripts/seed-fixture.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

let runsDir: string;
let inputsRoot: string;
let app: UiApp;
let base: string;

async function get<T = unknown>(path: string): Promise<{ status: number; body: T; headers: Headers }> {
  const res = await fetch(`${base}${path}`);
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // raw body
  }
  return { status: res.status, body: body as T, headers: res.headers };
}

async function post<T = unknown>(path: string, payload: unknown): Promise<{ status: number; body: T }> {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  return { status: res.status, body: (await res.json()) as T };
}

type JobView = { status: string; stdout: string; stderr: string; swarm_id: string | null };

/**
 * Every job a test accepts must be awaited before the test returns: a
 * `swarm.sh start` still running while the `after` hook removes the runs
 * directory keeps creating its sandbox under it, and the removal fails with
 * ENOTEMPTY (seen on Linux CI, where the race goes the other way from macOS).
 */
async function waitJobAt(at: string, id: string, timeoutMs = 20_000): Promise<JobView> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await fetch(`${at}/api/jobs/${id}`);
    const body = (await res.json()) as JobView;
    if (body.status !== "running") return body;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`job ${id} did not finish`);
}

function waitJob(id: string, timeoutMs = 20_000): Promise<JobView> {
  return waitJobAt(base, id, timeoutMs);
}

// The VM hubs' parent, for everything this file starts: a short directory of
// its own, so a run never creates ~/.dfirswarm/hubs and a socket path stays
// short. Tests that need hubs of their own set their own and put this back.
let hubsDir: string | null = null;
const hubsDirWas = process.env.SWARM_HUBS_DIR;

before(async () => {
  if (!process.env.SWARM_HUBS_DIR) {
    hubsDir = join(await mkdtemp("/tmp/dfh."), "dfirswarm-hubs");
    await mkdir(hubsDir, { mode: 0o700 });
    process.env.SWARM_HUBS_DIR = hubsDir;
  }
  runsDir = await mkdtemp(join(tmpdir(), "swarm-ui-"));
  await seedFixtureRuns(runsDir);
  // The inputs library: one real set, and a symlink that must never count as one.
  inputsRoot = await mkdtemp(join(tmpdir(), "swarm-inputs-"));
  await mkdir(join(inputsRoot, "brief", "data"), { recursive: true });
  await writeFile(join(inputsRoot, "brief", "README.md"), "# Brief\n", "utf8");
  await writeFile(join(inputsRoot, "brief", "data", "readings.csv"), "sensor,reading\na,1\n", "utf8");
  await symlink(tmpdir(), join(inputsRoot, "escape"));
  app = createUiApp({
    root: ROOT,
    runsDir,
    distDir: join(runsDir, "no-dist"),
    inputsRoot,
    models: async () => ({ source: "static", models: ["deepseek/deepseek-v4-pro", "openai-codex/gpt-6-astra"] }),
    readiness: async (models) => ({
      checked_at: "2026-09-17T00:00:00.000Z",
      providers: Object.fromEntries(
        [...new Set(models.map((m) => m.split("/")[0]))].map((p) => [
          p,
          p === "openai-codex" ? { status: "ready" as const, provider: p, auth_type: "oauth" } : { status: "not_ready" as const, provider: p, reason: "credentials_not_configured" },
        ]),
      ),
    }),
    heartbeatMs: 200,
    // No time-based reuse of a finish-line result: only "nothing changed" may serve one from cache.
    checksTtlMs: 0,
  });
  const { port } = await app.listen(0, "127.0.0.1");
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  const running = app.runner.list().filter((j) => j.status === "running");
  assert.deepEqual(running, [], "a test returned with a swarm.sh job still running; await it, or the teardown races its writes");
  await app.close();
  // A kickoff with inputs leaves read-only directories behind; give the bits back before removing them.
  execFileSync("chmod", ["-R", "u+w", runsDir]);
  await rm(runsDir, { recursive: true, force: true });
  await rm(inputsRoot, { recursive: true, force: true });
  if (hubsDir) await rm(dirname(hubsDir), { recursive: true, force: true });
  if (hubsDirWas === undefined) delete process.env.SWARM_HUBS_DIR;
  else process.env.SWARM_HUBS_DIR = hubsDirWas;
});

/** A goal document the harness will accept: it carries its own finish line. */
const FIXTURE_GOAL = `## Goal

Fixture kickoff from the web app test.

## Definition of done

\`work/fixture.txt\` exists.

## Checks

- \`test -f work/fixture.txt\`
`;

test("a microVM kickoff reaches the command line, and a VM option without it is refused", () => {
  const host = validateStart({ n: 2, cap_usd: 1, model: "openai/gpt-5.4", no_start: true });
  assert.equal(host.ok, true);
  if (!host.ok) return;
  assert.ok(!startArgv(host.params).includes("--isolation"), "host is the default and adds nothing");

  const vm = validateStart({
    n: 2,
    cap_usd: 1,
    model: "openai/gpt-5.4",
    no_start: true,
    isolation: "microvm",
    image: "ghcr.io/halilozturkci/dfirswarm-pro-disk@sha256:" + "a".repeat(64),
    vm_cpus: 1,
    vm_memory: 1024,
    vm_snapshot: false,
  });
  assert.equal(vm.ok, true);
  if (!vm.ok) return;
  const argv = startArgv(vm.params);
  const at = argv.indexOf("--isolation");
  assert.deepEqual(argv.slice(at, at + 9), [
    "--isolation", "microvm",
    "--image", "ghcr.io/halilozturkci/dfirswarm-pro-disk@sha256:" + "a".repeat(64),
    "--vm-cpus", "1",
    "--vm-memory", "1024",
    "--no-vm-snapshot",
  ]);

  for (const bad of [
    { isolation: "docker" },
    { image: "dfirswarm-disk:dev" },
    { isolation: "microvm", image: "not an image; rm -rf /" },
    { isolation: "microvm", vm_cpus: 0 },
    { isolation: "microvm", vm_memory: 64 },
    { vm_cpus: 2 },
    { vm_snapshot: false },
  ]) {
    assert.equal(validateStart({ n: 2, cap_usd: 1, model: "x/y", no_start: true, ...bad }).ok, false, JSON.stringify(bad));
  }
});

test("the network setting reaches the command line, and a bad one is refused", () => {
  // Guarded is the default and adds nothing: netguard is already on.
  const guarded = validateStart({ n: 2, cap_usd: 1, model: "openai/gpt-5.4", no_start: true });
  assert.equal(guarded.ok, true);
  if (!guarded.ok) return;
  assert.equal(guarded.params.net, "guarded");
  const guardedArgv = startArgv(guarded.params);
  assert.ok(!guardedArgv.includes("--no-netguard"));
  assert.ok(!guardedArgv.includes("--allow-host"));

  // Named hosts become one --allow-host each, lower case, however they were typed.
  const hosts = validateStart({
    n: 2,
    cap_usd: 1,
    model: "openai/gpt-5.4",
    no_start: true,
    net: "hosts",
    allow_hosts: "PyPI.org, files.pythonhosted.org",
  });
  assert.equal(hosts.ok, true);
  if (!hosts.ok) return;
  assert.deepEqual(hosts.params.allow_hosts, ["pypi.org", "files.pythonhosted.org"]);
  const hostsArgv = startArgv(hosts.params);
  assert.deepEqual(
    hostsArgv.filter((a, i) => a === "--allow-host" || hostsArgv[i - 1] === "--allow-host"),
    ["--allow-host", "pypi.org", "--allow-host", "files.pythonhosted.org"],
  );
  assert.ok(!hostsArgv.includes("--no-netguard"), "named hosts keep the guard on");

  // Open takes the guard off.
  const open = validateStart({ n: 2, cap_usd: 1, model: "openai/gpt-5.4", no_start: true, net: "open" });
  assert.equal(open.ok, true);
  if (!open.ok) return;
  assert.ok(startArgv(open.params).includes("--no-netguard"));

  // The old boolean still means what it meant.
  const legacy = validateStart({ n: 2, cap_usd: 1, model: "openai/gpt-5.4", no_start: true, netguard: false });
  assert.equal(legacy.ok, true);
  if (!legacy.ok) return;
  assert.equal(legacy.params.net, "open");
  assert.ok(startArgv(legacy.params).includes("--no-netguard"));

  // Refusals: an unknown setting, a host that is not a host, hosts with no host.
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "x/y", no_start: true, net: "loose" }).ok, false);
  assert.equal(
    validateStart({ n: 2, cap_usd: 1, model: "x/y", no_start: true, net: "hosts", allow_hosts: "not a host; rm -rf /" }).ok,
    false,
  );
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "x/y", no_start: true, net: "hosts", allow_hosts: "" }).ok, false);
});

test("a host is a name with a dot, localhost, an address, a suffix, or any of them with a port", () => {
  for (const ok of ["pypi.org", "files.pythonhosted.org", "127.0.0.1", "127.0.0.1:11434", "localhost", "localhost:1234", "[::1]", "[::1]:8080", "gpu-box.local", "192.168.1.20:8000", "*.blob.core.windows.net", ".googleapis.com"]) {
    assert.equal(isHostName(ok), true, `${ok} should be a host`);
  }
  for (const bad of ["", "not a host; rm -rf /", "nodots", "host:", "host:0", "host:70000", "[::1", "a..b", "-bad.example", "*.com", ".com", "a*.b.com", "*.*.x.com"]) {
    assert.equal(isHostName(bad), false, `${bad} should not be a host`);
  }
});

test("local is decided from the address the same way swarm.sh decides it", () => {
  for (const local of ["127.0.0.1", "localhost", "::1", "[::1]", "10.0.0.5", "192.168.1.20", "172.16.0.9", "172.31.255.1", "169.254.1.1", "fe80::1", "fd12:3456::1", "gpu-box.local", "nas.lan"]) {
    assert.equal(isLocalHost(local), true, `${local} is local`);
  }
  for (const cloud of ["api.openai.com", "172.32.0.1", "11.0.0.1", "gateway.example.com", "localhost.evil.com"]) {
    assert.equal(isLocalHost(cloud), false, `${cloud} is not local`);
  }
});

test("a team that bills nothing is expressed with a token cap, and local-only reaches the command line", () => {
  // cap_usd alone, as before.
  const usd = validateStart({ n: 2, cap_usd: 1, model: "openai/gpt-5.4", no_start: true });
  assert.ok(usd.ok && usd.params.cap_tokens === undefined);
  assert.deepEqual(startArgv(usd.params).slice(0, 5), ["start", "--cap-usd", "1", "--n", "2"]);
  // No dollars at all is only acceptable with a token cap: that is the free team.
  assert.equal(validateStart({ n: 2, cap_usd: 0, model: "ollama/qwen3:8b", no_start: true }).ok, false);
  assert.equal(validateStart({ n: 2, model: "ollama/qwen3:8b", no_start: true }).ok, false);
  const free = validateStart({ n: 2, cap_usd: 0, cap_tokens: 5000000, model: "ollama/qwen3:8b", no_start: true, net: "local" });
  assert.ok(free.ok, "a token cap stands in for the USD cap");
  if (!free.ok) return;
  assert.equal(free.params.cap_usd, 0);
  assert.equal(free.params.cap_tokens, 5000000);
  assert.equal(free.params.net, "local");
  const argv = startArgv(free.params);
  assert.ok(!argv.includes("--cap-usd"), "no USD cap is passed when none was given");
  assert.deepEqual(argv.filter((a, i) => a === "--cap-tokens" || argv[i - 1] === "--cap-tokens"), ["--cap-tokens", "5000000"]);
  assert.ok(argv.includes("--local-only"));
  assert.ok(!argv.includes("--no-netguard") && !argv.includes("--allow-host"));
  // Both caps travel together on a metered team.
  const both = validateStart({ n: 2, cap_usd: 3, cap_tokens: 100, model: "openai/gpt-5.4", no_start: true });
  assert.ok(both.ok && startArgv(both.params).includes("--cap-tokens") && startArgv(both.params).includes("--cap-usd"));
  // Refusals: a token cap that is not a whole positive number, a negative USD cap.
  assert.equal(validateStart({ n: 2, cap_usd: 1, cap_tokens: 0, model: "a/b", no_start: true }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: 1, cap_tokens: "5m", model: "a/b", no_start: true }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: -1, model: "a/b", no_start: true }).ok, false);
});

test("a local provider in models.json reaches the picker and readiness, keyless or not", async () => {
  // Pi omits a keyless provider from --list-models entirely, so the picker
  // reads models.json itself; readiness turns "not logged in" into "local,
  // needs a placeholder apiKey", which is the fix rather than a login.
  const agentDir = await mkdtemp(join(tmpdir(), "pi-agent-"));
  try {
    await writeFile(
      join(agentDir, "models.json"),
      JSON.stringify({
        providers: {
          ollama: { baseUrl: "http://127.0.0.1:11434/v1", api: "openai-completions", models: [{ id: "qwen3:8b" }, { id: "paid", cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 } }] },
          lmstudio: { baseUrl: "http://localhost:1234/v1", api: "openai-completions", apiKey: "x", models: [{ id: "m" }] },
          gateway: { baseUrl: "https://gateway.example.com/v1", api: "openai-completions", apiKey: "x", models: [{ id: "m" }] },
        },
      }),
    );
    const local = readLocalProviders(agentDir);
    assert.deepEqual(
      local.map((l) => [l.model, l.has_key, l.metered]),
      [
        ["ollama/qwen3:8b", false, false],
        ["ollama/paid", false, true],
        ["lmstudio/m", true, false],
      ],
      "the gateway on the internet is not local; the cost block decides metered",
    );
    // With no pi binary the list is static, and the local models are folded in.
    const list = await listModels(500, join(agentDir, "no-such-pi"), agentDir);
    assert.equal(list.source, "static");
    assert.ok(list.models.includes("ollama/qwen3:8b") && list.models.includes("lmstudio/m"));
    assert.equal(list.local?.length, 3);
    assert.equal(readLocalProviders(join(agentDir, "nowhere")).length, 0, "no models.json, no local providers");

    // A fake pi that answers the way the real one does for a keyless provider.
    const fakePi = join(agentDir, "fakepi");
    await writeFile(fakePi, '#!/usr/bin/env bash\nprintf \'{"status":"not_ready","provider":"%s","reason":"credentials_not_configured"}\\n\' "${4%%/*}"\nexit 1\n', { mode: 0o755 });
    const report = await checkReadiness(["ollama/qwen3:8b", "gateway/m"], 5000, fakePi, agentDir);
    assert.equal(report.providers.ollama.status, "local");
    assert.equal(report.providers.ollama.local, true);
    assert.equal(report.providers.ollama.base_url, "http://127.0.0.1:11434/v1");
    assert.match(report.providers.ollama.reason ?? "", /placeholder apiKey/);
    assert.equal(report.providers.gateway.status, "not_ready", "a cloud gateway without a key is still not logged in");
    assert.equal(report.providers.gateway.local, undefined);
  } finally {
    await rm(agentDir, { recursive: true, force: true });
  }
});

test("health reports the runs dir and the watcher", async () => {
  const { status, body } = await get<{ ok: boolean; runs_dir: string; watching: boolean }>("/api/health");
  assert.equal(status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.runs_dir, runsDir);
  assert.equal(typeof body.watching, "boolean");
});

test("swarm list carries spend, tokens, calls, elapsed, markers, phase", async () => {
  const { status, body } = await get<Array<Record<string, unknown>>>("/api/swarms");
  assert.equal(status, 200);
  assert.equal(body.length, 5);
  const webserver = body.find((r) => r.id === "s7a1c");
  assert.ok(webserver);
  assert.equal(webserver.phase, "running");
  assert.equal(webserver.n, 6);
  assert.equal(webserver.model, "deepseek/deepseek-v4-pro");
  assert.ok((webserver.spent_usd as number) > 1 && (webserver.spent_usd as number) < 3);
  assert.equal(webserver.cap_usd, 3);
  assert.ok((webserver.tokens as number) > 1_000_000);
  assert.ok((webserver.calls as number) > 100);
  assert.ok((webserver.elapsed_ms as number) > 20 * 60_000);
  assert.equal(webserver.agents_dead, 1);
  assert.equal(webserver.violations, 1);
  const hello = body.find((r) => r.id === "s3f09");
  assert.equal(hello?.phase, "done");
  assert.equal(hello?.agents_done, 2);
  assert.equal(typeof hello?.finished_at, "string");
  assert.ok(hello?.sentinel_by && hello.sentinel_by !== "harness", "hello-n2 certified itself; the list must not call that a harness cap-stop");
  assert.notEqual(hello?.stop_reason, "cap");
  const stopped = body.find((r) => r.id === "s0d4e");
  assert.equal(stopped?.phase, "stopped");
  // The list's second line: how much has happened, across every thread.
  assert.ok((webserver.threads_total as number) >= 1);
  assert.ok((webserver.posts_total as number) >= 10, `posts_total ${String(webserver.posts_total)}`);
  assert.ok((hello?.threads_total as number) >= 1);
  assert.ok((hello?.posts_total as number) >= 1);
});

test("swarm detail carries a thread pulse per thread and the activity strip", async () => {
  const { body } = await get<{
    threads: Array<{ name: string; posts: number; activity: Array<{ at: string | null; from: string; tag: string }> }>;
    activity: { from: string | null; to: string | null; messages: number; tool_calls: number; buckets: Array<{ m: number; c: number }> };
  }>("/api/swarms/s7a1c");
  const main = body.threads.find((t) => t.name === "main");
  assert.ok(main);
  assert.equal(main.activity.length, main.posts);
  assert.ok(main.activity.every((d) => typeof d.from === "string" && typeof d.tag === "string"));
  assert.ok(body.activity.messages >= 1);
  assert.ok(body.activity.tool_calls >= 1);
  assert.equal(body.activity.buckets.length, 96);
  const summed = body.activity.buckets.reduce((a, b) => a + b.m + b.c, 0);
  assert.equal(summed, body.activity.messages + body.activity.tool_calls);
});

test("agent rows carry their activity span, failures and posts per thread", async () => {
  const { body } = await get<{
    agents: Array<{ id: string; first_event_at: string | null; last_event_at: string | null; failures: number; failure_at: string[]; thread_posts: Record<string, number>; posts: number }>;
    threads: Array<{ name: string; posts: number }>;
  }>("/api/swarms/s7a1c");
  for (const a of body.agents) {
    assert.equal(a.failures, a.failure_at.length);
    assert.equal(Object.values(a.thread_posts).reduce((x, y) => x + y, 0), a.posts, `${a.id}: thread_posts sums to posts`);
    if (a.first_event_at && a.last_event_at) assert.ok(a.first_event_at <= a.last_event_at);
  }
  // The claim violation in the fixture is a failure of the agent that caused it.
  const violator = body.agents.find((a) => a.id === "s7a1c02");
  assert.ok(violator && violator.failures >= 1, "s7a1c02's blocked write counts as a failure");
  // Every post on the board is somebody's.
  const board = body.threads.reduce((x, t) => x + t.posts, 0);
  const authored = body.agents.reduce((x, a) => x + a.posts, 0);
  assert.ok(authored <= board && authored >= board - 3, `agents authored ${authored} of ${board} posts (the rest are the harness's)`);
});

test("activitySeries buckets posts against tool calls and skips lifecycle lines", () => {
  const at = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
  const ev = (tool: string, s: number) => ({ ts: at(s), agent: "a0", tool, args: {}, result: {} });
  const series = activitySeries([ev("agent_start", 0), ev("post", 10), ev("bash", 20), ev("wait", 30), ev("thinking", 40), ev("agent_stop", 90)], at(0), at(100), 10);
  assert.equal(series.messages, 1);
  assert.equal(series.tool_calls, 2);
  assert.equal(series.buckets.length, 10);
  assert.deepEqual(series.buckets[1], { m: 1, c: 0 });
  assert.deepEqual(series.buckets[2], { m: 0, c: 1 });
  assert.deepEqual(series.buckets[3], { m: 0, c: 1 });
  assert.equal(series.from, at(0));
  assert.equal(series.to, at(100));
  // No stamps at all: an empty series, not a crash.
  const empty = activitySeries([], null, null, 4);
  assert.equal(empty.from, null);
  assert.equal(empty.buckets.length, 4);
});

test("swarm detail: threads dim, agents with callsign/claims/spend, work, history, violations", async () => {
  const { status, body } = await get<Record<string, any>>("/api/swarms/s7a1c");
  assert.equal(status, 200);
  assert.equal(body.summary.id, "s7a1c");
  assert.match(body.goal, /compromised/i);
  const threadNames = body.threads.map((t: { name: string }) => t.name);
  assert.deepEqual(threadNames, ["main", "review", "prefetch"], "main first, then the most recently active");
  const review = body.threads.find((t: { name: string }) => t.name === "review");
  assert.equal(review.last_tag, "hold");
  assert.equal(review.dim, true);
  assert.equal(review.created_by, "s7a1c05");
  assert.equal(typeof review.created_at, "string");
  const beak = body.threads.find((t: { name: string }) => t.name === "prefetch");
  assert.equal(beak.dim, true);
  const main = body.threads.find((t: { name: string }) => t.name === "main");
  assert.equal(main.dim, false);

  assert.equal(body.agents.length, 6);
  const scout = body.agents.find((a: { id: string }) => a.id === "s7a1c00");
  assert.equal(scout.callsign, "Scout");
  assert.deepEqual(scout.claims, ["work/attack-path.svg"]);
  assert.equal(scout.spent_usd, 0.41);
  assert.equal(scout.marker, "active");
  const dead = body.agents.find((a: { id: string }) => a.id === "s7a1c04");
  assert.equal(dead.marker, "dead");
  assert.equal(dead.dead, true);
  assert.deepEqual(dead.claims, []);
  assert.equal(dead.marker_info?.reason, "stalled");
  const critic = body.agents.find((a: { id: string }) => a.id === "s7a1c05");
  assert.equal(critic.role, "critic");

  assert.ok(body.work.some((w: { path: string; kind: string }) => w.path === "work/attack-path.svg" && w.kind === "svg"));
  assert.ok(body.work.some((w: { path: string; kind: string }) => w.path === "work/.browser/evtx-chart.png" && w.kind === "image"));
  assert.equal(body.history["work/attack-path.svg"].length, 2);
  assert.equal(body.violations.length, 1);
  assert.equal(body.violations[0].agent, "s7a1c02");
  assert.ok(body.traces.some((e: { tool: string }) => e.tool === "reaped"));
  assert.equal(body.layout.tabs, 1);
  assert.equal(body.sentinel, false);
});

test("done swarm: sentinel true with output_file, agents ticked", async () => {
  const { body } = await get<Record<string, any>>("/api/swarms/s3f09");
  assert.equal(body.sentinel, true);
  assert.equal(body.sentinel_info.output, "work/usb-devices.txt");
  assert.equal(body.sentinel_info.by, "s3f0901");
  assert.ok(body.agents.every((a: { done: boolean }) => a.done));
  assert.equal(body.agents[0].marker_info.reason, "done/SWARM_DONE exists");
});

test("single agent, N=1: goal, one post, trace with done + session end", async () => {
  const { body } = await get<Record<string, any>>("/api/swarms/s1e77");
  assert.equal(body.summary.n, 1);
  assert.match(body.goal, /Single agent/);
  assert.equal(body.threads[0].posts, 1);
  const tools = body.traces.map((e: { tool: string }) => e.tool);
  assert.ok(tools.includes("done"));
  assert.equal(tools.at(-1), "agent_stop");
  const done = body.traces.find((e: { tool: string }) => e.tool === "done");
  assert.equal(done.args.output_file, "work/triage.txt");
  assert.equal(done.args.reason, "DoD checks passed");
});

test("unknown or malformed swarm ids", async () => {
  assert.equal((await get("/api/swarms/nope0")).status, 404);
  assert.equal((await get("/api/swarms/bad%20id")).status, 400);
  assert.equal((await get("/api/swarms/s7a1c/nothing")).status, 404);
});

test("thread posts are parsed with frontmatter", async () => {
  const { status, body } = await get<Array<Record<string, unknown>>>("/api/swarms/s7a1c/threads/main");
  assert.equal(status, 200);
  assert.ok(body.length >= 9);
  assert.equal(body[0].tag, "intro");
  assert.equal(body[0].from, "s7a1c00");
  assert.match(String(body[0].body), /Call me Scout/);
  assert.equal(typeof body[0].at, "string", "posts carry an mtime timestamp for the timeline");
  const empty = await get<unknown[]>("/api/swarms/s7a1c/threads/missing");
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.body, []);
});

test("traces filter by agent, tool and free text", async () => {
  const all = await get<{ total: number; matched: number; events: unknown[]; agents: string[]; tools: string[] }>("/api/swarms/s7a1c/traces");
  assert.equal(all.status, 200);
  assert.ok(all.body.total >= 25);
  assert.equal(all.body.matched, all.body.total);
  assert.ok(all.body.tools.includes("claim_violation"));
  assert.ok(all.body.agents.includes("s7a1c05"));

  const byTool = await get<{ matched: number; events: Array<{ tool: string }> }>("/api/swarms/s7a1c/traces?tool=claim_violation");
  assert.equal(byTool.body.matched, 1);
  assert.equal(byTool.body.events[0].tool, "claim_violation");

  const inbox = await get<{
    events: Array<{ tool: string; result: { n?: number; from?: string[]; ids?: number[] } }>;
  }>("/api/swarms/s7a1c/traces?tool=inbox&q=s7a1c00");
  assert.ok(inbox.body.events.length >= 1);
  const withSenders = inbox.body.events.find((e) => (e.result.from?.length ?? 0) > 0);
  assert.ok(withSenders, "fixture inbox events include sender ids");
  assert.equal(typeof withSenders.result.n, "number");
  assert.ok(withSenders.result.from?.includes("s7a1c00"));
  assert.ok(Array.isArray(withSenders.result.ids) && withSenders.result.ids.every((id) => Number.isInteger(id)));

  const byAgent = await get<{ events: Array<{ agent: string }> }>("/api/swarms/s7a1c/traces?agent=s7a1c05&order=desc");
  assert.ok(byAgent.body.events.length >= 3);
  assert.ok(byAgent.body.events.every((e) => e.agent === "s7a1c05"));

  const byText = await get<{ matched: number }>("/api/swarms/s7a1c/traces?q=prefetch.csv");
  assert.ok(byText.body.matched >= 1);

  const limited = await get<{ events: unknown[] }>("/api/swarms/s7a1c/traces?limit=2");
  assert.equal(limited.body.events.length, 2);

  // The chips: every agent's line count over the whole trace, and its spend from budget.json.
  const stats = await get<{ total: number; by_agent: Record<string, { events: number; spent_usd: number }> }>("/api/swarms/s7a1c/traces?agent=s7a1c05");
  const lines = Object.values(stats.body.by_agent).reduce((a, s) => a + s.events, 0);
  assert.equal(lines, stats.body.total, "by_agent counts the whole trace, not the filtered page");
  assert.ok(stats.body.by_agent.s7a1c05.events >= 3);
  assert.ok(stats.body.by_agent.s7a1c00.spent_usd > 0);

  // matched_by_agent is the other number: who the *matches* belong to. The
  // console asks it one question — which agents produced reasoning — and must
  // be able to answer it without downloading every reasoning event.
  const census = await get<{ matched: number; events: unknown[]; matched_by_agent: Record<string, number> }>(
    "/api/swarms/s7a1c/traces?tool=thinking&limit=1",
  );
  assert.equal(census.body.events.length, 1, "one event of payload buys the whole census");
  assert.equal(census.body.matched_by_agent.s7a1c00, 2);
  assert.equal(census.body.matched_by_agent.s7a1c01, 1);
  assert.equal(census.body.matched_by_agent.s7a1c02, undefined, "an agent that never reasoned is absent, not zero");
  assert.equal(
    Object.values(census.body.matched_by_agent).reduce((a, n) => a + n, 0),
    census.body.matched,
    "matched_by_agent adds up to the filtered total, not the whole trace",
  );

  // And the reasoning itself is where the console reads it from: the result.
  const one = await get<{ events: Array<{ args: Record<string, unknown>; result: { text?: string; chars?: number } }> }>(
    "/api/swarms/s7a1c/traces?tool=thinking&limit=1&order=desc",
  );
  assert.deepEqual(one.body.events[0].args, {}, "the harness writes reasoning with empty args");
  assert.ok((one.body.events[0].result.text ?? "").length > 0);
});

test("every post across every thread, in one request, for the board analytics", async () => {
  const all = await get<Array<{ thread: string; from: string; tag: string; body: string; at: string | null }>>("/api/swarms/s7a1c/posts");
  assert.equal(all.status, 200);
  assert.ok(all.body.length >= 6, "the fixture board has posts");
  assert.ok(all.body.every((p) => typeof p.body === "string"), "bodies come with them: the analytics reads what was said");
  const ordered = all.body.map((p) => p.at ?? "");
  assert.deepEqual(ordered, [...ordered].sort(), "the board is one conversation, in clock order");
  const single = await get<unknown[]>("/api/swarms/s7a1c/threads/main");
  assert.ok(all.body.length >= single.body.length, "at least the primary thread, plus any others");
});

test("artifacts: list, serve with content type, refuse escapes", async () => {
  const list = await get<Array<{ path: string }>>("/api/swarms/s7a1c/work");
  assert.ok(list.body.some((w) => w.path === "work/notes.md"));

  const svg = await get<string>("/api/swarms/s7a1c/work/attack-path.svg");
  assert.equal(svg.status, 200);
  assert.match(svg.headers.get("content-type") ?? "", /image\/svg\+xml/);
  assert.match(svg.headers.get("content-security-policy") ?? "", /sandbox/);
  assert.match(svg.headers.get("content-security-policy") ?? "", /connect-src 'none'/);
  assert.equal(svg.headers.get("access-control-allow-origin"), null);
  assert.match(String(svg.body), /<svg/);

  const html = await get<string>("/api/swarms/sbe12/work/report.html");
  assert.match(html.headers.get("content-type") ?? "", /text\/html/);

  const png = await fetch(`${base}/api/swarms/s7a1c/work/.browser/evtx-chart.png`);
  assert.equal(png.status, 200);
  assert.equal(png.headers.get("content-type"), "image/png");

  assert.equal((await get("/api/swarms/s7a1c/work/..%2F..%2Fteam.json")).status, 400);
  assert.equal((await get("/api/swarms/s7a1c/work/nope.txt")).status, 404);
});

test("artifacts: a symlink under work/ is not served, wherever it points", async () => {
  // The lexical escape check cannot see a link an agent's shell made, and an
  // artifact is a file the swarm wrote: the route refuses every link rather
  // than deciding which ones are safe to follow.
  const leak = join(runsDir, "s7a1c", "work", "leak.txt");
  await symlink("/etc/passwd", leak);
  const res = await get<string>("/api/swarms/s7a1c/work/leak.txt");
  assert.equal(res.status, 409);
  assert.doesNotMatch(String(res.body), /^root:/);
  await rm(leak);

  // A file outside the sandbox, reached by a link with an ordinary name.
  const outside = join(runsDir, "outside-secret.txt");
  await writeFile(outside, "SECRET-OUTSIDE-THE-SANDBOX\n", "utf8");
  const alias = join(runsDir, "s7a1c", "work", "notes-link.md");
  await symlink(outside, alias);
  const aliased = await get<string>("/api/swarms/s7a1c/work/notes-link.md");
  assert.equal(aliased.status, 409);
  assert.doesNotMatch(String(aliased.body), /SECRET-OUTSIDE/);
  await rm(alias);
});

test("artifacts: a name outside Latin-1 is served, with an ASCII fallback and a UTF-8 filename*", async () => {
  // Names under work/ come from evidence (a Cyrillic report, a Turkish user
  // name); Node refuses a header value above U+00FF, so the raw name cannot go
  // in filename="...".
  for (const name of ["\u043e\u0442\u0447\u0435\u0442.txt", "kullan\u0131c\u0131_\u015f.csv"]) {
    const abs = join(runsDir, "s7a1c", "work", name);
    await writeFile(abs, "payload\n", "utf8");
    const res = await get<string>(`/api/swarms/s7a1c/work/${encodeURIComponent(name)}?download=1`);
    await rm(abs);
    assert.equal(res.status, 200);
    assert.equal(res.body, "payload\n");
    const disposition = res.headers.get("content-disposition") ?? "";
    assert.match(disposition, /^attachment; filename="[\x20-\x7e]+"; filename\*=UTF-8''/);
    assert.equal(decodeURIComponent(disposition.split("filename*=UTF-8''")[1]), name);
  }
});

test("artifacts: a file that cannot be opened fails the request, not the server", { skip: process.getuid?.() === 0 && "root ignores file modes" }, async () => {
  // The file is opened (as a regular file, no link, no FIFO) before any
  // header goes out, so a file that cannot be opened is an error response,
  // never a 200 cut short; and whatever fails later in the read must not be
  // an unhandled 'error' event that takes the whole console down.
  // The test runner swallows an uncaught exception that ui-server.ts would
  // die of, so the test listens for one itself. chmod 000 makes the open fail
  // every time, where a real rm between stat and open is a race.
  const uncaught: unknown[] = [];
  const onUncaught = (err: unknown) => uncaught.push(err);
  process.on("uncaughtException", onUncaught);
  const abs = join(runsDir, "s7a1c", "work", "unreadable.txt");
  await writeFile(abs, "secret\n", "utf8");
  execFileSync("chmod", ["000", abs]);
  let failure: unknown;
  let status = 0;
  let body = "";
  try {
    const res = await fetch(`${base}/api/swarms/s7a1c/work/unreadable.txt`, { signal: AbortSignal.timeout(5_000) });
    status = res.status;
    body = await res.text();
  } catch (err) {
    failure = err;
  } finally {
    execFileSync("chmod", ["600", abs]);
    await rm(abs);
    await new Promise((r) => setImmediate(r));
    process.off("uncaughtException", onUncaught);
  }
  assert.deepEqual(uncaught.map(String), [], "the read stream's error escaped as an uncaught exception");
  assert.ok(failure || status !== 200, "a body that could not be read must not arrive as a complete response");
  assert.ok(!failure || (failure as Error).name !== "TimeoutError", "the response was left hanging instead of being closed");
  assert.doesNotMatch(body, /secret/, "none of the file reached the reader");
  const alive = await get<string>("/api/swarms/s7a1c/work/notes.md");
  assert.equal(alive.status, 200);
});

test("history: list, read a revision, restore under an operator claim, refuse when held", async () => {
  const list = await get<Record<string, Array<{ rev: number }>>>("/api/swarms/s3f09/history");
  assert.equal(list.body["work/usb-devices.txt"].length, 2);

  const rev1 = await get<{ text: string; versions: unknown[] }>("/api/swarms/s3f09/history/rev?path=work/usb-devices.txt&rev=1");
  assert.equal(rev1.status, 200);
  assert.match(rev1.body.text, /^Kingston DataTraveler 3\.0/);
  assert.equal(rev1.body.versions.length, 2);
  assert.equal((await get("/api/swarms/s3f09/history/rev?path=work/usb-devices.txt&rev=9")).status, 404);
  assert.equal((await get("/api/swarms/s3f09/history/rev?path=team.json&rev=1")).status, 400);

  const restored = await post<{ ok: boolean; rev: number }>("/api/swarms/s3f09/history/restore", { path: "work/usb-devices.txt", rev: 1 });
  assert.equal(restored.status, 200);
  assert.equal(restored.body.ok, true);
  assert.match(await readFile(join(runsDir, "s3f09", "work", "usb-devices.txt"), "utf8"), /^Kingston DataTraveler 3\.0/);
  const after = await get<Record<string, Array<{ rev: number; agent: string }>>>("/api/swarms/s3f09/history");
  assert.equal(after.body["work/usb-devices.txt"].length, 3);
  assert.equal(after.body["work/usb-devices.txt"][2].agent, "operator");
  const events = await readFile(join(runsDir, "s3f09", "traces", "events.jsonl"), "utf8");
  assert.match(events, /"file_restore"/);
  const locks = await get<Record<string, any>>("/api/swarms/s3f09");
  assert.equal(locks.body.locks.length, 0, "operator lock is released after restore");

  // attack-path.svg is held by s7a1c00: operator must be refused.
  const held = await post<{ ok: boolean; owner: string }>("/api/swarms/s7a1c/history/restore", { path: "work/attack-path.svg", rev: 1 });
  assert.equal(held.status, 409);
  assert.equal(held.body.owner, "s7a1c00");

  assert.equal((await post("/api/swarms/s3f09/history/restore", { path: "team.json", rev: 1 })).status, 400);
});

test("kickoff validation", () => {
  assert.equal(validateStart({ n: 0, cap_usd: 1, model: "a/b" }).ok, false);
  assert.equal(validateStart({ n: 31, cap_usd: 1, model: "a/b" }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: 0, model: "a/b" }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "no-slash" }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "", no_start: true }).ok, true);
  // A goal with no finish line is refused, the way the CLI refuses it.
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "a/b", goal: "just do something" }).ok, false);
  assert.equal(validateStart({ n: 2, cap_usd: 1, model: "a/b", goal: "" }).ok, true);
  const ok = validateStart({ n: 3, cap_usd: 2.5, model: "deepseek/deepseek-v4-pro", goal: FIXTURE_GOAL, playwright: true, netguard: false, label: "demo" });
  assert.equal(ok.ok, true);
  if (ok.ok) {
    const argv = startArgv(ok.params);
    assert.deepEqual(argv.slice(0, 5), ["start", "--cap-usd", "2.5", "--n", "3"]);
    assert.ok(argv.includes("--playwright"));
    assert.ok(argv.includes("--no-netguard"));
    assert.ok(argv.includes("--label"));
  }
  assert.deepEqual(parseModelList("Available models:\n  deepseek/deepseek-v4-pro  ctx 128k\nopenai/gpt-5.4\njunk line\n"), [
    "deepseek/deepseek-v4-pro",
    "openai/gpt-5.4",
  ]);
  assert.ok(
    parseModelList(
      "provider  model              context  max-out  thinking  images\n" +
        "deepseek  deepseek-v4-pro    1M       384K     yes       no\n" +
        "openai    gpt-5.4            272K     128K     yes       yes\n",
    ).includes("deepseek/deepseek-v4-pro"),
  );
});

test("POST /api/swarms runs swarm.sh start (--no-start) and the run appears", async () => {
  const bad = await post<{ error: string }>("/api/swarms", { n: 99 });
  assert.equal(bad.status, 400);
  assert.match(bad.body.error, /1\.\.30/);

  const accepted = await post<{ id: string; kind: string; status: string }>("/api/swarms", {
    model: "deepseek/deepseek-v4-pro",
    cap_usd: 0.25,
    n: 2,
    goal: FIXTURE_GOAL,
    label: "web-test",
    no_start: true,
  });
  assert.equal(accepted.status, 202);
  assert.equal(accepted.body.kind, "start");
  const job = await waitJob(accepted.body.id);
  assert.equal(job.status, "ok", job.stderr);
  assert.match(job.stdout, /Sandbox ready/);
  assert.ok(job.swarm_id && /^s[0-9a-f]{4,6}$/.test(job.swarm_id), `swarm id parsed: ${job.swarm_id}`);

  const list = await get<Array<{ id: string; label: string; phase: string; goal: string }>>("/api/swarms");
  const created = list.body.find((r) => r.id === job.swarm_id);
  assert.ok(created);
  assert.equal(created.label, "web-test");
  assert.equal(created.phase, "prepared");
  assert.match(created.goal, /Fixture kickoff/);
  // The contract carries the goal's own definition of done, not a fixed one.
  const contract = await readFile(join(runsDir, created.id, "SWARM.md"), "utf8");
  assert.match(contract, /## Definition of done/);
  assert.match(contract, /work\/fixture\.txt/);

  const jobs = await get<Array<{ id: string }>>("/api/jobs");
  assert.ok(jobs.body.some((j) => j.id === accepted.body.id));
});

test("stop and reap go through swarm.sh", async () => {
  const stop = await post<{ id: string }>("/api/swarms/s0d4e/stop", {});
  assert.equal(stop.status, 202);
  const stopJob = await waitJob(stop.body.id);
  assert.equal(stopJob.status, "ok", stopJob.stderr);
  assert.match(stopJob.stdout, /Stopped s0d4e/);
  const registry = JSON.parse(await readFile(join(runsDir, "registry.json"), "utf8")) as { runs: Array<{ id: string; state: string }> };
  assert.equal(registry.runs.find((r) => r.id === "s0d4e")?.state, "stopped");

  const badReap = await post<{ error: string }>("/api/swarms/s0d4e/reap", { stall_sec: -1 });
  assert.equal(badReap.status, 400);
  const reap = await post<{ id: string }>("/api/swarms/s0d4e/reap", { stall_sec: 1 });
  assert.equal(reap.status, 202);
  const reapJob = await waitJob(reap.body.id);
  assert.equal(reapJob.status, "ok", reapJob.stderr);
  assert.match(reapJob.stdout, /reaped/);
  const detail = await get<Record<string, any>>("/api/swarms/s0d4e");
  assert.ok(detail.body.agents.every((a: { dead: boolean }) => a.dead), "all silent agents reaped");
  assert.equal((await post("/api/swarms/zzzz/stop", {})).status, 404);
});

test("SSE: hello, then a change event after the sandbox is touched", async () => {
  const controller = new AbortController();
  const res = await fetch(`${base}/api/events`, { signal: controller.signal });
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/event-stream/);
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const readUntil = async (test: string | RegExp, timeoutMs = 5000) => {
    const hit = () => (typeof test === "string" ? buffer.includes(test) : test.test(buffer));
    const deadline = Date.now() + timeoutMs;
    while (!hit()) {
      if (Date.now() > deadline) throw new Error(`no ${test} in SSE stream:\n${buffer}`);
      const { value, done } = await reader.read();
      if (done) throw new Error("stream closed");
      buffer += decoder.decode(value, { stream: true });
    }
  };
  await readUntil("event: hello");
  app.bus.touch("s7a1c", "threads");
  // The bus coalesces bursts, and an earlier job may still be flushing its own
  // registry touch, so the first change event on the wire is not necessarily
  // ours. Wait for a change frame that names this swarm and this kind — any
  // frame before it is somebody else's and proves nothing either way.
  await readUntil(/event: change\ndata: \{[^\n]*"swarm_ids":\[[^\]]*"s7a1c"[^\]]*\][^\n]*"kinds":\[[^\]]*"threads"[^\]]*\]/);
  await readUntil(": ping");
  controller.abort();
});

test("forged tools are listed with their usage and readable, never writable, from the console", async () => {
  const { body } = await get<{ tools: Array<{ name: string; by: string; version: number; runtime: string; calls: number; failures: number; users: string[]; last_used_at: string | null; params: Record<string, { type: string; required?: boolean }> }>; registry: { tool_forging?: boolean } | null }>("/api/swarms/s7a1c");
  assert.equal(body.tools.length, 1);
  const tool = body.tools[0];
  assert.equal(tool.name, "timeline_stats");
  assert.equal(tool.by, "s7a1c00");
  assert.equal(tool.version, 1);
  assert.equal(tool.runtime, "python3");
  assert.equal(tool.calls, 3);
  assert.equal(tool.failures, 1);
  assert.deepEqual([...tool.users].sort(), ["s7a1c01", "s7a1c05"]);
  assert.equal(typeof tool.last_used_at, "string");
  assert.equal(tool.params.path.required, true);

  const source = await get<{ id: string; manifest: { name: string; sha256: string }; script: string }>("/api/swarms/s7a1c/tools/timeline_stats");
  assert.equal(source.status, 200);
  assert.equal(source.body.manifest.name, "timeline_stats");
  assert.match(source.body.script, /json\.load\(sys\.stdin\)/);
  assert.equal((await get("/api/swarms/s7a1c/tools/nope")).status, 404);
  assert.equal((await get("/api/swarms/s7a1c/tools/..%2Fbudget.json")).status, 400);
  const denied = await fetch(`${base}/api/swarms/s7a1c/tools/timeline_stats`, { method: "POST" });
  assert.equal(denied.status, 405);

  // The trace filter knows the tool by name, like any other.
  const byTool = await get<{ matched: number; events: Array<{ agent: string; result: { forged?: boolean } }> }>("/api/swarms/s7a1c/traces?tool=timeline_stats");
  assert.equal(byTool.body.matched, 3);
  assert.ok(byTool.body.events.every((e) => e.result.forged === true));
});

test("read-only inputs are shown with their guard, healed writes and final check", async () => {
  const { body } = await get<{
    inputs: { source: string; files: Array<{ path: string; bytes: number; sha256: string }>; bytes: number; enforce: string; guard: string; enforced: Record<string, string>; violations: Array<{ agent: string }>; check: { ok: boolean; checked: number; by: string } | null } | null;
    registry: { inputs?: { files: number; guard: string } | null } | null;
  }>("/api/swarms/s7a1c");
  assert.ok(body.inputs, "the web-server swarm was seeded with inputs");
  assert.deepEqual(body.inputs.files.map((f) => f.path), ["inputs/brief.md", "inputs/logs/u_ex260211.log"]);
  assert.equal(body.inputs.guard, "seatbelt");
  assert.equal(body.inputs.enforce, "auto");
  assert.deepEqual(body.inputs.enforced, { s7a1c00: "kernel", s7a1c05: "none" });
  assert.equal(body.inputs.violations.length, 2, "one refused tool write, one healed shell write");
  assert.ok(body.inputs.violations.every((v) => v.agent === "s7a1c01"));
  assert.ok(body.inputs.check && body.inputs.check.ok && body.inputs.check.checked === 2 && body.inputs.check.by === "s7a1c00");
  assert.equal(body.registry?.inputs?.files, 2);
  // A swarm without inputs says so with null, not an empty shape.
  const plain = await get<{ inputs: unknown }>("/api/swarms/s3f09");
  assert.equal(plain.body.inputs, null);
});

test("a per-model cap rides on the --models spec as @cap, and cannot exceed the swarm's cap", () => {
  const team = parseModelTeam("openai/gpt-5.4-mini=2@6, openai/gpt-5.4-nano=2@4, deepseek/deepseek-v4-pro=1");
  assert.ok(team.ok);
  if (team.ok) {
    assert.equal(team.total, 5);
    assert.deepEqual(team.entries, [
      { model: "openai/gpt-5.4-mini", count: 2, cap: 6 },
      { model: "openai/gpt-5.4-nano", count: 2, cap: 4 },
      { model: "deepseek/deepseek-v4-pro", count: 1 },
    ]);
  }
  assert.ok(parseModelTeam("a/b@2.5").ok, "a count of one may be left out before the cap");
  assert.ok(parseModelTeam("lmstudio/qwen3:8b=2@1").ok, "a model id with a colon keeps its cap");
  assert.equal(parseModelTeam("a/b=2@").ok, false);
  assert.equal(parseModelTeam("a/b=2@free").ok, false);
  assert.equal(parseModelTeam("a/b=2@0").ok, false);
  assert.equal(validateStart({ models: "a/b=1@6,c/d=1@4", cap_usd: 10, n: 2 }).ok, true);
  assert.equal(validateStart({ models: "a/b=1@12,c/d=1@4", cap_usd: 10, n: 2 }).ok, false, "a model cap above the swarm cap could never bind");
  const p = validateStart({ models: "a/b=1@6,c/d=1@4", cap_usd: 10, n: 2 });
  assert.ok(p.ok && startArgv(p.params).includes("a/b=1@6,c/d=1@4"), "the spec reaches swarm.sh untouched");
});

test("the six kickoff switches the form gained: validated, and mapped to the flags swarm.sh takes", () => {
  const base = { model: "a/b", cap_usd: 1, n: 1 };
  // attach: copy is the default, bind needs a set, an image is not also bound
  assert.equal(validateStart({ ...base, inputs_attach: "bind" }).ok, false);
  assert.equal(validateStart({ ...base, inputs: "0:brief", inputs_attach: "bind" }).ok, true);
  assert.equal(validateStart({ ...base, inputs: "0:brief", inputs_attach: "tar" }).ok, false);
  assert.equal(validateStart({ ...base, inputs_image: "0:brief/laptop.dmg" }).ok, true);
  assert.equal(validateStart({ ...base, inputs_image: "0:brief/laptop.exe" }).ok, false, "only an image hdiutil attaches");
  assert.equal(validateStart({ ...base, inputs_image: "0:brief/../x.dmg" }).ok, false);
  assert.equal(validateStart({ ...base, inputs: "0:brief", inputs_attach: "bind", inputs_image: "0:brief/laptop.dmg" }).ok, false);
  // a size ceiling needs a set and is a whole number of MB
  assert.equal(validateStart({ ...base, inputs_max_mb: 500 }).ok, false);
  assert.equal(validateStart({ ...base, inputs: "0:brief", inputs_max_mb: 0 }).ok, false);
  assert.equal(validateStart({ ...base, inputs: "0:brief", inputs_max_mb: 500 }).ok, true);
  // no_pypi means nothing without allow_install; tools_from and no_read are run ids
  assert.equal(validateStart({ ...base, no_pypi: true }).ok, false);
  assert.equal(validateStart({ ...base, allow_install: true, no_pypi: true }).ok, true);
  assert.equal(validateStart({ ...base, tools_from: "../etc" }).ok, false);
  assert.equal(validateStart({ ...base, tools_from: "s83fd" }).ok, true);
  assert.equal(validateStart({ ...base, no_read: "s83fd" }).ok, false, "a list, not a string");
  assert.equal(validateStart({ ...base, no_read: ["s83fd", "s83fd", "s3f09"] }).ok, true);
  assert.equal(validateStart({ ...base, no_read: Array.from({ length: 11 }, (_, i) => `r${i}`) }).ok, false);
  // the server-only paths never come from the body
  const smuggled = validateStart({ ...base, tools_from: "s83fd", tools_from_dir: "/etc", no_read: ["s3f09"], no_read_dirs: ["/etc"], inputs_image: "0:brief/a.dmg", inputs_image_path: "/etc/passwd" });
  assert.ok(smuggled.ok && smuggled.params.tools_from_dir === undefined && smuggled.params.no_read_dirs === undefined && smuggled.params.inputs_image_path === undefined);
  assert.ok(smuggled.ok && !startArgv(smuggled.params).some((a) => a === "--tools-from" || a === "--no-read" || a === "--inputs-image"), "no path flag until the server resolved it");
  // once the server resolved them, the flags come out in swarm.sh's shape
  const p = validateStart({ ...base, inputs: "0:brief", inputs_attach: "bind", inputs_enforce: "on", toolbox: "dfir", toolbox_required: true, allow_install: true, no_pypi: true, tools_from: "s83fd", no_read: ["s3f09", "s7a9b"] });
  assert.ok(p.ok);
  if (p.ok) {
    p.params.inputs_dir = "/srv/sets/brief";
    p.params.tools_from_dir = "/runs/s83fd/tools";
    p.params.no_read_dirs = ["/runs/s3f09", "/runs/s7a9b"];
    const argv = startArgv(p.params);
    const after = (flag: string) => argv[argv.indexOf(flag) + 1];
    assert.deepEqual(argv.slice(argv.indexOf("--inputs"), argv.indexOf("--inputs") + 5), ["--inputs", "/srv/sets/brief", "--inputs-bind", "--inputs-enforce", "on"]);
    assert.ok(argv.includes("--toolbox-required") && argv.includes("--no-pypi"));
    assert.equal(after("--tools-from"), "/runs/s83fd/tools");
    assert.deepEqual(argv.filter((a, i) => argv[i - 1] === "--no-read"), ["/runs/s3f09", "/runs/s7a9b"]);
  }
  const copy = validateStart({ ...base, inputs: "0:brief", inputs_max_mb: 200, toolbox: "off", toolbox_required: true });
  assert.ok(copy.ok);
  if (copy.ok) {
    copy.params.inputs_dir = "/srv/sets/brief";
    const argv = startArgv(copy.params);
    assert.ok(!argv.includes("--inputs-bind") && argv.includes("--inputs-max-mb") && !argv.includes("--toolbox-required"), "no requirement on a toolbox that is off");
  }
  const image = validateStart({ ...base, inputs_image: "0:brief/laptop.dmg" });
  assert.ok(image.ok);
  if (image.ok) {
    image.params.inputs_image_path = "/srv/sets/brief/laptop.dmg";
    const argv = startArgv(image.params);
    assert.equal(argv[argv.indexOf("--inputs-image") + 1], "/srv/sets/brief/laptop.dmg");
    assert.ok(!argv.includes("--inputs"), "an image is attached in place of a directory");
  }
});

test("tools_from and no_read name runs; the server turns them into directories, or refuses", async () => {
  const start = (extra: Record<string, unknown>) =>
    post<{ id: string }>("/api/swarms", { model: "deepseek/deepseek-v4-pro", cap_usd: 0.5, n: 1, goal: FIXTURE_GOAL, no_start: true, ...extra });
  assert.equal((await start({ tools_from: "nope" })).status, 404, "an unknown run has no tools to give");
  assert.equal((await start({ tools_from: "s3f09" })).status, 400, "a run that forged nothing is refused, not silently ignored");
  assert.equal((await start({ no_read: ["nope"] })).status, 404);
  const accepted = await start({ label: "clean-room", no_read: ["s3f09"] });
  assert.equal(accepted.status, 202);
  const job = await waitJob(accepted.body.id);
  assert.equal(job.status, "ok", job.stderr);
  const hidden = await get<{ registry: { sandbox: string } }>("/api/swarms/s3f09");
  const view = await get<{ registry: { no_read?: string[] } }>(`/api/swarms/${job.swarm_id}`);
  assert.deepEqual(view.body.registry.no_read, [await realpath(hidden.body.registry.sandbox)], "the record names the directory the panes must not read");
});

test("several evidence roots, and one added from the form when the server allows it", async () => {
  const second = await mkdtemp(join(tmpdir(), "swarm-inputs2-"));
  const third = await mkdtemp(join(tmpdir(), "swarm-inputs3-"));
  await mkdir(join(second, "brief"), { recursive: true });
  await writeFile(join(second, "brief", "notes.md"), "# other brief\n", "utf8");
  await mkdir(join(third, "images"), { recursive: true });
  await writeFile(join(third, "images", "disk.E01"), "E01", "utf8");
  const runs2 = await mkdtemp(join(tmpdir(), "swarm-runs2-"));
  const open = createUiApp({
    root: ROOT,
    runsDir: runs2,
    distDir: join(runs2, "no-dist"),
    inputsRoot: `${inputsRoot}:${second}`,
    allowRuntimeRoots: true,
    models: async () => ({ source: "static", models: ["deepseek/deepseek-v4-pro"] }),
    readiness: async () => ({ checked_at: "2026-09-17T00:00:00.000Z", providers: {} }),
    heartbeatMs: 200,
  });
  const { port } = await open.listen(0, "127.0.0.1");
  const at = `http://127.0.0.1:${port}`;
  const read = async () => (await (await fetch(`${at}/api/inputs`)).json()) as { roots: Array<{ path: string; source: string }>; sets: Array<{ id: string; name: string; root_index: number }>; runtime_roots: boolean };
  const send = (method: string, path: string, body?: unknown) =>
    fetch(`${at}${path}`, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  try {
    let lib = await read();
    assert.equal(lib.runtime_roots, true);
    assert.deepEqual(lib.sets.map((s) => s.id), ["0:brief", "1:brief"], "the same name under two roots is two sets, told apart by the root");
    assert.deepEqual(lib.roots.map((r) => r.source), ["env", "env"]);

    // The form adds a third root: absolute, existing, a directory.
    assert.equal((await send("POST", "/api/inputs/roots", { path: "relative/path" })).status, 400);
    assert.equal((await send("POST", "/api/inputs/roots", { path: join(tmpdir(), "does-not-exist-" + Date.now()) })).status, 404);
    assert.equal((await send("POST", "/api/inputs/roots", { path: join(third, "images", "disk.E01") })).status, 400, "a file is not a root");
    assert.equal((await send("POST", "/api/inputs/roots", { path: third })).status, 200);
    assert.equal((await send("POST", "/api/inputs/roots", { path: third })).status, 409, "once");
    lib = await read();
    assert.deepEqual(lib.roots.map((r) => r.source), ["env", "env", "ui"]);
    assert.deepEqual(lib.sets.map((s) => s.id), ["0:brief", "1:brief", "2:images"]);
    assert.equal(JSON.parse(await readFile(join(runs2, "inputs-roots.json"), "utf8"))[0], await realpath(third), "a root added from the form survives a restart");

    // A kickoff resolves the added root's set like any other.
    const started = await send("POST", "/api/swarms", { model: "deepseek/deepseek-v4-pro", cap_usd: 0.5, n: 1, goal: FIXTURE_GOAL, no_start: true, inputs: "2:images", inputs_enforce: "off" });
    assert.equal(started.status, 202);

    // A root named at start cannot be removed from the form; one added there can.
    assert.equal((await send("DELETE", "/api/inputs/roots/0")).status, 400);
    assert.equal((await send("DELETE", "/api/inputs/roots/2")).status, 200);
    assert.equal((await send("DELETE", "/api/inputs/roots/7")).status, 404);
    lib = await read();
    assert.deepEqual(lib.sets.map((s) => s.id), ["0:brief", "1:brief"]);
  } finally {
    await open.close();
    // A kickoff leaves the pristine copy and the manifest read-only on
    // purpose; the bits go back before the directory is removed.
    for (const d of [second, third, runs2]) execFileSync("chmod", ["-R", "u+w", d]);
    await rm(second, { recursive: true, force: true });
    await rm(third, { recursive: true, force: true });
    await rm(runs2, { recursive: true, force: true });
  }
});

test("the inputs library: sets under the root by name, nothing outside it, and the kickoff copies the set", async () => {
  const lib = await get<{ configured: boolean; root: string | null; roots: Array<{ path: string; source: string; ok: boolean }>; sets: Array<{ id: string; name: string; root_index: number; files: number; bytes: number; sample: string[] }>; runtime_roots: boolean }>("/api/inputs");
  assert.equal(lib.status, 200);
  assert.equal(lib.body.configured, true);
  assert.deepEqual(lib.body.sets.map((s) => s.name), ["brief"], "a symlink under the root is not a set");
  assert.equal(lib.body.sets[0].id, "0:brief", "a set is named by its root's index and its name");
  assert.equal(lib.body.sets[0].files, 2);
  assert.deepEqual(lib.body.sets[0].sample, ["README.md", "data/readings.csv"]);
  assert.deepEqual(lib.body.roots.map((r) => [r.source, r.ok]), [["env", true]]);
  assert.equal(lib.body.runtime_roots, false, "a root from the form is off unless the server was started with the flag");
  // Off means off: the route refuses before it looks at the token or the body.
  assert.equal((await post("/api/inputs/roots", { path: tmpdir() })).status, 403);
  assert.equal((await get<{ roots: unknown[] }>("/api/inputs")).body.roots.length, 1);

  // Names only: the body cannot carry a path, and the server ignores a client's inputs_dir.
  assert.equal(validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "../etc" }).ok, false);
  assert.equal(validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "brief", inputs_enforce: "maybe" }).ok, false);
  assert.equal(validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs_enforce: "on" }).ok, false, "enforcement without inputs is refused");
  const named = validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "brief", inputs_enforce: "on", inputs_dir: "/etc" });
  assert.ok(named.ok && named.params.inputs === "brief" && named.params.inputs_enforce === "on" && named.params.inputs_dir === undefined);
  assert.ok(named.ok && !startArgv(named.params).includes("--inputs"), "no --inputs until the server resolved the set");
  const resolved = validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "brief", inputs_enforce: "off" });
  if (resolved.ok) {
    resolved.params.inputs_dir = "/srv/sets/brief";
    const argv = startArgv(resolved.params);
    assert.deepEqual(argv.slice(argv.indexOf("--inputs"), argv.indexOf("--inputs") + 4), ["--inputs", "/srv/sets/brief", "--inputs-enforce", "off"]);
  }

  // Both spellings reach the same directory: the qualified id the form sends, and the bare name an older client sends.
  assert.equal(await resolveInputSet([inputsRoot], "0:brief"), await resolveInputSet(inputsRoot, "brief"));
  await assert.rejects(resolveInputSet([inputsRoot], "1:brief"), /no inputs root 1/);
  assert.equal(validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "0:brief" }).ok, true);
  assert.equal(validateStart({ model: "a/b", cap_usd: 1, n: 1, inputs: "0:../brief" }).ok, false);
  assert.equal((await post("/api/swarms", { model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 1, no_start: true, inputs: "nope" })).status, 404);
  assert.equal((await post("/api/swarms", { model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 1, no_start: true, inputs: "escape" })).status, 404);
  assert.equal((await post("/api/swarms", { model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 1, no_start: true, inputs: "..%2F..%2Fetc" })).status, 400);

  const accepted = await post<{ id: string }>("/api/swarms", {
    model: "deepseek/deepseek-v4-pro",
    cap_usd: 0.5,
    n: 1,
    goal: FIXTURE_GOAL,
    label: "with-inputs",
    no_start: true,
    inputs: "brief",
    inputs_enforce: "off",
  });
  assert.equal(accepted.status, 202);
  const job = await waitJob(accepted.body.id);
  assert.equal(job.status, "ok", job.stderr);
  assert.match(job.stdout, /Inputs:\s+2 file\(s\)/);
  assert.ok(job.swarm_id);
  const manifest = JSON.parse(await readFile(join(runsDir, job.swarm_id, "inputs.json"), "utf8")) as { files: Array<{ path: string }>; guard: string; enforce: string };
  assert.deepEqual(manifest.files.map((f) => f.path), ["inputs/README.md", "inputs/data/readings.csv"]);
  assert.equal(manifest.enforce, "off");
  assert.equal(manifest.guard, "none");
  const view = await get<{ inputs: { files: unknown[]; guard: string } | null; registry: { inputs?: { files: number } | null } | null }>(`/api/swarms/${job.swarm_id}`);
  assert.equal(view.body.inputs?.files.length, 2);
  assert.equal(view.body.registry?.inputs?.files, 2);
});

test("kickoff carries tool forging through to swarm.sh", () => {
  const off = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2 });
  assert.ok(off.ok && off.params.tool_forging === false);
  assert.ok(off.ok && !startArgv(off.params).includes("--allow-tool-forging"));
  const on = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, tool_forging: true });
  assert.ok(on.ok && on.params.tool_forging === true);
  assert.ok(on.ok && startArgv(on.params).includes("--allow-tool-forging"));
});

test("kickoff carries self-compaction through to swarm.sh, on by default", () => {
  const plain = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2 });
  assert.ok(plain.ok && plain.params.self_compact === true, "on when the form says nothing");
  assert.ok(plain.ok && !startArgv(plain.params).includes("--no-self-compact"));
  assert.ok(plain.ok && !startArgv(plain.params).includes("--compact-at"), "no spec travels unless one was set");
  const off = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, self_compact: false, compact_at: "150k" });
  assert.ok(off.ok && off.params.self_compact === false);
  assert.ok(off.ok && startArgv(off.params).includes("--no-self-compact"));
  assert.ok(off.ok && !startArgv(off.params).includes("--compact-at"), "a line means nothing with the feature off");
  const tuned = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, self_compact: true, compact_notice_at: "30%", compact_warn_at: " 45% ", compact_at: "150k" });
  assert.ok(tuned.ok, tuned.ok ? "" : tuned.error);
  const argv = tuned.ok ? startArgv(tuned.params) : [];
  assert.deepEqual(argv.slice(argv.indexOf("--compact-notice-at"), argv.indexOf("--compact-notice-at") + 6), ["--compact-notice-at", "30%", "--compact-warn-at", "45%", "--compact-at", "150k"]);
  const bad = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, compact_at: "lots" });
  assert.ok(!bad.ok && /compact_at must be a token count/.test(bad.ok ? "" : bad.error));
  // Per-model lines travel as one spec; the summary model and the inbox page are their own flags.
  const perModel = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, compact_at: "60%, openai/gpt-5.4-mini=55%,grok-4.6=70%", compact_model: "openai/gpt-5.4-nano", inbox_page_chars: 12000 });
  assert.ok(perModel.ok, perModel.ok ? "" : perModel.error);
  const perArgv = perModel.ok ? startArgv(perModel.params) : [];
  assert.equal(perArgv[perArgv.indexOf("--compact-at") + 1], "60%, openai/gpt-5.4-mini=55%,grok-4.6=70%");
  assert.equal(perArgv[perArgv.indexOf("--compact-model") + 1], "openai/gpt-5.4-nano");
  assert.equal(perArgv[perArgv.indexOf("--inbox-page-chars") + 1], "12000");
  const unbounded = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, inbox_page_chars: 0 });
  assert.ok(unbounded.ok && startArgv(unbounded.params).includes("--inbox-page-chars") && unbounded.params.inbox_page_chars === 0, "0 travels: it means no bound");
  const badModel = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, compact_model: "nano" });
  assert.ok(!badModel.ok && /compact_model must be provider\/id/.test(badModel.ok ? "" : badModel.error));
  const modelOff = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, self_compact: false, compact_model: "openai/gpt-5.4-nano" });
  assert.ok(!modelOff.ok && /which is off/.test(modelOff.ok ? "" : modelOff.error));
  const badPage = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, inbox_page_chars: -5 });
  assert.ok(!badPage.ok && /inbox_page_chars must be a whole number/.test(badPage.ok ? "" : badPage.error));
  const badList = validateStart({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 2, compact_at: "60%,openai/gpt-5.4-mini=lots" });
  assert.ok(!badList.ok);
});

test("models endpoint honours the injected provider", async () => {
  const { body } = await get<{ source: string; models: string[] }>("/api/models");
  assert.equal(body.source, "static");
  assert.deepEqual(body.models, ["deepseek/deepseek-v4-pro", "openai-codex/gpt-6-astra"]);
});

test("readiness is reported per provider, so the kickoff can default to a usable model", async () => {
  const { status, body } = await get<{ checked_at: string; providers: Record<string, { status: string; auth_type?: string; reason?: string }> }>("/api/models/readiness");
  assert.equal(status, 200);
  assert.equal(body.providers["openai-codex"].status, "ready");
  assert.equal(body.providers["openai-codex"].auth_type, "oauth");
  assert.equal(body.providers.deepseek.status, "not_ready");
  assert.equal(body.providers.deepseek.reason, "credentials_not_configured");
  const again = await get<{ checked_at: string }>("/api/models/readiness");
  assert.equal(again.body.checked_at, body.checked_at, "a second read within the TTL is the cached answer");
  const denied = await fetch(`${base}/api/models/readiness`, { method: "POST" });
  assert.equal(denied.status, 405);
});

test("static root explains a missing bundle instead of 404", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 503);
  assert.match(await res.text(), /npm run ui:build/);
});

test("helpers: path classification and callsign heuristic", () => {
  assert.deepEqual(classifyPath("/runs", "/runs/s7a1c/threads/main/000001-x.md"), { swarmId: "s7a1c", kind: "threads" });
  assert.deepEqual(classifyPath("/runs", "registry.json"), { swarmId: null, kind: "registry" });
  assert.deepEqual(classifyPath("/runs", "s7a1c/budget.json"), { swarmId: "s7a1c", kind: "budget" });
  // The event log is news; the proxy log and the watchdog's state next to it are not.
  assert.equal(classifyPath("/runs", "s7a1c/traces/events.jsonl").kind, "events");
  assert.equal(classifyPath("/runs", "s7a1c/traces/netguard.log").kind, "logs");
  assert.equal(classifyPath("/runs", "s7a1c/traces/idle-nudge.state").kind, "logs");
  // Pi's session files, the inbox cursors and the lock-table mutex are the harness's own bookkeeping.
  assert.equal(classifyPath("/runs", "s7a1c/.pi-sessions/s7a1c00/session.jsonl").kind, "sessions");
  assert.equal(classifyPath("/runs", "s7a1c/inbox/s7a1c00/cursors.json").kind, "internal");
  assert.equal(classifyPath("/runs", "s7a1c/locks/.table.lock/pid").kind, "internal");
  assert.equal(classifyPath("/runs", "s7a1c/locks/abc.json").kind, "locks");
  assert.equal(classifyPath("/runs", "s7a1c/tools/csv_stats/manifest.json").kind, "tools");
  assert.equal(classifyPath("/runs", "s7a1c/names.json").kind, "names");
  assert.equal(classifyPath("/runs", "s7a1c/SWARM.md").kind, "contract");
  assert.equal(classifyPath("/runs", "s7a1c/ledger/entries.jsonl").kind, "ledger");
  assert.equal(classifyPath("/runs", "s7a1c/layout.json").kind, "other");
  for (const kind of ["sessions", "logs", "internal"] as const) assert.ok(SUPPRESSED_KINDS.has(kind));
  const posts = [
    { id: 1, thread: "main", from: "a0", to: "all", tag: "intro" as const, body: "I'm Quill. Taking slice 1.", path: "" },
    { id: 2, thread: "main", from: "a1", to: "all", tag: "intro" as const, body: "a1 checking in.", path: "" },
  ];
  assert.equal(deriveCallsign(posts, "a0"), "Quill");
  assert.equal(deriveCallsign(posts, "a1"), null);
  assert.equal(deriveCallsign(posts, "a2"), null);
});

test("a mixed team reaches swarm.sh as --models, and n has to agree", () => {
  const team = parseModelTeam("openai-codex/gpt-6-astra=3, deepseek/deepseek-v4-pro=2");
  assert.equal(team.ok, true);
  if (team.ok) {
    assert.equal(team.total, 5);
    assert.deepEqual(team.entries, [
      { model: "openai-codex/gpt-6-astra", count: 3 },
      { model: "deepseek/deepseek-v4-pro", count: 2 },
    ]);
  }
  assert.equal(parseModelTeam("nonsense=2").ok, false);
  assert.equal(parseModelTeam("a/b=0").ok, false);
  assert.equal(parseModelTeam("  ").ok, false);
  assert.equal(parseModelTeam("a/b=31").ok, false);

  // The counts decide N, so a form that disagrees is refused rather than
  // silently launching a swarm of a different size.
  const bad = validateStart({ models: "a/b=2,c/d=1", cap_usd: 1, n: 2 });
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.match(bad.error, /add up to 3/);

  const good = validateStart({ models: "a/b=2,c/d=1", cap_usd: 1, n: 3 });
  assert.equal(good.ok, true);
  if (good.ok) {
    const argv = startArgv(good.params);
    assert.ok(argv.includes("--models"));
    assert.equal(argv[argv.indexOf("--models") + 1], "a/b=2,c/d=1");
    assert.ok(!argv.includes("--model"), "a team must not also pass --model");
  }
});

test("the case settings reach swarm.sh, and the ones that need evidence say so", () => {
  const started = validateStart({
    model: "a/b",
    cap_usd: 100,
    n: 9,
    inputs: "belkactf6",
    catalog: true,
    toolbox: "dfir,crypto",
    quarantine: true,
    cap_per_agent: 15,
    case_id: "BELKA-CTF6",
    examiner: "H. Ozturkci",
  });
  assert.equal(started.ok, true);
  if (started.ok) {
    const argv = startArgv({ ...started.params, inputs_dir: "/evidence/belkactf6" });
    for (const flag of ["--catalog", "--quarantine"]) assert.ok(argv.includes(flag), `${flag} missing`);
    assert.equal(argv[argv.indexOf("--toolbox") + 1], "dfir,crypto");
    assert.equal(argv[argv.indexOf("--cap-per-agent") + 1], "15");
    assert.equal(argv[argv.indexOf("--case-id") + 1], "BELKA-CTF6");
    assert.equal(argv[argv.indexOf("--examiner") + 1], "H. Ozturkci");
    assert.ok(!argv.includes("--allow-install"), "installing is not implied by a case");
  }

  // The console can also open the package index for a case whose host is
  // missing a reader — into the sandbox, never as root, never system-wide.
  const installing = validateStart({ model: "a/b", cap_usd: 5, n: 2, allow_install: true });
  assert.equal(installing.ok, true);
  if (installing.ok) assert.ok(startArgv(installing.params).includes("--allow-install"));

  // A first pass over nothing is a kickoff that fails three minutes in, so it
  // fails here instead.
  const noEvidence = validateStart({ model: "a/b", cap_usd: 5, n: 2, catalog: true });
  assert.equal(noEvidence.ok, false);
  if (!noEvidence.ok) assert.match(noEvidence.error, /catalog needs inputs/);

  // A per-agent cap above the swarm's own cap can never fire.
  const overCap = validateStart({ model: "a/b", cap_usd: 10, n: 2, cap_per_agent: 25 });
  assert.equal(overCap.ok, false);

  assert.equal(validateStart({ model: "a/b", cap_usd: 5, n: 2, toolbox: "nmap" }).ok, false);
  assert.equal(validateStart({ model: "a/b", cap_usd: 5, n: 2, toolbox: "off,dfir" }).ok, false);
  assert.equal(validateStart({ model: "a/b", cap_usd: 5, n: 2, case_id: "bad id!" }).ok, false);
  assert.equal(validateStart({ model: "a/b", cap_usd: 5, n: 2, examiner: "a;rm -rf /" }).ok, false);

  // Nothing case-shaped on the command line when nothing case-shaped was asked for.
  const plain = validateStart({ model: "a/b", cap_usd: 5, n: 2 });
  assert.equal(plain.ok, true);
  if (plain.ok) {
    const argv = startArgv(plain.params);
    for (const flag of ["--catalog", "--toolbox", "--quarantine", "--case-id", "--examiner", "--cap-per-agent"]) {
      assert.ok(!argv.includes(flag), `${flag} should not appear`);
    }
  }
});

test("the investigation library lists its entries with their metadata, reads one without its block, and refuses ids that are not entries", async () => {
  const listed = await get<{ entries: Array<{ id: string; category: string; title: string; summary: string; evidence: string[]; checks: number; has_definition_of_done: boolean }> }>("/api/library");
  assert.equal(listed.status, 200);
  const intrusion = listed.body.entries.find((e) => e.id === "windows/host-intrusion");
  assert.ok(intrusion, "the repo ships library/windows/host-intrusion.md");
  assert.equal(intrusion!.category, "windows");
  assert.equal(intrusion!.title, "Compromised Windows host");
  assert.ok(intrusion!.summary.length > 10 && intrusion!.evidence.includes("disk-image"));
  assert.ok(intrusion!.checks >= 7 && intrusion!.has_definition_of_done, "the entry carries the standard checks and a finish line");
  const categories = listed.body.entries.map((e) => e.category);
  assert.deepEqual([...categories].sort(), categories.slice().sort(), "entries are listed");
  assert.ok(!listed.body.entries.some((e) => e.id.endsWith("/README")), "the README is not an entry");

  const read = await get<{ id: string; text: string; seats?: number }>("/api/library/windows/host-intrusion");
  assert.equal(read.status, 200);
  assert.ok(read.body.text.startsWith("## Goal"), "the document starts after the metadata block");
  assert.ok(!/^title: /m.test(read.body.text), "the block is not in the text");
  assert.equal(read.body.seats, 5, "the suggestion travels as metadata");

  assert.equal((await get("/api/library/windows/nope")).status, 404);
  assert.equal((await get("/api/library/..%2F..%2Fpackage/json")).status, 400);
  assert.equal((await get("/api/library/nothing/host-intrusion")).status, 400, "an unknown category is not an entry");
  const put = await fetch(`${base}/api/library/windows/host-intrusion`, { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(put.status, 405, "the library is read-only from the web app");
});

test("the goal library lists, reads, saves and refuses a goal with no finish line", async () => {
  const listed = await get<{ goals: Array<{ name: string; checks: number; has_definition_of_done: boolean }> }>(
    "/api/goals",
  );
  assert.equal(listed.status, 200);
  const hello = listed.body.goals.find((g) => g.name === "hello");
  assert.ok(hello, "the repo ships prompts/goals/hello.md");
  assert.equal(hello!.has_definition_of_done, true);
  assert.ok(hello!.checks >= 1, "hello.md has runnable checks");

  const read = await get<{ name: string; text: string }>("/api/goals/hello");
  assert.equal(read.status, 200);
  assert.match(read.body.text, /## Definition of done/);

  // Names are the only path component, and they cannot escape the library.
  assert.equal((await get("/api/goals/..%2F..%2Fpackage")).status, 400);
  assert.equal((await get("/api/goals/nope")).status, 404);

  // Writing goes to a scratch copy of the library so the repo is left alone.
  const scratchRoot = await mkdtemp(join(tmpdir(), "goal-lib-"));
  await mkdir(join(scratchRoot, "prompts", "goals"), { recursive: true });
  const writable = createUiApp({
    root: scratchRoot,
    runsDir,
    distDir: join(runsDir, "no-dist"),
    models: async () => ({ source: "static", models: [] }),
    heartbeatMs: 200,
  });
  const { port } = await writable.listen(0, "127.0.0.1");
  const at = `http://127.0.0.1:${port}`;
  const headers = { "content-type": "application/json" };
  try {
    const noDod = await fetch(`${at}/api/goals/draft`, {
      method: "PUT",
      headers,
      body: JSON.stringify({ text: "## Goal\n\nDo a thing.\n" }),
    });
    assert.equal(noDod.status, 400, "a goal with no finish line is not a goal");

    const saved = await fetch(`${at}/api/goals/draft`, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        text: "## Goal\n\nDo a thing.\n\n## Definition of done\n\nThe thing is done.\n\n## Checks\n\n- `test -f work/thing.txt`\n",
      }),
    });
    assert.equal(saved.status, 200);
    assert.equal((await saved.json() as { checks: number }).checks, 1);
    assert.match(await readFile(join(scratchRoot, "prompts", "goals", "draft.md"), "utf8"), /## Checks/);

    assert.equal((await fetch(`${at}/api/goals/Draft%20Two`, { method: "PUT", headers, body: JSON.stringify({ text: "x" }) })).status, 400);

    const removed = await fetch(`${at}/api/goals/draft`, { method: "DELETE" });
    assert.equal(removed.status, 200);
    assert.equal((await get(`/api/goals/draft`)).status, 404);

    // A goal that is a symlink would turn an open read into file disclosure and
    // a save into a write anywhere on the host.
    const secret = join(scratchRoot, "secret.md");
    await writeFile(secret, "## Definition of done\n\nnot yours\n", "utf8");
    await symlink(secret, join(scratchRoot, "prompts", "goals", "sneaky.md"));
    assert.equal((await fetch(`${at}/api/goals/sneaky`)).status, 400, "a symlinked goal is refused");
    const listedSneaky = await fetch(`${at}/api/goals`);
    assert.equal(listedSneaky.status, 200);
    const listedBody = (await listedSneaky.json()) as { goals: Array<{ name: string; title: string }> };
    assert.ok(!listedBody.goals.some((g) => g.name === "sneaky"), "GET /api/goals must not follow a symlink the named route refuses");
    assert.ok(!listedBody.goals.some((g) => /not yours/.test(g.title)), "the list must not leak the symlink target");
    const throughLink = await fetch(`${at}/api/goals/sneaky`, {
      method: "PUT",
      headers,
      body: JSON.stringify({ text: "## Definition of done\n\noverwritten\n" }),
    });
    assert.equal(throughLink.status, 400, "a save must not follow the link either");
    assert.match(await readFile(secret, "utf8"), /not yours/);

    // The count beside a goal has to mean the number of checks that will run.
    const counted = await fetch(`${at}/api/goals/counting`, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        text: [
          "## Goal",
          "",
          "Count carefully.",
          "",
          "## Definition of done",
          "",
          "Done.",
          "",
          "## Checks",
          "",
          "- `test -f a`",
          "- `test -f b` and also `test -f c`",
          "",
          "```",
          "- `this is inside a fence and does not run`",
          "```",
          "",
          "### Appendix",
          "",
          "- `this is under a deeper heading and does not run`",
          "",
        ].join("\n"),
      }),
    });
    assert.equal(counted.status, 200);
    assert.equal((await counted.json() as { checks: number }).checks, 3);
  } finally {
    await writable.close();
    await rm(scratchRoot, { recursive: true, force: true });
  }
});

test("the live contract is readable and cannot be written", async () => {
  const contract = await get<{ id: string; text: string }>("/api/swarms/s7a1c/contract");
  assert.equal(contract.status, 200);
  assert.equal(contract.body.id, "s7a1c");
  assert.match(contract.body.text, /Swarm contract/);

  const write = await fetch(`${base}/api/swarms/s7a1c/contract`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "# mine now" }),
  });
  assert.equal(write.status, 405, "SWARM.md is harness-owned; the API must not offer a way round that");
});

test("mutations need the token; watching does not", async () => {
  // A second app on the same fixture, this one with a token set.
  const guarded = createUiApp({
    root: ROOT,
    runsDir,
    distDir: join(runsDir, "no-dist"),
    token: "s3cret",
    models: async () => ({ source: "static", models: ["deepseek/deepseek-v4-pro"] }),
    heartbeatMs: 200,
  });
  const { port } = await guarded.listen(0, "127.0.0.1");
  const at = `http://127.0.0.1:${port}`;
  try {
    const health = await fetch(`${at}/api/health`);
    assert.equal(health.status, 200);
    assert.equal(((await health.json()) as { auth: boolean }).auth, true);

    // Reading is open: the whole point is that the LAN can watch.
    assert.equal((await fetch(`${at}/api/swarms`)).status, 200);

    const body = JSON.stringify({ model: "deepseek/deepseek-v4-pro", cap_usd: 1, n: 1, no_start: true });
    const headers = { "content-type": "application/json" };

    const denied = await fetch(`${at}/api/swarms`, { method: "POST", headers, body });
    assert.equal(denied.status, 401, "starting a swarm spends money and needs the token");

    const stop = await fetch(`${at}/api/swarms/s7a1c/stop`, { method: "POST", headers, body: "{}" });
    assert.equal(stop.status, 401);
    const reap = await fetch(`${at}/api/swarms/s7a1c/reap`, { method: "POST", headers, body: "{}" });
    assert.equal(reap.status, 401);
    const restore = await fetch(`${at}/api/swarms/s3f09/history/restore`, {
      method: "POST",
      headers,
      body: JSON.stringify({ path: "work/usb-devices.txt", rev: 1 }),
    });
    assert.equal(restore.status, 401);

    const withHeader = await fetch(`${at}/api/swarms`, {
      method: "POST",
      headers: { ...headers, authorization: "Bearer s3cret" },
      body,
    });
    assert.equal(withHeader.status, 202);
    const accepted: string[] = [((await withHeader.json()) as { id: string }).id];

    // RFC 9110: the scheme name is case-insensitive.
    const lowercased = await fetch(`${at}/api/swarms`, {
      method: "POST",
      headers: { ...headers, authorization: "bearer s3cret" },
      body,
    });
    assert.equal(lowercased.status, 202);
    accepted.push(((await lowercased.json()) as { id: string }).id);

    const wrongLength = await fetch(`${at}/api/swarms`, {
      method: "POST",
      headers: { ...headers, authorization: "Bearer s3cre" },
      body,
    });
    assert.equal(wrongLength.status, 401);

    // Same-origin SPA does not need CORS. A wildcard here let any website
    // (and a sandboxed artifact iframe) read traces and work files.
    const preflight = await fetch(`${at}/api/swarms`, { method: "OPTIONS" });
    assert.equal(preflight.headers.get("access-control-allow-origin"), null);
    const listed = await fetch(`${at}/api/swarms`);
    assert.equal(listed.headers.get("access-control-allow-origin"), null);

    // The server prints /#token= so the secret stays in the fragment. A
    // query parameter would land in access logs, history and Referer.
    const withQuery = await fetch(`${at}/api/swarms?token=s3cret`, { method: "POST", headers, body });
    assert.equal(withQuery.status, 401, "mutations accept Authorization: Bearer only, not ?token=");

    // Each accepted request ran swarm.sh for real and left a prepared run.
    const ids = new Set<string>();
    for (const id of accepted) {
      const job = await waitJobAt(at, id);
      assert.equal(job.status, "ok", job.stderr);
      assert.match(job.stdout, /Sandbox ready/);
      assert.ok(job.swarm_id, `job ${id} names its swarm`);
      ids.add(job.swarm_id);
    }
    assert.equal(ids.size, 2, "two authorized kickoffs, two runs");
    assert.deepEqual(
      guarded.runner.list().filter((j) => j.status === "running"),
      [],
      "nothing is left running on the guarded app",
    );
  } finally {
    await guarded.close();
  }
});

test("the ledger reaches the console: entries as recorded, merged authors, rendered flag", async () => {
  const { body } = await get<{ ledger: { entries: Array<{ seq: number; kind: string; ts?: string; value: string; authors: string[]; confidence?: string }>; rendered: boolean } }>("/api/swarms/s7a1c");
  assert.equal(body.ledger.rendered, true, "ledger.md is rendered after every record");
  assert.equal(body.ledger.entries.length, 4, "the duplicate event merged into one entry");
  assert.deepEqual(body.ledger.entries.map((e) => e.kind), ["event", "event", "ioc", "finding"]);
  const shared = body.ledger.entries.find((e) => e.value.startsWith("First request"));
  assert.deepEqual(shared?.authors, ["s7a1c00", "s7a1c01"]);
  assert.equal(shared?.ts, "2026-02-11T02:57:12.000Z");
  assert.equal(body.ledger.entries[3].confidence, "medium");
  // a swarm that never recorded anything has an empty ledger, not an error
  const hello = await get<{ ledger: { entries: unknown[]; rendered: boolean } }>("/api/swarms/s1e77");
  assert.deepEqual(hello.body.ledger, { entries: [], rendered: false });
});

test("the dossier comes out as files, with names and whole traces", async () => {
  // Nothing here is newly exposed — the view routes already return all of it
  // without a token — but a reader has to be handed a file, not a JSON body,
  // and the trace has to arrive whole. /api/swarms/:id/traces clamps to the
  // last 5000 events, which on a long run drops the beginning of the case.
  const summary = await get<string>("/api/swarms/s7a1c/dossier/summary.md");
  assert.equal(summary.status, 200);
  assert.equal(summary.headers.get("content-type"), "text/markdown; charset=utf-8");
  assert.equal(summary.headers.get("content-disposition"), 'attachment; filename="s7a1c-summary.md"');
  assert.match(String(summary.body), /^# /, "the summary is Markdown, rendered from the sandbox");

  const artifacts = await get<{ files: Array<{ path: string; sha256: string; packaged: boolean }> }>(
    "/api/swarms/s7a1c/dossier/artifacts.json",
  );
  assert.equal(artifacts.status, 200);
  assert.equal(artifacts.headers.get("content-disposition"), 'attachment; filename="s7a1c-artifacts.json"');
  assert.ok(artifacts.body.files.length > 0, "the fixture writes files under work/");
  for (const f of artifacts.body.files) assert.equal(f.sha256.length, 64, `${f.path} has no sha256`);

  const trace = await get<string>("/api/swarms/s7a1c/dossier/trace.jsonl");
  assert.equal(trace.status, 200);
  assert.equal(trace.headers.get("content-type"), "application/x-ndjson; charset=utf-8");
  const lines = String(trace.body).split("\n").filter(Boolean);
  const view = await get<{ total: number; events: unknown[] }>("/api/swarms/s7a1c/traces?limit=5");
  assert.equal(view.body.events.length, 5, "the view route pages");
  assert.equal(lines.length, view.body.total, "the file is the whole trace, not a page of it");
  assert.ok(lines.length > view.body.events.length);
  for (const line of lines) JSON.parse(line);

  const ledger = await get<string>("/api/swarms/s7a1c/dossier/ledger.jsonl");
  assert.equal(ledger.status, 200);
  assert.ok(String(ledger.body).split("\n").filter(Boolean).length >= 4);

  // A run that recorded nothing has no ledger file, and saying so beats an
  // empty download the operator would attach to a case.
  const missing = await get<{ error: string }>("/api/swarms/s1e77/dossier/ledger.jsonl");
  assert.equal(missing.status, 404);
  assert.match(missing.body.error, /has no ledger\.jsonl/);

  const unknown = await get<{ error: string }>("/api/swarms/s7a1c/dossier/passwords");
  assert.equal(unknown.status, 404);
  assert.match(unknown.body.error, /no such download/);

  const posted = await fetch(`${base}/api/swarms/s7a1c/dossier/summary.md`, { method: "POST" });
  assert.equal(posted.status, 405);
});

test("the report renders from the console, sandboxed, and the artifacts route hashes on demand", async () => {
  const report = await get<string>("/api/swarms/s7a1c/dossier/report.html");
  assert.equal(report.status, 200);
  assert.match(report.headers.get("content-type") ?? "", /text\/html/);
  // The report is agent-derived text the console frames in an iframe, so it
  // carries the same sandbox an artifact does: no same-origin, no network.
  const csp = report.headers.get("content-security-policy") ?? "";
  // No scripts: the report carries none, and a page that may run them can
  // navigate itself anywhere with what it holds.
  assert.match(csp, /^sandbox;/);
  assert.doesNotMatch(csp, /allow-scripts|script-src/);
  assert.match(csp, /connect-src 'none'/);
  const html = String(report.body);
  assert.match(html, /Forensic report/);
  assert.match(html, /203\.0\.113\.24/, "the fixture's indicator reaches the report");
  assert.match(html, /E-1/, "exhibit numbers are the ledger's own seq");
  // Self-contained: nothing is fetched when this is opened offline.
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /<link\b/i);
  assert.doesNotMatch(html, /\bsrc\s*=\s*["']https?:/i);

  const index = await get<{ files: Array<{ path: string; sha256: string; packaged: boolean; bytes: number }>; packaged_bytes: number }>(
    "/api/swarms/s7a1c/artifacts",
  );
  assert.equal(index.status, 200);
  assert.ok(index.body.files.some((f) => f.path === "work/attack-path.svg" && f.sha256.length === 64));
  // The fixture extracts a hive: hashed, and not carried by the package.
  const hive = index.body.files.find((f) => f.path === "work/extracted/SOFTWARE");
  assert.ok(hive, "the fixture's extracted material is in the index");
  assert.equal(hive.packaged, false);
  const total = index.body.files.reduce((n, f) => n + f.bytes, 0);
  const packaged = index.body.files.filter((f) => f.packaged).reduce((n, f) => n + f.bytes, 0);
  assert.equal(index.body.packaged_bytes, packaged);
  assert.ok(packaged < total, "the extracted hive's bytes are counted but not shipped");
});

test("GET /dossier is the handover as one product, with hashes of the bytes it holds", async () => {
  const pack = await get<{
    html: string;
    summary: string;
    artifactsJson: string;
    artifacts: { files: Array<{ path: string; sha256: string }> };
    files: Array<{ name: string; present: boolean; sha256: string | null; bytes: number | null }>;
  }>("/api/swarms/s7a1c/dossier");
  assert.equal(pack.status, 200);
  assert.match(pack.body.html, /Forensic report/);
  const byName = new Map(pack.body.files.map((f) => [f.name, f]));
  const report = byName.get("report.html");
  assert.equal(report?.present, true);
  assert.equal(report?.sha256, createHash("sha256").update(pack.body.html).digest("hex"));
  assert.equal(report?.bytes, Buffer.byteLength(pack.body.html));
  assert.equal(byName.get("summary.md")?.sha256, createHash("sha256").update(pack.body.summary).digest("hex"));
  assert.equal(byName.get("artifacts.json")?.sha256, createHash("sha256").update(pack.body.artifactsJson).digest("hex"));
  assert.ok(pack.body.artifacts.files.some((f) => f.path === "work/attack-path.svg" && f.sha256.length === 64));
  assert.match(pack.body.html, new RegExp(pack.body.artifacts.files[0].sha256), "the report cites a hash from this same walk");

  // A swarm that wrote nothing still gets the generated files; the ledger
  // is absent rather than an empty download.
  const empty = await get<{ files: Array<{ name: string; present: boolean }> }>("/api/swarms/s1e77/dossier");
  assert.equal(empty.status, 200);
  const emptyByName = new Map(empty.body.files.map((f) => [f.name, f]));
  assert.equal(emptyByName.get("report.html")?.present, true);
  assert.equal(emptyByName.get("ledger.jsonl")?.present, false);
});

test("the console reads runs/, and an older checkout's sandbox-runs/", async () => {
  // The console starts swarms by running scripts/swarm.sh with SWARM_RUNS_DIR
  // set to what this returns, so a disagreement here would send a run to one
  // directory and then look for it in another. The shell side of the same rule
  // is pinned against the real script in tests/swarm-preflight.test.sh.
  const home = await mkdtemp(join(tmpdir(), "runs-dir-"));
  try {
    assert.equal(defaultRunsDir(home), join(home, "runs"), "with neither present, runs/ is the answer");

    await mkdir(join(home, "sandbox-runs"), { recursive: true });
    assert.equal(
      defaultRunsDir(home),
      join(home, "sandbox-runs"),
      "a checkout from before the rename must keep reading its own runs",
    );

    await mkdir(join(home, "runs"), { recursive: true });
    assert.equal(defaultRunsDir(home), join(home, "runs"), "once runs/ exists it is the one used");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("the finish line goes to the shell only when the sandbox has changed", async () => {
  // Watching is open to the LAN, and each read of the finish line used to
  // run the goal's shell checks again once a short cache expired — every
  // fifteen seconds per open page, on a swarm nobody had touched.
  const health = await get<{ watching: boolean; checks_runs: number }>("/api/health");
  const before = health.body.checks_runs;
  const first = await get<{ total: number }>("/api/swarms/s3f09/checks");
  assert.equal(first.status, 200);
  await get("/api/swarms/s3f09/checks");
  const afterTwo = (await get<{ checks_runs: number }>("/api/health")).body.checks_runs;
  if (health.body.watching) {
    assert.equal(afterTwo - before, 1, "two reads of an untouched swarm: one run");
    app.bus.touch("s3f09", "work");
    await get("/api/swarms/s3f09/checks");
    const afterTouch = (await get<{ checks_runs: number }>("/api/health")).body.checks_runs;
    assert.equal(afterTouch - before, 2, "a change under the sandbox: one more run");
  } else {
    // Polling fallback: nothing can vouch for "unchanged", so the TTL alone decides and every read runs.
    assert.ok(afterTwo - before >= 1);
  }
});

test("the change bus says what moved per swarm and never publishes the harness's own bookkeeping", async () => {
  const bus = new ChangeBus(join(runsDir, "nowhere"), 5);
  const seen: BusMessage[] = [];
  bus.subscribe((m) => seen.push(m));
  const settle = () => new Promise((r) => setTimeout(r, 40));
  try {
    // One burst: a post on s1, a session append on s1, a proxy line on s2, a registry write.
    bus.touch("s1", "threads");
    bus.touch("s1", "sessions");
    bus.touch("s2", "logs");
    bus.touch(null, "registry");
    await settle();
    assert.equal(seen.length, 1, "one burst, one event");
    const change = seen[0];
    assert.equal(change.event, "change");
    if (change.event !== "change") return;
    assert.deepEqual(change.data.swarm_ids, ["s1"], "s2 was only touched by something nobody shows");
    assert.deepEqual(change.data.kinds, ["registry", "threads"]);
    assert.deepEqual(change.data.by_swarm, { s1: ["threads"] });
    assert.equal(bus.lastTouched("s1"), 1);
    assert.equal(bus.lastTouched("s2"), 0, "a suppressed kind does not move the change stamp either");
    // Bookkeeping alone: nothing goes out at all.
    bus.touch("s1", "internal");
    bus.touch("s1", "sessions");
    await settle();
    assert.equal(seen.length, 1, "no event for what the console cannot show");
    assert.equal(bus.lastTouched("s1"), 1);
    // Two kinds on one swarm in one burst are both named.
    bus.touch("s1", "events");
    bus.touch("s1", "locks");
    await settle();
    assert.equal(seen.length, 2);
    const second = seen[1];
    if (second.event !== "change") return;
    assert.deepEqual(second.data.by_swarm, { s1: ["events", "locks"] });
  } finally {
    bus.close();
  }
});

test("a burst ends after its last event, and a stream that never ends still flushes", async () => {
  const bus = new ChangeBus(join(runsDir, "nowhere"), 30, 120);
  const seen: BusMessage[] = [];
  bus.subscribe((m) => seen.push(m));
  const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));
  try {
    // Three events 15 ms apart: one logical write the filesystem reported in pieces.
    bus.touch("s1", "threads");
    await tick(15);
    bus.touch("s1", "threads");
    await tick(15);
    bus.touch("s1", "locks");
    await tick(60);
    assert.equal(seen.length, 1, "pieces of one write are one event");
    const first = seen[0];
    if (first.event === "change") assert.deepEqual(first.data.by_swarm, { s1: ["locks", "threads"] });
    // A steady stream, one event every 10 ms for 300 ms: flushes at the max wait, not never and not per event.
    seen.length = 0;
    for (let i = 0; i < 30; i++) {
      bus.touch("s1", "events");
      await tick(10);
    }
    await tick(60);
    assert.ok(seen.length >= 2 && seen.length <= 4, `a 300 ms stream at a 120 ms max wait flushed ${seen.length} times`);
  } finally {
    bus.close();
  }
});

test("a report of a path whose size and mtime did not move is not a change", async () => {
  // macOS reports one write several times over a second, and a sync client
  // touching attributes reports it again with the same bytes: each would be
  // a refetch on every open page for nothing.
  const dir = await mkdtemp(join(tmpdir(), "swarm-bus-"));
  // The window is what is under test, not how fast the machine is: at 5ms a
  // loaded CI runner can take longer than that between two file operations, and
  // the pair being coalesced lands in two windows instead of one.
  const bus = new ChangeBus(dir, 60);
  const seen: BusMessage[] = [];
  bus.subscribe((m) => seen.push(m));
  const settle = () => new Promise((r) => setTimeout(r, 300));
  try {
    await mkdir(join(dir, "s9", "threads", "main"), { recursive: true });
    const post = join(dir, "s9", "threads", "main", "000001-a.md");
    await writeFile(post, "one\n", "utf8");
    assert.equal(await bus.noteFsEvent("s9/threads/main/000001-a.md"), true, "first sight of a file is a change");
    assert.equal(await bus.noteFsEvent("s9/threads/main/000001-a.md"), false, "the same size and mtime again is not");
    assert.equal(await bus.noteFsEvent(join(dir, "s9/threads/main/000001-a.md")), false, "whether reported relative or absolute");
    await settle();
    assert.equal(seen.length, 1);
    await new Promise((r) => setTimeout(r, 10));
    await writeFile(post, "one\ntwo\n", "utf8");
    assert.equal(await bus.noteFsEvent("s9/threads/main/000001-a.md"), true, "an append is a change");
    await rm(post);
    assert.equal(await bus.noteFsEvent("s9/threads/main/000001-a.md"), true, "a removal is a change");
    assert.equal(await bus.noteFsEvent("s9/threads/main/000001-a.md"), false, "still gone: nothing new");
    assert.equal(await bus.noteFsEvent("s9/.pi-sessions/a/session.jsonl"), false, "a suppressed kind is never a change");
    await settle();
    assert.equal(seen.length, 2);
  } finally {
    bus.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("a kickoff from the console takes its isolation from the form, not from the console's environment", async () => {
  // A host form adds no --isolation; under an exported SWARM_ISOLATION=microvm
  // it became a VM run. The runner drops the variable, and the form decides.
  const dir = await mkdtemp(join(tmpdir(), "swarm-runner-iso-"));
  const was = process.env.SWARM_ISOLATION;
  try {
    const fake = join(dir, "fake-swarm.sh");
    await writeFile(fake, '#!/usr/bin/env bash\necho "ISOLATION=[${SWARM_ISOLATION:-unset}]"\n', "utf8");
    process.env.SWARM_ISOLATION = "microvm";
    const runner = new ActionRunner({ root: dir, runsDir: dir, swarmSh: fake });
    const job = runner.stop("sfake");
    const deadline = Date.now() + 10_000;
    while (runner.get(job.id)?.status === "running" && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const done = runner.get(job.id);
    assert.equal(done?.status, "ok", done?.stderr);
    assert.match(done!.stdout, /ISOLATION=\[unset\]/, "the console's SWARM_ISOLATION reached swarm.sh");
  } finally {
    if (was === undefined) delete process.env.SWARM_ISOLATION;
    else process.env.SWARM_ISOLATION = was;
    await rm(dir, { recursive: true, force: true });
  }
});

test("a swarm started from the console does not carry the console's token into the run", async () => {
  // The panes come out of this process tree, and a forged tool is agent-written
  // code: the token that starts, stops and reaps swarms must not travel with it.
  const dir = await mkdtemp(join(tmpdir(), "swarm-runner-"));
  try {
    const fake = join(dir, "fake-swarm.sh");
    await writeFile(fake, '#!/usr/bin/env bash\necho "TOKEN=[${SWARM_UI_TOKEN-unset}] RUNS=[${SWARM_RUNS_DIR-unset}] KEEP=[${DEEPSEEK_API_KEY-unset}]"\n', "utf8");
    const prevToken = process.env.SWARM_UI_TOKEN;
    const prevKey = process.env.DEEPSEEK_API_KEY;
    process.env.SWARM_UI_TOKEN = "console-token";
    process.env.DEEPSEEK_API_KEY = "sk-provider";
    try {
      const runner = new ActionRunner({ root: dir, runsDir: dir, swarmSh: fake });
      const job = runner.stop("sfake");
      const deadline = Date.now() + 10_000;
      while (runner.get(job.id)?.status === "running" && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      const done = runner.get(job.id);
      assert.equal(done?.status, "ok", done?.stderr);
      assert.match(done!.stdout, /TOKEN=\[unset\]/, "the console's token stays in the console");
      assert.match(done!.stdout, new RegExp(`RUNS=\\[${dir}\\]`), "the runs directory is still pinned");
      assert.match(done!.stdout, /KEEP=\[sk-provider\]/, "the rest of the environment is unchanged");
    } finally {
      if (prevToken === undefined) delete process.env.SWARM_UI_TOKEN;
      else process.env.SWARM_UI_TOKEN = prevToken;
      if (prevKey === undefined) delete process.env.DEEPSEEK_API_KEY;
      else process.env.DEEPSEEK_API_KEY = prevKey;
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the kickoff form takes installed packs by id and hands them to --pack; the server lists what pack.sh installed", async () => {
  const ok = validateStart({ n: 2, cap_usd: 1, model: "x/y", packs: ["windows-forensics", "memory-forensics", "windows-forensics"] });
  assert.ok(ok.ok);
  if (ok.ok) {
    assert.deepEqual(ok.params.packs, ["windows-forensics", "memory-forensics"], "a pack named twice is taken once");
    const argv = startArgv(ok.params);
    assert.deepEqual(argv.slice(argv.indexOf("--pack"), argv.indexOf("--pack") + 2), ["--pack", "windows-forensics,memory-forensics"]);
  }
  const bad = validateStart({ n: 2, cap_usd: 1, model: "x/y", packs: ["../etc"] });
  assert.equal(bad.ok, false);
  const none = validateStart({ n: 2, cap_usd: 1, model: "x/y", packs: [] });
  assert.ok(none.ok && none.params.packs === undefined && !startArgv(none.params).includes("--pack"));
  const home = await mkdtemp(join(tmpdir(), "ui-packs-"));
  await mkdir(join(home, "packs", "demo-pack"), { recursive: true });
  await writeFile(join(home, "packs", "demo-pack", "pack.json"), JSON.stringify({ id: "demo-pack", name: "Demo", version: "1.0.0", description: "d", depends: ["computer-forensics-base>=1.2.0"] }));
  await mkdir(join(home, "packs", "not-a-pack"), { recursive: true });
  assert.deepEqual(await listPacks(home), [{ id: "demo-pack", name: "Demo", version: "1.0.0", description: "d", depends: ["computer-forensics-base"] }]);
  await rm(home, { recursive: true, force: true });
});

test("the console refuses a host guard's setting for a microVM run, as the kickoff does", () => {
  const r = validateStart({ n: 2, cap_usd: 1, model: "x/y", isolation: "microvm", inputs: "case1", inputs_enforce: "on" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /microVM run has none/);
});

test("a run that failed at kickoff is failed, not unknown, and a hub-finished one without its sentinel is stopped", () => {
  assert.equal(derivePhase("failed", false), "failed");
  assert.equal(derivePhase("finished", false), "stopped");
  assert.equal(derivePhase("finished", true), "done");
  assert.equal(derivePhase("something-new", false), "unknown");
});

test("a VM run's VMs are shown from their records, with the live state only from this run's own hub", async () => {
  const base = await mkdtemp(join(tmpdir(), "ui-vms-"));
  const was = process.env.SWARM_HUBS_DIR;
  process.env.SWARM_HUBS_DIR = join(base, "dfirswarm-hubs");
  try {
    const sandbox = join(base, "sb");
    await mkdir(join(sandbox, "vm"), { recursive: true });
    await writeFile(join(sandbox, "vm", "a0.json"), JSON.stringify({
      agent: "a0", name: "dfs-r-a0", cpus: 2, memory_mib: 2048,
      image: { ref: "dfirswarm-disk:dev-arm64", manifest_digest: "sha256:aa", expected_digest: "sha256:aa" },
      probe: { hub: true, base: "ro", inputs: "ro", clock_skew_s: -0.4, fuse: false, loop: true, missing_binaries: [] },
      image_fit: { warnings: ["the image was built with cfb 1.2.1"], blockers: [] },
      installed_outside_image: { baseline: true, apt: { cowsay: "3.03" }, venv: {} },
      runtime: { name: "microsandbox", version: "0.7.2" },
    }));
    const hubs = join(base, "dfirswarm-hubs");
    const hub = join(hubs, "dfs-r.x");
    await mkdir(hub, { recursive: true });
    await writeFile(join(hub, "sandbox"), `${await realpath(sandbox)}\n`);
    await writeFile(join(hub, "status.json"), JSON.stringify({ agents: { a0: { state: "working", connected: true, since: "t" } } }));
    await writeFile(join(sandbox, "hub.dir"), `${await realpath(hub)}\n`);
    const [vm] = await vmHealth(sandbox);
    assert.deepEqual(vm.live, { state: "working", connected: true, since: "t", last_seen: null });
    assert.deepEqual(vm.image, { ref: "dfirswarm-disk:dev-arm64", digest: "sha256:aa", expected: "sha256:aa" });
    assert.equal(vm.probe.clock_skew_s, -0.4);
    assert.deepEqual(vm.installed_outside, ["apt cowsay 3.03"]);
    assert.deepEqual(vm.fit_warnings, ["the image was built with cfb 1.2.1"]);
    // hub.dir naming another sandbox's hub is not believed.
    await writeFile(join(hub, "sandbox"), "/somewhere/else\n");
    assert.equal((await vmHealth(sandbox))[0].live, null);
    assert.deepEqual(await vmHealth(join(base, "no-such")), [], "a host run has no VMs");
  } finally {
    if (was === undefined) delete process.env.SWARM_HUBS_DIR;
    else process.env.SWARM_HUBS_DIR = was;
    await rm(base, { recursive: true, force: true });
  }
});

test("under microVM the form's default copy of the evidence reaches the kickoff as --inputs-copy; bind stays a bind", () => {
  const argvOf = (extra: Record<string, unknown>) => {
    const r = validateStart({ n: 2, cap_usd: 1, model: "x/y", inputs: "brief", ...extra });
    assert.ok(r.ok, JSON.stringify(extra));
    return r.ok ? startArgv({ ...r.params, inputs_dir: "/evidence/brief" }) : [];
  };
  // The default and an explicit copy: without the flag the kickoff mounts the source in place.
  for (const extra of [{ isolation: "microvm" }, { isolation: "microvm", inputs_attach: "copy" }]) {
    const argv = argvOf(extra);
    assert.ok(argv.includes("--inputs-copy"), JSON.stringify(extra));
    assert.ok(!argv.includes("--inputs-bind"));
  }
  const bind = argvOf({ isolation: "microvm", inputs_attach: "bind" });
  assert.ok(bind.includes("--inputs-bind") && !bind.includes("--inputs-copy"));
  // A host run copies by default; the flag is a VM run's.
  const host = argvOf({});
  assert.ok(!host.includes("--inputs-copy") && !host.includes("--inputs-bind"));
});

test("OAuth in the VMs is a microVM run's switch, and reaches the kickoff as --allow-oauth-in-vm", () => {
  const on = validateStart({ n: 2, cap_usd: 1, model: "anthropic/claude-sonnet-4.5", isolation: "microvm", allow_oauth_in_vm: true });
  assert.ok(on.ok);
  if (on.ok) assert.ok(startArgv(on.params).includes("--allow-oauth-in-vm"));
  const off = validateStart({ n: 2, cap_usd: 1, model: "anthropic/claude-sonnet-4.5", isolation: "microvm" });
  assert.ok(off.ok && !startArgv(off.params).includes("--allow-oauth-in-vm"));
  const host = validateStart({ n: 2, cap_usd: 1, model: "anthropic/claude-sonnet-4.5", allow_oauth_in_vm: true });
  assert.equal(host.ok, false);
  if (!host.ok) assert.match(host.error, /allow_oauth_in_vm needs isolation microvm/);
});

test("provider hosts are provider=host as the kickoff checks them, one --provider-host each, in either mode", () => {
  const ok = validateStart({ n: 2, cap_usd: 1, model: "my-gw/m1", provider_hosts: ["my-gw=LLM.example.org", "llama=192.168.1.20:8000", "my-gw=LLM.example.org"] });
  assert.ok(ok.ok);
  if (ok.ok) {
    assert.deepEqual(ok.params.provider_hosts, ["my-gw=LLM.example.org", "llama=192.168.1.20:8000"], "an entry given twice is taken once");
    const argv = startArgv(ok.params);
    assert.deepEqual(
      argv.filter((a, i) => a === "--provider-host" || argv[i - 1] === "--provider-host"),
      ["--provider-host", "my-gw=LLM.example.org", "--provider-host", "llama=192.168.1.20:8000"],
    );
  }
  const typed = validateStart({ n: 2, cap_usd: 1, model: "x/y", isolation: "microvm", provider_hosts: "a=a.example.com, b=b.example.org" });
  assert.ok(typed.ok && typed.params.provider_hosts?.length === 2, "a typed list splits on commas and spaces");
  for (const bad of ["MyGW=llm.example.org", "gw", "gw=", "=llm.example.org", "gw=a=b.example.org", "gw=nodot", "gw=*.com", "-gw=llm.example.org"]) {
    const r = validateStart({ n: 2, cap_usd: 1, model: "x/y", provider_hosts: [bad] });
    assert.equal(r.ok, false, bad);
    if (!r.ok) assert.match(r.error, /provider_hosts/);
  }
  const many = validateStart({ n: 2, cap_usd: 1, model: "x/y", provider_hosts: Array.from({ length: 21 }, (_, i) => `p${i}=h${i}.example.org`) });
  assert.equal(many.ok, false);
});

test("readiness says what a VM kickoff would refuse: a subscription, a signing provider, a provider with no host", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ui-vmready-"));
  try {
    await writeFile(join(dir, "auth.json"), JSON.stringify({ anthropic: { type: "oauth" }, openai: { type: "api_key" } }));
    await writeFile(join(dir, "models.json"), JSON.stringify({ providers: { "my-gw": { baseUrl: "https://llm.example.org:8443/v1" }, lab: { baseUrl: "http://192.168.1.20:8000/v1", apiKey: "local" } } }));
    const opts = { agentDir: dir, env: {}, piHosts: async (m: string) => (m.startsWith("groq/") ? ["api.groq.com"] : []) };

    const sub = await vmReadiness("anthropic/claude-sonnet-4.5", undefined, opts);
    assert.deepEqual(sub.vm_blockers.map((b) => [b.kind, b.lifted_by]), [["oauth", "allow_oauth_in_vm"]]);
    assert.deepEqual(sub.vm_hosts, ["api.anthropic.com", "platform.claude.com"]);

    const key = await vmReadiness("openai/gpt-5.4", "api_key", opts);
    assert.deepEqual(key.vm_blockers, []);

    const signing = await vmReadiness("amazon-bedrock/claude", undefined, opts);
    assert.deepEqual(signing.vm_blockers.map((b) => [b.kind, b.lifted_by]), [["signing", undefined]], "nothing lifts a provider that signs its own requests");

    const unknown = await vmReadiness("mystery/m1", undefined, opts);
    assert.deepEqual(unknown.vm_blockers.map((b) => [b.kind, b.lifted_by]), [["unknown_host", "provider_hosts"]]);
    assert.match(unknown.vm_blockers[0].reason, /mystery=<the host/);

    assert.deepEqual((await vmReadiness("groq/llama", undefined, opts)).vm_blockers, [], "Pi's own list names the host");
    assert.deepEqual(await vmProviderHosts("my-gw/m1", opts), ["llm.example.org:8443"], "a models.json provider brings its base URL's host");
    assert.deepEqual(await vmReadiness("lab/qwen", undefined, opts), { vm_hosts: [], vm_blockers: [] }, "a local server goes through the host gateway");
    // Azure's resource comes from the shell, as the kickoff reads it.
    assert.deepEqual(await vmProviderHosts("azure-openai-responses/gpt", { ...opts, env: { AZURE_OPENAI_RESOURCE_NAME: "Contoso" } }), ["contoso.openai.azure.com"]);
    assert.equal((await vmReadiness("azure-openai-responses/gpt", undefined, opts)).vm_blockers[0]?.kind, "unknown_host");
    assert.equal(allowEntryOfUrl("http://127.0.0.1:8080/v1"), "127.0.0.1:8080");
    assert.equal(allowEntryOfUrl("https://api.example.org/v1"), "api.example.org");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("finish_failed and stop_incomplete are their own phases, sentinel or not, and the list says finishing while the hub puts the VMs away", async () => {
  assert.equal(derivePhase("finish_failed", true), "finish_failed");
  assert.equal(derivePhase("finish_failed", false), "finish_failed");
  assert.equal(derivePhase("stop_incomplete", true), "stop_incomplete", "a VM left up after a stop is said over the sentinel");
  assert.equal(derivePhase("stop_incomplete", false), "stop_incomplete");
  const dir = await mkdtemp(join(tmpdir(), "ui-finishing-"));
  try {
    const sandbox = join(dir, "sfin1");
    await mkdir(join(sandbox, "done"), { recursive: true });
    await mkdir(join(sandbox, "vm"), { recursive: true });
    await writeFile(join(sandbox, "done", "SWARM_DONE"), "---\nby: a0\n---\n");
    await writeFile(join(sandbox, "vm", "a0.json"), JSON.stringify({ agent: "a0" }));
    const registry = (state: string, mode = "microvm") => writeFile(join(dir, "registry.json"), JSON.stringify({ runs: [{ id: "sfin1", sandbox, state, isolation: { mode }, agents: ["a0"] }] }));
    const row = async () => (await listSwarmRows(dir)).find((r) => r.id === "sfin1")!;

    await registry("running");
    assert.deepEqual([(await row()).phase, (await row()).finishing], ["done", true], "the sentinel is written and a VM is not put away");
    await registry("running", "host");
    assert.equal((await row()).finishing, false, "a host run has no VMs to put away");
    await registry("running");
    await writeFile(join(sandbox, "vm", "a0.json"), JSON.stringify({ agent: "a0", stopped_at: "2026-09-24T10:00:00Z" }));
    assert.equal((await row()).finishing, false, "every VM is put away");
    await registry("finish_failed");
    assert.deepEqual([(await row()).phase, (await row()).finishing], ["finish_failed", false]);

    // The hub's own word: finished and not finish_done, while its process is
    // up, is finishing even after the registry says finished (custody runs then).
    const was = process.env.SWARM_HUBS_DIR;
    process.env.SWARM_HUBS_DIR = join(dir, "dfirswarm-hubs");
    try {
      const hub = join(dir, "dfirswarm-hubs", "dfs-sfin1.z");
      await mkdir(hub, { recursive: true });
      await writeFile(join(hub, "sandbox"), `${await realpath(sandbox)}\n`);
      await writeFile(join(sandbox, "hub.dir"), `${await realpath(hub)}\n`);
      await registry("finished");
      const hubStatus = (extra: Record<string, unknown>) => writeFile(join(hub, "status.json"), JSON.stringify({ at: new Date().toISOString(), pid: process.pid, agents: {}, ...extra }));
      await hubStatus({ finished: true, finish_done: false });
      assert.equal((await row()).finishing, true, "the hub is taking custody");
      await hubStatus({ finished: true, finish_done: true });
      assert.equal((await row()).finishing, false, "the hub is done");
      await hubStatus({ finished: true, finish_done: false, pid: 999_999_9 });
      assert.equal((await row()).finishing, false, "a dead hub's last word is not what is happening");
    } finally {
      if (was === undefined) delete process.env.SWARM_HUBS_DIR;
      else process.env.SWARM_HUBS_DIR = was;
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a VM run's hub is up only while its pid is this run's vm-hub.ts and the status is its own; last_seen, mounts, network and pack secrets are shown", async () => {
  const base = await mkdtemp(join(tmpdir(), "ui-hub-"));
  const was = process.env.SWARM_HUBS_DIR;
  process.env.SWARM_HUBS_DIR = join(base, "dfirswarm-hubs");
  let child: ReturnType<typeof spawn> | null = null;
  let keeper: ReturnType<typeof spawn> | null = null;
  try {
    const sandbox = join(base, "sb");
    await mkdir(join(sandbox, "vm"), { recursive: true });
    await writeFile(join(sandbox, "vm", "a0.json"), JSON.stringify({
      agent: "a0",
      mounts: [
        { host: "/runs/sb", guest: "/runs/sb", mode: "ro" },
        { host: "/runs/sb/work/a0", guest: "/runs/sb/work/a0", mode: "rw" },
        { host: "/runs/sb/work/a0/extracted", guest: "/runs/sb/work/a0/extracted", mode: "rw", noexec: true },
      ],
      network: { default: "deny", allow_hosts: ["api.openai.com"], host_ports: [] },
      secrets: [{ name: "openai (API key)", hosts: ["api.openai.com"] }, { name: "VT_KEY", hosts: ["www.virustotal.com"] }],
    }));
    const run = { id: "r", pack_secrets: { "memory-forensics": { names: ["VT_KEY"], mode: "injected" } } };

    // No hub.dir: no hub is recorded, and nothing is said about one.
    let [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, null);
    assert.deepEqual(vm.mounts, [
      { host: "/runs/sb", guest: "/runs/sb", mode: "ro", noexec: false },
      { host: "/runs/sb/work/a0", guest: "/runs/sb/work/a0", mode: "rw", noexec: false },
      { host: "/runs/sb/work/a0/extracted", guest: "/runs/sb/work/a0/extracted", mode: "rw", noexec: true },
    ]);
    assert.deepEqual(vm.network, { default: "deny", allow_hosts: ["api.openai.com"], host_ports: [] });
    assert.deepEqual(vm.secrets.map((s) => s.name), ["openai (API key)", "VT_KEY"]);
    assert.deepEqual(vm.pack_secrets, [{ pack: "memory-forensics", names: ["VT_KEY"], mode: "injected" }]);

    const hub = join(base, "dfirswarm-hubs", "dfs-r.y");
    await mkdir(hub, { recursive: true });
    const realHub = await realpath(hub);
    await writeFile(join(hub, "sandbox"), `${await realpath(sandbox)}\n`);
    await writeFile(join(sandbox, "hub.dir"), `${realHub}\n`);
    // A process whose command line is a hub's for this directory.
    child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "vm-hub.ts", "--dir", realHub], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 200));
    await writeFile(join(sandbox, "hub.pid"), `${child.pid}\n`);
    const status = (at: string) => writeFile(join(hub, "status.json"), JSON.stringify({ at, agents: { a0: { state: "working", connected: true, since: "t", last_seen: "2026-09-24T10:00:00.000Z" } } }));
    await status(new Date().toISOString());
    [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, true, vm.hub_detail ?? "");
    assert.equal(vm.live?.last_seen, "2026-09-24T10:00:00.000Z");
    assert.equal(typeof vm.hub_status_age_s, "number");

    // The pid is the hub's, but the status predates it: an earlier hub wrote it.
    await status(new Date(Date.now() - 3600_000).toISOString());
    [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, false);
    assert.match(vm.hub_detail ?? "", /has not written its status since it started/);
    assert.ok((vm.hub_status_age_s ?? 0) >= 3599, "how stale is said");

    // A status older than a pid file written long ago is the hub's own, however quiet.
    const old = new Date(Date.now() - 7200_000);
    await utimes(join(sandbox, "hub.pid"), old, old);
    assert.equal((await vmHealth(sandbox, run))[0].hub_alive, true, "no heartbeat: a quiet hub's status is old and that is fine");

    // A status that names its writer: the hub now in hub.pid, or another.
    await writeFile(join(hub, "status.json"), JSON.stringify({ at: new Date(Date.now() - 3600_000).toISOString(), pid: child.pid, finished: true, finish_done: false, agents: {} }));
    [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, true, "written by this hub, however long ago");
    assert.equal(vm.hub_finishing, true, "and it says it is putting the VMs away");
    await writeFile(join(hub, "status.json"), JSON.stringify({ at: new Date().toISOString(), pid: (child.pid ?? 0) + 1, agents: {} }));
    [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, false, "written by another process than the one hub.pid names");
    assert.match(vm.hub_detail ?? "", /an earlier hub's/);
    await status(new Date().toISOString());

    // The process ends: the hub is down, loudly, and the states are its last word.
    child.kill("SIGKILL");
    await new Promise((r) => child!.once("exit", r));
    [vm] = await vmHealth(sandbox, run);
    assert.equal(vm.hub_alive, false);
    assert.equal(vm.hub_tone, "danger");
    assert.equal(vm.hub_finishing, false, "a dead hub finishes nothing");
    assert.match(vm.hub_detail ?? "", /HUB DOWN/);
    assert.equal(vm.live?.state, "working");

    // With its keeper up it is being brought back: said, not shouted.
    keeper = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "hub-supervise.sh"], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 200));
    await writeFile(join(hub, "supervisor.pid"), `${keeper.pid}\n`);
    [vm] = await vmHealth(sandbox, run);
    assert.deepEqual([vm.hub_tone, vm.hub_keeper_alive], ["warn", true]);
    assert.match(vm.hub_detail ?? "", /its keeper \(pid \d+\) is up and brings it back/);
    // Once the stop has begun, a hub that is gone was ended on purpose.
    keeper.kill("SIGKILL");
    await new Promise((r) => keeper!.once("exit", r));
    await writeFile(join(hub, ".stop"), "");
    [vm] = await vmHealth(sandbox, run);
    assert.deepEqual([vm.hub_tone, vm.hub_stop_begun], ["warn", true]);
    await rm(join(hub, ".stop"));
    assert.equal((await vmHealth(sandbox, run))[0].hub_keeper_alive, false, "a keeper that is gone is said");

    // A pid that is alive but is not a hub (this test process) is not believed.
    await writeFile(join(sandbox, "hub.pid"), `${process.pid}\n`);
    assert.equal((await vmHealth(sandbox, run))[0].hub_alive, false);
  } finally {
    child?.kill("SIGKILL");
    keeper?.kill("SIGKILL");
    if (was === undefined) delete process.env.SWARM_HUBS_DIR;
    else process.env.SWARM_HUBS_DIR = was;
    await rm(base, { recursive: true, force: true });
  }
});

test("custody.json reaches the run's view whole: the verdict, the evidence counts, both chains, and every VM finding", async () => {
  const { body: before } = await get<{ summary: { sandbox: string }; custody: unknown }>("/api/swarms/s0d4e");
  const sandbox = before.summary.sandbox;
  const file = join(sandbox, "custody.json");
  // The stop test above may already have taken real custody of this run; it goes back as it was.
  const kept = await readFile(file, "utf8").catch(() => null);
  // So may its anchor, outside the run: set aside, so the hand-written
  // verdicts below are judged against the anchors this test writes.
  const anchorFile = join(await realpath(dirname(sandbox)), `${sandbox.split("/").pop()}.custody-anchor.json`);
  const keptAnchor = await readFile(anchorFile, "utf8").catch(() => null);
  await rm(anchorFile, { force: true });
  assert.equal(before.custody === null, kept === null, "the view has custody exactly when the run has custody.json");
  const custody = {
    at: "2026-09-24T10:00:00.000Z",
    run: "s0d4e",
    inputs: { files: 3, bytes: 30, unchanged: false, complete: false, changed: ["disk/a very long name that must not be cut short in any way.E01"], missing: [], added: ["x.txt"], skipped: ["big.raw"], manifest_sha256: "ab", manifest_anchored: true },
    sessions: { files: [], digest: "d", not_files: ["sessions/a0/link.jsonl"] },
    tool_outputs: { referenced: 2, verified: 2, missing: [], mismatched: [], refused: [] },
    trace: { lines: 40, intact: true, detail: "chain ok", unverified: 0, disputed: 0, spilled: [{ path: "p", lines: 2, agent: "a0", bad: 0, duplicates: 0 }, { path: "tool-output/a1/trace-spill.jsonl", lines: 0, agent: "a1", bad: 0, duplicates: 0, refused: "a link" }], gaps: [{ sid: "s", agent: "a1", missing: 3 }], clock: [] },
    ledger: { entries: 5, chained: 5, intact: false, detail: "broken at entry 4", missing_from_ledger: ["h1"], not_on_trace: [7] },
    vms: [{
      agent: "a0", record_sha256: "cc".repeat(32), image: "sha256:bb", expected_image: "sha256:aa", stopped: true, kept: null,
      snapshot: { path: "s", sha256: "h", verified: true, msb_verified: true }, logs: [],
      secret_violations: [{ at: "2026-09-24T09:00:00Z", env: "VT_KEY", host: "evil.example.org", method: "POST", path: "/x", action: "block" }],
      installed_outside: { apt: ["cowsay 3.03"], venv: [], note: null },
      runtime_changed: null,
    }],
    incomplete: null,
    summary: "EVIDENCE CHANGED: 1 changed, 0 missing, 1 added · LEDGER CHAIN BROKEN",
  };
  try {
    await writeFile(file, JSON.stringify(custody));
    const { body } = await get<{ custody: Record<string, any> }>("/api/swarms/s0d4e");
    const c = body.custody;
    assert.equal(c.verdict, "attention");
    assert.equal(c.summary, custody.summary);
    assert.deepEqual(c.evidence.changed, custody.inputs.changed, "names are whole");
    assert.deepEqual([c.evidence.files, c.evidence.added.length, c.evidence.skipped.length, c.evidence.complete], [3, 1, 1, false]);
    assert.deepEqual([c.trace.intact, c.trace.spilled, c.trace.lost], [true, 2, 3]);
    assert.deepEqual(c.trace.refused_spills, [{ path: "tool-output/a1/trace-spill.jsonl", why: "a link" }]);
    assert.deepEqual([c.ledger.intact, c.ledger.chained, c.ledger.missing_from_ledger, c.ledger.not_on_trace], [false, 5, ["h1"], [7]]);
    assert.deepEqual(c.sessions_not_files, ["sessions/a0/link.jsonl"]);
    assert.equal(c.vms[0].record_sha256, "cc".repeat(32));
    assert.equal(c.vms[0].image_differs, true);
    assert.equal(c.vms[0].secret_violations[0].host, "evil.example.org");
    assert.deepEqual(c.vms[0].installed_outside, ["apt cowsay 3.03"]);
    for (const want of [/evidence changed/, /not re-read before the deadline/, /not a file/, /3 trace lines lost/, /spill not read: tool-output\/a1/, /missing from the ledger/, /never on the trace.*seq 7/, /ledger chain broken/, /image digest differs/, /secret placeholder/, /installed outside the image/]) {
      assert.ok(c.problems.some((p: string) => want.test(p)), String(want));
    }

    // A clean one says so, and so does a link planted in its place.
    const clean = {
      ...custody,
      inputs: { ...custody.inputs, unchanged: true, complete: true, changed: [], added: [], skipped: [] },
      sessions: { ...custody.sessions, not_files: [] },
      trace: { ...custody.trace, gaps: [], spilled: [custody.trace.spilled[0]] },
      ledger: { entries: 5, chained: 5, intact: true, detail: "", missing_from_ledger: [], not_on_trace: [] },
      vms: [{ ...custody.vms[0], image: "sha256:aa", secret_violations: [], installed_outside: { apt: [], venv: [], note: null } }],
    };
    await writeFile(file, JSON.stringify(clean));
    assert.deepEqual((await readCustody(sandbox))?.problems, []);
    // Unchanged as far as it got is not unchanged: the deadline left files unread.
    await writeFile(file, JSON.stringify({ ...clean, inputs: { ...clean.inputs, unchanged: false, complete: false, skipped: ["big.raw"] } }));
    const partial = await readCustody(sandbox);
    assert.deepEqual(partial?.problems, ["evidence not fully re-hashed: 1 of 3 not re-read before the deadline, which the verdict does not cover"]);
    await writeFile(file, JSON.stringify(clean));
    assert.equal((await readCustody(sandbox))?.verdict, "clean");
    // Held to the verdict anchored outside the run: the one custody wrote
    // matches; a file edited after the stop is said not to.
    const sha = createHash("sha256").update(JSON.stringify(clean)).digest("hex");
    await writeFile(anchorFile, JSON.stringify({ run: "s0d4e", custody: [{ at: clean.at, sha256: sha }] }));
    const anchored = await readCustody(sandbox);
    assert.equal(anchored?.verdict, "clean");
    assert.match(anchored?.anchor ?? "", /^matches the verdict anchored outside the run/);
    await writeFile(file, JSON.stringify({ ...clean, summary: "evidence unchanged (edited after the stop)" }));
    const edited = await readCustody(sandbox);
    assert.equal(edited?.verdict, "attention");
    assert.match(edited?.problems[0] ?? "", /custody\.json DOES NOT MATCH the verdict anchored outside the run/);
    await rm(anchorFile, { force: true });
    await writeFile(file, JSON.stringify(clean));
    await rm(file);
    await symlink("/etc/hosts", file);
    const linked = await readCustody(sandbox);
    assert.equal(linked?.verdict, "attention");
    assert.match(linked?.problems[0] ?? "", /is a link/);
    await rm(file);
    assert.equal(await readCustody(sandbox), null, "no custody.json, no custody");
  } finally {
    await rm(file, { force: true });
    if (kept !== null) await writeFile(file, kept);
    await rm(anchorFile, { force: true });
    if (keptAnchor !== null) await writeFile(anchorFile, keptAnchor, { mode: 0o444 });
  }
});

test("an HTML artifact is framed with no scripts, and opened with them only once, by a grant the console asked for", async () => {
  // The default: the sandbox directive with no allow-scripts and no script-src.
  const plain = await get<string>("/api/swarms/sbe12/work/report.html");
  assert.equal(plain.status, 200);
  const csp = plain.headers.get("content-security-policy") ?? "";
  assert.match(csp, /^sandbox;/);
  assert.doesNotMatch(csp, /allow-scripts|script-src/);
  assert.match(csp, /connect-src 'none'/);
  assert.match(csp, /form-action 'none'/);

  const guarded = createUiApp({ root: ROOT, runsDir, distDir: join(runsDir, "no-dist"), token: "s3cret", heartbeatMs: 200, scriptGrantTtlMs: 300 });
  const { port } = await guarded.listen(0, "127.0.0.1");
  const at = `http://127.0.0.1:${port}`;
  const ask = (path: string, auth = true) =>
    fetch(`${at}/api/swarms/sbe12/work-scripts`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(auth ? { authorization: "Bearer s3cret" } : {}) },
      body: JSON.stringify({ path }),
    });
  const open = async (grant: string | null, path = "report.html") => {
    const res = await fetch(`${at}/api/swarms/sbe12/work/${path}${grant === null ? "" : `?scripts=${encodeURIComponent(grant)}`}`);
    await res.arrayBuffer();
    return { status: res.status, csp: res.headers.get("content-security-policy") ?? "", scripts: res.headers.get("x-artifact-scripts") };
  };
  const noScripts = (r: { csp: string }) => /^sandbox;/.test(r.csp) && !/allow-scripts|script-src/.test(r.csp);
  const traceHas = async (sha: string) => {
    const read = async (rel: string) => readFile(join(runsDir, "sbe12", rel), "utf8").catch(() => "");
    const lines = `${await read("traces/events.jsonl")}${await read("work/.trace-spill.jsonl")}`.split("\n").filter(Boolean);
    return lines.some((l) => {
      const e = JSON.parse(l) as { agent?: string; tool?: string; args?: { path?: string; sha256?: string } };
      return e.agent === "operator" && e.tool === "artifact_scripts" && e.args?.path === "work/report.html" && e.args?.sha256 === sha;
    });
  };
  try {
    // A grant needs the token: the artifact, framed with no scripts and no token, cannot mint one.
    assert.equal((await ask("work/report.html", false)).status, 401);
    // Only HTML is opened with its scripts.
    assert.equal((await ask("work/summary.md")).status, 400);

    // No grant, or one nobody issued: the no-script file.
    assert.ok(noScripts(await open(null)));
    assert.ok(noScripts(await open("made-up")), "an unknown grant serves the no-script file");

    // A valid grant: scripts on, still no same origin, no fetch, no forms.
    const granted = (await (await ask("work/report.html")).json()) as { grant: string; sha256: string };
    assert.match(granted.sha256, /^[0-9a-f]{64}$/);
    const on = await open(granted.grant);
    assert.equal(on.status, 200);
    assert.equal(on.scripts, "on");
    assert.match(on.csp, /^sandbox allow-scripts;/);
    assert.doesNotMatch(on.csp, /allow-same-origin|allow-top-navigation|allow-popups|allow-forms/);
    assert.match(on.csp, /connect-src 'none'/);
    assert.match(on.csp, /form-action 'none'/);
    assert.ok(await traceHas(granted.sha256), "opening with scripts is an operator action on the run's trace");

    // Spent: the same grant again serves the no-script file.
    const reused = await open(granted.grant);
    assert.equal(reused.scripts, "off");
    assert.ok(noScripts(reused), "a grant is single-use");

    // Bound to its path: presented for another file, it gives no scripts (and is spent).
    const other = (await (await ask("work/report.html")).json()) as { grant: string };
    const elsewhere = await open(other.grant, "summary.md");
    assert.ok(noScripts(elsewhere), "a grant for one file does not open another");
    assert.ok(noScripts(await open(other.grant)), "and it was spent by that attempt");

    // Bound to the bytes: a file changed since the grant gives no scripts.
    const before = (await (await ask("work/report.html")).json()) as { grant: string };
    const file = join(runsDir, "sbe12", "work", "report.html");
    const original = await readFile(file);
    await writeFile(file, Buffer.concat([original, Buffer.from("<!-- changed -->")]));
    try {
      assert.ok(noScripts(await open(before.grant)), "a grant is for the bytes the operator was shown");
    } finally {
      await writeFile(file, original);
    }

    // It lapses.
    const lapsed = (await (await ask("work/report.html")).json()) as { grant: string };
    await new Promise((r) => setTimeout(r, 400));
    assert.ok(noScripts(await open(lapsed.grant)), "an expired grant serves the no-script file");
  } finally {
    await guarded.close();
  }
});

test("a trace that is there and cannot be read is said so in the trace view, not shown as no traces", async () => {
  const base = await mkdtemp(join(tmpdir(), "ui-unread-"));
  try {
    await mkdir(join(base, "traces", "events.jsonl"), { recursive: true });
    const page = await queryTraces(base, {});
    assert.equal(page.total, 0);
    assert.equal(page.unreadable, "not a regular file");
    await rm(join(base, "traces", "events.jsonl"), { recursive: true });
    await writeFile(join(base, "traces", "events.jsonl"), `${JSON.stringify({ ts: "t", agent: "a0", tool: "bash", args: {}, result: {} })}\n`);
    const again = await queryTraces(base, {});
    assert.deepEqual([again.total, again.unreadable], [1, null]);
    const none = await queryTraces(join(base, "no-such"), {});
    assert.deepEqual([none.total, none.unreadable], [0, null], "no trace at all is not an unreadable one");
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("the console finds VM hubs where swarm.sh keeps them, and only in a directory of this user's that is not a link", async () => {
  const base = await mkdtemp(join(tmpdir(), "ui-hubs-parent-"));
  const was = process.env.SWARM_HUBS_DIR;
  try {
    const real = join(base, "hubs");
    await mkdir(real, { mode: 0o700 });
    process.env.SWARM_HUBS_DIR = real;
    assert.equal(await hubsParent(), await realpath(real));
    await symlink(real, join(base, "linked"));
    process.env.SWARM_HUBS_DIR = join(base, "linked");
    assert.equal(await hubsParent(), "", "a link is no hubs' parent");
    process.env.SWARM_HUBS_DIR = join(base, "missing");
    assert.equal(await hubsParent(), "");
    await writeFile(join(base, "file"), "");
    process.env.SWARM_HUBS_DIR = join(base, "file");
    assert.equal(await hubsParent(), "", "a file is no hubs' parent");
    // Unset, it is ~/.dfirswarm/hubs under DFIRSWARM_HOME.
    delete process.env.SWARM_HUBS_DIR;
    const home = process.env.DFIRSWARM_HOME;
    process.env.DFIRSWARM_HOME = base;
    await mkdir(join(base, "hubs2"), { mode: 0o700 });
    try {
      await rm(real, { recursive: true });
      await mkdir(join(base, "hubs"), { mode: 0o700 });
      assert.equal(await hubsParent(), await realpath(join(base, "hubs")));
    } finally {
      if (home === undefined) delete process.env.DFIRSWARM_HOME;
      else process.env.DFIRSWARM_HOME = home;
    }
  } finally {
    if (was === undefined) delete process.env.SWARM_HUBS_DIR;
    else process.env.SWARM_HUBS_DIR = was;
    await rm(base, { recursive: true, force: true });
  }
});
