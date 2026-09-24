/**
 * scripts/summary.ts against a hand-seeded sandbox. No model, no Herdr.
 *
 * The summary is what an examiner reads after a run, so the interesting
 * cases are the numbers it has to get right (spend by model, markers, the
 * harness signals on the trace, custody hashes) and a sandbox that has
 * almost nothing in it, which must still produce a page rather than throw.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { leadingCommand, summarize } from "../scripts/summary.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function seed(runs: string): Promise<string> {
  const sb = join(runs, "sum01");
  for (const dir of ["done/agents", "traces", "ledger", "work/sum0100", "work/extracted", "catalog", "inputs"]) {
    await mkdir(join(sb, dir), { recursive: true });
  }
  await writeFile(
    join(sb, "team.json"),
    JSON.stringify({
      swarm_id: "sum01",
      n: 3,
      agents: [
        { id: "sum0100", role: "worker", model: "openai/gpt-5.4" },
        { id: "sum0101", role: "worker", model: "openai/gpt-5.4" },
        { id: "sum0102", role: "worker", model: "deepseek/deepseek-v4-pro" },
      ],
    }),
  );
  // Two of the three said what they were taking on; the third never did.
  await writeFile(
    join(sb, "names.json"),
    JSON.stringify({
      names: [
        { id: "sum0100", name: "disk triage", doing: "the partition table and the file list", at: "2026-09-18T10:01:00.000Z" },
        { id: "sum0102", name: "critic", at: "2026-09-18T10:02:00.000Z" },
      ],
    }),
  );
  await writeFile(
    join(sb, "budget.json"),
    JSON.stringify({
      cap_usd: 20,
      spent_usd: 6.5,
      tokens: 120000,
      calls: 30,
      wall_clock_minutes: 60,
      started_at: "2026-09-18T10:00:00.000Z",
      source: "pi.sessionManager.getEntries",
      hard_kill: false,
      cap_steer_sent: false,
      cap_per_agent_usd: 12,
      cap_per_model_usd: { "openai/gpt-5.4": 10, "deepseek/deepseek-v4-pro": 1 },
      agents: {
        sum0100: { spent_usd: 3, tokens: 60000, calls: 14, input: 1, output: 1, cache_read: 0, cache_write: 0 },
        sum0101: { spent_usd: 2.5, tokens: 40000, calls: 10, input: 1, output: 1, cache_read: 0, cache_write: 0 },
        sum0102: { spent_usd: 1, tokens: 20000, calls: 6, input: 1, output: 1, cache_read: 0, cache_write: 0 },
      },
    }),
  );
  const events = [
    { ts: "2026-09-18T10:00:01.000Z", agent: "sum0100", tool: "agent_start", args: {}, result: { ok: true } },
    { ts: "2026-09-18T10:00:05.000Z", agent: "sum0100", tool: "bash", args: { command: "cd inputs && mmls disk.raw" }, result: { ok: true } },
    { ts: "2026-09-18T10:00:06.000Z", agent: "sum0100", tool: "bash", args: { command: "FOO=1 /opt/bin/mmls -B disk.raw" }, result: { ok: true } },
    { ts: "2026-09-18T10:00:07.000Z", agent: "sum0101", tool: "bash", args: { command: "vol -f mem.raw windows.pslist" }, result: { ok: true } },
    { ts: "2026-09-18T10:00:08.000Z", agent: "sum0100", tool: "claim_file", args: { path: "work/extracted/x.bin", reason: "bash write", implicit: true }, result: { ok: true, implicit: true } },
    { ts: "2026-09-18T10:00:09.000Z", agent: "sum0101", tool: "claim_violation", args: { tool: "bash", path: "work/report.md" }, result: { detected: true } },
    { ts: "2026-09-18T10:00:10.000Z", agent: "sum0101", tool: "make_tool", args: { name: "evtx_filter", runtime: "python3" }, result: { ok: true, forged: true } },
    { ts: "2026-09-18T10:00:11.000Z", agent: "sum0102", tool: "evtx_filter", args: {}, result: { ok: true } },
    { ts: "2026-09-18T10:00:12.000Z", agent: "sum0100", tool: "forge_hint", args: { command: "mmls" }, result: { runs: 8 } },
    { ts: "2026-09-18T10:00:13.000Z", agent: "sum0102", tool: "post", args: { thread: "main" }, result: { ok: true } },
    { ts: "2026-09-18T10:30:00.000Z", agent: "sum0102", tool: "inputs_check", args: {}, result: { ok: true, checked: 2, modified: [], missing: [], added: [] } },
    { ts: "2026-09-18T10:30:01.000Z", agent: "sum0102", tool: "sentinel_nudge", args: { peers: ["sum0100", "sum0101"] }, result: { reached: ["sum0100"], missed: ["sum0101"] } },
  ];
  await writeFile(join(sb, "traces", "events.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
  await writeFile(join(sb, "done", "SWARM_DONE"), "---\nby: sum0102\noutput: work/report.md\nreason: report signed off\nat: 2026-09-18T10:30:00.000Z\n---\n\nCollective finished.\n");
  await writeFile(join(sb, "done", "agents", "sum0102.done"), "---\nby: sum0102\noutput: work/report.md\nreason: report signed off\nat: 2026-09-18T10:30:00.000Z\n---\n");
  await writeFile(join(sb, "done", "agents", "sum0101.dead"), "---\nby: reaper\nreason: stalled\nat: 2026-09-18T10:29:00.000Z\n---\n");
  const ledger = [
    { seq: 1, kind: "event", ts: "2026-09-18T09:00:00.000Z", value: "Attacker logged in as admin", source: "Security.evtx", evidence: "record 4624/7", by: "sum0101", authors: ["sum0101"], at: "2026-09-18T10:00:20.000Z" },
    { seq: 2, kind: "event", ts: "2026-09-18T08:30:00.000Z", value: "Web shell written to wwwroot", source: "$MFT", evidence: "inode 5555", by: "sum0100", authors: ["sum0100"], at: "2026-09-18T10:00:21.000Z" },
    { seq: 3, kind: "ioc", value: "192.0.2.10", source: "IIS log", evidence: "u_ex150902.log line 88", confidence: "high", by: "sum0100", authors: ["sum0100"], at: "2026-09-18T10:00:22.000Z" },
  ];
  await writeFile(join(sb, "ledger", "entries.jsonl"), ledger.map((e) => JSON.stringify(e)).join("\n") + "\n");
  await writeFile(join(sb, "work", "report.md"), "# Report\n\nfindings\n");
  await writeFile(join(sb, "work", "notes.txt"), "scratch shared\n");
  await writeFile(join(sb, "work", "extracted", "x.bin"), "binary\n");
  await writeFile(join(sb, "work", "sum0100", "scratch.txt"), "mine\n");
  await writeFile(join(sb, "work", "sum0100", "more.txt"), "mine too\n");
  await writeFile(
    join(sb, "inputs.json"),
    JSON.stringify({
      source: "/cases/one",
      copied_at: "2026-09-18T09:59:00.000Z",
      files: [
        { path: "inputs/disk.raw", bytes: 1024, sha256: "a".repeat(64) },
        { path: "inputs/mem.raw", bytes: 2048, sha256: "b".repeat(64) },
      ],
      bytes: 3072,
      enforce: "auto",
      guard: "seatbelt",
    }),
  );
  await writeFile(
    join(sb, "toolbox.json"),
    JSON.stringify({ preset: "dfir", checked_at: "2026-09-18T09:59:30.000Z", present: [{ name: "mmls", version: "4.15", use: "partitions" }], missing: [{ name: "yara", use: "sweeps", install: "brew install yara" }] }),
  );
  await writeFile(join(sb, "catalog", "README.md"), "Summary: 1 disk image(s), 1 memory image(s), 9 catalog file(s)\n\n| File | What | Rows | Size |\n");
  await writeFile(
    join(runs, "registry.json"),
    JSON.stringify({
      runs: [
        { id: "other", label: "not this one", sandbox: join(runs, "other") },
        {
          id: "sum01",
          label: "summary-fixture",
          state: "done",
          sandbox: sb,
          n: 3,
          model: "2xopenai/gpt-5.4 + 1xdeepseek/deepseek-v4-pro",
          cap_usd: 20,
          cap_per_agent_usd: 12,
          case_id: "CASE-0001",
          examiner: "Jane Examiner",
          catalog: true,
          toolbox: "dfir",
          quarantine: true,
          allow_hosts: "isf-server.techanarchy.net",
        },
      ],
    }),
  );
  return sb;
}

test("summary: a seeded sandbox produces every section with the right numbers", async () => {
  const runs = await mkdtemp(join(tmpdir(), "summary."));
  try {
    const sb = await seed(runs);
    const text = await summarize(sb);
    const headings = text.split("\n").filter((l) => l.startsWith("## ")).map((l) => l.slice(3));
    assert.deepEqual(headings, ["Outcome", "Team", "Activity", "Ledger", "Work", "Custody"]);
    assert.match(text, /^# Run summary: sum01 — summary-fixture/m);
    assert.match(text, /State: done · sentinel present/);
    assert.match(text, /Duration: 30m 0s/);
    assert.match(text, /Case: CASE-0001 · Examiner: Jane Examiner/);
    assert.match(text, /catalog · toolbox dfir · quarantine · allow-host isf-server\.techanarchy\.net/);
    // outcome
    assert.match(text, /Sentinel `done\/SWARM_DONE` by \*\*sum0102\*\* at 2026-09-18T10:30:00\.000Z: report signed off/);
    assert.match(text, /\| sum0101 \| dead \| 2026-09-18T10:29:00\.000Z \| stalled \|/);
    assert.match(text, /\| sum0100 \| — \|/);
    assert.match(text, /2 of 3 agents marked \(1 reaped: sum0101\); without a marker: sum0100/);
    // team and by-model
    // The name is the agent's own: nothing in this fixture assigned it.
    assert.match(text, /\| sum0100 \| disk triage — the partition table and the file list \| worker \| openai\/gpt-5\.4 \| \$3\.00 \| 14 \| 60,000 \|/);
    assert.match(text, /\| sum0102 \| critic \| worker \| deepseek\/deepseek-v4-pro \|/, "an agent that gave no reason still shows its name");
    assert.match(text, /\| sum0101 \|  \| worker \|/, "an agent that never named itself has an empty cell");
    assert.match(text, /\| openai\/gpt-5\.4 \| \$5\.50 \| 85% \| 24 \| 2 \(sum0100, sum0101\) \|/);
    assert.match(text, /\| deepseek\/deepseek-v4-pro \| \$1\.00 \| 15% \| 6 \| 1 \(sum0102\) \|/);
    assert.match(text, /Spent \$6\.50 of a \$20\.00 cap, \$12\.00 per agent; 30 provider calls, 120,000 tokens\./);
    // A model's cap is read against its agents' spend together, and one at its cap is said to be over it.
    assert.match(text, /Per-model caps: deepseek\/deepseek-v4-pro spent \$1\.00 of its \$1\.00 cap and is over it; openai\/gpt-5\.4 spent \$5\.50 of its \$10\.00 cap\./);
    // activity
    assert.match(text, /12 trace events from 2026-09-18T10:00:01\.000Z to 2026-09-18T10:30:01\.000Z/);
    assert.match(text, /\| claim violations \| 1 \|/);
    assert.match(text, /\| implicit claims \(shell writes turned into claims\) \| 1 \|/);
    assert.match(text, /\| inputs checks \| 1 \|/);
    assert.match(text, /\| forge hints \| 1 \|/);
    assert.match(text, /\| sentinel nudges \| 1 \|/);
    assert.match(text, /\| bash calls \| 3 \|/);
    assert.match(text, /- `evtx_filter` by sum0101 at 2026-09-18T10:00:10\.000Z \(python3; called 1 time\)/);
    assert.match(text, /\| `mmls` \| 2 \|/);
    assert.match(text, /\| `vol` \| 1 \|/);
    // ledger: events in time order, the earlier one first
    assert.match(text, /3 entries: 2 events, 1 indicators, 0 findings/);
    const shell = text.indexOf("Web shell written to wwwroot");
    const login = text.indexOf("Attacker logged in as admin");
    assert.ok(shell > 0 && login > shell, "ledger events must be in time order");
    // work: top-level md first, scratch dir collapsed
    const report = text.indexOf("`work/report.md`");
    const notes = text.indexOf("`work/notes.txt`");
    const extracted = text.indexOf("`work/extracted/x.bin`");
    assert.ok(report > 0 && report < notes && report < extracted, "report.md is listed first");
    assert.match(text, /\| `work\/sum0100\/` \(scratch of sum0100\) \| 2 files, 14 B \|/);
    assert.doesNotMatch(text, /work\/sum0100\/scratch\.txt/);
    // custody
    assert.match(text, /Inputs copied from `\/cases\/one` 2026-09-18T09:59:00\.000Z: 2 files, 3\.0 KB; enforcement asked auto, kickoff guard seatbelt\./);
    assert.match(text, /No host custody was taken yet/, "without custody.json the summary says the agents' word is all there is");
    assert.match(text, new RegExp(`\\| \`inputs/disk\\.raw\` \\| 1,024 \\| \`${"a".repeat(64)}\` \\|`));
    assert.match(text, /\| 2026-09-18T10:30:00\.000Z \| sum0102 \| intact: 2 checked, 0 modified, 0 missing, 0 added \|/);
    assert.match(text, /Toolbox \(dfir\): 1 present — mmls \(4\.15\); 1 missing — yara\./);
    assert.match(text, /Evidence catalog: 1 disk image\(s\), 1 memory image\(s\), 9 catalog file\(s\)\./);
    // the CLI prints the same page
    const cli = execFileSync("node", ["--experimental-strip-types", join(ROOT, "scripts", "summary.ts"), sb], {
      encoding: "utf8",
      env: { ...process.env, SWARM_RUNS_DIR: runs },
      stdio: ["ignore", "pipe", "ignore"],
    });
    assert.equal(cli, text);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("summary: a sandbox with only team.json still gets a page", async () => {
  const runs = await mkdtemp(join(tmpdir(), "summary."));
  try {
    const sb = join(runs, "bare");
    await mkdir(sb, { recursive: true });
    await writeFile(join(sb, "team.json"), JSON.stringify({ swarm_id: "bare", n: 1, agents: [{ id: "bare00", role: "worker" }] }));
    const text = await summarize(sb);
    assert.match(text, /^# Run summary: bare/m);
    assert.match(text, /State: unknown \(no registry entry\) · sentinel absent/);
    assert.match(text, /No sentinel: the swarm has not finished/);
    assert.match(text, /\| bare00 \| — \|/);
    assert.match(text, /0 trace events\./);
    assert.match(text, /No ledger: nothing was recorded/);
    assert.match(text, /work\/ is empty\./);
    assert.match(text, /No read-only inputs were given to this swarm\./);
    // an empty directory, not even team.json, does not throw either
    const empty = join(runs, "empty");
    await mkdir(empty, { recursive: true });
    const bare = await summarize(empty);
    assert.match(bare, /No team\.json: no agents to report on\./);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("summary: a team of local models is described in tokens, never as $0.00 spent", async () => {
  const runs = await mkdtemp(join(tmpdir(), "summary."));
  try {
    const sb = join(runs, "free");
    await mkdir(sb, { recursive: true });
    await writeFile(
      join(sb, "team.json"),
      JSON.stringify({
        swarm_id: "free",
        n: 2,
        agents: [
          { id: "free00", role: "worker", model: "ollama/qwen3:8b" },
          { id: "free01", role: "worker", model: "ollama/qwen3:8b" },
        ],
      }),
    );
    await writeFile(
      join(sb, "budget.json"),
      JSON.stringify({
        cap_usd: 0,
        spent_usd: 0,
        tokens: 300000,
        calls: 40,
        wall_clock_minutes: 30,
        started_at: "2026-09-19T10:00:00.000Z",
        source: "pi.sessionManager.getEntries",
        hard_kill: false,
        cap_steer_sent: false,
        metered: false,
        cap_tokens: 5000000,
        agents: {
          free00: { spent_usd: 0, tokens: 200000, calls: 25, input: 1, output: 1, cache_read: 0, cache_write: 0 },
          free01: { spent_usd: 0, tokens: 100000, calls: 15, input: 1, output: 1, cache_read: 0, cache_write: 0 },
        },
      }),
    );
    const text = await summarize(sb);
    assert.match(text, /No metered cost: every model on this team is local\. 300,000 tokens of a 5,000,000-token cap; 40 provider calls, 300,000 tokens\./);
    assert.doesNotMatch(text, /Spent \$0\.00/);
    assert.match(text, /\| free00 \| .* \| free \| 25 \| 200,000 \|/);
    assert.match(text, /\| ollama\/qwen3:8b \| free \| 100% \| 40 \| 2 \(free00, free01\) \|/);
  } finally {
    await rm(runs, { recursive: true, force: true });
  }
});

test("summary: the leading command ignores env prefixes, cd chains and paths", () => {
  assert.equal(leadingCommand("cd inputs && mmls disk.raw"), "mmls");
  assert.equal(leadingCommand("FOO=1 BAR=2 /opt/bin/vol -f x"), "vol");
  assert.equal(leadingCommand("  python3 tool.py"), "python3");
  assert.equal(leadingCommand("$(evil)"), "");
});
