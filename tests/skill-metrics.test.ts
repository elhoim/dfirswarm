/**
 * What a run did with its skills, read from the trace alone
 * (ui/src/lib/skill-metrics.ts): the code the context audit and the console's
 * Packs tab share. A hand-made trace with every case the record can show: a
 * seat that never loaded one, a load a later row uses by name, one it uses by
 * a tool its front matter names, one nothing shows used, a body a compaction
 * took out and the seat loaded again, a miss, an answer that the body was
 * already held, and a seat whose prompt never carried the index.
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { audit, readRows, renderMarkdown, skillFindings } from "../scripts/context-audit.ts";
import { carriedSkills, skillUse, type SkillTraceRow } from "../ui/src/lib/skill-metrics.ts";

let clock = 0;
const row = (agent: string, tool: string, args: Record<string, unknown>, result: Record<string, unknown> = {}): SkillTraceRow => ({
  ts: `2026-10-07T10:00:${String(clock++).padStart(2, "0")}.000Z`,
  agent,
  tool,
  args,
  result,
});

const load = (agent: string, id: string, extra: Record<string, unknown> = {}) =>
  row(agent, "skill", { id }, { ok: true, pack: "pack-a", bytes: 2_000, sha256: `sha-${id}`, tokens: 500, tools: [], needs: [], ...extra });

function trace(): SkillTraceRow[] {
  clock = 0;
  return [
    row("s0", "skills_index", {}, { ok: true, section_tokens: 900, shown_tokens: 800 }),
    row("s1", "skills_index", {}, { ok: true, section_tokens: 900, shown_tokens: 800 }),
    row("s2", "skills_index", {}, { ok: true, section_tokens: 900, shown_tokens: 800 }),
    // s0: three loads. One is named later, one is used through a tool its front matter names, one nothing shows used.
    load("s0", "execution/prefetch", { tools: ["prefetch_mam"] }),
    load("s0", "registry/devices"),
    load("s0", "logs/security", { tokens: 700 }),
    row("s0", "bash", { command: "prefetch_mam /evidence/a.pf" }, { ok: true }),
    row("s0", "post", { body: "From registry/devices: the USB serial matches." }, { ok: true }),
    row("s0", "skill_done", { id: "registry/devices", note: "device serials" }, { ok: true, turn: 9 }),
    // A compaction: all three are summarised out. The seat loads one again, with the flag the harness writes.
    row("s0", "compact_done", { via: "self", reason: "threshold" }, { ok: true, cycle: 1, tokens_before: 160_000 }),
    load("s0", "registry/devices", { reload_after_compaction: true }),
    // s1: a miss, an answer that it already holds the body, an index read, then one load nothing shows used.
    row("s1", "skill", { id: "windows/execution/prefetch" }, { ok: false, error: "no such skill" }),
    load("s1", "execution/prefetch", { tools: ["prefetch_mam"] }),
    row("s1", "skill", { id: "execution/prefetch" }, { ok: true, already_loaded: true, loaded_at_turn: 3, tokens_saved: 500 }),
    row("s1", "skill", { id: "INDEX" }, { ok: true, in_prompt: false }),
    row("s1", "thinking", {}, { text: "nothing to do with prefetch here, the registry is empty", chars: 50 }),
    // s2 never touches a skill. s3 is a seat with no index row and no load.
    row("s2", "bash", { command: "ls" }, { ok: true }),
    row("s3", "bash", { command: "ls" }, { ok: true }),
    row("system", "reap", {}, { ok: true }),
  ];
}

test("per seat: loads, tokens, used after load, no trace of use, done, lost at a compaction, loaded again, misses", () => {
  const use = skillUse(trace(), ["s0", "s1", "s2", "s3"]);
  const s0 = use.seats.find((s) => s.agent === "s0")!;
  assert.deepEqual([s0.index_in_prompt, s0.index_tokens], [true, 900]);
  assert.equal(s0.loads, 4, "three, and the reload");
  assert.equal(s0.distinct, 3);
  assert.equal(s0.tokens_loaded, 500 + 500 + 700 + 500);
  // prefetch is used through its tool, devices by name; logs/security by nothing; the reload of devices has nothing after it.
  assert.deepEqual(s0.detail.map((d) => [d.id, d.referenced]), [["execution/prefetch", true], ["registry/devices", true], ["logs/security", false], ["registry/devices", false]]);
  assert.equal(s0.referenced, 2);
  assert.equal(s0.unused, 2);
  assert.equal(s0.done, 1);
  assert.equal(s0.compactions, 1);
  assert.equal(s0.lost_at_compaction, 3, "the three loaded before the compaction");
  assert.equal(s0.refetched, 1, "one load after it, of a note it held before");
  assert.deepEqual(s0.detail.filter((d) => d.lost_at_compaction).map((d) => [d.id, d.refetched]), [["execution/prefetch", false], ["registry/devices", true], ["logs/security", false]]);
  assert.deepEqual(s0.detail.filter((d) => d.done).map((d) => d.id), ["registry/devices"]);

  const s1 = use.seats.find((s) => s.agent === "s1")!;
  assert.deepEqual([s1.loads, s1.already_loaded, s1.failed, s1.index_reads], [1, 1, 1, 1]);
  assert.equal(s1.referenced, 0, "a reasoning row that says 'prefetch' is not the id, and the tool was never called");
  assert.equal(s1.unused, 1);

  const s2 = use.seats.find((s) => s.agent === "s2")!;
  assert.deepEqual([s2.index_in_prompt, s2.loads], [true, 0]);
  const s3 = use.seats.find((s) => s.agent === "s3")!;
  assert.deepEqual([s3.index_in_prompt, s3.loads], [false, 0], "a seat with no skills_index row did not get the index");

  assert.deepEqual(use.totals, {
    seats: 4,
    seats_with_index: 3,
    seats_that_loaded: 2,
    loads: 5,
    tokens_loaded: 2_700,
    done: 1,
    referenced: 2,
    unused: 3,
    lost_at_compaction: 3,
    refetched: 1,
    already_loaded: 1,
    failed: 1,
    index_reads: 1,
  });
});

test("a use by a tool the skill names counts only as a whole word, and a later mention of the id by another seat is not this seat's", () => {
  clock = 0;
  const rows = [
    load("a", "n/one", { tools: ["mam"] }),
    row("a", "bash", { command: "mammoth --list" }, { ok: true }),
    load("b", "n/one", { tools: ["mam"] }),
    row("a", "post", { body: "n/one says so" }, { ok: true }),
    row("b", "bash", { command: "echo nothing" }, { ok: true }),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.seats.map((s) => [s.agent, s.referenced]), [["a", 1], ["b", 0]], "mammoth is not mam; seat a's post is not seat b's use");
});

test("the per-skill rollup counts loads, tokens and the seats over the whole trace, keyed by pack and id", () => {
  clock = 0;
  const rows = [
    load("a", "shared/dup", { pack: "p1", tokens: 100 }),
    load("b", "shared/dup", { pack: "p2", tokens: 200 }),
    load("c", "shared/dup", { pack: "p1", tokens: 100 }),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.by_skill.map((r) => [r.key, r.loads, r.tokens, r.agents]), [["p1:shared/dup", 2, 200, ["a", "c"]], ["p2:shared/dup", 1, 200, ["b"]]]);
  assert.equal(carriedSkills(rows), true);
  assert.equal(carriedSkills([row("a", "bash", {})]), false);
});

test("a row from before the harness wrote the pack, the hash and the tokens still counts, from its bytes", () => {
  clock = 0;
  const old = row("a", "skill", { id: "x/y" }, { ok: true, bytes: 4_245 });
  const use = skillUse([old]);
  assert.equal(use.seats[0]!.tokens_loaded, 1_000);
  assert.deepEqual(use.by_skill.map((r) => r.key), ["x/y"]);
});

test("the context audit carries the skills: a table, findings that name the seats the index missed, and the JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "skill-audit-"));
  const file = join(dir, "events.jsonl");
  const seat = (agent: string): SkillTraceRow[] => [
    row(agent, "compact_config", { defaults: true }, { ok: true, model: "x/m", window: 200_000, ceiling: 200_000, notice: 80_000, warning: 100_000, compact: 120_000 }),
    row(agent, "context", {}, { ok: true, tokens: 20_000, ceiling: 200_000 }),
  ];
  const rows = [...trace().filter((r) => ["s0", "s1"].includes(r.agent)), ...seat("s0"), ...seat("s1"), ...seat("s2"), ...seat("s3"), row("s2", "skills_index", {}, { ok: true, section_tokens: 900 })];
  writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n"));
  const read = readRows(file);
  const run = audit(read.rows, file, read.bad);
  assert.deepEqual(run.agents.map((a) => a.agent), ["s0", "s1", "s2", "s3"]);
  assert.equal(run.skills.totals.loads, 5);
  assert.equal(run.agents.find((a) => a.agent === "s0")!.skills.loads, 4);
  const f = run.findings.join("\n");
  assert.match(f, /3 of 4 seats had the Skills section in their prompt; s3 did not \(no `skills_index` row\)/);
  assert.match(f, /Skills: 5 bodies loaded by 2 of 4 seats \(2,700 tokens\); 2 seats never loaded one\./);
  assert.match(f, /Of those loads, 2 show a later use .* and 3 show none \(a proxy.*1 was marked done with skill_done\./);
  assert.match(f, /3 loaded bodies were followed by a compaction, which summarised them out of the seat's context; 1 was loaded again\./);
  assert.match(f, /1 call asked for a body the seat already held and was told so/);
  assert.match(f, /1 skill call named no skill the packs carry\./);
  const md = renderMarkdown(run);
  assert.match(md, /## Skills\n\n\| Agent \| Index in prompt \| Loads \|/);
  assert.match(md, /\| s0 \| yes \(900 tokens\) \| 4 \| 3 \| 2,200 \| 2 \| 2 \| 1 \| 3 \| 1 \| 0 \|/);
  assert.match(md, /\| s1 \| yes \(900 tokens\) \| 1 \| 1 \| 500 \| 0 \| 1 \| 0 \| 0 \| 0 \| 1 \|/);
  // A run with no skill row says nothing about skills.
  const quiet = audit(readRows(file).rows.filter((r) => !r.tool.startsWith("skill")), file);
  assert.deepEqual(skillFindings(quiet.skills), []);
  assert.ok(!renderMarkdown(quiet).includes("## Skills"));
});

test("a run with self-compaction off still gets its skill findings, from the seats the trace shows", () => {
  clock = 0;
  const rows = [
    row("a0", "agent_start", {}, { ok: true }),
    row("a1", "agent_start", {}, { ok: true }),
    row("system", "reap", {}, { ok: true }),
    row("a0", "skills_index", {}, { ok: true, section_tokens: 600 }),
    load("a0", "execution/prefetch"),
  ];
  const use = skillUse(rows);
  assert.deepEqual(use.seats.map((s) => s.agent), ["a0", "a1"], "the watchdog is not a seat");
  const run = audit(rows.map((r) => ({ ts: r.ts, agent: r.agent, tool: r.tool, args: (r.args ?? {}) as Record<string, unknown>, result: (r.result ?? {}) as Record<string, unknown> })), "x");
  assert.deepEqual(run.skills.seats.map((s) => s.agent), ["a0", "a1"]);
  assert.match(run.findings.join("\n"), /No `context` rows/);
  assert.match(run.findings.join("\n"), /1 of 2 seats had the Skills section in their prompt; a1 did not/);
  assert.match(run.findings.join("\n"), /Skills: 1 body loaded by 1 of 2 seats/);
});
