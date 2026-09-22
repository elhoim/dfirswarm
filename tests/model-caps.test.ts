/**
 * The per-model cap: a ceiling on the combined spend of every agent running
 * one model, for a mixed team where the cost is in the model rather than the
 * seat. No model, no Herdr, no keys — the pressure is read from the budget
 * record alone, and the record has to keep the cap and each seat's model
 * through every fold of session usage.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  agentPressure,
  applySessionUsage,
  initSandbox,
  modelPressure,
  normalizeBudget,
  readBudget,
  writeBudget,
  type AgentBudget,
  type BudgetRecord,
} from "../extensions/protocol.ts";

function seat(model: string | undefined, spent: number): AgentBudget {
  return { spent_usd: spent, tokens: 0, calls: 0, input: 0, output: 0, cache_read: 0, cache_write: 0, ...(model ? { model } : {}) };
}

function budget(agents: Record<string, AgentBudget>, caps?: Record<string, number>): BudgetRecord {
  return {
    cap_usd: 40,
    spent_usd: Object.values(agents).reduce((sum, a) => sum + a.spent_usd, 0),
    tokens: 0,
    calls: 0,
    wall_clock_minutes: 60,
    started_at: "2026-01-01T00:00:00Z",
    source: "test",
    hard_kill: false,
    cap_steer_sent: false,
    ...(caps ? { cap_per_model_usd: caps } : {}),
    agents,
  };
}

const MINI = "openai/gpt-5.4-mini";
const NANO = "openai/gpt-5.4-nano";

test("per-model cap: the pressure is the model's agents together, under, at and over", () => {
  const under = budget({ a00: seat(MINI, 2), a01: seat(MINI, 3.5), a02: seat(NANO, 3.9) }, { [MINI]: 6, [NANO]: 4 });
  assert.deepEqual(modelPressure(under, MINI), { over: false, spent_usd: 5.5, cap_usd: 6, agents: 2 });
  const at = budget({ a00: seat(MINI, 2), a01: seat(MINI, 4), a02: seat(NANO, 1) }, { [MINI]: 6, [NANO]: 4 });
  assert.deepEqual(modelPressure(at, MINI), { over: true, spent_usd: 6, cap_usd: 6, agents: 2 }, "at the cap is over it, as the per-agent cap reads it");
  const over = budget({ a00: seat(MINI, 2.5), a01: seat(MINI, 4), a02: seat(NANO, 1) }, { [MINI]: 6, [NANO]: 4 });
  assert.deepEqual(modelPressure(over, MINI), { over: true, spent_usd: 6.5, cap_usd: 6, agents: 2 });
  assert.deepEqual(modelPressure(over, NANO), { over: false, spent_usd: 1, cap_usd: 4, agents: 1 }, "the other model's agents go on");
});

test("per-model cap: a model with no cap is never over, and another model's spend does not count", () => {
  const b = budget({ a00: seat(MINI, 50), a01: seat(NANO, 0.5), a02: seat(NANO, 0.5) }, { [NANO]: 4 });
  assert.deepEqual(modelPressure(b, MINI), { over: false, spent_usd: 50, cap_usd: 0, agents: 1 }, "no cap on the model, nothing to be over");
  assert.deepEqual(modelPressure(b, NANO), { over: false, spent_usd: 1, cap_usd: 4, agents: 2 }, "the $50 on the other model is not nano's");
  assert.deepEqual(modelPressure(budget({ a00: seat(MINI, 9) }), MINI), { over: false, spent_usd: 9, cap_usd: 0, agents: 1 }, "a swarm without per-model caps");
  assert.deepEqual(modelPressure(b, undefined), { over: false, spent_usd: 0, cap_usd: 0, agents: 0 }, "a seat with no model on record belongs to no group");
  const unrecorded = budget({ a00: seat(undefined, 9), a01: seat(NANO, 1) }, { [NANO]: 4 });
  assert.deepEqual(modelPressure(unrecorded, NANO), { over: false, spent_usd: 1, cap_usd: 4, agents: 1 }, "a seat with no model is in nobody's sum");
});

test("per-model cap: it is its own cap, next to the per-agent one, not instead of it", () => {
  const b = { ...budget({ a00: seat(MINI, 5), a01: seat(MINI, 1.5) }, { [MINI]: 6 }), cap_per_agent_usd: 3 };
  assert.equal(agentPressure(b, "a00").over, true, "a00 is over its own cap");
  assert.equal(agentPressure(b, "a01").over, false, "a01 is under its own cap");
  assert.equal(modelPressure(b, MINI).over, true, "but the model they share is over its cap, so a01 is stopped by that");
});

test("per-model cap: the record keeps the caps and each seat's model through a rebuild", () => {
  const raw = {
    ...budget({ a00: seat(MINI, 1), a01: seat(NANO, 1) }, { [MINI]: 6, [NANO]: 4, "bad/zero": 0, "bad/text": Number.NaN }),
  } as Partial<BudgetRecord>;
  const rebuilt = normalizeBudget(raw);
  assert.deepEqual(rebuilt.cap_per_model_usd, { [MINI]: 6, [NANO]: 4 }, "a cap that is not a positive number is not a cap");
  assert.equal(rebuilt.agents.a00.model, MINI);
  assert.equal(rebuilt.agents.a01.model, NANO);
  assert.equal(normalizeBudget(budget({ a00: seat(MINI, 1) }) as Partial<BudgetRecord>).cap_per_model_usd, undefined, "a swarm without per-model caps does not grow any");
  assert.equal(normalizeBudget({ ...budget({}), cap_per_model_usd: { "x/y": 0 } } as Partial<BudgetRecord>).cap_per_model_usd, undefined);
});

test("per-model cap: the caps and the seat's model survive every fold of session usage", async () => {
  // The kickoff writes both once. The per-agent cap was once lost this way —
  // the first fold rebuilt the record without it — so the per-model cap is
  // held to the same test from the start.
  const root = await mkdtemp(join(tmpdir(), "model-caps-"));
  try {
    await initSandbox(root, { reset: true, agentIds: ["a00", "a01", "a02"] });
    const seeded = await readBudget(root);
    seeded.cap_per_model_usd = { [MINI]: 6, [NANO]: 4 };
    seeded.agents.a00.model = MINI;
    seeded.agents.a01.model = MINI;
    seeded.agents.a02.model = NANO;
    await writeBudget(root, seeded);

    const spend = (usd: number) => ({ spent_usd: usd, tokens: 10, calls: 1, input: 10, output: 0, cache_read: 0, cache_write: 0 });
    await applySessionUsage(root, "a00", spend(2.5));
    const applied = await applySessionUsage(root, "a01", spend(3.5));
    assert.deepEqual(applied.budget.cap_per_model_usd, { [MINI]: 6, [NANO]: 4 }, "the fold keeps the per-model caps");
    assert.equal(applied.budget.agents.a01.model, MINI, "and the seat's model, though the usage slice carries none");

    const reread = await readBudget(root);
    assert.deepEqual(modelPressure(reread, MINI), { over: true, spent_usd: 6, cap_usd: 6, agents: 2 });
    assert.deepEqual(modelPressure(reread, NANO), { over: false, spent_usd: 0, cap_usd: 4, agents: 1 });
    assert.equal(agentPressure(reread, "a01").over, false, "no per-agent cap was set, so that road stays closed");

    // A seat the kickoff did not label takes the model its usage slice names.
    delete reread.agents.a02.model;
    await writeBudget(root, reread);
    const labelled = await applySessionUsage(root, "a02", { ...spend(1), model: NANO });
    assert.equal(labelled.budget.agents.a02.model, NANO);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
