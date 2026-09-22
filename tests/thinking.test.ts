import assert from "node:assert/strict";
import { test } from "node:test";
import { shortModel, thinkingCensus, thinkingChars, thinkingText, thinkingTruncated } from "../ui/src/lib/thinking.ts";
import type { SwarmEvent } from "../ui/src/lib/types.ts";

function event(args: Record<string, unknown>, result: Record<string, unknown> | null): SwarmEvent {
  return { ts: "2026-09-20T18:52:01.869Z", agent: "s821c03", tool: "thinking", args, result } as SwarmEvent;
}

test("reasoning is read from the shape the harness actually writes", () => {
  // extensions/agent-swarm.ts: logEvent(cwd, agent, "thinking", {}, { text, chars })
  const e = event({}, { text: "No pycryptodome available. Let me check what crypto modules are available.", chars: 74 });
  assert.equal(thinkingText(e), "No pycryptodome available. Let me check what crypto modules are available.");
  assert.equal(thinkingChars(e), 74);
  assert.equal(thinkingTruncated(e), false, "74 characters stored out of 74 is the whole thing");
});

test("a clipped block knows it is clipped, and by how much", () => {
  const e = event({}, { text: `${"x".repeat(239)}…`, chars: 911 });
  assert.equal(thinkingTruncated(e), true);
  assert.equal(thinkingText(e).length, 240);
});

test("an event with the text in args still renders, so archived traces keep working", () => {
  assert.equal(thinkingText(event({ text: "old shape" }, null)), "old shape");
  assert.equal(thinkingText(event({ thought: "older shape" }, {})), "older shape");
});

test("nothing anywhere is an empty string, never \"[object Object]\" or \"{}\"", () => {
  assert.equal(thinkingText(event({}, {})), "");
  assert.equal(thinkingText(event({}, null)), "");
  assert.equal(thinkingText(event({}, { chars: 0 })), "");
  assert.equal(thinkingChars(event({}, null)), null);
  assert.equal(thinkingTruncated(event({}, null)), false);
});

const TEAM = [
  { id: "a0", model: "azure-foundry/grok-4.6" },
  { id: "a1", model: "azure-foundry/grok-4.6" },
  { id: "a2", model: "azure-foundry/grok-4.6" },
  { id: "a3", model: "azure-foundry/DeepSeek-V4-Pro" },
  { id: "a4", model: "openai/gpt-5.4" },
];

test("a silent model is named as such, with the models that did reason", () => {
  // The BelkaCTF #6 census: every grok seat at zero, the rest talkative.
  const census = thinkingCensus("a1", TEAM, { a3: 228, a4: 120 });
  assert.equal(census.verdict, "model-silent");
  assert.equal(census.model, "azure-foundry/grok-4.6");
  assert.deepEqual(census.mine, { lines: 0, agents: 3 });
  assert.deepEqual(
    census.others.map((o) => o.model),
    ["azure-foundry/DeepSeek-V4-Pro", "openai/gpt-5.4"],
    "most talkative first",
  );
  assert.equal(census.total, 348);
});

test("one quiet agent on a talkative model is a different sentence", () => {
  const census = thinkingCensus("a3", [...TEAM, { id: "a5", model: "azure-foundry/DeepSeek-V4-Pro" }], { a5: 228 });
  assert.equal(census.verdict, "agent-silent");
  assert.equal(census.mine.lines, 228);
});

test("a run where nobody reasoned says so instead of blaming one model", () => {
  assert.equal(thinkingCensus("a1", TEAM, {}).verdict, "run-silent");
});

test("an agent missing from the roster falls back rather than throwing", () => {
  const census = thinkingCensus("nobody", TEAM, { a3: 5 }, "openai/gpt-5.4");
  assert.equal(census.model, "openai/gpt-5.4");
  assert.equal(census.verdict, "model-silent");
});

test("a model is spoken of by its name, not its provider path", () => {
  assert.equal(shortModel("azure-foundry/grok-4.6"), "grok-4.6");
  assert.equal(shortModel("lmstudio/qwen3.8-27b-uncensored"), "qwen3.8-27b-uncensored");
  assert.equal(shortModel("no-slash"), "no-slash");
});
