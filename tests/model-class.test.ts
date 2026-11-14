import assert from "node:assert/strict";
import { test } from "node:test";
import { recordKindToolsFor } from "../extensions/agent-swarm.ts";
import { modelClass as leadsModelClass } from "../extensions/leads.ts";
import { modelClass, weakClassReason } from "../extensions/model-class.ts";

const WEAK = [
  "deepseek/deepseek-v4-pro",
  "azure-foundry/DeepSeek-V4-Pro",
  "openrouter/qwen/qwen3-coder",
  "ollama/qwen3:8b",
  "openai/gpt-oss-120b",
  "localmock/gpt-oss:20b",
  "lmstudio/some-local-model",
  "zai-org/glm-4.6",
  "z-ai/glm-5.3",
  "google/gemma-3-27b",
  "groq/llama-3.3-70b-versatile",
  "bedrock/us.meta.llama3-3-70b-instruct-v1:0",
  "fireworks/accounts/fireworks/models/deepseek-v3",
  "openrouter/moonshotai/kimi-k2",
  "microsoft/phi4",
  "nousresearch/hermes-4-70b",
  "vllm/anything",
];
const STRONG = [
  "openai/gpt-5.4",
  "openai-codex/gpt-5.1-codex",
  "openai/gpt-4o-mini",
  "openai/o4-mini-high",
  "anthropic/claude-opus-4-5",
  "anthropic/claude-3-5-haiku",
  "google/gemini-2.5-pro",
  "google/gemini-3-pro",
  "xai/grok-4",
  "xai/grok-code-fast-1",
];

test("the weak model class has one definition: leads and the record tools read the same class for every name", () => {
  for (const m of WEAK) {
    assert.equal(modelClass(m), "weak", `${m} is of the weak class`);
    assert.equal(leadsModelClass(m), "weak", `leads.ts reads ${m} as weak`);
    const slash = m.indexOf("/");
    const offer = recordKindToolsFor({ provider: m.slice(0, slash), id: m.slice(slash + 1) }, {});
    assert.equal(offer.offer, true, `the record tools read ${m} as weak`);
    assert.match(offer.why, /the weak class$/);
  }
  for (const m of STRONG) {
    assert.equal(modelClass(m), "strong", `${m} is not of the weak class`);
    assert.equal(leadsModelClass(m), "strong");
    const slash = m.indexOf("/");
    assert.equal(recordKindToolsFor({ provider: m.slice(0, slash), id: m.slice(slash + 1) }, {}).offer, false, `the record tools read ${m} as strong`);
  }
  assert.equal(modelClass(""), null);
  assert.equal(modelClass(null), null);
  assert.equal(weakClassReason("ollama/llama3"), "served locally");
  assert.equal(weakClassReason("openrouter/deepseek/deepseek-chat"), "of an open-weight family");
  assert.equal(weakClassReason("openai/gpt-5.4"), null);
});
