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
  // The review's cases (P3-4): a hyphenated local provider, and open-weight families read as strong before.
  "lm-studio/my-model",
  "lm_studio/my-model",
  "llama.cpp/x",
  "llama_cpp/x",
  "cohere/command-a",
  "cohere/command-a-03-2025",
  "cohere/command-r7b-12-2024",
  "ai21/jamba-1.5-large",
  "databricks/dbrx",
  "databricks/databricks-dbrx-instruct",
  "cerebras/qwen-3-235b",
  "ollama-cloud/kimi-k2",
  "openrouter/z-ai/glm-4.6",
  "openrouter/mistralai/ministral-8b",
  "openrouter/meta-llama/llama-4",
  "fireworks/accounts/fireworks/models/kimi-k2-instruct",
  "moonshot/kimi-k2",
  "deepinfra/microsoft/phi-4",
  "mistral/mistral-large-3",
  "mistral/mistral-small-3.2",
  "mistral/magistral-small-1.2",
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
  // The review's cases (P3-4): no mainstream closed model is of the weak class, Mistral's closed ones among them.
  "openai/o3-mini",
  "openai/o1",
  "anthropic/claude-haiku-4-5",
  "anthropic/claude-3-7-sonnet-latest",
  "anthropic/claude-opus-4-1-yi",
  "google/gemini-2.5-flash-lite",
  "google/gemini-3-pro-preview",
  "vertex/gemini",
  "xai/grok-4-fast",
  "openrouter/x-ai/grok-4",
  "openrouter/openai/gpt-5",
  "openrouter/anthropic/claude-sonnet-4.5",
  "bedrock/anthropic.claude-sonnet-4",
  "github-copilot/gpt-4.1",
  "openai-codex/gpt-6-astra",
  "azure/gpt-5",
  "openai/gpt-5-codex",
  "openai/chatgpt-4o-latest",
  "openai/gpt-4.5-preview",
  "perplexity/sonar-pro",
  "amazon-bedrock/amazon.nova-pro-v1:0",
  "mistral/mistral-medium-3",
  "mistral/mistral-medium-2508",
  "openrouter/mistralai/mistral-medium-3.1",
  "mistral/magistral-medium-1.2",
  "mistral/devstral-medium-2507",
  "mistral/mistral-saba",
  "cohere/command",
  "ai21/j2-ultra",
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
