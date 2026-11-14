/**
 * The weak model class: one definition for every part of the harness that treats it apart (B2's record tools of one kind
 * each, D5's narrow leads and seeded leads).
 *
 * The weak class is the open-weight model families and the models a local server serves. On the Batman III runs their seats
 * had 30-45% of their record and attest calls refused, six to nine times the rest; their teams opened 11 to 20 leads a run,
 * several questions to a lead, lived 25 to 96 minutes with them and took 0 to 2 offers, where the closed frontier models
 * opened many narrow leads and took 5 to 22.
 */

/**
 * The open-weight families, read from a model's name at its start or after a separator (`/`, `:`, `_`, `.`, `-`, so a
 * routing prefix such as `openrouter/`, `accounts/x/models/` or Bedrock's `meta.` is passed over), and ending at the name's
 * end, a separator or a digit (so `phi4` and `qwen3` are read, and a word that only begins like a family is not).
 */
const WEAK_FAMILY =
  /(?:^|[/:_.-])(?:deepseek|qwen|qwq|glm|chatglm|zai|z-ai|kimi|moonshot|moonshotai|minimax|llama|meta-llama|mistral|mistralai|mixtral|codestral|devstral|magistral|gemma|phi|gpt-oss|nemotron|olmo|hermes|nousresearch|yi|01-ai|internlm|baichuan|ernie|hunyuan|seed-oss|granite|command-r|falcon|smollm)(?=$|[-_.:/\d])/i;

/** Providers that serve local models only: every model they serve is of the weak class. */
const LOCAL_PROVIDERS = new Set(["ollama", "lmstudio", "llama-cpp", "llamacpp", "llama.cpp", "cpp", "vllm", "sglang", "localmock", "local"]);

/**
 * Why a model is of the weak class, or null when it is not. `model` is the name a run gives it (`provider/model`, any
 * routing prefix); its first segment is read as the provider.
 */
export function weakClassReason(model: string): string | null {
  const m = model.trim();
  const provider = m.includes("/") ? m.slice(0, m.indexOf("/")).toLowerCase() : "";
  if (LOCAL_PROVIDERS.has(provider) || LOCAL_PROVIDERS.has(m.toLowerCase())) return "served locally";
  if (WEAK_FAMILY.test(m)) return "of an open-weight family";
  return null;
}

/** A model's class from its name: "weak" for an open-weight or locally served model, else "strong"; null when no name is given. */
export function modelClass(model: string | null | undefined): "weak" | "strong" | null {
  const m = String(model ?? "").trim();
  if (!m) return null;
  return weakClassReason(m) ? "weak" : "strong";
}
