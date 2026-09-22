import { ReadyDot } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS.
const READINESS = {
  anthropic: { status: "ready", provider: "anthropic", auth_type: "oauth" },
  openai: { status: "invalid", provider: "openai", auth_type: "api_key", reason: "401 from the key on this machine" },
  google: { status: "not_ready", provider: "google" },
  ollama: { status: "local", provider: "ollama", local: true, base_url: "http://127.0.0.1:11434/v1" },
} as Record<string, { status: "ready" | "not_ready" | "invalid" | "unknown" | "local"; provider: string; local?: boolean; base_url?: string; auth_type?: string; reason?: string }>;

const row = { display: "flex", alignItems: "center", gap: 8 } as const;
const model = { fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-ink)" } as const;
const note = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)", marginLeft: "auto" } as const;

const STATES = [
  { model: "anthropic/claude-opus-4", note: "ready · subscription" },
  { model: "ollama/qwen3-coder", note: "local · needs a placeholder apiKey" },
  { model: "google/gemini-2.5-pro", note: "not logged in" },
  { model: "openai/gpt-5.1", note: "credentials invalid" },
  { model: "together/deepseek-v3", note: "readiness unknown" },
];

/** Kelp when the provider is usable, saffron when it is not, brick when the key is bad, hollow when nothing was checked. */
export const EveryState = () => (
  <div style={{ display: "grid", gap: 9, maxWidth: 400 }}>
    {STATES.map((s) => (
      <span key={s.model} style={row}>
        <ReadyDot model={s.model} readiness={READINESS} />
        <span style={model}>{s.model}</span>
        <span style={note}>{s.note}</span>
      </span>
    ))}
  </div>
);

const TEAM = [
  { model: "anthropic/claude-opus-4", count: 2 },
  { model: "ollama/qwen3-coder", count: 4 },
  { model: "google/gemini-2.5-pro", count: 1 },
];

const count = { fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-ink-3)", marginLeft: "auto" } as const;

/** Where it is used: one dot per row of a mixed team, before the model select. */
export const DownAMixedTeam = () => (
  <div style={{ display: "grid", gap: 9, maxWidth: 340 }}>
    {TEAM.map((r) => (
      <span key={r.model} style={row}>
        <ReadyDot model={r.model} readiness={READINESS} />
        <span style={model}>{r.model}</span>
        <span style={count}>× {r.count}</span>
      </span>
    ))}
  </div>
);
