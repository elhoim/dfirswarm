import { NativeSelect, Label } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const field = { display: "flex", flexDirection: "column", gap: 6, maxWidth: 380 } as const;
const pair = { display: "flex", flexWrap: "wrap", gap: 16, alignItems: "flex-end" } as const;
const hint = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

/**
 * The model picker: the one select every kickoff goes through. Model ids are
 * identifiers, so this one is set in mono, as the kickoff screen sets it.
 */
export const Model = () => (
  <div style={field}>
    <Label htmlFor="model">Model</Label>
    <NativeSelect id="model" className="font-mono" defaultValue="openai/gpt-5.4" aria-label="Model">
      <option value="openai/gpt-5.4">openai/gpt-5.4 · subscription</option>
      <option value="deepseek/deepseek-v4-pro">deepseek/deepseek-v4-pro · api key</option>
      <option value="ollama/qwen3-coder:30b">ollama/qwen3-coder:30b · local · free</option>
      <option value="__custom">Other (type provider/id)</option>
    </NativeSelect>
    <p style={hint}>From <code>pi --list-models</code> on the server.</p>
  </div>
);

/** Two selects side by side, the way the read-only inputs section pairs them. */
export const InputSet = () => (
  <div style={pair}>
    <div style={field}>
      <Label htmlFor="input-set">Input set</Label>
      <NativeSelect id="input-set" defaultValue="acme-disk-triage" aria-label="Input set">
        <option value="">none</option>
        <option value="acme-disk-triage">acme-disk-triage · 14 files</option>
        <option value="mft-carve">mft-carve · 3 files</option>
      </NativeSelect>
    </div>
    <div style={field}>
      <Label htmlFor="kernel-guard">Kernel guard</Label>
      <NativeSelect id="kernel-guard" defaultValue="auto" aria-label="Inputs enforcement">
        <option value="auto">auto · kernel when the host can</option>
        <option value="on">on · refuse to start without it</option>
        <option value="off">off · detect and heal only</option>
      </NativeSelect>
    </div>
  </div>
);

/** Disabled: the guard is dead until a set is chosen, and says so by looking spent. */
export const Disabled = () => (
  <div style={field}>
    <Label htmlFor="kernel-guard-off">Kernel guard</Label>
    <NativeSelect id="kernel-guard-off" defaultValue="auto" aria-label="Inputs enforcement" disabled>
      <option value="auto">auto · kernel when the host can</option>
      <option value="on">on · refuse to start without it</option>
      <option value="off">off · detect and heal only</option>
    </NativeSelect>
    <p style={hint}>Nothing to guard until an input set is picked.</p>
  </div>
);
