import { Label, Input, NativeSelect, Textarea, Switch } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const field = { display: "flex", flexDirection: "column", gap: 6, maxWidth: 420 } as const;
const stack = { display: "flex", flexDirection: "column", gap: 16, maxWidth: 420 } as const;
const switchRow = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, maxWidth: 420 } as const;
const hint = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

/**
 * A label is only ever half of something. `htmlFor` binds it to the control's
 * `id`, so clicking the caption puts the caret in the field — which is the
 * whole point, and the only way to see whether it works.
 */
export const LabelledField = () => (
  <div style={field}>
    <Label htmlFor="swarm-label">Run label</Label>
    <Input id="swarm-label" defaultValue="acme disk triage · s2cb903" />
    <p style={hint}>The caption is the field's hit target too, not decoration above it.</p>
  </div>
);

/** One caption weight over every control the console has, so a form reads as one column. */
export const AcrossControls = () => (
  <div style={stack}>
    <div style={field}>
      <Label htmlFor="ac-model">Model</Label>
      <NativeSelect id="ac-model" className="font-mono" defaultValue="openai/gpt-5.4">
        <option value="openai/gpt-5.4">openai/gpt-5.4 · subscription</option>
        <option value="deepseek/deepseek-v4-pro">deepseek/deepseek-v4-pro · api key</option>
      </NativeSelect>
    </div>
    <div style={field}>
      <Label htmlFor="ac-note">Note for the operator</Label>
      <Textarea id="ac-note" style={{ minHeight: 72 }} defaultValue="Evidence is read-only; results go in work/." />
    </div>
    <div style={switchRow}>
      <Label htmlFor="ac-prepare">Prepare only · write the sandbox, launch nothing</Label>
      <Switch id="ac-prepare" />
    </div>
  </div>
);
