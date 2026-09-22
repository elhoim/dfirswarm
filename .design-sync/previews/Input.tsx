import { Input, Label } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const field = { display: "flex", flexDirection: "column", gap: 6, maxWidth: 420 } as const;
const hint = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

/**
 * The resting field: a label, the control, and a placeholder that shows the
 * shape of the answer rather than repeating the label.
 */
export const Resting = () => (
  <div style={field}>
    <Label htmlFor="run-label">Run label</Label>
    <Input id="run-label" placeholder="what this run is for" />
    <p style={hint}>Optional. It is what the jobs drawer lists the run under.</p>
  </div>
);

/** Filled with a real value. Paths and ids are set in mono, as the console sets them. */
export const Filled = () => (
  <div style={field}>
    <Label htmlFor="goal-file">Goal file</Label>
    <Input id="goal-file" className="font-mono" defaultValue="prompts/goals/analyse-inputs.md" spellCheck={false} />
    <p style={hint}>Read at kickoff and copied into the sandbox as <code>goal.md</code>.</p>
  </div>
);

/** `type="number"` with tabular figures: the agent count the kickoff slider mirrors. */
export const Numeric = () => (
  <div style={field}>
    <Label htmlFor="agents-n">Agents · N</Label>
    <Input id="agents-n" type="number" min={1} max={30} className="tabular" defaultValue={7} />
    <p style={hint}>Between 1 and 30. Each one gets a pane and a share of the cap.</p>
  </div>
);

/** Disabled: the field the kickoff form locks until a model list arrives. */
export const Disabled = () => (
  <div style={field}>
    <Label htmlFor="custom-model">Custom model id</Label>
    <Input id="custom-model" className="font-mono" defaultValue="deepseek/deepseek-v4-pro" disabled />
    <p style={hint}>Locked while the server is still listing models.</p>
  </div>
);
