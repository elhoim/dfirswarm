import { Switch, Label } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const row = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, maxWidth: 460 } as const;
const stack = { display: "flex", flexDirection: "column", gap: 14, maxWidth: 460 } as const;
const hint = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

/**
 * Both states side by side, each bound to its own caption. Off is the line
 * colour; on is kelp, the one accent this product spends on affirmatives.
 */
export const OffAndOn = () => (
  <div style={stack}>
    <div style={row}>
      <Label htmlFor="sw-off">Hard kill · off</Label>
      <Switch id="sw-off" />
    </div>
    <div style={row}>
      <Label htmlFor="sw-on">Hard kill · on</Label>
      <Switch id="sw-on" defaultChecked />
    </div>
  </div>
);

/** The kickoff settings block, verbatim: a switch is always a sentence and a state. */
export const Settings = () => (
  <div style={stack}>
    <div style={row}>
      <Label htmlFor="sw-playwright">Playwright · browser tools for goals that must render something</Label>
      <Switch id="sw-playwright" />
    </div>
    <div style={row}>
      <Label htmlFor="sw-forging">Tool forging · agents may write tools with make_tool and share them</Label>
      <Switch id="sw-forging" defaultChecked />
    </div>
    <div style={row}>
      <Label htmlFor="sw-hardkill">Hard kill · shut the session at the steer instead of after the grace</Label>
      <Switch id="sw-hardkill" />
    </div>
    <div style={row}>
      <Label htmlFor="sw-prepare">Prepare only · write the sandbox, launch nothing</Label>
      <Switch id="sw-prepare" defaultChecked />
    </div>
  </div>
);

/** Disabled in both states: the setting the run has already decided and will not reopen. */
export const Disabled = () => (
  <div style={stack}>
    <div style={row}>
      <Label htmlFor="sw-local">Local only · no model may leave the host</Label>
      <Switch id="sw-local" disabled />
    </div>
    <div style={row}>
      <Label htmlFor="sw-panes">Close panes as agents finish</Label>
      <Switch id="sw-panes" defaultChecked disabled />
    </div>
    <p style={hint}>Locked once a swarm is running: both were fixed at kickoff.</p>
  </div>
);
