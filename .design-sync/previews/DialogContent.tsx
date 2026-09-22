import { Badge, Button, Dialog, DialogContent, DialogDescription, DialogTitle, Input, Label, Switch } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;
const form = { marginTop: 16, display: "grid", gap: 12 } as const;
const field = { display: "grid", gap: 6 } as const;
const switchRow = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, fontSize: 13 } as const;
const pane = { marginTop: 12, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 } as const;
const titleRow = { display: "flex", flexWrap: "wrap", alignItems: "baseline", gap: 8 } as const;

/**
 * The shell: overlay, centred card, border, shadow, and the `x` it adds in its
 * own top-right corner. At its default `max-w-lg` it is a confirmation width —
 * one question, two buttons, nothing to scroll.
 */
export const StopConfirmation = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Stop dfir-alihadi?</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh stop s2cb9</code>: closes the Herdr workspace(s), kills the netguard sidecar, marks the
        registry <code>stopped</code>. Files in the sandbox stay. This does not write <code>SWARM_DONE</code>.
      </DialogDescription>
      <div style={actions}>
        <Button variant="secondary">Cancel</Button>
        <Button variant="danger">Stop swarm</Button>
      </div>
    </DialogContent>
  </Dialog>
);

/** The same shell holding controls: the `p-5` gutter has to carry a form too. */
export const ReapWithControls = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Reap stalled agents in dfir-alihadi</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh reap s2cb9 --stall-sec N</code>: any agent silent longer than N seconds gets{" "}
        <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
      </DialogDescription>
      <div style={form}>
        <div style={field}>
          <Label htmlFor="stall-content">Stall threshold (seconds)</Label>
          <Input id="stall-content" inputMode="numeric" defaultValue="90" className="tabular" style={{ width: "8rem" }} />
        </div>
        <label style={switchRow}>
          <span>
            Also close the agent's Herdr pane (<code>--stop</code>)
          </span>
          <Switch />
        </label>
      </div>
      <div style={actions}>
        <Button variant="secondary">Cancel</Button>
        <Button variant="warn">Reap now</Button>
      </div>
    </DialogContent>
  </Dialog>
);

/**
 * The width is the variant axis: one `max-w` override turns the confirmation
 * card into the reading surface the raw trace needs — call on the left, result
 * on the right.
 */
export const WideTraceRow = () => (
  <Dialog defaultOpen>
    <DialogContent className="max-w-[960px]">
      <DialogTitle className="font-mono">
        <span style={titleRow}>
          <span className="text-ink-3">10:41:12</span>
          <span>s2cb903</span>
          <Badge variant="kelp" className="font-mono">
            claim_file
          </Badge>
        </span>
      </DialogTitle>
      <DialogDescription className="font-mono">2026-09-18T10:41:12.118Z</DialogDescription>
      <div style={pane}>
        <div style={{ minWidth: 0 }}>
          <div className="label-caps">Call</div>
          <pre className="rounded-md bg-paper-2 text-ink" style={{ marginTop: 4, padding: "8px 12px", overflow: "hidden" }}>
{`{
  "path": "work/report.md",
  "ttl_sec": 900
}`}
          </pre>
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="label-caps">Result</div>
          <pre className="rounded-md bg-paper-2 text-ink" style={{ marginTop: 4, padding: "8px 12px", overflow: "hidden" }}>
{`{
  "ok": true,
  "lease": "s2cb9/s2cb903",
  "expires_in": 900
}`}
          </pre>
        </div>
      </div>
    </DialogContent>
  </Dialog>
);
