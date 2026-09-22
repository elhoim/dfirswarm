import { Button, Dialog, DialogContent, DialogDescription, DialogTitle, Input, Label, Switch } from "dfirswarm";

// Layout here is inline style, never a Tailwind utility: the shipped stylesheet
// is the app's compiled CSS, so it only contains classes the app itself uses.
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;
const form = { marginTop: 16, display: "grid", gap: 12 } as const;
const field = { display: "grid", gap: 6 } as const;
const switchRow = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, fontSize: 13 } as const;

/**
 * The root. It renders nothing itself — it owns the open state and portals its
 * content over the page — so every story here is the whole dialog, open.
 *
 * Stop is the console's destructive confirmation: it says exactly which script
 * runs and, just as importantly, what it does not do.
 */
export const StopSwarm = () => (
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

/** Reap is the other destructive one, and it takes an argument: the stall threshold. */
export const ReapStalled = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Reap stalled agents in dfir-alihadi</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh reap s2cb9 --stall-sec N</code>: any agent silent longer than N seconds gets{" "}
        <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
      </DialogDescription>
      <div style={form}>
        <div style={field}>
          <Label htmlFor="stall">Stall threshold (seconds)</Label>
          <Input id="stall" inputMode="numeric" defaultValue="90" className="tabular" style={{ width: "8rem" }} />
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

/** The operator's own addition: restoring a work file to an older revision. */
export const RestoreRevision = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Restore work/report.md to rev 4?</DialogTitle>
      <DialogDescription>
        The current bytes are saved as a new revision first, then rev 4 is copied back into <code>work/report.md</code>. Agents
        will see the change on their next read.
      </DialogDescription>
      <div style={actions}>
        <Button variant="secondary">Cancel</Button>
        <Button>Restore</Button>
      </div>
    </DialogContent>
  </Dialog>
);
