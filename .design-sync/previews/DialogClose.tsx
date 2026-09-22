import { Button, Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle, Input, Label, Switch } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;
const form = { marginTop: 16, display: "grid", gap: 12 } as const;
const field = { display: "grid", gap: 6 } as const;
const switchRow = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, fontSize: 13 } as const;

/**
 * `DialogClose` is the declarative way out, so a confirmation never has to hold
 * the open state itself. Two of them are on screen here: the `secondary`
 * Cancel, and the small `x` `DialogContent` puts in its own top-right corner.
 */
export const CancelsTheStop = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Stop dfir-alihadi?</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh stop s2cb9</code>: closes the Herdr workspace(s), kills the netguard sidecar, marks the
        registry <code>stopped</code>. Files in the sandbox stay. This does not write <code>SWARM_DONE</code>.
      </DialogDescription>
      <div style={actions}>
        <DialogClose asChild>
          <Button variant="secondary">Cancel</Button>
        </DialogClose>
        <Button variant="danger">Stop swarm</Button>
      </div>
    </DialogContent>
  </Dialog>
);

/**
 * The same escape on the dialog that carries a form: closing is never the
 * destructive path, so `DialogClose` stays on the quiet `secondary` button and
 * the `warn` one keeps the consequence.
 */
export const CancelsTheReap = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Reap stalled agents in dfir-alihadi</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh reap s2cb9 --stall-sec N</code>: any agent silent longer than N seconds gets{" "}
        <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
      </DialogDescription>
      <div style={form}>
        <div style={field}>
          <Label htmlFor="stall-close">Stall threshold (seconds)</Label>
          <Input id="stall-close" inputMode="numeric" defaultValue="90" className="tabular" style={{ width: "8rem" }} />
        </div>
        <label style={switchRow}>
          <span>
            Also close the agent's Herdr pane (<code>--stop</code>)
          </span>
          <Switch defaultChecked />
        </label>
      </div>
      <div style={actions}>
        <DialogClose asChild>
          <Button variant="secondary">Cancel</Button>
        </DialogClose>
        <Button variant="warn">Reap now</Button>
      </div>
    </DialogContent>
  </Dialog>
);
