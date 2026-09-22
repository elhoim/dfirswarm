import { Button, Dialog, DialogContent, DialogDescription, DialogTitle } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;

/**
 * The description carries the whole contract of a destructive action: the exact
 * argv, what it touches, and — the line that stops a wrong click — what it does
 * *not* do. Monospace is the tell: anything in `code` is something on disk.
 */
export const WhatStopDoes = () => (
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

/** The same contract for reap, down to the file each reaped agent is left with. */
export const WhatReapDoes = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Reap stalled agents in dfir-alihadi</DialogTitle>
      <DialogDescription>
        Runs <code>scripts/swarm.sh reap s2cb9 --stall-sec N</code>: any agent silent longer than N seconds gets{" "}
        <code>done/agents/&lt;id&gt;.dead</code>, its leases dropped and a <code>reap</code> trace line. Idempotent.
      </DialogDescription>
      <div style={actions}>
        <Button variant="secondary">Cancel</Button>
        <Button variant="warn">Reap now</Button>
      </div>
    </DialogContent>
  </Dialog>
);

/**
 * The state variation: a description can carry its own warning. When an agent
 * holds the file's lock, the refusal is said here, in `brick`, before the
 * operator reaches the button.
 */
export const RestoreBlockedByALock = () => (
  <Dialog defaultOpen>
    <DialogContent>
      <DialogTitle>Restore work/report.md to rev 4?</DialogTitle>
      <DialogDescription>
        The current bytes are saved as a new revision first, then rev 4 is copied back into <code>work/report.md</code>. Agents
        will see the change on their next read.
        <span className="block text-brick-ink" style={{ marginTop: 8 }}>
          s2cb903 holds this file's lock right now; the restore will be refused until it is released.
        </span>
      </DialogDescription>
      <div style={actions}>
        <Button variant="secondary">Cancel</Button>
        <Button>Restore</Button>
      </div>
    </DialogContent>
  </Dialog>
);
