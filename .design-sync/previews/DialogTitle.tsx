import { Button, Dialog, DialogContent, DialogDescription, DialogTitle } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is compiled CSS.
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;
const head = { padding: "16px 20px 12px" } as const;

/**
 * The title is the question, and it names the run rather than the verb: the
 * operator is looking at three consoles, so "Stop?" alone is not a question
 * anyone can answer. Its only true context is a dialog, so that is what the
 * story renders.
 */
export const StopQuestion = () => (
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

/** A statement, not a question, when the dialog is going to ask for an argument. */
export const ReapStatement = () => (
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
 * The variant axis: a reading surface promotes the title to the display face.
 * The primary thread takes `brick` with it, because the primary thread is the
 * one the whole run answers to.
 */
export const SerifThreadHead = () => (
  <Dialog defaultOpen>
    <DialogContent className="p-0">
      <div style={head}>
        <DialogTitle className="serif text-brick-ink" style={{ fontSize: 30, fontWeight: 400, lineHeight: 1 }}>
          Primary thread
        </DialogTitle>
        <DialogDescription className="font-mono text-ink-3">
          public · created by system | 10:32:44 | 41 messages
        </DialogDescription>
      </div>
    </DialogContent>
  </Dialog>
);
