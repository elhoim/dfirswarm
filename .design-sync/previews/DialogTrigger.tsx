import { Button, Chip, Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "dfirswarm";

// Inline style for preview layout — the shipped stylesheet is the app's
// compiled CSS and carries only the classes the app itself uses.
//
// The bar carries its OWN padding rather than leaning on the page gutter:
// Radix's scroll lock rewrites `body` padding the moment the dialog opens, so
// anything left sitting in the flow gets clipped against the viewport edge.
const bar = { padding: 20, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 } as const;
const buttons = { display: "flex", gap: 8 } as const;
const run = { display: "flex", alignItems: "center", gap: 8 } as const;
const actions = { marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 } as const;

/**
 * `DialogTrigger` is `asChild` in this console: it renders no element of its
 * own, it adopts the `Button` the action bar already has, so Stop keeps its
 * `danger` treatment and the bar keeps its vocabulary. Caught mid-press — the
 * trigger is still there, under the overlay it just opened.
 */
export const OpensTheStopDialog = () => (
  <Dialog defaultOpen>
    <div style={bar}>
      <span style={run}>
        <Chip tone="kelp" mono>
          s2cb9
        </Chip>
        <Chip tone="kelp">running</Chip>
      </span>
      <span style={buttons}>
        <Button variant="secondary" size="sm">
          Reap stalled
        </Button>
        <DialogTrigger asChild>
          <Button variant="danger" size="sm">
            Stop swarm
          </Button>
        </DialogTrigger>
      </span>
    </div>
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

/**
 * The same two triggers unobscured — the only view in which they are readable.
 * A finished run refuses both, and because the trigger is `asChild` it inherits
 * the button's own disabled treatment rather than inventing one.
 */
export const TriggersAtRest = () => (
  <Dialog>
    <div style={bar}>
      <span style={run}>
        <Chip tone="neutral" mono>
          s2cb9
        </Chip>
        <Chip tone="moss">done</Chip>
      </span>
      <span style={buttons}>
        <DialogTrigger asChild>
          <Button variant="secondary" size="sm" disabled>
            Reap stalled
          </Button>
        </DialogTrigger>
        <DialogTrigger asChild>
          <Button variant="danger" size="sm" disabled>
            Stop swarm
          </Button>
        </DialogTrigger>
      </span>
    </div>
  </Dialog>
);
