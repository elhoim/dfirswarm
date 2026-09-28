/**
 * Claim → write/edit → release runs per (agent, path); inventory §5 #20.
 * Pure: the server builds them over the whole trace, because the view's
 * trace is a tail and a run's claims are mostly made long before its last
 * few hundred lines (a tail of releases whose claims it no longer holds
 * showed "No claim sequences yet" on a run that made two dozen). The Claims
 * tab and node tests import it as it is.
 */

/** One step of a run: which call, and when by the sender's clock. */
export type ClaimStep = { tool: string; ts: string };

/** `open`: no release_file on the trace after the claim. Whether the lease is still live is the lock table's to say. */
export type ClaimSequence = { agent: string; path: string; steps: ClaimStep[]; open: boolean };

type TraceLine = { ts: string; agent: string; tool: string; args: Record<string, unknown>; result: unknown };

const WORK_STEPS = new Set(["write", "edit", "file_restore", "file_history", "publish_file", "publish_needed"]);

/**
 * The runs, newest first. Only the call and its time are kept of each step:
 * a write's line carries the whole file it wrote, and the trace has it.
 */
export function claimSequences(events: readonly TraceLine[]): ClaimSequence[] {
  const open = new Map<string, ClaimSequence>();
  const out: ClaimSequence[] = [];
  for (const e of events) {
    const args = e.args ?? {};
    // publish_file names its target `to` (a VM seat's write to a shared
    // file goes through the hub); every other step names it `path`.
    const target =
      e.tool === "publish_file"
        ? typeof args.to === "string" && args.to
          ? args.to
          : typeof args.path === "string"
            ? `work/${args.path.split("/").pop()}`
            : null
        : args.path;
    const path = typeof target === "string" ? target : null;
    if (!path) continue;
    const key = `${e.agent}\u0000${path}`;
    const step = { tool: e.tool, ts: e.ts };
    if (e.tool === "claim_file") {
      const r = e.result as { ok?: boolean } | null;
      if (r && r.ok === false) continue;
      if (!open.has(key)) {
        const seq: ClaimSequence = { agent: e.agent, path, steps: [], open: true };
        open.set(key, seq);
        out.push(seq);
      }
      open.get(key)!.steps.push(step);
    } else if (WORK_STEPS.has(e.tool)) {
      open.get(key)?.steps.push(step);
    } else if (e.tool === "release_file") {
      const seq = open.get(key);
      if (seq) {
        seq.steps.push(step);
        seq.open = false;
        open.delete(key);
      }
    }
  }
  return out.reverse();
}
