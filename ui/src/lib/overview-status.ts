import type { SwarmPhase, SwarmRow } from "./types.ts";

/**
 * The work reached its finish line: `done`, or `finish_failed`, where the
 * sentinel is written and only the hub's put-away of the VMs failed. What
 * the agents did is certified the same either way; the failure is the
 * harness's, and is shown as that.
 */
export function reachedDone(phase: SwarmPhase): boolean {
  return phase === "done" || phase === "finish_failed";
}

/**
 * The sentinel is written, whatever the harness did after: a stop that left
 * a VM up does not undo the work. `sentinel_by` is set only when the
 * sentinel exists.
 */
function workDone(row: Pick<SwarmRow, "phase" | "sentinel_by">): boolean {
  return reachedDone(row.phase) || (row.phase === "stop_incomplete" && row.sentinel_by !== null);
}

/** A certified finish, including one that spent the last dollars of the cap. */
export function isCertifiedDone(row: Pick<SwarmRow, "phase" | "sentinel_by">): boolean {
  return workDone(row) && row.sentinel_by !== "harness";
}

/** The harness wrote done/SWARM_DONE (cap or wall clock), matching the detail header. */
export function isHarnessStop(row: Pick<SwarmRow, "phase" | "sentinel_by">): boolean {
  return workDone(row) && row.sentinel_by === "harness";
}

export function harnessStopLabel(row: Pick<SwarmRow, "stop_reason">): string {
  return row.stop_reason === "wall_clock" ? "stopped by harness · wall clock" : "stopped by harness · cap";
}

/** Which filter of the list a run belongs to: live, reached its finish, or ended without one. */
export function phaseGroup(phase: SwarmPhase): "running" | "done" | "stopped" | "other" {
  if (phase === "running") return "running";
  if (reachedDone(phase)) return "done";
  if (phase === "stopped" || phase === "prepared" || phase === "failed" || phase === "stop_incomplete") return "stopped";
  return "other";
}

/**
 * Whether the operator's Stop may have anything to do. The hub runs the stop
 * itself after it finishes a VM run, so a finished one usually has nothing
 * left; after a failed finish, or a stop that left a VM up, there may be
 * VMs. Stop is safe to repeat, so it stays offered for all three.
 */
export function stopHasWork(state: string): boolean {
  return state === "running" || state === "prepared" || state === "finished" || state === "finish_failed" || state === "stop_incomplete";
}
