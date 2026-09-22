import type { SwarmRow } from "./types.ts";

/** A certified finish, including one that spent the last dollars of the cap. */
export function isCertifiedDone(row: Pick<SwarmRow, "phase" | "sentinel_by">): boolean {
  return row.phase === "done" && row.sentinel_by !== "harness";
}

/** The harness wrote done/SWARM_DONE (cap or wall clock), matching the detail header. */
export function isHarnessStop(row: Pick<SwarmRow, "phase" | "sentinel_by">): boolean {
  return row.phase === "done" && row.sentinel_by === "harness";
}

export function harnessStopLabel(row: Pick<SwarmRow, "stop_reason">): string {
  return row.stop_reason === "wall_clock" ? "stopped by harness · wall clock" : "stopped by harness · cap";
}
