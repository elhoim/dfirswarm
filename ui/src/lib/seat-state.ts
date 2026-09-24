/**
 * What a seat is doing, from one source. In a VM run the hub hears from each
 * VM (its link, its calls, the state the seat reports), so while that hub is
 * up and the VM is not put away the hub's word is the seat's state, and what
 * the host saw (a quiet pane, a stall) is secondary. Without a live hub the
 * host's markers decide, as in a host run. The band's counts, the Team list
 * and the team strip all read it from here, so they cannot disagree with the
 * VM panel. Pure: imported by node tests as well as by the client.
 */
import type { AgentRow, VmHealth } from "./types.ts";

export type SeatTone = "done" | "dead" | "quiet" | "working" | "idle";

export type SeatState = {
  /** The word shown: the hub's state for a VM seat it hears from, else the host's. */
  label: string;
  tone: SeatTone;
  /** Whose word it is. */
  by: "hub" | "host";
  /** The host's own reading when the hub's word is shown and they differ (a quiet pane the hub still hears). */
  host_note: string | null;
};

type SeatVm = Pick<VmHealth, "agent" | "live" | "hub_alive" | "stopped_at">;
type SeatAgent = Pick<AgentRow, "id" | "done" | "dead" | "stalled">;

/** The VMs whose hub is up and hears from them: the ones whose state the hub gives. */
export function hubLiveVms<T extends SeatVm>(vms: readonly T[] | null | undefined): T[] {
  return (vms ?? []).filter((v) => v.live && v.hub_alive === true && !v.stopped_at);
}

function hubTone(state: string): SeatTone {
  if (state === "working") return "working";
  if (state === "done") return "done";
  if (state === "gone") return "dead";
  if (state === "blocked") return "quiet";
  return "idle";
}

/**
 * One seat's state. `lastTool` is the host-side fallback for a live seat
 * without a hub: the last thing its trace shows it doing.
 */
export function seatState(agent: SeatAgent, vm: SeatVm | null | undefined, lastTool: string | null = null): SeatState {
  const hostWord = agent.done ? "done" : agent.dead ? "dead" : agent.stalled ? "stalled" : null;
  if (vm && hubLiveVms([vm]).length) {
    const live = vm.live!;
    const label = `${live.state}${live.connected ? "" : " · not linked"}`;
    // A reaped seat is the host's act on the run, and a finished one wrote
    // its marker: both stand whatever the hub last heard.
    if (agent.dead) return { label: "dead", tone: "dead", by: "host", host_note: null };
    if (agent.done) return { label: "done", tone: "done", by: "host", host_note: null };
    return { label, tone: live.connected ? hubTone(live.state) : "quiet", by: "hub", host_note: hostWord === "stalled" ? "the host saw it quiet" : null };
  }
  if (agent.done) return { label: "done", tone: "done", by: "host", host_note: null };
  if (agent.dead) return { label: "dead", tone: "dead", by: "host", host_note: null };
  if (agent.stalled) return { label: "stalled", tone: "quiet", by: "host", host_note: null };
  const label = lastTool ?? "idle";
  return { label, tone: label === "wait" || label === "idle" ? "idle" : "working", by: "host", host_note: null };
}

/** How many seats the live hub puts in each state, or null when no hub is live (the markers count then). */
export function hubStateCounts(vms: readonly SeatVm[] | null | undefined): Record<string, number> | null {
  const live = hubLiveVms(vms);
  if (!live.length) return null;
  const counts: Record<string, number> = {};
  for (const v of live) counts[v.live!.state] = (counts[v.live!.state] ?? 0) + 1;
  return counts;
}

/** Each seat's state by id, for a list. */
export function seatStates(agents: readonly SeatAgent[], vms: readonly SeatVm[] | null | undefined, lastTool: ReadonlyMap<string, string> = new Map()): Map<string, SeatState> {
  const byAgent = new Map((vms ?? []).map((v) => [v.agent, v]));
  return new Map(agents.map((a) => [a.id, seatState(a, byAgent.get(a.id), lastTool.get(a.id) ?? null)]));
}
