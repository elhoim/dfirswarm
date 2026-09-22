import { useEffect, useMemo, useState } from "react";
import type { AgentRow, SwarmEvent } from "./types";

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function useAgentNames(agents: AgentRow[] | undefined): (id: string) => string {
  return useMemo(() => {
    const map = new Map<string, string>();
    for (const a of agents ?? []) if (a.callsign) map.set(a.id, a.callsign);
    return (id: string) => {
      const c = map.get(id);
      return c ? `${c}` : id;
    };
  }, [agents]);
}

/** The chatter that "show all" reveals: polling, reading, and reasoning. */
export const NOISE_TOOLS = new Set([
  "inbox",
  "budget",
  "read",
  "bash",
  "list_team",
  "claims",
  "wait",
  "thinking",
  "grep",
  "find",
  "ls",
  // One row per turn end from the self-compaction extension: the time series
  // the context chart reads, and nothing a reader wants line by line.
  "context",
]);

export function isNoise(e: SwarmEvent): boolean {
  return NOISE_TOOLS.has(e.tool);
}

export type ToolTone = "brick" | "saffron" | "moss" | "kelp" | "slate" | "neutral";

export function toolTone(tool: string): ToolTone {
  switch (tool) {
    case "claim_violation":
      return "brick";
    case "reaped":
    case "reap":
      return "saffron";
    case "done":
    case "agent_stop":
      return "moss";
    case "post":
    case "inbox":
      return "kelp";
    case "claim_file":
    case "release_file":
    case "claims":
    case "write":
    case "edit":
    case "file_history":
    case "file_restore":
    case "file_diff":
      return "slate";
    case "harness_stop":
    case "cap_steer":
    case "wall_steer":
      return "brick";
    case "thread_open":
    case "thread_join":
      return "kelp";
    case "make_tool":
    case "tool_loaded":
    case "tools":
    case "inputs":
    case "inputs_guard":
    case "inputs_check":
      return "slate";
    case "inputs_violation":
      return "brick";
    // Self-compaction: the compact line and a failed compaction are the two
    // things that stop an agent; the warning and a held call are its approach;
    // a compaction and a saved note are the hand-off working as designed.
    case "compact_forced":
    case "compact_failed":
      return "brick";
    case "compact_warning":
    case "compact_hold":
      return "saffron";
    case "compact_done":
    case "compact_note":
      return "moss";
    case "compact_notice":
    case "compact_start":
    case "compact_config":
    case "context":
      return "slate";
    default:
      return "neutral";
  }
}

export function toolLabel(tool: string): string {
  if (tool === "agent_stop") return "session end";
  if (tool === "agent_start") return "session start";
  if (tool === "harness_stop") return "harness stop";
  if (tool === "make_tool") return "make tool";
  if (tool === "tool_loaded") return "tool loaded";
  if (tool === "inputs_guard") return "inputs guard";
  if (tool === "inputs_violation") return "inputs violation";
  if (tool === "inputs_check") return "inputs check";
  if (tool === "compact_notice") return "compact notice";
  if (tool === "compact_warning") return "compact warning";
  if (tool === "compact_forced") return "compact line";
  if (tool === "compact_hold") return "held at the line";
  if (tool === "compact_note") return "note to self";
  if (tool === "compact_start") return "compaction start";
  if (tool === "compact_done") return "compaction";
  if (tool === "compact_failed") return "compaction failed";
  if (tool === "compact_config") return "compact config";
  if (tool === "context") return "context";
  return tool;
}
