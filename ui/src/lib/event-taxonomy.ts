/**
 * How a trace event is classified, shared by the console server
 * (`scripts/ui/model.ts`) and the client (`screens/detail/agents-panel.tsx`)
 * so the two cannot drift. Pure: no node imports, safe for the browser bundle.
 */

/** A tool call the agent would count as having gone wrong. */
export function isFailureEvent(e: { tool: string; result: unknown }): boolean {
  if (e.tool === "claim_violation") return true;
  const r = e.result;
  if (typeof r !== "object" || r === null) return false;
  const rec = r as Record<string, unknown>;
  return rec.ok === false || typeof rec.error === "string" || rec.timed_out === true || rec.blocked === true;
}

/**
 * What a trace line is about, beyond the agents' own calls: the run's
 * infrastructure (the hub, the VMs, the keeper, the collector, custody, the
 * caps the hub enforces) or the operator (a command from the console or a
 * shell, a file opened with its scripts). The raw trace files these under
 * the harness's `system` agent; the console gives them their own lane.
 */
export type EventCategory = "infrastructure" | "operator" | "agent";

const INFRASTRUCTURE = new Set([
  "hub_call",
  "hub_link",
  "hub_restarted",
  "hub_clear_up",
  "collector_restarted",
  "vm_finish",
  "custody",
  "agent_cap_steer",
  "agent_cap_stop",
  "harness_stop",
  "idle_nudge",
  "notify",
  "repeat_hint",
  "budget_precall_stop",
]);
const OPERATOR = new Set(["operator_action", "artifact_scripts"]);

export function eventCategory(e: { tool: string; agent?: string }): EventCategory {
  if (OPERATOR.has(e.tool) || e.agent === "operator") return "operator";
  if (INFRASTRUCTURE.has(e.tool)) return "infrastructure";
  return "agent";
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v);
}

/**
 * One line in words for an infrastructure or operator event; null for an
 * agent's own call (the trace shows its arguments). Nothing is cut: the
 * words name what the record holds, and the row unfolds to the whole line.
 */
export function describeEvent(e: { tool: string; agent: string; args?: unknown; result?: unknown }): string | null {
  const a = (e.args && typeof e.args === "object" ? e.args : {}) as Record<string, unknown>;
  const r = (e.result && typeof e.result === "object" ? e.result : {}) as Record<string, unknown>;
  const failed = r.ok === false;
  switch (e.tool) {
    case "hub_call":
      return failed
        ? `the hub refused ${str(a.agent)} ${str(a.fn)}${typeof r.repeated === "number" ? ` (${r.repeated} more times since)` : ""}: ${str(r.error)}`
        : `${str(a.agent)} ${str(a.fn)} through the hub`;
    case "hub_link":
      return `${str(a.agent)}'s VM ${r.up === false ? "lost its link to" : "linked to"} the hub`;
    case "hub_restarted":
      return `the keeper restarted the hub${typeof a.restart === "number" ? ` (restart ${a.restart})` : ""}${failed ? ", and it did not come up" : ""}`;
    case "collector_restarted":
      return `the keeper restarted the trace collector${typeof a.restart === "number" ? ` (restart ${a.restart})` : ""}${failed ? ", and it did not come up" : ""}`;
    case "hub_clear_up":
      return "the hub cleared up after finishing the run (swarm.sh stop --after-hub)";
    case "vm_finish":
      return failed
        ? `the VMs' finish FAILED${r.error ? `: ${str(r.error)}` : ""}`
        : `${a.agent ? `${str(a.agent)}'s VM put away` : "every VM put away"}${Array.isArray(r.msb_db) && r.msb_db.length ? ` · msb DB ${(r.msb_db as Array<{ agent?: unknown; msb_db?: unknown }>).map((x) => `${str(x.agent)} ${str(x.msb_db)}`).join(", ")}` : typeof r.msb_db === "string" ? ` · msb DB ${r.msb_db}` : ""}`;
    case "custody":
      return failed ? `custody could not finish${r.error ? `: ${str(r.error)}` : ""}` : `custody taken${r.summary ? `: ${str(r.summary)}` : ""}`;
    case "agent_cap_steer":
      return `the hub steered ${str(a.agent || e.agent)} to finish: over its own cap`;
    case "agent_cap_stop":
      return `the hub stopped ${str(a.agent || e.agent)} at its own cap`;
    case "harness_stop":
      return `the harness stopped the run${a.reason ? `: ${str(a.reason)}` : ""}`;
    case "idle_nudge":
      return `the idle watchdog nudged ${str(a.agent)}`;
    case "notify":
      return `the notify command ran for ${str(a.event)}${failed ? ", and failed" : ""}`;
    case "repeat_hint":
      return `${e.agent} was told its long command's whole output is already kept`;
    case "budget_precall_stop":
      return `${e.agent} was stopped before a model call: at its cap`;
    case "operator_action":
      return `the operator ran ${str(a.command)}${Array.isArray(a.argv) && a.argv.length ? ` ${(a.argv as unknown[]).map(str).join(" ")}` : ""}${a.via ? ` via ${str(a.via)}` : ""}${a.os_user ? ` as ${str(a.os_user)}` : ""}`;
    case "artifact_scripts":
      return `the operator opened ${str(a.path)} with its scripts${a.os_user ? ` as ${str(a.os_user)}` : ""}${a.sha256 ? ` (sha256 ${str(a.sha256)})` : ""}`;
    default:
      return null;
  }
}
