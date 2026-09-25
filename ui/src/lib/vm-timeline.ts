/**
 * A microVM run's life, from the record and the trace: each VM's own steps
 * (created, probed, linked, capped, left, put away with its disk and msb's
 * database), the run's milestones in words, and one timeline across the run
 * with a lane for the run itself (kickoff, the keeper's restarts of the hub
 * and the collector, the finish, custody, the clear-up, the operator's
 * actions) and a lane per seat (created, every link up and down, a cap
 * steer or stop, the session's end, put away). Pure: the server builds the
 * timeline over the whole trace, and node tests import it as the client does.
 */
import { bytes, clock } from "./format.ts";

export type LifeTone = "neutral" | "moss" | "saffron" | "brick" | "kelp";

export type LifeStep = { at: string | null; what: string; tone: LifeTone };

/** The VM fields the lifecycle reads; the server's and the client's VmHealth both have them. */
export type LifeVm = {
  agent: string;
  created_at?: string | null;
  stopped_at: string | null;
  cap_stopped_at?: string | null;
  kept?: string | null;
  snapshot: string | null;
  snapshot_detail?: { bytes: number | null; error: string | null } | null;
  msb_db?: string | null;
  probe_checks?: Array<{ ok: boolean }>;
  hub_restarts?: number;
  collector_restarts?: number;
  keeper_gave_up_at?: string | null;
};

/** What the finish did to msb's database, in the words an examiner needs. */
export const MSB_DB: Record<string, { tone: LifeTone; words: string }> = {
  scrubbed: { tone: "moss", words: "msb's database cleared of this VM's configuration" },
  busy: { tone: "saffron", words: "msb's database was busy: this VM's configuration (a secret's value included) may remain in it until a later stop clears it" },
  "no sqlite3": { tone: "saffron", words: "no sqlite3 on this host: msb's database was not cleared; a secret's value may remain in it" },
  "no database": { tone: "neutral", words: "msb kept no database here" },
};

function probeStep(vm: LifeVm): { what: string; tone: LifeTone } | null {
  const checks = vm.probe_checks ?? [];
  if (!checks.length) return null;
  const failed = checks.filter((c) => !c.ok).length;
  return failed ? { what: `probe: ${failed} of ${checks.length} checks FAILED`, tone: "brick" } : { what: `probe: ${checks.length} of ${checks.length} checks held`, tone: "moss" };
}

function diskWords(vm: LifeVm): { what: string; tone: LifeTone } | null {
  if (vm.snapshot === "kept") return { what: `disk kept${vm.snapshot_detail?.bytes ? ` (${bytes(vm.snapshot_detail.bytes)})` : ""}`, tone: "moss" };
  if (vm.snapshot === "failed") return { what: "disk NOT kept", tone: "brick" };
  if (vm.snapshot === "not kept") return { what: "disk not kept (--no-vm-snapshot)", tone: "neutral" };
  return null;
}

/** One VM's life, in order: what its record says happened to it. */
export function vmLifecycle(vm: LifeVm): LifeStep[] {
  const steps: LifeStep[] = [];
  if (vm.created_at) steps.push({ at: vm.created_at, what: "created", tone: "neutral" });
  const probe = probeStep(vm);
  if (probe) steps.push({ at: null, ...probe });
  if (vm.cap_stopped_at) steps.push({ at: vm.cap_stopped_at, what: "stopped at its own cap by the hub", tone: "saffron" });
  if (vm.stopped_at) steps.push({ at: vm.stopped_at, what: "put away", tone: "neutral" });
  if (vm.kept) steps.push({ at: null, what: "KEPT, not put away", tone: "brick" });
  const disk = diskWords(vm);
  if (disk) steps.push({ at: null, ...disk });
  if (vm.msb_db) steps.push({ at: null, what: vm.msb_db === "scrubbed" ? "msb DB cleared" : `msb DB ${vm.msb_db}`, tone: MSB_DB[vm.msb_db]?.tone ?? "neutral" });
  return steps;
}

/** The run's VM milestones in words, for the Story: up, probed, restarts, caps, put away, msb's database, custody. */
export function runMilestones(vms: readonly LifeVm[], custody: { verdict: string; problems: readonly string[] } | null): Array<{ what: string; tone: LifeTone }> {
  if (!vms.length) return [];
  const steps: Array<{ what: string; tone: LifeTone }> = [];
  const created = vms.map((v) => v.created_at).filter((x): x is string => Boolean(x)).sort();
  steps.push({ what: `${vms.length} VM${vms.length === 1 ? "" : "s"} up${created.length ? ` at ${clock(created[0])}` : ""}`, tone: "kelp" });
  if (vms.some((v) => (v.probe_checks ?? []).length)) {
    const failed = vms.filter((v) => (v.probe_checks ?? []).some((c) => !c.ok));
    steps.push(failed.length ? { what: `isolation checks FAILED in ${failed.map((v) => v.agent).join(", ")}`, tone: "brick" } : { what: "every VM's isolation checks held", tone: "moss" });
  }
  const head = vms[0];
  if (head.hub_restarts) steps.push({ what: `hub restarted ${head.hub_restarts}× by its keeper`, tone: "saffron" });
  if (head.collector_restarts) steps.push({ what: `collector restarted ${head.collector_restarts}×`, tone: "saffron" });
  if (head.keeper_gave_up_at) steps.push({ what: `the keeper gave up on the hub at ${head.keeper_gave_up_at}`, tone: "brick" });
  const capped = vms.filter((v) => v.cap_stopped_at);
  if (capped.length) steps.push({ what: `${capped.map((v) => v.agent).join(", ")} stopped at their own cap`, tone: "saffron" });
  const away = vms.filter((v) => v.stopped_at && !v.kept);
  const kept = vms.filter((v) => v.kept);
  if (away.length) steps.push({ what: `${away.length === vms.length ? "every VM" : `${away.length} of ${vms.length} VMs`} put away${vms.some((v) => v.snapshot === "kept") ? ", disks kept" : ""}`, tone: "moss" });
  if (kept.length) steps.push({ what: `${kept.map((v) => v.agent).join(", ")} NOT put away`, tone: "brick" });
  const dbs = [...new Set(vms.map((v) => v.msb_db).filter((x): x is string => Boolean(x)))];
  if (dbs.length) steps.push(dbs.every((d) => d === "scrubbed" || d === "no database") ? { what: "msb's database cleared", tone: "moss" } : { what: `msb's database ${dbs.join(", ")}`, tone: "saffron" });
  if (custody) steps.push({ what: `custody ${custody.verdict === "clean" ? "clean" : `${custody.problems.length} to look at`}`, tone: custody.verdict === "clean" ? "moss" : "brick" });
  return steps;
}

export type TimelineKind =
  | "kickoff"
  | "created"
  | "linked"
  | "link_lost"
  | "cap_steer"
  | "cap_stop"
  | "left"
  | "put_away"
  | "kept"
  | "finish"
  | "custody"
  | "hub_restart"
  | "collector_restart"
  | "keeper_gave_up"
  | "clear_up"
  | "harness_stop"
  | "operator"
  | "ended";

export type TimelineMark = { at: string; pct: number; lane: string; kind: TimelineKind; what: string; tone: LifeTone };

export type VmTimeline = {
  from: string;
  to: string;
  /** "run", then one per seat in the team's order. */
  lanes: string[];
  /** Every mark in time order; `pct` is its place between from and to. */
  marks: TimelineMark[];
};

type TimelineEvent = { ts: string; agent: string; tool: string; args?: unknown; result?: unknown };

function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
}

/**
 * The run's timeline across its VMs. Null for a run with no VM. `events` is
 * the whole trace (the server passes it; the view's tail would lose the
 * kickoff's early links); `now` closes a run still going.
 */
export function vmTimeline(input: { started_at: string | null; finished_at: string | null; now: number; vms: readonly LifeVm[]; events: readonly TimelineEvent[] }): VmTimeline | null {
  const { vms, events } = input;
  if (!vms.length) return null;
  const seats = new Set(vms.map((v) => v.agent));
  const raw: Array<Omit<TimelineMark, "pct">> = [];
  const add = (at: string | null | undefined, lane: string, kind: TimelineKind, what: string, tone: LifeTone) => {
    if (at && Number.isFinite(Date.parse(at))) raw.push({ at, lane, kind, what, tone });
  };
  add(input.started_at, "run", "kickoff", "kickoff", "kelp");
  const linked = new Set<string>();
  const finishedBySeatEvent = new Set<string>();
  for (const e of events) {
    const a = rec(e.args);
    const r = rec(e.result);
    const failed = r.ok === false;
    const seat = typeof a.agent === "string" ? a.agent : null;
    switch (e.tool) {
      case "hub_link":
        if (seat && seats.has(seat)) {
          if (r.up === false) add(e.ts, seat, "link_lost", "lost its link to the hub", "saffron");
          else {
            add(e.ts, seat, "linked", linked.has(seat) ? "linked to the hub again" : "linked to the hub: running", "kelp");
            linked.add(seat);
          }
        }
        break;
      case "agent_cap_steer":
        if (seat && seats.has(seat)) add(e.ts, seat, "cap_steer", "steered by the hub to finish: over its own cap", "saffron");
        break;
      case "agent_cap_stop":
        if (seat && seats.has(seat)) add(e.ts, seat, "cap_stop", "stopped at its own cap by the hub", "saffron");
        break;
      case "agent_stop":
        if (seats.has(e.agent)) add(e.ts, e.agent, "left", `session ended${typeof a.reason === "string" && a.reason ? `: ${a.reason}` : ""}`, "neutral");
        break;
      case "vm_finish":
        if (seat && seats.has(seat)) {
          finishedBySeatEvent.add(seat);
          add(e.ts, seat, failed ? "kept" : "put_away", failed ? `finish FAILED${r.error ? `: ${String(r.error)}` : ""}` : "put away by the hub", failed ? "brick" : "moss");
        } else add(e.ts, "run", "finish", failed ? `the VMs' finish FAILED${r.error ? `: ${String(r.error)}` : ""}` : "every VM put away", failed ? "brick" : "moss");
        break;
      case "custody":
        add(e.ts, "run", "custody", failed ? `custody could not finish${r.error ? `: ${String(r.error)}` : ""}` : "custody taken", failed ? "brick" : "moss");
        break;
      case "hub_restarted":
        add(e.ts, "run", "hub_restart", `the keeper restarted the hub${typeof a.restart === "number" ? ` (restart ${a.restart})` : ""}${failed ? ", and it did not come up" : ""}`, failed ? "brick" : "saffron");
        break;
      case "collector_restarted":
        add(e.ts, "run", "collector_restart", `the keeper restarted the collector${typeof a.restart === "number" ? ` (restart ${a.restart})` : ""}${failed ? ", and it did not come up" : ""}`, failed ? "brick" : "saffron");
        break;
      case "hub_clear_up":
        add(e.ts, "run", "clear_up", "the hub cleared up after finishing", "neutral");
        break;
      case "harness_stop":
        add(e.ts, "run", "harness_stop", `the harness stopped the run${a.reason ? `: ${String(a.reason)}` : ""}`, "neutral");
        break;
      case "operator_action":
        add(e.ts, "run", "operator", `the operator ran ${String(a.command ?? "?")}${a.via ? ` via ${String(a.via)}` : ""}`, "neutral");
        break;
    }
  }
  for (const vm of vms) {
    const probe = probeStep(vm);
    add(vm.created_at, vm.agent, "created", `created${probe ? ` · ${probe.what}` : ""}`, probe?.tone === "brick" ? "brick" : "kelp");
    // The record's own stop, with what it kept; the hub's per-seat finish
    // line says the same moment, so the record is shown once when it has it.
    if (vm.stopped_at) {
      const disk = diskWords(vm);
      const db = vm.msb_db ? (vm.msb_db === "scrubbed" ? "msb DB cleared" : `msb DB ${vm.msb_db}`) : null;
      const tone: LifeTone = vm.kept || disk?.tone === "brick" ? "brick" : vm.msb_db && MSB_DB[vm.msb_db]?.tone === "saffron" ? "saffron" : "moss";
      if (finishedBySeatEvent.has(vm.agent)) {
        for (let i = raw.length - 1; i >= 0; i -= 1) if (raw[i].lane === vm.agent && raw[i].kind === "put_away") raw.splice(i, 1);
      }
      add(vm.stopped_at, vm.agent, vm.kept ? "kept" : "put_away", [vm.kept ? `KEPT, not put away: ${vm.kept}` : "put away", disk?.what, db].filter(Boolean).join(" · "), tone);
    }
  }
  add(vms[0]?.keeper_gave_up_at, "run", "keeper_gave_up", "the keeper gave up on the hub", "brick");
  add(input.finished_at, "run", "ended", "the run ended", "neutral");
  if (!raw.length) return null;
  const times = raw.map((m) => Date.parse(m.at));
  const fromMs = Math.min(...times);
  const toMs = Math.max(...times, input.finished_at ? Date.parse(input.finished_at) : input.now);
  const span = Math.max(1, toMs - fromMs);
  const marks = raw
    .map((m) => ({ ...m, pct: Math.min(100, Math.max(0, ((Date.parse(m.at) - fromMs) / span) * 100)) }))
    .sort((x, y) => Date.parse(x.at) - Date.parse(y.at));
  return { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString(), lanes: ["run", ...vms.map((v) => v.agent)], marks };
}
