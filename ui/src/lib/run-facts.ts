/**
 * What the kickoff decided for a run, in the order an operator asks about
 * it, and where a run's spend figures come from. Pure: the Goal and Budget
 * tabs render it, and node tests import it.
 */
import { inputsGuardSummary } from "./inputs-words.ts";
import type { SwarmView } from "./types.ts";

/** Where the spend figures come from: the host's meter, or what each VM reported. */
export function spendSourceNote(vmRun: boolean): string {
  return vmRun
    ? "In a microVM run these are what each VM reported through the hub; the host did not meter them. The wall clock and each VM's longest run are the host's own brakes, and the hub stops a seat at its own cap on the spend it reports."
    : "Metered on the host from each pane's own usage.";
}


export type Fact = { label: string; value: string; title?: string; tone?: "warn" };

/**
 * Everything the kickoff decided, in one row, in the order an operator would
 * ask about it: where the agents run, what they may reach, what they may do
 * to the evidence, and what stops them.
 */
export function frameFacts(view: SwarmView): Fact[] {
  const r = (view.registry ?? {}) as Record<string, unknown>;
  const layout = (view.layout ?? {}) as Record<string, unknown>;
  const s = view.summary;
  const out: Fact[] = [];
  if (s.workspace_id) {
    const tabs = typeof layout.tabs === "number" ? `${layout.tabs} tab${layout.tabs === 1 ? "" : "s"} · ` : "";
    out.push({ label: "Panes", value: `${s.workspace_id} · ${tabs}${s.n} panes`, title: "The Herdr workspace this run's agents live in" });
  }
  // Where the agents lived: on this host, or one microVM each.
  const iso = (r.isolation ?? {}) as { mode?: string; image?: string; cpus?: number; memory_mib?: number; disk_mib?: number; snapshot?: boolean; oauth_allowed?: boolean; image_digest?: string | null; snapshot_dir?: string | null };
  if (iso.mode === "microvm") {
    out.push({
      label: "Isolation",
      value: `microVM per agent · ${iso.image ?? "image not recorded"}${iso.cpus ? ` · ${iso.cpus} vCPU` : ""}${iso.memory_mib ? ` · ${iso.memory_mib} MiB` : ""}${iso.disk_mib ? ` · ${iso.disk_mib} MiB disk` : ""}${iso.snapshot === false ? " · disks not kept" : ""}`,
      title: "Each agent ran Pi in its own microVM: the run read-only but for its own work/<id>/, extracted and quarantine directories, outputs and session; shared files published through the hub, the board written by the hub on the host, no credential inside. vm/<id>.json holds each VM's record.",
    });
    const snapDir = (typeof r.vm_snapshot_dir === "string" && r.vm_snapshot_dir) || iso.snapshot_dir;
    if (iso.snapshot !== false) out.push({ label: "Disks kept", value: snapDir ? String(snapDir) : "beside the run (<sandbox>.vm-snapshots)", title: "Where each VM's disk is kept as a snapshot at stop" });
    out.push({
      label: "OAuth in VMs",
      value: iso.oauth_allowed ? "allowed" : "refused",
      tone: iso.oauth_allowed ? "warn" : undefined,
      title: "A subscription's token is the operator's whole account at the provider; the kickoff refuses one in a VM unless --allow-oauth-in-vm",
    });
  } else {
    // What held a host run is what its record says it had, not the defaults.
    const holders = [r.write_guard && r.write_guard !== "none" ? "the write guard" : null, "the tool guard", r.netguard === false ? null : "netguard"].filter(Boolean) as string[];
    out.push({
      label: "Isolation",
      value: "host processes · unisolated",
      title: `Each agent ran as a Pi process on this host, with no VM around it (a run with no isolation recorded is one of these), held by ${holders.join(", ")}${r.write_guard === "none" ? "; the write guard was off" : ""}${r.netguard === false ? "; netguard was off" : ""}`,
    });
  }
  if (view.inputs) {
    out.push({
      label: "Inputs",
      value: `read-only · ${inputsGuardSummary(view.inputs).text}`,
      title: "Agents read inputs/ and can never write it; this is the guard each pane actually got",
    });
  }
  // Open is what the record says, in either field: a VM run with
  // --no-netguard records netguard_mode microvm-open, and its policy was
  // public, not deny by default.
  const netOpen = r.net === "open" || r.netguard_mode === "microvm-open" || r.netguard === false;
  out.push({
    label: "Network",
    value:
      netOpen ? "open" : r.net === "local" ? "local endpoints only" : r.net === "hosts" ? `allowlist + ${String(r.allow_hosts ?? "")}` : "allowlist only",
    tone: netOpen ? "warn" : undefined,
    title:
      iso.mode === "microvm"
        ? netOpen
          ? "Each agent's VM could reach every public host (--no-netguard); credentials still went only to their own hosts"
          : "What each agent's VM could reach: msb's network policy, deny by default"
        : netOpen
          ? "The panes could reach whatever this machine could: netguard was off"
          : "What the panes could reach through netguard",
  });
  if (r.toolbox && r.toolbox !== "off") out.push({ label: "Toolbox", value: String(r.toolbox), title: iso.mode === "microvm" ? "The tool sets and the packs' programs, checked in the run's image before the run started" : "The tool sets checked on this host before the run started" });
  if (r.catalog === true) out.push({ label: "Catalog", value: "first pass done", title: "The standard first pass over the evidence ran before any agent" });
  if (r.quarantine === true) out.push({ label: "Quarantine", value: "no-exec on extracts", title: "Nothing under work/extracted or work/quarantine can execute" });
  out.push({ label: "Forging", value: r.tool_forging ? "on" : "off", title: "Whether agents could write tools with make_tool and share them" });
  // Absent on runs older than the feature; those say nothing rather than "off".
  const selfCompact = view.registry?.self_compact;
  if (selfCompact && typeof selfCompact === "object") {
    // A line the operator left unset next to one they set is a default the
    // extension may have fitted to it per seat; say so rather than show it as set.
    const set = selfCompact.set;
    const fitted = set && (set.notice_at || set.warn_at || set.compact_at);
    const shown = (spec: string | undefined, fallback: string, isSet: boolean | undefined) => `${spec || fallback}${fitted && !isSet ? " (default)" : ""}`;
    out.push({
      label: "Self compaction",
      value: selfCompact.enabled
        ? `on · notice ${shown(selfCompact.notice_at, "40%", set?.notice_at)} · warning ${shown(selfCompact.warn_at, "50%", set?.warn_at)} · compact ${shown(selfCompact.compact_at, "60%", set?.compact_at)}${selfCompact.model ? ` · summaries by ${selfCompact.model}` : ""}`
        : "off",
      title:
        "Whether agents compacted their own context, the three lines against each model's ceiling (per-model entries after a comma), and the model the summaries went to. A line marked default is fitted per seat to the lines the operator set where it would be out of order; each agent's compact_config trace row has the numbers it ran at",
    });
  }
  // Absent on runs older than the bound; those say nothing rather than a number they never had.
  if (typeof view.registry?.inbox_page_chars === "number") {
    out.push({
      label: "Inbox page",
      value: view.registry.inbox_page_chars > 0 ? `${view.registry.inbox_page_chars.toLocaleString()} chars of post text per delivery` : "unbounded",
      title: "How much post text one inbox or wait delivery carried; whole posts only, the rest stayed unread for the next call",
    });
  }
  if (r.allow_install === true) {
    out.push(
      iso.mode === "microvm"
        ? {
            label: "Install",
            value: `${r.install_hosts === false ? "from the cache" : "pypi"} into each VM`,
            title: "Each agent could install into its own VM's disk (/opt/dfir/agent), root in its VM only; nothing went into work/.toolchain, and what a VM held beyond its image is listed at stop",
          }
        : { label: "Install", value: "pypi into the sandbox", title: "Agents could pip-install into work/.toolchain; no root, no system packages" },
    );
  }
  out.push({ label: "Hard kill", value: view.budget?.hard_kill ? "on" : "off", title: "Whether a cap steer shuts the session down or waits out the grace period" });
  // What the kickoff recorded about how it ran and what it produced.
  const packSecrets = Object.entries((r.pack_secrets ?? {}) as Record<string, { names?: string[]; mode?: string }>);
  if (packSecrets.length) {
    out.push({
      label: "Pack secrets",
      value: packSecrets.map(([pack, v]) => `${pack}: ${v.mode ?? "?"}`).join(" · "),
      tone: packSecrets.some(([, v]) => v.mode === "exposed") ? "warn" : undefined,
      title: "What the kickoff did with each pack's secrets: injected as placeholders bound to their hosts (the operator's --allow-pack-secrets), withheld, exposed to host panes, or not set",
    });
  }
  const p = view.registry?.provenance;
  if (p) {
    out.push({
      label: "Provenance",
      value: `harness ${(p.harness_commit ?? "?").slice(0, 12)}${p.harness_dirty ? " (local changes)" : ""} · Node ${p.node_version ?? "?"} · Pi ${p.pi_version ?? "?"}${p.msb_version ? ` · msb ${p.msb_version}` : ""}`,
      tone: p.harness_dirty ? "warn" : undefined,
      title: `What produced the run: harness commit ${p.harness_commit ?? "?"}${p.harness_dirty ? ", with local changes" : ""}; Node ${p.node_version ?? "?"}; Pi ${p.pi_version ?? "?"}${p.msb_version ? `; msb ${p.msb_version}` : ""}${p.image_digest ? `; image ${p.image_digest}` : ""}; ${p.os ?? "?"} ${p.arch ?? ""}. The Custody tab shows it whole.`,
    });
  }
  const hc = view.registry?.host_clock;
  if (hc) {
    out.push({
      label: "Host clock",
      value: `${hc.tz ?? "?"} (UTC${hc.utc_offset ?? "?"}) · ${hc.synced === true ? "in sync" : hc.synced === false ? "not in sync" : "sync unknown"} · run processes in ${hc.run_processes_tz ?? "UTC"}`,
      tone: hc.synced === false ? "warn" : undefined,
      title: "The host's zone and clock sync at kickoff; the agents, the hub, the collector and the watchdogs ran in UTC, so a tool's local time and a zone-less time mean the same instant on every host",
    });
  }
  if (r.custody_timeout_sec !== undefined) out.push({ label: "Custody deadline", value: `${String(r.custody_timeout_sec)} s`, title: "How long the host's custody check at stop may take before it writes what it found and names what it did not reach" });
  if (r.idle_nudge_sec !== undefined) out.push({ label: "Idle nudge", value: Number(r.idle_nudge_sec) === 0 ? "off" : `${String(r.idle_nudge_sec)} s`, title: "How long a seat may sit quiet before the idle watchdog nudges it" });
  if (typeof r.disk_encryption === "string") {
    out.push({ label: "Disk", value: `encryption ${r.disk_encryption}`, tone: r.disk_encryption === "off" ? "warn" : undefined, title: "Whether the runs directory's volume is encrypted, as the kickoff found it" });
  }
  if (r.notify) out.push({ label: "Notify", value: "a command runs on the run's events", title: "--notify: finished, finish failed, stop incomplete, the cap, a changed evidence file or a broken chain. The command itself is not shown here." });
  const lf = r.ledger_from as string | { run?: string; entries?: number; reviewed?: boolean } | null | undefined;
  if (lf) {
    const run = typeof lf === "string" ? lf : lf.run;
    out.push({
      label: "Prior ledger",
      value: `${run ?? "?"}${typeof lf === "object" && typeof lf.entries === "number" ? ` · ${lf.entries} entries` : ""}${typeof lf === "object" && lf.reviewed === false ? " · unreviewed" : ""} · as hypotheses`,
      title: "--ledger-from: an earlier run's claims handed to this one to re-derive or refute from the evidence (prior/ledger.md), never counted as findings",
    });
  }
  if (typeof r.synced_folder_allowed_by === "string" && r.synced_folder_allowed_by) {
    out.push({ label: "Synced folder", value: `allowed by ${r.synced_folder_allowed_by}`, tone: "warn", title: "A copy of the evidence or the VMs' disks went into a synced folder (Dropbox, iCloud, OneDrive): its provider holds a copy" });
  }
  if (typeof r.cap_per_agent_usd === "number" && r.cap_per_agent_usd > 0) {
    out.push({ label: "Per agent", value: `$${r.cap_per_agent_usd}`, title: "What one agent may spend before it is steered to finish and stopped" });
  }
  if (typeof r.cap_per_agent_tokens === "number" && r.cap_per_agent_tokens > 0) {
    out.push({ label: "Per agent", value: `${r.cap_per_agent_tokens.toLocaleString("en-US")} tokens`, title: "What one agent may use in tokens before it is steered to finish and stopped" });
  }
  return out;
}
