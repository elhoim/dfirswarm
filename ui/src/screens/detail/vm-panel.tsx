/**
 * A microVM run's VMs: what the run's policy gives every VM (the network,
 * the placeholders, the pack secrets), then one card per agent's VM with its
 * life so far — created, probed (each isolation check the kickoff made), the
 * hub's live word on its agent, what the hub refused it, a cap stop, and what
 * stop found and kept: the disk, msb's database, the logs. Above them,
 * whether the hub and its keeper are up at all: a dead hub's last status
 * reads exactly like a live one, so the panel says which it is, and a hub
 * that finished the run and exited is said as that, not as a hub that is
 * down. A host run has none and shows nothing.
 */
import { Server } from "lucide-react";
import { Chip, type Tone } from "@/components/console";
import { InlineNote } from "@/components/states";
import { bytes, clock, money, shortDuration } from "@/lib/format";
import type { SwarmView, VmHealth } from "@/lib/types";
import { MSB_DB, vmLifecycle, type TimelineMark, type VmTimeline } from "@/lib/vm-timeline";

function liveChip(vm: VmHealth, hubDown: boolean) {
  if (vm.stopped_at) return <Chip tone="neutral">put away {clock(vm.stopped_at)}</Chip>;
  if (!vm.live) return <Chip tone="neutral">no hub answer</Chip>;
  const tone = hubDown ? "neutral" : vm.live.state === "working" ? "kelp" : vm.live.state === "gone" ? "brick" : vm.live.state === "done" ? "moss" : "saffron";
  return (
    <Chip tone={tone}>
      {hubDown ? "last known: " : ""}
      {vm.live.state}
      {vm.live.connected ? "" : " · not linked"}
    </Chip>
  );
}

/** What the kickoff did with a pack's secrets, and how worried to be about it. */
const SECRET_MODE: Record<string, { tone: Tone; words: string }> = {
  injected: { tone: "kelp", words: "injected: bound to their hosts, the value never in a VM" },
  withheld: { tone: "saffron", words: "withheld: not given to the VMs (no --allow-pack-secrets, or a secret that names no host)" },
  exposed: { tone: "brick", words: "exposed to the panes (--allow-pack-secrets)" },
  "not-set": { tone: "neutral", words: "not set on this host" },
};

function reaches(network: VmHealth["network"]): string {
  if (!network) return "no network record";
  if (network.default === "public") return "OPEN: every public host (--no-netguard); credentials still only to their own hosts";
  const hosts = network.allow_hosts.length ? network.allow_hosts.join(", ") : "nothing";
  const ports = network.host_ports.length ? ` · this host's ports ${network.host_ports.join(", ")}` : "";
  return `deny by default, then ${hosts}${ports}`;
}

function placeholders(vm: VmHealth): string {
  return vm.secrets.map((s) => `${s.name} → ${s.hosts.length ? s.hosts.join(", ") : "no host"}`).join(" · ");
}

function sameAcross<T>(vms: VmHealth[], pick: (vm: VmHealth) => T): boolean {
  const first = JSON.stringify(pick(vms[0]));
  return vms.every((v) => JSON.stringify(pick(v)) === first);
}

export function VmPanel({ view }: { view: SwarmView }) {
  const vms = view.vms ?? [];
  if (!vms.length) return null;
  const expected = vms.find((v) => v.image.expected)?.image.expected ?? null;
  const offDigest = expected ? vms.filter((v) => v.image.digest && v.image.digest !== expected) : [];
  const head = vms[0];
  const hubAlive = head.hub_alive;
  const hubDetail = head.hub_detail;
  const hubEnded = head.hub_ended === true;
  const allAway = vms.every((v) => v.stopped_at);
  // A hub that is down while VMs are still up is the loud case: nothing
  // carries their board, trace or stop. A hub that finished the run and
  // exited is what should happen; after every VM is put away a leftover is
  // only something for stop to clean.
  const hubDown = hubAlive === false && !hubEnded;
  const packSecrets = head.pack_secrets;
  const sharedNet = sameAcross(vms, (v) => v.network);
  const sharedSecrets = sameAcross(vms, (v) => v.secrets);
  const spendOf = new Map(view.agents.map((a) => [a.id, a.spent_usd]));
  return (
    <section className="card min-w-0 space-y-3 p-4" aria-label="Virtual machines">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Server className="size-4 text-kelp-ink" />
        <span className="text-[14px] font-medium text-ink">VMs · one per agent</span>
        <Chip tone="band" mono wrap>
          {head.image.ref ?? "image not recorded"}
        </Chip>
        {expected ? (
          offDigest.length ? (
            <Chip tone="brick">{offDigest.length} booted another digest</Chip>
          ) : (
            <Chip tone="kelp" mono wrap>
              one digest · {expected}
            </Chip>
          )
        ) : null}
        {hubAlive === true ? (
          <span title={hubDetail ?? undefined}>
            <Chip tone="kelp">hub up{head.hub_status_age_s !== null ? ` · status written ${shortDuration(head.hub_status_age_s * 1000)} ago` : ""}</Chip>
          </span>
        ) : null}
        {hubEnded ? <Chip tone="moss">hub finished the run and exited</Chip> : null}
        {head.hub_finishing ? <Chip tone="moss">the hub is putting the VMs away</Chip> : null}
        {hubAlive === true && head.hub_keeper_alive === false ? <Chip tone="saffron">keeper not running: a hub that dies stays down</Chip> : null}
        {head.hub_restarts ? <Chip tone="saffron">hub restarted {head.hub_restarts}×</Chip> : null}
        {head.collector_restarts ? <Chip tone="saffron">collector restarted {head.collector_restarts}×</Chip> : null}
      </div>
      {head.keeper_gave_up_at ? (
        <InlineNote tone="danger">
          The keeper gave up on the hub at {head.keeper_gave_up_at}: it kept dying as soon as it started. Nothing brings it back; the hub's own log in its directory says why. <code>swarm.sh stop {view.summary.id}</code> puts the VMs away.
        </InlineNote>
      ) : null}
      {hubEnded ? (
        <InlineNote tone="ok">{hubDetail}</InlineNote>
      ) : hubDown ? (
        allAway || head.hub_tone !== "danger" ? (
          <InlineNote tone="warn">
            {hubDetail}
            {allAway ? " Every VM is put away; stop cleans up what is left." : ""}
          </InlineNote>
        ) : (
          <InlineNote tone="danger">
            <strong>{hubDetail}</strong> While it is down nothing writes the board for the VMs, carries their trace to the collector, or enforces the caps and the stop from outside them; the agents fail closed within minutes. <code>swarm.sh stop {view.summary.id}</code> puts the VMs away.
          </InlineNote>
        )
      ) : null}
      <div className="grid min-w-0 gap-1 text-[12.5px]">
        {sharedNet ? (
          <div className="flex min-w-0 flex-wrap items-baseline gap-2">
            <span className="label-caps">Network · every VM</span>
            <span className={`min-w-0 [overflow-wrap:anywhere] ${head.network?.default === "public" ? "text-brick-ink" : "text-ink-2"}`}>{reaches(head.network)}</span>
          </div>
        ) : null}
        {sharedSecrets && head.secrets.length ? (
          <div className="flex min-w-0 flex-wrap items-baseline gap-2">
            <span className="label-caps">Placeholders · every VM</span>
            <span className="min-w-0 text-ink-2 [overflow-wrap:anywhere]">{placeholders(head)} · each swapped for the real value only toward its own hosts, in request headers</span>
          </div>
        ) : null}
        {packSecrets.length ? (
          <div className="flex min-w-0 flex-col gap-1">
            <span className="label-caps">Pack secrets</span>
            {packSecrets.map((p) => {
              const mode = SECRET_MODE[p.mode] ?? { tone: "neutral" as Tone, words: p.mode };
              return (
                <div key={p.pack} className="flex min-w-0 flex-wrap items-baseline gap-2">
                  <span className="font-mono">{p.pack}</span>
                  <Chip tone={mode.tone}>{p.mode}</Chip>
                  <span className="min-w-0 text-ink-2 [overflow-wrap:anywhere]">
                    {p.names.join(", ")} · {mode.words}
                  </span>
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
      {view.vm_timeline ? <VmTimelineView timeline={view.vm_timeline} /> : null}
      <ol className="m-0 grid min-w-0 list-none gap-3 p-0 lg:grid-cols-2">
        {vms.map((vm) => (
          <li key={vm.agent} className="min-w-0">
            <VmCard vm={vm} hubDown={hubDown} showNet={!sharedNet} showSecrets={!sharedSecrets} spent={spendOf.get(vm.agent) ?? null} />
          </li>
        ))}
      </ol>
    </section>
  );
}

function VmCard({ vm, hubDown, showNet, showSecrets, spent }: { vm: VmHealth; hubDown: boolean; showNet: boolean; showSecrets: boolean; spent: number | null }) {
  const skew = vm.probe.clock_skew_s;
  const checks = vm.probe_checks ?? [];
  const failed = checks.filter((c) => !c.ok);
  const upFor = vm.created_at ? Date.parse(vm.stopped_at ?? new Date().toISOString()) - Date.parse(vm.created_at) : null;
  const snap = vm.snapshot_detail;
  const msb = vm.msb_db ? (MSB_DB[vm.msb_db] ?? { tone: "neutral" as Tone, words: `msb's database: ${vm.msb_db}` }) : null;
  const trouble = Boolean(vm.kept || vm.snapshot === "failed" || failed.length || vm.installed_outside.length || vm.runtime_changed || (vm.msb_db && vm.msb_db !== "scrubbed" && vm.msb_db !== "no database"));
  return (
    <article className={`min-w-0 space-y-2 rounded-[8px] border p-3 ${trouble ? "border-brick/40" : "border-line"}`} aria-label={`VM of ${vm.agent}`}>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="font-mono text-[13px] text-ink">{vm.agent}</span>
        <span className="text-[11.5px] text-ink-3">
          {vm.cpus ?? "?"} vCPU · {vm.memory_mib ?? "?"} MiB
          {upFor !== null && Number.isFinite(upFor) ? ` · ${vm.stopped_at ? "ran" : "up"} ${shortDuration(upFor)}` : ""}
          {vm.max_duration_sec ? ` · at most ${shortDuration(vm.max_duration_sec * 1000)}` : ""}
        </span>
        <span className="ml-auto">{liveChip(vm, hubDown && !vm.stopped_at)}</span>
      </div>
      <div className="flex min-w-0 flex-wrap gap-1">
        {vmLifecycle(vm).map((s, i) => (
          <Chip key={i} tone={s.tone} wrap>
            {s.at ? `${clock(s.at)} · ` : ""}
            {s.what}
          </Chip>
        ))}
      </div>
      {vm.live?.last_seen && !vm.stopped_at ? (
        <p className="m-0 text-[11.5px] text-ink-3">
          last heard {clock(vm.live.last_seen)}
          {vm.live.detail ? <span className="text-ink-2"> · {vm.live.detail}</span> : null}
        </p>
      ) : null}
      {spent !== null ? <p className="m-0 text-[11.5px] text-ink-3">spend as this VM reported it: {money(spent)} (the host did not meter it)</p> : null}

      <div className="min-w-0 text-[12px]">
        <span className="label-caps">At kickoff</span>
        <p className={`m-0 mt-0.5 [overflow-wrap:anywhere] ${vm.probe.hub && !vm.probe.missing.length ? "text-ink-2" : "text-brick-ink"}`}>
          {[
            vm.probe.hub ? "hub linked" : "HUB NOT LINKED",
            vm.probe.inputs && vm.probe.inputs !== "absent" ? `evidence ${vm.probe.inputs}` : null,
            skew !== null ? `clock ${skew > 0 ? "+" : ""}${skew} s` : null,
            vm.probe.fuse === null ? null : `FUSE ${vm.probe.fuse ? "yes" : "no"}`,
            vm.probe.missing.length ? `missing ${vm.probe.missing.join(", ")}` : null,
          ]
            .filter(Boolean)
            .join(" · ")}
        </p>
        {vm.fit_warnings.length ? <p className="m-0 text-[11.5px] text-saffron-ink [overflow-wrap:anywhere]">{vm.fit_warnings.join(" · ")}</p> : null}
        {checks.length ? (
          <details className="mt-1 text-[11.5px]" open={failed.length > 0}>
            <summary className={`cursor-pointer ${failed.length ? "text-brick-ink" : "text-ink-3"}`}>
              isolation checked: {checks.length - failed.length} of {checks.length} held{failed.length ? ` · ${failed.length} FAILED` : ""}
            </summary>
            <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0">
              {checks.map((c) => (
                <li key={c.check} className={`[overflow-wrap:anywhere] ${c.ok ? "text-ink-2" : "text-brick-ink"}`}>
                  {c.ok ? "✓" : "✗"} {c.check}: wants {c.want}, found {c.got}
                  {c.meaning ? <span className={c.ok ? "text-ink-3" : undefined}> · {c.meaning}</span> : null}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </div>

      {vm.refusals?.length ? (
        <div className="min-w-0 text-[12px]">
          <span className="label-caps">Refused by the hub</span>
          <ul className="m-0 mt-0.5 flex list-none flex-col gap-0.5 p-0">
            {vm.refusals.map((r) => (
              <li key={r.fn} className="[overflow-wrap:anywhere] text-saffron-ink">
                <span className="font-mono">{r.fn}</span> × {r.count} · last {clock(r.last_at)}: {r.last_error}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {showNet || (showSecrets && vm.secrets.length) || vm.mounts.length ? (
        <div className="min-w-0 text-[12px] text-ink-2">
          {showNet ? <p className={`m-0 [overflow-wrap:anywhere] ${vm.network?.default === "public" ? "text-brick-ink" : ""}`}>{reaches(vm.network)}</p> : null}
          {showSecrets && vm.secrets.length ? <p className="m-0 text-[11.5px] [overflow-wrap:anywhere]">placeholders: {placeholders(vm)}</p> : null}
          {vm.mounts.length ? (
            <details className="text-[11.5px]">
              <summary className="cursor-pointer text-ink-3">
                {vm.mounts.length} mount{vm.mounts.length === 1 ? "" : "s"} · {vm.mounts.filter((m) => m.mode === "rw").length} writable
              </summary>
              <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono">
                {vm.mounts.map((m) => (
                  <li key={`${m.host}→${m.guest}`} className={`[overflow-wrap:anywhere] ${m.mode === "rw" ? "text-ink" : "text-ink-2"}`}>
                    {m.guest} ← {m.host} · {m.mode}
                    {m.noexec ? " · noexec" : ""}
                  </li>
                ))}
              </ul>
            </details>
          ) : (
            <p className="m-0 text-[11.5px] text-ink-3">no mounts recorded</p>
          )}
        </div>
      ) : null}

      {vm.stopped_at || snap || vm.kept || vm.msb_db ? (
        <div className="min-w-0 space-y-1 text-[12px]">
          <span className="label-caps">At stop</span>
          {vm.kept ? (
            <InlineNote tone="danger">
              <strong>Not put away:</strong> {vm.kept} Free what it names (disk space, a stuck VM), then run <code>swarm.sh stop</code> again: the kept VM is put away and its disk taken then.
            </InlineNote>
          ) : null}
          {snap?.path ? (
            <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
              disk kept at <span className="font-mono">{snap.path}</span>
              {snap.bytes !== null ? ` · ${bytes(snap.bytes)}` : ""}
              {snap.integrity === true ? " · msb's check passed" : snap.integrity === false ? " · msb's check FAILED" : ""}
              {snap.sha256 ? (
                <span className="block font-mono text-[11px] text-ink-3" title="sha256 of the kept disk">
                  sha256 {snap.sha256}
                </span>
              ) : null}
            </p>
          ) : snap?.error && !vm.kept ? (
            <p className="m-0 text-brick-ink [overflow-wrap:anywhere]">disk not kept: {snap.error}</p>
          ) : vm.snapshot === "not kept" ? (
            <p className="m-0 text-ink-3">disk not kept (the run said --no-vm-snapshot)</p>
          ) : null}
          {snap?.retry_error ? <p className="m-0 text-saffron-ink [overflow-wrap:anywhere]">a later snapshot failed and the earlier disk was kept: {snap.retry_error}</p> : null}
          {/* The lifecycle line above carries the chip; this is what it means. */}
          {msb ? <p className={`m-0 [overflow-wrap:anywhere] ${msb.tone === "saffron" ? "text-saffron-ink" : "text-ink-2"}`}>{msb.words}</p> : null}
          {vm.logs ? <p className="m-0 text-[11.5px] text-ink-3 [overflow-wrap:anywhere]">its logs kept at <span className="font-mono">{vm.logs}</span></p> : null}
          {vm.logs_not_kept?.length ? <p className="m-0 text-[11.5px] text-saffron-ink [overflow-wrap:anywhere]">logs not kept: {vm.logs_not_kept.join("; ")}</p> : null}
          {vm.installed_outside.length ? <p className="m-0 text-brick-ink [overflow-wrap:anywhere]">installed outside the image: {vm.installed_outside.join(", ")}</p> : null}
          {vm.runtime_changed ? <p className="m-0 text-brick-ink">msb changed during the run: {vm.runtime_changed}</p> : null}
        </div>
      ) : null}
    </article>
  );
}

const DOT: Record<TimelineMark["tone"], string> = { kelp: "bg-kelp", moss: "bg-moss", saffron: "bg-saffron", brick: "bg-brick", neutral: "bg-ink-3" };

/**
 * The run's life across its VMs on one clock: a lane for the run (kickoff,
 * the keeper's restarts, the finish, custody, the operator) and one per
 * seat (created and probed, each link up and down, a cap, the session's
 * end, put away with the disk and msb's database). A mark says what it is
 * on hover; the list under it has every mark in words, in time order.
 */
export function VmTimelineView({ timeline }: { timeline: VmTimeline }) {
  const lanes = timeline.lanes.map((lane) => ({ lane, marks: timeline.marks.filter((m) => m.lane === lane) }));
  return (
    <section className="min-w-0 space-y-1.5" aria-label="The run's VM timeline">
      <div className="flex min-w-0 flex-wrap items-baseline justify-between gap-2">
        <span className="label-caps">Lifecycle</span>
        <span className="font-mono text-[11px] text-ink-3">
          {clock(timeline.from)} → {clock(timeline.to)}
        </span>
      </div>
      <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-center gap-x-2 gap-y-1">
        {lanes.map(({ lane, marks }) => (
          <div key={lane} className="contents">
            <span className="font-mono text-[11px] text-ink-2">{lane}</span>
            <div className="relative h-4 min-w-0 rounded-[3px] bg-paper-3">
              <div className="absolute inset-x-1.5 inset-y-0">
                {marks.map((m, i) => (
                  <span
                    key={`${m.kind}-${i}`}
                    title={`${clock(m.at)} · ${m.what}`}
                    aria-label={`${lane}: ${m.what} at ${clock(m.at)}`}
                    className={`absolute top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-1 ring-card ${DOT[m.tone]}`}
                    style={{ left: `${m.pct}%` }}
                  />
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      <details className="text-[12px]">
        <summary className="cursor-pointer text-ink-2">every mark, in time order ({timeline.marks.length})</summary>
        <ol className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0">
          {timeline.marks.map((m, i) => (
            <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2">
              <span className={`inline-block size-2 shrink-0 rounded-full ${DOT[m.tone]}`} />
              <span className="font-mono text-[11px] text-ink-3">{clock(m.at)}</span>
              <span className="font-mono text-[11px] text-ink-2">{m.lane}</span>
              <span className={`min-w-0 [overflow-wrap:anywhere] ${m.tone === "brick" ? "text-brick-ink" : "text-ink"}`}>{m.what}</span>
            </li>
          ))}
        </ol>
      </details>
    </section>
  );
}
