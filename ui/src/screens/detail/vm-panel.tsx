/**
 * A microVM run's VMs, one row each: what the kickoff's probe found in it,
 * how its image fits the run's packs, what it mounts and may reach, the
 * hub's live word on its agent, and what stop found and kept. Above them,
 * whether the hub is up at all: a dead hub's last status reads exactly like
 * a live one, so the panel says which it is. A host run has none and shows
 * nothing.
 */
import { Server } from "lucide-react";
import { Chip, type Tone } from "@/components/console";
import { InlineNote } from "@/components/states";
import { clock, shortDuration } from "@/lib/format";
import type { SwarmView, VmHealth } from "@/lib/types";

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
  withheld: { tone: "saffron", words: "withheld: named no hosts, so not given to the VMs" },
  exposed: { tone: "brick", words: "exposed to the panes (--allow-pack-secrets)" },
  "not-set": { tone: "neutral", words: "not set on this host" },
};

function reaches(vm: VmHealth): string {
  if (!vm.network) return "no network record";
  if (vm.network.default === "public") return "OPEN: every public host (--no-netguard); credentials still only to their own hosts";
  const hosts = vm.network.allow_hosts.length ? vm.network.allow_hosts.join(", ") : "nothing";
  const ports = vm.network.host_ports.length ? ` · this host's ports ${vm.network.host_ports.join(", ")}` : "";
  return `deny by default, then ${hosts}${ports}`;
}

export function VmPanel({ view }: { view: SwarmView }) {
  const vms = view.vms ?? [];
  if (!vms.length) return null;
  const expected = vms.find((v) => v.image.expected)?.image.expected ?? null;
  const offDigest = expected ? vms.filter((v) => v.image.digest && v.image.digest !== expected) : [];
  const hubAlive = vms[0].hub_alive;
  const hubDetail = vms[0].hub_detail;
  const allAway = vms.every((v) => v.stopped_at);
  // A hub that is down while VMs are still up is the loud case: nothing
  // carries their board, trace or stop. After every VM is put away it is
  // only a leftover for stop to clean.
  const hubDown = hubAlive === false;
  const packSecrets = vms[0].pack_secrets;
  return (
    <section className="card space-y-3 p-4" aria-label="Virtual machines">
      <div className="flex flex-wrap items-center gap-2">
        <Server className="size-4 text-kelp-ink" />
        <span className="text-[14px] font-medium text-ink">VMs · one per agent</span>
        <Chip tone="band" mono>
          {vms[0].image.ref ?? "image not recorded"}
        </Chip>
        {expected ? (
          offDigest.length ? (
            <Chip tone="brick">{offDigest.length} booted another digest</Chip>
          ) : (
            <span title={expected}>
              <Chip tone="kelp" mono>
                one digest · {expected}
              </Chip>
            </span>
          )
        ) : null}
        {hubAlive === true ? (
          <span title={hubDetail ?? undefined}>
            <Chip tone="kelp">hub up{vms[0].hub_status_age_s !== null ? ` · status written ${shortDuration(vms[0].hub_status_age_s * 1000)} ago` : ""}</Chip>
          </span>
        ) : null}
        {vms[0].hub_finishing ? <Chip tone="moss">the hub is putting the VMs away</Chip> : null}
        {hubAlive === true && vms[0].hub_keeper_alive === false ? <Chip tone="saffron">keeper not running: a hub that dies stays down</Chip> : null}
      </div>
      {hubDown ? (
        allAway || vms[0].hub_tone !== "danger" ? (
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
      {packSecrets.length ? (
        <div className="flex flex-col gap-1 text-[12.5px]">
          <span className="label-caps">Pack secrets</span>
          {packSecrets.map((p) => {
            const mode = SECRET_MODE[p.mode] ?? { tone: "neutral" as Tone, words: p.mode };
            return (
              <div key={p.pack} className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono">{p.pack}</span>
                <Chip tone={mode.tone}>{p.mode}</Chip>
                <span className="text-ink-2 [overflow-wrap:anywhere]">
                  {p.names.join(", ")} · {mode.words}
                </span>
              </div>
            );
          })}
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead className="text-left text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-normal">Agent</th>
              <th className="py-1 pr-3 font-normal">Now</th>
              <th className="py-1 pr-3 font-normal">At kickoff</th>
              <th className="py-1 pr-3 font-normal">Reaches · mounts</th>
              <th className="py-1 pr-3 font-normal">At stop</th>
            </tr>
          </thead>
          <tbody>
            {vms.map((vm) => {
              const skew = vm.probe.clock_skew_s;
              const kickoff = [
                vm.probe.hub ? "hub linked" : "HUB NOT LINKED",
                `floor ${vm.probe.floor ?? "?"}`,
                vm.probe.inputs && vm.probe.inputs !== "absent" ? `evidence ${vm.probe.inputs}` : null,
                skew !== null ? `clock ${skew > 0 ? "+" : ""}${skew} s` : null,
                vm.probe.fuse === null ? null : `FUSE ${vm.probe.fuse ? "yes" : "no"}`,
                vm.probe.missing.length ? `missing ${vm.probe.missing.join(", ")}` : null,
              ].filter(Boolean);
              const atStop = [
                vm.snapshot ? `disk ${vm.snapshot}` : null,
                vm.installed_outside.length ? `installed outside the image: ${vm.installed_outside.join(", ")}` : null,
                vm.runtime_changed ? `msb changed ${vm.runtime_changed}` : null,
              ].filter(Boolean);
              const open = vm.network?.default === "public";
              return (
                <tr key={vm.agent} className="border-t border-line align-top">
                  <td className="py-1.5 pr-3 font-mono">
                    {vm.agent}
                    <span className="block text-[11px] text-ink-3">
                      {vm.cpus ?? "?"} vCPU · {vm.memory_mib ?? "?"} MiB
                    </span>
                  </td>
                  <td className="py-1.5 pr-3">
                    {liveChip(vm, hubDown && !vm.stopped_at)}
                    {vm.live?.last_seen && !vm.stopped_at ? <span className="block text-[11px] text-ink-3">last heard {clock(vm.live.last_seen)}</span> : null}
                  </td>
                  <td className={`py-1.5 pr-3 ${vm.probe.hub && !vm.probe.missing.length ? "text-ink-2" : "text-brick-ink"}`}>
                    {kickoff.join(" · ")}
                    {vm.fit_warnings.length ? <span className="block text-[11.5px] text-saffron-ink">{vm.fit_warnings.join(" · ")}</span> : null}
                  </td>
                  <td className="py-1.5 pr-3 text-ink-2">
                    <span className={`block [overflow-wrap:anywhere] ${open ? "text-brick-ink" : ""}`}>{reaches(vm)}</span>
                    {vm.secrets.length ? (
                      <span className="block text-[11.5px] [overflow-wrap:anywhere]">
                        placeholders: {vm.secrets.map((s) => `${s.name} → ${s.hosts.length ? s.hosts.join(", ") : "no host"}`).join(" · ")}
                      </span>
                    ) : null}
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
                      <span className="block text-[11.5px] text-ink-3">no mounts recorded</span>
                    )}
                  </td>
                  <td className={`py-1.5 pr-3 ${vm.installed_outside.length || vm.snapshot === "failed" || vm.runtime_changed ? "text-brick-ink" : "text-ink-2"}`}>
                    {atStop.length ? atStop.join(" · ") : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
