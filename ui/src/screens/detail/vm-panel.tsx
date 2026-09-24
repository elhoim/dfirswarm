/**
 * A microVM run's VMs, one row each: what the kickoff's probe found in it,
 * how its image fits the run's packs, the hub's live word on its agent, and
 * what stop found and kept. A host run has none and shows nothing.
 */
import { Server } from "lucide-react";
import { Chip } from "@/components/console";
import { clock } from "@/lib/format";
import type { SwarmView, VmHealth } from "@/lib/types";

function liveChip(vm: VmHealth) {
  if (vm.stopped_at) return <Chip tone="neutral">put away {clock(vm.stopped_at)}</Chip>;
  if (!vm.live) return <Chip tone="neutral">no hub answer</Chip>;
  const tone = vm.live.state === "working" ? "kelp" : vm.live.state === "gone" ? "brick" : vm.live.state === "done" ? "moss" : "saffron";
  return (
    <Chip tone={tone}>
      {vm.live.state}
      {vm.live.connected ? "" : " · not linked"}
    </Chip>
  );
}

export function VmPanel({ view }: { view: SwarmView }) {
  const vms = view.vms ?? [];
  if (!vms.length) return null;
  const expected = vms.find((v) => v.image.expected)?.image.expected ?? null;
  const offDigest = expected ? vms.filter((v) => v.image.digest && v.image.digest !== expected) : [];
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
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead className="text-left text-ink-3">
            <tr>
              <th className="py-1 pr-3 font-normal">Agent</th>
              <th className="py-1 pr-3 font-normal">Now</th>
              <th className="py-1 pr-3 font-normal">At kickoff</th>
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
              return (
                <tr key={vm.agent} className="border-t border-line align-top">
                  <td className="py-1.5 pr-3 font-mono">
                    {vm.agent}
                    <span className="block text-[11px] text-ink-3">
                      {vm.cpus ?? "?"} vCPU · {vm.memory_mib ?? "?"} MiB
                    </span>
                  </td>
                  <td className="py-1.5 pr-3">{liveChip(vm)}</td>
                  <td className={`py-1.5 pr-3 ${vm.probe.hub && !vm.probe.missing.length ? "text-ink-2" : "text-brick-ink"}`}>
                    {kickoff.join(" · ")}
                    {vm.fit_warnings.length ? <span className="block text-[11.5px] text-saffron-ink">{vm.fit_warnings.join(" · ")}</span> : null}
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
