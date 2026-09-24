/**
 * The read-only inputs a swarm was given: where they came from, every file
 * with its size, what guards them in each pane (measured, not assumed), the
 * writes that were caught and healed, and the final check an agent made when
 * it called done. Nothing here can be changed from the console; the whole
 * point of inputs/ is that nothing changes it.
 */
import { Lock, ShieldCheck, ShieldAlert, ShieldOff } from "lucide-react";
import { Chip } from "@/components/console";
import { EvidenceRow } from "@/components/evidence";
import { bytes, clock } from "@/lib/format";
import type { InputsView, SwarmView } from "@/lib/types";

function guardWord(guard: string): string {
  if (guard === "seatbelt") return "kernel (macOS sandbox-exec)";
  if (guard === "mountns") return "kernel (Linux mount namespace)";
  if (guard === "microvm") return "a read-only mount in each microVM";
  return "detect + heal";
}

function enforcedWord(enforced: string): { text: string; tone: "kelp" | "saffron" | "brick" } {
  if (enforced === "kernel") return { text: "kernel", tone: "kelp" };
  if (enforced === "mode") return { text: "permission bits", tone: "saffron" };
  return { text: "none", tone: "brick" };
}

export function inputsGuardSummary(inputs: InputsView): { text: string; tone: "kelp" | "saffron" | "brick" } {
  const seen = Object.values(inputs.enforced);
  if (seen.length === 0) return { text: inputs.guard === "none" ? "detect + heal" : `${guardWord(inputs.guard)} planned`, tone: inputs.guard === "none" ? "saffron" : "kelp" };
  if (inputs.guard === "microvm" && seen.every((v) => v === "kernel")) return { text: "read-only in every agent's microVM", tone: "kelp" };
  if (seen.every((v) => v === "kernel")) return { text: "kernel in every pane", tone: "kelp" };
  if (seen.some((v) => v === "kernel")) return { text: "kernel in some panes", tone: "saffron" };
  return { text: "detect + heal only", tone: "saffron" };
}

export function InputsPanel({ view }: { view: SwarmView }) {
  const inputs = view.inputs;
  if (!inputs) return null;
  const summary = inputsGuardSummary(inputs);
  const Icon = summary.tone === "kelp" ? ShieldCheck : summary.tone === "saffron" ? ShieldAlert : ShieldOff;
  const agents = view.agents.map((a) => a.id);
  return (
    <section className="card space-y-3 p-4" aria-label="Read-only inputs">
      <div className="flex flex-wrap items-center gap-2">
        <Lock className="size-4 text-kelp-ink" />
        <span className="text-[14px] font-medium text-ink">Inputs · read-only</span>
        <Chip tone="band" mono>
          {inputs.files.length} file{inputs.files.length === 1 ? "" : "s"} · {bytes(inputs.bytes)}
        </Chip>
        <Chip tone={summary.tone}>
          <Icon className="mr-1 inline size-3.5" /> {summary.text}
        </Chip>
        {inputs.violations.length ? <Chip tone="brick">{inputs.violations.length} write{inputs.violations.length === 1 ? "" : "s"} refused or healed</Chip> : null}
        {inputs.check ? <Chip tone={inputs.check.ok ? "kelp" : "brick"}>{inputs.check.ok ? `intact at the end (${inputs.check.checked} checked)` : "changed by the end"}</Chip> : null}
      </div>
      <p className="text-[12.5px] leading-[1.5] text-ink-2">
        Copied from <code className="break-all">{inputs.source || "the operator"}</code> into <code>inputs/</code>. Agents read and grep it; <code>edit</code>, <code>write</code> and <code>claim_file</code> refuse it, a shell write is undone from the pristine copy and announced, and where the host allows it the pane runs with <code>inputs/</code> read-only at the kernel ({guardWord(inputs.guard)} was set up at kickoff; enforcement asked: <code>{inputs.enforce}</code>).
      </p>
      {agents.length ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-ink-2">
          <span className="label-caps mr-1">Per pane</span>
          {agents.map((id) => {
            const seen = inputs.enforced[id];
            const word = seen ? enforcedWord(seen) : { text: "not started", tone: "saffron" as const };
            return (
              <Chip key={id} tone={word.tone} mono>
                {id} · {word.text}
              </Chip>
            );
          })}
        </div>
      ) : null}
      {/*
        The hash used to be `title={f.sha256}` and nothing else: computed at
        kickoff, carried in the manifest, shipped to this browser, and drawn
        as a hover. It is the one number that lets somebody else confirm they
        are looking at the same evidence, so it is on the row now.
      */}
      <ul className="max-h-80 space-y-1 overflow-auto" aria-label="Input files">
        {inputs.files.map((f) => (
          <li key={f.path}>
            <EvidenceRow path={f.path} bytes={f.bytes} sha={f.sha256} icon={<Lock />} meta={<span>read-only</span>} />
          </li>
        ))}
      </ul>
      {inputs.violations.length ? (
        <ol className="space-y-1 text-[12px] text-ink-2" aria-label="Refused and healed writes">
          {inputs.violations.map((e, i) => {
            const r = (e.result ?? {}) as { healed?: string; error?: string; blocked?: boolean; via?: string };
            const args = (e.args ?? {}) as { path?: string };
            return (
              <li key={`${e.ts}-${i}`} className="flex flex-wrap items-center gap-2">
                <span className="tabular text-ink-3">{clock(e.ts)}</span>
                <Chip tone="brick" mono>
                  {e.agent}
                </Chip>
                <code>{args.path}</code>
                <span>{r.blocked ? `${r.via ?? "write"} refused by the tool guard` : r.healed === "restored" ? "restored from the pristine copy after a shell write" : r.healed === "removed" ? "a planted file was removed" : `not healed${r.error ? `: ${r.error}` : ""}`}</span>
              </li>
            );
          })}
        </ol>
      ) : null}
      {inputs.check && !inputs.check.ok ? (
        <p className="text-[12px] text-brick">
          At {clock(inputs.check.at)} {inputs.check.by} found {inputs.check.modified.length} modified, {inputs.check.missing.length} missing and {inputs.check.added.length} added under <code>inputs/</code>. The pristine copy is under <code>.inputs-pristine/</code> in the sandbox.
        </p>
      ) : null}
    </section>
  );
}
