/**
 * What the host could say about the run once nothing was running any more:
 * custody.json, which stop (or the hub, at the end of a VM run) writes after
 * re-hashing the evidence, checking the trace and ledger chains, and putting
 * each VM's disk away. The console used to show none of it, so a changed
 * evidence file or a secret aimed at the wrong host was only in a file
 * nobody opens. Every name is shown whole: nothing here is cut.
 */
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Chip } from "@/components/console";
import { dateTime } from "@/lib/format";
import type { CustodyView, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

function Names({ label, names }: { label: string; names: string[] }) {
  if (!names.length) return null;
  return (
    <details className="text-[12px]">
      <summary className="cursor-pointer text-ink-2">
        {names.length} {label}
      </summary>
      <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px] text-ink">
        {names.map((n) => (
          <li key={n} className="[overflow-wrap:anywhere]">
            {n}
          </li>
        ))}
      </ul>
    </details>
  );
}

function Row({ label, bad, children }: { label: string; bad?: boolean; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 border-t border-line py-2 sm:grid-cols-[140px_minmax(0,1fr)]">
      <span className="label-caps pt-0.5">{label}</span>
      <div className={cn("flex min-w-0 flex-col gap-1 text-[12.5px] [overflow-wrap:anywhere]", bad ? "text-brick-ink" : "text-ink-2")}>{children}</div>
    </div>
  );
}

function evidenceLine(e: NonNullable<CustodyView["evidence"]>): { text: string; bad: boolean } {
  if ("unverifiable" in e) return { text: `unverifiable: ${e.unverifiable}`, bad: true };
  const anchored = e.manifest_anchored === true ? "manifest anchored to the kickoff's record" : e.manifest_anchored === false ? "MANIFEST REWRITTEN: not the one the kickoff recorded" : "manifest not anchored (no kickoff record to compare)";
  // Skipped is what the deadline left unread: the verdict does not cover it.
  const skipped = e.skipped.length ? ` · ${e.skipped.length} NOT RE-READ before the deadline` : "";
  if (e.unchanged && e.complete) return { text: `unchanged · ${e.files} file${e.files === 1 ? "" : "s"} re-hashed in full · ${anchored}`, bad: e.manifest_anchored === false };
  if (e.changed.length || e.missing.length || e.added.length || e.manifest_anchored === false) {
    return { text: `CHANGED · ${e.changed.length} changed, ${e.missing.length} missing, ${e.added.length} added of ${e.files}${skipped} · ${anchored}`, bad: true };
  }
  return { text: `NOT FULLY RE-HASHED · ${e.files - e.skipped.length} of ${e.files} checked unchanged${skipped} · ${anchored}`, bad: true };
}

export function CustodyPanel({ view }: { view: SwarmView }) {
  const c = view.custody;
  const phase = view.summary.phase;
  if (!c) {
    if (phase === "running" || phase === "prepared" || view.summary.finishing) return null;
    return (
      <section className="card flex items-start gap-2.5 p-4 text-[12.5px] text-ink-2" aria-label="Custody">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-ink-3" />
        <span>
          No custody was taken for this run: no <code>custody.json</code>. <code>scripts/swarm.sh stop {view.summary.id}</code> takes it (the hub takes it itself at the end of a VM run), or run <code>scripts/custody.ts</code> on the sandbox.
        </span>
      </section>
    );
  }
  const clean = c.verdict === "clean";
  const ev = c.evidence ? evidenceLine(c.evidence) : null;
  return (
    <section className="card space-y-2 p-4" aria-label="Custody">
      <div className="flex flex-wrap items-center gap-2">
        {clean ? <ShieldCheck className="size-4 text-moss" /> : <ShieldAlert className="size-4 text-brick" />}
        <span className="text-[14px] font-medium text-ink">Custody</span>
        <Chip tone={clean ? "moss" : "brick"}>{clean ? "clean" : `${c.problems.length} to look at`}</Chip>
        {c.at ? <span className="font-mono text-[11.5px] text-ink-3">taken {dateTime(c.at)}</span> : null}
      </div>
      {c.summary ? <p className="m-0 font-mono text-[11.5px] leading-[1.55] text-ink-2 [overflow-wrap:anywhere]">{c.summary}</p> : null}
      {c.problems.length ? (
        <ul className="m-0 flex list-disc flex-col gap-0.5 pl-5 text-[12.5px] text-brick-ink">
          {c.problems.map((p) => (
            <li key={p} className="[overflow-wrap:anywhere]">
              {p}
            </li>
          ))}
        </ul>
      ) : null}
      <div className="flex flex-col">
        <Row label="Evidence" bad={ev?.bad}>
          {ev ? ev.text : "no evidence was given to this run"}
          {c.evidence && !("unverifiable" in c.evidence) ? (
            <>
              <Names label="changed" names={c.evidence.changed} />
              <Names label="missing" names={c.evidence.missing} />
              <Names label="added" names={c.evidence.added} />
              <Names label="not re-read before the deadline (the verdict does not cover them)" names={c.evidence.skipped} />
            </>
          ) : null}
        </Row>
        {c.incomplete ? (
          <Row label="Incomplete" bad>
            {c.incomplete}
          </Row>
        ) : null}
        {c.sessions_not_files.length ? (
          <Row label="Sessions" bad>
            {c.sessions_not_files.length} name{c.sessions_not_files.length === 1 ? "" : "s"} under the sessions not a regular file, so sealed as nothing
            <Names label="not a file" names={c.sessions_not_files} />
          </Row>
        ) : null}
        <Row label="Trace chain" bad={!c.trace || !c.trace.lines || !c.trace.intact || c.trace.lost > 0 || c.trace.refused_spills.length > 0}>
          {!c.trace
            ? "not checked"
            : !c.trace.lines
              ? "NO TRACE"
              : `${c.trace.lines} lines · ${c.trace.intact ? "chain intact" : `CHAIN NOT INTACT${c.trace.detail ? `: ${c.trace.detail}` : ""}`}${c.trace.unverified ? ` · ${c.trace.unverified} unverified` : ""}${c.trace.disputed ? ` · ${c.trace.disputed} disputed` : ""}${c.trace.spilled ? ` · ${c.trace.spilled} outside the chain (spilled)` : ""}${c.trace.lost ? ` · ${c.trace.lost} LOST` : ""}`}
          {c.trace?.refused_spills.length ? (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
              {c.trace.refused_spills.map((r) => (
                <li key={r.path} className="[overflow-wrap:anywhere]">
                  SPILL NOT READ: {r.path} is {r.why}
                </li>
              ))}
            </ul>
          ) : null}
        </Row>
        <Row label="Ledger chain" bad={!!c.ledger && !c.ledger.intact}>
          {!c.ledger
            ? "no ledger"
            : `${c.ledger.entries} entr${c.ledger.entries === 1 ? "y" : "ies"}${c.ledger.chained !== null && c.ledger.chained !== c.ledger.entries ? `, ${c.ledger.chained} chained` : ""} · ${c.ledger.intact ? "chain intact" : `NOT INTACT${c.ledger.detail ? `: ${c.ledger.detail}` : ""}`}`}
          {c.ledger ? (
            <>
              <Names label="on the trace and missing from the ledger (deleted)" names={c.ledger.missing_from_ledger} />
              <Names label="in the ledger and never on the trace (seq; written without the tool)" names={c.ledger.not_on_trace.map(String)} />
            </>
          ) : null}
        </Row>
        {c.tool_outputs ? (
          <Row label="Kept outputs" bad={!!(c.tool_outputs.missing.length || c.tool_outputs.mismatched.length || c.tool_outputs.refused.length)}>
            {c.tool_outputs.verified} of {c.tool_outputs.referenced} verified against the trace
            <Names label="missing" names={c.tool_outputs.missing} />
            <Names label="not matching the trace" names={c.tool_outputs.mismatched} />
            <Names label="refused" names={c.tool_outputs.refused} />
          </Row>
        ) : null}
        {c.vms?.map((vm) => {
          const away = vm.stopped && !vm.kept && !vm.snapshot?.startsWith("failed");
          const bad = !away || vm.image_differs || vm.secret_violations.length > 0 || vm.installed_outside.length > 0 || !!vm.runtime_changed;
          return (
            <Row key={vm.agent} label={`VM ${vm.agent}`} bad={bad}>
              <span>
                {away ? "put away" : `NOT PUT AWAY${vm.kept ? `: ${vm.kept}` : ""}`}
                {vm.snapshot ? ` · snapshot ${vm.snapshot}` : " · no snapshot"}
                {vm.runtime_changed ? ` · msb changed ${vm.runtime_changed}` : ""}
              </span>
              {vm.image_differs ? (
                <span>
                  IMAGE DIGEST DIFFERS: booted <code>{vm.image}</code>, the run expected <code>{vm.expected_image}</code>
                </span>
              ) : null}
              {vm.secret_violations.length ? (
                <div>
                  {vm.secret_violations.length} secret placeholder{vm.secret_violations.length === 1 ? "" : "s"} aimed at a host not its own, stopped by msb:
                  <ul className="m-0 mt-0.5 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
                    {vm.secret_violations.map((x, i) => (
                      <li key={i} className="[overflow-wrap:anywhere]">
                        {x.at} · {x.env} → {x.host} {x.method} {x.path} · {x.action}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {vm.installed_outside.length ? <span>installed outside the image and the toolchain record: {vm.installed_outside.join(", ")}</span> : null}
              {vm.installed_note ? <span className="text-ink-3">{vm.installed_note}</span> : null}
              {vm.record_sha256 ? <span className="font-mono text-[11px] text-ink-3">record sha256 {vm.record_sha256}</span> : null}
            </Row>
          );
        })}
      </div>
    </section>
  );
}
