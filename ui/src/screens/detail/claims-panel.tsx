import { useMemo } from "react";
import { Lock, LockOpen, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/states";
import { clock, duration } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import type { SwarmEvent, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

type Sequence = { agent: string; path: string; steps: SwarmEvent[]; open: boolean };

/** Group claim → write/edit → release runs per (agent, path); inventory §5 #20. */
function sequences(events: SwarmEvent[]): Sequence[] {
  const open = new Map<string, Sequence>();
  const out: Sequence[] = [];
  for (const e of events) {
    // publish_file names its target `to` (a VM seat's write to a shared
    // file goes through the hub); every other step names it `path`.
    const target =
      e.tool === "publish_file"
        ? typeof e.args.to === "string" && e.args.to
          ? e.args.to
          : typeof e.args.path === "string"
            ? `work/${e.args.path.split("/").pop()}`
            : null
        : e.args.path;
    const path = typeof target === "string" ? target : null;
    if (!path) continue;
    const key = `${e.agent}\u0000${path}`;
    if (e.tool === "claim_file") {
      const r = e.result as { ok?: boolean } | null;
      if (r && r.ok === false) continue;
      if (!open.has(key)) {
        const seq: Sequence = { agent: e.agent, path, steps: [], open: true };
        open.set(key, seq);
        out.push(seq);
      }
      open.get(key)!.steps.push(e);
    } else if (["write", "edit", "file_restore", "file_history", "publish_file", "publish_needed"].includes(e.tool)) {
      open.get(key)?.steps.push(e);
    } else if (e.tool === "release_file") {
      const seq = open.get(key);
      if (seq) {
        seq.steps.push(e);
        seq.open = false;
        open.delete(key);
      }
    }
  }
  return out.reverse();
}

export function ClaimsPanel({ view, now }: { view: SwarmView; now: number }) {
  const names = useAgentNames(view.agents);
  const seqs = useMemo(() => sequences(view.traces), [view.traces]);
  // The server filters expired leases out of `claims`. An older payload has
  // only the raw lock directory, so derive the live ones from it rather than
  // reporting that nobody holds anything.
  const claims = useMemo(() => {
    if (view.claims) return view.claims;
    return (view.locks ?? [])
      .filter((l) => Date.parse(l.expires_at) > now)
      .map((l) => ({
        ...l,
        reason: l.reason ?? "",
        seconds: l.seconds ?? 0,
        expires_in_seconds: Math.max(0, Math.round((Date.parse(l.expires_at) - now) / 1000)),
      }));
  }, [view.claims, view.locks, now]);
  const reaps = view.traces.filter((e) => e.tool === "reap" || e.tool === "reaped");

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="space-y-2">
        <h3 className="label-caps flex items-center gap-1.5">
          <Lock className="size-3.5" /> Live claims ({claims.length})
        </h3>
        {claims.length ? (
          <div className="card overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b border-line text-left">
                  <th className="label-caps px-3 py-2">Path</th>
                  <th className="label-caps px-3 py-2">Owner</th>
                  <th className="label-caps px-3 py-2">Why</th>
                  <th className="label-caps px-3 py-2">Claimed</th>
                  <th className="label-caps px-3 py-2">Lease</th>
                </tr>
              </thead>
              <tbody>
                {claims.map((l) => {
                  const left = Date.parse(l.expires_at) - now;
                  return (
                    <tr key={l.path} className="border-b border-line last:border-0">
                      <td className="px-3 py-2 font-mono text-ink">{l.path}</td>
                      <td className="px-3 py-2">
                        <span className="font-medium text-ink">{names(l.owner)}</span>
                        {names(l.owner) !== l.owner ? <code className="ml-1 text-[11px] text-ink-3">{l.owner}</code> : null}
                      </td>
                      <td className="px-3 py-2 text-ink-2">{l.reason || <span className="text-ink-3">—</span>}</td>
                      <td className="px-3 py-2 tabular text-ink-2">{clock(l.claimed_at)}</td>
                      <td className={cn("px-3 py-2 tabular", left <= 0 ? "text-brick-ink" : left < 30_000 ? "text-saffron-ink" : "text-ink-2")}>{left <= 0 ? "expired" : duration(left)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={<LockOpen />} title="No live claims" hint="Nobody holds a path right now. A claim is a short lease with a reason; it is renewed by re-claiming and dropped on release." className="py-6" />
        )}

        <h3 className="label-caps flex items-center gap-1.5 pt-2">
          <ShieldAlert className="size-3.5" /> Claim violations ({view.violations.length})
        </h3>
        {view.violations.length ? (
          <ul className="space-y-1.5">
            {view.violations.map((v, i) => {
              const r = v.result as { owner?: string; reason?: string; via?: string; blocked?: boolean; rev?: number | null } | null;
              const viaBash = r?.via === "bash";
              return (
                <li key={`${v.ts}${i}`} className="rounded-md border border-brick/40 bg-brick-soft/60 px-3 py-2 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-x-2">
                    <span className="font-semibold text-brick-ink">{names(v.agent)}</span>
                    <span className="text-brick-ink/90">
                      {viaBash ? "wrote" : "tried"} <code>{String(v.args.tool ?? "write")}</code> on{" "}
                      <code>{String(v.args.path ?? "?")}</code>
                    </span>
                    <Badge variant={viaBash ? "saffron" : "brick"}>{viaBash ? "detected after the fact" : "blocked"}</Badge>
                    {r?.owner ? <Badge variant="brick">lock held by {names(r.owner)}</Badge> : <Badge variant="brick">no lock held</Badge>}
                    <span className="ml-auto tabular text-brick-ink/70">{clock(v.ts)}</span>
                  </div>
                  {r?.reason ? <div className="mt-0.5 font-mono text-[11px] text-brick-ink/80">{r.reason}</div> : null}
                  {viaBash ? (
                    <div className="mt-0.5 text-[11px] text-brick-ink/80">
                      A shell write cannot be blocked mid-command. The harness snapshotted it
                      {typeof r?.rev === "number" ? ` as rev ${r.rev}` : ""} and announced it on the board; the claim's
                      owner can put the file back with file_restore.
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : (
          <EmptyState icon={<ShieldCheck />} title="No violations" hint="Every edit/write so far went through a live claim. The Layer B guard logs claim_violation when one does not." className="py-6" />
        )}

        {reaps.length ? (
          <>
            <h3 className="label-caps pt-2">Reaped ({reaps.length})</h3>
            <ul className="space-y-1.5">
              {reaps.map((e, i) => {
                const r = e.result as Record<string, unknown>;
                return (
                  <li key={`${e.ts}${i}`} className="rounded-md border border-saffron/40 bg-saffron-soft/50 px-3 py-2 text-[12.5px]">
                    <span className="font-semibold text-saffron-ink">{names(e.agent)}</span> <span className="text-ink-2">marked dead by {e.tool === "reap" ? "reap.sh" : "the harness"}</span>
                    <span className="text-ink-3">
                      {typeof r.idle_seconds === "number" ? ` · idle ${r.idle_seconds}s` : ""} · {String(r.locks_released ?? (Array.isArray(r.released) ? r.released.length : 0))} lock(s) released
                    </span>
                    <span className="float-right tabular text-ink-3">{clock(e.ts)}</span>
                  </li>
                );
              })}
            </ul>
          </>
        ) : null}
      </section>

      <section className="space-y-2">
        <h3 className="label-caps">Claim → work → release</h3>
        {seqs.length ? (
          <ol className="space-y-2">
            {seqs.map((s, i) => (
              <li key={i} className={cn("card p-3", s.open && "border-slate/40")}>
                <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                  <span className="font-semibold text-ink">{names(s.agent)}</span>
                  <code className="text-ink-2">{s.path}</code>
                  <Badge variant={s.open ? "slate" : "moss"} className="ml-auto">
                    {s.open ? "still held" : "released"}
                  </Badge>
                </div>
                <ol className="mt-2 flex flex-wrap items-center gap-1">
                  {s.steps.map((st, j) => (
                    <li key={j} className="flex items-center gap-1">
                      <Badge variant={st.tool === "claim_file" ? "slate" : st.tool === "release_file" ? "moss" : "neutral"} className="font-mono" title={st.ts}>
                        {st.tool}
                      </Badge>
                      {j < s.steps.length - 1 ? <span className="text-ink-3">→</span> : null}
                    </li>
                  ))}
                  {s.open ? <span className="text-[11px] text-ink-3">→ …</span> : null}
                </ol>
                <div className="mt-1 text-[11px] tabular text-ink-3">
                  {clock(s.steps[0].ts)} – {clock(s.steps[s.steps.length - 1].ts)}
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState title="No claim sequences yet" hint="Once an agent claims a path you will see its claim → write → release run here." className="py-6" />
        )}
      </section>
    </div>
  );
}
