/**
 * The operator requests (extensions/requests.ts, docs/adr/0014): everything
 * the run asked of a person, each with its durable id (R-n), its kind, and
 * where it stands in its lifecycle (pending, notified, acknowledged, then
 * answered, declined or withdrawn); an acquisition also shows its stage
 * (requested, authorised, collecting, received, validated, unavailable, or
 * declined) and what it asks for: the source, where it is, what it would
 * establish, how urgent, who holds it and what authority collecting it
 * needs. What waits on the operator comes first, each with the act that
 * answers it; the acts run as `swarm.sh requests`, so they land on the
 * trace and the operator's record like the CLI's. The acting person this
 * console session chose for the Questions tab goes with them as `--as`, a
 * claim. Nothing is cut: every request is shown whole.
 */
import { useCallback, useState } from "react";
import { AlertTriangle, Inbox, PackagePlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Chip, type Tone } from "@/components/console";
import { JobCard } from "@/components/jobs-drawer";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { useLive, useResource } from "@/lib/live";
import type { OperatorRequest, SwarmView } from "@/lib/types";

const STATE_TONE: Record<OperatorRequest["state"], Tone> = { pending: "brick", notified: "saffron", acknowledged: "kelp", answered: "moss", declined: "slate", withdrawn: "slate" };
const KIND_LABEL: Record<OperatorRequest["kind"], string> = { lead: "a lead needs you", acquisition: "acquisition", clarification: "clarification", decision: "decision", network: "network item" };

function actingPerson(): string {
  try {
    return sessionStorage.getItem("dfirswarm.questions.as") ?? "";
  } catch {
    return "";
  }
}

type Action = Parameters<typeof api.requestAct>[1]["action"];

function RequestCard({ r, runId, onJob }: { r: OperatorRequest; runId: string; onJob: (id: string) => void }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const open = !r.closed;
  const act = async (action: Action) => {
    setError(null);
    setBusy(true);
    try {
      const as = actingPerson();
      const payload = { action, request: r.rid, ...(action === "answer" ? { text: text.trim() } : text.trim() ? { why: text.trim() } : {}), ...(as ? { as } : {}) };
      const job = await api.requestAct(runId, payload);
      onJob(job.id);
      setText("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const l = r.line;
  const answerable = r.kind === "decision" || r.kind === "lead" || r.kind === "clarification";
  const stage = r.stage ?? "requested";
  return (
    <li className={`rounded-md border px-3 py-2.5 text-[13px] ${open ? "border-2 border-brick bg-brick-soft/40" : "border-line bg-card"}`}>
      <div className="flex flex-wrap items-center gap-2">
        {open ? <AlertTriangle className="size-4 text-brick-ink" aria-hidden="true" /> : null}
        <code className="font-mono font-semibold text-ink">{r.rid}</code>
        <Chip tone="neutral">{KIND_LABEL[r.kind]}</Chip>
        <Chip tone={STATE_TONE[r.state]}>{r.state}</Chip>
        {r.stage ? <Chip tone={r.stage === "validated" ? "moss" : r.stage === "declined" || r.stage === "unavailable" ? "slate" : "saffron"}>stage {r.stage}</Chip> : null}
        {r.ask && r.ask.urgency !== "normal" ? <Chip tone="brick">{r.ask.urgency}</Chip> : null}
        {r.lead ? <Chip tone="slate">{r.lead}</Chip> : null}
        {r.questions.map((q) => (
          <Chip key={q} tone="band">
            {q}
          </Chip>
        ))}
        <span className="text-ink-3">
          from {r.by} at {clock(r.at)}
        </span>
      </div>
      {l.title ? <p className="m-0 mt-1 font-medium text-ink">{String(l.title)}</p> : null}
      {l.request ? <p className="m-0 mt-0.5 whitespace-pre-wrap text-ink-2">{String(l.request)}</p> : null}
      {r.ask ? (
        <dl className="m-0 mt-1 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-[12.5px]">
          <dt className="text-ink-3">Source</dt>
          <dd className="m-0 text-ink">{r.ask.source}</dd>
          <dt className="text-ink-3">Where</dt>
          <dd className="m-0 text-ink">{r.ask.where}</dd>
          <dt className="text-ink-3">Would establish</dt>
          <dd className="m-0 text-ink">{r.ask.expected_value}</dd>
          {r.ask.owner ? (
            <>
              <dt className="text-ink-3">Held by</dt>
              <dd className="m-0 text-ink">{r.ask.owner}</dd>
            </>
          ) : null}
          {r.ask.authority_needed ? (
            <>
              <dt className="text-ink-3">Authority needed</dt>
              <dd className="m-0 text-ink">{r.ask.authority_needed}</dd>
            </>
          ) : null}
        </dl>
      ) : null}
      {r.closed ? (
        <p className="m-0 mt-1 text-ink-2">
          {r.closed.ev} by {r.closed.by} at {clock(r.closed.at)}: {r.closed.text}
        </p>
      ) : l.answer ? (
        <p className="m-0 mt-1 break-all font-mono text-[11.5px] text-ink-3">{String(l.answer)}</p>
      ) : null}
      {r.history.length > 1 ? (
        <ul className="m-0 mt-1 list-none space-y-0.5 p-0 text-[12px] text-ink-3">
          {r.history.slice(1).map((h) => (
            <li key={h.seq}>
              {clock(h.at)} {h.ev}
              {h.stage ? ` ${h.stage}` : ""} by {h.by}
              {h.targets ? ` (${h.targets.join(", ") || "no target"})` : ""}
              {h.text ? `: ${h.text}` : h.why ? `: ${h.why}` : ""}
            </li>
          ))}
        </ul>
      ) : null}
      {open ? (
        <div className="mt-2 grid gap-2">
          <Input aria-label={`Answer or reason for ${r.rid}`} value={text} onChange={(e) => setText(e.target.value)} placeholder={answerable ? "your answer, or your reason" : "your reason"} className="h-8" />
          <div className="flex flex-wrap gap-2">
            {!r.acknowledged ? (
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => void act("ack")}>
                Acknowledge
              </Button>
            ) : null}
            {answerable ? (
              <Button size="sm" disabled={busy || !text.trim()} onClick={() => void act("answer")}>
                Answer
              </Button>
            ) : null}
            {r.kind === "acquisition" && stage === "requested" ? (
              <Button size="sm" disabled={busy} onClick={() => void act("authorise")}>
                Authorise
              </Button>
            ) : null}
            {r.kind === "acquisition" && (stage === "requested" || stage === "authorised") ? (
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => void act("collecting")}>
                Collecting
              </Button>
            ) : null}
            {r.kind === "acquisition" ? (
              <Button size="sm" variant="secondary" disabled={busy || !text.trim()} onClick={() => void act("unavailable")}>
                Unavailable
              </Button>
            ) : null}
            {r.kind !== "network" ? (
              <Button size="sm" variant="secondary" disabled={busy || !text.trim()} onClick={() => void act("decline")}>
                Decline
              </Button>
            ) : null}
            <Button size="sm" variant="ghost" disabled={busy || !text.trim()} onClick={() => void act("withdraw")}>
              Withdraw
            </Button>
          </div>
          {r.kind === "acquisition" ? (
            <p className="m-0 text-[12px] text-ink-3">
              Supply it from a shell: <code>swarm.sh evidence {runId} add PATH --for {r.rid} --why TEXT</code>. It is sealed in the store as an inventory revision and read through jobs; the leads, answers and acceptances of its questions are reopened. A decline is an evidence gap, never a finding that something is absent.
            </p>
          ) : r.kind === "network" ? (
            <p className="m-0 text-[12px] text-ink-3">A network item is granted or declined on the Network tab.</p>
          ) : null}
          {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
        </div>
      ) : null}
    </li>
  );
}

export function RequestsPanel({ view, version }: { view: SwarmView; version: number }) {
  const id = view.summary.id;
  const live = useLive();
  const loader = useCallback(() => api.requests(id), [id]);
  const res = useResource(loader, version, [id]);
  const [jobId, setJobId] = useState<string | null>(null);
  const job = jobId ? (live.jobs[jobId] ?? null) : null;
  if (res.error && !res.data) return <ErrorState error={res.error} onRetry={res.reload} title="Could not read the operator requests" />;
  if (!res.data) return <LoadingState label="Reading the operator requests" rows={4} />;
  const d = res.data;
  const open = d.requests.filter((r) => !r.closed);
  const closed = d.requests.filter((r) => r.closed);
  return (
    <div className="space-y-5">
      <section className="space-y-1">
        <p className="m-0 text-[12.5px] text-ink-2">
          {d.brief.total} request{d.brief.total === 1 ? "" : "s"}, {d.brief.open} open. Each is committed first and then delivered: pending until your notification targets are handed its id (ids only, never what it asks), acknowledged when you say so, then answered, declined or withdrawn. More evidence under this case policy: <strong>{d.more_evidence}</strong>
          {d.more_evidence === "no" ? ' (an acquisition is answered at once: "no additional input under this case policy")' : d.more_evidence === "yes" ? " (an acquisition is authorised by the policy; you collect it)" : " (you authorise or decline each acquisition)"}. Chain {d.chain.ok ? "intact" : <span className="text-brick-ink">BROKEN at line {d.chain.broken_at} ({d.chain.reason})</span>}. The CLI is <code>swarm.sh requests {id} list</code>.
        </p>
      </section>
      <section className="space-y-2" aria-label="Waiting on the operator">
        <h3 className="label-caps flex items-center gap-1.5 text-brick-ink">
          <AlertTriangle className="size-3.5" /> Waiting on you ({open.length})
        </h3>
        {open.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {open.map((r) => (
              <RequestCard key={r.rid} r={r} runId={id} onJob={setJobId} />
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-3">Nothing waits on you.</p>
        )}
        {job ? <JobCard job={job} /> : null}
      </section>
      {d.material.length ? (
        <section className="space-y-1">
          <h3 className="label-caps flex items-center gap-1.5">
            <PackagePlus className="size-3.5" /> Evidence and material added ({d.material.length})
          </h3>
          <ul className="m-0 list-none space-y-1 p-0 text-[12.5px] text-ink-2">
            {d.material.map((m) => (
              <li key={String(m.import)}>
                <code className="font-mono text-[12px] text-ink">import:{String(m.import)}</code> {String(m.class ?? "").replace(/_/g, " ")}
                {m.inventory_rev ? `, inventory revision ${String(m.inventory_rev)}` : ""}
                {m.request ? ` for ${String(m.request)}` : ""} by {String(m.supplied_by ?? "")} at {clock(String(m.at ?? ""))}: {String(m.why ?? "")}
                <ul className="m-0 list-none p-0 pl-4">
                  {((m.files as Array<{ path: string; bytes: number; sha256: string }> | undefined) ?? []).map((f) => (
                    <li key={f.path} className="break-all font-mono text-[11.5px]">
                      {f.path} ({f.bytes} bytes) sha256 {f.sha256}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <section className="space-y-2">
        <h3 className="label-caps flex items-center gap-1.5">
          <Inbox className="size-3.5" /> Closed ({closed.length})
        </h3>
        {closed.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {closed.map((r) => (
              <RequestCard key={r.rid} r={r} runId={id} onJob={setJobId} />
            ))}
          </ul>
        ) : !open.length ? (
          <EmptyState title="Nothing was asked of you" hint="An agent asks by closing a lead needs_operator (with ask.kind acquisition for evidence the run does not have) or with question_ask; the hub asks you to decide on a stop when nothing yields." />
        ) : (
          <p className="m-0 text-[12.5px] text-ink-3">None closed yet.</p>
        )}
      </section>
    </div>
  );
}
