/**
 * The lead register (extensions/leads.ts): the swarm's open investigative
 * work, who holds each piece, what it waits for and how it ended. What waits
 * on the operator comes first and is shown loudest, with the form that
 * answers it: a note (recorded on the lead, posted to the board, the lead
 * reopened) and, in a microVM run, a host the run's jobs may reach from now
 * on. The answer is run as `swarm.sh lead`, so it lands on the trace and the
 * operator's record like the CLI's. "Add directive" opens an unheld lead under
 * a question (or under a question asked in the same act), with the product it
 * is to make and what makes that product acceptable: a directive says what to
 * look at, never who does it (a held one would be an assignment). Every lead
 * is listed whole; nothing is cut.
 */
import { useCallback, useState, type ReactNode } from "react";
import { AlertTriangle, CircleDot, Compass, Hourglass, ListChecks, PlayCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Chip } from "@/components/console";
import { JobCard } from "@/components/jobs-drawer";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useLive, useResource } from "@/lib/live";
import type { LeadView, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS_TONE: Record<LeadView["status"], "kelp" | "saffron" | "slate" | "moss"> = { active: "kelp", blocked: "saffron", open: "slate", closed: "moss" };

function LeadCard({ lead, names }: { lead: LeadView; names: (id: string) => string }) {
  return (
    <li className="card space-y-1.5 px-3 py-2.5 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <code className="font-mono text-[12px] font-semibold text-ink">{lead.id}</code>
        <span className="font-medium text-ink">{lead.title}</span>
        <Chip tone={STATUS_TONE[lead.status]}>{lead.status}</Chip>
        {!lead.material ? <Chip tone="slate">not material</Chip> : null}
        {lead.priority ? <Chip tone="slate">{lead.priority} waiting on it</Chip> : null}
        {lead.stale ? <Chip tone="brick">holder stale since {clock(lead.stale.at)}</Chip> : null}
      </div>
      <p className="m-0 text-ink-2">{lead.why}</p>
      <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-ink-2">
        <dt className="text-ink-3">Origin</dt>
        <dd className="m-0">
          {lead.origin}; opened by {names(lead.opened_by)} at {clock(lead.opened_at)}
        </dd>
        {lead.holder ? (
          <>
            <dt className="text-ink-3">Holder</dt>
            <dd className="m-0">
              {names(lead.holder)} (generation {lead.generation}){lead.held_since ? `, since ${clock(lead.held_since)}` : ""}
            </dd>
          </>
        ) : null}
        {lead.needs.length ? (
          <>
            <dt className="text-ink-3">Needs</dt>
            <dd className="m-0">
              {lead.needs.map((n) => (
                <span key={n.need} className={cn("mr-2", n.met ? "text-moss-ink" : "text-saffron-ink")}>
                  {n.need} {n.met ? "(met)" : `(unmet: ${n.why ?? "not yet"})`}
                </span>
              ))}
            </dd>
          </>
        ) : null}
        {lead.answers.length ? (
          <>
            <dt className="text-ink-3">Questions</dt>
            <dd className="m-0">{lead.answers.map((a) => `question:${a}`).join(", ")}</dd>
          </>
        ) : null}
        {lead.proposition ? (
          <>
            <dt className="text-ink-3">Tests</dt>
            <dd className="m-0">
              {lead.proposition}; <span className="text-ink-3">against:</span> {lead.negation}
            </dd>
          </>
        ) : null}
        {lead.product ? (
          <>
            <dt className="text-ink-3">Product</dt>
            <dd className="m-0">
              {lead.product}; <span className="text-ink-3">accepted when:</span> {lead.acceptance}
            </dd>
          </>
        ) : null}
        {lead.jobs.length ? (
          <>
            <dt className="text-ink-3">Jobs</dt>
            <dd className="m-0 font-mono text-[11.5px]">{lead.jobs.join(", ")}</dd>
          </>
        ) : null}
        {lead.disposition ? (
          <>
            <dt className="text-ink-3">Closed</dt>
            <dd className="m-0">
              {lead.disposition} by {names(lead.closed_by ?? "")} at {clock(lead.closed_at ?? "")}: <span className="text-ink">{lead.ref}</span>
              {lead.close_why ? ` (${lead.close_why})` : ""}
            </dd>
          </>
        ) : null}
        {lead.reopened.map((r) => (
          <FragmentRow key={`r${r.at}`} label="Reopened" text={`${clock(r.at)} by ${r.by} (${r.cause}): ${r.why}`} />
        ))}
        {lead.notes.map((n) => (
          <FragmentRow key={`n${n.at}`} label="Operator" text={`${clock(n.at)}: ${n.text}${n.allow_host ? ` (allowed ${n.allow_host})` : ""}`} />
        ))}
      </dl>
    </li>
  );
}

function FragmentRow({ label, text }: { label: string; text: string }) {
  return (
    <>
      <dt className="text-ink-3">{label}</dt>
      <dd className="m-0">{text}</dd>
    </>
  );
}

/** One request waiting on the operator, with the form that answers it. */
function OperatorRequest({ lead, runId, vmRun, onJob }: { lead: LeadView; runId: string; vmRun: boolean; onJob: (id: string) => void }) {
  const [text, setText] = useState("");
  const [host, setHost] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function answer(action: "note" | "reopen") {
    setError(null);
    setBusy(true);
    try {
      const job = await api.leadAct(runId, { action, lead: lead.id, ...(text.trim() ? { text: text.trim() } : {}), ...(host.trim() ? { allow_host: host.trim() } : {}) });
      onJob(job.id);
      setText("");
      setHost("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <li className="rounded-md border-2 border-brick bg-brick-soft/40 px-3 py-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <AlertTriangle className="size-4 text-brick-ink" aria-hidden="true" />
        <code className="font-mono font-semibold text-ink">{lead.id}</code>
        <span className="font-medium text-ink">{lead.title}</span>
        <span className="text-ink-3">asked by {lead.closed_by} at {clock(lead.closed_at ?? "")}</span>
      </div>
      <p className="m-0 mt-1 text-ink">{lead.ref}</p>
      <div className="mt-2 grid gap-2">
        <Label htmlFor={`note-${lead.id}`} className="text-[12px] text-ink-2">
          Your answer (recorded on {lead.id}, posted to the board as the examiner, and the lead reopened)
        </Label>
        <Input id={`note-${lead.id}`} value={text} onChange={(e) => setText(e.target.value)} placeholder="what you did, or the answer" className="h-8" />
        {vmRun ? (
          <div className="flex flex-wrap items-center gap-2">
            <Label htmlFor={`host-${lead.id}`} className="text-[12px] text-ink-2">
              Allow a host for the run's jobs (optional)
            </Label>
            <Input id={`host-${lead.id}`} value={host} onChange={(e) => setHost(e.target.value)} placeholder="example.org" className="h-8 max-w-[260px]" />
          </div>
        ) : (
          <p className="m-0 text-[12px] text-ink-3">A host run reads its allowlist once, at start: a host cannot be allowed while it runs.</p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={busy || !text.trim()} onClick={() => void answer("note")}>
            Answer and reopen
          </Button>
        </div>
        {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      </div>
    </li>
  );
}

/** "Add directive": an unheld lead under a question, with its product and acceptance, run as swarm.sh lead direct. */
function DirectiveForm({ runId, onJob }: { runId: string; onJob: (id: string) => void }) {
  const loader = useCallback(() => api.questions(runId), [runId]);
  const questions = useResource(loader, 0, [runId]);
  const [q, setQ] = useState("");
  const [newQuestion, setNewQuestion] = useState("");
  const [newWhy, setNewWhy] = useState("");
  const [title, setTitle] = useState("");
  const [why, setWhy] = useState("");
  const [product, setProduct] = useState("");
  const [acceptance, setAcceptance] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const options = [
    { value: "", label: "A new question", hint: "asked in the same act, as yourself" },
    ...(questions.data?.questions ?? []).filter((x) => x.scope === "in_scope" && !x.withdrawn).map((x) => ({ value: x.id, label: x.id, hint: x.text })),
  ];
  let as = "";
  try {
    as = sessionStorage.getItem("dfirswarm.questions.as") ?? "";
  } catch {
    as = "";
  }
  async function submit() {
    setError(null);
    setBusy(true);
    try {
      const job = await api.leadDirect(runId, { ...(q ? { q } : { new_question: newQuestion, new_why: newWhy }), title, why, product, acceptance, ...(as ? { as } : {}) });
      onJob(job.id);
      setTitle("");
      setWhy("");
      setProduct("");
      setAcceptance("");
      setNewQuestion("");
      setNewWhy("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const ready = title.trim() && why.trim() && product.trim() && acceptance.trim() && (q || (newQuestion.trim() && newWhy.trim()));
  return (
    <details className="card px-3 py-2.5 text-[12.5px]">
      <summary className="label-caps flex cursor-pointer items-center gap-1.5">
        <Compass className="size-3.5" /> Add directive
      </summary>
      <div className="mt-2 grid gap-2">
        <p className="m-0 text-[12px] text-ink-3">A directive says what to look at and what to produce; nobody is assigned it. It opens unheld under a question, and the seat idle longest is woken for it.</p>
        <Select value={q} onChange={setQ} options={options} aria-label="Under the question" />
        {!q ? (
          <>
            <Textarea value={newQuestion} onChange={(e) => setNewQuestion(e.target.value)} placeholder="the question it serves, whole" />
            <Input value={newWhy} onChange={(e) => setNewWhy(e.target.value)} placeholder="why the case needs that question" />
          </>
        ) : null}
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="what to look at (the lead's title)" />
        <Input value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why" />
        <Input value={product} onChange={(e) => setProduct(e.target.value)} placeholder="the product: what it is to produce" />
        <Input value={acceptance} onChange={(e) => setAcceptance(e.target.value)} placeholder="acceptance: what makes the product acceptable" />
        <div>
          <Button size="sm" disabled={busy || !ready} onClick={() => void submit()}>
            Open the directive
          </Button>
        </div>
        {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      </div>
    </details>
  );
}

export function LeadsPanel({ view, version }: { view: SwarmView; version: number }) {
  const id = view.summary.id;
  const live = useLive();
  const names = useAgentNames(view.agents);
  const loader = useCallback(() => api.leads(id), [id]);
  const res = useResource(loader, version, [id]);
  const [jobId, setJobId] = useState<string | null>(null);
  const job = jobId ? (live.jobs[jobId] ?? null) : null;
  const vmRun = (view.vms ?? []).length > 0 || (view.registry?.isolation as { mode?: string } | undefined)?.mode === "microvm";
  if (res.error && !res.data) return <ErrorState error={res.error} onRetry={res.reload} title="Could not read the lead register" />;
  if (!res.data) return <LoadingState label="Reading the lead register" rows={4} />;
  const d = res.data;
  const groups: Array<[string, LeadView[], ReactNode]> = [
    ["Active", d.leads.filter((l) => l.status === "active"), <PlayCircle key="a" className="size-3.5" />],
    ["Blocked", d.leads.filter((l) => l.status === "blocked"), <Hourglass key="b" className="size-3.5" />],
    ["Open, held by nobody", d.leads.filter((l) => l.status === "open"), <CircleDot key="o" className="size-3.5" />],
    ["Closed", d.leads.filter((l) => l.status === "closed" && l.disposition !== "needs_operator"), <ListChecks key="c" className="size-3.5" />],
  ];
  return (
    <div className="space-y-5">
      <p className="m-0 text-[12.5px] text-ink-2">
        {d.leads.length} lead{d.leads.length === 1 ? "" : "s"} in <code>leads/leads.md</code>; chain{" "}
        {d.chain.ok ? `intact, ${d.chain.events} events` : <span className="text-brick-ink">BROKEN at line {d.chain.broken_at} ({d.chain.reason})</span>}. Priority is how many leads and unanswered questions wait on a lead, then its age. The harness assigns none of them.
      </p>
      {view.until_solved ? (
        <InlineNote tone="warn">This run is until solved: it ends when every question is answered, or when you stop it. What waits on you below is what it cannot do alone.</InlineNote>
      ) : null}

      <section className="space-y-2" aria-label="Waiting on the operator">
        <h3 className="label-caps flex items-center gap-1.5 text-brick-ink">
          <AlertTriangle className="size-3.5" /> Waiting on you ({d.waiting_on_operator.length})
        </h3>
        {d.waiting_on_operator.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {d.waiting_on_operator.map((l) => (
              <OperatorRequest key={l.id} lead={l} runId={id} vmRun={vmRun} onJob={setJobId} />
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-3">Nothing: no lead is closed needs_operator. The CLI is <code>swarm.sh lead {id} list</code>.</p>
        )}
        {job ? <JobCard job={job} /> : null}
        {d.hosts.length ? <p className="m-0 text-[12px] text-ink-2">Hosts allowed for the run's jobs while it ran: {d.hosts.join(", ")}.</p> : null}
      </section>

      <DirectiveForm runId={id} onJob={setJobId} />

      {d.coverage.questions.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Questions</h3>
          <p className="m-0 text-[12.5px] text-ink-2">
            {d.coverage.questions.length} in the goal; without a standing answer: {d.coverage.unanswered.length ? d.coverage.unanswered.map((q) => `question:${q}`).join(", ") : "none"}. Held by no lead:{" "}
            {d.coverage.uncovered.length ? (
              <span className="text-saffron-ink">{d.coverage.uncovered.map((q) => `question:${q}${d.coverage.open_leads_for[q] ? ` (open: ${d.coverage.open_leads_for[q].join(", ")})` : ""}`).join(", ")}</span>
            ) : (
              "none"
            )}
            .
          </p>
        </section>
      ) : null}

      {d.awaiting.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Jobs awaiting an interpretation ({d.awaiting.length})</h3>
          <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-ink-2">
            {d.awaiting.map((a) => (
              <li key={a.job}>
                <code className="font-mono">{a.job}</code> of {names(a.agent)}
                {a.lead ? ` (under ${a.lead}: holds the finish line)` : ""}: {a.why}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {d.leads.length ? (
        groups.map(([label, list, icon]) =>
          list.length ? (
            <section key={label} className="space-y-2">
              <h3 className="label-caps flex items-center gap-1.5">
                {icon} {label} ({list.length})
              </h3>
              <ul className="m-0 list-none space-y-2 p-0">
                {list.map((l) => (
                  <LeadCard key={l.id} lead={l} names={names} />
                ))}
              </ul>
            </section>
          ) : null,
        )
      ) : (
        <EmptyState title="No lead yet" hint="An agent opens a lead for work it found that has to be followed (lead_open, or record with opens); the register shows who holds each and how it ended." />
      )}
    </div>
  );
}
