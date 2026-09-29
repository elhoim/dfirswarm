/**
 * The question register (extensions/questions.ts): what the examination is
 * asked, by the goal, by an agent or by a person, and how each question
 * stands. What waits on the operator comes first (the triage queue, each
 * proposed question on a full card so a clarification on it is answered
 * before it is admitted, and the clarifications agents asked), then the add
 * form, then every question with
 * its origin badge, its author (claimed or signed, enrolled or not), scope,
 * work state, answer, leads, revisions and clarification thread. Every act is
 * run as `swarm.sh question`, so it is checked, written to the chain, and
 * only then acknowledged; the acting person this console session chose goes
 * with it as `--as`, a claim (signing an act is the command line's). A
 * question's words are shown whole; nothing is cut.
 */
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, HelpCircle, ListChecks, MessageSquare, PenLine, PlusCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, type SelectOption } from "@/components/ui/select";
import { Chip, type Tone } from "@/components/console";
import { JobCard } from "@/components/jobs-drawer";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { useLive, useResource } from "@/lib/live";
import type { QuestionOrigin, QuestionView, QuestionsPanelView, SwarmView } from "@/lib/types";
import { acceptPayload, amendPayload, baseMoved, formBase, questionGroups, type FormBase } from "@/lib/question-forms";
import { cn } from "@/lib/utils";

const ORIGIN_TONE: Record<QuestionOrigin["kind"], Tone> = { goal: "slate", agent: "neutral", analyst: "kelp", reviewer: "saffron", observer: "band" };
const SCOPE_TONE: Record<QuestionView["scope"], Tone> = { in_scope: "moss", proposed: "saffron", excluded: "slate" };
const AS_KEY = "dfirswarm.questions.as";

function readAs(): string {
  try {
    return sessionStorage.getItem(AS_KEY) ?? "";
  } catch {
    return "";
  }
}

function writeAs(v: string): void {
  try {
    if (v) sessionStorage.setItem(AS_KEY, v);
    else sessionStorage.removeItem(AS_KEY);
  } catch {
    // Private windows: the choice lasts as long as the page.
  }
}

/** The origin as a badge: goal, agent, or a person's role, and whether the act is claimed or signed. */
function OriginBadge({ o }: { o: QuestionOrigin }) {
  const label = o.kind === "analyst" ? (o.role === "operator" ? "operator" : o.role ?? "analyst") : o.kind;
  return (
    <>
      <Chip tone={ORIGIN_TONE[o.kind]}>{label}</Chip>
      {o.kind !== "goal" && o.kind !== "agent" ? (
        <Chip tone={o.identity === "signed" ? "moss" : "slate"}>
          {o.identity === "signed" ? "signed" : "claimed"}
          {o.enrolled === false ? ", not enrolled" : ""}
        </Chip>
      ) : null}
    </>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-ink-3">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

type Act = (payload: Record<string, unknown> & { action: string }) => Promise<void>;

/**
 * The small forms a question card opens: amend, priority, withdraw, accept.
 * An amend or accept form keeps the revision it was opened on (its base)
 * until the operator refreshes it: another person's amendment arriving live
 * is named, never folded into what the form sends (question-forms.ts).
 */
function CardActions({ q, act, busy }: { q: QuestionView; act: Act; busy: boolean }) {
  const [open, setOpen] = useState<null | "amend" | "priority" | "withdraw" | "accept">(null);
  const [base, setBase] = useState<FormBase | null>(null);
  const [text, setText] = useState(q.text);
  const [why, setWhy] = useState("");
  const [neutral, setNeutral] = useState(q.neutral?.text ?? "");
  const [reason, setReason] = useState(q.priority_reason ?? "");
  const [acceptAs, setAcceptAs] = useState("bounded");
  if (q.withdrawn || q.after_done) return null;
  const load = () => {
    const b = formBase(q);
    setBase(b);
    setText(b.text);
    setNeutral(b.neutral);
  };
  const toggle = (k: "amend" | "priority" | "withdraw" | "accept") => {
    if (open === k) return setOpen(null);
    if (k === "amend" || k === "accept") load();
    setOpen(k);
  };
  const moved = baseMoved(base, q);
  const submit = async (payload: Record<string, unknown> & { action: string }) => {
    await act(payload);
    setOpen(null);
    setBase(null);
    setWhy("");
  };
  const movedNote =
    moved !== null && base ? (
      <InlineNote tone="danger">
        {q.id} is at revision {moved} now: this form was opened on revision {base.rev}, and sending it is refused as stale.{" "}
        <Button size="sm" variant="secondary" onClick={load}>
          Refresh to revision {moved}
        </Button>{" "}
        (your draft is replaced by revision {moved}'s words)
      </InlineNote>
    ) : null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {(["amend", "priority", "withdraw", ...(q.scope === "in_scope" ? (["accept"] as const) : [])] as const).map((k) => (
          <Button key={k} size="sm" variant={open === k ? "default" : "secondary"} onClick={() => toggle(k)}>
            {k === "amend" ? "Amend" : k === "priority" ? (q.priority === "urgent" ? "Priority" : "Mark urgent") : k === "withdraw" ? "Withdraw" : "Accept its limits"}
          </Button>
        ))}
      </div>
      {open === "amend" && base ? (
        <div className="grid gap-1.5">
          <Label className="text-[12px] text-ink-2">A new verbatim revision against revision {base.rev} (refused if someone amended it since)</Label>
          {movedNote}
          <Textarea value={text} onChange={(e) => setText(e.target.value)} />
          <Input value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why it is amended" />
          <Input value={neutral} onChange={(e) => setNeutral(e.target.value)} placeholder="a neutral formulation (optional, attributed to you)" />
          <Button size="sm" disabled={busy || (!text.trim() && !neutral.trim())} onClick={() => void submit(amendPayload(q.id, base, { text, why, neutral }))}>
            Record revision
          </Button>
        </div>
      ) : null}
      {open === "priority" ? (
        <div className="grid gap-1.5">
          <Label className="text-[12px] text-ink-2">Urgent orders the offers and tells the holders under the same objective; it cancels nothing.</Label>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="why it is urgent" />
          <div className="flex gap-2">
            <Button size="sm" disabled={busy || !reason.trim() || q.priority === "urgent"} onClick={() => void submit({ action: "priority", q: q.id, priority: "urgent", reason })}>
              Urgent
            </Button>
            <Button size="sm" variant="secondary" disabled={busy || q.priority === "normal"} onClick={() => void submit({ action: "priority", q: q.id, priority: "normal" })}>
              Normal
            </Button>
          </div>
        </div>
      ) : null}
      {open === "withdraw" ? (
        <div className="grid gap-1.5">
          <Label className="text-[12px] text-ink-2">Its leads close withdrawn; a lead holding a finding goes to your triage instead, and nothing found is erased.</Label>
          <Input value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why it is withdrawn" />
          <Button size="sm" variant="danger" disabled={busy || !why.trim()} onClick={() => void submit({ action: "withdraw", q: q.id, why })}>
            Withdraw {q.id}
          </Button>
        </div>
      ) : null}
      {open === "accept" && base ? (
        <div className="grid gap-1.5">
          <Label className="text-[12px] text-ink-2">Accepting a question's limits ends the run examination-limited; it is refused while a lead on it is open, and holds for revision {base.rev} only.</Label>
          {movedNote}
          <Select value={acceptAs} onChange={setAcceptAs} aria-label="Accept as" options={[{ value: "bounded", label: "Bounded", hint: "the examination as far as it went" }, { value: "not_determinable", label: "Not determinable", hint: "the evidence cannot settle it" }]} />
          <Input value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why" />
          <Button size="sm" disabled={busy || !why.trim()} onClick={() => void submit(acceptPayload(q.id, base, acceptAs, why))}>
            Accept
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function QuestionCard({ q, sigs, act, busy, children }: { q: QuestionView; sigs: QuestionsPanelView["signatures"]; act: Act; busy: boolean; children?: ReactNode }) {
  const [reply, setReply] = useState<Record<string, string>>({});
  const mySigs = sigs.filter((s) => s.q === q.id);
  return (
    <li className={cn("card space-y-1.5 px-3 py-2.5 text-[12.5px]", q.priority === "urgent" && !q.withdrawn ? "border-l-4 border-l-brick" : "")}>
      <div className="flex flex-wrap items-center gap-2">
        <code className="font-mono text-[12px] font-semibold text-ink">{q.id}</code>
        <span className="font-mono text-[11px] text-ink-3">question:{q.section} · rev {q.rev}</span>
        <OriginBadge o={q.origin} />
        <Chip tone={SCOPE_TONE[q.scope]}>{q.scope.replace("_", " ")}</Chip>
        {q.work ? <Chip tone={q.work === "clarification_needed" ? "saffron" : q.work === "working" ? "kelp" : "slate"}>{q.work.replace("_", " ")}</Chip> : null}
        {q.priority === "urgent" ? <Chip tone="brick">urgent</Chip> : null}
        {q.materiality === "background" ? <Chip tone="slate">background</Chip> : null}
        {q.review_query ? <Chip tone="saffron">reviewer's query</Chip> : null}
        {q.leading_forms.length ? <Chip tone="saffron">leading form: {q.leading_forms.join(", ")}</Chip> : null}
        {q.withdrawn ? <Chip tone="slate">withdrawn</Chip> : null}
        {q.after_done ? <Chip tone="slate">after done: a follow-up</Chip> : null}
      </div>
      <p className="m-0 whitespace-pre-wrap text-[13px] text-ink">{q.text}</p>
      <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-ink-2">
        <Row label="Asked by">
          {q.author}, {clock(q.opened_at)}
        </Row>
        <Row label="Why">{q.why}</Row>
        {q.neutral ? <Row label="Neutral">{q.neutral.text}</Row> : null}
        <Row label="Scope">{q.scope_why}</Row>
        {q.objective || q.objective_text ? <Row label="Objective">{q.objective ?? `would add: ${q.objective_text}`}</Row> : null}
        {q.parent ? <Row label="Follows">{q.parent}</Row> : null}
        {q.expects ? <Row label="Expects">{q.expects} (a hint, never a format)</Row> : null}
        {q.hints.length ? <Row label="Hints">{q.hints.map((h) => `${h.ref}${h.value ? ` (says: ${h.value})` : ""}`).join("; ")}</Row> : null}
        {q.attachments.length ? <Row label="Attached">{q.attachments.join(", ")}</Row> : null}
        {q.suggested_to ? <Row label="Suggested">{q.suggested_to}</Row> : null}
        {q.deadline ? <Row label="Wanted by">{clock(q.deadline)}</Row> : null}
        <Row label="Answer">
          {q.answer ? (
            <span className={q.answer.stale ? "text-brick-ink" : "text-moss-ink"}>
              E-{q.answer.seq}
              {q.answer.result ? ` (${q.answer.result.replace(/_/g, " ")})` : ""}
              {q.answer.inconclusive ? " (inconclusive)" : ""}
              {q.answer.stale ? `: answers revision ${q.answer.question_rev ?? 1} of ${q.rev}, stale` : q.rev > 1 ? ` (revision ${q.answer.question_rev ?? 1})` : ""}
            </span>
          ) : (
            "none yet"
          )}
        </Row>
        {q.leads.length ? <Row label="Leads">{q.leads.map((l) => `${l.id} ${l.status}${l.holder ? ` (${l.holder})` : ""}${l.disposition ? ` ${l.disposition}` : ""}`).join(", ")}</Row> : null}
        {q.offers.length ? <Row label="Offered">{q.offers.map((o) => `${o.to}${o.first ? " first" : ""} at ${clock(o.at)}${o.accepted ? " (accepted)" : o.declined ? ` (declined: ${o.declined.why})` : ""}`).join(", ")}</Row> : null}
        {q.accepted ? <Row label="Accepted">{`${q.accepted.as.replace("_", " ")} by ${q.accepted.origin.name ?? q.accepted.origin.person ?? "?"}${q.accepted.stands ? "" : " (no longer stands: amended since)"}: ${q.accepted.why}`}</Row> : null}
        {q.withdrawn ? <Row label="Withdrawn">{`${clock(q.withdrawn.at)} by ${q.withdrawn.origin.name ?? q.withdrawn.origin.person ?? "?"}: ${q.withdrawn.why}`}</Row> : null}
        {mySigs.map((s) => (
          <Row key={`${s.act_seq}-${s.sign_seq ?? "none"}`} label="Signature">
            <span className={s.state === "bad" || s.state === "wrong-principal" ? "text-brick-ink" : "text-moss-ink"}>
              event {s.act_seq} by {s.person} ({s.key_kind}): {s.state}
            </span>
          </Row>
        ))}
      </dl>
      {q.revisions.length > 1 ? (
        <details className="text-ink-2">
          <summary className="cursor-pointer text-[12px] text-ink-3">{q.revisions.length} revisions</summary>
          <ol className="m-0 mt-1 space-y-1 pl-5">
            {q.revisions.map((r) => (
              <li key={r.rev}>
                <span className="text-ink-3">
                  rev {r.rev}, {clock(r.at)}, {r.origin.name ?? r.origin.person ?? r.origin.agent ?? r.origin.kind}
                  {r.why ? ` (why: ${r.why})` : ""}:
                </span>{" "}
                <span className="whitespace-pre-wrap">{r.text}</span>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
      {q.clarifications.length ? (
        <div className="space-y-1.5 rounded-md bg-card-2 px-2 py-1.5">
          {q.clarifications.map((c) => (
            <div key={c.id} className="space-y-1">
              <p className="m-0">
                <MessageSquare className="mr-1 inline size-3.5 text-ink-3" aria-hidden="true" />
                <code className="font-mono">{c.id}</code> from {c.by} to {c.to} at {clock(c.at)}: {c.what}
              </p>
              {c.answer ? (
                <p className="m-0 pl-5 text-moss-ink">
                  answered {clock(c.answer.at)}: {c.answer.text}
                </p>
              ) : (
                <div className="flex flex-wrap items-center gap-2 pl-5">
                  <Input className="h-8 max-w-[520px]" value={reply[c.id] ?? ""} onChange={(e) => setReply({ ...reply, [c.id]: e.target.value })} placeholder="what you meant" />
                  <Button size="sm" disabled={busy || !(reply[c.id] ?? "").trim()} onClick={() => void act({ action: "clarify_reply", q: q.id, clarify: c.id, answer: reply[c.id] })}>
                    Reply
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : null}
      {children}
      <CardActions q={q} act={act} busy={busy} />
    </li>
  );
}

/** The add form: a person's question, with everything the register records beside its words. */
function AddForm({ data, view, act, busy }: { data: QuestionsPanelView; view: SwarmView; act: Act; busy: boolean }) {
  const [text, setText] = useState("");
  const [why, setWhy] = useState("");
  const [objective, setObjective] = useState("");
  const [objectiveText, setObjectiveText] = useState("");
  const [parent, setParent] = useState("");
  const [materiality, setMateriality] = useState("material");
  const [priority, setPriority] = useState("normal");
  const [reason, setReason] = useState("");
  const [expects, setExpects] = useState("");
  const [hints, setHints] = useState<Array<{ ref: string; value: string }>>([]);
  const [hintPick, setHintPick] = useState("");
  const [attachments, setAttachments] = useState("");
  const [suggested, setSuggested] = useState("");
  const [deadline, setDeadline] = useState("");
  const objectives: SelectOption[] = [
    { value: "", label: "No objective", hint: "an examiner's or the operator's question is in scope anyway; an analyst's is proposed" },
    ...data.objectives.map((o) => ({ value: o.id, label: o.id, hint: o.text })),
    { value: "new", label: "A new objective", hint: "expands the case (the examiner's or the operator's; an analyst's is proposed)" },
  ];
  const parents: SelectOption[] = [{ value: "", label: "None" }, ...data.questions.filter((q) => q.scope === "in_scope" && !q.withdrawn).map((q) => ({ value: q.id, label: q.id, hint: q.text }))];
  const inventory: SelectOption[] = (view.inputs?.files ?? []).map((f) => ({ value: `input:${f.path.replace(/^inputs\//, "")}`, label: f.path }));
  const left = data.budget ? (data.budget.until_solved ? "until solved: caps advisory" : `$${Math.max(0, data.budget.cap_usd - data.budget.spent_usd).toFixed(2)} of $${data.budget.cap_usd.toFixed(2)} left${data.budget.cap_tokens ? `, ${Math.max(0, data.budget.cap_tokens - data.budget.tokens).toLocaleString()} tokens` : ""}`) : "unknown";
  const submit = async () => {
    await act({
      action: "add",
      text,
      why,
      submission: `console-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      ...(objective ? { objective } : {}),
      ...(objective === "new" ? { objective_text: objectiveText } : {}),
      ...(parent ? { parent } : {}),
      materiality,
      priority,
      ...(priority === "urgent" ? { reason } : {}),
      ...(expects ? { expects } : {}),
      ...(hints.length ? { hints: hints.map((h) => ({ ref: h.ref, ...(h.value.trim() ? { value: h.value } : {}) })) } : {}),
      ...(attachments.trim() ? { attachments: attachments.split(/[\s,]+/).filter(Boolean) } : {}),
      ...(suggested ? { suggested_to: suggested } : {}),
      ...(deadline ? { deadline: new Date(deadline).toISOString() } : {}),
    });
    setText("");
    setWhy("");
    setHints([]);
    setReason("");
  };
  return (
    <section className="card space-y-2 px-3 py-3" aria-label="Ask the swarm a question">
      <h3 className="label-caps m-0 flex items-center gap-1.5">
        <PlusCircle className="size-3.5" /> Ask a question
      </h3>
      <p className="m-0 text-[12px] text-ink-3">
        It is recorded on the chain first, then posted from you, offered to the suggested seat for its first minute or to the most suited idle seat, and ranked first in every agent's header. The agents test it as a proposition, never as a conclusion. Budget: {left}.
      </p>
      <Textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="the question, whole (it is kept verbatim)" aria-label="Question" />
      <Input value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why the case needs it" aria-label="Why" />
      <div className="grid gap-2 sm:grid-cols-2">
        <Select value={objective} onChange={setObjective} options={objectives} aria-label="Objective" />
        <Select value={parent} onChange={setParent} options={parents} aria-label="Follows" placeholder="Follows" />
        {objective === "new" ? <Input className="sm:col-span-2" value={objectiveText} onChange={(e) => setObjectiveText(e.target.value)} placeholder="the new objective" /> : null}
        <Select value={materiality} onChange={setMateriality} aria-label="Materiality" options={[{ value: "material", label: "Material", hint: "the finish line waits for its answer" }, { value: "background", label: "Background", hint: "worth knowing; nothing waits for it" }]} />
        <Select value={priority} onChange={setPriority} aria-label="Priority" options={[{ value: "normal", label: "Normal" }, { value: "urgent", label: "Urgent", hint: "needs a reason; orders the offers, cancels nothing" }]} />
        {priority === "urgent" ? <Input className="sm:col-span-2" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="why it is urgent" /> : null}
        <Select value={expects} onChange={setExpects} aria-label="Expects" options={[{ value: "", label: "Expects: say nothing" }, ...["existence", "value", "narrative", "timeline", "list"].map((e) => ({ value: e, label: `Expects ${e}`, hint: "a hint, never a format demand" }))]} />
        <Select value={suggested} onChange={setSuggested} aria-label="Suggested seat" options={[{ value: "", label: "No seat suggested", hint: "the most suited idle seat is offered it" }, ...data.seats.map((s) => ({ value: s, label: s, hint: "offered it first, for a minute" }))]} />
        <Input type="datetime-local" value={deadline} onChange={(e) => setDeadline(e.target.value)} aria-label="Wanted by" />
        <Input value={attachments} onChange={(e) => setAttachments(e.target.value)} placeholder="attachments: refs or paths in the run" aria-label="Attachments" />
      </div>
      <div className="space-y-1.5">
        <Label className="text-[12px] text-ink-2">Hints: where to look, never what to find. A hint that says something is recorded as a hypothesis to test.</Label>
        <div className="flex flex-wrap items-center gap-2">
          {inventory.length ? <Select className="max-w-[360px]" value={hintPick} onChange={setHintPick} options={inventory} mono searchable aria-label="From the inventory" placeholder="from the inventory" /> : null}
          <Input className="h-8 max-w-[360px]" value={hintPick} onChange={(e) => setHintPick(e.target.value)} placeholder="or a ref or path (input:…, job:…/…)" />
          <Button size="sm" variant="secondary" disabled={!hintPick.trim()} onClick={() => { setHints([...hints, { ref: hintPick.trim(), value: "" }]); setHintPick(""); }}>
            Add hint
          </Button>
        </div>
        {hints.map((h, i) => (
          <div key={`${h.ref}-${i}`} className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-[11.5px]">{h.ref}</code>
            <Input className="h-8 max-w-[420px]" value={h.value} onChange={(e) => setHints(hints.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} placeholder="what it says, if anything (optional)" />
            <Button size="sm" variant="ghost" onClick={() => setHints(hints.filter((_, j) => j !== i))}>
              Remove
            </Button>
          </div>
        ))}
      </div>
      <Button disabled={busy || !text.trim() || !why.trim() || (priority === "urgent" && !reason.trim()) || (objective === "new" && !objectiveText.trim())} onClick={() => void submit()}>
        Record and deliver
      </Button>
    </section>
  );
}

export function QuestionsPanel({ view, version }: { view: SwarmView; version: number }) {
  const id = view.summary.id;
  const live = useLive();
  const loader = useCallback(() => api.questions(id), [id]);
  const res = useResource(loader, version, [id]);
  const peopleLoader = useCallback(() => api.examiners(), []);
  const people = useResource(peopleLoader, 0, []);
  const [as, setAsState] = useState(readAs);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [triageWhy, setTriageWhy] = useState<Record<string, string>>({});
  const job = jobId ? (live.jobs[jobId] ?? null) : null;
  useEffect(() => writeAs(as), [as]);
  const act: Act = useCallback(
    async (payload) => {
      setError(null);
      setBusy(true);
      try {
        const j = await api.questionAct(id, { ...payload, ...(as ? { as } : {}) });
        setJobId(j.id);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : (err as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [id, as],
  );
  // The acknowledgement: the CLI's last line, once the chain holds the act.
  const ack = useMemo(() => {
    if (!job || job.status === "running") return null;
    const last = job.stdout.trim().split("\n").at(-1) ?? "";
    try {
      return JSON.parse(last) as { ok?: boolean; q?: string; rev?: number; scope?: string; scope_why?: string; delivered?: Array<{ q: string; offer_to: string | null; first: boolean }>; reason?: string };
    } catch {
      return null;
    }
  }, [job]);
  if (res.error && !res.data) return <ErrorState error={res.error} onRetry={res.reload} title="Could not read the question register" />;
  if (!res.data) return <LoadingState label="Reading the question register" rows={4} />;
  const d = res.data;
  const persons: SelectOption[] = [
    { value: "", label: "Myself, not enrolled", hint: "the operator: this host's OS account, with the operator's authority" },
    ...(people.data?.people ?? []).map((p) => ({ value: p.id, label: `${p.name} (${p.role})`, hint: `${p.organisation}: a claim; signing is the command line's (--sign)` })),
  ];
  const grouped = questionGroups(d.questions);
  const proposed = grouped.find((g) => g.key === "proposed")?.questions ?? [];
  const triage = d.triage.filter((t) => !t.resolved);
  const clarifications = d.questions.filter((q) => q.pending_clarifications.length);
  const ICONS: Record<string, ReactNode> = { people: <HelpCircle key="p" className="size-3.5" />, goal: <ListChecks key="g" className="size-3.5" />, agents: <PenLine key="a" className="size-3.5" /> };
  // The proposed ones are cards in the triage section, above.
  const groups: Array<[string, QuestionView[], ReactNode]> = grouped.filter((g) => g.key !== "proposed").map((g) => [g.label, g.questions, ICONS[g.key] ?? null]);
  return (
    <div className="space-y-5">
      <p className="m-0 text-[12.5px] text-ink-2">
        {d.questions.length} question{d.questions.length === 1 ? "" : "s"} in <code>questions/questions.md</code>; chain{" "}
        {d.chain.ok ? `intact, ${d.chain.events} events` : <span className="text-brick-ink">BROKEN at line {d.chain.broken_at} ({d.chain.reason})</span>}
        {d.seeded ? "" : "; the goal's questions are read from the goal until the register's first write"}. Q-n is the ledger's question:n.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Label className="text-[12px] text-ink-2">Acting as</Label>
        <Select className="max-w-[360px]" value={as} onChange={setAsState} options={persons} aria-label="Acting as" />
        <span className="text-[12px] text-ink-3">for this console session: a claim, never a signature</span>
      </div>
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      {job ? (
        <div className="space-y-1">
          {ack?.ok && ack.q ? (
            <InlineNote tone="ok">
              {ack.q}
              {ack.rev ? ` revision ${ack.rev}` : ""} is on the chain{ack.scope ? `, ${ack.scope.replace("_", " ")}: ${ack.scope_why ?? ""}` : ""}
              {ack.delivered?.length ? `; delivered${ack.delivered.map((x) => (x.offer_to ? `, offered to ${x.offer_to}${x.first ? " first" : ""}` : "")).join("")}` : ""}.
            </InlineNote>
          ) : null}
          <JobCard job={job} />
        </div>
      ) : null}

      <section className="space-y-2" aria-label="Waiting for your triage">
        <h3 className="label-caps flex items-center gap-1.5 text-saffron-ink">
          <AlertTriangle className="size-3.5" /> Waiting for your triage ({proposed.length + triage.length})
        </h3>
        {proposed.length + triage.length === 0 ? <p className="m-0 text-[12.5px] text-ink-3">Nothing: every question is in scope or excluded, and no lead waits after a withdrawal.</p> : null}
        <ul className="m-0 list-none space-y-2 p-0">
          {proposed.map((q) => (
            // A proposed question whole: its details, its clarifications (answered here before it is admitted), and the triage.
            <QuestionCard key={q.id} q={q} sigs={d.signatures} act={act} busy={busy}>
              <div className="flex flex-wrap items-center gap-2 rounded-md border border-saffron bg-saffron-soft/30 px-2 py-1.5">
                <span className="text-ink-2">
                  Triage{q.objective_text ? `; admitting it adds the objective: ${q.objective_text}` : ""}:
                </span>
                <Input className="h-8 max-w-[420px]" value={triageWhy[q.id] ?? ""} onChange={(e) => setTriageWhy({ ...triageWhy, [q.id]: e.target.value })} placeholder="why" />
                <Button size="sm" disabled={busy || !(triageWhy[q.id] ?? "").trim()} onClick={() => void act({ action: "scope", target: q.id, scope: "in_scope", why: triageWhy[q.id] })}>
                  Admit
                </Button>
                <Button size="sm" variant="secondary" disabled={busy || !(triageWhy[q.id] ?? "").trim()} onClick={() => void act({ action: "scope", target: q.id, scope: "excluded", why: triageWhy[q.id] })}>
                  Exclude
                </Button>
              </div>
            </QuestionCard>
          ))}
          {triage.map((t) => {
            const target = t.lead ?? t.q ?? "";
            return (
              <li key={t.seq} className="rounded-md border border-saffron bg-saffron-soft/30 px-3 py-2 text-[12.5px]">
                <p className="m-0">
                  <code className="font-mono font-semibold">{target}</code>: {t.cause}
                </p>
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  <Input className="h-8 max-w-[420px]" value={triageWhy[target] ?? ""} onChange={(e) => setTriageWhy({ ...triageWhy, [target]: e.target.value })} placeholder="why" />
                  <Button size="sm" disabled={busy || !(triageWhy[target] ?? "").trim()} onClick={() => void act({ action: "scope", target, scope: "in_scope", why: triageWhy[target] })}>
                    Keep
                  </Button>
                  <Button size="sm" variant="secondary" disabled={busy || !(triageWhy[target] ?? "").trim()} onClick={() => void act({ action: "scope", target, scope: "excluded", why: triageWhy[target] })}>
                    {t.lead ? "Close it" : "Exclude"}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      {clarifications.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0 flex items-center gap-1.5">
            <MessageSquare className="size-3.5" /> Clarifications waiting ({clarifications.reduce((n, q) => n + q.pending_clarifications.length, 0)})
          </h3>
          <p className="m-0 text-[12.5px] text-ink-2">An agent asked what a question means; the rest of the work goes on. Answer on the question below: {clarifications.map((q) => `${q.id} (${q.pending_clarifications.join(", ")})`).join(", ")}.</p>
        </section>
      ) : null}

      <AddForm data={d} view={view} act={act} busy={busy} />

      {d.objectives.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Objectives</h3>
          <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-ink-2">
            {d.objectives.map((o) => (
              <li key={o.id}>
                <code className="font-mono">{o.id}</code> {o.text}
                {o.added_by ? <span className="text-ink-3"> ({o.why || `added by ${o.added_by}`})</span> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {d.questions.length ? (
        groups.map(([label, list, icon]) =>
          list.length ? (
            <section key={label} className="space-y-2">
              <h3 className="label-caps flex items-center gap-1.5">
                {icon} {label} ({list.length})
              </h3>
              <ul className="m-0 list-none space-y-2 p-0">
                {list.map((q) => (
                  <QuestionCard key={q.id} q={q} sigs={d.signatures} act={act} busy={busy} />
                ))}
              </ul>
            </section>
          ) : null,
        )
      ) : (
        <EmptyState title="No question yet" hint="The goal's numbered questions appear here; so does every question an agent opens (question_open) or a person asks, here or with swarm.sh question." />
      )}
    </div>
  );
}
