/**
 * The Technical review tab: the reviewer's screen of two-stage signing.
 *
 * A technical reviewer enrolled with --role reviewer records what they
 * checked and signs their own record with their own key and secret (a
 * countersign line, in the dfirswarm-review namespace). The record names
 * the state it was made over, shown here before anything is signed: the
 * report's sha256, the ledger's head, custody's sha256 and the head of the
 * examiner's dispositions. Once any of them changes the record is over an
 * earlier state, and the report says so. A record the examiner wrote naming
 * an enrolled reviewer, or one the reviewer left unsigned, can be
 * countersigned here later (after a release, the countersign names it).
 *
 * The reviewer is never the examiner: the server refuses the same id, name
 * or key. A reviewer on another machine works from the run's package on the
 * command line instead, and the examiner imports what they made.
 */
import { useCallback, useMemo, useState } from "react";
import { Chip } from "@/components/console";
import { InlineNote } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { SecretDialog, SigningUnavailable } from "@/components/signing";
import { api } from "@/lib/api";
import { useResource, useSwarmVersion } from "@/lib/live";
import type { EnrolledPerson, ExaminersView, ReleaseStateView, SwarmView, TechnicalReviewView } from "@/lib/types";

const STATUS_TONE = { signed: "moss", "countersigned-after-release": "kelp", recorded: "saffron", stale: "brick", "bad-signature": "brick" } as const;
const OUTCOME_HINT: Record<string, string> = {
  agreed: "the methods and the conclusions they support hold as the examiner left them",
  "issues-resolved": "issues were raised and resolved: say each one and how",
  disagreement: "a disagreement stands: say what it is; a seal that requires a review waits for another",
};

export function ReviewerPanel({ view }: { view: SwarmView }) {
  const id = view.summary.id;
  const version = useSwarmVersion(id, ["ledger", "events"]);
  const [nonce, setNonce] = useState(0);
  const stateLoader = useCallback(() => api.releaseState(id), [id]);
  const state = useResource<ReleaseStateView>(stateLoader, version + nonce, [id, "release"]);
  const peopleLoader = useCallback(() => api.examiners(), []);
  const people = useResource<ExaminersView>(peopleLoader, nonce, ["examiners"]);
  const reviewers = useMemo(() => (people.data?.people ?? []).filter((p) => p.role === "reviewer"), [people.data]);

  if (state.error) return <InlineNote tone="danger">The run's review could not be read: {state.error.message}</InlineNote>;
  const s = state.data;
  if (!s) return null;
  const ended = !["running", "prepared", "finishing"].includes(String(s.state ?? ""));
  return (
    <div className="space-y-4">
      <section className="card space-y-2 p-3" aria-label="Technical reviews">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="label-caps m-0">Technical reviews</h3>
          {s.policy.require_technical_review ? <Chip tone="kelp">required before a release ({s.policy.source})</Chip> : null}
        </div>
        {s.technical.length ? (
          <ol className="m-0 list-none space-y-2 p-0">
            {s.technical.map((t) => (
              <TechnicalRow key={t.review_seq} id={id} t={t} reviewers={reviewers} signingOk={s.signing.ok && ended} onDone={() => setNonce((n) => n + 1)} />
            ))}
          </ol>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-2">No technical review.</p>
        )}
      </section>
      {ended ? (
        <RecordForm id={id} state={s} reviewers={reviewers} signing={people.data?.signing ?? s.signing} onDone={() => setNonce((n) => n + 1)} />
      ) : (
        <InlineNote>The run is still {s.state}: its methods are reviewed once it has ended and custody is taken.</InlineNote>
      )}
      <InlineNote>
        A reviewer on another machine works from the run's package: <code>swarm.sh review &lt;package-dir&gt; --technical-review --reviewer ID --outcome … --checked …</code> writes review-import.jsonl, and the examiner adds it with <code>swarm.sh review {id} --import FILE --allowed-signers REGISTER</code>. The private key and the passphrase never move.
      </InlineNote>
    </div>
  );
}

function TechnicalRow({ id, t, reviewers, signingOk, onDone }: { id: string; t: TechnicalReviewView; reviewers: EnrolledPerson[]; signingOk: boolean; onDone: () => void }) {
  const [dialog, setDialog] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reviewer = reviewers.find((r) => (t.reviewer.id ? r.id === t.reviewer.id : r.name.trim().toLowerCase() === t.reviewer.name.trim().toLowerCase()));
  const canCountersign = signingOk && !t.countersign && reviewer && reviewer.console === "ok" && t.status !== "stale";
  const sign = async (secret: string) => {
    if (!reviewer) return;
    setBusy(true);
    setError(null);
    try {
      await api.countersign(id, { reviewer: reviewer.id, seq: t.review_seq, secret, consent: true });
      setDialog(false);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className="space-y-1 rounded-md border border-line p-2.5 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11px] text-ink-3">line {t.review_seq}</span>
        <Chip tone={STATUS_TONE[t.status]}>{t.status.replace(/-/g, " ")}</Chip>
        <span className="text-ink">
          {t.reviewer.name}
          {t.reviewer.organisation ? `, ${t.reviewer.organisation}` : ""}
        </span>
        {t.outcome ? <Chip tone={t.outcome === "disagreement" ? "brick" : "neutral"}>{t.outcome}</Chip> : null}
      </div>
      <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">{t.words}</p>
      <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">
        checked: {t.methods_checked}
        {t.scope === "all-answers" ? " (every answer)" : t.entries.length ? ` (${t.entries.map((e) => `E-${e.seq}`).join(", ")})` : ""}
        {t.reviewed_at ? `; reviewed ${t.reviewed_at}` : ""}
      </p>
      {t.disagreements.length ? <p className="m-0 text-ink-2 [overflow-wrap:anywhere]">disagreements: {t.disagreements.join("; ")}</p> : null}
      {canCountersign && reviewer ? (
        <>
          <Button size="sm" variant="secondary" onClick={() => (setError(null), setDialog(true))}>
            Countersign as {reviewer.name}
          </Button>
          <SecretDialog
            open={dialog}
            onOpenChange={setDialog}
            kind={reviewer.key.kind}
            pin={Boolean(reviewer.key.verify_required)}
            title={`Countersign review line ${t.review_seq}`}
            description={<p className="m-0">{reviewer.name} signs this record as it stands in the review, with {reviewer.words}.</p>}
            busy={busy}
            error={error}
            onSubmit={(s) => void sign(s)}
          />
        </>
      ) : null}
    </li>
  );
}

function RecordForm({ id, state, reviewers, signing, onDone }: { id: string; state: ReleaseStateView; reviewers: EnrolledPerson[]; signing: ReleaseStateView["signing"]; onDone: () => void }) {
  const [reviewer, setReviewer] = useState("");
  const [outcome, setOutcome] = useState("agreed");
  const [checked, setChecked] = useState("");
  const [entries, setEntries] = useState("");
  const [allAnswers, setAllAnswers] = useState(false);
  const [disagreements, setDisagreements] = useState("");
  const [reviewedAt, setReviewedAt] = useState("");
  const [consent, setConsent] = useState(false);
  const [dialog, setDialog] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const person = reviewers.find((r) => r.id === reviewer) ?? null;
  const entryList = entries
    .split(/[,\s]+/)
    .map((x) => Number(x.replace(/^(?:#|E-)/i, "")))
    .filter((n) => Number.isInteger(n) && n > 0);
  const lines = disagreements
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const ready = person && checked.trim() && consent && (outcome !== "disagreement" || lines.length) && !(allAnswers && entryList.length);
  const command = `swarm.sh review ${id} --technical-review --reviewer ${reviewer || "ID"} --outcome ${outcome} --checked TEXT`;
  const submit = async (secret: string) => {
    if (!person) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.technicalReview(id, {
        reviewer: person.id,
        outcome,
        checked: checked.trim(),
        ...(entryList.length ? { entries: entryList } : allAnswers ? { all_answers: true } : {}),
        ...(lines.length ? { disagreements: lines } : {}),
        ...(reviewedAt ? { reviewed_at: new Date(reviewedAt).toISOString() } : {}),
        secret,
        consent: true,
      });
      setDialog(false);
      setDone(`Recorded at review line ${r.seq} and countersigned at line ${r.countersign_seq}.`);
      setConsent(false);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  const st = state.reviewed_state;
  return (
    <section className="card space-y-3 p-3" aria-label="Record and sign a technical review">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="label-caps m-0">Record and sign a technical review</h3>
        <span className="text-[12px] text-ink-3">the reviewer's own record, signed with the reviewer's own key</span>
      </div>
      <SigningUnavailable signing={signing} command={command} />
      {!reviewers.length ? (
        <InlineNote>
          No technical reviewer is enrolled on this install: <code>swarm.sh examiner enroll --role reviewer …</code>, or the Examiners page.
        </InlineNote>
      ) : null}
      <div className="grid gap-1 text-[12px]">
        <div className="label-caps text-[11px]">What the record will be over</div>
        <div className="font-mono text-[11px] [overflow-wrap:anywhere]">work/report.md sha256 {st?.report_sha256 ?? "none"}</div>
        <div className="font-mono text-[11px] [overflow-wrap:anywhere]">ledger head {st?.ledger_head ?? "none"}</div>
        <div className="font-mono text-[11px] [overflow-wrap:anywhere]">custody.json sha256 {st?.custody_sha256 ?? "none"}</div>
        <div className="font-mono text-[11px] [overflow-wrap:anywhere]">dispositions head {st?.dispositions_head ?? "none"}</div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <span className="text-[12px] font-medium text-ink-2">Reviewer</span>
          <Select
            value={reviewer}
            onChange={setReviewer}
            placeholder="Choose the enrolled reviewer…"
            aria-label="Reviewer"
            disabled={!signing.ok || busy}
            options={reviewers.map((r) => ({ value: r.id, label: `${r.name} (${r.organisation})`, hint: r.console === "ok" ? r.words : `not from the console: ${r.console}`, disabled: r.console !== "ok" || Boolean(r.locked_until) }))}
          />
        </div>
        <div className="space-y-1">
          <span className="text-[12px] font-medium text-ink-2">Outcome</span>
          <Select value={outcome} onChange={setOutcome} aria-label="Outcome" disabled={busy} options={state.outcomes.map((o) => ({ value: o, label: o, hint: OUTCOME_HINT[o] }))} />
        </div>
      </div>
      <div className="space-y-1">
        <span className="text-[12px] font-medium text-ink-2">What was checked</span>
        <Textarea value={checked} onChange={(e) => setChecked(e.target.value)} placeholder="the methods re-run or read: which tool, over which evidence, what it showed" aria-label="What was checked" disabled={busy} />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Input value={entries} onChange={(e) => setEntries(e.target.value)} placeholder="entries by seq: 4, 10" aria-label="Entries reviewed" className="w-[220px]" disabled={busy || allAnswers} />
        <label className="flex items-center gap-1.5 text-[12.5px] text-ink-2">
          <input type="checkbox" className="accent-kelp" checked={allAnswers} onChange={(e) => setAllAnswers(e.target.checked)} disabled={busy || entryList.length > 0} /> every answer
        </label>
        <label className="flex items-center gap-1.5 text-[12.5px] text-ink-2">
          reviewed at <Input type="datetime-local" value={reviewedAt} onChange={(e) => setReviewedAt(e.target.value)} className="w-[210px]" disabled={busy} aria-label="Reviewed at" />
        </label>
      </div>
      <div className="space-y-1">
        <span className="text-[12px] font-medium text-ink-2">Disagreements and how each stands (one per line)</span>
        <Textarea value={disagreements} onChange={(e) => setDisagreements(e.target.value)} placeholder="E-19: the one command is not in the trace; rendered inconclusive by the examiner" aria-label="Disagreements" disabled={busy} className="min-h-[64px]" />
      </div>
      <label className="flex items-start gap-2 text-[13px] text-ink">
        <input type="checkbox" className="mt-0.5 accent-kelp" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
        <span>I reviewed this run as it stands, over the state above, and this record is mine.</span>
      </label>
      {done ? <InlineNote tone="ok">{done}</InlineNote> : null}
      <Button disabled={!signing.ok || !ready || busy} onClick={() => (setError(null), setDone(null), setDialog(true))}>
        Sign the review
      </Button>
      {person ? (
        <SecretDialog
          open={dialog}
          onOpenChange={setDialog}
          kind={person.key.kind}
          pin={Boolean(person.key.verify_required)}
          title={`Sign the technical review as ${person.name}`}
          description={<p className="m-0">The record ({outcome}) and its countersign are written together, and only if the review has not moved meanwhile. Five wrong secrets lock {person.name} out of the console for fifteen minutes.</p>}
          busy={busy}
          error={error}
          onSubmit={(s) => void submit(s)}
        />
      ) : null}
    </section>
  );
}
