/**
 * The harness's part of the finish line, beside the goal's checks: what the
 * lead register holds against a done, and how the run would end if it ended
 * now. The goal's checks say whether the definition of done is met; this says
 * whether material work is still open (a lead with no disposition, a lead's
 * job with no interpretation) and whether a run that meets its checks
 * answered every question or is examination-limited: a section the answers
 * check found limited or inconclusive, a defect a limitation names, a
 * material lead closed deferred, infeasible or needs_operator. A limitation
 * permits an end; it never reads as an answer.
 *
 * The question register (extensions/questions.ts) is read in the same
 * snapshot: every question in scope beyond the goal's own (a person's, an
 * agent's) is held to an answer as a goal question is (check-answers.ts's
 * ledger mode, run here over those sections), so a question admitted while
 * the run goes on makes the finish not ready; a proposed one waits for the
 * operator's triage and holds nothing. An answer recorded before its
 * question's last amendment is stale, and an accepted question limits the
 * run instead of holding it.
 *
 * In an until-solved run (budget.json until_solved, set at kickoff) nothing
 * short of every question answered ends the run: the refusal names each
 * question that is not, and what blocks it.
 *
 * Read on the host, by the process that runs the finish line
 * (protocol.ts runFinishLine: the pane on a host run, the hub in a VM run),
 * from one snapshot of the files; the caller binds the whole run to the
 * state revision it was taken against.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import type { FinishLineRun } from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "./check-answers.ts";

export type FinishGateQuestion = { id: string; outcome: string; blocks: string[] };

/** What the question register holds against a done. */
export type QuestionDefect = { code: "open_question" | "question_answer" | "stale_answer"; question: string; what: string; fix: string };

export type FinishGate = {
  defects: Array<L.LeadDefect | QuestionDefect>;
  /** Why a run that meets its checks is examination-limited, each in words; empty when it answered everything. */
  limited: string[];
  /** Each goal question and how it stands, with what blocks the ones not answered. */
  questions: FinishGateQuestion[];
  /** The run takes no end but every question answered (budget.json until_solved). */
  until_solved: boolean;
  /** Why the gate could not be read at all: the finish line is then unavailable, never met. */
  error?: string;
  /** The question register's head the gate read, what it holds in scope, and what waits outside the run's work. */
  register?: { head: string | null; events: number; in_scope: string[]; proposed: string[]; after_done: string[] };
  /** The lines of `limited` that are the operator's acceptances: a limit the operator took, which even a run under --stop operator may end on. */
  accepted?: string[];
};

/** Whether the run's stop policy is the operator's (--stop operator, or its alias --until-solved). */
export async function untilSolved(sandbox: string): Promise<boolean> {
  try {
    const b = JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { until_solved?: unknown; stop_policy?: unknown };
    return b.until_solved === true || b.stop_policy === "operator";
  } catch {
    return false;
  }
}

const OUTCOME_WORDS: Record<string, string> = { limited: "examination-limited", inconclusive: "inconclusive", unanswered: "unanswered", answered: "answered" };

export async function finishGate(sandbox: string, run: FinishLineRun | null): Promise<FinishGate> {
  const until = await untilSolved(sandbox);
  try {
    await L.reopenOnLedger(sandbox).catch(() => undefined);
    const snap = await L.leadsSnapshot(sandbox);
    if (!snap.state.chain.ok) {
      return { defects: [], limited: [], questions: [], until_solved: until, error: `leads/leads.jsonl's chain is broken at line ${snap.state.chain.broken_at} (${snap.state.chain.reason}): the register cannot say what is open` };
    }
    const qs = snap.questions;
    if (qs && !qs.state.chain.ok) {
      return { defects: [], limited: [], questions: [], until_solved: until, error: `questions/questions.jsonl's chain is broken at line ${qs.state.chain.broken_at} (${qs.state.chain.reason}): the register cannot say what the run is asked` };
    }
    const lead = await L.leadDefects(sandbox, snap);
    const defects: FinishGate["defects"] = [...lead.defects];
    const limiting = lead.limiting;
    const limited: string[] = [];
    // What the answers check said about each section, passing or not.
    const outcomes = new Map<string, string>();
    let sawAnswers = false;
    for (const c of run?.checks ?? []) {
      const a = c.answers as { outcomes?: Record<string, string>; named?: string[] } | undefined;
      if (!a) continue;
      sawAnswers = true;
      for (const [k, v] of Object.entries(a.outcomes ?? {})) {
        const key = k.startsWith("question:") || k === "summary" || k === "narrative" ? k : `question:${k}`;
        outcomes.set(key, v);
      }
      for (const n of a.named ?? []) limited.push(`a defect a limitation names: ${n}`);
    }
    for (const [k, v] of outcomes) if (v !== "answered") limited.push(`${k} is ${OUTCOME_WORDS[v] ?? v}`);
    for (const l of limiting) limited.push(`${l.lead} was closed ${l.disposition} (${l.ref})`);
    // Each goal question, and what stands in its way.
    const questions: FinishGateQuestion[] = [];
    for (const id of snap.goal.questions) {
      const key = `question:${id}`;
      const said = outcomes.get(key) ?? (sawAnswers ? "unanswered" : snap.answered.has(id) ? "has an answer (not checked)" : "unanswered");
      // A goal question the operator accepted (bounded, or not determinable) for its current revision is disposed: it limits the run and holds nothing.
      const reg = qs?.bySection.get(id);
      // A goal question the register holds as withdrawn is off what the run must answer: named, holding nothing.
      if (reg?.withdrawn) {
        questions.push({ id, outcome: "withdrawn", blocks: [] });
        continue;
      }
      const outcome = said !== "answered" && reg && Q.acceptanceStands(reg) ? "accepted" : said;
      const blocks: string[] = [];
      if (outcome !== "answered" && outcome !== "accepted") {
        for (const l of snap.state.leads.values()) {
          if (!l.answers.includes(id)) continue;
          const st = L.leadStatus(l, snap.state, snap.ledger);
          if (st === "closed") {
            if (L.LIMITING_DISPOSITIONS.has(l.closed!.disposition)) blocks.push(`${l.id} "${l.title}" was closed ${l.closed!.disposition}: ${l.closed!.ref}`);
            continue;
          }
          const unmet = l.needs.map((n) => ({ n, s: L.needState(n, snap.state, snap.ledger) })).filter((x) => !x.s.met);
          blocks.push(`${l.id} "${l.title}" is ${st}${l.holder ? ` (held by ${l.holder})` : " (nobody holds it)"}${unmet.length ? `, waiting on ${unmet.map((x) => `${x.n}: ${x.s.why}`).join("; ")}` : ""}`);
        }
        if (!snap.answered.has(id)) blocks.push("no standing answer entry");
        if (!blocks.length) blocks.push(`its answer is ${OUTCOME_WORDS[outcome] ?? outcome}: it rests on a limitation, a search that only documents one, or is marked inconclusive`);
      }
      questions.push({ id, outcome, blocks });
    }
    const accepted: string[] = [];
    const register = qs ? await registerGate(sandbox, snap, qs, defects, limited, questions, accepted) : undefined;
    return { defects, limited, questions, until_solved: until, ...(register ? { register } : {}), ...(accepted.length ? { accepted } : {}) };
  } catch (err) {
    return { defects: [], limited: [], questions: [], until_solved: until, error: `the lead register could not be read: ${(err as Error).message}` };
  }
}

/** How a register question's blockers read: its leads, open or closed limiting. */
function blocksOf(snap: L.LeadsSnapshot, section: string): string[] {
  const out: string[] = [];
  for (const l of snap.state.leads.values()) {
    if (!l.answers.includes(section)) continue;
    const st = L.leadStatus(l, snap.state, snap.ledger);
    if (st === "closed") {
      if (L.LIMITING_DISPOSITIONS.has(l.closed!.disposition)) out.push(`${l.id} "${l.title}" was closed ${l.closed!.disposition}: ${l.closed!.ref}`);
      continue;
    }
    out.push(`${l.id} "${l.title}" is ${st}${l.holder ? ` (held by ${l.holder})` : " (nobody holds it)"}`);
  }
  return out;
}

/**
 * The register's part of the gate: stale answers and acceptances on every
 * question in scope, and every material question in scope beyond the goal's
 * own held to an answer the way the goal's check holds its questions.
 */
async function registerGate(sandbox: string, snap: L.LeadsSnapshot, qs: Q.QuestionsSnapshot, defects: FinishGate["defects"], limited: string[], questions: FinishGateQuestion[], accepted: string[]): Promise<NonNullable<FinishGate["register"]>> {
  const ctx: Q.ViewContext = { questions: qs, leads: snap.state, ledger: snap.ledger };
  const views = Q.questionViews(ctx);
  const inScope = views.filter((v) => v.scope === "in_scope" && !v.withdrawn && !v.after_done);
  for (const v of inScope) {
    if (v.answer?.stale) {
      const byEvidence = v.answer.stale_why === "evidence";
      const arrived = v.evidence.at(-1);
      defects.push({
        code: "stale_answer",
        question: v.id,
        what: byEvidence
          ? `new evidence for ${v.id} (question:${v.section}) arrived after its answer E-${v.answer.seq} was recorded (${arrived?.import ?? "an addition"}${arrived?.request ? ` for ${arrived.request}` : ""})`
          : `${v.id} (question:${v.section}) was amended to revision ${v.rev} after its answer E-${v.answer.seq} was recorded`,
        fix: byEvidence
          ? `examine the new evidence through a job (it is ${arrived?.import ?? "in store/imports"}), then record the answer again with supersedes=${v.answer.seq}, unchanged if the new evidence changes nothing`
          : `hold the answer to revision ${v.rev} (questions show ${v.id}) and record it again with supersedes=${v.answer.seq}`,
      });
    }
    if (v.accepted?.stands) {
      const line = `${v.id} was accepted as ${v.accepted.as === "bounded" ? "a bounded examination" : "not determinable"} by ${Q.originWords(v.accepted.origin)}: ${v.accepted.why}`;
      limited.push(line);
      accepted.push(line);
    }
  }
  const extra = Q.registerQuestions(qs).filter((q) => q.materiality === "material" && !Q.acceptanceStands(q));
  if (extra.length) {
    const sections = extra.map((q) => `question:${q.section}`);
    const r = await checkLedgerAnswers(sandbox, sections, extra.filter((q) => q.expects === "existence").map((q) => q.section));
    for (const q of extra) {
      const key = `question:${q.section}`;
      const outcome = r.outcomes[key] ?? "unanswered";
      if (outcome === "unanswered") {
        defects.push({
          code: "open_question",
          question: q.id,
          what: `${q.id} (${key}, ${Q.originWords(q.origin)}${q.origin.kind === "agent" ? "" : ", in scope"}) has no answer that stands: "${q.text}"`,
          fix: `answer it in the ledger (record kind=answer, section=${key}, resting on entries recorded with answers=["${q.section}"]${Q.HUMAN_ORIGINS.has(q.origin.kind) ? ", with contrary or contrary_none_why" : ""}), or record a limitation with answers=["${q.section}"] saying why it cannot be answered`,
        });
      } else if (outcome !== "answered") limited.push(`${q.id} (${key}) is ${outcome === "limited" ? "examination-limited" : outcome}`);
      questions.push({ id: q.section, outcome: outcome === "limited" ? "limited" : outcome, blocks: outcome === "answered" ? [] : [...blocksOf(snap, q.section), ...(outcome === "unanswered" ? ["no standing answer entry"] : [])] });
    }
    const bySection = new Map(extra.map((q) => [`question:${q.section}`, q]));
    for (const d of r.defects) {
      const q = d.section ? bySection.get(d.section) : undefined;
      if (!q || d.code === "no_answer") continue;
      if (d.named_by.length) limited.push(`a defect a limitation names: ${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`);
      else defects.push({ code: "question_answer", question: q.id, what: d.what, fix: d.fix });
    }
  }
  return {
    head: qs.state.chain.head,
    events: qs.state.events.length,
    in_scope: inScope.map((v) => v.id),
    proposed: views.filter((v) => v.scope === "proposed" && !v.withdrawn).map((v) => v.id),
    after_done: views.filter((v) => v.after_done).map((v) => v.id),
  };
}
