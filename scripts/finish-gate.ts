/**
 * The harness's part of the finish line, beside the goal's checks: what the
 * lead register holds against a done, and how the run would end if it ended
 * now. The goal's checks say whether the definition of done is met; this says
 * whether material work is still open (a lead with no disposition, a lead's
 * job with no interpretation) and whether a run that meets its checks
 * answered every question or is examination-limited: a section the answers
 * check found limited or inconclusive, a material lead closed deferred,
 * infeasible or needs_operator, an acceptance. A limitation is never an
 * answer, and a defect it only names holds the run (holding).
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
 * The rule is the same under every stop policy (docs/adr/0013, joint-r3
 * Phase 1a): done finishes a run only when every question in scope has a
 * disposition under the bar:
 * established, partial, a bounded negative or not determinable resting on a
 * coverage record another seat reviewed, a premise shown not to hold, out of
 * scope, accepted by the operator, or withdrawn. Each question carries its
 * disposition here. A question with no disposition, a defect a limitation
 * only names, and a quick negative nobody has attested hold done, each named
 * with what blocks it. The stop policy decides only who else ends the run: a
 * cap pauses or stops it and the operator stops it, whatever the questions'
 * state (paused, stopped; never completed); under --stop operator (its alias
 * --until-solved, budget.json until_solved) nothing else does and nobody
 * abandons. It adds no stricter answer requirement.
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
import { ACCEPTANCE_NEVER_EXCUSES, type FinishLineRun } from "../extensions/protocol.ts";
import { checkLedgerAnswers } from "./check-answers.ts";

/**
 * A question and how it stands: the answers check's outcome (answered,
 * limited, inconclusive, unanswered), or the register's (accepted,
 * withdrawn); its disposition under the bar when it has one; what blocks it.
 */
export type FinishGateQuestion = { id: string; outcome: string; blocks: string[]; disposition?: string };

/** What the question register holds against a done. */
export type QuestionDefect = { code: "open_question" | "question_answer" | "stale_answer"; question: string; what: string; fix: string };

/** An addition committed whose effects (its ledger entry, its request, the leads and answers it reopens, its board post) are not all recorded yet. */
export type AdditionDefect = { code: "addition_incomplete"; import: string; what: string; fix: string };

export type FinishGate = {
  defects: Array<L.LeadDefect | QuestionDefect | AdditionDefect>;
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
  /**
   * What holds done beside the questions, under every stop policy: a defect
   * a limitation only names (a defect is fixed, and a named one is no
   * disposition). Every other line of `limited` is a disposition's, or a
   * route's, and makes the end examination-limited.
   */
  holding?: string[];
  /** What the answers check warns of and does not hold on (a not-determinable answer naming no acquisition ask, nor why none). */
  warnings?: string[];
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
    // A store sweep lost with the process that began it is run before the gate is read (store-sweep.ts).
    await import("../extensions/store-sweep.ts").then((SW) => SW.reconcileSweeps(sandbox)).catch(() => 0);
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
    // Evidence or material committed whose effects are not all recorded: what it reopens may still look settled.
    const { unappliedAdditions } = await import("./material.ts");
    for (const a of await unappliedAdditions(sandbox)) {
      defects.push({
        code: "addition_incomplete",
        import: a.import,
        what: `import:${a.import} (${a.type === "evidence_added" ? "evidence" : "material"} added by ${a.by} at ${a.at}) is committed, and what follows from it is not all recorded yet: its ledger entry, its request's stages, the leads and answers it reopens, its board post`,
        fix: "the hub records it at its next round; with no hub running, swarm.sh evidence <run> list records it",
      });
    }
    const limiting = lead.limiting;
    const limited: string[] = [];
    // What the answers check said about each section, passing or not.
    const outcomes = new Map<string, string>();
    // The sections whose answer claims established and every review holds a best candidate only (B2: check-answers.ts, protocol.ts heldAsBestCandidate).
    const best = new Set<string>();
    // Each section's disposition under the bar, as the answers check found it.
    const dispositions = new Map<string, string>();
    const holding: string[] = [];
    const warnings: string[] = [];
    let sawAnswers = false;
    for (const c of run?.checks ?? []) {
      const a = c.answers as { outcomes?: Record<string, string>; named?: string[]; best_candidate?: string[]; dispositions?: Record<string, string>; warnings?: string[] } | undefined;
      if (!a) continue;
      sawAnswers = true;
      for (const [k, v] of Object.entries(a.outcomes ?? {})) {
        const key = k.startsWith("question:") || k === "summary" || k === "narrative" ? k : `question:${k}`;
        outcomes.set(key, v);
      }
      for (const b of a.best_candidate ?? []) best.add(b.startsWith("question:") ? b : `question:${b}`);
      for (const [k, v] of Object.entries(a.dispositions ?? {})) dispositions.set(k.startsWith("question:") ? k : `question:${k}`, v);
      for (const n of a.named ?? []) {
        limited.push(`a defect a limitation names: ${n}`);
        holding.push(`a defect a limitation names: ${n}`);
      }
      for (const w of a.warnings ?? []) if (!warnings.includes(w)) warnings.push(w);
    }
    for (const [k, v] of outcomes) if (v !== "answered") limited.push(best.has(k) ? `${k} is a best candidate, not established (every review holds it so)` : `${k} is ${OUTCOME_WORDS[v] ?? v}`);
    // A quick negative nobody else has attested holds its questions: its
    // search is a cue for review, and a disposition on it waits for one.
    const quick = await unattestedQuickNegatives(sandbox, snap);
    // Each goal question, and what stands in its way.
    const questions: FinishGateQuestion[] = [];
    for (const id of snap.goal.questions) {
      const key = `question:${id}`;
      const said = outcomes.get(key) ?? (sawAnswers ? "unanswered" : snap.answered.has(id) ? "has an answer (not checked)" : "unanswered");
      // A goal question the operator accepted (bounded, or not determinable), for its current revision and the answer that stands now, is disposed: it limits the run and holds nothing.
      const reg = qs?.bySection.get(id);
      // A goal question the register holds as withdrawn is off what the run must answer: named, holding nothing.
      if (reg?.withdrawn) {
        questions.push({ id, outcome: "withdrawn", blocks: [] });
        continue;
      }
      const outcome = said !== "answered" && reg && Q.acceptanceStands(reg, snap.ledger) ? "accepted" : said;
      const blocks: string[] = [];
      // A quick negative holds a question that is not answered outright (an answer that settles it needs no other).
      const held = outcome === "answered" || outcome === "accepted" ? [] : (quick.get(id) ?? []);
      const disposition = outcome === "accepted" || held.length ? undefined : dispositions.get(key);
      for (const h of held) blocks.push(h);
      if (outcome !== "answered" && outcome !== "accepted" && !disposition) {
        if (best.has(key)) blocks.push("its answer is a best candidate, not established: every review holds it so; take the route that would settle it, or the operator accepts its limits");
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
        if (!blocks.length) blocks.push(`its answer is ${OUTCOME_WORDS[outcome] ?? outcome} and no disposition under the bar: it rests on a limitation, a search that only documents one, a coverage record nobody else reviewed or that no longer stands, or is marked inconclusive`);
      }
      questions.push({ id, outcome, blocks, ...(disposition ? { disposition } : {}) });
    }
    const accepted: string[] = [];
    const register = qs ? await registerGate(sandbox, snap, qs, defects, limited, questions, accepted, holding, quick, warnings) : undefined;
    // A route lead (a material lead closed deferred, infeasible or
    // needs_operator) keeps its disposition in history and limits the run
    // until its questions are disposed under the bar and another seat holds
    // its limitation no longer material, or the operator accepted them
    // (L.routeLimitation): a failed route stays failed, and stops holding a
    // question another route answered only when somebody says it no longer
    // matters.
    const disposed = (section: string): "answered" | "accepted" | null => {
      const q = questions.find((x) => x.id === section);
      if (q?.outcome === "answered" || q?.disposition) return "answered";
      if (q?.outcome === "accepted") return "accepted";
      const reg = qs?.bySection.get(section);
      if (reg && Q.acceptanceStands(reg, snap.ledger)) return "accepted";
      return null;
    };
    for (const l of limiting) {
      const lead = snap.state.leads.get(l.lead);
      const verdict = lead ? L.routeLimitation(lead, disposed) : { limiting: true, why: "" };
      if (verdict.limiting) limited.push(`${l.lead} was closed ${l.disposition} (${l.ref})${verdict.why ? `: ${verdict.why}` : ""}`);
    }
    return { defects, limited, questions, until_solved: until, holding, ...(register ? { register } : {}), ...(accepted.length ? { accepted } : {}), ...(warnings.length ? { warnings } : {}) };
  } catch (err) {
    return { defects: [], limited: [], questions: [], until_solved: until, error: `the lead register could not be read: ${(err as Error).message}` };
  }
}

/**
 * The negative bar's defects (evidence added since a negative's coverage, a
 * completeness claim with no coverage of its areas, a store sweep pending or
 * with hits outside its record, among them), and an answer resting on
 * material the case policy forbids: fixed, never named, and never excused
 * by an acceptance (protocol.ts ACCEPTANCE_NEVER_EXCUSES). A partial sweep is
 * excused by one, and evidence added before the acceptance too
 * (acceptanceExcuses); the answers check drops those before this reads it.
 */
export const NEGATIVE_BAR_CODES: ReadonlySet<string> = ACCEPTANCE_NEVER_EXCUSES;

/**
 * The quick negatives nobody else has attested (a lead closed negative
 * after one job over one object within two minutes, leads.ts), by the
 * sections of the questions they serve: each a line saying so.
 */
async function unattestedQuickNegatives(sandbox: string, snap: L.LeadsSnapshot): Promise<Map<string, string[]>> {
  const P = await import("../extensions/protocol.ts");
  const attestations = await P.readAttestations(sandbox).catch(() => [] as Awaited<ReturnType<typeof P.readAttestations>>);
  const out = new Map<string, string[]>();
  for (const l of snap.state.leads.values()) {
    if (!l.quick_negative || l.closed?.disposition !== "negative") continue;
    const m = /^E-(\d+)$/.exec(l.closed.ref);
    const e = m ? snap.ledger.bySeq.get(Number(m[1])) : undefined;
    if (e && attestations.some((x) => P.attestationAct(x) === "attest" && x.target === (e.hash ?? P.ledgerHash(e, "genesis")) && !e.authors.includes(x.by))) continue;
    const line = `${l.id} "${l.title}" was closed a quick negative (${Math.round(l.quick_negative.held_ms / 1000)} s, ${l.quick_negative.jobs} job(s), ${l.quick_negative.objects} object(s); ${l.closed.ref}) that nobody else has attested: another seat attests ${l.closed.ref} (what it ran again, from which object)`;
    for (const q of l.answers) out.set(q, [...(out.get(q) ?? []), line]);
  }
  return out;
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
async function registerGate(
  sandbox: string,
  snap: L.LeadsSnapshot,
  qs: Q.QuestionsSnapshot,
  defects: FinishGate["defects"],
  limited: string[],
  questions: FinishGateQuestion[],
  accepted: string[],
  holding: string[],
  quick: Map<string, string[]>,
  warnings: string[] = [],
): Promise<NonNullable<FinishGate["register"]>> {
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
  // A summary or a narrative that cites a question symbolically (A4) is
  // revalidated when that question's scope changes: withdrawn, excluded or
  // sent back to triage since, it is recorded again.
  for (const e of snap.ledger.entries) {
    if (e.kind !== "answer" || snap.ledger.replaced.has(e.seq) || !e.question_refs?.length) continue;
    for (const r of e.question_refs) {
      const q = qs.bySection.get(r.section.replace(/^question:/, ""));
      if (!q) continue;
      const gone = q.withdrawn ? `withdrawn by ${Q.originWords(q.withdrawn.origin)}` : q.scope !== "in_scope" ? `now ${q.scope}` : null;
      if (gone) defects.push({ code: "question_answer", question: q.id, what: `the ${e.section} E-${e.seq} cites ${r.q} (${r.section}), ${gone} since`, fix: `record the ${e.section} again with supersedes=${e.seq}, without ${r.q} or saying what its change means for the conclusion` });
    }
  }
  const material = Q.registerQuestions(qs).filter((q) => q.materiality === "material");
  const extra = material.filter((q) => !Q.acceptanceStands(q, snap.ledger));
  // An accepted question is excused its answer, never the negative bar: a
  // negative it rests on is covered, reviewed and worded as one, whatever
  // was accepted.
  const acceptedQs = material.filter((q) => Q.acceptanceStands(q, snap.ledger));
  if (acceptedQs.length) {
    const r = await checkLedgerAnswers(sandbox, acceptedQs.map((q) => `question:${q.section}`), acceptedQs.filter((q) => q.expects === "existence").map((q) => q.section));
    const bySection = new Map(acceptedQs.map((q) => [`question:${q.section}`, q]));
    for (const d of r.defects) {
      const q = d.section ? bySection.get(d.section) : undefined;
      if (q && NEGATIVE_BAR_CODES.has(d.code)) defects.push({ code: "question_answer", question: q.id, what: d.what, fix: d.fix });
    }
  }
  if (extra.length) {
    const sections = extra.map((q) => `question:${q.section}`);
    const r = await checkLedgerAnswers(sandbox, sections, extra.filter((q) => q.expects === "existence").map((q) => q.section));
    for (const w of r.warnings) if (!warnings.includes(w)) warnings.push(w);
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
      const held = outcome === "answered" ? [] : (quick.get(q.section) ?? []);
      const disposition = held.length ? undefined : r.dispositions[key];
      questions.push({
        id: q.section,
        outcome: outcome === "limited" ? "limited" : outcome,
        blocks: outcome === "answered" && !held.length ? [] : [...held, ...(disposition ? [] : blocksOf(snap, q.section)), ...(outcome === "unanswered" ? ["no standing answer entry"] : [])],
        ...(disposition ? { disposition } : {}),
      });
    }
    const bySection = new Map(extra.map((q) => [`question:${q.section}`, q]));
    for (const d of r.defects) {
      const q = d.section ? bySection.get(d.section) : undefined;
      if (!q || d.code === "no_answer") continue;
      if (d.named_by.length) {
        const line = `a defect a limitation names: ${d.what} (named by ${d.named_by.map((n) => `#${n}`).join(", ")})`;
        limited.push(line);
        holding.push(line);
      } else defects.push({ code: "question_answer", question: q.id, what: d.what, fix: d.fix });
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
