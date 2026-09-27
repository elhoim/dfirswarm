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
import type { FinishLineRun } from "../extensions/protocol.ts";

export type FinishGateQuestion = { id: string; outcome: string; blocks: string[] };

export type FinishGate = {
  defects: L.LeadDefect[];
  /** Why a run that meets its checks is examination-limited, each in words; empty when it answered everything. */
  limited: string[];
  /** Each goal question and how it stands, with what blocks the ones not answered. */
  questions: FinishGateQuestion[];
  /** The run takes no end but every question answered (budget.json until_solved). */
  until_solved: boolean;
  /** Why the gate could not be read at all: the finish line is then unavailable, never met. */
  error?: string;
};

/** Whether the run was started with --until-solved. */
export async function untilSolved(sandbox: string): Promise<boolean> {
  try {
    return (JSON.parse(await readFile(join(sandbox, "budget.json"), "utf8")) as { until_solved?: unknown }).until_solved === true;
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
    const { defects, limiting } = await L.leadDefects(sandbox, snap);
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
      const outcome = outcomes.get(key) ?? (sawAnswers ? "unanswered" : snap.answered.has(id) ? "has an answer (not checked)" : "unanswered");
      const blocks: string[] = [];
      if (outcome !== "answered") {
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
    return { defects, limited, questions, until_solved: until };
  } catch (err) {
    return { defects: [], limited: [], questions: [], until_solved: until, error: `the lead register could not be read: ${(err as Error).message}` };
  }
}
