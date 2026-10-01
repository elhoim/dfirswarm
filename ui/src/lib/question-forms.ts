/**
 * The question panel's forms and groups, apart from React so they can be
 * tested (tests/question-forms.test.ts).
 *
 * A form that acts against a revision (amend, accept) keeps the revision it
 * was opened on, its base, until the operator refreshes it: a live update
 * that brings another person's amendment changes what the card shows, never
 * what the open form sends. Sent against a replaced revision, the act is
 * refused by the register (it names the revision it read), which is the
 * conflict the operator resolves by refreshing, not a silent overwrite.
 *
 * Every question is shown on a full card, the proposed ones included, so a
 * clarification an agent asked on a question still waiting for triage can be
 * answered from the console before it is admitted or excluded.
 */
import type { QuestionView } from "./types.ts";

/** What an amend or accept form was opened on. */
export type FormBase = { rev: number; text: string; neutral: string };

export function formBase(q: Pick<QuestionView, "rev" | "text" | "neutral">): FormBase {
  return { rev: q.rev, text: q.text, neutral: q.neutral?.text ?? "" };
}

/** Whether the question moved past the form's base since it was opened: the revision it is at now, or null. */
export function baseMoved(base: FormBase | null, live: Pick<QuestionView, "rev">): number | null {
  return base && live.rev !== base.rev ? live.rev : null;
}

/** An amendment against the form's base: only what differs from the base is sent, with the base's revision. */
export function amendPayload(id: string, base: FormBase, draft: { text: string; why: string; neutral: string }): Record<string, unknown> & { action: "amend" } {
  return {
    action: "amend",
    q: id,
    expected_rev: base.rev,
    ...(draft.text.trim() && draft.text.trim() !== base.text ? { text: draft.text } : {}),
    ...(draft.why.trim() ? { why: draft.why } : {}),
    ...(draft.neutral.trim() && draft.neutral.trim() !== base.neutral ? { neutral: draft.neutral } : {}),
  };
}

/**
 * Require a question to be established, or release the requirement: an
 * amendment against the revision the card shows, which makes no new
 * revision. A release says why (the register refuses one without); a
 * requirement may.
 */
export function mustEstablishPayload(q: Pick<QuestionView, "id" | "rev">, required: boolean, why: string): Record<string, unknown> & { action: "amend" } {
  return { action: "amend", q: q.id, expected_rev: q.rev, must_establish: required, ...(why.trim() ? { why: why.trim() } : {}) };
}

/** Who required a question to be established, or released it, in words: the goal, or the person or agent the register names. */
export function mustEstablishWords(m: NonNullable<QuestionView["must_establish"]>): string {
  const who = m.origin.kind === "goal" ? "the goal" : (m.origin.name ?? m.origin.person ?? m.origin.agent ?? m.origin.kind);
  return m.required ? `required by ${who}${m.why ? `: ${m.why}` : ""}` : `released by ${who}: ${m.why ?? ""}`;
}

/** An acceptance of the form's base revision: it holds for that revision only. */
export function acceptPayload(id: string, base: FormBase, as: string, why: string): Record<string, unknown> & { action: "accept" } {
  return { action: "accept", q: id, accept_as: as, why, expected_rev: base.rev };
}

/**
 * The panel's groups of cards: proposed first (each with its triage and its
 * clarifications), then asked by people, the goal's, opened by agents,
 * excluded and withdrawn. Every question is in exactly one.
 */
export function questionGroups(questions: QuestionView[]): Array<{ key: string; label: string; questions: QuestionView[] }> {
  const groups: Array<{ key: string; label: string; pick: (q: QuestionView) => boolean }> = [
    { key: "proposed", label: "Proposed, waiting for your triage", pick: (q) => q.scope === "proposed" && !q.withdrawn },
    { key: "people", label: "Asked by people", pick: (q) => ["analyst", "reviewer", "observer"].includes(q.origin.kind) && q.scope === "in_scope" && !q.withdrawn },
    { key: "goal", label: "The goal's", pick: (q) => q.origin.kind === "goal" && !q.withdrawn && q.scope !== "excluded" },
    { key: "agents", label: "Opened by agents", pick: (q) => q.origin.kind === "agent" && q.scope === "in_scope" && !q.withdrawn },
    { key: "excluded", label: "Excluded", pick: (q) => q.scope === "excluded" && !q.withdrawn },
    { key: "withdrawn", label: "Withdrawn", pick: (q) => Boolean(q.withdrawn) },
  ];
  const placed = new Set<string>();
  const out = groups.map((g) => {
    const list = questions.filter((q) => !placed.has(q.id) && g.pick(q));
    for (const q of list) placed.add(q.id);
    return { key: g.key, label: g.label, questions: list };
  });
  // Anything no group names (a future scope) still gets a card.
  const rest = questions.filter((q) => !placed.has(q.id));
  if (rest.length) out.push({ key: "other", label: "Other", questions: rest });
  return out;
}
