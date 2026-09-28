/**
 * The console's question forms (ui/src/lib/question-forms.ts): an amend or
 * accept form keeps the revision it was opened on until the operator
 * refreshes it, so another person's amendment arriving live is never
 * overwritten by a stale draft; and every question, a proposed one included,
 * is on a full card where its clarifications can be answered.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { acceptPayload, amendPayload, baseMoved, formBase, questionGroups } from "../ui/src/lib/question-forms.ts";
import type { QuestionView } from "../ui/src/lib/types.ts";

const view = (over: Partial<QuestionView>): QuestionView =>
  ({
    id: "Q-4",
    section: "4",
    origin: { kind: "analyst", role: "analyst", person: "ana" },
    author: "ANA",
    text: "When was the archive made?",
    rev: 1,
    revisions: [],
    neutral: null,
    why: "timeline",
    scope: "in_scope",
    withdrawn: null,
    pending_clarifications: [],
    clarifications: [],
    ...over,
  }) as unknown as QuestionView;

test("a form keeps its base revision: a live amendment is named, never folded into what the form sends", () => {
  const opened = view({ rev: 1, text: "When was the archive made?" });
  const base = formBase(opened);
  // Another person amends it while the form is open: the card refreshes, the form does not.
  const live = view({ rev: 2, text: "When was the archive made, in UTC?" });
  assert.equal(baseMoved(base, live), 2);
  assert.equal(baseMoved(base, opened), null);
  const sent = amendPayload(live.id, base, { text: "When was the archive made, and by which clock?", why: "the clock matters", neutral: "" });
  assert.deepEqual(sent, { action: "amend", q: "Q-4", expected_rev: 1, text: "When was the archive made, and by which clock?", why: "the clock matters" }, "sent against revision 1: the register refuses it as stale");
  // A draft left unchanged sends no text, whatever the live revision says.
  assert.deepEqual(amendPayload(live.id, base, { text: base.text, why: "", neutral: "How old is the archive?" }), { action: "amend", q: "Q-4", expected_rev: 1, neutral: "How old is the archive?" });
  assert.deepEqual(acceptPayload(live.id, base, "bounded", "enough"), { action: "accept", q: "Q-4", accept_as: "bounded", why: "enough", expected_rev: 1 });
  // Refreshed: the base is the live revision.
  assert.equal(formBase(live).rev, 2);
});

test("every question is on a card, a proposed one with a clarification waiting included", () => {
  const qs = [
    view({ id: "Q-1", origin: { kind: "goal" } as QuestionView["origin"] }),
    view({ id: "Q-5", scope: "proposed", origin: { kind: "observer", person: "oli" } as QuestionView["origin"], pending_clarifications: ["C-1"] }),
    view({ id: "Q-6", scope: "excluded" }),
    view({ id: "Q-7", withdrawn: { at: "t", why: "w", origin: { kind: "analyst" } } as QuestionView["withdrawn"] }),
    view({ id: "Q-8", origin: { kind: "agent", agent: "a0" } as QuestionView["origin"] }),
    view({ id: "Q-9" }),
  ];
  const groups = questionGroups(qs);
  const carded = groups.flatMap((g) => g.questions.map((q) => q.id));
  assert.deepEqual([...carded].sort(), qs.map((q) => q.id).sort(), "each question on exactly one card");
  assert.equal(new Set(carded).size, carded.length);
  assert.deepEqual(groups.find((g) => g.key === "proposed")?.questions.map((q) => q.id), ["Q-5"], "the proposed question, with its clarification, is on a card");
  for (const q of qs.filter((x) => x.pending_clarifications.length)) assert.ok(carded.includes(q.id));
});
