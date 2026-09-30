/**
 * A review of the report carries over (docs/adr/0015, "A review carries
 * over"; the limits spec, item 3 refinement). On c10 run sd9645b the finish
 * took about 49 minutes over three versions of the report: 19 acks, most of
 * them no-objection re-acks, since every version reset every seat's review.
 * Here an ack binds each section of the report it covered by that section's
 * digest: a version that leaves them unchanged keeps it standing, only a
 * review of a changed section is asked again, and the finish register
 * records the carry-over. Late items keep their per-item rule, and the final
 * transaction is unchanged: an objection still holds the done, whatever
 * section it is on.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as F from "../extensions/finish.ts";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import { reviewsOf } from "../scripts/replay.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

const REPORT = "work/report.md";
const SEATS = ["a0", "a1", "a2", "a3", "a4"];

async function run() {
  const base = await mkdtemp(join(tmpdir(), "finish-carry-"));
  dirs.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "fc", agentIds: SEATS, capUsd: 5, wallClockMinutes: 30 });
  for (const a of SEATS) await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: new Date().toISOString(), recv_ts: new Date().toISOString(), agent: a, tool: "bash", args: {}, result: { ok: true } })}\n`);
  const ctx = (id: string) => ({ sandboxRoot: S, agentId: id });
  return { S, ctx };
}

/** A report with a preamble, three numbered sections and a closing one; `over` replaces a section's body. */
function report(over: Record<string, string> = {}): string {
  const body = (k: string, d: string) => over[k] ?? d;
  return [
    "# Case report",
    "",
    body("preamble", "Examiner's summary line."),
    "",
    "## 1. The device",
    "",
    body("1", "Section one rests on E-1."),
    "",
    "## 2. The account",
    "",
    body("2", "Section two rests on E-2."),
    "",
    "## 3. The destination",
    "",
    body("3", "Section three rests on E-3."),
    "",
    "## Conclusions and limitations",
    "",
    body("Conclusions and limitations", "What the evidence shows and where it ends."),
    "",
  ].join("\n");
}

async function publish(S: string, text: string, agent = "a0"): Promise<void> {
  await mkdir(join(S, "work"), { recursive: true });
  await writeFile(join(S, REPORT), text);
  await P.recordFileVersion(S, REPORT, agent);
}

const ok = <T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> => {
  assert.ok(r.ok, `refused: ${(r as { reason?: string }).reason}`);
  return r as Extract<T, { ok: true }>;
};
const seat = (r: F.ReviewStanding | null, by: string) => r?.seats.find((x) => x.by === by);

test("the report's sections: the preamble, numbered headings by number, others by their words, repeats numbered, fenced headings not headings; every line in one section", () => {
  const text = "# T\nintro\n## 1. One\na\n```\n## 2. not a heading\n```\n## Notes\nb\n## Notes\nc\n### sub\nd\n";
  const secs = F.reportSections(text);
  assert.deepEqual(secs.map((x) => x.key), [F.PREAMBLE, "1", "Notes", "Notes (2)"]);
  assert.deepEqual(secs.map((x) => x.title), ["", "1. One", "Notes", "Notes"]);
  // A change inside the fence changes section 1 only; a change under the repeated heading changes that one only.
  const a = F.reportSections(text.replace("## 2. not a heading", "## 2. still not"));
  assert.deepEqual(a.map((x, i) => x.digest === secs[i].digest), [true, false, true, true]);
  const b = F.reportSections(text.replace("\nd\n", "\ne\n"));
  assert.deepEqual(b.map((x, i) => x.digest === secs[i].digest), [true, true, true, false]);
  // Names a reviewer can use: the key, the number in several spellings, the heading's words.
  assert.deepEqual(F.namedSections(secs, ["1", "§1", "Q-1", "section 1", "notes", "Notes (2)", "preamble"]), { ok: true, keys: ["1", "Notes", "Notes (2)", F.PREAMBLE] });
  const bad = F.namedSections(secs, ["7"], REPORT);
  assert.ok(!bad.ok && /"7" is not a section of work\/report\.md; its sections are preamble, 1, Notes, Notes \(2\)/.test(bad.reason));
});

test("a republish that changes one section asks again only the reviews that covered it; the others carry over, and the finish register records why", async () => {
  const { S, ctx } = await run();
  await publish(S, report());
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  // a1 reviews the whole report, a2 section 1, a3 section 3 and the conclusions, a4 section 2.
  const w = ok(await F.ackReport(ctx("a1"), { verdict: "no_objection" }));
  assert.equal(w.whole, true);
  assert.deepEqual(w.sections, [F.PREAMBLE, "1", "2", "3", "Conclusions and limitations"]);
  ok(await F.ackReport(ctx("a2"), { verdict: "no_objection", sections: ["1"] }));
  ok(await F.ackReport(ctx("a3"), { verdict: "no_objection", sections: ["§3", "Conclusions and limitations"] }));
  ok(await F.ackReport(ctx("a4"), { verdict: "no_objection", sections: "2" }));
  const before = await F.reportReview(S);
  assert.deepEqual(before?.seats.map((x) => [x.by, x.standing]), [["a1", "direct"], ["a2", "direct"], ["a3", "direct"], ["a4", "direct"]]);
  assert.deepEqual(before?.uncovered, []);
  assert.equal((await F.readFinish(S)).carries.length, 0, "no carry while every review is of this version");

  // Section 3 is folded: only it changes.
  await publish(S, report({ "3": "Section three rests on E-3 and E-9 now." }));
  const r = await F.reportReview(S);
  assert.deepEqual(r?.seats.map((x) => [x.by, x.standing, x.changed]), [
    ["a1", "reasked", ["3"]],
    ["a2", "carried", []],
    ["a3", "reasked", ["3"]],
    ["a4", "carried", []],
  ]);
  assert.deepEqual(seat(r, "a3")?.covered, ["Conclusions and limitations"], "what a3 reviewed and did not change still counts");
  // The coordinator prepares again: the carry is on the chain before the prepare, and prepare says whom to ask, on what.
  const prep = ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  assert.match(String(prep.next), /the reviews of a2, a4 stand \(a2, a4 carried over: the sections they reviewed are unchanged\); ask again only on what changed: a1 \(3\); a3 \(3\)/);
  const st = await F.readFinish(S);
  assert.equal(st.carries.length, 1);
  const carry = st.carries[0];
  assert.equal(carry.digest, await F.reportDigest(S, REPORT));
  assert.deepEqual(carry.kept.map((x) => [x.by, x.acks, x.sections]), [["a2", [st.acks[1].seq], ["1"]], ["a4", [st.acks[3].seq], ["2"]]]);
  assert.deepEqual(carry.reasked.map((x) => [x.by, x.changed]), [["a1", ["3"]], ["a3", ["3"]]]);
  const prepares = st.events.filter((e) => e.ev === "prepare").map((e) => e.seq);
  assert.ok(carry.seq < prepares.at(-1)! && carry.seq > prepares[0], "the carry is recorded before the prepare that follows the republish");
  assert.ok(st.chain.ok);
  // Each seat's header says what it does: nothing again, or only the changed section.
  assert.match(String(await F.finishHeader(S, "a2")), /Your review of the report stands \(carried over: the sections you reviewed are unchanged\): do not ack it again, and do not post it on the board/);
  assert.match(String(await F.finishHeader(S, "a1")), /The report changed since your review in 3: review only that \(finish ack with sections \["3"\]\); the rest of your review carries over/);
  assert.match(String(await F.finishHeader(S, "a0")), /Review: the reviews of a2, a4 stand .*ask again only on what changed: a1 \(3\); a3 \(3\)/);

  // a1 and a3 review section 3 alone: every review stands again, a1's still a review of the whole report.
  ok(await F.ackReport(ctx("a1"), { verdict: "no_objection", sections: ["3"] }));
  ok(await F.ackReport(ctx("a3"), { verdict: "no_objection", sections: ["3"] }));
  const again = await F.reportReview(S);
  assert.deepEqual(again?.seats.map((x) => [x.by, x.standing]), [["a1", "carried"], ["a2", "carried"], ["a3", "carried"], ["a4", "carried"]]);
  assert.equal(seat(again, "a1")?.whole, true);
  assert.deepEqual(seat(again, "a1")?.covered, [F.PREAMBLE, "1", "2", "3", "Conclusions and limitations"]);
  const status = await F.finishStatus(ctx("a2"));
  assert.match(String((status.reviews as { invite: string }).invite), /the reviews of a1, a2, a3, a4 stand .*; ask nobody to review it again/);
  assert.equal((status.reviews as { carry?: number }).carry, carry.seq, "status names the carry event the standing reviews rest on");
  // Nothing more to weigh for this version: the acks since are of it, so no second carry.
  await F.finishHeader(S, "a0");
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  assert.equal((await F.readFinish(S)).carries.length, 1);
});

test("an objection on an unchanged section still holds the done: a republish of another section answers nothing, the objector's review of that other section does not answer it, and the final transaction reads it", async () => {
  const { S, ctx } = await run();
  await publish(S, report());
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  const obj = ok(await F.ackReport(ctx("a2"), { verdict: "objection", why: "section 2 names the wrong account", sections: ["2"] }));
  assert.deepEqual(obj.sections, ["2"]);
  // Section 1 is changed, not 2: the objection stands.
  await publish(S, report({ "1": "Section one, reworded." }));
  const late = await F.lateItems(S, "a0", REPORT);
  assert.deepEqual(late.map((x) => [x.kind, x.id]), [["objection", obj.seq]]);
  // The objector reviews section 1 (what changed): its objection to section 2 is not answered by it.
  ok(await F.ackReport(ctx("a2"), { verdict: "no_objection", sections: ["1"] }));
  assert.deepEqual((await F.lateItems(S, "a0", REPORT)).map((x) => x.id), [obj.seq]);
  // The final transaction reads it: the coordinator's done does not write the sentinel.
  const lease = (await F.readFinish(S)).lease!;
  await assert.rejects(P.markDone(ctx("a0"), { reason: "finished", outputFile: REPORT, finish: { holder: lease.holder, generation: lease.generation } } as Parameters<typeof P.markDone>[1]), /late against the report: objection .* by a2/);
  assert.equal(await P.swarmDoneExists(S), false);
  // The objector's review of section 2 answers its own objection; or the coordinator's resolution would.
  ok(await F.ackReport(ctx("a2"), { verdict: "no_objection", sections: ["Q-2"] }));
  assert.deepEqual(await F.lateItems(S, "a0", REPORT), []);
  // An objection to the whole report stands through a review of one section, and falls to a review of the whole.
  const whole = ok(await F.ackReport(ctx("a3"), { verdict: "objection", why: "the conclusions overstate section 3" }));
  ok(await F.ackReport(ctx("a3"), { verdict: "no_objection", sections: ["3"] }));
  assert.deepEqual((await F.lateItems(S, "a0", REPORT)).map((x) => x.id), [whole.seq]);
  ok(await F.ackReport(ctx("a3"), { verdict: "no_objection" }));
  assert.deepEqual(await F.lateItems(S, "a0", REPORT), []);
  // Per item as ever: an objection racing the done holds the sentinel, and its resolution lets it through.
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  const racing = ok(await F.ackReport(ctx("a4"), { verdict: "objection", why: "the preamble names the wrong image", sections: ["preamble"] }));
  await assert.rejects(P.markDone(ctx("a0"), { reason: "finished", outputFile: REPORT, finish: { holder: lease.holder, generation: lease.generation } } as Parameters<typeof P.markDone>[1]), /late against the report: objection/);
  ok(await F.resolveLate(ctx("a0"), { ack: racing.seq, how: "not_material", why: "the preamble names the image the inputs list" }));
  assert.deepEqual(await F.lateItems(S, "a0", REPORT), []);
});

test("a review of the whole report is asked about a section added or removed since; an ack from before per-section reviews reads as before, and the chain verifies", async () => {
  const { S, ctx } = await run();
  await publish(S, report());
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  ok(await F.ackReport(ctx("a1"), { verdict: "no_objection" }));
  ok(await F.ackReport(ctx("a2"), { verdict: "no_objection", sections: ["1", "2"] }));
  // A section is added: the whole-report review is asked about it, the scoped one is not.
  await publish(S, `${report()}## Appendix\n\nA table.\n`);
  let r = await F.reportReview(S);
  assert.deepEqual(r?.seats.map((x) => [x.by, x.standing, x.changed]), [["a1", "reasked", ["Appendix"]], ["a2", "carried", []]]);
  assert.deepEqual(r?.uncovered, ["Appendix"]);
  ok(await F.ackReport(ctx("a1"), { verdict: "no_objection", sections: ["Appendix"] }));
  // A section is removed: the whole-report review is asked about it, answered by a review of the whole report as it is.
  await publish(S, report().replace(/## 3\. The destination\n\nSection three rests on E-3\.\n\n/, ""));
  r = await F.reportReview(S);
  assert.deepEqual(r?.seats.map((x) => [x.by, x.standing, x.removed]), [["a1", "reasked", ["3", "Appendix"]], ["a2", "carried", []]]);
  assert.match(String(await F.finishHeader(S, "a1")), /changed since your review in removed: 3, Appendix: review only that \(finish ack with no sections, the whole report as it is\)/);
  ok(await F.ackReport(ctx("a1"), { verdict: "no_objection" }));
  assert.equal(seat(await F.reportReview(S), "a1")?.standing, "direct");

  // An ack from before per-section reviews (no sections): of the whole report at its digest, asked again on any other.
  const legacyDigest = (await F.reportDigest(S, REPORT))!;
  await appendRaw(S, { by: "a3", ev: "ack", digest: legacyDigest, verdict: "no_objection" });
  assert.equal(seat(await F.reportReview(S), "a3")?.standing, "direct");
  await publish(S, report({ "2": "Section two, folded." }));
  r = await F.reportReview(S);
  assert.deepEqual([seat(r, "a3")?.standing, seat(r, "a3")?.changed.length], ["reasked", 5]);
  // Its objection reads as before too: any later ack of its seat answers it.
  const obj = await appendRaw(S, { by: "a4", ev: "ack", digest: (await F.reportDigest(S, REPORT))!, verdict: "objection", why: "legacy" });
  assert.deepEqual((await F.lateItems(S, "a0", REPORT)).map((x) => x.id), [obj]);
  ok(await F.ackReport(ctx("a4"), { verdict: "no_objection", sections: ["1"] }));
  assert.deepEqual(await F.lateItems(S, "a0", REPORT), []);
  const text = await readFile(join(S, F.FINISH_LOG), "utf8");
  assert.ok(L.verifyLeadChain(text).ok);
  // A legacy line carries no section field: it hashes as it always did.
  const legacy = text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as F.FinishEvent).filter((e) => e.ev === "ack" && e.by === "a3");
  assert.deepEqual(legacy.map((e) => ["sections" in e, "whole" in e]), [[false, false]]);
});

test("replay estimates what the rule avoids on a run's recorded acks (values-free): re-reviews that stand, section reviews asked, rounds and echo posts", async () => {
  const { S, ctx } = await run();
  // Three versions, as on sd9645b: v2 changes sections 2 and the conclusions, v3 section 3 and the conclusions.
  const v1 = report();
  const v2 = report({ "2": "two, folded", "Conclusions and limitations": "c2" });
  const v3 = report({ "2": "two, folded", "3": "three, folded", "Conclusions and limitations": "c3" });
  await publish(S, v1);
  ok(await F.prepareFinish(ctx("a0"), { report: REPORT }));
  const d = async () => (await F.reportDigest(S, REPORT))!;
  // Acks as a harness from before recorded them: no sections.
  for (const by of ["a1", "a2", "a3"]) await appendRaw(S, { by, ev: "ack", digest: await d(), verdict: "no_objection" });
  await publish(S, v2);
  for (const by of ["a1", "a2", "a3", "a4"]) await appendRaw(S, { by, ev: "ack", digest: await d(), verdict: "no_objection" });
  await publish(S, v3);
  const at = new Date().toISOString();
  for (const by of ["a1", "a2", "a3", "a4"]) await appendRaw(S, { by, ev: "ack", digest: await d(), verdict: "no_objection" });
  // a1 announces its ack on the board and the coordinator resolves the post: an echo.
  const post = await P.postMessage(ctx("a1"), { tag: "result", body: "finish ack: no objection" });
  await appendFile(join(S, P.EVENTS_REL), `${JSON.stringify({ ts: new Date(Date.parse(at) + 5_000).toISOString(), recv_ts: at, agent: "a1", tool: "post", args: {}, result: { ok: true, id: post.id } })}\n`);
  await appendRaw(S, { by: "a0", ev: "resolve", post: post.id, how: "not_material", why: "an ack, announced" });
  // The seats' own questions (the scoped what-if): a1 answered 1, a2 answered 2, a3 answered 3, a4 none.
  await mkdir(join(S, "ledger"), { recursive: true });
  await writeFile(join(S, "ledger", "entries.jsonl"), [["a1", 1], ["a2", 2], ["a3", 3]].map(([by, n], i) => JSON.stringify({ v: 4, seq: i + 1, kind: "answer", by, authors: [by], section: `question:${n}` })).join("\n") + "\n");

  const est = await reviewsOf(F as never, P as never, S);
  assert.ok(est);
  assert.deepEqual(est.acks, { total: 11, no_objection: 11, objection: 0, unmapped: 0 });
  assert.equal(est.versions, 3);
  assert.equal(est.reviewed, 3);
  // Re-reviews: a1-a3 on v2, a1-a4 on v3 (a4's first was v2). Whole-report acks: the conclusions change each time, so none stands.
  assert.equal(est.reacks.recorded, 7);
  assert.equal(est.reacks.standing_whole, 0);
  // Scoped: on v2 a1 (1) and a3 (3) stand, a2 (2) is asked; on v3 a1 (1) and a2 (2) stand, a3 (3) is asked, a4 (none answered: whole) is asked.
  assert.equal(est.reacks.standing_scoped, 4);
  // Section reviews: 7 re-reviews of 5 sections recorded; the rule asks only what changed (2 each).
  assert.deepEqual(est.section_reviews, { recorded: 35, asked_whole: 14 });
  assert.deepEqual(est.rounds, [
    { version: 2, sections: 5, changed: 2, reacks: 3, asked_whole: 3, asked_scoped: 1 },
    { version: 3, sections: 5, changed: 2, reacks: 4, asked_whole: 4, asked_scoped: 2 },
  ]);
  assert.equal(est.echoes, 1);
});

/** Append a finish event as an earlier harness wrote it (no section fields), chained. */
async function appendRaw(S: string, d: Record<string, unknown>): Promise<number> {
  const text = await readFile(join(S, F.FINISH_LOG), "utf8").catch(() => "");
  const chain = L.verifyLeadChain(text);
  assert.ok(chain.ok);
  const prev = chain.head ?? "genesis";
  const draft = { v: 1, seq: chain.total + 1, at: new Date().toISOString(), ...d, prev };
  const e = { ...draft, hash: L.leadEventHash(draft as never, prev) };
  await mkdir(join(S, "leads"), { recursive: true });
  await appendFile(join(S, F.FINISH_LOG), `${JSON.stringify(e)}\n`);
  return e.seq;
}
