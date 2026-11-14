/**
 * No answer to a seat is unbounded: the wall in the hub, and the finish
 * header that rides on every answer.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { boundItem, boundItems, boundRpcAnswer, HOST_UNBOUNDED_FNS, joinLedgerPages, ledgerPage, rpcAnswerMax, UNBOUNDED_FNS, type AnswerCut } from "../extensions/reply-bound.ts";
import { HANDOFF_LEADS_MAX, handoffLeads } from "../extensions/self-compact.ts";

test("an answer past the bound is cut to it, the whole kept and named; one within it goes as it is", async () => {
  const small = { ok: true, result: { text: "x".repeat(1000) } };
  assert.deepEqual((await boundRpcAnswer("leadsDigest", small, async () => { throw new Error("not called"); })).answer, small);
  const kept: string[] = [];
  const keep = async (text: string) => (kept.push(text), { path: "tool-output/s1a2b01/20261114-answer-x.text.log", bytes: text.length, sha256: "ab".repeat(32) });
  // A long text: the part that fits is answered, cut where it is long, with the counts beside it as they were.
  const huge = { ok: true, result: { text: "Finish: not ready (43): " + "job:j000011/tree/Windows/x.cat (its 12224 bytes would pass the budget); ".repeat(40_000), ready: false, items: 43 } };
  const r = await boundRpcAnswer("waitForSwarmChange", huge, keep);
  assert.equal(r.answer.ok, true);
  const size = Buffer.byteLength(JSON.stringify(r.answer));
  assert.ok(size <= 262144 && size > 200_000, `the answer is ${size} bytes: under the bound, and most of it`);
  const res = r.answer.result as { text: string; ready: boolean; items: number; answer_cut: AnswerCut };
  assert.deepEqual([res.ready, res.items], [false, 43]);
  assert.ok(res.text.startsWith("Finish: not ready (43): job:j000011/tree/Windows/x.cat"));
  assert.match(res.text, /… \[cut by the answer bound: the whole answer is tool-output\/s1a2b01\/20261114-answer-x\.text\.log\]$/);
  assert.equal(res.answer_cut.kept, "tool-output/s1a2b01/20261114-answer-x.text.log");
  assert.equal(res.answer_cut.bytes, Buffer.byteLength(JSON.stringify(huge)));
  assert.equal(res.answer_cut.max, 262144);
  assert.match(res.answer_cut.cut[0]!, /^text: \d+ of \d+ characters$/);
  assert.match(res.answer_cut.note, /the hub's answer to waitForSwarmChange was \d+ bytes, over the bound of 262144 on an answer: what did not fit is cut, kept whole at tool-output\/s1a2b01\/.*read it in pages.*fault of the harness/);
  assert.equal(kept.at(-1), JSON.stringify(huge), "the whole answer is kept");
  assert.deepEqual(r.cut, { fn: "waitForSwarmChange", bytes: res.answer_cut.bytes, max: 262144, kept: "tool-output/s1a2b01/20261114-answer-x.text.log" });
  // A long list: its first items, whole, and how many there were.
  const posts = { ok: true, result: { posts: Array.from({ length: 5000 }, (_, i) => ({ id: i + 1, from: "s1a2b02", body: `post ${i} ${"y".repeat(200)}` })), remaining: 0 } };
  const lp = (await boundRpcAnswer("readInbox", posts, keep)).answer.result as { posts: Array<{ id: number; body: string }>; remaining: number; answer_cut: AnswerCut };
  assert.ok(lp.posts.length > 500 && lp.posts.length < 5000, String(lp.posts.length));
  assert.deepEqual(lp.posts.map((p) => p.id), Array.from({ length: lp.posts.length }, (_, i) => i + 1), "the first posts, in order");
  assert.ok(lp.posts.every((p) => p.body.endsWith("y".repeat(200))), "each one whole");
  assert.deepEqual(lp.answer_cut.cut, [`posts: the first ${lp.posts.length} of 5000 items`]);
  assert.ok(Buffer.byteLength(JSON.stringify(lp)) <= 262144);
  // One item larger than the bound: the list keeps it, and its text is cut.
  const one = { ok: true, result: { posts: [{ id: 1, body: "z".repeat(600_000) }, { id: 2, body: "z".repeat(600_000) }] } };
  const lo = (await boundRpcAnswer("readInbox", one, keep)).answer.result as { posts: Array<{ id: number; body: string }>; answer_cut: AnswerCut };
  assert.deepEqual(lo.posts.map((p) => p.id), [1]);
  assert.ok(lo.posts[0]!.body.length > 200_000 && lo.posts[0]!.body.endsWith("]"));
  assert.ok(Buffer.byteLength(JSON.stringify(lo)) <= 262144);
  // A text answer, and a refusal too long to send.
  const text = (await boundRpcAnswer("leadsDigest", { ok: true, result: "w".repeat(400_000) }, keep)).answer.result as string;
  assert.ok(Buffer.byteLength(text) <= 262144 && text.startsWith("wwww") && /the whole answer is tool-output/.test(text) && /fault of the harness/.test(text));
  const err = (await boundRpcAnswer("recordEntry", { ok: false, error: "v".repeat(400_000) }, keep)).answer;
  assert.equal(err.ok, false);
  assert.ok(Buffer.byteLength(JSON.stringify(err)) <= 262144 && /fault of the harness/.test(err.error ?? ""));
  const unkept = await boundRpcAnswer("readInbox", huge, async () => ({ write_error: "disk full" }));
  assert.equal(unkept.answer.ok, true);
  assert.match((unkept.answer.result as { answer_cut: AnswerCut }).answer_cut.note, /the whole could not be kept \(disk full\)/);
  assert.match((unkept.answer.result as { text: string }).text, /\[cut by the answer bound\]$/);
});

test("what leaves is always within the wall: many long texts are cut alike in one pass, a deep answer is cut, and an answer whose shape alone is past it is a stub that names the kept file", async () => {
  const kept: string[] = [];
  const keep = async (text: string) => (kept.push(text), { path: "tool-output/a0/20261114-answer-leadsView.text.log", bytes: Buffer.byteLength(text), sha256: "cd".repeat(32) });
  const sent = (a: unknown) => Buffer.byteLength(JSON.stringify(a));
  // Two hundred texts of 10 KB each (2 MB): cutting one text a round gave up after 64 rounds and sent 1.37 MB, saying it had cut.
  const wide: Record<string, unknown> = { state: "open", count: 200 };
  for (let i = 0; i < 200; i++) wide[`f${i}`] = `field ${i} ` + "x".repeat(10_000);
  const r = await boundRpcAnswer("leadsView", { ok: true, result: wide }, keep);
  assert.ok(sent(r.answer) <= 262144, `${sent(r.answer)} bytes sent`);
  const res = r.answer.result as Record<string, string | number | AnswerCut> & { answer_cut: AnswerCut };
  assert.deepEqual([res.state, res.count], ["open", 200], "the short fields stay as they were");
  for (let i = 0; i < 200; i++) assert.ok(String(res[`f${i}`]).startsWith(`field ${i} xxx`) && String(res[`f${i}`]).endsWith("[cut by the answer bound: the whole answer is tool-output/a0/20261114-answer-leadsView.text.log]"), `f${i} is cut with the mark`);
  const lens = Array.from({ length: 200 }, (_, i) => String(res[`f${i}`]).length);
  assert.ok(Math.min(...lens) > 500, `every text keeps a part of itself (the shortest is ${Math.min(...lens)} characters)`);
  assert.match(res.answer_cut.note, /what did not fit is cut, kept whole at tool-output\/a0\//);
  assert.ok(res.answer_cut.cut.some((c) => /^every text longer than \d+ characters \(\d+ of them\): its first \d+ characters$/.test(c)), JSON.stringify(res.answer_cut.cut));
  assert.equal(kept.at(-1), JSON.stringify({ ok: true, result: wide }), "the whole is kept");
  // A deep answer: three hundred levels, each with a text of 5 KB.
  let deep: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < 300; i++) deep = { level: i, text: `level ${i} ` + "d".repeat(5000), inner: deep };
  const d = await boundRpcAnswer("leadsView", { ok: true, result: deep }, keep);
  assert.ok(sent(d.answer) <= 262144, `${sent(d.answer)} bytes sent`);
  let at = d.answer.result as Record<string, unknown>;
  for (let i = 299; i >= 0; i--) {
    assert.equal(at.level, i, "every level is there, with its number");
    at = at.inner as Record<string, unknown>;
  }
  assert.equal(at.leaf, true);
  // Lists of lists of short texts: no text is long enough to cut, so the lists are.
  const lists = { rows: Array.from({ length: 400 }, (_, i) => ({ id: i, tags: Array.from({ length: 60 }, (_, k) => `tag-${i}-${k}`) })) };
  const l = await boundRpcAnswer("leadsView", { ok: true, result: lists }, keep);
  assert.ok(sent(l.answer) <= 262144, `${sent(l.answer)} bytes sent`);
  assert.ok((l.answer.result as { rows: unknown[] }).rows.length >= 1);
  // Sixty thousand short fields: nothing in it can be cut, and none of it is sent; a stub says so and names the kept file.
  const flat: Record<string, string> = {};
  for (let i = 0; i < 60_000; i++) flat[`k${i}`] = `v${i}`;
  const f = await boundRpcAnswer("leadsView", { ok: true, result: flat }, keep, 64 * 1024);
  assert.ok(sent(f.answer) <= 2048, `the stub is ${sent(f.answer)} bytes`);
  const stub = (f.answer.result as { answer_cut: AnswerCut }).answer_cut;
  assert.deepEqual(Object.keys(f.answer.result as object), ["answer_cut"]);
  assert.equal(stub.kept, "tool-output/a0/20261114-answer-leadsView.text.log");
  assert.match(stub.note, /none of it is sent: even with every text and list in it cut, its shape alone is past the bound; kept whole at tool-output\/a0\//);
  assert.doesNotMatch(stub.note, /what did not fit is cut/, "the stub does not say it sent a part");
  assert.deepEqual(f.cut, { fn: "leadsView", bytes: Buffer.byteLength(JSON.stringify({ ok: true, result: flat })), max: 64 * 1024, kept: "tool-output/a0/20261114-answer-leadsView.text.log" });
  // A list of such objects cut to one is still past it: refused, never an empty list that looks whole.
  const listed = await boundRpcAnswer("listClaims", { ok: true, result: [flat, flat] }, keep, 64 * 1024);
  assert.equal(listed.answer.ok, false);
  assert.match(String(listed.answer.error), /none of it is sent/);
  // Every size of bound, on every shape: within it.
  for (const max of [16 * 1024, 64 * 1024, 262144]) {
    for (const body of [wide, deep, lists, flat, "t".repeat(900_000)]) {
      const b = await boundRpcAnswer("leadsView", { ok: true, result: body }, keep, max);
      assert.ok(sent(b.answer) <= max, `${sent(b.answer)} bytes over a bound of ${max}`);
    }
    const e = await boundRpcAnswer("recordEntry", { ok: false, error: "e".repeat(900_000) }, keep, max);
    assert.ok(sent(e.answer) <= max);
  }
});

test("only the answers code reads whole (a lookup, a window it pages itself) are exempt; a diff, a restore, a job's answer and a fetch are held to the wall; the bound can be set", async () => {
  const big = { ok: true, result: { diff: "y".repeat(600_000) } };
  assert.deepEqual([...UNBOUNDED_FNS].sort(), ["listFileHistory", "listForgedTools"]);
  for (const fn of UNBOUNDED_FNS) assert.deepEqual((await boundRpcAnswer(fn, big, async () => { throw new Error("not called"); })).answer, big);
  // The ledger's window is paged by the hub within the wall (ledgerPage, tests/ledger-page.test.ts), and the wall stands behind it; in a
  // host run nothing crosses a wire and the ledger tool pages the window itself.
  assert.deepEqual([...HOST_UNBOUNDED_FNS].sort(), ["listFileHistory", "listForgedTools", "listLedger"]);
  const window = Array.from({ length: 3000 }, (_, i) => ({ seq: i + 1, value: "w".repeat(300) }));
  const page = ledgerPage(window) as { ledger_page: true; entries: Array<{ seq: number }>; window: number; remaining: number; next: number; note: string };
  assert.equal(page.ledger_page, true);
  assert.ok(Buffer.byteLength(JSON.stringify({ ok: true, result: page })) <= 262144);
  assert.deepEqual([page.window, page.entries.length + page.remaining, page.next], [3000, 3000, page.entries.length + 1]);
  assert.match(page.note, /held back to keep the answer within 262144 bytes: ask again with the cursor \{from: \d+\}/);
  assert.deepEqual(ledgerPage(window.slice(0, 10)), window.slice(0, 10), "a window within the wall is answered as it is");
  // Joined from pages, also when entries are recorded between them: the window as it was at the first page, each once.
  let ledger = [...window];
  const joined = await joinLedgerPages<{ seq: number }>(async (cursor) => {
    const got = ledgerPage(cursor ? ledger.filter((e) => e.seq >= cursor.from) : ledger);
    ledger = [...ledger, { seq: ledger.length + 1, value: "late" }];
    return got;
  });
  assert.deepEqual(joined.map((e) => e.seq), window.map((e) => e.seq));
  for (const fn of ["listLedger", "fileDiff", "restoreFileVersion", "jobStatus", "jobSubmit", "netFetch", "runFinishLine"]) {
    const r = await boundRpcAnswer(fn, big, async (t) => ({ path: "p", bytes: t.length, sha256: "s" }));
    assert.equal(r.answer.ok, true, fn);
    assert.ok(Buffer.byteLength(JSON.stringify(r.answer)) <= 262144, fn);
    assert.equal((r.answer.result as { answer_cut: AnswerCut }).answer_cut.fn, fn);
  }
  assert.equal(rpcAnswerMax({}), 262144);
  assert.equal(rpcAnswerMax({ SWARM_RPC_ANSWER_MAX_BYTES: "1048576" }), 1048576);
  assert.equal(rpcAnswerMax({ SWARM_RPC_ANSWER_MAX_BYTES: "12" }), 262144, "a bound too small to answer anything is not taken");
});

test("a host run's answers meet the same wall where the seat's own process runs the call, the whole kept among its own outputs", async () => {
  const { mkdtemp, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const P = await import("../extensions/protocol.ts");
  const board = await import("../extensions/board.ts");
  const base = await mkdtemp(join(tmpdir(), "reply-host-"));
  const S = join(base, "run");
  const saved = { socket: process.env.SWARM_BOARD_SOCKET, max: process.env.SWARM_RPC_ANSWER_MAX_BYTES };
  try {
    delete process.env.SWARM_BOARD_SOCKET;
    process.env.SWARM_RPC_ANSWER_MAX_BYTES = String(64 * 1024);
    await P.initSandbox(S, { swarmId: "rh1", agentIds: ["a0", "a1"], capUsd: 1, wallClockMinutes: 30 });
    const a0 = { sandboxRoot: S, agentId: "a0" };
    const a1 = { sandboxRoot: S, agentId: "a1" };
    for (let i = 0; i < 60; i++) await P.postMessage(a1, { tag: "result", body: `post ${i}: ${"q".repeat(3000)}` });
    const inbox = (await board.readInbox(a0, { pageChars: 0 })) as Awaited<ReturnType<typeof P.readInbox>> & { answer_cut?: AnswerCut };
    assert.ok(inbox.answer_cut, "the answer was cut");
    assert.ok(Buffer.byteLength(JSON.stringify(inbox)) <= 64 * 1024);
    assert.ok(inbox.posts.length > 0 && inbox.posts.length < 60);
    assert.match(inbox.answer_cut.kept!, /^tool-output\/a0\/.*-answer-readInbox-.*\.text\.log$/);
    const whole = JSON.parse(await readFile(join(S, inbox.answer_cut.kept!), "utf8")) as { ok: boolean; result: { posts: unknown[] } };
    assert.equal(whole.result.posts.length, 60, "the whole answer, every post, is in the file it names");
    // Small answers are as they were: the same inbox again, read.
    const small = await board.readInbox(a0, { pageChars: 0 });
    assert.equal((small as { answer_cut?: unknown }).answer_cut, undefined);
    assert.equal(small.posts.length, 0);
  } finally {
    if (saved.socket === undefined) delete process.env.SWARM_BOARD_SOCKET;
    else process.env.SWARM_BOARD_SOCKET = saved.socket;
    if (saved.max === undefined) delete process.env.SWARM_RPC_ANSWER_MAX_BYTES;
    else process.env.SWARM_RPC_ANSWER_MAX_BYTES = saved.max;
    await rm(base, { recursive: true, force: true });
  }
});

test("the finish header's items: the caller's own first, each cut, the rest counted (the run s5d814f's 38 MB item)", () => {
  const monster = `answer #12 (question:5) rests on coverage record E-93, whose store sweep is partial: not searched: ${"job:j000011/tree/a.cat (why); ".repeat(137_703)}`;
  const items = [monster, 'L-3 "nonce" is active (held by s5d814f05) with no disposition', 'L-9 "media" is active (held by s5d814f02) with no disposition', ...Array.from({ length: 40 }, (_, i) => `job j0000${i} has no interpretation yet`)];
  const b = boundItems(items, (i) => i.includes("s5d814f02"));
  assert.ok(b.text.length < 3200, `the header's item text is ${b.text.length} characters`);
  assert.ok(b.text.startsWith('L-9 "media" is active (held by s5d814f02)'), "the caller's own item comes first");
  assert.match(b.text, /and 37 more \(finish status lists every one\)$/);
  assert.deepEqual([b.total, b.own, b.shown], [43, 1, 6]);
  assert.match(boundItem(monster), /… \(\d+ characters; whole in finish status\)$/);
  assert.equal(boundItem("short"), "short");
  assert.equal(boundItems([], () => false).text, "");
});

test("a hand-off carries the seat's own part of the lead register and the finish as a count, within 2,000 characters", () => {
  const digest = [
    "Leads: 0 open, 7 active, 0 blocked, 8 closed (leads for the whole register).",
    "Open, unheld, by priority: none.",
    "Yours: L-9 active.",
    "Blocked on you: none.",
    "Awaiting your interpretation: j000309; j000313.",
    "Questions nobody holds a lead for, with no answer yet: question:11.",
    `Parked (held, no job and no act on it): ${"L-6 (s5d814f07, 118 min); ".repeat(300)}`,
    `Finish: not ready (93, 2 of them yours): ${"job j000001 has no interpretation yet; ".repeat(5000)}; nobody coordinates it yet.`,
  ].join("\n");
  const h = handoffLeads(digest);
  assert.ok(h.length <= HANDOFF_LEADS_MAX, `${h.length} characters`);
  assert.match(h, /^Leads: 0 open/);
  assert.match(h, /Yours: L-9 active\./);
  assert.match(h, /Awaiting your interpretation: j000309; j000313\./);
  assert.match(h, /Finish: not ready \(93, 2 of them yours\); finish status lists what holds it\.$/);
  assert.doesNotMatch(h, /Parked|Open, unheld|no interpretation yet/);
  assert.ok(handoffLeads(`Yours: ${"L-1 active; ".repeat(2000)}`).length <= HANDOFF_LEADS_MAX);
  assert.equal(handoffLeads("Finish: READY by the registers; s1 coordinates it."), "Finish: READY by the registers; finish status lists what holds it.");
});

test("a tool-supply post names the programs and counts the libraries (a bundle's post was 25,000 characters)", async () => {
  const { postFileList, POST_FILES_MAX } = await import("../scripts/material.ts");
  const sha = "a".repeat(64);
  const files = [
    ...Array.from({ length: 80 }, (_, i) => ({ path: `lib/lib${String(i).padStart(2, "0")}.so.1`, bytes: 1000 + i, sha256: sha })),
    { path: "bin/zbarimg", bytes: 50_000, sha256: sha },
    { path: "PACKAGES.txt", bytes: 300, sha256: sha },
  ];
  const text = postFileList("mat-0002", files);
  assert.ok(text.startsWith("bin/zbarimg (50000 bytes, sha256 "), "the program comes first");
  assert.match(text, new RegExp(`and ${files.length - POST_FILES_MAX} more \\(store/imports/mat-0002/manifest\\.json lists every file with its sha256\\)$`));
  assert.ok(text.length < 1000, `${text.length} characters`);
  assert.equal(postFileList("mat-0001", [files[80]!]), `bin/zbarimg (50000 bytes, sha256 ${sha})`);
});
