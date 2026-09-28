/**
 * A release and the question register (docs/adr/0016): release.json binds
 * the register's length and head as custody sealed them, what those events
 * say (the questions by origin, every person who asked or acted, claimed or
 * signed) and what was recorded after; verification holds the chain here to
 * it and recomputes what it says. Custody and releases hold the operator
 * requests' chain as they hold the others: the operator's acts after the
 * stop follow the sealed line and are named; a sealed line changed is not.
 */
import assert from "node:assert/strict";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import * as L from "../extensions/leads.ts";
import * as Q from "../extensions/questions.ts";
import { custodyAnchorPath, sealPrefix, takeCustody, verifyCustody } from "../scripts/custody.ts";
import { draftRelease, runContext } from "../scripts/release.ts";
import { questionsBinding, readReleases, runLayout, verifyReleases } from "../scripts/release-record.ts";
import { reviewsPath } from "../scripts/review.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";

after(async () => {
  await cleanUp();
});

const eve: Q.Actor = { kind: "human", role: "examiner", person: "eve", name: "EVE", enrolled: true, os_user: "tester", host: "lab", via: "cli", identity: "claimed" };

/** A chain of lines hashed as the lead register hashes them (the requests' chain uses the same code). */
function chained(prev: string | null, seq0: number, bodies: Array<Record<string, unknown>>): { lines: string[]; head: string } {
  let p = prev ?? "genesis";
  const lines: string[] = [];
  bodies.forEach((b, i) => {
    const e = { v: 1, seq: seq0 + i + 1, at: new Date().toISOString(), by: "operator", ev: "note", ...b, prev: p } as unknown as L.LeadEvent;
    const hash = L.leadEventHash(e, p);
    lines.push(JSON.stringify({ ...e, hash }));
    p = hash;
  });
  return { lines, head: p };
}

test("release.json binds the question register as custody sealed it, says what it holds, and verification holds the chain to it", async () => {
  const r = await stoppedRun({ id: "sqrel" });
  await writeFile(join(r.root, "team.json"), JSON.stringify({ swarm_id: r.id, n: 1, agents: [{ id: "a0", role: "worker" }] }));
  // The goal as a kickoff renders it: three numbered questions and the check that names them.
  await writeFile(join(r.root, "SWARM.md"), ["# Contract", "", "## Goal", "", "### Questions", "", "1. How did the intruder get in?", "2. What did they run?", "3. What did they take?", "", "## Checks", "", '- `node x "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3`', ""].join("\n"));
  await Q.seedRegister(r.root);
  const opened = await Q.act(r.root, eve, "open", { text: "Was the upload handler reached from outside?", why: "the examiner needs the entry point", materiality: "material" });
  assert.ok(opened.ok, (opened as { reason?: string }).reason);
  const custody = await takeCustody(r.root, { runsDir: r.runs });
  assert.ok(custody.seal?.questions?.lines, "custody seals the question register");
  const ctx = runContext(r.root, { run: r.id, runsDir: r.runs });
  await draftRelease(ctx, { home: r.home, say: () => undefined });
  const rel = readReleases(r.root).at(-1)!;
  const q = rel.record!.questions!;
  assert.equal(q.lines, custody.seal!.questions!.lines);
  assert.equal(q.head, custody.seal!.questions!.head);
  assert.equal(q.sealed, true);
  assert.deepEqual(q.by_origin, { goal: 3, analyst: 1 });
  assert.deepEqual(q.analysts, [{ person: "eve", name: "EVE", role: "examiner", enrolled: true, identity: "claimed", asked: ["Q-4"], acts: 1, signed_acts: 0 }]);
  assert.deepEqual(q.post_seal.lines, 0);
  const layout = () => runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
  const good = await verifyReleases(layout());
  assert.equal(good.ok, true, good.lines.join("\n"));
  assert.match(good.lines.join("\n"), /binds the question register's first \d+ events \(3 goal, 1 analyst; asked or acted on by eve \(claimed\)\)/);

  // A question asked after the verdict: the part the release binds is intact, and it says so.
  const text = await readFile(join(r.root, "questions", "questions.jsonl"), "utf8");
  const later = await Q.act(r.root, eve, "open", { text: "Which account ran the shell?", why: "after the stop", materiality: "material" });
  assert.ok(later.ok);
  const grown = await verifyReleases(layout());
  assert.equal(grown.ok, true, grown.lines.join("\n"));
  assert.match(grown.lines.join("\n"), /the question register it binds \(\d+ events\) is a prefix of the question register here/);
  // Rewritten in place, its hashes kept: the chain breaks, and the release does not verify.
  await writeFile(join(r.root, "questions", "questions.jsonl"), text.replace("the examiner needs the entry point", "someone else's reason"));
  const rewritten = await verifyReleases(layout());
  assert.equal(rewritten.ok, false);
  assert.match(rewritten.lines.join("\n"), /the question register's chain here is broken/);
  // Cut back past what it binds.
  await writeFile(join(r.root, "questions", "questions.jsonl"), `${text.split("\n").filter(Boolean).slice(0, -1).join("\n")}\n`);
  const cut = await verifyReleases(layout());
  assert.equal(cut.ok, false);
  assert.match(cut.lines.join("\n"), /the question register here has \d+ events, fewer than the \d+ it binds/);
  await writeFile(join(r.root, "questions", "questions.jsonl"), text);
  assert.equal((await verifyReleases(layout())).ok, true);
});

test("the binding: questions by origin and every person who acted, a signed act said so, and what came after the seal", () => {
  const ev = (seq: number, ev: string, q: string | undefined, origin: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ seq, ev, ...(q ? { q } : {}), at: `2026-09-28T10:00:0${seq}Z`, hash: `h${seq}`, origin, ...extra });
  const events = [
    ev(1, "open", "Q-1", { kind: "goal" }),
    ev(2, "seed", undefined, { kind: "goal" }),
    ev(3, "open", "Q-2", { kind: "analyst", person: "ana", name: "ANA", role: "analyst", enrolled: true, identity: "signed" }, { signature: { person: "ana" } }),
    ev(4, "amend", "Q-2", { kind: "analyst", person: "ana", role: "analyst", enrolled: true, identity: "claimed" }),
    ev(5, "open", "Q-3", { kind: "agent", agent: "a1" }),
    ev(6, "open", "Q-4", { kind: "observer", person: "obs", role: "observer", enrolled: false, identity: "claimed" }),
  ] as Parameters<typeof questionsBinding>[0];
  const b = questionsBinding(events, { lines: 5, head: "h5" });
  assert.deepEqual(b.by_origin, { goal: 1, analyst: 1, agent: 1 });
  assert.deepEqual(b.analysts, [{ person: "ana", name: "ANA", role: "analyst", enrolled: true, identity: "signed", asked: ["Q-2"], acts: 2, signed_acts: 1 }]);
  assert.deepEqual(b.post_seal.events, [{ seq: 6, ev: "open", q: "Q-4", at: "2026-09-28T10:00:06Z" }]);
  const never = questionsBinding([], undefined, { goal: 3 });
  assert.deepEqual([never.lines, never.head, never.sealed, never.by_origin], [0, null, false, { goal: 3 }]);
  assert.match(never.note, /never written/);
});

test("custody and releases hold the operator requests: the operator's acts after the stop are named; a sealed line changed is a drift", async () => {
  const r = await stoppedRun({ id: "sreqrel" });
  await writeFile(join(r.root, "team.json"), JSON.stringify({ swarm_id: r.id, n: 1, agents: [{ id: "a0", role: "worker" }] }));
  await mkdir(join(r.root, "requests"), { recursive: true });
  const first = chained(null, 0, [{ ev: "request", request: "R-1", kind: "decision" }, { ev: "notified", request: "R-1" }]);
  await writeFile(join(r.root, "requests", "requests.jsonl"), `${first.lines.join("\n")}\n`);
  const custody = await takeCustody(r.root, { runsDir: r.runs });
  assert.equal(custody.seal?.requests?.lines, 2);
  const ctx = runContext(r.root, { run: r.id, runsDir: r.runs });
  await draftRelease(ctx, { home: r.home, say: () => undefined });
  const layout = () => runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
  assert.equal((await verifyReleases(layout())).ok, true);
  // The operator answers the request after the stop.
  const more = chained(first.head, 2, [{ ev: "answered", request: "R-1" }]);
  await appendFile(join(r.root, "requests", "requests.jsonl"), `${more.lines.join("\n")}\n`);
  const v = await verifyCustody(r.root, { runsDir: r.runs });
  assert.ok(v.seal_after.some((x) => /operator requests: 1 event\(s\) after the seal/.test(x)), JSON.stringify(v.seal_after));
  assert.ok(!v.seal_drift.some((d) => d.what === "operator requests"));
  const grown = await verifyReleases(layout());
  assert.equal(grown.ok, true, grown.lines.join("\n"));
  assert.match(grown.lines.join("\n"), /the operator requests it binds \(2 events\) is a prefix of the operator requests here \(3\)/);
  // A sealed line rewritten, chained anew: a drift, and the release does not verify.
  const forged = chained(null, 0, [{ ev: "request", request: "R-1", kind: "clarification" }, { ev: "notified", request: "R-1" }]);
  await writeFile(join(r.root, "requests", "requests.jsonl"), `${forged.lines.join("\n")}\n`);
  const drifted = await verifyCustody(r.root, { runsDir: r.runs });
  assert.ok(drifted.seal_drift.some((d) => d.what === "operator requests"), JSON.stringify(drifted.seal_drift));
  assert.equal((await verifyReleases(layout())).ok, false);
  // An earlier verdict held as a prefix names the requests too.
  const p = sealPrefix(custody.seal, { trace: "", ledger: "", attestations: "", disputes: "", leads: "", questions: "", grants: "", fetches: "", requests: `${first.lines.join("\n")}\n${more.lines.join("\n")}\n`, journal: null, gateway: null });
  assert.ok(p.held.includes("the operator requests (2)"), JSON.stringify(p));
  // Finding 10: a sealed request's body changed but its stored hash and prev
  // fields left in place. A prefix check that recomputes the chain catches it;
  // one that trusted the stored head would not.
  const tampered = JSON.parse(first.lines[0]);
  tampered.kind = "clarification";
  const keptHashes = sealPrefix(custody.seal, { trace: "", ledger: "", attestations: "", disputes: "", leads: "", questions: "", grants: "", fetches: "", requests: `${JSON.stringify(tampered)}\n${first.lines[1]}\n`, journal: null, gateway: null });
  assert.ok(keptHashes.broken.some((b) => /operator requests/.test(b)), JSON.stringify(keptHashes.broken));
});
