/**
 * The contract fixtures (docs/adr/0017, "Measuring a rule change"):
 * synthetic register histories under tests/fixtures/contract/, each read
 * again by scripts/replay.ts, and held to an expect.json written by hand from
 * the ADRs (never from the code's output). Under every fixture and every
 * stop policy it names: readiness, the answers check and the finish gate
 * agree on each question's disposition; a warning never holds; every custody
 * verdict the history holds verifies as a prefix of its registers; the
 * history itself is never written.
 *
 * The acceptance case, c10-partial-cascade, reconstructs the run s9722fa:
 * under the harness it ran with (3338e3c) readiness held its six partial
 * answers as best candidates while the answers check disposed them partial;
 * under this checkout they are disposed and readiness is ready. The old rule
 * is run, not asserted: 3338e3c's harness is extracted from this
 * repository's history with git archive into the test's temporary
 * directory (a fraction of a second; the repository's worktrees are not
 * touched), and the fixture is replayed with it. A checkout without that
 * history (a shallow clone, a tarball) skips that half and says why; the
 * expectation stays on record in expect.json's `rules`.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { after, test } from "node:test";
import { copyFile } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { copyRun, diffProjections, evaluateIn, extractCommit, replay, resolveRun, warningCode, type Delivery, type Projection, type StopPolicy, type Target } from "../scripts/replay.ts";

const ROOT = resolve(import.meta.dirname, "..");
const FIXTURES = join(ROOT, "tests", "fixtures", "contract");
const OLD_RULE = "3338e3c7715ce612f227cf5663c1e60d2ed4bd23";
/** The harness before the source-first review and the delta rule (docs/adr/0013, 0015): the parent of that change. */
const BEFORE_DELTA = "c34c6cba3cde48b2507a952ae14d2828cf051a66";
/** The histories written with the source-first review and the reverse sweep: the harness before them cannot read their sweep lines. */
const WRITTEN_WITH_DELTA = new Set(["evidence-stale-cleared", "late-evidence-hits", "review-source-first"]);
/** The harness before the premise register and the claim and open-part rows (docs/adr/0011 "Premises", 0013 "Claim and open-part rows"). */
const BEFORE_PREMISES = "be4e6a3cfe9f79825a223bd8b96d0d4d71682740";
/** The histories written with premises or rows: the harness before them has neither. */
const WRITTEN_WITH_PREMISES = new Set(["premise-given", "premise-admitted", "premise-scopes", "premise-held", "premise-rebutted", "premise-conditional", "parts-omitted", "accepted-excused"]);
/**
 * The histories written for the acceptance's one rule (the Fable review of
 * the limits branch, P1-1): the answers check before it held, on an accepted
 * question, defects readiness excused (premise_inconsistent, no_critic_act,
 * an answer resting on nothing checkable now). They read differently under
 * an older harness by design, and are held to their expect.json instead.
 */
const WRITTEN_FOR_ACCEPTANCE = new Set(["accepted-excused", "accepted-negative-held"]);

const scratch: string[] = [];
after(async () => {
  for (const d of scratch) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
});
async function tmp(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  scratch.push(d);
  return d;
}

type QuestionExpect = {
  disposition?: string | null;
  /** The finish gate's outcome for the question (answered, accepted, limited, …). */
  gate_outcome?: string;
  /** The answers check's open defects on the question, exactly. */
  defects?: string[];
  best_candidate?: boolean;
  readiness_holds?: boolean;
  readiness_includes?: string[];
  defects_include?: string[];
  warnings?: string[];
  /** The entries each warning names beside the answer, by code (ids). */
  warned?: Record<string, number[]>;
  report_best_candidate?: boolean;
};
type Expect = {
  questions: Record<string, QuestionExpect>;
  ready?: boolean;
  verdict?: { proceed: boolean; outcome?: string; failing?: string };
  last_check?: { proceed: boolean };
  done?: "proceeds" | "held";
  late?: Array<{ kind: string; by: string; tag: string | null }>;
  /** The coordinator's lease at the end: holder, generation, and after a resume its segment and how many posts it carries. */
  lease?: { holder: string; generation: number; segment?: number; carried?: number };
  /** The coordinator's prepares (docs/adr/0015, "Preparing the finish"): how many, and the last one. */
  prepared?: { count: number; last: { by: string; generation: number; late: number; current: boolean } | null };
  /** The typed resolutions in the finish register, and the batches they came in. */
  resolutions?: { count: number; batches: number };
  seals?: { verdicts: number; hold: number };
  agreement?: Array<{ section: string; kind: string }>;
  /** Where the warnings are delivered, act by act (replay --deliveries): the acts read, and each delivery in time order, held field by field as given. */
  deliveries?: { acts?: { record: number; review_offer: number; attest: number; lead_close: number }; delivered: Array<Partial<Delivery>> };
  /** The harness's own words of a question's warnings (replay --show-text): what they say, and what they never say. */
  warning_words?: Record<string, { includes?: string[]; excludes?: string[] }>;
  /** What the history itself holds: the acquisition asks opened, and the premise disputes (requests of kind premise). */
  history?: { acquisition_requests?: number; premise_requests?: number };
  /** The sources' broad extractions (docs/adr/0013): each source's outcome per capability, and the questions held or warned on them, with their sources. */
  preparation?: { sources: Record<string, string[]>; held: Record<string, string[]>; warned: Record<string, string[]> };
  /** The source-first review rule over the recorded established attests (docs/adr/0015): how many, and each it would cap by section and codes. */
  review_caps?: { established: number; capped: Array<{ section: string; codes: string[] }> };
  /** Each evidence addition's reverse sweep (docs/adr/0013): counts per question. */
  late_evidence?: Array<{ addition: number; synthetic: boolean; state: string; records: number; terms: number; questions: Array<{ section: string; objects: number; occurrences: number }> }>;
};
type Fixture = { name: string; case: string; design: string[]; policies: string[]; expect: Expect; rules?: Record<string, Expect & { why: string }> };

const fixtures: Fixture[] = readdirSync(FIXTURES, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => ({ name: d.name, ...(JSON.parse(readFileSync(join(FIXTURES, d.name, "expect.json"), "utf8")) as Omit<Fixture, "name">) }));

/** Every file of a history, by path and sha256: the replay must leave it as it was. */
function treeDigest(dir: string): string {
  const h = createHash("sha256");
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else h.update(`${relative(dir, p)}\0${createHash("sha256").update(readFileSync(p)).digest("hex")}\0${statSync(p).size}\n`);
    }
  };
  walk(dir);
  return h.digest("hex");
}

/** The projection held to what the design says, field by field; `where` names the fixture, rule and policy. */
function holdTo(p: Projection, e: Expect, where: string): void {
  for (const [section, want] of Object.entries(e.questions)) {
    const q = p.questions.find((x) => x.section === section);
    assert.ok(q, `${where}: ${section} is not in the projection (${p.questions.map((x) => x.section).join(", ")})`);
    const at = `${where} ${section}`;
    if ("disposition" in want) {
      assert.equal(q.gate?.disposition ?? null, want.disposition, `${at}: the gate's disposition`);
      if (q.check) assert.equal(q.check.disposition, want.disposition, `${at}: the answers check's disposition`);
    }
    if (want.gate_outcome !== undefined) assert.equal(q.gate?.outcome ?? null, want.gate_outcome, `${at}: the gate's outcome`);
    if (want.defects) assert.deepEqual(q.check?.defects ?? [], [...want.defects].sort(), `${at}: the answers check's open defects`);
    if (want.best_candidate !== undefined) assert.equal(q.check?.best_candidate ?? false, want.best_candidate, `${at}: held a best candidate`);
    if (want.readiness_holds !== undefined) assert.equal(q.readiness.length > 0, want.readiness_holds, `${at}: readiness holds it (${q.readiness.join(", ") || "nothing"})`);
    for (const c of want.readiness_includes ?? []) assert.ok(q.readiness.includes(c), `${at}: readiness holds it on ${c} (it holds ${q.readiness.join(", ") || "nothing"})`);
    for (const c of want.defects_include ?? []) assert.ok(q.check?.defects.includes(c), `${at}: the answers check's defect ${c} (it has ${q.check?.defects.join(", ") || "none"})`);
    if (want.disposition) assert.deepEqual(q.check?.defects ?? [], [], `${at}: a question with a disposition has no open defect`);
    if (want.warnings) assert.deepEqual(q.warnings, [...want.warnings].sort(), `${at}: its warnings`);
    for (const [code, entries] of Object.entries(want.warned ?? {})) assert.deepEqual(q.warned?.find((w) => w.code === code)?.entries, entries, `${at}: the entries ${code} names`);
    if (want.report_best_candidate !== undefined) assert.equal(q.report?.best_candidate ?? false, want.report_best_candidate, `${at}: the report says best candidate`);
  }
  if (e.ready !== undefined) assert.equal(p.readiness?.ready, e.ready, `${where}: ready (${JSON.stringify(p.readiness?.items)})`);
  if (e.verdict) {
    assert.equal(p.verdict?.proceed, e.verdict.proceed, `${where}: the verdict (${JSON.stringify(p.verdict)})`);
    if (e.verdict.outcome) assert.equal(p.verdict?.outcome, e.verdict.outcome, `${where}: the outcome`);
    if (e.verdict.failing) assert.equal(p.verdict?.failing, e.verdict.failing, `${where}: what the verdict holds on`);
  }
  if (e.last_check) assert.equal(p.finish?.last_check?.proceed, e.last_check.proceed, `${where}: the last check recorded`);
  if (e.done) assert.equal(p.finish?.done, e.done, `${where}: the done (${p.finish?.held_by.join(", ")})`);
  if (e.late) assert.deepEqual(p.finish?.late.map((x) => ({ kind: x.kind, by: x.by, tag: x.tag })), e.late, `${where}: what is late against the report`);
  if (e.lease) assert.deepEqual(p.finish?.lease, e.lease, `${where}: the coordinator's lease`);
  if (e.prepared) assert.deepEqual(p.finish?.prepared, e.prepared, `${where}: the prepares`);
  if (e.resolutions) assert.deepEqual(p.finish?.resolutions, e.resolutions, `${where}: the resolutions and their batches`);
  if (e.seals) assert.deepEqual({ verdicts: p.seals.verdicts, hold: p.seals.hold }, e.seals, `${where}: the custody verdicts (${JSON.stringify(p.seals.broken)})`);
  if (e.agreement) assert.deepEqual(p.agreement, e.agreement, `${where}: where readiness, the check and the gate disagree`);
  if (e.deliveries) {
    const d = p.deliveries;
    assert.ok(d, `${where}: the deliveries were read`);
    assert.equal(d.error, null, `${where}: ${d.error}`);
    if (e.deliveries.acts) assert.deepEqual(d.acts, e.deliveries.acts, `${where}: the acts read again`);
    const got = d.delivered.map(({ point, entry, lead, on, by, sections, warnings }) => ({ point, entry, lead, on, by, sections, warnings }));
    assert.equal(d.delivered.length, e.deliveries.delivered.length, `${where}: the deliveries (${JSON.stringify(got)})`);
    for (const [i, want] of e.deliveries.delivered.entries()) {
      for (const [k, v] of Object.entries(want)) assert.deepEqual(d.delivered[i]![k as keyof Delivery], v, `${where}: delivery ${i + 1}'s ${k} (${JSON.stringify(got)})`);
    }
  }
  if (e.preparation) {
    const pp = p.preparation;
    assert.ok(pp, `${where}: the checkout read the preparations`);
    assert.deepEqual(Object.fromEntries(pp.sources.map((x) => [x.source, x.capabilities.map((c) => c.outcome)])), e.preparation.sources, `${where}: each source's broad extraction`);
    assert.deepEqual(Object.fromEntries(pp.held.map((x) => [x.section, x.sources])), e.preparation.held, `${where}: what a preparation holds`);
    assert.deepEqual(Object.fromEntries(pp.warned.map((x) => [x.section, x.sources])), e.preparation.warned, `${where}: what a preparation warns of`);
  }
  if (e.review_caps) {
    assert.ok(p.review_caps, `${where}: the checkout read the review rule`);
    assert.deepEqual({ established: p.review_caps.established, capped: p.review_caps.capped.map((c) => ({ section: c.section, codes: c.codes })) }, e.review_caps, `${where}: what the review rule would cap`);
  }
  if (e.late_evidence) {
    assert.ok(p.late_evidence, `${where}: the checkout read the reverse sweeps`);
    assert.deepEqual(p.late_evidence.map(({ addition, synthetic, state, records, terms, questions }) => ({ addition, synthetic, state, records, terms, questions })), e.late_evidence, `${where}: the reverse sweeps`);
  }
  for (const [section, w] of Object.entries(e.warning_words ?? {})) {
    const lines = (p.text?.warnings ?? []).filter((l) => warningCode(l).section === section);
    assert.ok(lines.length, `${where} ${section}: its warnings' words were read (--show-text)`);
    for (const must of w.includes ?? []) assert.ok(lines.every((l) => l.includes(must)), `${where} ${section}: every warning says "${must}": ${lines.join(" | ")}`);
    for (const never of w.excludes ?? []) assert.ok(lines.every((l) => !l.includes(never)), `${where} ${section}: no warning says "${never}": ${lines.join(" | ")}`);
  }
}

const HERE: Target = { label: "this checkout", harness: ROOT, how: "this checkout", commit: null };

for (const f of fixtures) {
  test(`contract fixture ${f.name}: ${f.case}`, async () => {
    assert.ok(f.design.length, `${f.name}: its expect.json names the design it is written from`);
    const dir = join(FIXTURES, f.name, "run");
    const before = treeDigest(dir);
    const policies = f.policies.filter((p) => p !== "as run") as StopPolicy[];
    const r = await replay({ run: await resolveRun(dir), targets: [HERE], policies: policies.length ? policies : null, deliveries: Boolean(f.expect.deliveries), showText: Boolean(f.expect.warning_words), scratch: await tmp(`contract-${f.name}-`) });
    assert.equal(r.unchanged, true, "the history's registers are unchanged");
    assert.equal(treeDigest(dir), before, "no file of the history was written");
    assert.equal(r.evaluations.length, Math.max(1, policies.length));
    for (const e of r.evaluations) {
      const where = `${f.name} [${e.policy}]`;
      assert.ok(e.projection, `${where}: ${e.error}`);
      const p = e.projection;
      assert.deepEqual(p.errors, [], `${where}: every part evaluated`);
      if (policies.length) assert.equal(p.stop_policy, e.policy, `${where}: the copy's stop policy`);
      holdTo(p, f.expect, where);
      // The invariants, whatever the case.
      assert.deepEqual(p.agreement, [], `${where}: readiness, the answers check and the gate never disagree on a disposition`);
      assert.deepEqual(p.warnings_hold, [], `${where}: a warning never holds`);
      assert.equal(p.seals.hold, p.seals.verdicts, `${where}: every custody verdict verifies as a prefix (${JSON.stringify(p.seals.broken)})`);
      for (const q of p.questions) {
        if (!q.warnings.length) continue;
        assert.ok(!q.readiness.some((c) => q.warnings.includes(c)), `${where} ${q.section}: a warning is never a readiness item`);
      }
      // Finish status says every warning the answers check says, and nothing else.
      if (p.deliveries) {
        const status = p.deliveries.delivered.filter((x) => x.point === "finish_status").flatMap((x) => x.warnings.map((c) => `${x.sections[0]} ${c}`)).sort();
        assert.deepEqual(status, p.questions.flatMap((q) => q.warnings.map((c) => `${q.section} ${c}`)).sort(), `${where}: finish status and the answers check say the same warnings`);
      }
    }
    const opened = (kind: string) => {
      const log = join(dir, "requests", "requests.jsonl");
      return existsSync(log) ? readFileSync(log, "utf8").split("\n").filter((l) => l.trim() && (JSON.parse(l) as { ev?: string; kind?: string }).ev === "open" && (JSON.parse(l) as { kind?: string }).kind === kind).length : 0;
    };
    if (f.expect.history?.acquisition_requests !== undefined) assert.equal(opened("acquisition"), f.expect.history.acquisition_requests, `${f.name}: the acquisition asks the history holds`);
    if (f.expect.history?.premise_requests !== undefined) assert.equal(opened("premise"), f.expect.history.premise_requests, `${f.name}: the premise disputes the history holds`);
  });
}

test("a warning never holds: the warnings-only history is ready and its done proceeds, every question disposed, three warnings said", async () => {
  const f = fixtures.find((x) => x.name === "warnings-only")!;
  const r = await replay({ run: await resolveRun(join(FIXTURES, f.name, "run")), targets: [HERE], policies: ["operator", "cap-pause", "cap-stop"], scratch: await tmp("contract-warnings-") });
  for (const e of r.evaluations) {
    const p = e.projection!;
    assert.deepEqual(p.questions.flatMap((q) => q.warnings).sort(), ["lead_findings_uncited", "no_acquisition_ask", "partial_all_parts_established"], e.policy);
    assert.equal(p.readiness?.ready, true, e.policy);
    assert.equal(p.readiness?.warnings, 3, e.policy);
    assert.equal(p.verdict?.proceed, true, e.policy);
    assert.equal(p.finish?.done, "proceeds", e.policy);
    assert.ok(p.questions.every((q) => q.gate?.disposition), `${e.policy}: every question disposed`);
  }
});

test("acceptance: the c10 partial cascade is held under 3338e3c's readiness rule and disposed under this checkout's", async (t) => {
  const f = fixtures.find((x) => x.name === "c10-partial-cascade")!;
  const rule = f.rules?.["3338e3c"];
  assert.ok(rule, "the old rule's expectation is on record");
  if (spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${OLD_RULE}^{commit}`]).status !== 0) {
    t.skip(`3338e3c is not in this checkout's history (a shallow clone or an archive): the old rule is not run here; its expectation stays in ${relative(ROOT, join(FIXTURES, f.name, "expect.json"))}`);
    return;
  }
  const work = await tmp("contract-c10-");
  const old = join(work, "harness-3338e3c");
  await extractCommit(OLD_RULE, old);
  const r = await replay({ run: await resolveRun(join(FIXTURES, f.name, "run")), targets: [{ label: "3338e3c", harness: old, how: "3338e3c, extracted", commit: OLD_RULE }, HERE], scratch: work });
  const [a, b] = r.evaluations.map((e) => e.projection!);
  assert.ok(a && b, JSON.stringify(r.evaluations.map((e) => e.error)));
  holdTo(a, { ...f.expect, ...rule, questions: rule.questions, done: undefined, late: undefined, lease: undefined, prepared: undefined, resolutions: undefined }, "c10 under 3338e3c");
  holdTo(b, f.expect, "c10 under this checkout");
  // The difference is the rule, and only the rule: readiness and the report's words, never a disposition.
  const fields = new Set(r.differences!.map((d) => d.field));
  assert.deepEqual([...fields].sort(), ["disagreements", "readiness holds", "readiness items", "ready", "report says best candidate"]);
  for (const d of r.differences!.filter((x) => x.field === "readiness holds")) assert.deepEqual([d.a, d.b], ["best_candidate", "none"], d.section ?? "");
});

test("the delta rule, measured: the history recorded before it clears question 2 under c34c6cb's rule and holds it under this checkout's", async (t) => {
  const f = fixtures.find((x) => x.name === "evidence-stale-without-delta")!;
  const rule = f.rules?.["c34c6cb"];
  assert.ok(rule, "the old rule's expectation is on record");
  if (spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${BEFORE_DELTA}^{commit}`]).status !== 0) {
    t.skip(`c34c6cb is not in this checkout's history: the old rule is not run here; its expectation stays in ${relative(ROOT, join(FIXTURES, f.name, "expect.json"))}`);
    return;
  }
  const work = await tmp("contract-delta-");
  const old = join(work, "harness-c34c6cb");
  await extractCommit(BEFORE_DELTA, old);
  const r = await replay({ run: await resolveRun(join(FIXTURES, f.name, "run")), targets: [{ label: "c34c6cb", harness: old, how: "c34c6cb, extracted", commit: BEFORE_DELTA }, HERE], scratch: work });
  const [a, b] = r.evaluations.map((e) => e.projection!);
  assert.ok(a && b, JSON.stringify(r.evaluations.map((e) => e.error)));
  holdTo(a, { ...f.expect, ...rule, questions: rule.questions, late_evidence: undefined, done: undefined }, "without a delta, under c34c6cb");
  holdTo(b, f.expect, "without a delta, under this checkout");
  // The difference is question 2's, and the run's count of stale answers: nothing else.
  assert.deepEqual([...new Set(r.differences!.filter((d) => d.section).map((d) => d.section))], ["question:2"], JSON.stringify(r.differences));
  assert.deepEqual(r.differences!.filter((d) => !d.section).map((d) => d.field).sort(), ["readiness items"], JSON.stringify(r.differences));
});

test("old histories replayed unchanged: every fixture recorded before the source-first review and the delta reads the same under c34c6cb and this checkout, but where the delta rule applies", async (t) => {
  if (spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${BEFORE_DELTA}^{commit}`]).status !== 0) {
    t.skip("c34c6cb is not in this checkout's history (a shallow clone or an archive): the comparison is not run here");
    return;
  }
  const work = await tmp("contract-before-delta-");
  const old = join(work, "harness-c34c6cb");
  await extractCommit(BEFORE_DELTA, old);
  const names = fixtures.map((f) => f.name).filter((n) => !WRITTEN_WITH_DELTA.has(n) && !WRITTEN_WITH_PREMISES.has(n) && !WRITTEN_FOR_ACCEPTANCE.has(n));
  // One copy per checkout, each evaluated in one process per checkout (replay's own copy, and the custody anchor beside it).
  const copies = async (label: string) => {
    const out: string[] = [];
    for (const n of names) {
      const run = await resolveRun(join(FIXTURES, n, "run"));
      const dest = join(work, label, n, "runs", run.id);
      await copyRun(run.sandbox, dest);
      const anchor = join(dirname(run.sandbox), `${basename(run.sandbox)}.custody-anchor.json`);
      if (existsSync(anchor)) await copyFile(anchor, join(dirname(dest), `${run.id}.custody-anchor.json`));
      out.push(dest);
    }
    return out;
  };
  const before = await evaluateIn(old, await copies("before"), false);
  const now = await evaluateIn(ROOT, await copies("now"), false);
  for (const [i, n] of names.entries()) {
    const a = before[i]!;
    const b = now[i]!;
    assert.ok(!("error" in a) && !("error" in b), `${n}: ${JSON.stringify("error" in a ? a : b)}`);
    const diffs = diffProjections(a as Projection, b as Projection);
    if (n === "evidence-stale-without-delta") assert.deepEqual([...new Set(diffs.map((d) => d.section ?? d.field))].sort(), ["question:2", "readiness items"], `${n}: ${JSON.stringify(diffs)}`);
    else assert.deepEqual(diffs, [], `${n}: an old history reads the same (${JSON.stringify(diffs)})`);
  }
});

test("old histories replayed unchanged: every fixture recorded before the premise register and the claim and open-part rows reads the same under be4e6a3 and this checkout", async (t) => {
  if (spawnSync("git", ["-C", ROOT, "cat-file", "-e", `${BEFORE_PREMISES}^{commit}`]).status !== 0) {
    t.skip("be4e6a3 is not in this checkout's history (a shallow clone or an archive): the comparison is not run here");
    return;
  }
  const work = await tmp("contract-before-premises-");
  const old = join(work, "harness-be4e6a3");
  await extractCommit(BEFORE_PREMISES, old);
  const names = fixtures.map((f) => f.name).filter((n) => !WRITTEN_WITH_PREMISES.has(n) && !WRITTEN_FOR_ACCEPTANCE.has(n));
  const copies = async (label: string) => {
    const out: string[] = [];
    for (const n of names) {
      const run = await resolveRun(join(FIXTURES, n, "run"));
      const dest = join(work, label, n, "runs", run.id);
      await copyRun(run.sandbox, dest);
      const anchor = join(dirname(run.sandbox), `${basename(run.sandbox)}.custody-anchor.json`);
      if (existsSync(anchor)) await copyFile(anchor, join(dirname(dest), `${run.id}.custody-anchor.json`));
      out.push(dest);
    }
    return out;
  };
  const before = await evaluateIn(old, await copies("before"), false);
  const now = await evaluateIn(ROOT, await copies("now"), false);
  for (const [i, n] of names.entries()) {
    const a = before[i]!;
    const b = now[i]!;
    assert.ok(!("error" in a) && !("error" in b), `${n}: ${JSON.stringify("error" in a ? a : b)}`);
    assert.deepEqual(diffProjections(a as Projection, b as Projection), [], `${n}: an old history reads the same`);
  }
});
