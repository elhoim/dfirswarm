/**
 * A recipe that can list before it digests (recipe.json `phases: ["listing"]`)
 * is run twice at kickoff: the listing alone first, told in RECIPE_PHASE, then
 * whole (scripts/job-service.ts queueKickoffRecipes, LISTING_PHASE). The
 * listing's post says what it is and what follows, so nobody walks the image
 * for a list of their own; a phase a recipe does not declare is refused; a
 * phase is not the recipe whole to the reuse key.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import * as P from "../extensions/protocol.ts";
import { JobService, LISTING_PHASE, phaseWords, type JobRecord } from "../scripts/job-service.ts";
import { localWorker } from "./job-service-worker.ts";
import { ad1Image, type Ad1Node } from "./ad1-fixture.ts";
import { createHash } from "node:crypto";

const ROOT = join(import.meta.dirname, "..");
const made: string[] = [];
after(() => {
  for (const d of made) {
    spawnSync("chmod", ["-R", "u+w", d]);
    rmSync(d, { recursive: true, force: true });
  }
});

const RUN_PY = `import json, os, sys
cmd = sys.argv[1]
t = json.loads(sys.argv[3]) if not os.path.isfile(sys.argv[3]) else json.load(open(sys.argv[3]))
head = open(t["paths"][0], "rb").read(16)
if cmd == "detect":
    ok = head.startswith(b"BOX")
    print(json.dumps({"applies": ok, "why": "a box" if ok else "not a box"}))
    sys.exit(0 if ok else 1)
out = sys.argv[sys.argv.index("--out") + 1]
os.makedirs(out, exist_ok=True)
phase = os.environ.get("RECIPE_PHASE") or "all"
open(os.path.join(out, "members.tsv"), "w").write("n\\tpath\\tsha256\\n1\\ta.txt\\t%s\\n" % ("" if phase == "listing" else "ab" * 32))
open(os.path.join(out, "index.tsv"), "w").write("members.tsv\\tthe members\\n")
cov = {"status": "partial" if phase == "listing" else "complete", "covered": "the box", "not_covered": "nothing", "limits_hit": [], "errors": [], "phase_seen": phase}
json.dump(cov, open(os.path.join(out, "coverage.json"), "w"))
`;

async function boxRun(phases: string[] | undefined) {
  const base = await mkdtemp(join(tmpdir(), "catalog-phases-"));
  made.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "phase1", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: "## Goal\n\nExamine the box.\n\n### Questions\n\n1. What is in the box?\n" });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "a.box"), "BOX one");
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/a.box", sha256: "0".repeat(64), bytes: 7 }] }));
  const pack = join(base, "bpack");
  mkdirSync(join(pack, "recipes", "items"), { recursive: true });
  writeFileSync(join(pack, "recipes", "items", "run.py"), RUN_PY);
  writeFileSync(join(pack, "recipes", "items", "recipe.json"), JSON.stringify({ id: "items", version: "1.0.0", description: "the members of a box", object: "box", order: 10, min_bytes: 1, runtime: "python3", entry: "run.py", limits: { seconds: 60 }, outputs: ["members.tsv"], covers: "the box", purpose: "inventory", auto: ["kickoff"], ...(phases ? { phases } : {}) }));
  writeFileSync(join(pack, "pack.json"), JSON.stringify({ id: "bpack", name: "bpack", version: "1.0.0" }));
  const census = spawnSync("python3", [join(ROOT, "scripts", "evidence_catalog.py"), S, "--plan-only", "--recipes-from", pack], { encoding: "utf8" });
  assert.equal(census.status, 0, census.stderr);
  const posts: Array<[string, string]> = [];
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [pack], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async (to, body) => void posts.push([to, body]), identity: async (a) => ({ name: `${a}-name` }) });
  return { S, svc, posts };
}

async function eventually(ok: () => boolean, what: string, ms = 30000): Promise<void> {
  const until = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > until) assert.fail(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}
const done = (j: JobRecord) => ["committed", "failed", "cancelled"].includes(j.state) && (j.state !== "committed" || Boolean(j.generation));

test("a recipe that declares the listing phase is run twice at kickoff: the listing first, then whole", async () => {
  const { S, svc, posts } = await boxRun(["listing"]);
  await svc.start();
  await eventually(() => svc.jobs.size === 2 && [...svc.jobs.values()].every(done), "both kickoff jobs catalogued");
  const jobs = [...svc.jobs.values()].sort((a, b) => a.id.localeCompare(b.id));
  assert.deepEqual(jobs.map((j) => j.spec.phase ?? "whole"), ["listing", "whole"], "the listing is submitted first");
  const seen = (j: JobRecord) => (JSON.parse(readFileSync(join(S, "catalog", "gen", j.generation!, "coverage.json"), "utf8")) as { phase_seen: string }).phase_seen;
  assert.equal(seen(jobs[0]!), "listing", "the recipe was told its phase in RECIPE_PHASE");
  assert.equal(seen(jobs[1]!), "all", "the whole run is told none");
  assert.notEqual(jobs[0]!.generation, jobs[1]!.generation);
  assert.equal(jobs[0]!.spec.alias, undefined, "the alias is the whole catalogue's");
  const listingPost = posts.find(([to, b]) => to === "all" && b.includes(jobs[0]!.generation!));
  assert.ok(listingPost, JSON.stringify(posts));
  assert.match(listingPost![1], /the listing \(every member's path, size and times/);
  assert.match(listingPost![1], /the whole catalogue follows as a later revision/);
  const wholePost = posts.find(([to, b]) => to === "all" && b.includes(jobs[1]!.generation!));
  assert.match(wholePost![1], /— complete\./);
  assert.doesNotMatch(wholePost![1], /the listing \(/);
  await svc.stop("over");
});

test("a recipe that declares no phase runs once, and a phase it does not declare is refused with what it has", async () => {
  const { S, svc } = await boxRun(undefined);
  await svc.start();
  await eventually(() => svc.jobs.size >= 1 && [...svc.jobs.values()].every(done), "the kickoff job");
  assert.equal(svc.jobs.size, 1);
  const target = { paths: [join(S, "inputs", "a.box")], ref: "input:a.box" };
  const r = await svc.submit("a1", { kind: "recipe", recipe: "bpack/items", phase: "listing", target, inputs: ["input:a.box"], timeout_seconds: 60, network: "off" } as never);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /has no phase "listing" to run alone \(its recipe\.json declares none\); leave phase out/);
  await svc.stop("over");
  assert.ok(existsSync(S));
  chmodSync(S, 0o755);
});

test("the post of a generation that is not a listing is its status, unchanged", () => {
  assert.equal(phaseWords(undefined, "partial"), "partial");
  assert.equal(phaseWords("other", "complete"), "complete");
  assert.match(phaseWords(LISTING_PHASE, "partial"), /nobody need walk the image for a list \(partial until then\)/);
});

/**
 * The plan's bar for the kickoff catalogue of a large AD1 (IMPROVEMENT-PLAN-2 A12): the listing of a 400,000-item image is committed
 * in under 60 s through the job service, the whole catalogue following as a later job. AD1_LISTING_ITEMS sets the count, as
 * CLOUD_TIMELINE_ROWS does for the cloud timeline: the default is small enough for every run of the suite, and the bar is the plan's
 * rate, 60 s for each 400,000 items, and never under ten seconds (what a kickoff does once whatever the image's size: the census,
 * the service's start, the seal). `AD1_LISTING_ITEMS=400000` measures the plan's own case against its own 60 s. The image is built from the format's layout
 * (tests/ad1-fixture.ts): folders of a thousand empty files, and one file in each with content.
 */
const ITEMS = Math.max(1000, Math.floor(Number(process.env.AD1_LISTING_ITEMS ?? 20_000) / 1000) * 1000 || 20_000);

test(`the listing of a ${ITEMS}-item AD1 is committed through the job service at the rate that commits 400,000 in under 60 s (AD1_LISTING_ITEMS sets the count)`, { timeout: 3_600_000 }, async (t) => {
  const base = await mkdtemp(join(tmpdir(), "catalog-phases-ad1-"));
  made.push(base);
  const S = join(base, "run");
  await P.initSandbox(S, { swarmId: "phase2", agentIds: ["a0", "a1"], capUsd: 5, wallClockMinutes: 30, goal: "## Goal\n\nList the image.\n\n### Questions\n\n1. What does the image hold?\n" });
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S, d), { recursive: true });
  const dirs: Ad1Node[] = [];
  for (let k = 0; k < ITEMS / 1000; k++) {
    const kids: Ad1Node[] = [];
    for (let i = 0; i < 1000; i++) kids.push({ name: `f${i}.txt`, content: i === 500 ? Buffer.from(`file 500 of d${k}`) : Buffer.alloc(0) });
    dirs.push({ name: `d${k}`, folder: true, children: kids });
  }
  const image = ad1Image(dirs);
  writeFileSync(join(S, "inputs", "case.ad1"), image);
  writeFileSync(join(S, "inputs.json"), JSON.stringify({ files: [{ path: "inputs/case.ad1", sha256: createHash("sha256").update(image).digest("hex"), bytes: image.length }] }));
  const CFB = join(ROOT, "packs", "computer-forensics-base");
  const began = Date.now();
  const census = spawnSync("python3", [join(ROOT, "scripts", "evidence_catalog.py"), S, "--plan-only", "--recipes-from", CFB], { encoding: "utf8" });
  assert.equal(census.status, 0, census.stderr);
  const posts: Array<[string, string]> = [];
  const svc = new JobService({ sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [CFB], forging: false, minFreeMb: 1, runWorker: localWorker(), destroyWorker: async () => ({ ok: true }), notify: async (to, body) => void posts.push([to, body]), identity: async (a) => ({ name: `${a}-name` }) });
  await svc.start();
  try {
    const listing = () => [...svc.jobs.values()].find((j) => j.spec.kind === "recipe" && j.spec.phase === LISTING_PHASE && j.spec.recipe === "computer-forensics-base/ad1-items");
    await eventually(() => Boolean(listing() && done(listing()!)), "the listing job catalogued", 3_000_000);
    const job = listing()!;
    assert.equal(job.state, "committed");
    const committedAt = Date.parse(String(svc.journal.of("job_committed").find((l) => l.job === job.id)!.at));
    const ms = committedAt - began;
    const cov = JSON.parse(readFileSync(join(S, "catalog", "gen", job.generation!, "coverage.json"), "utf8")) as { phase: string; items: number; files: number };
    assert.deepEqual([cov.phase, cov.items, cov.files], ["listing complete; digests pending", ITEMS + ITEMS / 1000, ITEMS]);
    const rows = readFileSync(join(S, "catalog", "gen", job.generation!, "members.tsv"), "utf8").trimEnd().split("\n").length - 1;
    assert.equal(rows, ITEMS + ITEMS / 1000, "every item is listed");
    // Said to everyone as the listing, with what follows.
    assert.ok(posts.some(([to, b]) => to === "all" && b.includes(job.generation!) && /the listing \(every member's path, size and times/.test(b)), JSON.stringify(posts.map(([to, b]) => [to, b.slice(0, 160)])));
    const bar = Math.max((60_000 * ITEMS) / 400_000, 10_000);
    t.diagnostic(`${ITEMS} items (an image of ${image.length} bytes): the listing committed ${ms} ms after the census began (the plan's rate allows ${Math.round(bar)} ms)`);
    assert.ok(ms < bar, `the listing of ${ITEMS} items was committed ${ms} ms after the census began`);
  } finally {
    await svc.stop("over");
  }
});
