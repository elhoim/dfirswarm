/**
 * The reuse hints under review (Astra, WP7): a hint is optional, so it never
 * holds a job up. A job_similar line that cannot be written leaves the job
 * registered, queued and run (and, with nothing on disk naming the rest,
 * every similar job in the answer); and the index same_as is computed from
 * is built off the commit path, so a historical manifest that is slow to
 * read delays only the hint, never a commit or the store's next operation.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobService, type JobRecord } from "../scripts/job-service.ts";
import { similarView, SIMILAR_SHOWN, type Similar } from "../scripts/job-reuse.ts";
import { storePaths } from "../scripts/evidence-store.ts";
import { listInputs, localWorker } from "./job-service-worker.ts";

const ROOT = join(import.meta.dirname, "..");

function sandbox(): string {
  const S = join(mkdtempSync(join(tmpdir(), "reuse-review-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1", "work/a2"]) mkdirSync(join(S, d), { recursive: true });
  writeFileSync(join(S, "inputs", "disk.img"), "disk bytes\n".repeat(20));
  listInputs(S);
  return S;
}

function service(S: string): JobService {
  return new JobService({
    sandbox: S, run: "s000000", image: "img:test", workers: 2, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false,
    packDirs: [join(ROOT, "packs", "computer-forensics-base")], forging: false, minFreeMb: 1,
    runWorker: localWorker(), destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined, identity: async (a) => ({ name: `${a}-name` }),
  });
}

async function until(svc: JobService, id: string, what: (j: JobRecord) => boolean = (j) => j.state === "committed" || j.state === "failed" || j.state === "cancelled", tries = 400): Promise<JobRecord> {
  for (let i = 0; i < tries; i += 1) {
    const j = svc.jobs.get(id);
    if (j && what(j)) return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`${id} never got there`);
}

const journal = (S: string) => readFileSync(storePaths(S).journal, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

test("a job_similar line that cannot be written holds nothing up: the job is registered, queued and run, and the answer names every similar job", async () => {
  const S = sandbox();
  const svc = service(S);
  await svc.start();
  const spec = { kind: "command" as const, command: "strings inputs/disk.img > \"$OUT/s.txt\"", inputs: ["input:disk.img"] };
  const first = await svc.submit("a2", spec);
  assert.ok(first.ok);
  const append = svc.journal.append.bind(svc.journal);
  svc.journal.append = (async (e: Parameters<typeof append>[0]) => {
    if (e.type === "job_similar") throw new Error("the disk is full");
    return append(e);
  }) as typeof svc.journal.append;
  const second = await svc.submit("a1", spec);
  assert.ok(second.ok, JSON.stringify(second));
  assert.equal(second.similar?.length, 1);
  assert.equal(second.similar_recorded, false);
  assert.ok(svc.jobs.has(second.job.id), "the job is registered");
  const done = await until(svc, second.job.id);
  assert.deepEqual([done.state, done.status], ["committed", "ok"], "and it ran");
  assert.equal(journal(S).filter((l) => l.type === "job_similar").length, 0);
  // With no line to name the rest, the answer carries every one.
  const many: Similar[] = Array.from({ length: SIMILAR_SHOWN + 4 }, (_, i) => ({ job: `j${String(i + 1).padStart(6, "0")}`, seat: "a2", state: "committed", status: "ok", lead: null, objects: "same", shared: 1, match: "same command", op: "command:strings" }));
  const view = similarView("j000099", many, false, false);
  assert.equal((view.similar as Similar[]).length, SIMILAR_SHOWN + 4);
  assert.equal(view.similar_more, undefined);
  svc.journal.append = append;
  await until(svc, first.job.id);
  await svc.stop("over");
});

test("same_as never holds a commit up: a historical manifest that is slow to read delays only the hint, never a commit or the store's next operation", async () => {
  const S = sandbox();
  const svc = service(S);
  await svc.start();
  const first = await svc.submit("a1", { kind: "command", command: "printf 'the same bytes' > \"$OUT/x.txt\"", inputs: [] });
  assert.ok(first.ok);
  await until(svc, first.job.id);
  await svc.stop("over");
  // The first job's manifest becomes a FIFO: reading it blocks until something writes it.
  const man = join(storePaths(S).jobs, first.job.id, "manifest.json");
  const text = readFileSync(man, "utf8");
  unlinkSync(man);
  assert.equal(spawnSync("mkfifo", [man]).status, 0, "mkfifo");
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    writeFileSync(man, text);
  };
  const again = service(S);
  try {
    await again.start();
    const second = await again.submit("a2", { kind: "command", command: "printf 'the same bytes' > \"$OUT/y.txt\"", inputs: [] });
    assert.ok(second.ok);
    const committed = await until(again, second.job.id, undefined, 200);
    assert.equal(committed.state, "committed", "committed while the index is still being read");
    assert.equal(committed.same_as, undefined, "its hint waits for the index");
    const third = await again.submit("a3", { kind: "command", command: "printf 'other' > \"$OUT/z.txt\"", inputs: [] });
    assert.ok(third.ok);
    assert.equal((await until(again, third.job.id, undefined, 200)).state, "committed", "the store's next operation is not held either");
    release();
    const hinted = await until(again, second.job.id, (j) => Boolean(j.same_as?.length));
    assert.deepEqual(hinted.same_as?.map((s) => [s.path, s.job, s.file]), [["y.txt", first.job.id, "x.txt"]]);
    const line = await (async () => {
      for (let i = 0; i < 100; i += 1) {
        const l = journal(S).find((x) => x.type === "job_same_as" && x.job === second.job.id);
        if (l) return l;
        await new Promise((r) => setTimeout(r, 50));
      }
      return null;
    })();
    assert.ok(line, "the job_same_as line is written once the index answers");
    assert.equal(again.jobs.get(third.job.id)?.same_as, undefined, "different bytes say nothing");
  } finally {
    release();
    await again.stop("over");
  }
});
