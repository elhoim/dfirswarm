/**
 * The EXPERIMENTAL observation of a job's reads (fanotify in its worker), on
 * the host's side: a log written by the collector's own writer
 * (scripts/job-observe.py, run here without fanotify) read back as complete
 * only when every check holds; dropped events, a mark that failed, a stall
 * or a read outside the declared scope as partial; a collector that died, a
 * forged or missing line, an unseen canary, no key or no fanotify as unknown.
 * And the wiring: off by default, and with the flag a declared job's worker
 * gets the collector, its own mount, a canary in its view, the command as an
 * unprivileged user, and the log read after the worker is gone. The guest
 * side is tests/job-observe-vm.test.ts, not run here.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { observedRun, readObservation } from "../scripts/job-observe.ts";
import { JobService } from "../scripts/job-service.ts";
import { storePaths, verifyJournalText } from "../scripts/evidence-store.ts";
import { listInputs } from "./job-service-worker.ts";
import type { WorkerSpec } from "../scripts/vm.ts";

const ROOT = join(import.meta.dirname, "..");
const S = "/runs/s1";
const CANARY = `${S}/.observe-canary`;
const SCOPE = [`${S}/inputs/disk.E01`, `${S}/inputs/disk.E02`, `${S}/work/a1/parse.py`, CANARY];

type Rec = Record<string, unknown>;

/** A log as the collector writes it: its own Log class, from its own file, with the records given. */
function signed(records: Rec[], o: { gapUs?: number } = {}): { text: string; key: string } {
  const dir = mkdtempSync(join(tmpdir(), "observe-"));
  const py = `
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("obs", sys.argv[1])
obs = importlib.util.module_from_spec(spec); spec.loader.exec_module(obs)
log = obs.Log(sys.argv[2])
gap = int(sys.argv[4])
if gap:
    real = time.monotonic_ns
    n = {"i": 0}
    def fake():
        n["i"] += 1
        return real() + (gap * 1000 if n["i"] > 2 else 0)
    time.monotonic_ns = fake
for r in json.loads(sys.argv[3]):
    log.write(r)
`;
  const r = spawnSync("python3", ["-c", py, join(ROOT, "scripts", "job-observe.py"), join(dir, "out"), JSON.stringify(records), String(o.gapUs ?? 0)], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return { text: readFileSync(join(dir, "out", "events.jsonl"), "utf8"), key: readFileSync(join(dir, "out", "key"), "utf8") };
}

const start = (extra: Rec = {}) => ({ kind: "start", pid: 10, uid: 0, kernel: "6.12.0", marks: [{ mount: S, ok: true }, { mount: `${S}/inputs`, ok: true }], ...extra });
const open = (path: string, what = ["open"]) => ({ kind: "event", what, path, pid: 42, dir: false });
const end = { kind: "end", events: 4, overflow: 0, unnamed: 0 };
const good = [start(), open(CANARY), open(`${S}/inputs/disk.E01`), open(`${S}/inputs/disk.E01`, ["access"]), open(`${S}/inputs`, ["open"]), open(CANARY), end];
const read = (log: { text: string; key: string | null }) => readObservation(log.text, log.key, { scope: SCOPE, canary: CANARY });

test("complete only when every check holds: the canary seen twice, every mount marked, verified line by line, ended", () => {
  const o = read(signed(good));
  assert.equal(o.status, "complete", o.reasons.join("; "));
  assert.deepEqual(o.opened.map((x) => [x.path, x.what]), [[`${S}/inputs/disk.E01`, ["access", "open"]], [`${S}/inputs`, ["open"]]], "a listing of a directory on the way to a declared file is in scope");
  assert.equal(o.kernel, "6.12.0");
  // A name that is not ASCII verifies the same on both sides.
  assert.equal(read(signed([start(), open(CANARY), open(`${S}/inputs/disk.E01`), open(`${S}/work/a1/parse.py`), open(CANARY), end])).status, "complete");
  const utf = read(signed([start(), open(CANARY), open(`${S}/inputs/Ünlü dosya.E01`), open(CANARY), end]));
  assert.equal(utf.reasons.some((r) => /does not verify/.test(r)), false, "the canonical form agrees for a non-ASCII path");
});

test("dropped events, a mount not marked, a stall or a read outside the scope make it partial, never complete", () => {
  const overflow = read(signed([start(), open(CANARY), { kind: "overflow" }, open(CANARY), end]));
  assert.equal(overflow.status, "partial");
  assert.match(overflow.reasons.join(), /queue overflowed 1 time/);
  const unmarked = read(signed([start({ marks: [{ mount: S, ok: true }, { mount: `${S}/inputs/case`, ok: false, error: "Operation not supported" }] }), open(CANARY), open(CANARY), end]));
  assert.equal(unmarked.status, "partial");
  assert.match(unmarked.reasons.join(), /inputs\/case could not be marked \(Operation not supported\)/);
  const escape = read(signed([start(), open(CANARY), open("/etc/shadow"), open(`${S}/inputs/memory.raw`), open(CANARY), end]));
  assert.equal(escape.status, "partial");
  assert.deepEqual(escape.escapes, ["/etc/shadow", `${S}/inputs/memory.raw`]);
  const stalled = read(signed([start(), open(CANARY), open(CANARY), end], { gapUs: 8_000_000 }));
  assert.equal(stalled.status, "partial");
  assert.match(stalled.reasons.join(), /stalled for 80\d\d ms/);
});

test("a collector that died, a forged, edited or missing line, an unseen canary, no key or no fanotify read as unknown", () => {
  const died = signed(good.slice(0, -1));
  assert.match(read(died).reasons.join(), /no end: the collector died/);
  const log = signed(good);
  const lines = log.text.trimEnd().split("\n");
  // A line the job wrote: well formed, not keyed.
  const forged = [...lines.slice(0, -1), JSON.stringify({ ...JSON.parse(lines[1]), seq: lines.length - 1, path: "/elsewhere", mac: "0".repeat(64) }), lines.at(-1)].join("\n");
  assert.equal(read({ text: forged, key: log.key }).status, "unknown");
  assert.match(read({ text: forged, key: log.key }).reasons.join(), /does not verify/);
  const edited = lines.map((l, i) => (i === 2 ? l.replace("disk.E01", "disk.E02") : l)).join("\n");
  assert.match(read({ text: edited, key: log.key }).reasons.join(), /line 3 does not verify/);
  const dropped = [...lines.slice(0, 2), ...lines.slice(3)].join("\n");
  assert.match(read({ text: dropped, key: log.key }).reasons.join(), /out of order or a line before it is missing/);
  assert.match(read({ text: log.text, key: null }).reasons.join(), /key is missing/);
  assert.match(read(signed([start(), open(CANARY), end])).reasons.join(), /canary was seen opened 1 time/);
  assert.match(read(signed([start({ unsupported: "fanotify_init: Function not implemented" }), end])).reasons.join(), /not available in this worker: fanotify_init/);
  assert.match(read({ text: "", key: log.key }).reasons.join(), /did not start/);
});

test("run.sh with observation: the collector first, the canary read by the job's user around its command, run as nobody, the collector stopped last", () => {
  const lines = observedRun({ mounts: [S, `${S}/inputs`], canary: CANARY, cmd: "timeout 900 bash /job/command.sh > /job/stdout.log" });
  assert.match(lines[0], /^python3 \/job\/observe\.py \/observe '\/runs\/s1' '\/runs\/s1\/inputs' & OBSERVER=\$!$/);
  const as = "setpriv --reuid=65534 --regid=65534 --clear-groups --";
  assert.deepEqual(lines.slice(3, 7), [`${as} cat '${CANARY}' > /dev/null`, `${as} timeout 900 bash /job/command.sh > /job/stdout.log`, "echo $? > /job/exit", `${as} cat '${CANARY}' > /dev/null`]);
  assert.equal(lines.at(-1), 'kill -TERM "$OBSERVER"; wait "$OBSERVER"');
});

test("off by default; with the flag a declared job's worker gets the collector, a canary and its own mount, and the log is read after the worker is gone", async () => {
  const S2 = join(mkdtempSync(join(tmpdir(), "obsrun-")), "run");
  for (const d of ["inputs", "tools", "catalog", "work/a1"]) mkdirSync(join(S2, d), { recursive: true });
  writeFileSync(join(S2, "inputs", "disk.E01"), "evidence");
  listInputs(S2);
  const specs: WorkerSpec[] = [];
  const seen: Array<{ runSh: string; collector: boolean; canary: string | null }> = [];
  // A worker that writes what a collector would have (signed by its own writer) and the job's exit.
  const runWorker = async (spec: WorkerSpec) => {
    specs.push(spec);
    const obs = spec.mounts.find((m) => m.guest === "/observe");
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const view = spec.mounts.find((m) => m.view && m.guest === S2);
    seen.push({ runSh: readFileSync(join(ctl, "run.sh"), "utf8"), collector: existsSync(join(ctl, "observe.py")), canary: view && existsSync(join(view.host, ".observe-canary")) ? readFileSync(join(view.host, ".observe-canary"), "utf8") : null });
    if (obs) {
      const canary = join(S2, ".observe-canary");
      const log = signed([{ ...start(), marks: [{ mount: S2, ok: true }] }, open(canary), open(join(S2, "inputs", "disk.E01")), open(canary), end]);
      writeFileSync(join(obs.host, "events.jsonl"), log.text);
      writeFileSync(join(obs.host, "key"), log.key);
    }
    writeFileSync(join(ctl, "exit"), "0\n");
    return { code: 0, fenced: true };
  };
  const svc = new JobService({ sandbox: S2, run: "s000000", image: "img:test", workers: 1, workerCpus: 1, workerMemoryMib: 512, allowHosts: [], openNet: false, packDirs: [], forging: false, minFreeMb: 1, runWorker, destroyWorker: async () => ({ ok: true }), notify: async () => undefined, identity: async () => ({}) });
  await svc.start();
  const until = async (id: string) => {
    for (let i = 0; i < 400; i += 1) {
      const j = svc.jobs.get(id);
      if (j && (j.state === "committed" || j.state === "failed")) return j;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`job ${id} did not finish`);
  };
  const plain = await svc.submit("a1", { kind: "command", command: "cat inputs/disk.E01", inputs: ["input:disk.E01"] });
  assert.ok(plain.ok);
  await until(plain.job.id);
  assert.ok(!specs[0].mounts.some((m) => m.guest === "/observe"), "off by default");
  process.env.SWARM_JOB_OBSERVE = "fanotify-experimental";
  try {
    const r = await svc.submit("a1", { kind: "command", command: "cat inputs/disk.E01", inputs: ["input:disk.E01"] });
    assert.ok(r.ok);
    const job = await until(r.job.id);
    const spec = specs[1];
    assert.ok(spec.mounts.some((m) => m.guest === "/observe" && !m.readonly), "the collector's own mount");
    assert.ok(seen[1].collector, "the collector's script beside the job's");
    assert.match(seen[1].runSh, /python3 \/job\/observe\.py \/observe .* & OBSERVER=\$!/);
    assert.match(seen[1].runSh, /setpriv --reuid=65534 --regid=65534 --clear-groups -- timeout/);
    assert.match(String(seen[1].canary), new RegExp(`^${job.id}\\.1\\.`), "a canary in the job's view");
    assert.doesNotMatch(seen[0].runSh, /observe\.py|setpriv/);
    const lines = verifyJournalText(readFileSync(storePaths(S2).journal, "utf8")).lines;
    const observed = lines.find((l) => l.type === "job_observed" && l.job === job.id)!;
    assert.equal(observed.experimental, true);
    assert.equal(observed.status, "complete", String(observed.reasons));
    assert.equal(observed.opened, 1);
    const kept = readFileSync(join(S2, String(observed.log)), "utf8");
    assert.match(kept, /"kind":"start"/, "the collector's log kept whole beside the job's record");
    // Declared nothing: not observed, whatever the flag.
    const broad = await svc.submit("a1", { kind: "command", command: "true" });
    assert.ok(broad.ok);
    await until(broad.job.id);
    assert.ok(!specs[2].mounts.some((m) => m.guest === "/observe"));
  } finally {
    delete process.env.SWARM_JOB_OBSERVE;
    await svc.stop("over");
  }
});
