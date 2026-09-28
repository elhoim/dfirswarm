/**
 * The dynamic network through the hub (docs/adr/0011): a seat's net_request
 * and net_fetch arrive on its own socket (who asks is the channel, never an
 * argument), are decided and carried out on the host, and the capture lands
 * on the ledger; a job given a grant fetches it itself, as its own
 * principal, through the fetch service on the host port its worker is
 * given, with the helper the job service writes; a host run says it has no
 * dynamic network.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import * as B from "../extensions/board.ts";
import * as P from "../extensions/protocol.ts";
import { JobService } from "../scripts/job-service.ts";
import { bindJobGrants, externalLineage, netTick, recordCaptures } from "../scripts/net-broker.ts";
import { readNetState } from "../scripts/net-grants.ts";
import { boardTable } from "../scripts/vm-hub.ts";
import type { WorkerSpec } from "../scripts/vm.ts";
import { json, setup, skipWithoutTls } from "./net-mock.ts";

/**
 * The job service's local stand-in for a worker VM (tests/job-service-worker.ts),
 * run without blocking this process: the fetch service the job calls lives
 * in it too.
 */
function asyncLocalWorker(record: WorkerSpec[]) {
  return async (spec: WorkerSpec) => {
    record.push(spec);
    const ctl = spec.mounts.find((m) => m.guest === "/job")!.host;
    const out = spec.mounts.find((m) => m.host.includes(".staging/") && m.host.endsWith("/out"))!;
    const local = (text: string) => text.split("/job/").join(`${ctl}/`).split(out.guest!).join(out.host);
    const script = local(readFileSync(join(ctl, "run.sh"), "utf8")).replace(/timeout --kill-after=10 (\d+) /g, "");
    writeFileSync(join(ctl, "run-local.sh"), script);
    const code = await new Promise<number | null>((done) => {
      const child = spawn("bash", [join(ctl, "run-local.sh")], { cwd: spec.workdir, env: { ...process.env, ...spec.env, OUT: out.host }, stdio: "ignore" });
      child.on("close", (c) => done(c));
    });
    return { code, fenced: true };
  };
}

const route = (h: string, p: string) => (h === "rdap.org" && p === "/domain/example.org" ? json({ objectClassName: "domain", ldhName: "EXAMPLE.ORG" }) : null);

test("a seat's request and fetch go through its own socket; the grant is the seat's, the capture is on the ledger", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route });
  const table = boardTable({ sandbox: s.S, settle: async () => undefined, wrote: () => undefined, ids: ["a1", "a2"], dir: s.hubDir });
  const call = (who: string, fn: string, arg: unknown) => (table as Record<string, (w: string, a: unknown[], sig: AbortSignal) => Promise<unknown>>)[fn](who, [s.S, arg], new AbortController().signal) as Promise<Record<string, any>>;
  const r = await call("a1", "netRequest", { lead: "L-1", adapter: "rdap_domain", params: { domain: "example.org" }, purpose: "who registered it" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.grant, "N-1");
  // Another seat asking in a1's name is still itself: L-1 is not its lead.
  const spoof = await call("a2", "netRequest", { lead: "L-1", adapter: "rdap_domain", params: { domain: "example.org" }, purpose: "as a1", principal: "seat:a1" });
  assert.equal(spoof.ok, false);
  const f = await call("a1", "netFetch", { grant: "N-1" });
  assert.equal(f.ok, true, JSON.stringify(f));
  assert.equal(f.capture, "net:1/1");
  assert.match(f.body_text, /EXAMPLE\.ORG/);
  assert.match(f.entry, /^E-\d+$/);
  assert.match(f.note, /External data/);
  // The same grant from another seat's socket is refused by the fetch service.
  const other = await call("a2", "netFetch", { grant: "N-1" });
  assert.equal(other.ok, false);
  // A page of the sealed capture, by its ref.
  const page = await call("a2", "netFetch", { capture: "net:1/1", offset: 2 });
  assert.equal(page.ok, true);
  assert.equal(page.offset, 2);
  const view = await call("a1", "netView", { view: "mine" });
  assert.equal(view.grants.length, 1);
  assert.equal(view.grants[0].status, "exhausted");
  assert.equal((await call("a2", "netView", { view: "mine" })).grants.length, 0);
  const adapters = await call("a1", "netView", { view: "adapters" });
  assert.ok(adapters.adapters.some((a: { name: string }) => a.name === "rdap_domain"));
});

test("a job given a grant makes its request itself, as job:<id>, through the host port its worker is given", async (t) => {
  if (await skipWithoutTls(t)) return;
  const s = await setup({ route });
  mkdirSync(join(s.S, "work", "a1"), { recursive: true });
  const specs: WorkerSpec[] = [];
  const svc = new JobService({
    sandbox: s.S,
    run: "n1",
    image: "img:test",
    workers: 1,
    workerCpus: 1,
    workerMemoryMib: 512,
    allowHosts: [],
    openNet: false,
    packDirs: [],
    forging: false,
    minFreeMb: 1,
    runWorker: asyncLocalWorker(specs),
    destroyWorker: async () => ({ ok: true }),
    notify: async () => undefined,
    identity: async () => ({}),
    // The worker reaches the host as host.microsandbox.internal; this stand-in runs on the host itself.
    netAccess: async (job) => {
      const b = await bindJobGrants(s.S, s.hubDir, job.id, job.requester.agent, job.spec.net_grants ?? []);
      return b.ok ? { ...b, env: { ...b.env, SWARM_NET_URL: b.env.SWARM_NET_URL.replace("host.microsandbox.internal", "127.0.0.1") } } : b;
    },
  });
  await svc.start();
  const table = boardTable({ sandbox: s.S, settle: async () => undefined, wrote: () => undefined, ids: ["a1", "a2"], jobs: () => svc, dir: s.hubDir });
  const call = (who: string, fn: string, arg: unknown) => (table as Record<string, (w: string, a: unknown[], sig: AbortSignal) => Promise<unknown>>)[fn](who, [s.S, arg], new AbortController().signal) as Promise<Record<string, any>>;
  const r = await call("a1", "netRequest", { lead: "L-1", adapter: "rdap_domain", params: { domain: "example.org" }, purpose: "parse the record in a job", for: "job" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.for, "job");
  // Not a seat's to fetch, nor another seat's to give a job.
  assert.equal((await call("a1", "netFetch", { grant: r.grant })).ok, false);
  const theirs = await call("a2", "jobSubmit", { command: "true", net_grants: [r.grant] });
  assert.equal(theirs.ok, false);
  assert.match(theirs.reason, /not yours/);
  const sub = await call("a1", "jobSubmit", { command: 'python3 "$(dirname "$0")/net_fetch.py" ' + r.grant + ' --out "$OUT/rdap.json"', net_grants: [r.grant], timeout_seconds: 60 });
  assert.equal(sub.ok, true, JSON.stringify(sub));
  const id = sub.job.job as string;
  let st: Record<string, any> = {};
  for (let i = 0; i < 400; i += 1) {
    st = await call("a1", "jobStatus", { job_id: id });
    if (["committed", "failed", "cancelled"].includes(st.job?.state)) break;
    await new Promise((res) => setTimeout(res, 50));
  }
  assert.equal(st.job?.status, "ok", JSON.stringify(st));
  // Its worker was given the fetch service's port and its own token, and nothing more of the host.
  const spec = specs.at(-1)!;
  assert.deepEqual(spec.hostPorts, [s.port]);
  assert.equal(spec.env.SWARM_NET_PRINCIPAL, `job:${id}`);
  assert.equal(spec.network.mode, "off");
  const out = readFileSync(join(s.S, "store", "jobs", id, "out", "rdap.json"), "utf8");
  assert.match(out, /EXAMPLE\.ORG/);
  const state = await readNetState(s.S);
  assert.equal(state.grants.get(r.grant)?.bound?.job, id);
  assert.equal(state.fetches.get(r.grant)?.[0].principal, `job:${id}`);
  // The hub's round records the job's capture on the ledger, and it stays external through the job.
  await netTick(s.S, () => true);
  const ext = (await P.readLedger(s.S)).find((e) => e.kind === "external");
  assert.ok(ext, "the job's capture is on the ledger");
  const lin = await externalLineage(s.S);
  assert.deepEqual(lin.jobs.get(id), ["net:1/1"]);
  assert.ok(existsSync(join(s.S, "store", "net", "1", "1", "capture.json")));
  await recordCaptures(s.S);
  assert.equal((await P.readLedger(s.S)).filter((e) => e.kind === "external").length, 1);
  await svc.stop("the test is over");
});

test("a host run has no dynamic network, and its tools say so", async () => {
  const was = process.env.SWARM_BOARD_SOCKET;
  delete process.env.SWARM_BOARD_SOCKET;
  try {
    for (const fn of [B.netRequest, B.netFetch, B.netView]) {
      const r = await fn("/nonexistent", {});
      assert.equal(r.ok, false);
      assert.match(String(r.reason), /no dynamic network/);
    }
  } finally {
    if (was !== undefined) process.env.SWARM_BOARD_SOCKET = was;
  }
});
