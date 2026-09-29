/**
 * Signing from the console (scripts/ui/signing.ts through scripts/ui/app.ts):
 * enrolment, a release prepared and shown then sealed with the examiner's
 * passphrase, a technical reviewer's record, and everything that holds them
 * tight: the token even when the server's is empty, a loopback Host, the
 * console's own Origin, a JSON body, no live host-mode run, a lockout after
 * five wrong secrets (on the operator's record), keys without a passphrase
 * refused, and the secret nowhere but the pipe (not in a job, the audit or
 * a response). A stopped fixture run and keys in its temporary home.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createUiApp, type UiApp } from "../scripts/ui/app.ts";
import { enrollPerson } from "../scripts/signers.ts";
import { appendReview } from "../scripts/review.ts";
import { readReleases } from "../scripts/release-record.ts";
import { cleanUp, stoppedRun, type StoppedRun } from "./release-fixture.ts";

const ROOT = join(import.meta.dirname, "..");
const PASS = "console passphrase one";
const apps: UiApp[] = [];
after(async () => {
  for (const a of apps) await a.close();
  await cleanUp();
});

async function served(r: StoppedRun, token = "t0k"): Promise<string> {
  const app = createUiApp({ root: ROOT, runsDir: r.runs, distDir: join(r.runs, "no-dist"), token, signersHome: r.home, liveHubDirs: async () => [] });
  apps.push(app);
  const { port } = await app.listen(0, "127.0.0.1");
  return `http://127.0.0.1:${port}`;
}

function post(at: string, path: string, body: unknown, o: { token?: string | null; host?: string; origin?: string; type?: string } = {}): Promise<{ status: number; body: Record<string, unknown> }> {
  const u = new URL(`${at}${path}`);
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((done, fail) => {
    const req = request(
      {
        host: u.hostname,
        port: u.port,
        path: u.pathname,
        method: "POST",
        headers: {
          "content-type": o.type ?? "application/json",
          "content-length": data.length,
          ...(o.token === null ? {} : { authorization: `Bearer ${o.token ?? "t0k"}` }),
          ...(o.host ? { host: o.host } : {}),
          ...(o.origin ? { origin: o.origin } : {}),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let parsed: Record<string, unknown> = {};
          try {
            parsed = JSON.parse(text) as Record<string, unknown>;
          } catch {
            parsed = { raw: text };
          }
          done({ status: res.statusCode ?? 0, body: parsed });
        });
      },
    );
    req.on("error", fail);
    req.end(data);
  });
}

async function dispose(r: StoppedRun) {
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
}

function enrol(r: StoppedRun, name: string, o: { role?: "examiner" | "reviewer"; plain?: boolean; id?: string } = {}) {
  const e = enrollPerson({ name, id: o.id, organisation: "Lab One", competence: "GCFA", generateKey: true, noPassphrase: o.plain, role: o.role }, r.home, o.plain ? null : Buffer.from(PASS));
  assert.ok(!("why" in e), JSON.stringify(e));
}

test("the signing routes hold: the token even when the server has none, a loopback Host, the console's own Origin, JSON, and no live host-mode run", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner");
  await dispose(r);
  const at = await served(r);
  const prep = "/api/runs/s4v4/release/prepare";
  assert.equal((await post(at, prep, { examiner: "ada-examiner" }, { token: null })).status, 401);
  assert.equal((await post(at, prep, { examiner: "ada-examiner" }, { token: "wrong" })).status, 401);
  const host = await post(at, prep, { examiner: "ada-examiner" }, { host: "evil.example:80" });
  assert.equal(host.status, 403);
  assert.match(String(host.body.error), /only for a loopback Host/);
  const origin = await post(at, prep, { examiner: "ada-examiner" }, { origin: "http://evil.example" });
  assert.equal(origin.status, 403);
  assert.match(String(origin.body.error), /only from this console's own page/);
  assert.equal((await post(at, prep, { examiner: "ada-examiner" }, { type: "text/plain" })).status, 415);
  // A server started with SWARM_UI_TOKEN="" cannot sign at all.
  const open = await served(r, "");
  const none = await post(open, prep, { examiner: "ada-examiner" }, { token: null });
  assert.equal(none.status, 403);
  assert.match(String(none.body.error), /started with SWARM_UI_TOKEN empty: signing needs the server's token/);
  // A live host-mode run on this install: nothing is signed until it ends.
  const reg = join(r.runs, "registry.json");
  const regText = readFileSync(reg, "utf8");
  const registry = JSON.parse(regText) as { runs: Array<Record<string, unknown>> };
  registry.runs.push({ id: "shost", state: "running", sandbox: join(r.runs, "shost"), isolation: { mode: "host" } });
  writeFileSync(reg, JSON.stringify(registry));
  const live = await post(at, prep, { examiner: "ada-examiner" });
  assert.equal(live.status, 409);
  assert.match(String(live.body.error), /a host-mode run \(shost\) is live on this install/);
  registry.runs.at(-1)!.isolation = { mode: "microvm" };
  writeFileSync(reg, JSON.stringify(registry));
  assert.equal((await post(at, prep, { examiner: "ada-examiner" })).status, 200, "a microVM run does not stop it");
  writeFileSync(reg, regText);
  // The old way of signing, a background job, is refused.
  const job = await post(at, "/api/swarms/s4v4/review", { action: "sign", examiner: "Ada Examiner" });
  assert.equal(job.status, 400);
  assert.match(String(job.body.error), /signed from the Release panel with the examiner's own secret/);
});

test("prepare shows the bytes, seal signs them with the passphrase from the console; five wrong secrets lock the examiner out, on the operator's record; the secret is nowhere else", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner");
  enrol(r, "Pat Plain", { plain: true });
  await dispose(r);
  const at = await served(r);
  // Who can sign from here.
  const people = (await (await fetch(`${at}/api/examiners`)).json()) as { people: Array<{ id: string; console: string }>; signing: { ok: boolean } };
  assert.equal(people.signing.ok, true);
  assert.equal(people.people.find((p) => p.id === "ada-examiner")?.console, "ok");
  assert.match(String(people.people.find((p) => p.id === "pat-plain")?.console), /has no passphrase/);
  const plain = await post(at, "/api/runs/s4v4/release/prepare", { examiner: "pat-plain" });
  assert.equal(plain.status, 400);
  assert.match(String(plain.body.error), /has no passphrase: the console signs only with a key that needs one/);
  // Prepared: the report to read, its sha256, the counts, the key.
  const p = await post(at, "/api/runs/s4v4/release/prepare", { examiner: "ada-examiner" });
  assert.equal(p.status, 200, JSON.stringify(p.body));
  const nonce = String(p.body.nonce);
  const html = await fetch(`${at}${p.body.report_url}`);
  assert.equal(html.status, 200);
  assert.match(html.headers.get("content-security-policy") ?? "", /^sandbox; default-src 'none'/);
  const bytes = Buffer.from(await html.arrayBuffer());
  const shown = createHash("sha256").update(bytes).digest("hex");
  assert.equal(shown, (p.body.report as { html: { sha256: string } }).html.sha256);
  assert.equal((p.body.signer as { secret: string }).secret, "passphrase");
  assert.equal(p.body.pending, undefined, "the pending directory's path is not handed to the browser");
  // No consent, no seal.
  assert.equal((await post(at, "/api/runs/s4v4/release/seal", { nonce, shown_sha256: shown, examiner: "ada-examiner", secret: PASS })).status, 400);
  // Five wrong secrets: the fifth locks Ada out, and the record says so.
  for (let i = 1; i <= 5; i++) {
    const w = await post(at, "/api/runs/s4v4/release/seal", { nonce, shown_sha256: shown, examiner: "ada-examiner", secret: `wrong-${i}-passphrase`, consent: true });
    assert.equal(w.status, i < 5 ? 403 : 423, JSON.stringify(w.body));
    if (i === 5) assert.match(String(w.body.error), /ada-examiner is locked out of signing from the console until \S+: 5 wrong secrets in a row/);
  }
  const locked = await post(at, "/api/runs/s4v4/release/seal", { nonce, shown_sha256: shown, examiner: "ada-examiner", secret: PASS, consent: true });
  assert.equal(locked.status, 423, "the right secret does not lift a lockout");
  const audit = readFileSync(join(r.runs, "operator-audit.jsonl"), "utf8");
  assert.match(audit, /"command":"signing-lockout","argv":\["ada-examiner","s4v4"\]/);
  assert.match(audit, /"command":"release-seal".*"wrong_secret":true/);
  for (let i = 1; i <= 5; i++) assert.ok(!audit.includes(`wrong-${i}-passphrase`), "no secret reaches the audit");
  assert.equal(readReleases(r.root).filter((x) => x.record?.state === "adopted").length, 0);
  // Another examiner, not locked, signs.
  enrol(r, "Bea Examiner");
  const p2 = await post(at, "/api/runs/s4v4/release/prepare", { examiner: "bea-examiner" });
  assert.equal(p2.status, 200, JSON.stringify(p2.body));
  const sealed = await post(at, "/api/runs/s4v4/release/seal", { nonce: p2.body.nonce, shown_sha256: (p2.body.report as { html: { sha256: string } }).html.sha256, examiner: "bea-examiner", secret: PASS, consent: true });
  assert.equal(sealed.status, 200, JSON.stringify(sealed.body));
  assert.equal(sealed.body.version, 1);
  const v1 = readReleases(r.root).find((x) => x.version === 1)?.record;
  assert.equal(v1?.signing?.via, "console");
  assert.equal(v1?.signing?.consent, "confirmed");
  assert.equal(v1?.signer.examiner?.name, "Bea Examiner");
  const jobs = (await (await fetch(`${at}/api/jobs`)).json()) as unknown[];
  assert.equal(jobs.length, 0, "no signing act is a job");
  const everything = `${JSON.stringify(sealed.body)}${readFileSync(join(r.runs, "operator-audit.jsonl"), "utf8")}${readFileSync(join(v1 ? join(r.root, "release", "v1") : r.root, "release.json"), "utf8")}`;
  assert.ok(!everything.includes(PASS), "the passphrase is in no response, record or audit line");
  // The release state the panel reads.
  const state = (await (await fetch(`${at}/api/runs/s4v4/release`)).json()) as { releases: Array<{ version: number; signing: { via: string } | null }>; verify: { ok: boolean }; signing: { ok: boolean } };
  assert.deepEqual(state.releases.map((x) => x.version), [0, 1]);
  assert.equal(state.releases[1].signing?.via, "console");
  assert.equal(state.verify.ok, true);
});

test("enrolment and a technical reviewer's signed record from the console", async () => {
  const r = await stoppedRun();
  enrol(r, "Ada Examiner");
  await dispose(r);
  const at = await served(r);
  const differ = await post(at, "/api/examiners/enroll", { kind: "ssh", role: "reviewer", name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE", passphrase: "reviewer pass 1", passphrase_again: "reviewer pass 2" });
  assert.equal(differ.status, 400);
  assert.match(String(differ.body.error), /the two passphrases differ/);
  const plain = await post(at, "/api/examiners/enroll", { kind: "ssh", role: "reviewer", name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE", no_passphrase: true });
  assert.equal(plain.status, 400);
  const ok = await post(at, "/api/examiners/enroll", { kind: "ssh", role: "reviewer", name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE", passphrase: "reviewer pass 1", passphrase_again: "reviewer pass 1" });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal((ok.body.person as { role: string }).role, "reviewer");
  assert.match(String(ok.body.register), /^bo-reviewer namespaces="dfirswarm-review,dfirswarm-question" ssh-ed25519 /);
  const rec = await post(at, "/api/runs/s4v4/review/technical", { reviewer: "bo-reviewer", outcome: "agreed", checked: "re-ran fls", entries: [4, 10], secret: "reviewer pass 1", consent: true });
  assert.equal(rec.status, 200, JSON.stringify(rec.body));
  const state = (await (await fetch(`${at}/api/runs/s4v4/release`)).json()) as { technical: Array<{ status: string; words: string; reviewer: { name: string } }> };
  assert.equal(state.technical[0].status, "signed");
  assert.match(state.technical[0].words, /^signed by the reviewer \(Bo Reviewer/);
  const audit = readFileSync(join(r.runs, "operator-audit.jsonl"), "utf8");
  assert.ok(!audit.includes("reviewer pass 1"));
  assert.match(audit, /"command":"examiner","argv":\["enroll","bo-reviewer","--role","reviewer","--ssh"\]/);
});
