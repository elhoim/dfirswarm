/**
 * Signing a release with the examiner's own secret (scripts/secret-io.ts,
 * scripts/signers.ts, scripts/release.ts): the three kinds of key (an ssh
 * key with a passphrase, a FIDO key, an e-signature certificate on a token),
 * how the secret travels (a pipe on fd 3, never argv, the environment or a
 * file), and the two halves of an adoption: prepare renders the final bytes
 * once and says what will be signed; seal signs exactly those bytes, and
 * refuses when they, the review or custody moved, when fifteen minutes
 * passed, or when the nonce was used. The e-signature tests run against a
 * throwaway SoftHSM2 token and skip, saying why, when it is not installed.
 * Keys and tokens are made in temporary directories; no real key, token or
 * PIN is touched, and nothing is written to the real ~/.dfirswarm.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { appendFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discardPrepared, prepareRelease, runContext, sealPrepared, signRelease, WrongSecretError, PENDING_TTL_MS } from "../scripts/release.ts";
import { readReleases, runLayout, verifyReleases } from "../scripts/release-record.ts";
import { builtInFido, consoleRefusal, enrollPerson, fidoKeygen, keyFileEncrypted, listPeople, loadExaminer, loadPerson, personSummary, keyWords, allowedSignersLine, type Person } from "../scripts/signers.ts";
import { runWithSecret, signingEnv, readSecretFromFd, ASKPASS } from "../scripts/secret-io.ts";
import { certExtensions, certInfo, tokenUri } from "../scripts/pkcs11.ts";
import { appendReview, reviewsPath } from "../scripts/review.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { cleanUp, fakeChrome, stoppedRun, type StoppedRun } from "./release-fixture.ts";
import { softToken, SUBJECT_SERIAL, TEST_PIN } from "./pkcs11-fixture.ts";

after(cleanUp);
const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const quiet = () => undefined;
const PASS = Buffer.from("correct horse battery");
const secret = () => Buffer.from(PASS);

function ctxOf(r: StoppedRun) {
  return runContext(r.root, { run: r.id, runsDir: r.runs });
}
function layout(r: StoppedRun) {
  return runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
}
function enrolSsh(r: StoppedRun, o: { name?: string; id?: string; role?: "examiner" | "reviewer" | "analyst" | "observer"; noPassphrase?: boolean } = {}): Person {
  const e = enrollPerson({ name: o.name ?? "Ada Examiner", organisation: "Lab One", competence: "GCFA; ten years of casework", generateKey: true, noPassphrase: o.noPassphrase, role: o.role, id: o.id }, r.home, o.noPassphrase ? null : secret());
  assert.ok(!("why" in e), JSON.stringify(e));
  return (e as { person: Person }).person;
}
/** The dispositions the fixture's defective answers need before a release. */
async function dispose(r: StoppedRun) {
  const ADA = { examiner: "Ada Examiner", examinerId: "ada-examiner", key: "k" };
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "adopt", entry_seq: 14 });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
  await appendReview(r.runs, r.id, r.root, { ...ADA, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
}

test("the secret goes down a pipe on fd 3: the askpass helper answers ssh-keygen from it, and a wrong one is told apart", async () => {
  const d = mkdtempSync(join(tmpdir(), "dfs-secret-"));
  try {
    const key = join(d, "k");
    // A key with a passphrase, made through the same pipe (ssh-keygen asks twice).
    const made = runWithSecret("ssh-keygen", ["-q", "-t", "ed25519", "-C", "t", "-f", key], secret(), { env: signingEnv(process.env, { askpass: true }), times: 2 });
    assert.equal(made.code, 0, made.err);
    assert.equal(keyFileEncrypted(key), true, "the key made is encrypted");
    const file = join(d, "f");
    writeFileSync(file, "bytes\n");
    const ok = runWithSecret("ssh-keygen", ["-Y", "sign", "-f", key, "-n", "t", file], secret(), { env: signingEnv(process.env, { askpass: true, dropAgent: true }) });
    assert.equal(ok.code, 0, ok.err);
    assert.ok(existsSync(`${file}.sig`));
    const wrong = runWithSecret("ssh-keygen", ["-Y", "sign", "-f", key, "-n", "t", file], Buffer.from("not it"), { env: signingEnv(process.env, { askpass: true, dropAgent: true }) });
    assert.notEqual(wrong.code, 0);
    assert.match(wrong.err, /incorrect passphrase/);
    // The helper takes nothing from its arguments or its environment.
    const helper = readFileSync(ASKPASS, "utf8");
    assert.match(helper, /read -r line <&3/);
    assert.doesNotMatch(helper.replace(/^#.*$/gm, ""), /\$1|\$\{?[A-Z_]*PASS/);
    const env = signingEnv({ SSH_AUTH_SOCK: "/tmp/agent", DISPLAY: ":0", PATH: "/bin" }, { dropAgent: true, askpass: true });
    assert.equal(env.SSH_AUTH_SOCK, undefined, "the console's signing never reaches the agent");
    assert.equal(env.DISPLAY, undefined);
    assert.equal(env.SSH_ASKPASS_REQUIRE, "force");
    // A descriptor's secret, as the console hands it down: every byte, less the trailing newline.
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", `const m = await import(${JSON.stringify(join(import.meta.dirname, "..", "scripts", "secret-io.ts"))}); const b = m.readSecretFromFd(3); process.stdout.write(String(b.length) + ":" + b.toString());`], { stdio: ["ignore", "pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout?.on("data", (c: Buffer) => (out += c.toString()));
    (child.stdio[3] as NodeJS.WritableStream).end(Buffer.from("s3cret with spaces\n"));
    await new Promise((res) => child.on("close", res));
    assert.equal(out, "18:s3cret with spaces");
    void readSecretFromFd;
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

test("an ssh key is made with a passphrase fed on stdin in a session with no terminal, and a key given must be encrypted", async () => {
  const r = await stoppedRun();
  const p = enrolSsh(r);
  assert.equal(p.key.kind, "ssh");
  if (p.key.kind !== "ssh") return;
  assert.equal(p.key.passphrase, true);
  assert.equal(keyFileEncrypted(p.key.path), true, "ssh-keygen -y -P \"\" fails on the key made");
  assert.equal(consoleRefusal(p), null, "an encrypted key file signs from the console");
  const short = enrollPerson({ name: "Short Pass", organisation: "Lab", competence: "x", generateKey: true }, r.home, Buffer.from("abc"));
  assert.match((short as { why: string }).why, /at least 8 characters/);
  // A key given without a passphrase is refused unless the trade is made on purpose.
  const keys = mkdtempSync(join(tmpdir(), "dfs-keys-"));
  spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "bo", "-f", join(keys, "bo")]);
  const refused = enrollPerson({ name: "Bo Plain", organisation: "Lab", competence: "x", key: join(keys, "bo") }, r.home);
  assert.match((refused as { why: string }).why, /has no passphrase: `ssh-keygen -y -P ""` reads it/);
  const traded = enrollPerson({ name: "Bo Plain", organisation: "Lab", competence: "x", key: join(keys, "bo"), noPassphrase: true }, r.home);
  assert.ok(!("why" in traded), JSON.stringify(traded));
  if ("why" in traded) return;
  assert.match(String(consoleRefusal(traded.person)), /has no passphrase: the console signs only with a key that needs one/);
  // A key given with a passphrase: the proof of possession needs it, and a wrong one enrols nothing.
  const encrypted = runWithSecret("ssh-keygen", ["-q", "-t", "ed25519", "-C", "cy", "-f", join(keys, "cy")], secret(), { env: signingEnv(process.env, { askpass: true }), times: 2 });
  assert.equal(encrypted.code, 0, encrypted.err);
  const wrong = enrollPerson({ name: "Cy Given", organisation: "Lab", competence: "x", key: join(keys, "cy") }, r.home, Buffer.from("wrong passphrase"));
  assert.match((wrong as { why: string }).why, /the key could not sign .*incorrect passphrase.*nothing was enrolled/);
  const given = enrollPerson({ name: "Cy Given", organisation: "Lab", competence: "x", key: join(keys, "cy") }, r.home, secret());
  assert.ok(!("why" in given), JSON.stringify(given));
  // A key held in ssh-agent (its .pub given) is the command line's only.
  const agent = { ...(given as { person: Person }).person, key: { ...(given as { person: Person }).person.key, agent: true } } as Person;
  assert.match(String(consoleRefusal(agent)), /held in ssh-agent/);
  await rm(keys, { recursive: true, force: true });
});

test("roles: a reviewer's register line is in the review namespace, a reviewer never signs a release, and an old enrolment reads as an examiner's ssh key", async () => {
  const r = await stoppedRun();
  const rev = enrolSsh(r, { name: "Bo Reviewer", role: "reviewer" });
  assert.equal(rev.role, "reviewer");
  assert.match(allowedSignersLine(rev), /^bo-reviewer namespaces="dfirswarm-review,dfirswarm-question" ssh-ed25519 /);
  const ex = enrolSsh(r);
  assert.match(allowedSignersLine(ex), /namespaces="dfirswarm-release,dfirswarm-package,dfirswarm-question"/);
  assert.deepEqual(listPeople(r.home, "reviewer").map((p) => p.id), ["bo-reviewer"]);
  await dispose(r);
  await assert.rejects(prepareRelease(ctxOf(r), { examiner: "bo-reviewer", home: r.home }), /enrolled as a technical reviewer, not an examiner/);
  // An analyst adds questions to a case and never signs a release; neither does an observer.
  const ana = enrolSsh(r, { name: "Ana Lyst", role: "analyst" });
  assert.match(allowedSignersLine(ana), /^ana-lyst namespaces="dfirswarm-question" ssh-ed25519 /);
  await assert.rejects(prepareRelease(ctxOf(r), { examiner: "ana-lyst", home: r.home }), /enrolled as an analyst, not an examiner: an analyst adds questions to a case, and never signs a release/);
  enrolSsh(r, { name: "Oli Server", role: "observer" });
  await assert.rejects(prepareRelease(ctxOf(r), { examiner: "oli-server", home: r.home }), /enrolled as an observer, not an examiner/);
  // An enrolment written before kinds and roles.
  const legacy = { kind: "examiner", v: 1, id: "old-one", name: "Old One", organisation: "Lab", competence: "x", principal: "old-one", key: { path: "/nowhere/key", public: ex.key.kind === "ssh" ? ex.key.public : "", fingerprint: ex.key.fingerprint, generated: true }, tsa: null, enrolled_at: "2026-09-01T00:00:00Z", enrolled_by: { os_user: "u", host: "h" } };
  writeFileSync(join(r.home, "examiners", "old-one.json"), JSON.stringify(legacy));
  const old = loadPerson("old-one", r.home);
  assert.ok("person" in old);
  if ("person" in old) {
    assert.equal(old.person.role, "examiner");
    assert.equal(old.person.key.kind, "ssh");
    assert.equal(old.person.key.kind === "ssh" && old.person.key.passphrase, null);
  }
  assert.match(String((loadExaminer("nobody", r.home) as { why: string }).why), /no examiner nobody is enrolled/);
});

test("a FIDO-capable ssh-keygen is found from its files, never by talking to an authenticator", () => {
  const apple = "/usr/bin/ssh-keygen";
  if (process.platform === "darwin" && existsSync("/usr/libexec/ssh-sk-helper")) assert.equal(builtInFido(apple, {}), false, "macOS's own ssh-keygen has no FIDO support");
  const brew = ["/opt/homebrew/opt/openssh/bin/ssh-keygen", "/usr/local/opt/openssh/bin/ssh-keygen"].find((p) => existsSync(p));
  if (brew) assert.equal(builtInFido(brew, {}), true, `${brew} has built-in FIDO support`);
  const named = fidoKeygen({ PATH: "/usr/bin:/bin", DFIRSWARM_SSH_KEYGEN: apple });
  assert.deepEqual(named, { path: apple, how: "DFIRSWARM_SSH_KEYGEN" }, "the operator's choice is taken as it is");
  assert.match(String((fidoKeygen({ PATH: "/usr/bin:/bin", DFIRSWARM_SSH_KEYGEN: "/nowhere/ssh-keygen" }) as { why: string }).why), /not there/);
  const provider = fidoKeygen({ PATH: "/nonexistent-dir", SSH_SK_PROVIDER: "/usr/lib/libsk.so" });
  if (!brew) assert.match(String((provider as { why: string }).why ?? ""), /no ssh-keygen with FIDO support/);
});

test("prepare renders the final bytes once into a pending directory and says what will be signed; seal signs exactly those bytes with the passphrase", async () => {
  const r = await stoppedRun();
  const ex = enrolSsh(r);
  await dispose(r);
  const p = await prepareRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(p.version, 1, "the machine's draft is v0, written first");
  assert.match(p.nonce, /^[0-9a-f]{32}$/);
  const dir = join(r.root, "release", `.pending-${p.nonce}`);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  for (const f of readdirSync(dir)) assert.equal(statSync(join(dir, f)).mode & 0o777, 0o600, f);
  assert.deepEqual(readdirSync(dir).sort(), ["pending.json", "record.json", "report.html"]);
  const html = readFileSync(join(dir, "report.html"), "utf8");
  assert.doesNotMatch(html, /class="watermark"/, "the final bytes carry no DRAFT mark");
  assert.equal(p.report.html.sha256, sha(html));
  assert.deepEqual([p.gate.adopted, p.gate.withdrawn, p.gate.inconclusive, p.gate.not_adopted], [1, 1, 1, 2]);
  assert.equal(p.signer.kind, "ssh");
  assert.equal(p.signer.secret, "passphrase");
  assert.equal(p.signer.fingerprint, ex.key.fingerprint);
  assert.equal(p.statement, "I have read the report and the answers I adopt");
  assert.equal(readReleases(r.root).length, 1, "prepare writes no release");
  // A wrong passphrase signs nothing, and the prepared release waits for another try.
  await assert.rejects(sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: ex.id, secret: Buffer.from("wrong horse"), consent: "confirmed", via: "cli", home: r.home, say: quiet }), (e: Error) => e instanceof WrongSecretError && /incorrect passphrase/.test(e.message));
  assert.ok(existsSync(join(dir, "pending.json")));
  assert.ok(!existsSync(join(dir, "release.json")), "the failed attempt left no record behind");
  // Bytes shown that are not the bytes prepared: refused.
  await assert.rejects(sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: "0".repeat(64), examiner: ex.id, secret: secret(), consent: "confirmed", via: "cli", home: r.home, say: quiet }), /the report shown .* is not the one prepared/);
  const w = await sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: ex.id, secret: secret(), consent: "confirmed", via: "cli", home: r.home, say: quiet });
  assert.equal(w.version, 1);
  assert.ok(!existsSync(dir), "the pending directory became release/v1");
  assert.deepEqual(readdirSync(w.dir).sort(), ["release.json", "release.json.sig", "report.html"]);
  assert.equal(sha(readFileSync(join(w.dir, "report.html"))), p.report.html.sha256, "nothing was rendered again after consent");
  const s = w.record.signing;
  assert.ok(s);
  assert.equal(s?.via, "cli");
  assert.equal(s?.consent, "confirmed");
  assert.equal(s?.shown_sha256, p.report.html.sha256);
  assert.equal(s?.nonce, p.nonce);
  assert.deepEqual(s?.key, { kind: "ssh", fingerprint: ex.key.fingerprint });
  assert.match(String(s?.ssh_keygen), /ssh-keygen$/);
  assert.equal(w.record.signer.key_kind, "ssh");
  // The nonce is spent.
  await assert.rejects(sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: ex.id, secret: secret(), consent: "confirmed", via: "cli", home: r.home, say: quiet }), /was sealed already, as v1: a nonce is used once/);
  const v = await verifyReleases(layout(r));
  assert.equal(v.ok, true, v.lines.join("\n"));
  assert.match(v.lines[0], /^Release v0:   DRAFT, .*sealed by this install's machine key \(SHA256:\S+\), not an examiner: machine seal, self-checked/);
  assert.doesNotMatch(v.lines[0], /verified/);
  assert.match(v.lines[1], /signed on the command line, the consent confirmed at \S+ over report\.html as shown/);
  assert.equal(v.signatures[0].state, "self-checked");
});

test("seal refuses what moved since prepare: the review, custody, another release, fifteen minutes; and a console seal refuses a key without a passphrase", async () => {
  const r = await stoppedRun();
  const ex = enrolSsh(r);
  await dispose(r);
  const seal = (nonce: string, shown: string, o: { now?: number; via?: "console" | "cli"; examiner?: string } = {}) => sealPrepared(ctxOf(r), { nonce, shownSha256: shown, examiner: o.examiner ?? ex.id, secret: secret(), consent: "confirmed", via: o.via ?? "cli", home: r.home, say: quiet, now: o.now });
  let p = await prepareRelease(ctxOf(r), { home: r.home, say: quiet });
  await appendReview(r.runs, r.id, r.root, { examiner: "Ada Examiner", examinerId: "ada-examiner", action: "adopt", entry_seq: 20 });
  await assert.rejects(seal(p.nonce, p.report.html.sha256), /no longer stands \(the examiner's review moved since/);
  assert.ok(!existsSync(join(r.root, "release", `.pending-${p.nonce}`)), "a stale prepared release is removed");
  p = await prepareRelease(ctxOf(r), { home: r.home, say: quiet });
  await assert.rejects(seal(p.nonce, p.report.html.sha256, { now: Date.parse(p.prepared_at) + PENDING_TTL_MS + 1000 }), /older than 15 minutes/);
  p = await prepareRelease(ctxOf(r), { home: r.home, say: quiet });
  const custody = join(r.root, "custody.json");
  const text = readFileSync(custody, "utf8");
  writeFileSync(custody, text.replace(/\n$/, " \n"));
  await assert.rejects(seal(p.nonce, p.report.html.sha256), /custody\.json changed since/);
  writeFileSync(custody, text);
  p = await prepareRelease(ctxOf(r), { home: r.home, say: quiet });
  await assert.rejects(seal(p.nonce, p.report.html.sha256, { examiner: "someone-else" }), /is ada-examiner's to seal, not someone-else's/);
  assert.equal(discardPrepared(ctxOf(r), p.nonce), true);
  await assert.rejects(seal(p.nonce, p.report.html.sha256), /there is no prepared release .*: it expired, was discarded, or was never prepared/);
  // The console refuses a key with no passphrase, at prepare and at seal.
  const plain = enrollPerson({ name: "Pat Plain", organisation: "Lab", competence: "x", generateKey: true, noPassphrase: true }, r.home);
  assert.ok(!("why" in plain));
  await assert.rejects(prepareRelease(ctxOf(r), { home: r.home, examiner: "pat-plain", via: "console", say: quiet }), /has no passphrase: the console signs only with a key that needs one/);
  // The gate runs again at seal: consent never waives a defect.
  p = await prepareRelease(ctxOf(r), { home: r.home, examiner: ex.id, say: quiet });
  const w = await seal(p.nonce, p.report.html.sha256);
  assert.equal(w.version, 1);
});

test("--yes is recorded as the consent presented, never confirmed; the CLI refuses to sign with no terminal and no --yes", async () => {
  const r = await stoppedRun();
  enrolSsh(r, { noPassphrase: true });
  await dispose(r);
  const cli = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "release.ts"), "sign", "--runs", r.runs, "--run", r.id, "--sandbox", r.root, ...args], { encoding: "utf8", env: { ...process.env, DFIRSWARM_HOME: r.home, SWARM_SIGNERS_HOME: r.home }, detached: true } as never) as unknown as { status: number; stdout: string; stderr: string };
  const refused = cli();
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /asks for the examiner's confirmation on the terminal, and there is none/);
  assert.equal(readReleases(r.root).length, 0, "nothing was prepared, and no draft either");
  const ok = cli("--yes");
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /Consent: {6}presented; its confirmation was skipped \(--yes\)/);
  assert.match(ok.stdout, /Key: {10}ssh key SHA256:\S+ \(made at enrolment; NO PASSPHRASE/);
  const v1 = readReleases(r.root).find((x) => x.version === 1);
  assert.equal(v1?.record?.signing?.consent, "presented");
});

test("an e-signature certificate on a token: enrolled without the PIN, never showing the subject's serialNumber; a CAdES signature with the PIN on fd 3, checked against the CA", async (t) => {
  const tok = softToken();
  if ("why" in tok) {
    t.skip(`SoftHSM2 test token unavailable: ${tok.why}`);
    return;
  }
  const was = process.env.SOFTHSM2_CONF;
  process.env.SOFTHSM2_CONF = tok.env.SOFTHSM2_CONF;
  try {
    const r = await stoppedRun();
    const e = enrollPerson({ name: "Ada Examiner", organisation: "Lab One", competence: "Nitelikli elektronik sertifika", pkcs11Module: tok.module, pkcs11Id: tok.id }, r.home);
    assert.ok(!("why" in e), JSON.stringify(e));
    if ("why" in e) return;
    const k = e.person.key;
    assert.equal(k.kind, "pkcs11");
    if (k.kind !== "pkcs11") return;
    assert.match(k.fingerprint, /^X509-SHA256:[0-9a-f]{64}$/);
    assert.equal(k.certificate.cn, "Ada Examiner");
    assert.equal(k.certificate.issuer, "DFIR Swarm Test Qualified CA, Test Trust Services");
    assert.deepEqual(k.certificate.key_usage, ["digitalSignature", "nonRepudiation"]);
    assert.equal(k.certificate.qc_statement, true);
    assert.deepEqual(k.certificate.qc_statements, ["0.4.0.1862.1.1"]);
    assert.equal(e.register, "", "a certificate has no register line: its issuer vouches for it");
    // What is shown never carries the subject's serialNumber (the PEM kept in the record does, as the certificate does).
    for (const shown of [JSON.stringify(personSummary(e.person)), keyWords(k)]) assert.ok(!shown.includes(SUBJECT_SERIAL), shown);
    const list = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(import.meta.dirname, "..", "scripts", "signers.ts"), "show", "ada-examiner"], { encoding: "utf8", env: { ...process.env, SWARM_SIGNERS_HOME: r.home } });
    assert.equal(list.status, 0, list.stderr);
    assert.ok(!`${list.stdout}${list.stderr}`.includes(SUBJECT_SERIAL));
    assert.match(list.stdout, /Console: {6}can sign from the console/);
    // Refused: a certificate that cannot sign, an id with nothing there.
    tok.otherCert({ id: "0417", keyUsage: "keyEncipherment" });
    const noSign = enrollPerson({ name: "Enc Only", organisation: "Lab", competence: "x", pkcs11Module: tok.module, pkcs11Id: "0417" }, r.home);
    assert.match((noSign as { why: string }).why, /key usage lacks digitalSignature and nonRepudiation/);
    const none = enrollPerson({ name: "Nobody", organisation: "Lab", competence: "x", pkcs11Module: tok.module, pkcs11Id: "0999" }, r.home);
    assert.match((none as { why: string }).why, /reading the certificate from the token/);
    assert.ok(!(none as { why: string }).why.includes(SUBJECT_SERIAL));
    // The adoption: the PIN on fd 3; a wrong one signs nothing.
    await dispose(r);
    const was2 = process.env.SWARM_CHROME;
    process.env.SWARM_CHROME = await fakeChrome();
    try {
      const p = await prepareRelease(ctxOf(r), { home: r.home, pdf: true, say: quiet });
      assert.equal(p.signer.secret, "pin");
      await assert.rejects(sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: "ada-examiner", secret: Buffer.from("00000000"), consent: "confirmed", via: "console", home: r.home, say: quiet }), (err: Error) => err instanceof WrongSecretError && !err.message.includes(SUBJECT_SERIAL));
      const w = await sealPrepared(ctxOf(r), { nonce: p.nonce, shownSha256: p.report.html.sha256, examiner: "ada-examiner", secret: Buffer.from(TEST_PIN), consent: "confirmed", via: "console", home: r.home, say: quiet });
      assert.deepEqual(readdirSync(w.dir).sort(), ["release.json", "release.json.p7s", "report.html", "report.pdf", "report.pdf.p7s"]);
      assert.equal(w.record.signer.key_kind, "pkcs11");
      assert.equal(w.record.signer.public, "");
      assert.equal(w.record.signer.certificate?.sha256, k.certificate.sha256);
      assert.ok(!readFileSync(join(w.dir, "release.json"), "utf8").includes(SUBJECT_SERIAL), "the release names the certificate by its hash and CN");
      assert.equal(w.record.signing?.openssl !== null, true);
      // CAdES-BES: the signing-certificate-v2 attribute is in the CMS.
      const printed = spawnSync("openssl", ["cms", "-cmsout", "-print", "-inform", "DER", "-in", join(w.dir, "release.json.p7s")], { encoding: "utf8" });
      if (printed.status === 0) assert.match(printed.stdout, /signingCertificateV2|1\.2\.840\.113549\.1\.9\.16\.2\.47/);
      let v = await verifyReleases(layout(r));
      assert.equal(v.ok, true, v.lines.join("\n"));
      assert.match(v.lines[1], /e-signature certificate X509-SHA256:[0-9a-f]{64}\): signature valid, by Ada Examiner .*certificate chain not checked \(--ca FILE\)/);
      assert.match(v.lines[1], /report\.pdf's e-signature: signature valid/);
      assert.equal(v.signatures[1].state, "unchecked");
      // The root alone does not reach the certificate: the issuing CA is not in the CMS (no --pkcs11-chain) nor given.
      v = await verifyReleases(layout(r), { ca: tok.ca });
      assert.equal(v.ok, false);
      assert.match(v.lines.join("\n"), /certificate chain does not verify against the trust anchor\(s\) in .*DFIR Swarm Test Root sha256 [0-9a-f]{64}/);
      v = await verifyReleases(layout(r), { ca: tok.ca, caIntermediate: tok.intermediate });
      assert.equal(v.ok, true, v.lines.join("\n"));
      assert.equal(v.signatures[1].state, "verified");
      assert.match(v.lines[1], /its chain verified against the trust anchor\(s\) in \S+ \(DFIR Swarm Test Root sha256 [0-9a-f]{64}\), with the intermediates in/);
      for (const l of v.lines) assert.ok(!l.includes(SUBJECT_SERIAL), l);
      // Bytes changed under the CMS: not verified.
      const rel = join(w.dir, "release.json");
      const text = readFileSync(rel, "utf8");
      chmodSync(rel, 0o644);
      writeFileSync(rel, text.replace('"adopted by the examiner"', '"adopted twice"'));
      v = await verifyReleases(layout(r), { ca: tok.ca, caIntermediate: tok.intermediate });
      assert.equal(v.ok, false);
      assert.match(v.lines.join("\n"), /SIGNATURE: DOES NOT VERIFY/);
    } finally {
      if (was2 === undefined) delete process.env.SWARM_CHROME;
      else process.env.SWARM_CHROME = was2;
    }
    // Enrolled with the issuing CA's certificate (--pkcs11-chain), each CMS carries it: the root alone verifies.
    const r3 = await stoppedRun();
    const withChain = enrollPerson({ name: "Ada Examiner", organisation: "Lab One", competence: "x", pkcs11Module: tok.module, pkcs11Id: tok.id, pkcs11Chain: tok.intermediate }, r3.home);
    assert.ok(!("why" in withChain), JSON.stringify(withChain));
    if (!("why" in withChain) && withChain.person.key.kind === "pkcs11") {
      assert.deepEqual(withChain.person.key.chain?.certs.map((c) => c.cn), ["DFIR Swarm Test Qualified CA"]);
      await dispose(r3);
      const p3 = await prepareRelease(ctxOf(r3), { home: r3.home, say: quiet });
      await sealPrepared(ctxOf(r3), { nonce: p3.nonce, shownSha256: p3.report.html.sha256, examiner: "ada-examiner", secret: Buffer.from(TEST_PIN), consent: "confirmed", via: "cli", home: r3.home, say: quiet });
      const v3 = await verifyReleases(layout(r3), { ca: tok.ca });
      assert.equal(v3.ok, true, v3.lines.join("\n"));
      assert.equal(v3.signatures[1].state, "verified");
    }
    assert.match(String((enrollPerson({ name: "No Chain", organisation: "L", competence: "x", pkcs11Module: tok.module, pkcs11Id: tok.id, pkcs11Chain: join(r.home, "missing.pem") }, r.home) as { why: string }).why), /no certificate file at/);
    // Signing checks the token still holds the enrolled certificate.
    const moved = { ...e.person, key: { ...k, id: "0417" } } as Person;
    const { signAs } = await import("../scripts/signers.ts");
    const f = join(r.home, "x.txt");
    writeFileSync(f, "x\n");
    const s = signAs(moved, f, "dfirswarm-release", Buffer.from(TEST_PIN));
    assert.equal(s.ok, false);
    assert.match((s as { why: string }).why, /is not the enrolled one .*nothing was signed/);
  } finally {
    if (was === undefined) delete process.env.SOFTHSM2_CONF;
    else process.env.SOFTHSM2_CONF = was;
    tok.cleanup();
  }
});

test("a certificate's key usage and qcStatements are read from its DER; a PKCS#11 URI loses its PIN and type", () => {
  const d = mkdtempSync(join(tmpdir(), "dfs-cert-"));
  try {
    writeFileSync(join(d, "ext.cnf"), "keyUsage=critical,digitalSignature,nonRepudiation\n1.3.6.1.5.5.7.1.3=DER:30:0a:30:08:06:06:04:00:8e:46:01:01\n");
    const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", join(d, "k"), "-out", join(d, "c.pem"), "-days", "2", "-subj", "/serialNumber=12345/CN=Test Person", "-extensions", "v3", "-config", "/dev/stdin"], { input: `[req]\ndistinguished_name=dn\n[dn]\n[v3]\nkeyUsage=critical,digitalSignature,nonRepudiation\n1.3.6.1.5.5.7.1.3=DER:30:0a:30:08:06:06:04:00:8e:46:01:01\n`, encoding: "utf8" });
    if (r.status !== 0) return;
    const info = certInfo(readFileSync(join(d, "c.pem")));
    assert.equal(info.cn, "Test Person");
    assert.deepEqual(info.key_usage, ["digitalSignature", "nonRepudiation"]);
    assert.equal(info.qc_statement, true);
    assert.ok(!JSON.stringify({ ...info, pem: "" }).includes("12345"), "nothing shown carries the subject's serialNumber");
    assert.deepEqual(certExtensions(Buffer.from(info.pem.replace(/-----[^-]+-----|\s/g, ""), "base64")).qc_statements, ["0.4.0.1862.1.1"]);
  } finally {
    spawnSync("rm", ["-rf", d]);
  }
  assert.deepEqual(tokenUri({ uri: "pkcs11:token=T%20X;id=%04%16;type=private;pin-value=1234" }), { uri: "pkcs11:token=T%20X;id=%04%16", id: "0416", token: "T X" });
  assert.deepEqual(tokenUri({ id: "04:16" }), { uri: "pkcs11:id=%04%16", id: "0416", token: null });
  assert.match(String((tokenUri({ uri: "pkcs11:token=T" }) as { why: string }).why), /names no object id/);
});

test("signRelease without a secret still signs with a key that has none, and records the consent as presented", async () => {
  const r = await stoppedRun();
  enrolSsh(r, { noPassphrase: true });
  await dispose(r);
  const w = await signRelease(ctxOf(r), { home: r.home, say: quiet });
  assert.equal(w.record.signing?.consent, "presented");
  assert.equal(w.record.signing?.via, "cli");
  const anchor = JSON.parse(readFileSync(custodyAnchorPath(r.root), "utf8")) as { releases: Array<{ version: number }> };
  assert.deepEqual(anchor.releases.map((x) => x.version), [0, 1]);
  await appendFile(join(r.root, "work", "unrelated.txt"), "x");
});

test("the release binds what the kickoff recorded of the signing keys' reach, and verify says when they were not hidden", async () => {
  const exposed = await stoppedRun({
    registry: {
      isolation: { mode: "host" },
      signer_keys_hidden: false,
      signer_isolation: { isolation: "host", guard: "none", keys_hidden: false, hidden: [], agent_sockets: [], exposed: ["/home/x/.dfirswarm/machine/release_ed25519"], exposure_accepted: true, why: "no write guard on this host" },
      earlier_runs_hidden: { by: null, sandboxes: 0, reviews: null, skipped: [], why: "no guard" },
    },
  });
  const { draftRelease } = await import("../scripts/release.ts");
  const d = await draftRelease(ctxOf(exposed), { home: exposed.home, say: quiet });
  const host = d.written?.record.host;
  assert.equal(host?.signer_keys_hidden, false);
  assert.equal(host?.signer_isolation?.exposure_accepted, true);
  assert.deepEqual(host?.signer_isolation?.exposed, ["/home/x/.dfirswarm/machine/release_ed25519"]);
  assert.equal(host?.earlier_runs_hidden?.by, null);
  assert.match(String(host?.note), /the signers' keys were NOT hidden from their panes \(no write guard on this host; started with --accept-signer-exposure\): .*rotate the machine key/);
  const v = await verifyReleases(layout(exposed));
  assert.match(v.lines[0], /the host: the agents ran on the host \(host mode\), and the signers' keys were NOT hidden/);
  const hidden = await stoppedRun({ registry: { isolation: { mode: "host" }, signer_keys_hidden: true, signer_isolation: { isolation: "host", guard: "seatbelt", keys_hidden: true, hidden: ["/x"], agent_sockets: [], exposed: [], exposure_accepted: false, why: "denied at the kernel" } } });
  await draftRelease(ctxOf(hidden), { home: hidden.home, say: quiet });
  const v2 = await verifyReleases(layout(hidden));
  assert.doesNotMatch(v2.lines[0], /the host:/, "keys hidden from the panes: nothing to say");
});
