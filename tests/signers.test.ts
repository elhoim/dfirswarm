/**
 * Who seals a release (scripts/signers.ts): the install's machine key, made
 * once and labelled as the machine's, and examiners enrolled on purpose,
 * each with a name, an organisation, a competence statement and a key
 * given or made only when asked, checked by signing a challenge, with the
 * line for the organisation's signer register. And what a signature shows:
 * verified against a register, sound under the key the record names,
 * unlisted, listed for another principal, or not a signature at all.
 * Keys are made in temporary directories; none is printed.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allowedSignersLine, checkSshSignature, enrollExaminer, listExaminers, loadExaminer, machineSigner, sshSign, MACHINE_LABEL, RELEASE_NAMESPACE } from "../scripts/signers.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
async function tmp(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

test("the machine key is made once, outside every run, with no passphrase, and says it is the machine's and not an examiner", async () => {
  const home = await tmp("signers-home-");
  assert.match(String((machineSigner(home, { create: false }) as { why: string }).why), /no machine key yet/);
  const m = machineSigner(home);
  assert.ok(!("why" in m), JSON.stringify(m));
  if ("why" in m) return;
  assert.equal(m.kind, "machine");
  assert.match(m.principal, /^dfirswarm-machine-[0-9a-f]{12}$/);
  assert.match(m.fingerprint, /^SHA256:/);
  assert.equal(m.label, MACHINE_LABEL);
  assert.match(m.label, /not an examiner and adopts nothing/);
  assert.equal(statSync(join(home, "machine")).mode & 0o777, 0o700);
  assert.equal(statSync(join(home, "machine", "machine.json")).mode & 0o777, 0o600);
  // Made once: asked again, the same key.
  const again = machineSigner(home);
  assert.ok(!("why" in again) && again.fingerprint === m.fingerprint);
  // It signs without a passphrase, and the signature is sound under its public half.
  const file = join(home, "x.txt");
  writeFileSync(file, "a release\n");
  const s = sshSign(file, m.key, RELEASE_NAMESPACE);
  assert.ok(s.ok, JSON.stringify(s));
  assert.equal(checkSshSignature({ file, sig: `${file}.sig`, namespace: RELEASE_NAMESPACE, principal: m.principal, publicKey: m.public }).state, "unchecked");
  // Half a key is looked at, not made over.
  const half = await tmp("signers-half-");
  execFileSync("mkdir", ["-p", join(half, "machine")]);
  writeFileSync(join(half, "machine", "release_ed25519"), "not a key\n");
  assert.match(String((machineSigner(half) as { why: string }).why), /half a machine key/);
});

test("an examiner is enrolled with a name, an organisation, a competence statement and a key made only when asked; enrolment gives the register line", async () => {
  const home = await tmp("signers-home-");
  const refused = (input: Parameters<typeof enrollExaminer>[0], re: RegExp) => {
    const r = enrollExaminer(input, home);
    assert.ok("why" in r, `enrolled: ${JSON.stringify(input)}`);
    assert.match((r as { why: string }).why, re);
  };
  const base = { name: "Ada Examiner", organisation: "Lab One", competence: "GCFA; ten years of casework", generateKey: true, noPassphrase: true };
  refused({ ...base, name: " " }, /name is required/);
  refused({ ...base, organisation: "" }, /organisation the examiner signs for is required/);
  refused({ ...base, competence: "" }, /competence statement is required/);
  refused({ ...base, generateKey: false }, /give the examiner's key \(--key FILE\) or ask for one to be made/);
  refused({ ...base, key: "/nonexistent" }, /one of the two/);
  refused({ ...base, id: "Ada Examiner" }, /is not an examiner id/);
  refused({ ...base, tsaCa: "/nonexistent.pem", tsaUrl: "http://tsa.test" }, /no CA file at/);
  const r = enrollExaminer(base, home);
  assert.ok(!("why" in r), JSON.stringify(r));
  if ("why" in r) return;
  assert.equal(r.examiner.id, "ada-examiner");
  assert.equal(r.examiner.key.generated, true);
  assert.ok(existsSync(r.examiner.key.path) && r.examiner.key.path.startsWith(join(home, "examiners", "keys")));
  assert.equal(statSync(r.file).mode & 0o777, 0o600);
  assert.equal(r.register, `ada-examiner namespaces="dfirswarm-release,dfirswarm-package" ${r.examiner.key.public.split(" ").slice(0, 2).join(" ")}`);
  assert.equal(allowedSignersLine(r.examiner), r.register);
  assert.doesNotMatch(readFileSync(r.file, "utf8"), /PRIVATE KEY/, "the record names the key's path, never its bytes");
  // Enrolled once under an id: a new key is a new enrolment.
  refused(base, /is enrolled already/);
  const loaded = loadExaminer("ada-examiner", home);
  assert.ok("examiner" in loaded && loaded.examiner.name === "Ada Examiner" && /^[0-9a-f]{64}$/.test(loaded.sha256));
  assert.match(String((loadExaminer("nobody", home) as { why: string }).why), /no examiner nobody is enrolled/);
  assert.deepEqual(listExaminers(home).map((e) => e.id), ["ada-examiner"]);
});

test("a key given is checked by signing a challenge: a public half that is not the key's own is refused", async () => {
  const home = await tmp("signers-home-");
  const keys = await tmp("signers-keys-");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "bo@lab", "-f", join(keys, "bo")]);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "other", "-f", join(keys, "other")]);
  const ok = enrollExaminer({ name: "Bo Reviewer", organisation: "Lab Two", competence: "EnCE", key: join(keys, "bo"), principal: "bo@lab.example", tsaUrl: "https://tsa.example/tsr" }, home);
  assert.ok(!("why" in ok), JSON.stringify(ok));
  if (!("why" in ok)) {
    assert.equal(ok.examiner.key.generated, false);
    assert.equal(ok.examiner.principal, "bo@lab.example");
    assert.deepEqual(ok.examiner.tsa, { url: "https://tsa.example/tsr", ca: null, ca_sha256: null });
  }
  // A .pub beside the key that is another key's: the challenge is refused (by ssh-keygen, or by the check), and nothing is enrolled.
  writeFileSync(join(keys, "bo.pub"), readFileSync(join(keys, "other.pub")));
  const bad = enrollExaminer({ name: "Cy Other", organisation: "Lab", competence: "x", key: join(keys, "bo") }, home);
  assert.ok("why" in bad);
  assert.match((bad as { why: string }).why, /doesn't match|does not verify under its public half/);
  assert.equal(loadExaminer("cy-other", home).hasOwnProperty("examiner"), false);
});

test("a signature is verified against a register, sound but unchecked without one, unlisted, listed for another principal, or bad", async () => {
  const d = await tmp("signers-sig-");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "ada", "-f", join(d, "ada")]);
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "eve", "-f", join(d, "eve")]);
  const pub = readFileSync(join(d, "ada.pub"), "utf8").trim();
  const file = join(d, "release.json");
  writeFileSync(file, '{"version":1}\n');
  assert.ok(sshSign(file, join(d, "ada"), RELEASE_NAMESPACE).ok);
  const check = (allowedSigners?: string, principal = "ada") => checkSshSignature({ file, sig: `${file}.sig`, namespace: RELEASE_NAMESPACE, principal, publicKey: pub, allowedSigners });
  assert.equal(check().state, "unchecked");
  const register = join(d, "register");
  writeFileSync(register, `ada namespaces="${RELEASE_NAMESPACE}" ${pub.split(" ").slice(0, 2).join(" ")}\n`);
  assert.equal(check(register).state, "verified");
  writeFileSync(register, `eve namespaces="${RELEASE_NAMESPACE}" ${readFileSync(join(d, "eve.pub"), "utf8").trim().split(" ").slice(0, 2).join(" ")}\n`);
  assert.equal(check(register).state, "unlisted");
  writeFileSync(register, `mallory namespaces="${RELEASE_NAMESPACE}" ${pub.split(" ").slice(0, 2).join(" ")}\n`);
  const wrong = check(register);
  assert.equal(wrong.state, "wrong-principal");
  assert.match(wrong.detail, /for mallory, NOT for ada/);
  // A signature in another namespace is not a release's; bytes changed are not what was signed.
  writeFileSync(file, '{"version":2}\n');
  assert.equal(check().state, "bad");
  writeFileSync(file, '{"version":1}\n');
  rmSync(`${file}.sig`);
  spawnSync("ssh-keygen", ["-Y", "sign", "-f", join(d, "ada"), "-n", "dfirswarm-custody", file]);
  assert.ok(existsSync(`${file}.sig`));
  assert.equal(check().state, "bad");
});
