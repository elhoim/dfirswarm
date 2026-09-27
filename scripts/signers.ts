#!/usr/bin/env node
/**
 * Who seals a release, kept apart by kind and by wording everywhere:
 *
 * - the machine: one key per install of DFIR Swarm, made once, the first
 *   time a release is sealed, and kept outside every run
 *   ($DFIRSWARM_HOME/machine/, 0700). It seals the draft the harness writes
 *   when custody is taken at stop: a record of what the host held then. It
 *   is not an examiner, it has no name and no competence, and a release it
 *   seals is adopted by no one;
 * - an examiner: a person enrolled on this install on purpose
 *   (`swarm.sh examiner enroll`): name, organisation, a competence
 *   statement, and an ssh key they gave or asked to have made. Enrolment
 *   prints the key's fingerprint and the line for the organisation's signer
 *   register (an allowed-signers file). Possession of the key is what the
 *   signature shows; that the key is that person's is what the register,
 *   kept by the organisation and checked in person, shows. Without a
 *   register the tie is the fingerprint alone, and every check says so.
 *
 * Signatures are ssh's (ssh-keygen -Y sign), over files, detached. No key's
 * private half is ever read, printed or copied here: ssh-keygen reads it,
 * and asks for its passphrase itself when it has one (or uses the agent,
 * or a hardware key).
 *
 *   node scripts/signers.ts enroll --name NAME --organisation ORG --competence TEXT
 *        (--key FILE | --generate-key [--no-passphrase]) [--id ID] [--principal P]
 *        [--tsa-url URL --tsa-ca FILE]
 *   node scripts/signers.ts list | show ID | machine
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, hostname, tmpdir, userInfo } from "node:os";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** The namespace a release's signature is made in: a signature from another use of the same key is not one. */
export const RELEASE_NAMESPACE = "dfirswarm-release";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/**
 * Where an install keeps what is its own and no run's: the machine key and
 * the examiners, under $DFIRSWARM_HOME (~/.dfirswarm), or SWARM_SIGNERS_HOME
 * when the signers are kept apart from the packs (the shell suites keep
 * theirs in a temporary home).
 */
export function dfirswarmHome(env: NodeJS.ProcessEnv = process.env): string {
  return resolve(env.SWARM_SIGNERS_HOME || env.DFIRSWARM_HOME || join(homedir(), ".dfirswarm"));
}

function run(cmd: string, args: string[], o: { input?: string | Buffer; tty?: boolean } = {}): { code: number; out: string; err: string; missing: boolean } {
  // With a tty, ssh-keygen asks for a passphrase on it (it reads /dev/tty itself).
  const r = spawnSync(cmd, args, { input: o.input, stdio: o.tty ? ["inherit", "pipe", "pipe"] : ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
  const missing = (r.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
  return { code: r.status ?? 1, out: String(r.stdout ?? ""), err: String(r.stderr ?? ""), missing };
}

/** An ssh public key line's fingerprint (SHA256:…), from ssh-keygen, or null. */
export function fingerprintOf(publicKey: string): string | null {
  const r = run("ssh-keygen", ["-l", "-f", "-"], { input: `${publicKey.trim()}\n` });
  return r.code === 0 ? (r.out.trim().split(/\s+/)[1] ?? null) : null;
}

/** The key type and its base64, the part of a public key line an allowed-signers file names. */
export function publicKeyCore(publicKey: string): string {
  return publicKey.trim().split(/\s+/).slice(0, 2).join(" ");
}

/** A principal an allowed-signers file can carry: one word, no pattern characters. */
export const PRINCIPAL = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;

// --- signing and checking -------------------------------------------------------------

/** Sign `file` in `namespace`: `<file>.sig` beside it. The key's passphrase, when it has one, is asked on the tty by ssh-keygen. */
export function sshSign(file: string, key: string, namespace: string): { ok: true; sig: string; sha256: string } | { ok: false; why: string } {
  if (!existsSync(key)) return { ok: false, why: `no key at ${key}` };
  rmSync(`${file}.sig`, { force: true });
  const r = run("ssh-keygen", ["-Y", "sign", "-f", key, "-n", namespace, file], { tty: Boolean(process.stdin.isTTY) });
  if (r.missing) return { ok: false, why: "ssh-keygen is not on this host" };
  if (r.code !== 0 || !existsSync(`${file}.sig`)) return { ok: false, why: `ssh-keygen -Y sign failed: ${r.err.trim().split("\n").filter((l) => !/^Signing file|^Write signature/.test(l)).join(" ") || `exit ${r.code}`}` };
  return { ok: true, sig: `${file}.sig`, sha256: sha256(readFileSync(`${file}.sig`)) };
}

/**
 * What a signature over `file` shows:
 * - verified: an allowed-signers file (the organisation's register) names
 *   this principal with the key that made it;
 * - unchecked: it is sound under the key the record names, and who holds
 *   that key was not checked (no register given);
 * - unlisted: it is sound under the key the record names, and the register
 *   given does not list that key at all;
 * - wrong-principal: the register lists the key, under another principal;
 * - bad: it does not verify.
 */
export type SignatureState = "verified" | "unchecked" | "unlisted" | "wrong-principal" | "bad";

export function checkSshSignature(o: { file: string; sig: string; namespace: string; principal: string; publicKey: string; allowedSigners?: string }): { state: SignatureState; detail: string } {
  if (!existsSync(o.sig)) return { state: "bad", detail: `no signature at ${o.sig}` };
  if (!existsSync(o.file)) return { state: "bad", detail: `no file at ${o.file}` };
  const data = readFileSync(o.file);
  const selfCheck = (): { ok: boolean; detail: string } => {
    if (!PRINCIPAL.test(o.principal) || !/^[a-z0-9-]+@?[a-z0-9.-]* [A-Za-z0-9+/=]+$/.test(publicKeyCore(o.publicKey))) return { ok: false, detail: "the record names no usable principal and key" };
    const dir = mkdtempSync(join(tmpdir(), "dfs-signers-"));
    try {
      const allowed = join(dir, "allowed");
      writeFileSync(allowed, `${o.principal} namespaces="${o.namespace}" ${publicKeyCore(o.publicKey)}\n`);
      const r = run("ssh-keygen", ["-Y", "verify", "-f", allowed, "-I", o.principal, "-n", o.namespace, "-s", o.sig], { input: data });
      return { ok: r.code === 0, detail: `${r.out}${r.err}`.trim() };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  if (!o.allowedSigners) {
    const s = selfCheck();
    return s.ok
      ? { state: "unchecked", detail: `sound under the key the record names (${fingerprintOf(o.publicKey) ?? "fingerprint unread"}); who holds it was not checked: no allowed-signers file` }
      : { state: "bad", detail: `DOES NOT VERIFY under the key the record names: ${s.detail}` };
  }
  if (!existsSync(o.allowedSigners)) return { state: "bad", detail: `no allowed-signers file at ${o.allowedSigners}` };
  const found = run("ssh-keygen", ["-Y", "find-principals", "-s", o.sig, "-f", o.allowedSigners, "-n", o.namespace]);
  const principals = found.code === 0 ? found.out.split("\n").map((l) => l.trim()).filter(Boolean) : [];
  if (!principals.length) {
    const s = selfCheck();
    return s.ok
      ? { state: "unlisted", detail: `sound under the key the record names (${fingerprintOf(o.publicKey) ?? "fingerprint unread"}), a key ${o.allowedSigners} does not list` }
      : { state: "bad", detail: `DOES NOT VERIFY: ${s.detail}` };
  }
  if (!principals.includes(o.principal)) return { state: "wrong-principal", detail: `made by a key ${o.allowedSigners} lists for ${principals.join(", ")}, NOT for ${o.principal}, the signer the record names` };
  const r = run("ssh-keygen", ["-Y", "verify", "-f", o.allowedSigners, "-I", o.principal, "-n", o.namespace, "-s", o.sig], { input: data });
  return r.code === 0 ? { state: "verified", detail: `by ${o.principal}, a signer ${o.allowedSigners} allows` } : { state: "bad", detail: `DOES NOT VERIFY for ${o.principal}: ${`${r.out}${r.err}`.trim()}` };
}

// --- the machine --------------------------------------------------------------------------

export type MachineSigner = {
  kind: "machine";
  v: 1;
  id: string;
  principal: string;
  /** The private key's path (never its bytes). */
  key: string;
  public: string;
  fingerprint: string;
  host: string;
  created_at: string;
  label: string;
};

export const MACHINE_LABEL =
  "this install's machine key: it seals the draft the harness writes when custody is taken at stop. It is not an examiner and adopts nothing; a release it seals is a record of what the host held, not anyone's opinion";

/**
 * This install's machine key, made the first time it is asked for (with no
 * passphrase: it seals at stop, when nobody is there to type one). `create:
 * false` only reads it.
 */
export function machineSigner(home = dfirswarmHome(), o: { create?: boolean } = {}): MachineSigner | { why: string } {
  const dir = join(home, "machine");
  const meta = join(dir, "machine.json");
  const key = join(dir, "release_ed25519");
  if (existsSync(meta) && existsSync(key)) {
    try {
      const m = JSON.parse(readFileSync(meta, "utf8")) as MachineSigner;
      return { ...m, key };
    } catch (err) {
      return { why: `${meta} is not readable JSON (${(err as Error).message})` };
    }
  }
  if (o.create === false) return { why: `this install has no machine key yet (${dir})` };
  if (existsSync(key) || existsSync(meta)) return { why: `${dir} holds half a machine key (the key or its record without the other): look before anything is made again` };
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const id = randomBytes(6).toString("hex");
  const principal = `dfirswarm-machine-${id}`;
  const made = run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", principal, "-f", key]);
  if (made.missing) return { why: "ssh-keygen is not on this host" };
  if (made.code !== 0) return { why: `ssh-keygen could not make the machine key: ${made.err.trim()}` };
  const pub = readFileSync(`${key}.pub`, "utf8").trim();
  const m: MachineSigner = {
    kind: "machine",
    v: 1,
    id,
    principal,
    key,
    public: pub,
    fingerprint: fingerprintOf(pub) ?? "unknown",
    host: hostname(),
    created_at: new Date().toISOString(),
    label: MACHINE_LABEL,
  };
  writeFileSync(meta, `${JSON.stringify(m, null, 2)}\n`, { mode: 0o600 });
  return m;
}

// --- examiners ------------------------------------------------------------------------------

export type Examiner = {
  kind: "examiner";
  v: 1;
  id: string;
  name: string;
  organisation: string;
  competence: string;
  principal: string;
  key: {
    /** What ssh-keygen signs with: the private key, or a public key whose private half is in the agent or on a hardware key. Its path, never its bytes. */
    path: string;
    public: string;
    fingerprint: string;
    /** Made at enrolment because the examiner asked (--generate-key), not given. */
    generated: boolean;
  };
  /** The RFC 3161 authority the examiner's releases are timestamped by, and its CA certificates. */
  tsa: { url: string; ca: string | null; ca_sha256: string | null } | null;
  enrolled_at: string;
  enrolled_by: { os_user: string; host: string };
};

export const EXAMINER_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;

export function examinersDir(home = dfirswarmHome()): string {
  return join(home, "examiners");
}

/** The allowed-signers line an organisation's register carries for this examiner. */
export function allowedSignersLine(e: Pick<Examiner, "principal" | "key">): string {
  return `${e.principal} namespaces="${RELEASE_NAMESPACE},dfirswarm-package" ${publicKeyCore(e.key.public)}`;
}

/** An enrolled examiner by id, or why there is none. */
export function loadExaminer(id: string, home = dfirswarmHome()): { examiner: Examiner; sha256: string } | { why: string } {
  if (!EXAMINER_ID.test(id)) return { why: `${JSON.stringify(id)} is not an examiner id (lower-case letters, digits and dashes)` };
  const file = join(examinersDir(home), `${id}.json`);
  if (!existsSync(file)) return { why: `no examiner ${id} is enrolled on this install (swarm.sh examiner enroll)` };
  try {
    const text = readFileSync(file, "utf8");
    const e = JSON.parse(text) as Examiner;
    if (e.kind !== "examiner" || e.id !== id) return { why: `${file} is not an examiner's enrolment` };
    return { examiner: e, sha256: sha256(text) };
  } catch (err) {
    return { why: `${file} is not readable JSON (${(err as Error).message})` };
  }
}

export function listExaminers(home = dfirswarmHome()): Examiner[] {
  const dir = examinersDir(home);
  if (!existsSync(dir)) return [];
  const out: Examiner[] = [];
  for (const f of readdirSync(dir).sort()) {
    if (!f.endsWith(".json")) continue;
    const r = loadExaminer(basename(f, ".json"), home);
    if ("examiner" in r) out.push(r.examiner);
  }
  return out;
}

export type EnrollInput = {
  name: string;
  organisation: string;
  competence: string;
  id?: string;
  principal?: string;
  key?: string;
  generateKey?: boolean;
  noPassphrase?: boolean;
  tsaUrl?: string;
  tsaCa?: string;
};

const slug = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);

/**
 * Enrol an examiner: the record outside every run, the key checked by
 * signing a challenge with it and verifying that with its public half
 * (so a wrong path or a key the agent does not hold is refused now, not at
 * the first sign-off). A key is made only when asked (--generate-key).
 */
export function enrollExaminer(input: EnrollInput, home = dfirswarmHome()): { examiner: Examiner; file: string; register: string } | { why: string } {
  const name = input.name?.trim();
  const organisation = input.organisation?.trim();
  const competence = input.competence?.trim();
  if (!name) return { why: "an examiner's name is required (--name)" };
  if (!organisation) return { why: "the organisation the examiner signs for is required (--organisation)" };
  if (!competence) return { why: "a competence statement is required (--competence): what qualifies this person to adopt a forensic report" };
  if (!input.key === !input.generateKey) return { why: "give the examiner's key (--key FILE) or ask for one to be made (--generate-key), one of the two" };
  const id = input.id ?? slug(name);
  if (!EXAMINER_ID.test(id)) return { why: `${JSON.stringify(id)} is not an examiner id: lower-case letters, digits and dashes (--id)` };
  const principal = input.principal ?? id;
  if (!PRINCIPAL.test(principal)) return { why: `${JSON.stringify(principal)} cannot be an allowed-signers principal: one word of letters, digits and . _ @ + - (--principal)` };
  const dir = examinersDir(home);
  const file = join(dir, `${id}.json`);
  if (existsSync(file)) return { why: `an examiner ${id} is enrolled already (${file}); a new key is a new enrolment under another id` };
  if (input.tsaUrl && !/^https?:\/\//.test(input.tsaUrl)) return { why: `${input.tsaUrl} is not an http(s) URL (--tsa-url)` };
  if (input.tsaCa && !existsSync(input.tsaCa)) return { why: `no CA file at ${input.tsaCa} (--tsa-ca)` };
  if (input.tsaCa && !input.tsaUrl) return { why: "a CA without an authority: give --tsa-url with --tsa-ca" };
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  let keyPath: string;
  let pub: string;
  if (input.generateKey) {
    const keys = join(dir, "keys");
    mkdirSync(keys, { recursive: true, mode: 0o700 });
    keyPath = join(keys, `${id}_ed25519`);
    if (existsSync(keyPath)) return { why: `${keyPath} exists already: it is not made over` };
    // A passphrase unless the examiner said none: ssh-keygen asks for it on the tty.
    const r = run("ssh-keygen", ["-q", "-t", "ed25519", "-C", principal, "-f", keyPath, ...(input.noPassphrase ? ["-N", ""] : [])], { tty: !input.noPassphrase });
    if (r.missing) return { why: "ssh-keygen is not on this host" };
    if (r.code !== 0 || !existsSync(`${keyPath}.pub`)) return { why: `ssh-keygen could not make the key: ${r.err.trim() || `exit ${r.code}`}` };
    pub = readFileSync(`${keyPath}.pub`, "utf8").trim();
  } else {
    keyPath = resolve(String(input.key));
    if (!existsSync(keyPath)) return { why: `no key at ${keyPath} (--key)` };
    const pubFile = keyPath.endsWith(".pub") ? keyPath : `${keyPath}.pub`;
    if (existsSync(pubFile)) pub = readFileSync(pubFile, "utf8").trim();
    else {
      const r = run("ssh-keygen", ["-y", "-f", keyPath], { tty: Boolean(process.stdin.isTTY) });
      if (r.code !== 0) return { why: `the public half of ${keyPath} could not be read: ${r.err.trim() || `exit ${r.code}`}` };
      pub = r.out.trim();
    }
  }
  const fingerprint = fingerprintOf(pub);
  if (!fingerprint) return { why: `${keyPath} is not an ssh key ssh-keygen can read` };
  // Proof of possession: a challenge signed and verified, in a scratch directory.
  const scratch = mkdtempSync(join(tmpdir(), "dfs-enrol-"));
  try {
    const challenge = join(scratch, "challenge");
    writeFileSync(challenge, `DFIR Swarm examiner enrolment ${id} ${randomBytes(16).toString("hex")}\n`);
    const signed = sshSign(challenge, keyPath, RELEASE_NAMESPACE);
    if (!signed.ok) return { why: `the key could not sign (${signed.why}): nothing was enrolled` };
    const checked = checkSshSignature({ file: challenge, sig: signed.sig, namespace: RELEASE_NAMESPACE, principal, publicKey: pub });
    if (checked.state !== "unchecked") return { why: `a signature made with ${keyPath} does not verify under its public half: ${checked.detail}` };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  const tsaCaSha = input.tsaCa ? sha256(readFileSync(input.tsaCa)) : null;
  const e: Examiner = {
    kind: "examiner",
    v: 1,
    id,
    name,
    organisation,
    competence,
    principal,
    key: { path: keyPath, public: pub, fingerprint, generated: Boolean(input.generateKey) },
    tsa: input.tsaUrl ? { url: input.tsaUrl, ca: input.tsaCa ? resolve(input.tsaCa) : null, ca_sha256: tsaCaSha } : null,
    enrolled_at: new Date().toISOString(),
    enrolled_by: { os_user: userInfo().username, host: hostname() },
  };
  writeFileSync(file, `${JSON.stringify(e, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return { examiner: e, file, register: allowedSignersLine(e) };
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function describe(e: Examiner): string[] {
  return [
    `Examiner:     ${e.name} (${e.id}), ${e.organisation}`,
    `Competence:   ${e.competence}`,
    `Key:          ${e.key.fingerprint} (${e.key.generated ? "made at enrolment" : "given"}; ${e.key.path})`,
    `Principal:    ${e.principal}`,
    `Timestamps:   ${e.tsa ? `${e.tsa.url}${e.tsa.ca ? `, checked against ${e.tsa.ca}` : ", NO CA: tokens are held to their digest only"}` : "none configured: releases are not timestamped (swarm.sh timestamp <run> later)"}`,
    `Enrolled:     ${e.enrolled_at} by ${e.enrolled_by.os_user}@${e.enrolled_by.host}`,
  ];
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const home = dfirswarmHome();
  switch (cmd) {
    case "enroll": {
      const r = enrollExaminer({
        name: opt(args, "--name") ?? "",
        organisation: opt(args, "--organisation") ?? opt(args, "--organization") ?? "",
        competence: opt(args, "--competence") ?? "",
        id: opt(args, "--id"),
        principal: opt(args, "--principal"),
        key: opt(args, "--key"),
        generateKey: args.includes("--generate-key"),
        noPassphrase: args.includes("--no-passphrase"),
        tsaUrl: opt(args, "--tsa-url"),
        tsaCa: opt(args, "--tsa-ca"),
      }, home);
      if ("why" in r) {
        console.error(`BLOCKER: ${r.why}`);
        return 2;
      }
      for (const l of describe(r.examiner)) console.log(l);
      console.log(`Recorded:     ${r.file} (outside every run)`);
      console.log("");
      console.log("For the organisation's signer register (an ssh allowed-signers file), this line:");
      console.log(`  ${r.register}`);
      console.log(`Check the fingerprint ${r.examiner.key.fingerprint} with ${r.examiner.name} in person before it goes in: the register, not this install, is what ties the key to the person.`);
      if (r.examiner.key.generated && args.includes("--no-passphrase")) console.log("The key has NO passphrase: anyone who can read this account's files can sign as this examiner.");
      return 0;
    }
    case "list": {
      const all = listExaminers(home);
      if (!all.length) console.log(`No examiner is enrolled on this install (${examinersDir(home)}).`);
      for (const e of all) console.log(`${e.id}\t${e.name}\t${e.organisation}\t${e.key.fingerprint}`);
      return 0;
    }
    case "show": {
      const id = args[0] ?? "";
      const r = loadExaminer(id, home);
      if ("why" in r) {
        console.error(r.why);
        return 1;
      }
      for (const l of describe(r.examiner)) console.log(l);
      console.log(`Register:     ${allowedSignersLine(r.examiner)}`);
      return 0;
    }
    case "machine": {
      const m = machineSigner(home, { create: false });
      if ("why" in m) {
        console.log(m.why);
        return 0;
      }
      console.log(`Machine key:  ${m.fingerprint} (${m.principal}), made ${m.created_at} on ${m.host}`);
      console.log(`What it is:   ${m.label}`);
      return 0;
    }
    default:
      console.error("usage: signers.ts enroll … | list | show ID | machine");
      return 2;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`examiner: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    },
  );
}
