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
 * - a person enrolled on this install on purpose (`swarm.sh examiner
 *   enroll`), in one role: an examiner, who adopts a report and signs its
 *   release, or a technical reviewer, who signs their own review record.
 *   Name, organisation, a competence statement, and one key of one kind:
 *   - ssh: an ed25519 key file with a passphrase (made here with
 *     --generate-key, or given with --key and checked to be encrypted;
 *     --no-passphrase is a documented trade the console refuses);
 *   - fido: an ed25519-sk key made on a FIDO authenticator by an ssh-keygen
 *     built with FIDO support: a touch signs, plus the PIN when made with
 *     --fido-verify-required; the key-handle file lives here;
 *   - pkcs11: an X.509 certificate on a token (a qualified e-signature card),
 *     read without the PIN; signing makes a CAdES-BES CMS on the token
 *     (scripts/pkcs11.ts).
 *   Enrolment prints the key's fingerprint and, for an ssh or fido key, the
 *   line for the organisation's signer register (an allowed-signers file).
 *   Possession of the key is what the signature shows; that the key is that
 *   person's is what the register (or, for a certificate, its issuer's
 *   chain) shows. Without one the tie is the fingerprint alone, and every
 *   check says so.
 *
 * Signatures are ssh's (ssh-keygen -Y sign, SSHSIG) or CMS, over files,
 * detached. No key's private half is ever read, printed or copied here. A
 * passphrase or a PIN reaches ssh-keygen or openssl only down a pipe on
 * their fd 3 (scripts/secret-io.ts), never in argv, the environment or a
 * file.
 *
 *   node scripts/signers.ts enroll --name NAME --organisation ORG --competence TEXT [--role examiner|reviewer]
 *        (--generate-key [--no-passphrase] | --key FILE [--no-passphrase]
 *         | --fido [--fido-verify-required] [--fido-resident]
 *         | --pkcs11-module PATH (--pkcs11-id HEX | --pkcs11-uri URI) [--pkcs11-chain FILE])
 *        [--id ID] [--principal P] [--tsa-url URL --tsa-ca FILE] [--passphrase-fd N] [--json]
 *   node scripts/signers.ts list [--json] | show ID [--json] | machine
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, hostname, tmpdir, userInfo } from "node:os";
import { basename, delimiter, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { certFingerprint, certRefusal, cmsSign, cmsVerify, pemCerts, readTokenCert, tokenUri, type CertInfo } from "./pkcs11.ts";
import { hasTty, readFromTty, readSecretFromFd, runDetachedWithInput, runWithSecret, signingEnv, wipe } from "./secret-io.ts";

/** The namespace a release's signature is made in: a signature from another use of the same key is not one. */
export const RELEASE_NAMESPACE = "dfirswarm-release";
/** The namespace a technical reviewer's countersignature is made in. */
export const REVIEW_NAMESPACE = "dfirswarm-review";

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

// --- which ssh-keygen -------------------------------------------------------------------------------

function onPath(name: string, env: NodeJS.ProcessEnv): string | null {
  for (const d of (env.PATH ?? "").split(delimiter)) {
    if (!d) continue;
    const p = join(d, name);
    try {
      if (statSync(p).isFile()) return p;
    } catch {
      // not here
    }
  }
  return null;
}

/**
 * Whether an ssh-keygen can make and use a FIDO key by itself, read from its
 * files and never from the authenticator (a probe that talked to a plugged-in
 * key would make it blink and wait for a touch): the ssh-sk-helper it names
 * (or SSH_SK_HELPER) must be built with the internal FIDO support. Apple's
 * says "internal security key support not enabled"; a build with libfido2
 * does not.
 */
export function builtInFido(keygen: string, env: NodeJS.ProcessEnv = process.env): boolean {
  try {
    let helper = env.SSH_SK_HELPER || null;
    if (!helper) {
      const bin = readFileSync(keygen).toString("latin1");
      helper = /\/[\x21-\x7e]*ssh-sk-helper/.exec(bin)?.[0] ?? null;
    }
    if (!helper || !existsSync(helper)) return false;
    const text = readFileSync(helper).toString("latin1");
    return !text.includes("internal security key support not enabled") && text.includes("fido_");
  } catch {
    return false;
  }
}

/**
 * The ssh-keygen a FIDO key is made and used with, and how it was chosen:
 * DFIRSWARM_SSH_KEYGEN when set; else the first with built-in FIDO support
 * of Homebrew's openssh (linked or not) and the one on PATH; else, when
 * SSH_SK_PROVIDER names a middleware library, the one on PATH with it.
 * macOS's own ssh-keygen has no FIDO support ("No FIDO SecurityKeyProvider
 * specified"); a Linux distribution's normally has it built in.
 */
export function fidoKeygen(env: NodeJS.ProcessEnv = process.env): { path: string; how: string } | { why: string } {
  if (env.DFIRSWARM_SSH_KEYGEN) {
    return existsSync(env.DFIRSWARM_SSH_KEYGEN) ? { path: env.DFIRSWARM_SSH_KEYGEN, how: "DFIRSWARM_SSH_KEYGEN" } : { why: `DFIRSWARM_SSH_KEYGEN names ${env.DFIRSWARM_SSH_KEYGEN}, which is not there` };
  }
  const pathKeygen = onPath("ssh-keygen", env);
  for (const p of ["/opt/homebrew/opt/openssh/bin/ssh-keygen", "/usr/local/opt/openssh/bin/ssh-keygen", pathKeygen].filter((x): x is string => Boolean(x))) {
    if (existsSync(p) && builtInFido(p, env)) return { path: p, how: `${p} (built-in FIDO support)` };
  }
  if (env.SSH_SK_PROVIDER && pathKeygen) return { path: pathKeygen, how: `${pathKeygen} with SSH_SK_PROVIDER=${env.SSH_SK_PROVIDER}` };
  return { why: "no ssh-keygen with FIDO support was found: install Homebrew's openssh (brew install openssh libfido2; it need not be linked), or name one with DFIRSWARM_SSH_KEYGEN, or a middleware library with SSH_SK_PROVIDER" };
}

/** The ssh-keygen an ssh key is used with: DFIRSWARM_SSH_KEYGEN, else the one on PATH, as an absolute path. */
export function sshKeygen(env: NodeJS.ProcessEnv = process.env): string {
  return env.DFIRSWARM_SSH_KEYGEN || onPath("ssh-keygen", env) || "ssh-keygen";
}

// --- signing and checking -------------------------------------------------------------------------------

export type SignResult = { ok: true; sig: string; sha256: string; format: "sshsig" | "cms"; ssh_keygen: string | null; openssl: string | null } | { ok: false; why: string; wrongSecret?: boolean };

const WRONG_SECRET = /incorrect passphrase|PIN incorrect|wrong PIN|invalid PIN|PIN required/i;

/**
 * Sign `file` in `namespace`: `<file>.sig` beside it. With no options it is
 * the machine's signature: no passphrase, and nothing is asked. With a
 * `secret` (a passphrase or a FIDO PIN) it is handed to ssh-keygen through
 * SSH_ASKPASS on fd 3; `dropAgent` takes the ssh-agent socket out of reach,
 * so a key held there cannot sign in place of the key file.
 */
export function sshSign(file: string, key: string, namespace: string, o: { secret?: Buffer | null; keygen?: string; dropAgent?: boolean; timeoutMs?: number } = {}): SignResult {
  if (!existsSync(key)) return { ok: false, why: `no key at ${key}` };
  rmSync(`${file}.sig`, { force: true });
  const keygen = o.keygen ?? sshKeygen();
  const r = runWithSecret(keygen, ["-Y", "sign", "-f", key, "-n", namespace, file], o.secret ?? null, { env: signingEnv(process.env, { dropAgent: o.dropAgent, askpass: true }), timeoutMs: o.timeoutMs ?? 180_000 });
  if (r.missing) return { ok: false, why: `${keygen} is not on this host` };
  if (r.timedOut) return { ok: false, why: "ssh-keygen -Y sign timed out (a hardware key that was not touched?)" };
  const said = r.err.trim().split("\n").filter((l) => !/^Signing file|^Write signature|^Confirm user presence|^User presence confirmed/.test(l)).join(" ");
  if (r.code !== 0 || !existsSync(`${file}.sig`)) return { ok: false, why: `ssh-keygen -Y sign failed: ${said || `exit ${r.code}`}`, wrongSecret: WRONG_SECRET.test(said) };
  return { ok: true, sig: `${file}.sig`, sha256: sha256(readFileSync(`${file}.sig`)), format: "sshsig", ssh_keygen: keygen, openssl: null };
}

/**
 * What a signature over `file` shows:
 * - verified: an allowed-signers file (the organisation's register) names
 *   this principal with the key that made it (for a certificate: its chain
 *   verifies against the CA file given);
 * - self-checked: the machine's seal, sound under the machine key the record
 *   names; nothing more is claimed for it;
 * - unchecked: it is sound under the key the record names, and who holds
 *   that key was not checked (no register given);
 * - unlisted: it is sound under the key the record names, and the register
 *   given does not list that key at all;
 * - wrong-principal: the register lists the key, under another principal;
 * - bad: it does not verify.
 */
export type SignatureState = "verified" | "self-checked" | "unchecked" | "unlisted" | "wrong-principal" | "bad";

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
    // Kept as it was made, each time it is used: the directory the owner's
    // alone, the key and its record 0600. A copy restored from a backup, or
    // a umask, may have left them readable by others.
    try {
      chmodSync(dir, 0o700);
      chmodSync(key, 0o600);
      chmodSync(meta, 0o600);
    } catch (err) {
      return { why: `${dir} could not be made its owner's alone (0700, the key and its record 0600): ${(err as Error).message}` };
    }
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

// --- people: examiners and technical reviewers ------------------------------------------------------

export type Role = "examiner" | "reviewer";
export type KeyKind = "ssh" | "fido" | "pkcs11";

export type SshKey = {
  kind: "ssh";
  /** What ssh-keygen signs with: the private key file, or a public key whose private half is in ssh-agent. Its path, never its bytes. */
  path: string;
  public: string;
  fingerprint: string;
  /** Made at enrolment because the examiner asked (--generate-key), not given. */
  generated: boolean;
  /** Whether the key file is encrypted: false is --no-passphrase; null is an enrolment from before this was recorded. */
  passphrase: boolean | null;
  /** The private half is in ssh-agent (a public key was enrolled): the command line only. */
  agent: boolean;
};

export type FidoKey = {
  kind: "fido";
  /** The key-handle file (ed25519-sk): useless without the authenticator. */
  path: string;
  public: string;
  fingerprint: string;
  generated: boolean;
  /** Every signature needs the authenticator's PIN as well as a touch. */
  verify_required: boolean;
  /** The key was made resident on the authenticator. */
  resident: boolean;
  /** The ssh-keygen it was made with, and how that one was chosen. */
  ssh_keygen: string;
  ssh_keygen_how: string;
};

export type Pkcs11Key = {
  kind: "pkcs11";
  /** The PKCS#11 module that serves the token. */
  module: string;
  /** The key's URI, with no PIN and no type. */
  uri: string;
  /** The object id, hex. */
  id: string;
  token: string | null;
  /** X509-SHA256:<the certificate's sha256>. */
  fingerprint: string;
  /** The certificate: its PEM (which carries the whole subject) and what is shown of it. */
  certificate: CertInfo;
  /** The issuing CA's intermediate certificates (--pkcs11-chain), put into every CMS so a verifier needs only the root. */
  chain?: { pem: string; certs: Array<{ sha256: string; cn: string | null }> } | null;
};

export type PersonKey = SshKey | FidoKey | Pkcs11Key;

export type Person = {
  /**
   * The register the record is in: every enrolled person's record is an
   * examiners/ record, and `role` says which role it is for. (The host-mode
   * kickoff reads the key paths of every record of this kind to hide them.)
   */
  kind: "examiner";
  v: 2;
  id: string;
  name: string;
  organisation: string;
  competence: string;
  principal: string;
  /** examiner: adopts a report and signs its release; reviewer: signs their own technical review. One person who is both enrols twice, and is refused on one run in both roles. */
  role: Role;
  key: PersonKey;
  /** The RFC 3161 authority the examiner's releases are timestamped by, and its CA certificates. */
  tsa: { url: string; ca: string | null; ca_sha256: string | null } | null;
  enrolled_at: string;
  enrolled_by: { os_user: string; host: string };
};

/** The name the release code has always used for an enrolled signer. */
export type Examiner = Person;

export const EXAMINER_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;

export function examinersDir(home = dfirswarmHome()): string {
  return join(home, "examiners");
}

/** The allowed-signers line an organisation's register carries for this person (a certificate has none: its issuer vouches for it). */
export function allowedSignersLine(e: Pick<Person, "principal" | "key"> & { role?: Role }): string {
  if (e.key.kind === "pkcs11") return "";
  const ns = e.role === "reviewer" ? REVIEW_NAMESPACE : `${RELEASE_NAMESPACE},dfirswarm-package`;
  return `${e.principal} namespaces="${ns}" ${publicKeyCore(e.key.public)}`;
}

/** A record as enrolment wrote it, read into this shape: an enrolment from before kinds and roles is an examiner's ssh key. */
function normalise(raw: Record<string, unknown>): Person | null {
  if (raw.kind !== "examiner") return null;
  if (raw.v === 2) return raw as unknown as Person;
  const k = (raw.key ?? {}) as { path?: string; public?: string; fingerprint?: string; generated?: boolean };
  const path = String(k.path ?? "");
  return {
    ...(raw as unknown as Omit<Person, "kind" | "v" | "role" | "key">),
    kind: "examiner",
    v: 2,
    role: "examiner",
    key: { kind: "ssh", path, public: String(k.public ?? ""), fingerprint: String(k.fingerprint ?? ""), generated: Boolean(k.generated), passphrase: null, agent: path.endsWith(".pub") },
  };
}

/** An enrolled person by id (either role), or why there is none. */
export function loadPerson(id: string, home = dfirswarmHome(), noun: "examiner" | "reviewer" | "person" = "person"): { person: Person; sha256: string } | { why: string } {
  if (!EXAMINER_ID.test(id)) return { why: `${JSON.stringify(id)} is not an ${noun === "person" ? "enrolled person's" : noun} id (lower-case letters, digits and dashes)` };
  const file = join(examinersDir(home), `${id}.json`);
  if (!existsSync(file)) return { why: noun === "person" ? `no one is enrolled on this install under ${id} (swarm.sh examiner enroll)` : `no ${noun} ${id} is enrolled on this install (swarm.sh examiner enroll${noun === "reviewer" ? " --role reviewer" : ""})` };
  try {
    const text = readFileSync(file, "utf8");
    const p = normalise(JSON.parse(text) as Record<string, unknown>);
    if (!p || p.id !== id) return { why: `${file} is not an enrolment` };
    return { person: p, sha256: sha256(text) };
  } catch (err) {
    return { why: `${file} is not readable JSON (${(err as Error).message})` };
  }
}

/** An enrolled examiner by id, or why there is none. */
export function loadExaminer(id: string, home = dfirswarmHome()): { examiner: Examiner; sha256: string } | { why: string } {
  const r = loadPerson(id, home, "examiner");
  return "why" in r ? r : { examiner: r.person, sha256: r.sha256 };
}

/** Everyone enrolled, or only those in one role. */
export function listPeople(home = dfirswarmHome(), role?: Role): Person[] {
  const dir = examinersDir(home);
  if (!existsSync(dir)) return [];
  const out: Person[] = [];
  for (const f of readdirSync(dir).sort()) {
    if (!f.endsWith(".json")) continue;
    const r = loadPerson(basename(f, ".json"), home);
    if ("person" in r && (!role || r.person.role === role)) out.push(r.person);
  }
  return out;
}

export function listExaminers(home = dfirswarmHome()): Examiner[] {
  return listPeople(home, "examiner");
}

export function listReviewers(home = dfirswarmHome()): Person[] {
  return listPeople(home, "reviewer");
}

/** Whether an ssh key file is encrypted: `ssh-keygen -y -P ""` fails on it for the passphrase. Null: not a private key file ssh-keygen reads. */
export function keyFileEncrypted(path: string, keygen = sshKeygen()): boolean | null {
  let head = "";
  try {
    head = readFileSync(path, "utf8").slice(0, 64);
  } catch {
    return null;
  }
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(head)) return null;
  const r = runWithSecret(keygen, ["-y", "-P", "", "-f", path], null, { env: signingEnv(process.env, { dropAgent: true, askpass: true }), timeoutMs: 30_000 });
  if (r.code === 0) return false;
  return /incorrect passphrase|passphrase/i.test(r.err) ? true : null;
}

/**
 * Whether this person's key can sign from the console: an ssh key with a
 * passphrase, held in a file (not in ssh-agent), a FIDO key, or a token's
 * certificate. Null when it can; why not, when not.
 */
export function consoleRefusal(p: Person): string | null {
  if (p.key.kind === "ssh") {
    if (p.key.agent) return `${p.name}'s key is held in ssh-agent: the console does not sign with an agent's key (sign on the command line)`;
    const enc = existsSync(p.key.path) ? keyFileEncrypted(p.key.path) : null;
    if (enc === false || p.key.passphrase === false) return `${p.name}'s key has no passphrase: the console signs only with a key that needs one (sign on the command line, where --no-passphrase is a documented trade)`;
    if (enc === null) return `${p.name}'s key at ${p.key.path} could not be read as an encrypted private key`;
  }
  return null;
}

/** What a key needs to sign: a passphrase, a PIN, a touch. */
export function keyNeeds(p: Pick<Person, "key">): { secret: "passphrase" | "fido-pin" | "pin" | null; touch: boolean } {
  const k = p.key;
  if (k.kind === "pkcs11") return { secret: "pin", touch: false };
  if (k.kind === "fido") return { secret: k.verify_required ? "fido-pin" : null, touch: true };
  if (k.agent) return { secret: null, touch: false };
  if (k.passphrase === false) return { secret: null, touch: false };
  if (k.passphrase === null && keyFileEncrypted(k.path) === false) return { secret: null, touch: false };
  return { secret: "passphrase", touch: false };
}

export type EnrollInput = {
  name: string;
  organisation: string;
  competence: string;
  role?: Role;
  id?: string;
  principal?: string;
  key?: string;
  generateKey?: boolean;
  noPassphrase?: boolean;
  fido?: boolean;
  fidoVerifyRequired?: boolean;
  fidoResident?: boolean;
  pkcs11Module?: string;
  pkcs11Id?: string;
  pkcs11Uri?: string;
  pkcs11Chain?: string;
  tsaUrl?: string;
  tsaCa?: string;
};

const slug = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);

/** Which kind of key the flags ask for, or why they contradict each other. */
export function kindOf(input: EnrollInput): KeyKind | { why: string } {
  const asked = [input.fido ? "fido" : null, input.pkcs11Module ? "pkcs11" : null].filter(Boolean) as KeyKind[];
  if (asked.length > 1) return { why: "one key per enrolment: --fido or --pkcs11-module, not both" };
  if (asked[0] === "pkcs11" && (input.key || input.generateKey)) return { why: "a token's certificate is enrolled with --pkcs11-module, without --key or --generate-key" };
  if (asked[0] === "fido" && input.key) return { why: "--fido makes a key on the authenticator: to enrol a key handle you already have, give it with --key alone" };
  return asked[0] ?? "ssh";
}

/**
 * Enrol a person: the record outside every run, the key checked by signing a
 * challenge with it and verifying that with its public half (so a wrong path,
 * a wrong passphrase or a key the agent does not hold is refused now, not at
 * the first sign-off). A key is made only when asked. `secret` is the
 * passphrase (ssh) or the PIN (fido), when one is needed; it is zeroed by
 * the caller.
 */
export function enrollPerson(input: EnrollInput, home = dfirswarmHome(), secret: Buffer | null = null, say: (s: string) => void = () => undefined): { person: Person; file: string; register: string } | { why: string } {
  const name = input.name?.trim();
  const organisation = input.organisation?.trim();
  const competence = input.competence?.trim();
  const role: Role = input.role ?? "examiner";
  if (!name) return { why: "a name is required (--name)" };
  if (!organisation) return { why: `the organisation the ${role} signs for is required (--organisation)` };
  if (!competence) return { why: `a competence statement is required (--competence): what qualifies this person to ${role === "reviewer" ? "review a forensic examination's methods" : "adopt a forensic report"}` };
  if (role !== "examiner" && role !== "reviewer") return { why: `--role is examiner or reviewer, not ${JSON.stringify(role)}` };
  const kind = kindOf(input);
  if (typeof kind !== "string") return kind;
  if (kind === "ssh" && !input.key === !input.generateKey) return { why: "give the key (--key FILE) or ask for one to be made (--generate-key), one of the two; or --fido, or --pkcs11-module" };
  const id = input.id ?? slug(name);
  if (!EXAMINER_ID.test(id)) return { why: `${JSON.stringify(id)} is not an examiner id: lower-case letters, digits and dashes (--id)` };
  const principal = input.principal ?? id;
  if (!PRINCIPAL.test(principal)) return { why: `${JSON.stringify(principal)} cannot be an allowed-signers principal: one word of letters, digits and . _ @ + - (--principal)` };
  const dir = examinersDir(home);
  const file = join(dir, `${id}.json`);
  if (existsSync(file)) return { why: `someone is enrolled already under ${id} (${file}); a new key is a new enrolment under another id` };
  if (input.tsaUrl && !/^https?:\/\//.test(input.tsaUrl)) return { why: `${input.tsaUrl} is not an http(s) URL (--tsa-url)` };
  if (input.tsaCa && !existsSync(input.tsaCa)) return { why: `no CA file at ${input.tsaCa} (--tsa-ca)` };
  if (input.tsaCa && !input.tsaUrl) return { why: "a CA without an authority: give --tsa-url with --tsa-ca" };
  if (kind === "ssh" && input.generateKey && !input.noPassphrase && (!secret || secret.length < 8)) return { why: "a key made here has a passphrase of at least 8 characters (or --no-passphrase, a documented trade the console refuses)" };
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const keys = join(dir, "keys");
  const ns = role === "reviewer" ? REVIEW_NAMESPACE : RELEASE_NAMESPACE;
  let key: PersonKey;
  if (kind === "pkcs11") {
    const uri = tokenUri({ uri: input.pkcs11Uri, id: input.pkcs11Id });
    if ("why" in uri) return uri;
    const module = resolve(String(input.pkcs11Module));
    const cert = readTokenCert({ module, id: uri.id, token: uri.token });
    if ("why" in cert) return { why: `${cert.why}: nothing was enrolled` };
    const refused = certRefusal(cert.info);
    if (refused) return { why: `${refused}: nothing was enrolled` };
    let chain: Pkcs11Key["chain"] = null;
    if (input.pkcs11Chain) {
      if (!existsSync(input.pkcs11Chain)) return { why: `no certificate file at ${input.pkcs11Chain} (--pkcs11-chain)` };
      let certs: ReturnType<typeof pemCerts>;
      try {
        certs = pemCerts(readFileSync(input.pkcs11Chain, "utf8"));
      } catch (err) {
        return { why: `${input.pkcs11Chain} holds a certificate this reader does not take (${(err as Error).message}) (--pkcs11-chain)` };
      }
      if (!certs.length) return { why: `${input.pkcs11Chain} holds no PEM certificate (--pkcs11-chain: the issuing CA's intermediates)` };
      chain = { pem: certs.map((c) => c.pem).join(""), certs: certs.map((c) => ({ sha256: c.sha256, cn: c.cn })) };
    } else if (input.pkcs11Chain === "") return { why: "--pkcs11-chain names no file" };
    key = { kind: "pkcs11", module, uri: uri.uri, id: uri.id, token: uri.token, fingerprint: certFingerprint(cert.info.sha256), certificate: cert.info, chain };
  } else if (kind === "fido") {
    const keygen = fidoKeygen();
    if ("why" in keygen) return keygen;
    mkdirSync(keys, { recursive: true, mode: 0o700 });
    const keyPath = join(keys, `${id}_ed25519_sk`);
    if (existsSync(keyPath)) return { why: `${keyPath} exists already: it is not made over` };
    const opts = ["-O", `application=ssh:dfirswarm-${id}`];
    if (input.fidoVerifyRequired) opts.push("-O", "verify-required");
    if (input.fidoResident) opts.push("-O", "resident");
    say("Touch the FIDO key when it blinks (twice if it asks for its PIN first).");
    // The key handle needs no passphrase of its own: the authenticator is what signs. The PIN, when asked, comes through askpass.
    const r = runWithSecret(keygen.path, ["-q", "-t", "ed25519-sk", ...opts, "-C", principal, "-N", "", "-f", keyPath], secret, { env: signingEnv(process.env, { askpass: true }), timeoutMs: 180_000, times: 3 });
    if (r.code !== 0 || !existsSync(`${keyPath}.pub`)) {
      rmSync(keyPath, { force: true });
      rmSync(`${keyPath}.pub`, { force: true });
      return { why: `the FIDO key could not be made (${r.timedOut ? "timed out: was the key touched?" : r.err.trim().split("\n").filter((l) => !/touch your authenticator/i.test(l)).join(" ") || `exit ${r.code}`}): nothing was enrolled` };
    }
    const pub = readFileSync(`${keyPath}.pub`, "utf8").trim();
    const fp = fingerprintOf(pub);
    if (!fp) return { why: `${keyPath}.pub is not a key ssh-keygen can read` };
    // Made on the authenticator a moment ago: that is the proof of possession, and a second touch would prove no more.
    key = { kind: "fido", path: keyPath, public: pub, fingerprint: fp, generated: true, verify_required: Boolean(input.fidoVerifyRequired), resident: Boolean(input.fidoResident), ssh_keygen: keygen.path, ssh_keygen_how: keygen.how };
  } else {
    let keyPath: string;
    let pub: string;
    let passphrase: boolean;
    let agent = false;
    let sk = false;
    const keygen = sshKeygen();
    if (input.generateKey) {
      mkdirSync(keys, { recursive: true, mode: 0o700 });
      keyPath = join(keys, `${id}_ed25519`);
      if (existsSync(keyPath)) return { why: `${keyPath} exists already: it is not made over` };
      if (input.noPassphrase) {
        const r = run(keygen, ["-q", "-t", "ed25519", "-C", principal, "-f", keyPath, "-N", ""]);
        if (r.missing) return { why: "ssh-keygen is not on this host" };
        if (r.code !== 0 || !existsSync(`${keyPath}.pub`)) return { why: `ssh-keygen could not make the key: ${r.err.trim() || `exit ${r.code}`}` };
      } else {
        // The passphrase twice on stdin, in a session with no terminal, so ssh-keygen reads it there and nowhere else.
        const input2 = Buffer.concat([secret as Buffer, Buffer.from("\n"), secret as Buffer, Buffer.from("\n")]);
        const r = runDetachedWithInput(keygen, ["-q", "-t", "ed25519", "-C", principal, "-f", keyPath], input2, { env: signingEnv(process.env, { dropAgent: true }) });
        if (r.missing) return { why: "ssh-keygen is not on this host" };
        if (r.code !== 0 || !existsSync(`${keyPath}.pub`)) return { why: `ssh-keygen could not make the key: ${r.err.replace(/Enter (same )?passphrase[^:]*:\s*/g, "").trim() || `exit ${r.code}`}` };
      }
      pub = readFileSync(`${keyPath}.pub`, "utf8").trim();
      passphrase = !input.noPassphrase;
      if (passphrase && keyFileEncrypted(keyPath, keygen) !== true) {
        rmSync(keyPath, { force: true });
        rmSync(`${keyPath}.pub`, { force: true });
        return { why: "the key was made without the passphrase it was given: nothing was enrolled" };
      }
    } else {
      keyPath = resolve(String(input.key));
      if (!existsSync(keyPath)) return { why: `no key at ${keyPath} (--key)` };
      const pubFile = keyPath.endsWith(".pub") ? keyPath : `${keyPath}.pub`;
      agent = keyPath.endsWith(".pub");
      if (existsSync(pubFile)) pub = readFileSync(pubFile, "utf8").trim();
      else {
        const r = runWithSecret(keygen, ["-y", "-f", keyPath], secret, { env: signingEnv(process.env, { askpass: true }) });
        if (r.code !== 0) return { why: `the public half of ${keyPath} could not be read: ${r.err.trim() || `exit ${r.code}`}` };
        pub = r.out.trim();
      }
      sk = /^sk-/.test(pub);
      if (agent) passphrase = false;
      else {
        const enc = keyFileEncrypted(keyPath, keygen);
        if (enc === null) return { why: `${keyPath} is not a private key file ssh-keygen reads (give the private key, or its .pub for a key held in ssh-agent)` };
        passphrase = enc;
        if (!sk && !enc && !input.noPassphrase) return { why: `${keyPath} has no passphrase: \`ssh-keygen -y -P ""\` reads it. Give an encrypted key (ssh-keygen -p -f ${keyPath} adds one), or --no-passphrase, a documented trade the console refuses` };
      }
    }
    const fingerprint = fingerprintOf(pub);
    if (!fingerprint) return { why: `${keyPath} is not an ssh key ssh-keygen can read` };
    if (sk) {
      const fk = fidoKeygen();
      if ("why" in fk) return fk;
      key = { kind: "fido", path: keyPath, public: pub, fingerprint, generated: false, verify_required: false, resident: false, ssh_keygen: fk.path, ssh_keygen_how: fk.how };
    } else key = { kind: "ssh", path: keyPath, public: pub, fingerprint, generated: Boolean(input.generateKey), passphrase, agent };
  }
  // Proof of possession: a challenge signed and verified, in a scratch directory. A FIDO key made just
  // now needs none; a token's certificate is enrolled without its PIN, and every signature later holds
  // the token to the certificate's fingerprint.
  if (!(key.kind === "fido" && key.generated) && key.kind !== "pkcs11") {
    const scratch = mkdtempSync(join(tmpdir(), "dfs-enrol-"));
    try {
      const challenge = join(scratch, "challenge");
      writeFileSync(challenge, `DFIR Swarm enrolment ${id} ${randomBytes(16).toString("hex")}\n`);
      if (key.kind === "fido") say("Touch the FIDO key to prove it holds this key.");
      const tmpPerson = { kind: "examiner", v: 2, id, name, organisation, competence, principal, role, key } as Person;
      const signed = signAs(tmpPerson, challenge, ns, secret, { dropAgent: false });
      if (!signed.ok) {
        if (input.generateKey) {
          rmSync((key as SshKey).path, { force: true });
          rmSync(`${(key as SshKey).path}.pub`, { force: true });
        }
        return { why: `the key could not sign (${signed.why}): nothing was enrolled` };
      }
      const checked = verifyAs(tmpPerson, challenge, signed.sig, ns);
      if (checked.state !== "unchecked") return { why: `a signature made with the key does not verify under its public half: ${checked.detail}` };
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  }
  const tsaCaSha = input.tsaCa ? sha256(readFileSync(input.tsaCa)) : null;
  const p: Person = {
    kind: "examiner",
    v: 2,
    id,
    name,
    organisation,
    competence,
    principal,
    role,
    key,
    tsa: input.tsaUrl ? { url: input.tsaUrl, ca: input.tsaCa ? resolve(input.tsaCa) : null, ca_sha256: tsaCaSha } : null,
    enrolled_at: new Date().toISOString(),
    enrolled_by: { os_user: userInfo().username, host: hostname() },
  };
  writeFileSync(file, `${JSON.stringify(p, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return { person: p, file, register: allowedSignersLine(p) };
}

/** An examiner's enrolment (the role the release code has always enrolled). */
export function enrollExaminer(input: EnrollInput, home = dfirswarmHome(), secret: Buffer | null = null): { examiner: Examiner; file: string; register: string } | { why: string } {
  const r = enrollPerson({ ...input, role: input.role ?? "examiner" }, home, secret);
  return "why" in r ? r : { examiner: r.person, file: r.file, register: r.register };
}

/**
 * Sign `file` as this person, with their key's kind: an SSHSIG at
 * `<file>.sig` (ssh, fido) or a CAdES-BES CMS at `<file>.p7s` (pkcs11).
 */
export function signAs(p: Pick<Person, "key">, file: string, namespace: string, secret: Buffer | null, o: { dropAgent?: boolean } = {}): SignResult {
  const k = p.key;
  if (k.kind === "pkcs11") {
    if (!secret?.length) return { ok: false, why: "the token's PIN is needed to sign", wrongSecret: true };
    const r = cmsSign({ file, module: k.module, uri: k.uri, id: k.id, token: k.token, certPem: k.certificate.pem, certSha256: k.certificate.sha256, chainPem: k.chain?.pem ?? null, pin: secret });
    return r.ok ? { ok: true, sig: r.sig, sha256: r.sha256, format: "cms", ssh_keygen: null, openssl: r.openssl } : r;
  }
  const keygen = k.kind === "fido" ? k.ssh_keygen : sshKeygen();
  return sshSign(file, k.path, namespace, { secret, keygen, dropAgent: o.dropAgent });
}

/** What a signature made by `signAs` shows, against a register (ssh, fido) or a CA (pkcs11) when one is given. */
export function verifyAs(p: Pick<Person, "key" | "principal">, file: string, sig: string, namespace: string, o: { allowedSigners?: string; ca?: string; intermediates?: string } = {}): { state: SignatureState; detail: string } {
  const k = p.key;
  if (k.kind === "pkcs11") {
    const v = cmsVerify({ file, sig, certSha256: k.certificate.sha256, ca: o.ca, intermediates: o.intermediates });
    return { state: v.state, detail: v.detail };
  }
  return checkSshSignature({ file, sig, namespace, principal: p.principal, publicKey: k.public, allowedSigners: o.allowedSigners });
}

/** A one-line account of a person's key, for a list, a summary or a release: never a certificate's subject beyond its CN. */
export function keyWords(k: PersonKey): string {
  if (k.kind === "pkcs11") return `e-signature certificate ${k.fingerprint}: CN ${k.certificate.cn ?? "?"}, issued by ${k.certificate.issuer}, valid ${k.certificate.not_before.slice(0, 10)} to ${k.certificate.not_after.slice(0, 10)}${k.certificate.qc_statement ? ", with a qualified-certificate statement" : ""}; on the token through ${k.module}${k.chain?.certs.length ? `; each signature carries ${k.chain.certs.map((c) => c.cn ?? c.sha256).join(", ")}` : ""}`;
  if (k.kind === "fido") return `FIDO key ${k.fingerprint} (a touch${k.verify_required ? " and its PIN" : ""} per signature${k.resident ? "; resident" : ""}; handle ${k.path}; ${k.ssh_keygen})`;
  return `ssh key ${k.fingerprint} (${k.generated ? "made at enrolment" : "given"}; ${k.agent ? "held in ssh-agent" : k.passphrase === true ? "with a passphrase" : k.passphrase === false ? "NO PASSPHRASE" : "passphrase not recorded"}; ${k.path})`;
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function describe(e: Person): string[] {
  const lines = [
    `${e.role === "reviewer" ? "Reviewer:    " : "Examiner:    "} ${e.name} (${e.id}), ${e.organisation}`,
    `Competence:   ${e.competence}`,
    `Key:          ${keyWords(e.key)}`,
    `Principal:    ${e.principal}`,
  ];
  if (e.role === "examiner") lines.push(`Timestamps:   ${e.tsa ? `${e.tsa.url}${e.tsa.ca ? `, checked against ${e.tsa.ca}` : ", NO CA: tokens are held to their digest only"}` : "none configured: releases are not timestamped (swarm.sh timestamp <run> later)"}`);
  lines.push(`Enrolled:     ${e.enrolled_at} by ${e.enrolled_by.os_user}@${e.enrolled_by.host}`);
  return lines;
}

/** What a list or the console shows of a person: no private path's bytes, no certificate subject beyond its CN. */
export function personSummary(p: Person): Record<string, unknown> {
  const k = p.key;
  return {
    id: p.id,
    name: p.name,
    organisation: p.organisation,
    competence: p.competence,
    role: p.role,
    principal: p.principal,
    key: {
      kind: k.kind,
      fingerprint: k.fingerprint,
      ...(k.kind === "ssh" ? { passphrase: k.passphrase, agent: k.agent, generated: k.generated } : {}),
      ...(k.kind === "fido" ? { verify_required: k.verify_required, resident: k.resident, ssh_keygen: k.ssh_keygen } : {}),
      ...(k.kind === "pkcs11" ? { cn: k.certificate.cn, issuer: k.certificate.issuer, not_before: k.certificate.not_before, not_after: k.certificate.not_after, key_usage: k.certificate.key_usage, qc_statement: k.certificate.qc_statement, module: k.module } : {}),
    },
    words: keyWords(k),
    console: consoleRefusal(p) ?? "ok",
    enrolled_at: p.enrolled_at,
  };
}

/** The secret an enrolment needs, from the descriptor the console hands down, or asked on the terminal. */
async function enrolmentSecret(args: string[], kind: KeyKind): Promise<Buffer | null> {
  const fd = opt(args, "--passphrase-fd");
  if (fd !== undefined) return readSecretFromFd(Number(fd));
  const generate = args.includes("--generate-key");
  const noPass = args.includes("--no-passphrase");
  if (kind === "ssh" && generate && !noPass) {
    if (!hasTty()) throw new Error("there is no terminal to ask the new key's passphrase on: run it at a terminal, or --passphrase-fd N");
    const a = await readFromTty("Passphrase for the new key (at least 8 characters, not shown): ");
    const b = await readFromTty("The same passphrase again: ");
    const same = a.equals(b);
    wipe(b);
    if (!same) {
      wipe(a);
      throw new Error("the two passphrases differ: nothing was made");
    }
    return a;
  }
  // A key given: its passphrase is asked only when it has one (one without is refused, or taken with --no-passphrase).
  const given = opt(args, "--key");
  if (kind === "ssh" && given && !given.endsWith(".pub") && keyFileEncrypted(resolve(given)) === true) {
    if (!hasTty()) throw new Error("there is no terminal to ask the key's passphrase on (to prove it signs): run it at a terminal, or --passphrase-fd N");
    return readFromTty("The key's passphrase, to prove it signs (not shown): ");
  }
  if (kind === "fido" && (args.includes("--fido-verify-required") || args.includes("--fido-resident"))) {
    if (!hasTty()) throw new Error("there is no terminal to ask the FIDO PIN on: run it at a terminal, or --passphrase-fd N");
    return readFromTty("The FIDO authenticator's PIN (not shown): ");
  }
  return null;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const home = dfirswarmHome();
  const json = args.includes("--json");
  switch (cmd) {
    case "enroll": {
      const role = (opt(args, "--role") ?? "examiner") as Role;
      const input: EnrollInput = {
        name: opt(args, "--name") ?? "",
        organisation: opt(args, "--organisation") ?? opt(args, "--organization") ?? "",
        competence: opt(args, "--competence") ?? "",
        role,
        id: opt(args, "--id"),
        principal: opt(args, "--principal"),
        key: opt(args, "--key"),
        generateKey: args.includes("--generate-key"),
        noPassphrase: args.includes("--no-passphrase"),
        fido: args.includes("--fido"),
        fidoVerifyRequired: args.includes("--fido-verify-required"),
        fidoResident: args.includes("--fido-resident"),
        pkcs11Module: opt(args, "--pkcs11-module"),
        pkcs11Id: opt(args, "--pkcs11-id"),
        pkcs11Uri: opt(args, "--pkcs11-uri"),
        pkcs11Chain: opt(args, "--pkcs11-chain"),
        tsaUrl: opt(args, "--tsa-url"),
        tsaCa: opt(args, "--tsa-ca"),
      };
      const kind = kindOf(input);
      if (typeof kind !== "string") {
        console.error(`BLOCKER: ${kind.why}`);
        return 2;
      }
      let secret: Buffer | null = null;
      try {
        secret = await enrolmentSecret(args, kind);
      } catch (err) {
        console.error(`BLOCKER: ${(err as Error).message}`);
        return 2;
      }
      let r: ReturnType<typeof enrollPerson>;
      try {
        r = enrollPerson(input, home, secret, (s) => (json ? console.error(s) : console.log(s)));
      } finally {
        wipe(secret);
      }
      if ("why" in r) {
        if (json) console.log(JSON.stringify({ ok: false, error: r.why }));
        else console.error(`BLOCKER: ${r.why}`);
        return 2;
      }
      if (json) {
        console.log(JSON.stringify({ ok: true, person: personSummary(r.person), register: r.register || null }));
        return 0;
      }
      for (const l of describe(r.person)) console.log(l);
      console.log(`Recorded:     ${r.file} (outside every run)`);
      console.log("");
      if (r.register) {
        console.log("For the organisation's signer register (an ssh allowed-signers file), this line:");
        console.log(`  ${r.register}`);
        console.log(`Check the fingerprint ${r.person.key.fingerprint} with ${r.person.name} in person before it goes in: the register, not this install, is what ties the key to the person.`);
      } else {
        console.log(`The certificate's issuer, not a register line, ties this key to ${r.person.name}: check a signature's chain with --ca FILE (the issuer's CA certificates). The certificate travels inside every signature it makes.`);
      }
      if (r.person.key.kind === "ssh" && r.person.key.passphrase === false && !r.person.key.agent) console.log("The key has NO passphrase: anyone who can read this account's files can sign as this person. The console refuses it; the command line takes it.");
      return 0;
    }
    case "list": {
      const all = listPeople(home);
      if (json) {
        console.log(JSON.stringify(all.map(personSummary)));
        return 0;
      }
      if (!all.length) console.log(`No one is enrolled on this install (${examinersDir(home)}).`);
      for (const e of all) console.log(`${e.id}\t${e.name}\t${e.organisation}\t${e.key.fingerprint}\t${e.role}\t${e.key.kind}`);
      return 0;
    }
    case "show": {
      const id = args.find((a) => !a.startsWith("--")) ?? "";
      const r = loadPerson(id, home);
      if ("why" in r) {
        console.error(r.why);
        return 1;
      }
      if (json) {
        console.log(JSON.stringify(personSummary(r.person)));
        return 0;
      }
      for (const l of describe(r.person)) console.log(l);
      const line = allowedSignersLine(r.person);
      console.log(line ? `Register:     ${line}` : "Register:     none: the certificate's issuer vouches for it (verify with --ca FILE)");
      const refused = consoleRefusal(r.person);
      console.log(`Console:      ${refused ?? "can sign from the console"}`);
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
