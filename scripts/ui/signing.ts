/**
 * Signing from the console: enrolment, a release's prepare and seal, a
 * technical reviewer's record and countersign. What a browser can do here
 * is held tighter than anything else the console serves, because a secret
 * (a passphrase, a PIN) arrives with the request:
 *
 * - the server's token is required even when SWARM_UI_TOKEN is empty (a
 *   console started without one cannot sign), with the Host a loopback name,
 *   the Origin (when sent) the console's own, a JSON body, and the server
 *   listening on loopback only;
 * - nothing is signed while a host-mode run is live on this install: its
 *   panes read the host's files and could reach this console;
 * - five wrong secrets for one person lock that person out for fifteen
 *   minutes, and the operator's audit says so;
 * - the scripts are spawned directly, never as a /api/jobs job (a job's
 *   output is served to anyone who can watch), with the secret on a pipe at
 *   their fd 3 and the ssh-agent socket out of their environment; the
 *   console's own copy of it is dropped as soon as it is written down the
 *   pipe (a JavaScript string cannot be zeroed; the Buffer it becomes is).
 *
 * A passphrase typed into a browser also trusts the browser and this
 * server, and proves nothing about who typed it: SECURITY.md says so.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmdirSync, statSync, writeSync } from "node:fs";
import { hostname, userInfo } from "node:os";
import { join } from "node:path";
import type { IncomingMessage } from "node:http";
import { listPeople, personSummary, dfirswarmHome } from "../signers.ts";
import { readReleases, runLayout, verifyReleases } from "../release-record.ts";
import { hostExposure, runContext, technicalReviewPolicy } from "../release.ts";
import { readReviews, reviewedStateNow, reviewsPath, technicalReviewsOf, REVIEW_OUTCOMES, type ReviewLine } from "../review.ts";
import { custodyAnchorPath } from "../custody.ts";
import { wipe } from "../secret-io.ts";

export class SigningError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** How many wrong secrets lock a person out, and for how long. */
export const LOCKOUT_AFTER = 5;
export const LOCKOUT_MS = 15 * 60_000;

const LOOPBACK_NAMES = /^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$/i;
const LOOPBACK_BIND = new Set(["127.0.0.1", "::1", "localhost"]);

/**
 * One line on the operator's record (runs/operator-audit.jsonl), chained as
 * swarm.sh chains it: the console's signing acts and every lockout. Never a
 * secret: the argv is ids and a nonce.
 */
export function appendOperatorAudit(runsDir: string, command: string, argv: string[], detail: Record<string, unknown> | null): void {
  const file = join(runsDir, "operator-audit.jsonl");
  const lock = join(runsDir, ".operator-audit.lock");
  mkdirSync(runsDir, { recursive: true });
  let held = false;
  for (let i = 0; i < 60 && !held; i++) {
    try {
      mkdirSync(lock);
      held = true;
    } catch {
      if (i === 59) {
        // A lock older than this was left by a command that died holding it.
        try {
          rmdirSync(lock);
          mkdirSync(lock);
          held = true;
        } catch {
          held = false;
        }
      } else Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
  }
  try {
    let prev: string | null = null;
    if (existsSync(file) && statSync(file).size > 0) {
      const last = readFileSync(file, "utf8").split("\n").filter((l) => l.length).at(-1);
      prev = last ? createHash("sha256").update(last).digest("hex") : null;
    }
    const line = { at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), command, argv, cwd: process.cwd(), os_user: userInfo().username, host: hostname(), via: "console", ...(detail ? { detail } : {}), prev };
    const fd = openSync(file, "a", 0o600);
    try {
      writeSync(fd, `${JSON.stringify(line)}\n`);
    } finally {
      closeSync(fd);
    }
  } finally {
    if (held) {
      try {
        rmdirSync(lock);
      } catch {
        // gone already
      }
    }
  }
}

type Registry = { runs?: Array<Record<string, unknown>> };

export type SigningDeps = {
  root: string;
  runsDir: string;
  token: string;
  /** The address the server is bound to (null before listen). */
  boundHost: () => string | null;
  /** The signers' home, when not the environment's (tests). */
  home?: string;
};

type Ran = { code: number; stdout: string; stderr: string; json: Record<string, unknown> | null };

export function createSigning(d: SigningDeps) {
  const lockouts = new Map<string, { wrong: number; until: number }>();
  const home = () => d.home ?? dfirswarmHome();

  function readRegistry(): Registry {
    try {
      return JSON.parse(readFileSync(join(d.runsDir, "registry.json"), "utf8")) as Registry;
    } catch {
      return {};
    }
  }

  /** A host-mode run that is live on this install: its panes read the host, so nothing is signed until it ends. */
  function liveHostRun(): string | null {
    for (const r of readRegistry().runs ?? []) {
      const state = String(r.state ?? "");
      const mode = ((r.signer_isolation as { isolation?: string } | undefined)?.isolation ?? (r.isolation as { mode?: string } | undefined)?.mode ?? "host") as string;
      if (["running", "prepared", "finishing"].includes(state) && mode !== "microvm") return String(r.id ?? "?");
    }
    return null;
  }

  /** Whether this console can sign at all, and why not. */
  function availability(): { ok: boolean; why: string | null; host_run: string | null } {
    const host = liveHostRun();
    if (!d.token) return { ok: false, why: "this console was started with SWARM_UI_TOKEN empty: signing needs the server's token, so it is off. Restart the console without SWARM_UI_TOKEN=\"\" (it makes a token and prints it in the URL).", host_run: host };
    const bound = d.boundHost();
    if (bound !== null && !LOOPBACK_BIND.has(bound)) return { ok: false, why: `this console listens on ${bound}, not on loopback: it signs only when it listens on this machine alone (swarm.sh ui without --host)`, host_run: host };
    if (host) return { ok: false, why: `a host-mode run (${host}) is live on this install: its panes read this machine's files and could reach this console, so nothing is signed until it ends. Sign on the command line, or stop the run first.`, host_run: host };
    return { ok: true, why: null, host_run: null };
  }

  /** Every signing request: the token (never optional here), a loopback Host, the console's own Origin, a JSON body. */
  function guard(req: IncomingMessage): void {
    const a = availability();
    if (!d.token) throw new SigningError(403, a.why as string);
    const header = req.headers.authorization ?? "";
    const bearer = /^bearer\s+/i.test(header) ? header.replace(/^bearer\s+/i, "").trim() : "";
    const want = Buffer.from(d.token);
    const got = Buffer.from(bearer);
    if (got.length !== want.length || !got.equals(want)) throw new SigningError(401, "signing needs the server token (Authorization: Bearer ...)");
    const host = String(req.headers.host ?? "");
    if (!LOOPBACK_NAMES.test(host)) throw new SigningError(403, `a signing request is taken only for a loopback Host (127.0.0.1, localhost, [::1]), not ${JSON.stringify(host)}`);
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://${host}`) throw new SigningError(403, `a signing request is taken only from this console's own page (Origin ${JSON.stringify(origin)} is not http://${host})`);
    const site = req.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin" && site !== "none") throw new SigningError(403, `a signing request is taken only from this console's own page (Sec-Fetch-Site ${site})`);
    if (!/^application\/json\b/i.test(String(req.headers["content-type"] ?? ""))) throw new SigningError(415, "a signing request is JSON (content-type: application/json)");
    if (!a.ok) throw new SigningError(a.host_run ? 409 : 403, a.why as string);
  }

  function lockedOut(person: string): string | null {
    const l = lockouts.get(person);
    if (!l || l.until <= Date.now()) return null;
    return `${person} is locked out of signing from the console until ${new Date(l.until).toISOString()}: ${LOCKOUT_AFTER} wrong secrets in a row`;
  }

  function wrongSecret(person: string, act: string, run: string | null): void {
    const l = lockouts.get(person) ?? { wrong: 0, until: 0 };
    if (l.until && l.until <= Date.now()) {
      l.wrong = 0;
      l.until = 0;
    }
    l.wrong += 1;
    if (l.wrong >= LOCKOUT_AFTER) {
      l.until = Date.now() + LOCKOUT_MS;
      appendOperatorAudit(d.runsDir, "signing-lockout", [person, ...(run ? [run] : [])], { act, wrong: l.wrong, until: new Date(l.until).toISOString() });
    }
    lockouts.set(person, l);
  }

  function rightSecret(person: string): void {
    lockouts.delete(person);
  }

  /** The environment a signing script runs in: no ssh-agent, no console token, this console's runs. */
  function childEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env, SWARM_RUNS_DIR: d.runsDir };
    delete env.SSH_AUTH_SOCK;
    delete env.SWARM_UI_TOKEN;
    if (d.home) env.SWARM_SIGNERS_HOME = d.home;
    return env;
  }

  /** A script run directly (never as a job), the secret down fd 3 and dropped. */
  function runScript(script: string, args: string[], secret: Buffer | null, timeoutMs: number): Promise<Ran> {
    return new Promise((resolveRun) => {
      const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", join(d.root, "scripts", script), ...args], { cwd: d.root, env: childEnv(), stdio: ["ignore", "pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout?.on("data", (c: Buffer) => (stdout += c.toString()));
      child.stderr?.on("data", (c: Buffer) => (stderr += c.toString()));
      const pipe = child.stdio[3] as NodeJS.WritableStream & { on: (e: string, f: () => void) => void };
      pipe.on("error", () => undefined);
      const payload = secret ? Buffer.concat([secret, Buffer.from("\n")]) : Buffer.alloc(0);
      pipe.end(payload, () => wipe(payload));
      wipe(secret);
      const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
      child.on("close", (code) => {
        clearTimeout(timer);
        let json: Record<string, unknown> | null = null;
        const last = stdout.trim().split("\n").at(-1) ?? "";
        try {
          json = last ? (JSON.parse(last) as Record<string, unknown>) : null;
        } catch {
          json = null;
        }
        resolveRun({ code: code ?? 1, stdout, stderr, json });
      });
    });
  }

  const str = (v: unknown, what: string, max = 2000): string => {
    if (typeof v !== "string" || !v.trim() || v.length > max || /[\x00-\x08\x0b-\x1f\x7f]/.test(v)) throw new SigningError(400, `${what}: text, at most ${max} characters`);
    return v.trim();
  };
  const idOf = (v: unknown, what: string) => {
    if (typeof v !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(v)) throw new SigningError(400, `${what} is an enrolled person's id`);
    return v;
  };
  const secretOf = (v: unknown, what: string): Buffer => {
    if (typeof v !== "string" || !v.length || Buffer.byteLength(v) > 1024 || /[\r\n\0]/.test(v)) throw new SigningError(400, `${what}: one line, at most 1024 bytes`);
    return Buffer.from(v, "utf8");
  };

  function runOf(id: string): { sandbox: string; rec: Record<string, unknown> } {
    const rec = (readRegistry().runs ?? []).find((r) => r.id === id);
    if (!rec) throw new SigningError(404, "swarm not found");
    const sandbox = typeof rec.sandbox === "string" ? rec.sandbox : join(d.runsDir, id);
    const state = String(rec.state ?? "");
    if (["running", "prepared", "finishing"].includes(state)) throw new SigningError(409, `run ${id} is still ${state}: a release is signed once the run has ended`);
    if (state === "purged") throw new SigningError(409, `run ${id} was purged`);
    return { sandbox, rec };
  }

  const fail = (r: Ran, fallback: string): never => {
    throw new SigningError(r.code === 5 ? 403 : 400, String(r.json?.error ?? (r.stderr.trim().split("\n").filter((l) => !/^(Touch|WRONG)/.test(l)).at(-1) || fallback)));
  };

  return {
    availability,
    guard,

    /** Everyone enrolled, with whether each can sign from the console and any lockout. */
    examiners() {
      return {
        people: listPeople(home()).map((p) => ({ ...personSummary(p), locked_until: lockouts.get(p.id)?.until && (lockouts.get(p.id)?.until ?? 0) > Date.now() ? new Date(lockouts.get(p.id)?.until ?? 0).toISOString() : null })),
        signing: availability(),
      };
    },

    /** Enrolment from the console: an ssh key made here (the passphrase twice), a FIDO key made with a touch, or a token's certificate. */
    async enroll(body: Record<string, unknown>) {
      const kind = body.kind === "fido" || body.kind === "pkcs11" ? body.kind : body.kind === "ssh" ? "ssh" : null;
      if (!kind) throw new SigningError(400, "kind is ssh, fido or pkcs11");
      const role = (["reviewer", "analyst", "observer"] as const).find((r) => r === body.role) ?? "examiner";
      const args = ["enroll", "--name", str(body.name, "name", 200), "--organisation", str(body.organisation, "organisation", 200), "--competence", str(body.competence, "competence"), "--role", role, "--json"];
      if (body.id !== undefined && body.id !== "") args.push("--id", idOf(body.id, "id"));
      let secret: Buffer | null = null;
      if (kind === "ssh") {
        if (body.no_passphrase) throw new SigningError(400, "the console makes an ssh key only with a passphrase: --no-passphrase is a command-line trade");
        const a = secretOf(body.passphrase, "passphrase");
        const b = secretOf(body.passphrase_again, "the passphrase again");
        const same = a.equals(b);
        wipe(b);
        if (!same) {
          wipe(a);
          throw new SigningError(400, "the two passphrases differ: nothing was made");
        }
        if (a.length < 8) {
          wipe(a);
          throw new SigningError(400, "a passphrase of at least 8 characters");
        }
        secret = a;
        args.push("--generate-key", "--passphrase-fd", "3");
      } else if (kind === "fido") {
        args.push("--fido", "--passphrase-fd", "3");
        if (body.fido_verify_required) args.push("--fido-verify-required");
        if (body.fido_resident) args.push("--fido-resident");
        if (typeof body.pin === "string" && body.pin) secret = secretOf(body.pin, "PIN");
      } else {
        args.push("--pkcs11-module", str(body.pkcs11_module, "pkcs11_module", 1024));
        if (typeof body.pkcs11_uri === "string" && body.pkcs11_uri) args.push("--pkcs11-uri", str(body.pkcs11_uri, "pkcs11_uri", 2048));
        else args.push("--pkcs11-id", str(body.pkcs11_id, "pkcs11_id", 256));
        if (typeof body.pkcs11_chain === "string" && body.pkcs11_chain) args.push("--pkcs11-chain", str(body.pkcs11_chain, "pkcs11_chain", 1024));
      }
      const r = await runScript("signers.ts", args, secret, 5 * 60_000);
      if (!r.json?.ok) fail(r, "the enrolment failed");
      const person = (r.json?.person ?? {}) as { id?: string };
      appendOperatorAudit(d.runsDir, "examiner", ["enroll", String(person.id ?? "?"), "--role", role, `--${kind}`], { via: "console" });
      return r.json;
    },

    /** A run's releases, how each was signed, what verify says without a register, the technical reviews, and whether signing is open. */
    async releaseState(id: string) {
      const rec = (readRegistry().runs ?? []).find((r) => r.id === id);
      if (!rec) throw new SigningError(404, "swarm not found");
      const sandbox = typeof rec.sandbox === "string" ? rec.sandbox : join(d.runsDir, id);
      const ctx = runContext(sandbox, { run: id, runsDir: d.runsDir });
      const releases = readReleases(sandbox).map((r) => ({
        version: r.version,
        error: r.error,
        sha256: r.sha256,
        state: r.record?.state ?? null,
        at: r.record?.at ?? null,
        reason: r.record?.reason ?? null,
        signer: r.record ? { kind: r.record.signer.kind, key_kind: r.record.signer.key_kind ?? (r.record.signer.kind === "machine" ? "machine" : "ssh"), fingerprint: r.record.signer.fingerprint, name: r.record.signer.examiner?.name ?? null, organisation: r.record.signer.examiner?.organisation ?? null, cn: r.record.signer.certificate?.cn ?? null } : null,
        signing: r.record?.signing ? { via: r.record.signing.via, consent: r.record.signing.consent, confirmed_at: r.record.signing.confirmed_at, shown_sha256: r.record.signing.shown_sha256 } : null,
        technical: (r.record?.adoption?.technical_review ?? []).map((t) => ({ reviewer: t.reviewer.name, outcome: t.outcome ?? null, words: t.words ?? null })),
      }));
      const reviewFile = reviewsPath(d.runsDir, id);
      let verify: { ok: boolean; lines: string[]; signatures: unknown[] } | null = null;
      if (releases.length) {
        const v = await verifyReleases(runLayout(sandbox, existsSync(reviewFile) ? reviewFile : null, existsSync(custodyAnchorPath(sandbox)) ? custodyAnchorPath(sandbox) : null));
        verify = { ok: v.ok, lines: v.lines, signatures: v.signatures };
      }
      const lines = (await readReviews(d.runsDir, id).catch(() => [])) as Array<ReviewLine & { text: string }>;
      const now = existsSync(sandbox) ? await reviewedStateNow(sandbox, lines) : null;
      const technical = technicalReviewsOf(lines, now, { check: true }).map((t) => ({ review_seq: t.review_seq, reviewer: t.reviewer, recorded_as: t.recorded_as ?? "examiner", outcome: t.outcome ?? null, reviewed_at: t.reviewed_at ?? null, scope: t.scope ?? null, entries: t.entries, disagreements: t.disagreements ?? [], methods_checked: t.methods_checked, status: t.status, words: t.words, countersign: t.countersign ? { review_seq: t.countersign.review_seq, fingerprint: t.countersign.fingerprint, kind: t.countersign.kind, after_release: t.countersign.after_release } : null }));
      return {
        run: id,
        state: rec.state ?? null,
        releases,
        verify,
        technical,
        reviewed_state: now,
        review_lines: lines.length,
        policy: technicalReviewPolicy(ctx),
        host: hostExposure(ctx),
        outcomes: REVIEW_OUTCOMES,
        signing: availability(),
      };
    },

    /** The first half of an adoption: the final bytes rendered once, and what the examiner is asked to confirm. */
    async prepare(id: string, body: Record<string, unknown>) {
      const { sandbox } = runOf(id);
      const examiner = idOf(body.examiner, "examiner");
      const locked = lockedOut(examiner);
      if (locked) throw new SigningError(423, locked);
      const args = ["prepare", sandbox, "--run", id, "--runs", d.runsDir, "--examiner", examiner, "--via", "console"];
      if (body.pdf === true) args.push("--pdf");
      if (typeof body.amend_reason === "string" && body.amend_reason.trim()) args.push("--amend-reason", str(body.amend_reason, "amend_reason", 1000));
      const r = await runScript("release.ts", args, null, 10 * 60_000);
      if (r.code !== 0 || !r.json) {
        const why = r.stderr.trim().replace(/^BLOCKER:\s*/, "") || "the release could not be prepared";
        throw new SigningError(400, why);
      }
      const p = r.json as { nonce: string };
      return { ...r.json, pending: undefined, report_url: `/api/runs/${id}/release/pending/${p.nonce}/report.html` };
    },

    /** The prepared report's own bytes, to be shown in a sandboxed frame. */
    pendingReport(id: string, nonce: string): string {
      if (!/^[0-9a-f]{32}$/.test(nonce)) throw new SigningError(400, "not a nonce");
      const rec = (readRegistry().runs ?? []).find((r) => r.id === id);
      if (!rec) throw new SigningError(404, "swarm not found");
      const sandbox = typeof rec.sandbox === "string" ? rec.sandbox : join(d.runsDir, id);
      return join(sandbox, "release", `.pending-${nonce}`, "report.html");
    },

    /** The second half: sealed with the examiner's secret over exactly the bytes shown, after the consent box was ticked. */
    async seal(id: string, body: Record<string, unknown>) {
      const { sandbox } = runOf(id);
      const examiner = idOf(body.examiner, "examiner");
      if (body.consent !== true) throw new SigningError(400, "the examiner confirms first: \"I have read the report and the answers I adopt\"");
      const nonce = typeof body.nonce === "string" && /^[0-9a-f]{32}$/.test(body.nonce) ? body.nonce : null;
      if (!nonce) throw new SigningError(400, "nonce: the prepared release's");
      const shown = typeof body.shown_sha256 === "string" && /^[0-9a-f]{64}$/.test(body.shown_sha256) ? body.shown_sha256 : null;
      if (!shown) throw new SigningError(400, "shown_sha256: the sha256 of the report shown");
      const locked = lockedOut(examiner);
      if (locked) throw new SigningError(423, locked);
      const secret = typeof body.secret === "string" && body.secret.length ? secretOf(body.secret, "secret") : null;
      delete body.secret;
      const r = await runScript("release.ts", ["seal", sandbox, "--run", id, "--runs", d.runsDir, "--nonce", nonce, "--shown", shown, "--examiner", examiner, "--via", "console", "--consent", "confirmed", "--secret-fd", "3"], secret, 5 * 60_000);
      if (r.code === 5 || r.json?.wrong_secret) {
        wrongSecret(examiner, "release-seal", id);
        appendOperatorAudit(d.runsDir, "release-seal", [id, "--examiner", examiner, "--nonce", nonce], { ok: false, wrong_secret: true });
        const locked2 = lockedOut(examiner);
        throw new SigningError(locked2 ? 423 : 403, locked2 ?? String(r.json?.error ?? "the secret was not the key's: nothing was signed"));
      }
      appendOperatorAudit(d.runsDir, "release-seal", [id, "--examiner", examiner, "--nonce", nonce], r.json?.ok ? { ok: true, version: r.json.version, sha256: r.json.sha256 } : { ok: false, error: r.json?.error ?? null });
      if (!r.json?.ok) fail(r, "the release was not sealed");
      rightSecret(examiner);
      return r.json;
    },

    /** A prepared release given up. */
    async discard(id: string, body: Record<string, unknown>) {
      const { sandbox } = runOf(id);
      const nonce = typeof body.nonce === "string" && /^[0-9a-f]{32}$/.test(body.nonce) ? body.nonce : null;
      if (!nonce) throw new SigningError(400, "nonce: the prepared release's");
      const r = await runScript("release.ts", ["discard", sandbox, "--run", id, "--runs", d.runsDir, "--nonce", nonce], null, 60_000);
      return { ok: r.code === 0 };
    },

    /** A technical reviewer's own record, signed with their secret. */
    async technical(id: string, body: Record<string, unknown>) {
      const { sandbox } = runOf(id);
      const reviewer = idOf(body.reviewer, "reviewer");
      if (body.consent !== true) throw new SigningError(400, "the reviewer confirms the record first");
      const locked = lockedOut(reviewer);
      if (locked) throw new SigningError(423, locked);
      const outcome = typeof body.outcome === "string" && (REVIEW_OUTCOMES as readonly string[]).includes(body.outcome) ? body.outcome : null;
      if (!outcome) throw new SigningError(400, `outcome is ${REVIEW_OUTCOMES.join(", ")}`);
      const args = ["record", "--runs", d.runsDir, "--run", id, "--sandbox", sandbox, "--reviewer", reviewer, "--outcome", outcome, "--checked", str(body.checked, "checked"), "--yes", "--via", "console", "--secret-fd", "3", "--json"];
      if (Array.isArray(body.entries) && body.entries.length) {
        if (!body.entries.every((n) => Number.isInteger(n) && (n as number) > 0)) throw new SigningError(400, "entries are ledger seqs");
        args.push("--entries", body.entries.join(","));
      } else if (body.all_answers === true) args.push("--all-answers");
      for (const x of Array.isArray(body.disagreements) ? body.disagreements : []) args.push("--disagreement", str(x, "disagreement"));
      if (typeof body.reviewed_at === "string" && body.reviewed_at) args.push("--reviewed-at", str(body.reviewed_at, "reviewed_at", 64));
      const secret = typeof body.secret === "string" && body.secret.length ? secretOf(body.secret, "secret") : null;
      delete body.secret;
      const r = await runScript("technical-review.ts", args, secret, 5 * 60_000);
      if (r.code === 5 || r.json?.wrong_secret) {
        wrongSecret(reviewer, "technical-review", id);
        appendOperatorAudit(d.runsDir, "review", [id, "--technical-review", "--reviewer", reviewer], { ok: false, wrong_secret: true });
        const locked2 = lockedOut(reviewer);
        throw new SigningError(locked2 ? 423 : 403, locked2 ?? String(r.json?.error ?? "the secret was not the key's: nothing was written"));
      }
      appendOperatorAudit(d.runsDir, "review", [id, "--technical-review", "--reviewer", reviewer], r.json?.ok ? { ok: true, seq: r.json.seq } : { ok: false, error: r.json?.error ?? null });
      if (!r.json?.ok) fail(r, "the technical review was not recorded");
      rightSecret(reviewer);
      return r.json;
    },

    /** A reviewer's countersign over a record already in the review. */
    async countersign(id: string, body: Record<string, unknown>) {
      const { sandbox } = runOf(id);
      const reviewer = idOf(body.reviewer, "reviewer");
      if (body.consent !== true) throw new SigningError(400, "the reviewer confirms first");
      const seq = Number(body.seq);
      if (!Number.isInteger(seq) || seq < 1) throw new SigningError(400, "seq: the review line to countersign");
      const locked = lockedOut(reviewer);
      if (locked) throw new SigningError(423, locked);
      const secret = typeof body.secret === "string" && body.secret.length ? secretOf(body.secret, "secret") : null;
      delete body.secret;
      const r = await runScript("technical-review.ts", ["countersign", "--runs", d.runsDir, "--run", id, "--sandbox", sandbox, "--reviewer", reviewer, "--seq", String(seq), "--yes", "--via", "console", "--secret-fd", "3", "--json"], secret, 5 * 60_000);
      if (r.code === 5 || r.json?.wrong_secret) {
        wrongSecret(reviewer, "countersign", id);
        appendOperatorAudit(d.runsDir, "review", [id, "--countersign", String(seq), "--reviewer", reviewer], { ok: false, wrong_secret: true });
        const locked2 = lockedOut(reviewer);
        throw new SigningError(locked2 ? 423 : 403, locked2 ?? String(r.json?.error ?? "the secret was not the key's: nothing was written"));
      }
      appendOperatorAudit(d.runsDir, "review", [id, "--countersign", String(seq), "--reviewer", reviewer], r.json?.ok ? { ok: true } : { ok: false, error: r.json?.error ?? null });
      if (!r.json?.ok) fail(r, "the countersign was not written");
      rightSecret(reviewer);
      return r.json;
    },
  };
}

export type Signing = ReturnType<typeof createSigning>;
