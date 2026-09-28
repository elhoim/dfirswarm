#!/usr/bin/env node
/**
 * The technical reviewer's side of two-stage signing: a second person,
 * enrolled on purpose with `swarm.sh examiner enroll --role reviewer`,
 * records what they checked and signs their own record with their own key.
 *
 * A review record (`technical_review` in the run's review file) names who,
 * on what competence, what was checked (entries by seq and hash, or every
 * answer), the outcome (agreed, issues-resolved, disagreement, each
 * disagreement with how it stands), when, and the state it was made over:
 * report.md's sha256, the ledger's head, custody's sha256 and the
 * dispositions' head. The `countersign` line after it carries the
 * reviewer's signature over the record line's exact bytes (SSHSIG in the
 * dfirswarm-review namespace, or a CMS made on an e-signature token), the
 * key, and the latest adopted release when there is one: a countersign after
 * release names vN, and the next amendment binds it.
 *
 * The two lines are made and signed first, then appended together, and only
 * when the review's head is still the one they name: a wrong passphrase
 * leaves nothing behind, and nothing is signed over a review that moved.
 *
 * On another machine the reviewer works from the run's package: `remote`
 * makes the same two lines over the package's own review, report, ledger and
 * custody, into review-import.jsonl; the examiner's `import` checks the
 * hashes, the signature and the register (an allowed-signers file, a CA, or
 * the reviewer's enrolment on this install) and appends them as they are,
 * refusing a file made over a review head that is no longer this run's.
 * Private keys and passphrases never move.
 *
 * A reviewer is refused when they are one of the run's examiners by id, by
 * name or by key: one person is never examiner and reviewer on one run.
 *
 *   node scripts/technical-review.ts record --runs DIR --run ID --sandbox DIR --reviewer ID|NAME
 *        --outcome agreed|issues-resolved|disagreement --checked TEXT [--entries 4,10 | --all-answers]
 *        [--disagreement TEXT]... [--reviewed-at ISO] [--report PATH] [--examiner ID] [--competence TEXT]
 *        [--organisation ORG] [--yes] [--secret-fd N] [--via cli|console] [--json]
 *   node scripts/technical-review.ts countersign --runs DIR --run ID --sandbox DIR --reviewer ID --seq N [--yes] [--secret-fd N] [--via cli|console] [--json]
 *   node scripts/technical-review.ts remote --package DIR --reviewer ID --outcome … --checked … [--out FILE] [--yes] [--secret-fd N]
 *   node scripts/technical-review.ts import --runs DIR --run ID --sandbox DIR --file FILE [--allowed-signers FILE] [--ca FILE [--ca-intermediate FILE]] [--json]
 */
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { cmsVerify } from "./pkcs11.ts";
import { readReleases } from "./release-record.ts";
import {
  appendCountersign,
  appendImported,
  appendReview,
  checkCountersign,
  dispositionsHead,
  independenceConflict,
  isSandboxPath,
  ledgerHead,
  opts,
  readReviews,
  verifyReviewChain,
  REVIEW_OUTCOMES,
  type ReadReviewLine,
  type ReviewLine,
  type ReviewOutcome,
} from "./review.ts";
import { checkSshSignature, consoleRefusal, dfirswarmHome, keyNeeds, keyWords, loadExaminer, loadPerson, signAs, REVIEW_NAMESPACE, type Person } from "./signers.ts";
import { confirmOnTty, hasTty, readFromTty, readSecretFromFd, wipe } from "./secret-io.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** A wrong passphrase or PIN: nothing was written. */
export class WrongReviewSecret extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrongReviewSecret";
  }
}

/** Where a review's parts are: a run (its sandbox and the review beside the registry) or a package. */
type Place = { review: string | null; ledger: string; custody: string; root: string; releasesRoot: string };

export function runPlace(runsDir: string, run: string, sandbox: string): Place {
  return { review: join(runsDir, "reviews", `${run}.jsonl`), ledger: join(sandbox, "ledger", "entries.jsonl"), custody: join(sandbox, "custody.json"), root: sandbox, releasesRoot: sandbox };
}

export function packagePlace(dir: string): Place {
  return { review: join(dir, "review.jsonl"), ledger: join(dir, "ledger.jsonl"), custody: join(dir, "custody.json"), root: dir, releasesRoot: dir };
}

const readOr = (p: string | null): string | null => {
  try {
    return p && existsSync(p) ? readFileSync(p, "utf8") : null;
  } catch {
    return null;
  }
};

function reviewLinesAt(p: Place): ReadReviewLine[] {
  return (readOr(p.review) ?? "")
    .split("\n")
    .filter(Boolean)
    .map((text) => {
      try {
        return { ...(JSON.parse(text) as ReviewLine), text };
      } catch {
        return { text } as ReadReviewLine;
      }
    });
}

/** The state a review is over, read where it is: report.md, the ledger's head, custody, the dispositions. */
function stateAt(p: Place, lines: ReadReviewLine[], reportPath: string) {
  const ledgerText = readOr(p.ledger) ?? "";
  const entries = ledgerText
    .split("\n")
    .filter((l) => l.trim())
    .flatMap((text) => {
      try {
        return [{ ...(JSON.parse(text) as { seq?: number; hash?: string; kind?: string }), text }];
      } catch {
        return [];
      }
    });
  const report = join(p.root, reportPath);
  const custody = readOr(p.custody);
  return {
    entries,
    state: {
      report_sha256: existsSync(report) ? sha256(readFileSync(report)) : null,
      ledger_head: entries.length ? ledgerHead(entries, sha256(ledgerText)) : null,
      custody_sha256: custody === null ? null : sha256(custody),
      dispositions_head: dispositionsHead(lines),
    },
  };
}

/** The run's examiners as the review and the releases name them: whoever made a disposition, recorded a review or adopted a release. */
export function runExaminers(p: Place, lines: ReadReviewLine[], home: string): Array<{ id: string | null; name: string; fingerprint: string | null }> {
  const out = new Map<string, { id: string | null; name: string; fingerprint: string | null }>();
  const add = (id: string | null, name: string, fingerprint: string | null) => out.set(`${id ?? ""}|${name}|${fingerprint ?? ""}`, { id, name, fingerprint });
  for (const l of lines) {
    if (!l.action || l.action === "countersign" || (l.action === "technical_review" && l.recorded_as === "reviewer")) continue;
    let fp = l.key ?? null;
    if (l.examiner_id && !fp) {
      const e = loadExaminer(l.examiner_id, home);
      fp = "examiner" in e ? e.examiner.key.fingerprint : null;
    }
    add(l.examiner_id ?? null, l.examiner, fp);
  }
  for (const r of readReleases(p.releasesRoot)) {
    const x = r.record;
    if (x?.state === "adopted" && x.signer.examiner) add(x.signer.examiner.id, x.signer.examiner.name, x.signer.fingerprint);
  }
  return [...out.values()];
}

/** Why this reviewer cannot review this run: the first examiner they are the same person as. */
function notIndependent(reviewer: Person, examiners: ReturnType<typeof runExaminers>): string | null {
  for (const e of examiners) {
    const clash = independenceConflict({ id: reviewer.id, name: reviewer.name, fingerprint: reviewer.key.fingerprint }, e);
    if (clash) return `${reviewer.name} ${clash.replace("the examiner's", `the examiner ${e.name}'s`)}: one person is never examiner and reviewer on one run`;
  }
  return null;
}

/** The latest adopted release, when there is one: a countersign made after it names it. */
function latestAdopted(root: string): { version: number; sha256: string } | null {
  const a = [...readReleases(root)].reverse().find((r) => r.record?.state === "adopted" && r.sha256);
  return a ? { version: a.version, sha256: a.sha256 as string } : null;
}

/** Sign a record line's bytes as the reviewer: the signature as the countersign line carries it. */
function signRecord(reviewer: Person, text: string, secret: Buffer | null, dropAgent: boolean): { format: "sshsig" | "cms"; namespace: string; data: string } {
  const dir = mkdtempSync(join(tmpdir(), "dfs-review-sign-"));
  try {
    const file = join(dir, "record");
    writeFileSync(file, text);
    const r = signAs(reviewer, file, REVIEW_NAMESPACE, secret, { dropAgent });
    if (!r.ok) {
      if (r.wrongSecret) throw new WrongReviewSecret(`nothing was written: ${r.why}`);
      throw new Error(`the record could not be signed: ${r.why}`);
    }
    return r.format === "cms" ? { format: "cms", namespace: REVIEW_NAMESPACE, data: readFileSync(r.sig).toString("base64") } : { format: "sshsig", namespace: REVIEW_NAMESPACE, data: readFileSync(r.sig, "utf8") };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function signerBlock(p: Person): NonNullable<ReviewLine["signer"]> {
  const k = p.key;
  return { id: p.id, name: p.name, principal: p.principal, kind: k.kind, fingerprint: k.fingerprint, ...(k.kind === "pkcs11" ? { certificate_sha256: k.certificate.sha256 } : { public: k.public }) };
}

export type RecordInput = {
  outcome: string;
  checked: string;
  entries?: number[];
  allAnswers?: boolean;
  disagreements?: string[];
  reviewedAt?: string;
  report?: string;
  note?: string;
};

/**
 * The reviewer's two lines, made over what `place` holds now and signed:
 * the record (seq and prev the review's next) and the countersign after it.
 */
export function makeSignedRecord(place: Place, reviewer: Person, input: RecordInput, secret: Buffer | null, o: { dropAgent: boolean; home: string }): { record: ReviewLine; texts: [string, string]; base: { lines: number; head: string | null } } {
  const lines = reviewLinesAt(place);
  const chain = verifyReviewChain(lines);
  if (!chain.ok) throw new Error(`the review is broken (${chain.reason}): nothing is added to it`);
  const outcome = input.outcome as ReviewOutcome;
  if (!REVIEW_OUTCOMES.includes(outcome)) throw new Error(`a technical review says its outcome (--outcome ${REVIEW_OUTCOMES.join("|")})`);
  if (!input.checked?.trim()) throw new Error("a technical review says which methods were checked (--checked TEXT)");
  const disagreements = (input.disagreements ?? []).map((d) => d.trim()).filter(Boolean);
  if (outcome === "disagreement" && !disagreements.length) throw new Error("a disagreement says what it is, and how it stands (--disagreement TEXT, once for each)");
  if (input.allAnswers && input.entries?.length) throw new Error("a technical review's scope is entries by seq or every answer (--all-answers), not both");
  if (input.reviewedAt !== undefined && !Number.isFinite(Date.parse(input.reviewedAt))) throw new Error(`${JSON.stringify(input.reviewedAt)} is not a date and time (--reviewed-at, ISO 8601)`);
  const reportPath = input.report ?? "work/report.md";
  if (!isSandboxPath(reportPath)) throw new Error(`${JSON.stringify(reportPath)} is not a path under the run (--report work/…)`);
  const clash = notIndependent(reviewer, runExaminers(place, lines, o.home));
  if (clash) throw new Error(clash);
  const { entries, state } = stateAt(place, lines, reportPath);
  if (!state.report_sha256) throw new Error(`there is no ${reportPath} to review`);
  const head = lines.length ? sha256(lines[lines.length - 1].text) : null;
  const at = new Date().toISOString();
  const rec: ReviewLine = {
    v: 1,
    seq: lines.length + 1,
    at,
    examiner: reviewer.name,
    os_user: userInfo().username,
    host: hostname(),
    action: "technical_review",
    examiner_id: reviewer.id,
    key: reviewer.key.fingerprint,
    recorded_as: "reviewer",
    reviewer: { name: reviewer.name, organisation: reviewer.organisation, competence: reviewer.competence, id: reviewer.id, fingerprint: reviewer.key.fingerprint, key_kind: reviewer.key.kind },
    methods_checked: input.checked.trim(),
    outcome,
    reviewed_at: input.reviewedAt ? new Date(input.reviewedAt).toISOString() : at,
    ...(input.entries?.length
      ? {
          scope: "entries" as const,
          entries: input.entries.map((seq) => {
            const e = entries.find((x) => x.seq === seq);
            if (!e) throw new Error(`the ledger has no entry ${seq}`);
            return { seq, hash: e.hash ?? sha256(e.text) };
          }),
        }
      : input.allAnswers
        ? { scope: "all-answers" as const }
        : {}),
    ...(disagreements.length ? { disagreements } : {}),
    report_path: reportPath,
    report_sha256: state.report_sha256,
    ledger_head: state.ledger_head ?? undefined,
    custody_sha256: state.custody_sha256,
    dispositions_head: state.dispositions_head,
    ...(input.note?.trim() ? { note: input.note.trim() } : {}),
    prev: head,
  };
  const recText = JSON.stringify(rec);
  const signature = signRecord(reviewer, recText, secret, o.dropAgent);
  const cs: ReviewLine = {
    v: 1,
    seq: rec.seq + 1,
    at: new Date().toISOString(),
    examiner: reviewer.name,
    os_user: userInfo().username,
    host: hostname(),
    action: "countersign",
    examiner_id: reviewer.id,
    key: reviewer.key.fingerprint,
    over_seq: rec.seq,
    over_sha256: sha256(recText),
    signature,
    signer: signerBlock(reviewer),
    after_release: latestAdopted(place.releasesRoot),
    prev: sha256(recText),
  };
  return { record: rec, texts: [recText, JSON.stringify(cs)], base: { lines: lines.length, head } };
}

/** Append made lines to the run's review, only if its head is still the one they were made over. */
async function appendMade(runsDir: string, run: string, texts: string[], base: { lines: number; head: string | null }): Promise<void> {
  await appendImported(runsDir, run, texts, (before) => {
    const head = before.length ? sha256(before[before.length - 1].text) : null;
    if (before.length !== base.lines || head !== base.head) throw new Error(`the review moved while the record was being signed (${base.lines} lines then, ${before.length} now): nothing was written; record it again`);
  });
}

/**
 * A reviewer's record of a run, made, signed and appended: what the command
 * line and the console do once the reviewer has confirmed and given the
 * secret. Refused for anyone but an enrolled reviewer, and from the console
 * for a key the console does not take.
 */
export async function recordSigned(runsDir: string, run: string, sandbox: string, reviewerId: string, input: RecordInput, secret: Buffer | null, o: { via?: "cli" | "console"; home?: string } = {}): Promise<{ seq: number; countersign_seq: number }> {
  const home = o.home ?? dfirswarmHome();
  const r = loadPerson(reviewerId, home, "reviewer");
  if ("why" in r) throw new Error(r.why);
  if (r.person.role !== "reviewer") throw new Error(`${r.person.name} is enrolled as an examiner: a technical review is signed by an enrolled reviewer`);
  if (o.via === "console") {
    const refused = consoleRefusal(r.person);
    if (refused) throw new Error(refused);
  }
  const made = makeSignedRecord(runPlace(runsDir, run, sandbox), r.person, input, secret, { dropAgent: o.via === "console", home });
  await appendMade(runsDir, run, made.texts, made.base);
  return { seq: made.record.seq, countersign_seq: made.record.seq + 1 };
}

/** A reviewer's countersign over a record already in the review (one the examiner recorded naming them, or one left unsigned). */
export async function countersignRecord(runsDir: string, run: string, sandbox: string, reviewerId: string, seq: number, secret: Buffer | null, o: { via?: "cli" | "console"; home?: string } = {}): Promise<ReviewLine> {
  const home = o.home ?? dfirswarmHome();
  const r = loadPerson(reviewerId, home, "reviewer");
  if ("why" in r) throw new Error(r.why);
  const reviewer = r.person;
  if (reviewer.role !== "reviewer") throw new Error(`${reviewer.name} is enrolled as an examiner: a countersign is a technical reviewer's`);
  if (o.via === "console") {
    const refused = consoleRefusal(reviewer);
    if (refused) throw new Error(refused);
  }
  const place = runPlace(runsDir, run, sandbox);
  const lines = reviewLinesAt(place);
  const clash = notIndependent(reviewer, runExaminers(place, lines.filter((l) => l.seq !== seq), home));
  if (clash) throw new Error(clash);
  return appendCountersign(runsDir, run, { overSeq: seq, signer: signerBlock(reviewer), afterRelease: latestAdopted(sandbox), sign: async (text) => signRecord(reviewer, text, secret, o.via === "console") });
}

/** The secret a signature needs, from a descriptor or the terminal; null when the key needs none. */
async function takeSecret(reviewer: Person, fd: string | undefined): Promise<Buffer | null> {
  if (fd !== undefined) return readSecretFromFd(Number(fd));
  const needs = keyNeeds(reviewer);
  if (!needs.secret) return null;
  if (!hasTty()) throw new Error(`the ${needs.secret === "passphrase" ? "key's passphrase" : "PIN"} is asked on the terminal, and there is none: run it at a terminal, or --secret-fd N`);
  return readFromTty(needs.secret === "pin" ? "The e-signature token's PIN (not shown): " : needs.secret === "fido-pin" ? "The FIDO key's PIN (not shown): " : "The key's passphrase (not shown): ");
}

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

const entriesOf = (s: string | undefined) => (s ? s.split(",").map((x) => Number(x.trim().replace(/^(?:#|E-)/i, ""))).filter((n) => Number.isInteger(n) && n > 0) : undefined);

function recordInput(args: string[]): RecordInput {
  return { outcome: opt(args, "--outcome") ?? "", checked: opt(args, "--checked") ?? "", entries: entriesOf(opt(args, "--entries")), allAnswers: args.includes("--all-answers"), disagreements: opts(args, "--disagreement"), reviewedAt: opt(args, "--reviewed-at"), report: opt(args, "--report"), note: opt(args, "--note") };
}

/** A reviewer's confirmation before signing: on the terminal, unless --yes (the console asks in its own dialog). */
async function confirm(args: string[], summary: string[], question: string, say: (s: string) => void): Promise<boolean> {
  for (const l of summary) say(l);
  if (args.includes("--yes")) return true;
  if (!hasTty()) throw new Error("a technical reviewer's signature asks for confirmation on the terminal, and there is none: run it at a terminal, or pass --yes");
  return confirmOnTty(question).catch(() => false);
}

function summaryOf(reviewer: Person, input: RecordInput, where: string): string[] {
  return [
    `Reviewer:     ${reviewer.name} (${reviewer.id}), ${reviewer.organisation}: ${reviewer.competence}`,
    `Over:         ${where}`,
    `Outcome:      ${input.outcome}${input.disagreements?.length ? `; ${input.disagreements.join("; ")}` : ""}`,
    `Checked:      ${input.checked}${input.entries?.length ? ` (entries ${input.entries.map((n) => `E-${n}`).join(", ")})` : input.allAnswers ? " (every answer)" : ""}`,
    `Key:          ${keyWords(reviewer.key)}${keyNeeds(reviewer).touch ? ": touch it when it blinks" : ""}`,
  ];
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  const home = dfirswarmHome();
  const json = args.includes("--json");
  const say = (s: string) => (json ? console.error(s) : console.log(s));
  const via = opt(args, "--via") === "console" ? "console" : "cli";
  const out = (o: Record<string, unknown>) => (json ? console.log(JSON.stringify(o)) : undefined);
  try {
    switch (cmd) {
      case "record": {
        const runsDir = opt(args, "--runs") ?? process.env.SWARM_RUNS_DIR ?? "";
        const run = opt(args, "--run") ?? "";
        const sandbox = opt(args, "--sandbox") ?? "";
        if (!runsDir || !run || !sandbox) throw new Error("record: --runs DIR, --run ID and --sandbox DIR are required");
        const who = opt(args, "--reviewer") ?? "";
        const enrolled = loadPerson(who, home);
        const input = recordInput(args);
        if (!("person" in enrolled) || enrolled.person.role !== "reviewer") {
          // A reviewer who is not enrolled: the examiner records it, and the reviewer did not sign it.
          const ex = loadExaminer(opt(args, "--examiner") ?? "", home);
          if ("why" in ex) throw new Error(`${who ? `${who} is not an enrolled technical reviewer, so ` : ""}the examiner records this review (--examiner ID): ${ex.why}`);
          const line = await appendReview(runsDir, run, sandbox, {
            action: "technical_review",
            examiner: ex.examiner.name,
            examinerId: ex.examiner.id,
            key: ex.examiner.key.fingerprint,
            reviewer: { name: who, organisation: opt(args, "--organisation"), competence: opt(args, "--competence") ?? "" },
            methodsChecked: input.checked,
            entries: input.entries,
            allAnswers: input.allAnswers,
            outcome: input.outcome,
            reviewedAt: input.reviewedAt,
            disagreements: input.disagreements,
            report: input.report,
            note: input.note,
            recordedAs: "examiner",
          });
          say(`Recorded:     review line ${line.seq}, a technical review by ${who} (${line.outcome}), recorded by the examiner ${ex.examiner.name}; not signed by the reviewer`);
          out({ ok: true, seq: line.seq, signed: false });
          return 0;
        }
        const reviewer = enrolled.person;
        if (via === "console") {
          const refused = consoleRefusal(reviewer);
          if (refused) throw new Error(refused);
        }
        const place = runPlace(runsDir, run, sandbox);
        const lines = reviewLinesAt(place);
        const { state } = stateAt(place, lines, input.report ?? "work/report.md");
        if (!(await confirm(args, summaryOf(reviewer, input, `${input.report ?? "work/report.md"} ${state.report_sha256 ?? "(none)"}, ledger head ${state.ledger_head ?? "none"}, custody ${state.custody_sha256 ?? "none"}, dispositions ${state.dispositions_head}`), `Record and sign this technical review of run ${run} as ${reviewer.name}?`, say))) {
          say("Not signed:   nothing was written.");
          out({ ok: false, error: "not confirmed" });
          return 1;
        }
        for (let attempt = 1; ; attempt++) {
          let secret: Buffer | null = null;
          try {
            secret = await takeSecret(reviewer, opt(args, "--secret-fd"));
            if (keyNeeds(reviewer).touch) say("Touch your key now, every time it blinks.");
            const made = makeSignedRecord(place, reviewer, input, secret, { dropAgent: via === "console", home });
            await appendMade(runsDir, run, made.texts, made.base);
            say(`Signed:       review line ${made.record.seq}, ${reviewer.name}'s technical review (${made.record.outcome}), countersigned at line ${made.record.seq + 1} with ${reviewer.key.fingerprint}`);
            out({ ok: true, seq: made.record.seq, countersign_seq: made.record.seq + 1, signed: true });
            return 0;
          } catch (err) {
            if (err instanceof WrongReviewSecret && opt(args, "--secret-fd") === undefined && hasTty() && attempt < 3) {
              say(`WRONG:        ${err.message}; try again (${3 - attempt} left).`);
              continue;
            }
            throw err;
          } finally {
            wipe(secret);
          }
        }
      }
      case "countersign": {
        const runsDir = opt(args, "--runs") ?? process.env.SWARM_RUNS_DIR ?? "";
        const run = opt(args, "--run") ?? "";
        const sandbox = opt(args, "--sandbox") ?? "";
        const seq = Number(opt(args, "--seq"));
        if (!runsDir || !run || !sandbox || !Number.isInteger(seq)) throw new Error("countersign: --runs DIR, --run ID, --sandbox DIR and --seq N are required");
        const enrolled = loadPerson(opt(args, "--reviewer") ?? "", home, "reviewer");
        if ("why" in enrolled) throw new Error(enrolled.why);
        const reviewer = enrolled.person;
        if (reviewer.role !== "reviewer") throw new Error(`${reviewer.name} is enrolled as an examiner: a countersign is a technical reviewer's`);
        if (via === "console") {
          const refused = consoleRefusal(reviewer);
          if (refused) throw new Error(refused);
        }
        const lines = reviewLinesAt(runPlace(runsDir, run, sandbox));
        const rec = lines.find((l) => l.seq === seq);
        if (!rec || rec.action !== "technical_review") throw new Error(`review line ${seq} is not a technical review`);
        if (!(await confirm(args, [`Countersign:  review line ${seq}, the technical review by ${rec.reviewer?.name ?? "?"} (${rec.outcome ?? "no outcome"}) recorded ${rec.at}`, `Key:          ${keyWords(reviewer.key)}`], `Sign review line ${seq} as ${reviewer.name}?`, say))) {
          out({ ok: false, error: "not confirmed" });
          return 1;
        }
        let secret: Buffer | null = null;
        try {
          secret = await takeSecret(reviewer, opt(args, "--secret-fd"));
          if (keyNeeds(reviewer).touch) say("Touch your key now, every time it blinks.");
          const line = await countersignRecord(runsDir, run, sandbox, reviewer.id, seq, secret, { via, home });
          say(`Signed:       review line ${seq}, countersigned at line ${line.seq}${line.after_release ? `, after release v${line.after_release.version}: the next amendment binds it` : ""}`);
          out({ ok: true, seq: line.seq, after_release: line.after_release ?? null });
          return 0;
        } finally {
          wipe(secret);
        }
      }
      case "remote": {
        const pkg = resolve(opt(args, "--package") ?? "");
        if (!existsSync(join(pkg, "MANIFEST.txt"))) throw new Error(`${pkg} is not a package (no MANIFEST.txt): swarm.sh package <id> makes one`);
        const enrolled = loadPerson(opt(args, "--reviewer") ?? "", home, "reviewer");
        if ("why" in enrolled) throw new Error(enrolled.why);
        const reviewer = enrolled.person;
        if (reviewer.role !== "reviewer") throw new Error(`${reviewer.name} is enrolled as an examiner: a technical review is a reviewer's`);
        const place = packagePlace(pkg);
        const input = recordInput(args);
        const lines = reviewLinesAt(place);
        const { state } = stateAt(place, lines, input.report ?? "work/report.md");
        if (!(await confirm(args, summaryOf(reviewer, input, `the package ${pkg}: ${input.report ?? "work/report.md"} ${state.report_sha256 ?? "(none)"}, over its review of ${lines.length} line(s)`), `Record and sign this technical review as ${reviewer.name}?`, say))) {
          out({ ok: false, error: "not confirmed" });
          return 1;
        }
        let secret: Buffer | null = null;
        try {
          secret = await takeSecret(reviewer, opt(args, "--secret-fd"));
          if (keyNeeds(reviewer).touch) say("Touch your key now, every time it blinks.");
          const made = makeSignedRecord(place, reviewer, input, secret, { dropAgent: false, home });
          const file = resolve(opt(args, "--out") ?? join(pkg, "review-import.jsonl"));
          writeFileSync(file, `${made.texts.join("\n")}\n`, { mode: 0o644, flag: "wx" });
          say(`Wrote:        ${file}: the technical review and its countersign, made over the package's review of ${made.base.lines} line(s). The examiner adds it with swarm.sh review <id> --import ${file}`);
          out({ ok: true, file });
          return 0;
        } finally {
          wipe(secret);
        }
      }
      case "import": {
        const runsDir = opt(args, "--runs") ?? process.env.SWARM_RUNS_DIR ?? "";
        const run = opt(args, "--run") ?? "";
        const sandbox = opt(args, "--sandbox") ?? "";
        const file = opt(args, "--file") ?? "";
        if (!runsDir || !run || !sandbox || !file) throw new Error("import: --runs DIR, --run ID, --sandbox DIR and --file FILE are required");
        const r = await importReview(runsDir, run, sandbox, file, { allowedSigners: opt(args, "--allowed-signers"), ca: opt(args, "--ca"), caIntermediate: opt(args, "--ca-intermediate"), home });
        say(`Imported:     review lines ${r.seq} and ${r.seq + 1}, ${r.reviewer}'s technical review (${r.outcome}) and its countersign; ${r.register}`);
        out({ ok: true, ...r });
        return 0;
      }
      default:
        console.error("usage: technical-review.ts record | countersign | remote | import …");
        return 2;
    }
  } catch (err) {
    const wrong = err instanceof WrongReviewSecret;
    if (json) console.log(JSON.stringify({ ok: false, error: (err as Error).message, wrong_secret: wrong }));
    else console.error(`BLOCKER: ${(err as Error).message}`);
    return wrong ? 5 : 1;
  }
}

/**
 * A review made from the package elsewhere, checked and appended as it is:
 * the first line must follow this run's review head, its hashes must be the
 * run's as it stands, the countersign must be over it and verify, and the
 * key must be one the register given (or this install's enrolment) names.
 */
export async function importReview(runsDir: string, run: string, sandbox: string, file: string, o: { allowedSigners?: string; ca?: string; caIntermediate?: string; home?: string }): Promise<{ seq: number; reviewer: string; outcome: string; register: string }> {
  const texts = readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
  if (texts.length !== 2) throw new Error(`${file} is not a review import: two lines, the technical review and its countersign`);
  const [recText, csText] = texts;
  let rec: ReviewLine;
  let cs: ReviewLine;
  try {
    rec = JSON.parse(recText) as ReviewLine;
    cs = JSON.parse(csText) as ReviewLine;
  } catch {
    throw new Error(`${file} is not JSON lines`);
  }
  if (rec.action !== "technical_review" || !rec.outcome || cs.action !== "countersign") throw new Error(`${file} does not hold a technical review and its countersign`);
  const place = runPlace(runsDir, run, sandbox);
  const lines = await readReviews(runsDir, run);
  const head = lines.length ? sha256(lines[lines.length - 1].text) : null;
  if (rec.seq !== lines.length + 1 || (rec.prev ?? null) !== head) throw new Error(`${file} was made over a review of ${rec.seq - 1} line(s) (head ${rec.prev ?? "none"}), and this run's review is now ${lines.length} line(s) (head ${head ?? "none"}): a stale review head. The reviewer makes it again from a new package.`);
  const { state } = stateAt(place, lines, rec.report_path ?? "work/report.md");
  const differs = [
    rec.report_sha256 !== state.report_sha256 ? `${rec.report_path ?? "work/report.md"} (reviewed ${rec.report_sha256}; here ${state.report_sha256})` : null,
    (rec.ledger_head ?? null) !== state.ledger_head ? "the ledger's head" : null,
    (rec.custody_sha256 ?? null) !== state.custody_sha256 ? "custody.json" : null,
    rec.dispositions_head !== state.dispositions_head ? "the dispositions" : null,
  ].filter(Boolean);
  if (differs.length) throw new Error(`${file} was made over another state of the run: ${differs.join(", ")} differ. Nothing was imported.`);
  if (cs.seq !== rec.seq + 1 || cs.over_seq !== rec.seq || cs.over_sha256 !== sha256(recText) || (cs.prev ?? null) !== sha256(recText)) throw new Error(`${file}'s countersign does not name the review line before it`);
  const sig = checkCountersign(recText, cs);
  if (sig.state === "bad") throw new Error(`${file}'s countersign DOES NOT VERIFY: ${sig.detail}`);
  // Who holds the key: the organisation's register, the certificate's issuer, or this install's enrolment.
  let register: string;
  const signer = cs.signer;
  if (!signer) throw new Error(`${file}'s countersign names no signer`);
  const local = loadPerson(signer.id, o.home ?? dfirswarmHome());
  if (signer.kind === "pkcs11") {
    if (o.ca) {
      const dir = mkdtempSync(join(tmpdir(), "dfs-import-"));
      try {
        writeFileSync(join(dir, "record"), recText);
        writeFileSync(join(dir, "record.p7s"), Buffer.from(cs.signature?.data ?? "", "base64"));
        const v = cmsVerify({ file: join(dir, "record"), sig: join(dir, "record.p7s"), certSha256: signer.certificate_sha256 ?? "", ca: o.ca, intermediates: o.caIntermediate });
        if (v.state !== "verified") throw new Error(`the reviewer's certificate is not one ${o.ca} vouches for: ${v.detail}`);
        register = `the certificate's chain verified against ${o.ca}`;
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    } else if ("person" in local && local.person.key.fingerprint === signer.fingerprint && local.person.role === "reviewer") register = `the reviewer ${signer.id} is enrolled on this install with this certificate`;
    else throw new Error("the reviewer's certificate is not checked against anything: give --ca FILE (the issuer's CA), or enrol the reviewer on this install");
  } else if (o.allowedSigners) {
    const dir = mkdtempSync(join(tmpdir(), "dfs-import-"));
    try {
      writeFileSync(join(dir, "record"), recText);
      writeFileSync(join(dir, "record.sig"), cs.signature?.data ?? "");
      const v = checkSshSignature({ file: join(dir, "record"), sig: join(dir, "record.sig"), namespace: REVIEW_NAMESPACE, principal: signer.principal, publicKey: signer.public ?? "", allowedSigners: o.allowedSigners });
      if (v.state !== "verified") throw new Error(`the register ${o.allowedSigners} does not vouch for the reviewer's key: ${v.detail}`);
      register = `the key is ${signer.principal}'s in ${o.allowedSigners}`;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } else if ("person" in local && local.person.key.fingerprint === signer.fingerprint && local.person.role === "reviewer") register = `the reviewer ${signer.id} is enrolled on this install with this key`;
  else throw new Error("the reviewer's key is not checked against anything: give --allowed-signers FILE (the organisation's register, with the dfirswarm-review namespace), or enrol the reviewer on this install");
  // Independence, against this run's examiners.
  const examiners = runExaminers(place, lines, o.home ?? dfirswarmHome());
  for (const e of examiners) {
    const clash = independenceConflict({ id: signer.id, name: signer.name, fingerprint: signer.fingerprint }, e);
    if (clash) throw new Error(`the reviewer ${signer.name} ${clash}: one person is never examiner and reviewer on one run`);
  }
  await appendImported(runsDir, run, texts, (before) => {
    const h = before.length ? sha256(before[before.length - 1].text) : null;
    if (before.length !== lines.length || h !== head) throw new Error("the review moved during the import: nothing was imported");
  });
  return { seq: rec.seq, reviewer: signer.name, outcome: rec.outcome, register };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(`technical review: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    },
  );
}
