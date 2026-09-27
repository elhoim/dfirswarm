/**
 * Writes tests/fixtures/ledger-v4/: a small run whose ledger holds every
 * kind of entry and every act of version 4, for the renderer to build
 * against and for tests/ledger-v4.test.ts to hold the protocol to.
 *
 * A fictional web-server intrusion, three questions, four seats: a0 and a1
 * find, a3 writes the answers, a2 is the critic. The ledger opens with a
 * legacy version 3 prefix (and a version 1 attestation) written as the
 * harness wrote them before version 4, then goes on through the harness's
 * own record, attest and dispute: a finding resting on a failed job with
 * `qualifies`, an inferred finding with alternatives, a superseded finding
 * cited with its correction, a complete search, a limitation, a hypothesis,
 * a contradiction an answer weighs, an answer per section type, a dispute
 * that invalidates an answer and, through it, the summary (transitively), the
 * corrected answers, a withdrawn dispute, and the limitation that names the
 * one defect left. gate.json is the ledger gate's verdict over it.
 *
 *   node --experimental-strip-types tests/fixtures/ledger-v4/generate.ts
 */
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  attestEntry,
  disputeEntry,
  initSandbox,
  ledgerGate,
  ledgerHash,
  readAttestations,
  readDisputes,
  readLedger,
  recordEntry,
  renderLedger,
  type LedgerEntry,
  type LedgerInput,
} from "../../../extensions/protocol.ts";
import { sealTree, storePaths } from "../../../scripts/evidence-store.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
export const FIXTURE_SECTIONS = ["1", "2", "3", "summary", "narrative"];

const digest = (s: string) => createHash("sha256").update(s).digest("hex");

/** A job as the job service leaves it: its sealed output, its manifest and its job.json. */
async function job(root: string, id: string, files: Record<string, string>, record: Record<string, unknown>): Promise<void> {
  const staging = join(root, "..", `staging-${id}`);
  await mkdir(staging, { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    await mkdir(dirname(join(staging, name)), { recursive: true });
    await writeFile(join(staging, name), text);
  }
  await sealTree(root, staging, join(storePaths(root).jobs, id, "out"), id, 1);
  await writeFile(join(storePaths(root).jobs, id, "job.json"), `${JSON.stringify({ id, attempt: 1, state: "committed", ...record }, null, 2)}\n`);
}

/** Entries as the harness wrote them before version 4: chained, version 3. */
async function legacyPrefix(root: string): Promise<void> {
  const at = (n: number) => `2026-02-03T10:0${n}:00.000Z`;
  const lines: LedgerEntry[] = [
    { v: 3, seq: 1, kind: "event", ts: "2026-02-03T09:12:41.000Z", value: "GET /uploads/shell.php answered 200", source: "inputs/web/access.log", evidence: "line 4411", refs: ["input:web/access.log"], answers: ["1"], basis: "observed", precision: "second", clock: "web server local, logged in UTC", by: "a0", authors: ["a0"], at: at(1) },
    { v: 3, seq: 2, kind: "finding", value: "The web shell was first requested from 203.0.113.7", source: "inputs/web/access.log", evidence: "grep shell.php access.log | head -1 (line 4411)", confidence: "medium", refs: ["input:web/access.log"], answers: ["1"], by: "a0", authors: ["a0"], at: at(2) },
    { v: 3, seq: 3, kind: "ioc", value: "203.0.113.7", source: "inputs/web/access.log", evidence: "line 4411, client address", confidence: "high", by: "a0", authors: ["a0"], at: at(3) },
  ];
  let prev = "genesis";
  const text: string[] = [];
  for (const e of lines) {
    e.prev = prev;
    e.hash = ledgerHash(e, prev);
    prev = e.hash;
    text.push(JSON.stringify(e));
  }
  await mkdir(join(root, "ledger"), { recursive: true });
  await writeFile(join(root, "ledger", "entries.jsonl"), `${text.join("\n")}\n`);
  // a1 recorded #3 word for word: a version 1 attestation, as it was written then.
  const a = { seq: 3, by: "a1", at: at(4) };
  const hash = digest(`genesis\n${JSON.stringify(a)}`);
  await writeFile(join(root, "ledger", "attestations.jsonl"), `${JSON.stringify({ ...a, prev: "genesis", hash })}\n`);
}

function must<T extends { ok: boolean }>(r: T, what: string): T & { ok: true } {
  if (!r.ok) throw new Error(`${what}: ${(r as unknown as { reason: string }).reason}`);
  return r as T & { ok: true };
}

/** Build the run in `root` (an empty directory). */
export async function buildFixtureRun(root: string): Promise<void> {
  await initSandbox(root, { reset: true, agentIds: ["a0", "a1", "a2", "a3"] });
  await writeFile(
    join(root, "inputs.json"),
    `${JSON.stringify({ files: [{ path: "inputs/web.E01", sha256: digest("web.E01"), bytes: 1048576 }, { path: "inputs/web/access.log", sha256: digest("access.log"), bytes: 20480 }] }, null, 2)}\n`,
  );
  const image = { image: "dfirswarm-disk:dev-arm64", image_digest: `sha256:${digest("dfirswarm-disk")}` };
  await job(root, "j000001", { "fls.txt": "0|/var/www/uploads/shell.php|88493-128-4|r/rrw-r--r--|33|33|1284|1770109950|1770109950|1770109950|1770109950\n" }, {
    spec: { kind: "command", inputs: ["input:web.E01"], timeout_seconds: 900, network: "off", profile: "disk", command: "fls -r -m / inputs/web.E01 > \"$OUT/fls.txt\"" },
    requester: { agent: "a0", name: "disk", doing: "file system timeline of the web root" },
    status: "ok",
    exit: 0,
    ...image,
  });
  await job(root, "j000002", { "partial.txt": "09:13:02 id\n09:13:05 uname -a\n09:14:10 tar czf /tmp/www.tgz /var/www\n" }, {
    spec: { kind: "tool", inputs: ["input:web.E01"], timeout_seconds: 120, network: "off", tool: "cmdlog_parse", args: { image: "inputs/web.E01", inode: "90112-128-1", output: "{OUT}/partial.txt" } },
    requester: { agent: "a1", name: "shell", doing: "what ran through the web shell" },
    status: "timed_out",
    exit: null,
    reason: "timed out after 120 s",
    tool_sha256: digest("cmdlog_parse"),
    ...image,
  });
  await job(root, "j000003", { "proxy-grep.txt": "no line for 203.0.113.7 between 2026-02-03T09:00:00Z and 2026-02-03T10:00:00Z\n" }, {
    spec: { kind: "import", inputs: ["work/a1/proxy-grep.txt"], timeout_seconds: 120, network: "off", source: "work/a1/proxy-grep.txt" },
    requester: { agent: "a1", name: "shell", doing: "what ran through the web shell" },
    status: "ok",
    exit: 0,
    ...image,
  });
  await legacyPrefix(root);

  const as = (id: string) => ({ sandboxRoot: root, agentId: id });
  const rec = async (id: string, input: LedgerInput, what: string) => must(await recordEntry(as(id), input), what).entry;
  const observed = { basis: "observed" };

  // --- the finders (a0, a1) ---------------------------------------------------------------
  const e4 = await rec("a0", { kind: "event", ts: "2026-02-03T09:12:30Z", value: "shell.php was created in /var/www/uploads", source: "inputs/web.E01, NTFS $MFT", evidence: "fls -r -m / (job j000001), inode 88493-128-4", refs: ["job:j000001/fls.txt"], locators: [{ ref: "job:j000001/fls.txt", at: "row 1" }], clock: "NTFS $SI created", precision: "second", answers: ["1"], ...observed }, "event");
  const e5 = await rec("a0", {
    kind: "finding",
    value: "The upload handler wrote shell.php to /var/www/uploads eleven seconds before its first request",
    source: "inputs/web.E01 $MFT and inputs/web/access.log",
    evidence: "fls row 1 of job j000001 (created 09:12:30Z) and access.log line 4411 (GET at 09:12:41Z)",
    refs: ["job:j000001/fls.txt", "input:web/access.log"],
    locators: [{ ref: "input:web/access.log", at: "line 4411" }],
    answers: ["1"],
    basis: "observed",
    confidence: "high",
    indicates: "The shell arrived through the site's own upload handler: a file written by the web server process and fetched seconds later is how an upload-then-execute intrusion looks.",
    confidence_why: "Both times come from authoritative records (the $MFT creation time and the server's own log in UTC), the method reads them directly, and the two sources are independent of each other.",
    rel: [{ to: e4.seq, kind: "supports" }],
  }, "finding 5");
  const e6 = await rec("a1", {
    kind: "finding",
    value: "Commands were run through shell.php between 09:13 and 09:15Z",
    source: "inputs/web/access.log",
    evidence: "POST /uploads/shell.php lines 4412-4430, each with a cmd parameter",
    refs: ["input:web/access.log"],
    answers: ["2"],
    basis: "inferred",
    confidence: "medium",
    indicates: "The POSTs carry a cmd parameter and the server answered each with output-sized bodies, which is a shell executing what it was sent.",
    confidence_why: "One source only (the access log), which records the requests and response sizes, not the commands' effect.",
    alternatives: [
      { explanation: "An automated scanner probed the shell without running anything", status: "rejected", why: "the requests arrive at human intervals and their response sizes differ", test_refs: ["input:web/access.log"] },
      { explanation: "The responses are error pages, not command output", status: "open", why: "the log holds sizes only; the bodies were not kept" },
    ],
  }, "finding 6");
  const e7 = await rec("a1", {
    kind: "finding",
    value: "The shell's command log lists an archive of the web root written to /tmp/www.tgz",
    source: "inputs/web.E01, the shell's own log (inode 90112-128-1)",
    evidence: "cmdlog_parse over inode 90112-128-1 (job j000002, timed out): line 3",
    refs: ["job:j000002/partial.txt"],
    answers: ["3"],
    basis: "observed",
    confidence: "medium",
    indicates: "An archive of the whole web root was made on the server, the step that usually precedes taking it.",
    confidence_why: "The tool timed out, but the rows it kept are whole lines of the log; one source, read directly.",
    qualifies: [{ ref: "job:j000002/partial.txt", why: "the parser timed out after writing three whole lines; each line is complete and the file was sealed as the job left it" }],
  }, "finding 7 (failed job, qualified)");
  const e8 = await rec("a1", {
    kind: "finding",
    value: "The archive was sent to 203.0.113.7 over HTTPS",
    source: "inputs/web/access.log",
    evidence: "the shell's last POST answered 200 with 18 MB",
    refs: ["input:web/access.log"],
    answers: ["3"],
    basis: "inferred",
    confidence: "low",
    indicates: "A large response to the shell suggests the archive left through it.",
    confidence_why: "One response size, no content; nothing records a transfer.",
    alternatives_none_why: "recorded early, before the proxy log was read",
  }, "finding 8 (to be superseded)");
  const e9 = await rec("a1", {
    kind: "finding",
    value: "The archive was left in /tmp; the proxy log records no outbound transfer to 203.0.113.7",
    source: "the proxy log, as imported from work/a1/proxy-grep.txt",
    evidence: "grep 203.0.113.7 over the proxy log, 09:00-10:00Z (import job j000003)",
    refs: ["job:j000003/proxy-grep.txt"],
    answers: ["3"],
    basis: "observed",
    confidence: "medium",
    indicates: "The archive was staged but, within the hour the proxy log covers, not sent: #8's inference does not hold.",
    confidence_why: "The proxy log is authoritative for outbound web traffic, but it was grepped in a seat's own VM and imported, so the grep itself is not a sealed job.",
    supersedes: e8.seq,
    because: "the proxy log shows no transfer; the 18 MB response was the shell listing /var/www",
  }, "finding 9 (correction)");
  const e10 = await rec("a0", { kind: "absence", value: "No connection to 203.0.113.7 in the proxy log after 09:12Z", source: "the proxy log, 09:00-10:00Z", evidence: "grep 203.0.113.7 (GNU grep 3.11), the whole imported log", refs: ["job:j000003/proxy-grep.txt"], completion: "complete", answers: ["3"] }, "absence");
  const e11 = await rec("a0", { kind: "limitation", value: "Outbound traffic after 10:00Z was not examined", source: "the proxy log", evidence: "the imported log ends at 10:00Z; later rotations were not in the acquisition", reason: "unavailable", answers: ["3"], rel: [{ to: e10.seq, kind: "derived_from" }] }, "limitation");
  const e12 = await rec("a1", { kind: "hypothesis", value: "The intruder meant to collect the archive later", source: "/tmp/www.tgz left in place", evidence: "no transfer within the logged hour", status: "open", rel: [{ to: e9.seq, kind: "supports" }] }, "hypothesis");
  const e13 = await rec("a0", {
    kind: "finding",
    value: "The first request for shell.php came from 198.51.100.4, a monitoring probe, before 203.0.113.7",
    source: "inputs/web/access.log",
    evidence: "line 4409, user agent of the site's uptime monitor",
    refs: ["input:web/access.log"],
    locators: [{ ref: "input:web/access.log", at: "line 4409" }],
    answers: ["1"],
    basis: "observed",
    confidence: "high",
    indicates: "The monitor fetched the new file first; #2's 'first requested from 203.0.113.7' is the first request by a person, not the first request.",
    confidence_why: "The line and its user agent are in the server's own log, read directly.",
    rel: [{ to: 2, kind: "contradicts" }],
  }, "finding 13 (contradicts legacy #2)");

  // --- the report author (a3) ---------------------------------------------------------------
  const q1 = await rec("a3", {
    kind: "answer",
    section: "question:1",
    value: "The intruder uploaded shell.php through the site's upload handler at 09:12:30Z and first used it from 203.0.113.7",
    reasoning: `The file was created at 2026-02-03T09:12:30Z (E-${e4.seq}) and fetched eleven seconds later (E-1); E-${e5.seq} ties the two to the upload handler. The legacy finding E-2 says the first request came from 203.0.113.7; E-${e13.seq} shows a monitoring probe fetched it first, so 203.0.113.7 is the first person to use it, not the first client.`,
    confidence: "high",
    confidence_why: "Two independent authoritative records agree on the sequence; the probe's earlier request is explained, not contradicting.",
    contrary: [e13.seq],
    alternatives_open: "none open: a stolen administrator login was considered and the log holds no authenticated session before the upload",
    would_change: "an authenticated admin session before 09:12:30Z, or a file creation earlier than the log's first request",
  }, "answer question:1");
  const q2 = await rec("a3", {
    kind: "answer",
    section: "question:2",
    value: "Commands were run through the shell for about two minutes, among them an archive of the web root",
    reasoning: `E-${e6.seq}: the POSTs to shell.php between 09:13 and 09:15Z carry commands; E-${e7.seq} (from a job that timed out, qualified there) lists one of them, the archive of /var/www.`,
    confidence: "medium",
    confidence_why: "The access log is one source for the commands having run; the command list is from a partial parse.",
    alternatives_open: "the responses may be error pages (E-6's open alternative)",
    would_change: "the response bodies, or a process record from memory",
  }, "answer question:2");
  const q3 = await rec("a3", {
    kind: "answer",
    section: "question:3",
    value: "Data was staged in /tmp/www.tgz; no transfer out is recorded within the hour the proxy log covers",
    reasoning: `E-${e7.seq} shows the archive being made. E-${e8.seq} said it was sent; its correction E-${e9.seq} and the complete search E-${e10.seq} show no transfer. The archive's hash, 0123456789abcdef0123456789abcdef, was not recorded by anyone.`,
    confidence: "medium",
    confidence_why: "The proxy log is authoritative for its hour; after it nothing was examined (the limitation).",
    limitations: [e11.seq],
    alternatives_open: "a transfer after 10:00Z, or over a channel the proxy does not see",
    would_change: "the proxy logs after 10:00Z, or firewall flow records",
    inconclusive: false,
  }, "answer question:3");
  const summary = await rec("a3", {
    kind: "answer",
    section: "summary",
    value: "An intruder uploaded a web shell, ran commands through it and archived the web root; no transfer out is recorded in the hour examined.",
    reasoning: `How they got in: E-${q1.seq}. What they ran: E-${q2.seq}. What was taken: E-${q3.seq}.`,
    confidence: "medium",
    confidence_why: "It rests on the three answers, the weakest of them medium.",
  }, "answer summary");
  const narrative = await rec("a3", {
    kind: "answer",
    section: "narrative",
    value: "At 09:12:30Z shell.php was written through the upload handler; eleven seconds later it was fetched, and for two minutes it was used to run commands, the last of which archived the web root into /tmp.",
    reasoning: `09:12:30Z the file is created (E-${e4.seq}); 09:12:41Z the first fetch by a person (E-1, E-${e5.seq}); 09:13-09:15Z commands through the shell (E-${e6.seq}); the archive (E-${e7.seq}); no transfer within the logged hour (E-${e9.seq}, E-${e10.seq}).`,
  }, "answer narrative");

  // --- the critic (a2) ------------------------------------------------------------------------
  must(await attestEntry(as("a2"), { seq: e5.seq, how: "re-derived the creation time from job:j000001/fls.txt row 1 and the request time from input:web/access.log line 4411; read the rest", refs: ["job:j000001/fls.txt", "input:web/access.log"] }), "attest 5");
  for (const a of [q1, q3, narrative]) must(await attestEntry(as("a2"), { seq: a.seq, how: `re-read every entry answer #${a.seq} cites against its refs; re-derived the times from the sealed objects` }), `attest ${a.seq}`);
  // The critic disputes #6: the answer to question 2, and through it the summary, stop standing.
  must(await disputeEntry(as("a2"), { seq: e6.seq, why: "response sizes alone do not show execution; the sizes match the site's 404 page", refs: ["input:web/access.log"] }), "dispute 6");
  // a1 disputes the correction #9 by a0's absence... then takes it back.
  must(await disputeEntry(as("a0"), { seq: e9.seq, why: "the import was copied live and may be incomplete" }), "dispute 9");
  must(await disputeEntry(as("a0"), { seq: e9.seq, withdraw: true, why: "the import's own record shows the file did not change while it was copied" }), "withdraw 9");
  // The author answers the dispute: question 2 again, qualifying #6 and resting on #7.
  const q2b = await rec("a3", {
    kind: "answer",
    section: "question:2",
    value: "At least one command ran through the shell: the archive of the web root; the others are likely but unproven",
    reasoning: `E-${e7.seq} shows the archive command in the shell's own log. E-${e6.seq} is disputed (the sizes match the 404 page), so the other POSTs are not counted as commands.`,
    confidence: "medium",
    confidence_why: "The shell's own log is direct evidence for the one command; the rest rests on a disputed inference.",
    qualifies: [{ ref: `E-${e6.seq}`, why: "cited only for the times of the POSTs, which the dispute does not question" }],
    alternatives_open: "the other POSTs may be probes that ran nothing",
    would_change: "the response bodies, or a process record from memory",
    supersedes: q2.seq,
    because: "E-6 was disputed",
  }, "answer question:2, corrected");
  must(await attestEntry(as("a2"), { seq: q2b.seq, how: "re-derived line 3 of job:j000002/partial.txt; read E-6 for its times only", refs: ["job:j000002/partial.txt"] }), "attest q2b");
  // The narrative rested on #6 too: recorded again, the dispute answered in qualifies.
  const narrative2 = await rec("a3", {
    kind: "answer",
    section: "narrative",
    value: narrative.value,
    reasoning: `09:12:30Z the file is created (E-${e4.seq}); 09:12:41Z the first fetch by a person (E-1, E-${e5.seq}); 09:13-09:15Z POSTs to the shell (E-${e6.seq}, disputed as commands), one of which archived the web root (E-${e7.seq}); no transfer within the logged hour (E-${e9.seq}, E-${e10.seq}).`,
    qualifies: [{ ref: `E-${e6.seq}`, why: "cited for the times of the POSTs, which the dispute does not question" }],
    supersedes: narrative.seq,
    because: "E-6 was disputed",
  }, "answer narrative, corrected");
  must(await attestEntry(as("a2"), { seq: narrative2.seq, how: "re-derived the times from job:j000001/fls.txt and input:web/access.log; read the rest" }), "attest narrative2");
  // The summary still cites the superseded answer: the one defect left, named by a limitation.
  await rec("a3", {
    kind: "limitation",
    value: `The summary E-${summary.seq} still cites the first answer to question 2 (E-${q2.seq}); its wording holds for the corrected answer E-${q2b.seq} and was not rewritten before the run's end`,
    source: "the ledger's answers",
    evidence: "the ledger gate at done named the summary's superseded support",
    reason: "partial",
    rel: [{ to: summary.seq, kind: "derived_from" }],
  }, "limitation naming the defect");
  must(await attestEntry(as("a2"), { seq: summary.seq, how: "re-read the three answers it cites; found its question-2 citation superseded (named by a limitation)" }), "attest summary");
  await renderLedger(root);
}

/** Regenerate the committed fixture. */
async function main(): Promise<void> {
  const work = await mkdtemp(join(tmpdir(), "ledger-v4-fixture-"));
  const root = join(work, "run");
  await mkdir(root, { recursive: true });
  await buildFixtureRun(root);
  const entries = await readLedger(root);
  const gate = ledgerGate({ entries, attestations: await readAttestations(root), disputes: await readDisputes(root), sections: FIXTURE_SECTIONS });
  for (const name of ["ledger", "store", "inputs.json"]) await rm(join(HERE, name), { recursive: true, force: true });
  await cp(join(root, "ledger"), join(HERE, "ledger"), { recursive: true });
  await cp(join(root, "inputs.json"), join(HERE, "inputs.json"));
  // The store without its blob links and read-only modes: the manifests, the job records and the outputs.
  for (const id of await readdir(storePaths(root).jobs)) {
    const from = join(storePaths(root).jobs, id);
    const to = join(HERE, "store", "jobs", id);
    await cp(from, to, { recursive: true });
  }
  const fix = async (dir: string): Promise<void> => {
    await chmod(dir, 0o755);
    for (const name of await readdir(dir)) {
      const p = join(dir, name);
      if ((await stat(p)).isDirectory()) await fix(p);
      else await chmod(p, 0o644);
    }
  };
  await fix(join(HERE, "store"));
  await writeFile(
    join(HERE, "gate.json"),
    `${JSON.stringify({ sections: FIXTURE_SECTIONS, roles: { finders: ["a0", "a1"], author: "a3", critic: "a2" }, answers: Object.fromEntries(Object.entries(gate.answers).map(([k, v]) => [k, v?.seq ?? null])), defects: gate.defects, open: gate.open, unsupported: gate.unsupported }, null, 2)}\n`,
  );
  await fix(work).catch(() => undefined);
  await rm(work, { recursive: true, force: true });
  process.stdout.write(`wrote ${HERE}: ${entries.length} entries; ${gate.defects.length} defects, ${gate.open.length} open\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
