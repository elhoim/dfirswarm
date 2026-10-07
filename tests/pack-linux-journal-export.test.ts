/**
 * The Linux pack: journal_export, against a journalctl stand-in that prints `-o json` entries as systemd's
 * "Journal JSON Format" shows them: every value a string, the cursor `s=..;i=..;b=..;m=..;t=..;x=..`,
 * `__REALTIME_TIMESTAMP` and `__MONOTONIC_TIMESTAMP` in microseconds, a field that is a byte array or null.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { JOURNAL, asJob, body, everythingBut, exists, lines, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const BOOT_A = "9d6a4f4b7a7e4b2d9b2f0a1e3f4c5d6e";
const BOOT_B = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const MACHINE = "3f2e1d0c9b8a79685746352413020100";

function entry(seq: number, o: Record<string, string | number[] | null>): string {
  const hex = (n: number): string => n.toString(16);
  const rt = String(1_771_061_400_000_000 + seq * 1_000_000 + 123_456);
  const mono = String(5_000_000 + seq * 1_000_000);
  const boot = (o._BOOT_ID as string) ?? BOOT_A;
  const row: Record<string, unknown> = {
    __CURSOR: `s=739ad463348b4ceca5a9699c3d7d5e1f;i=${hex(0x3a00 + seq)};b=${boot};m=${hex(Number(mono))};t=${hex(Number(rt))};x=1a2b3c4d5e6f${hex(seq)}`,
    __REALTIME_TIMESTAMP: rt,
    __MONOTONIC_TIMESTAMP: mono,
    _BOOT_ID: boot,
    _MACHINE_ID: MACHINE,
    _HOSTNAME: "web01",
    _TRANSPORT: "journal",
    PRIORITY: "6",
    ...o,
  };
  return JSON.stringify(row);
}

/** A journalctl stand-in: prints the file STUB_LINES (or sleeps, or fails), and records its argv in STUB_ARGV. */
async function journalStub(bin: string): Promise<void> {
  const path = join(bin, "journalctl");
  await writeFile(
    path,
    `#!/usr/bin/env python3
import json, os, sys, time
open(os.environ["STUB_ARGV"], "a").write(json.dumps(sys.argv[1:]) + "\\n")
if "--verify" in sys.argv:
    sys.stdout.write(open(os.environ["STUB_VERIFY"]).read())
    sys.stderr.write("stub verify note\\n")
    sys.exit(int(os.environ.get("STUB_VERIFY_EXIT", "0")))
data = open(os.environ["STUB_LINES"], "rb").read()
sys.stdout.buffer.write(data)
sys.stdout.flush()
sys.stderr.write(os.environ.get("STUB_STDERR", ""))
time.sleep(float(os.environ.get("STUB_SLEEP", "0")))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
`,
  );
  await chmod(path, 0o755);
}

async function journalFixture(cwd: string, bin: string, native: string): Promise<Record<string, string>> {
  await journalStub(bin);
  await mkdir(join(cwd, "work", "journal"), { recursive: true });
  await writeFile(join(cwd, "work", "journal", "system.journal"), Buffer.concat([Buffer.from("LPKSHHRH"), Buffer.alloc(248)]));
  await writeFile(join(cwd, "stub-lines.jsonl"), native);
  return { STUB_LINES: join(cwd, "stub-lines.jsonl"), STUB_ARGV: join(cwd, "stub-argv.txt") };
}

const JOURNAL_SECRET = "hunter2-journal-secret";

function nativeJournal(): string {
  return (
    [
      entry(1, { MESSAGE: "Started Session 1 of user alice.", _PID: "812", _UID: "0", _COMM: "systemd", _EXE: "/usr/lib/systemd/systemd", _CMDLINE: "/sbin/init", _SYSTEMD_UNIT: "session-1.scope", SYSLOG_IDENTIFIER: "systemd" }),
      entry(2, { MESSAGE: `sudo: alice : COMMAND=/usr/bin/mount -o password=${JOURNAL_SECRET} //srv/share /mnt`, _PID: "900", _UID: "1000", _COMM: "sudo", _EXE: "/usr/bin/sudo", _CMDLINE: `sudo mount -o password=${JOURNAL_SECRET} //srv/share /mnt`, SYSLOG_IDENTIFIER: "sudo", _AUDIT_SESSION: "3" }),
      // The wall clock stepped back an hour within the boot: the realtime stamp is lower than the entry before's, the monotonic one higher.
      entry(3, { MESSAGE: "clock stepped", _PID: "1", _UID: "0", __REALTIME_TIMESTAMP: "1771057800000001", _SOURCE_REALTIME_TIMESTAMP: "1771057800000000" }),
      entry(4, { MESSAGE: [104, 105, 0, 255], _PID: "2", _UID: "0", _BOOT_ID: BOOT_B }),
      entry(5, { MESSAGE: null, _BOOT_ID: BOOT_B }),
    ].join("\n") + "\n"
  );
}

test("journal_export keeps the whole native export, with the cursor and both clocks, and offers the projection as well", async () => {
  await withCwd(async (cwd, bin) => {
    const native = nativeJournal();
    const env = await journalFixture(cwd, bin, native);
    const run = await asJob(JOURNAL, cwd, { path: "work/journal", write_text: true }, bin, env);
    const out = body(run);
    // Every byte journalctl wrote is in the file, in its order.
    const kept = await readFile(join(cwd, "out", "journal-native.jsonl"), "utf8");
    assert.equal(kept, native);
    assert.equal((await stat(join(cwd, "out", "journal-native.jsonl"))).mode & 0o777, 0o600);
    assert.equal(out.text.written, 5);
    assert.equal(out.entry_count, 5);
    assert.equal(out.export_status, "complete");
    // The projection: the identity and the clocks, as raw values beside the decoded time.
    const rows = await rowsOf(cwd, out);
    assert.equal(rows.length, 5);
    assert.match(rows[1].cursor, /^s=739ad463348b4ceca5a9699c3d7d5e1f;i=/);
    assert.equal(rows[1].realtime_us, "1771061402123456");
    assert.equal(rows[1].monotonic_us, "5000002".replace("5000002", String(5_000_000 + 2_000_000)));
    assert.equal(rows[1].time, "2026-02-14T09:30:02.123456Z");
    assert.equal(rows[1].boot_id, BOOT_A);
    assert.equal(rows[1].machine_id, MACHINE);
    assert.equal(rows[1].audit_session, "3");
    assert.equal(rows[1].native_line, 2);
    assert.equal(rows[2].source_realtime_us, "1771057800000000");
    assert.equal(rows[2].realtime_us, "1771057800000001");
    // A field journalctl encodes as bytes or as null is counted, not turned into text.
    assert.equal(rows[3].message_encoding, "bytes");
    assert.equal(rows[4].message_encoding, "null");
    assert.equal(out.boots_seen, 2);
    const boots = Object.fromEntries(out.boots.map((b: Json) => [b.boot_id, b]));
    assert.equal(boots[BOOT_A].entries, 3);
    assert.equal(boots[BOOT_A].first_monotonic_us, String(6_000_000));
    // The export asked for every field in full and for this journal only.
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.deepEqual(argv.slice(0, 2), ["--directory", "work/journal"]);
    assert.ok(argv.includes("--all") && argv.includes("--no-pager") && argv.includes("json"));
    assert.deepEqual(out.argv.slice(1), argv, "the argv is recorded as an array");
  });
});

test("journal_export does not say the clock is consistent within a boot, or that a missing directory means a volatile journal", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal" }, bin, env));
    assert.doesNotMatch(out.note, /clock is consistent/i);
    assert.doesNotMatch(out.note, /was volatile/i);
    assert.doesNotMatch(out.note, /everything before the last boot is gone/i);
    assert.doesNotMatch(out.note, /boot_id first and time second/i);
    assert.match(out.note, /monotonic/i);
    assert.match(out.note, /not (?:collected|in what you)|path was not/i);
  });
});

test("journal_export keeps messages and command lines out of its answer unless asked, in a job", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    for (const run of [await tool(JOURNAL, cwd, { path: "work/journal", limit: 2 }, env, bin), await asJob(JOURNAL, cwd, { path: "work/journal", limit: 2 }, bin, env)]) {
      const out = body(run);
      assert.ok(out.records[1].message_bytes > 0 && out.records[1].cmdline_bytes > 0);
      assert.ok(!("message" in out.records[1]) && !("cmdline" in out.records[1]));
      assert.equal(out.text.written, 0);
      const all = await everythingBut(cwd, run.stdout, []);
      assert.ok(!all.includes(JOURNAL_SECRET), "no file of the answer carries the command line");
    }
    assert.match(refused(await tool(JOURNAL, cwd, { path: "work/journal", write_text: true }, env, bin)).error, /outside a job/);
    const preview = body(await asJob(JOURNAL, cwd, { path: "work/journal", preview_text: true }, bin, env));
    assert.ok(preview.records[1].message.includes(JOURNAL_SECRET));
    assert.ok(preview.records[1].cmdline.includes(JOURNAL_SECRET));
  });
});

test("journal_export asks for time bounds with their zone and records them", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    const bad = refused(await asJob(JOURNAL, cwd, { path: "work/journal", since: "2026-02-14 00:00:00" }, bin, env));
    assert.match(bad.error, /UTC/);
    assert.match(refused(await asJob(JOURNAL, cwd, { path: "work/journal", until: "yesterday" }, bin, env)).error, /UTC/);
    assert.equal(await exists(env.STUB_ARGV), false, "journalctl was not run with a bound it would have read in this machine's zone");
    const ok = body(await asJob(JOURNAL, cwd, { path: "work/journal", since: "2026-02-14 00:00:00 UTC", until: "@1771100000" }, bin, env));
    assert.deepEqual(ok.time_bounds, { since: "2026-02-14 00:00:00 UTC", until: "@1771100000", interpretation: "as written, with its own zone" });
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.ok(argv.includes("--since") && argv.includes("2026-02-14 00:00:00 UTC"));
  });
});

test("journal_export returns the paths and a partial status when journalctl does not finish, and names a line that is no JSON", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal() + "this is not json\n");
    const slow = body(await asJob(JOURNAL, cwd, { path: "work/journal", write_text: true, max_seconds: 1 }, bin, { ...env, STUB_SLEEP: "30" }));
    assert.equal(slow.timed_out, true);
    assert.equal(slow.export_status, "partial");
    assert.equal(slow.entry_count, 5, "what was read before the deadline is kept");
    assert.match(slow.text.file, /journal-native\.jsonl$/);
    assert.equal(slow.parse_errors.count, 1);
    assert.equal(slow.parse_errors.first[0].native_line, 6);
    assert.ok(!("text" in slow.parse_errors.first[0]));
    // A journalctl that fails and wrote nothing is an error with its stderr kept whole in a file.
    await writeFile(join(cwd, "empty.jsonl"), "");
    const failed = refused(await asJob(JOURNAL, cwd, { path: "work/journal" }, bin, { ...env, STUB_EXIT: "1", STUB_STDERR: "Journal file is corrupted\n", STUB_LINES: join(cwd, "empty.jsonl") }, "out-failed"));
    assert.match(failed.error, /journalctl/);
    assert.equal(failed.exit_code, 1);
    assert.equal(await readFile(join(cwd, "out-failed", "journalctl.stderr"), "utf8"), "Journal file is corrupted\n");
  });
});

test("journal_export verifies in a mode of its own and claims nothing about completeness", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await journalFixture(cwd, bin, nativeJournal());
    await writeFile(join(cwd, "verify.txt"), "PASS: work/journal/system.journal\n");
    const out = body(await asJob(JOURNAL, cwd, { path: "work/journal", mode: "verify" }, bin, { ...env, STUB_VERIFY: join(cwd, "verify.txt") }));
    assert.equal(out.mode, "verify");
    assert.equal(out.exit_code, 0);
    assert.match(out.verify.output_file, /journal-verify\.txt$/);
    assert.equal(await readFile(join(cwd, "out", "journal-verify.txt"), "utf8"), "PASS: work/journal/system.journal\n");
    assert.equal("entry_count" in out, false, "verification exports nothing");
    assert.match(out.claims, /structural/i);
    assert.match(out.does_not_show, /missing|removed|complete/i);
    assert.equal("complete" in out, false);
    const argv: string[] = JSON.parse((await readFile(env.STUB_ARGV, "utf8")).trim().split("\n")[0]);
    assert.ok(argv.includes("--verify"));
  });
});
