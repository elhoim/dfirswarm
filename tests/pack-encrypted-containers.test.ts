/**
 * The encrypted-containers pack's tools, against fixtures built by the test
 * from the documented formats and never from a tool's own output: a BitLocker
 * recovery password is eight groups of six digits, each a multiple of eleven
 * whose quotient fits sixteen bits; a LUKS1 header is the on-disk layout of
 * the LUKS1 specification (a 592-byte header: 208 bytes of fixed fields, then
 * eight key slots of 48 bytes); a LUKS2 header is cryptsetup's
 * `struct luks2_hdr_disk` (4096 bytes: label at 24, UUID at 168).
 *
 * recovery_key_scan is the reference implementation of the secret-safe output
 * pattern (docs/packs.md, "Secrets and sensitive output"): what it prints and
 * what it writes are checked here for a value, a fragment, a shape and a
 * digest, in the answer and in every file the answer names.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const ENC = join(ROOT, "packs", "encrypted-containers", "tools");
const SCAN = join(ENC, "recovery_key_scan", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

// --- recovery_key_scan --------------------------------------------------------

// A BitLocker recovery password: eight groups of six digits, each a multiple of
// 11 whose quotient is below 65536 (so no group is above 720885).
const QUOTIENTS = [4103, 51234, 7, 65535, 12345, 999, 40000, 20202];
const GROUPS = QUOTIENTS.map((q) => String(q * 11).padStart(6, "0"));
const KEY = GROUPS.join("-");
// The same password with its third group no longer a multiple of 11.
const BAD_GROUPS = GROUPS.map((g, i) => (i === 2 ? "000078" : g));
const BAD_KEY = BAD_GROUPS.join("-");

test("the fixture is a well-formed recovery password by the format's own rule", () => {
  for (const q of QUOTIENTS) assert.ok(q >= 0 && q < 65536);
  for (const g of GROUPS) {
    assert.equal(g.length, 6);
    assert.equal(Number(g) % 11, 0);
    assert.ok(Number(g) / 11 < 65536);
  }
  assert.notEqual(Number(BAD_GROUPS[2]) % 11, 0);
});

type Finding = {
  finding_id: string;
  file: string;
  offset: number;
  length: number;
  kind: string;
  encoding?: string;
  groups_passing_check?: number;
  passes_structure_check?: boolean;
  duplicate_of?: string;
  key_type?: string;
  parser: string;
};
type Exception = { path: string; status: string; reason: string; error?: string; bytes?: number; bytes_read?: number; bytes_unread?: number };
type Page = { matched: number; returned: number; truncated: boolean; all_results?: string };
type Scan = {
  findings: Finding[];
  finding_count: number;
  recovery_passwords: { found: number; pass_structure_check: number };
  files_worth_opening: { file: string; why: string }[];
  exceptions: Exception[];
  coverage: Record<string, number | boolean>;
  pages: { findings: Page; files_worth_opening: Page; exceptions: Page };
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
  truncated: boolean;
  parser: string;
};

/** Everything that must carry no secret: the answer, and each file it names. */
async function everythingPrinted(cwd: string, stdout: string): Promise<string> {
  const answer = JSON.parse(stdout) as Scan;
  let all = stdout;
  for (const page of Object.values(answer.pages ?? {})) {
    if (page.all_results) all += "\n" + (await readFile(join(cwd, page.all_results), "utf8"));
  }
  return all;
}

function assertNoSecret(printed: string): void {
  for (const g of [...GROUPS, ...BAD_GROUPS]) assert.ok(!printed.includes(g), `a group of the value (${g}) is in the output`);
  assert.doesNotMatch(printed, /[0-9a-f]{64}/i, "a 64-hex digest is in the output");
  assert.doesNotMatch(printed, /\*{3,}/, "a masked shape is in the output");
  assert.doesNotMatch(printed, /"shape"|sha256_of_value/);
  // Not a fragment of the value either: no run of eight digits of it, in either spelling.
  const digits = GROUPS.join("");
  for (let i = 0; i + 8 <= digits.length; i++) assert.ok(!printed.includes(digits.slice(i, i + 8)), "a run of the value's digits is in the output");
}

async function plant(cwd: string): Promise<void> {
  await mkdir(join(cwd, "work", "ev", "Users", "alice"), { recursive: true });
  // As Windows' "save a recovery key" writes it: UTF-16LE text with a byte-order mark.
  const note = `BitLocker Drive Encryption recovery key\r\n\r\nRecovery Key ID: 11111111-2222-3333-4444-555555555555\r\n\r\n${KEY}\r\n`;
  await writeFile(join(cwd, "work", "ev", "Users", "alice", "BitLocker Recovery Key 1111.txt"), Buffer.from("﻿" + note, "utf16le"));
  await writeFile(join(cwd, "work", "ev", "notes.txt"), `my notes\nthe key is ${KEY} (copied)\n`);
}

test("recovery_key_scan locates a recovery password without a value, a fragment, a shape or a digest", async () => {
  // It printed the first two digits of each group (sixteen characters of the
  // secret) and an unsalted sha256 of the whole value, in an ordinary answer.
  await withCwd(async (cwd) => {
    await plant(cwd);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assertNoSecret(await everythingPrinted(cwd, out.stdout));
    assert.equal(scan.finding_count, 2);
    assert.equal(scan.recovery_passwords.found, 2);
    assert.equal(scan.recovery_passwords.pass_structure_check, 2);
    const byEncoding = Object.fromEntries(scan.findings.map((f) => [f.encoding ?? "", f]));
    // The text file: after "my notes\nthe key is " (20 bytes).
    assert.equal(byEncoding["ASCII"].offset, "my notes\nthe key is ".length);
    assert.equal(byEncoding["ASCII"].length, 55);
    // The UTF-16LE file: the position of the first digit in the file's bytes.
    const head = "﻿BitLocker Drive Encryption recovery key\r\n\r\nRecovery Key ID: 11111111-2222-3333-4444-555555555555\r\n\r\n";
    assert.equal(byEncoding["UTF-16LE"].offset, head.length * 2);
    assert.equal(byEncoding["UTF-16LE"].length, 55);
    for (const f of scan.findings) {
      assert.equal(f.kind, "BitLocker recovery password");
      assert.equal(f.groups_passing_check, 8);
      assert.equal(f.passes_structure_check, true);
      assert.match(f.finding_id, /^F\d{6}$/);
      assert.match(f.parser, /^recovery_key_scan\//);
    }
    // Where it was found is the answer: file, and the same value twice is said without saying the value.
    assert.match(byEncoding["UTF-16LE"].file, /BitLocker Recovery Key 1111\.txt$/);
    assert.equal(byEncoding["UTF-16LE"].duplicate_of === byEncoding["ASCII"].finding_id || byEncoding["ASCII"].duplicate_of === byEncoding["UTF-16LE"].finding_id, true);
    assert.equal(scan.secret_values.requested, false);
    assert.equal(scan.secret_values.written, 0);
    assert.equal(scan.secret_values.values_file, null);
  });
});

test("recovery_key_scan says a group that fails the multiple-of-eleven check, and calls the result a structure check", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "partial.txt"), `x ${BAD_KEY} y\n`);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0].groups_passing_check, 7);
    assert.equal(scan.findings[0].passes_structure_check, false);
    assert.equal(scan.recovery_passwords.found, 1);
    assert.equal(scan.recovery_passwords.pass_structure_check, 0);
    assert.doesNotMatch(out.stdout, /"complete":/, "the old name claimed more than a structure check shows");
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan writes values only on request, only in a job, only under $OUT, mode 0600", async () => {
  await withCwd(async (cwd) => {
    await plant(cwd);
    // Outside a job there is no sealed output: the request is refused and nothing is written.
    const direct = refused(await tool(SCAN, cwd, { path: "work/ev", write_values: true }));
    assert.match(direct.error, /write_values/);
    assert.match(direct.error, /secret_output/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["ev"]);

    const outDir = join(cwd, "out");
    await mkdir(outDir);
    const job = { JOB_ID: "j000001", OUT: outDir };
    // In a job, without the flag: still no value anywhere.
    const quiet = await tool(SCAN, cwd, { path: "work/ev" }, job);
    assert.deepEqual((await readdir(outDir)).filter((n) => n.includes("password")), []);
    assertNoSecret(await everythingPrinted(outDir, quiet.stdout).catch(() => quiet.stdout));

    const loud = await tool(SCAN, cwd, { path: "work/ev", write_values: true }, job);
    const scan = body<Scan>(loud);
    assert.equal(scan.secret_values.requested, true);
    assert.equal(scan.secret_values.written, 2);
    assert.equal(scan.secret_values.contains_secret_values, true);
    assert.equal(scan.secret_values.values_file, "store/jobs/j000001/out/recovery-passwords.jsonl");
    // The answer names the file and holds no value; the file holds the value, canonical, once per finding.
    assertNoSecret(loud.stdout);
    const file = join(outDir, "recovery-passwords.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; value: string; file: string; offset: number });
    assert.equal(rows.length, 2);
    for (const r of rows) assert.equal(r.value, KEY);
    assert.deepEqual(rows.map((r) => r.finding_id).sort(), scan.findings.map((f) => f.finding_id).sort());
    // Nothing else under $OUT carries it: the metadata page, if any, is clean.
    for (const name of await readdir(outDir, { recursive: true })) {
      if (name === "recovery-passwords.jsonl") continue;
      const path = join(outDir, name);
      if ((await stat(path)).isFile()) assertNoSecret(await readFile(path, "utf8"));
    }
  });
});

test("recovery_key_scan keeps a finding that straddles its read window, once", async () => {
  // Streaming reads 4 MiB at a time; a value across the seam is found once,
  // at its true offset, and one past the seam is not lost.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const window = 1 << 22;
    const blob = Buffer.alloc(window + (1 << 20), 0x20);
    blob.write(KEY, window - 20, "latin1");
    blob.write(KEY, window + 5000, "latin1");
    blob.write(KEY, blob.length - 55, "latin1");
    await writeFile(join(cwd, "work", "ev", "big.bin"), blob);
    const out = await tool(SCAN, cwd, { path: "work/ev", max_bytes_per_file: 16 << 20 });
    const scan = body<Scan>(out);
    assert.deepEqual(scan.findings.map((f) => f.offset), [window - 20, window + 5000, blob.length - 55]);
    assert.equal(scan.coverage.files_partial, 0);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan lists a file it could only read a prefix of, with the bytes it did not read", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const blob = Buffer.alloc(10_000, 0x20);
    blob.write(KEY, 9000, "latin1");
    await writeFile(join(cwd, "work", "ev", "tail.bin"), blob);
    const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev", max_bytes_per_file: 4096 }));
    assert.equal(scan.finding_count, 0, "the value sits past the budget");
    assert.equal(scan.coverage.files_partial, 1);
    const partial = scan.exceptions.find((e) => e.status === "partial");
    assert.ok(partial, JSON.stringify(scan.exceptions));
    assert.equal(partial.bytes, 10_000);
    assert.equal(partial.bytes_read, 4096);
    assert.equal(partial.bytes_unread, 10_000 - 4096);
    assert.equal(scan.coverage.max_bytes_per_file, 4096);
    assert.equal(scan.coverage.bytes_unread_in_partial_files, 10_000 - 4096);
  });
});

// Reads that fail with EIO, wherever the tool runs: root reads a mode-000 file,
// so the failure is made by the interpreter, not by chmod. unreadable.bin fails
// to open; flaky.bin gives its first read and fails the next, part way through.
const EIO_SITE = String.raw`
import builtins, errno, os
_real = builtins.open
class _Flaky:
    def __init__(self, fh):
        self._fh, self._n = fh, 0
    def read(self, n=-1):
        self._n += 1
        if self._n > 1:
            raise OSError(errno.EIO, "Input/output error")
        return self._fh.read(n)
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self._fh.close()
def _open(file, *args, **kwargs):
    name = os.fsdecode(file) if isinstance(file, (str, bytes, os.PathLike)) else ""
    if name.endswith("unreadable.bin"):
        raise OSError(errno.EIO, "Input/output error", name)
    if name.endswith("flaky.bin"):
        return _Flaky(_real(file, *args, **kwargs))
    return _real(file, *args, **kwargs)
builtins.open = _open
`;

test("recovery_key_scan names a file it could not read, and does not count it as read", async () => {
  // A read failure returned no findings, and the file was still counted in
  // files_scanned: the answer said "searched, nothing" for a file it never read.
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    await writeFile(join(cwd, "work", "ev", "readable.txt"), "nothing here\n");
    await writeFile(join(cwd, "work", "ev", "unreadable.bin"), `${KEY}\n`);
    const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") }));
    assert.equal(scan.coverage.files_attempted, 2);
    assert.equal(scan.coverage.files_read, 1);
    assert.equal(scan.coverage.files_failed, 1);
    const failed = scan.exceptions.filter((e) => e.status === "failed");
    assert.equal(failed.length, 1);
    assert.match(failed[0].path, /unreadable\.bin$/);
    assert.match(failed[0].error ?? "", /Input\/output error|EIO|\[Errno 5\]/);
    assert.equal(scan.finding_count, 0);
  });
});

test("recovery_key_scan keeps what it found before a read failed part way, and still calls the file failed", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    await mkdir(join(cwd, "pystub"), { recursive: true });
    await writeFile(join(cwd, "pystub", "sitecustomize.py"), EIO_SITE);
    const text = `first ${KEY} last\n`;
    await writeFile(join(cwd, "work", "ev", "flaky.bin"), text);
    const out = await tool(SCAN, cwd, { path: "work/ev" }, { PYTHONPATH: join(cwd, "pystub") });
    const scan = body<Scan>(out);
    assert.equal(scan.finding_count, 1, "the value in the part that was read is still reported");
    assert.equal(scan.coverage.files_failed, 1);
    assert.equal(scan.coverage.files_read, 0);
    const failed = scan.exceptions.filter((e) => e.status === "failed");
    assert.equal(failed.length, 1);
    assert.equal(failed[0].bytes_read, text.length);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan names a file whose permissions refuse the read (where the user is not root)", async (t) => {
  if (process.getuid?.() === 0) return t.skip("root reads a mode-000 file; the read failure is covered by the EIO case");
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "locked"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "secret.txt"), `${KEY}\n`);
    await chmod(join(cwd, "work", "ev", "secret.txt"), 0o000);
    await writeFile(join(cwd, "work", "ev", "locked", "inside.txt"), `${KEY}\n`);
    await chmod(join(cwd, "work", "ev", "locked"), 0o000);
    try {
      const scan = body<Scan>(await tool(SCAN, cwd, { path: "work/ev" }));
      assert.equal(scan.coverage.files_failed, 1);
      assert.equal(scan.coverage.directories_failed, 1);
      assert.equal(scan.coverage.files_read, 0);
      assert.deepEqual(scan.exceptions.map((e) => e.status).sort(), ["failed", "failed"]);
    } finally {
      await chmod(join(cwd, "work", "ev", "locked"), 0o755);
      await chmod(join(cwd, "work", "ev", "secret.txt"), 0o644);
    }
  });
});

test("recovery_key_scan reads regular files only, follows no link, and reports what it skipped and why", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev", "proc"), { recursive: true });
    await mkdir(join(cwd, "work", "ev", "Users", "bob", "dev"), { recursive: true });
    await writeFile(join(cwd, "work", "ev", "proc", "hidden.txt"), `${KEY}\n`);
    await writeFile(join(cwd, "work", "ev", "Users", "bob", "dev", "kept.txt"), `${KEY}\n`);
    await mkdir(join(cwd, "work", "outside"), { recursive: true });
    await writeFile(join(cwd, "work", "outside", "linked.txt"), `${KEY}\n`);
    await symlink(join(cwd, "work", "outside", "linked.txt"), join(cwd, "work", "ev", "file-link.txt"));
    await symlink(join(cwd, "work", "outside"), join(cwd, "work", "ev", "dir-link"));
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    // The directory named dev two levels down is evidence; a root-level proc is not scanned, and is said so.
    assert.deepEqual(scan.findings.map((f) => f.file.replace(/^.*work\/ev\//, "")), ["Users/bob/dev/kept.txt"]);
    const skipped = scan.exceptions.filter((e) => e.status === "skipped").map((e) => e.path.replace(/^.*work\/ev\//, "")).sort();
    assert.deepEqual(skipped, ["dir-link", "file-link.txt", "proc"]);
    for (const e of scan.exceptions.filter((x) => x.status === "skipped")) assert.ok(e.reason.length > 10);
    assert.equal(scan.coverage.files_attempted, 1);
    assertNoSecret(out.stdout);
  });
});

test("recovery_key_scan pages its findings and keeps the whole of them, still without a value", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(cwd, "work", "ev", `n${i}.txt`), `k ${KEY}\n`);
    const out = await tool(SCAN, cwd, { path: "work/ev", limit: 2 });
    const scan = body<Scan>(out);
    assert.equal(scan.finding_count, 5);
    assert.equal(scan.findings.length, 2);
    assert.equal(scan.truncated, true);
    assert.equal(scan.pages.findings.matched, 5);
    const whole = (await readFile(join(cwd, scan.pages.findings.all_results!), "utf8")).trimEnd().split("\n");
    assert.equal(whole.length, 5);
    assertNoSecret(await everythingPrinted(cwd, out.stdout));
  });
});

test("recovery_key_scan reports a private key by type and place, never its body", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "ev"), { recursive: true });
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n";
    await writeFile(join(cwd, "work", "ev", "id_ed25519"), pem);
    const out = await tool(SCAN, cwd, { path: "work/ev" });
    const scan = body<Scan>(out);
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0].kind, "private key");
    assert.equal(scan.findings[0].key_type, "OPENSSH PRIVATE KEY");
    assert.equal(scan.findings[0].offset, 0);
    assert.ok(!out.stdout.includes("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU="));
    assert.equal(scan.files_worth_opening.length, 1);
  });
});

test("recovery_key_scan refuses what it cannot answer for, loudly", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(SCAN, cwd, {})).error, /path is required/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work/missing" })).error, /no such file or directory/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", max_bytes_per_file: 10 })).error, /at least 1024/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", limit: 0 })).error, /limit/);
    assert.match(refused(await tool(SCAN, cwd, { path: "work", write_values: "yes" })).error, /write_values/);
  });
});
