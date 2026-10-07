/**
 * The mobile pack's recipes, against archives the test builds from the formats' own layouts and stand-ins for
 * iLEAPP and ALEAPP that print what those programs print and write a report folder the way they do.
 *
 * Tar: Python's tarfile writes the archive (GNU format, so a name that is not UTF-8 is kept as bytes). An adb
 * backup is "ANDROID BACKUP\n", the version, the compression flag and the encryption scheme on their own lines,
 * then a tar, zlib-compressed when the flag says so; a member's content is streamed through the compressor, so
 * 300 MiB of zeros costs a few hundred KiB on disk.
 *
 * To see that a test fails on the code it was written against, point MOBILE_PACK at a copy of the pack as it
 * was before the fixes:
 *
 *   git archive origin/claude/pack-standard-and-links packs/mobile-forensics | tar -x -C /tmp/old
 *   MOBILE_PACK=/tmp/old/packs/mobile-forensics node --experimental-strip-types --test tests/pack-mobile-recipes.test.ts
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";

const PACK = process.env.MOBILE_PACK ?? join(ROOT, "packs", "mobile-forensics");
const RECIPES = join(PACK, "recipes");

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

/** Every regular file under a directory (not following links), with its bytes. */
async function filesUnder(dir: string): Promise<{ path: string; data: Buffer }[]> {
  const found: { path: string; data: Buffer }[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) await walk(p);
      else if (entry.isFile()) found.push({ path: p, data: await readFile(p) });
    }
  };
  await walk(dir);
  return found;
}

// --- the recipes ------------------------------------------------------------------------

type RecipeRun = { code: number | null; stdout: string; stderr: string };

function recipe(name: string, args: string[], cwd: string, env: Record<string, string> = {}, extraPath?: string): Promise<RecipeRun> {
  return new Promise((resolve, reject) => {
    const e = { ...process.env, ...env };
    if (extraPath) e.PATH = `${extraPath}:${e.PATH ?? ""}`;
    const child = spawn("python3", [join(RECIPES, name, "run.py"), ...args], { cwd, env: e });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
  });
}

const target = (path: string): string => JSON.stringify({ paths: [path] });

type Coverage = {
  recipe: string; status: string; covered: string; not_covered: string; limits_hit: string[]; errors: string[];
  modules?: { log_format_recognised: boolean; counts: Record<string, number>; records_reported_by_modules: number; tracebacks_on_stderr: number; report_layout: string; files_beside_the_report?: string; files_left_in_program_directories?: Record<string, number> };
  payload_stream?: string; tar_end?: string; decompressed_bytes?: number; categories?: Record<string, number>;
};

async function coverage(out: string): Promise<Coverage> {
  return JSON.parse(await readFile(join(out, "coverage.json"), "utf8")) as Coverage;
}

/** A tar of the named members (name -> bytes), made by Python's tarfile. */
const TAR = String.raw`
import io, json, sys, tarfile
path, spec = sys.argv[1], json.loads(sys.argv[2])
with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
    for name, size in spec:
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        archive.addfile(info, io.BytesIO(b"x" * size))
`;

/** A stand-in for iLEAPP or ALEAPP: writes a report folder like the real one, with the log lines the test gives. */
async function standin(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  await writeFile(join(bin, name), `#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2;; -t) kind="$2"; shift 2;; -i) src="$2"; shift 2;; *) shift;; esac; done\n${script}\n`, "utf8");
  await chmod(join(bin, name), 0o755);
}

const REPORT = String.raw`d="$out/Reports_2026-10-01"; mkdir -p "$d/_TSV Exports" "$d/_Timeline" "$d/_HTML"; : > "$d/_Timeline/tl.db"; : > "$d/_HTML/index.html"`;

/** Log lines in the shape iLEAPP v2026.4.1 prints, for a stand-in: a module that found records, one that found nothing, one that failed. */
const LOG = {
  header: (n: number): string => `echo "Artifact to parse: ${n}"`,
  found: (i: number, n: number, name: string, mod: string, records: number): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; printf 'a\\tb\\n1\\t2\\n' > "$d/_TSV Exports/${name}.tsv"; echo "Found ${records} records for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  nofile: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "No file found"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  nodata: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "No data found for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  failed: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "Error with /some/path/${name}.sqlite:"; echo " - unable to open database: file:None?mode=ro"
echo "Reading ${name} artifact had errors!"; echo "Error was list index out of range"; echo "Exception Traceback: Traceback (most recent call last):"; echo "  File \\"x.py\\", line 1, in ${name}"
echo "${name} [${mod}] artifact failed after 0.0s"`,
  readerror: (i: number, n: number, name: string, mod: string): string =>
    `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"; echo "${name}: error reading /case/path/db: no such table: t54-SECRET-TABLE"; echo "No data found for ${name}"; echo "${name} [${mod}] artifact completed in 0.0s"`,
  started: (i: number, n: number, name: string, mod: string): string => `echo "[${i}/${n}] ${name} [${mod}] artifact started at 09:29:44 UTC"`,
  end: `echo "Processes completed."`,
};

for (const [recipeName, program, marker, label] of [
  ["ios-ileapp", "ileapp", "private/var/mobile/Library/SMS/sms.db", "iLEAPP"],
  ["android-aleapp", "aleapp", "data/system/packages.xml", "ALEAPP"],
] as const) {
  test(`${recipeName} is complete only when its log accounts for every module and none errored (exit 0 and a TSV are not enough)`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16], ["data/data/com.example/databases/x.db", 4]]));
      const run = async (out: string, lines: string[]): Promise<{ result: RecipeRun; coverage: Coverage; tsv: string[] }> => {
        await standin(bin, program, `${REPORT}\n${lines.join("\n")}`);
        const result = await recipe(recipeName, ["run", "--target", target(tar), "--out", join(cwd, out)], cwd, {}, bin);
        const tsv = (await exists(join(cwd, out, "modules.tsv"))) ? (await readFile(join(cwd, out, "modules.tsv"), "utf8")).trimEnd().split("\n") : [];
        return { result, coverage: await coverage(join(cwd, out)), tsv };
      };
      // A module failed while another wrote its report, and the program exited 0: partial, and which module.
      const bad = await run("bad", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.failed(2, 2, "addressBook", "addressBook"), LOG.end]);
      assert.equal(bad.result.code, 0);
      assert.equal(bad.coverage.status, "partial", "exit 0 and a TSV said complete before");
      assert.deepEqual(bad.coverage.modules?.counts, { completed: 1, no_record: 0, errored: 1, errors_logged: 0, unknown: 0 });
      assert.ok(bad.coverage.errors.some((e) => /1 module\(s\) errored: addressBook/.test(e)), JSON.stringify(bad.coverage.errors));
      assert.match(bad.tsv[2], /^1\terrored\taddressBook\taddressBook\t0\t\d+\t/);
      assert.doesNotMatch(bad.coverage.covered, /ran every module/);
      assert.doesNotMatch(JSON.stringify(bad.coverage) + bad.tsv.join("\n"), /list index out of range|unable to open/, "the module's error text is in the kept log, not in the receipt");
      // Every module completed: complete, with what each says it found. A module that found nothing is no_record, never "absent".
      const good = await run("good", [LOG.header(3), LOG.found(1, 3, "Messages", "messages", 2), LOG.nofile(2, 3, "Notes", "notes"), LOG.nodata(3, 3, "Mail", "mail"), LOG.end]);
      assert.equal(good.coverage.status, "complete", JSON.stringify(good.coverage));
      assert.deepEqual(good.coverage.modules?.counts, { completed: 1, no_record: 2, errored: 0, errors_logged: 0, unknown: 0 });
      assert.equal(good.coverage.modules?.log_format_recognised, true);
      assert.equal(good.coverage.modules?.records_reported_by_modules, 2);
      assert.equal(good.tsv[0], "n\tstatus\tartefact\tmodule\trecords\tlogged_error_lines\tlog\tline");
      assert.match(good.tsv[1], new RegExp(`^0\\tcompleted\\tMessages\\tmessages\\t2\\t0\\t${program}.stdout\\t\\d+$`));
      assert.match(good.tsv[2], /^1\tno_record\tNotes\tnotes\t0\t0\t/);
      assert.match(good.tsv[3], /^2\tno_record\tMail\tmail\t0\t0\t/);
      assert.match(await readFile(join(cwd, "good", "index.tsv"), "utf8"), /^modules\.tsv\t/m);
      // A module that completed but wrote error lines (it could not read a table and said so): not complete, and its text is not copied.
      const logged = await run("logged", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.readerror(2, 2, "Telegram", "telegram"), LOG.end]);
      assert.equal(logged.coverage.status, "partial");
      assert.equal(logged.coverage.modules?.counts.errors_logged, 1);
      assert.match(logged.tsv[2], /^1\terrors_logged\tTelegram\ttelegram\t0\t1\t/);
      assert.doesNotMatch(JSON.stringify(logged.coverage) + logged.tsv.join("\n"), /SECRET-TABLE/);
      // A module that started and said nothing more is unknown, and a log that stops short of the modules it announced is not complete.
      const cut = await run("cut", [LOG.header(2), LOG.found(1, 2, "Messages", "messages", 2), LOG.started(2, 2, "Notes", "notes")]);
      assert.equal(cut.coverage.status, "partial");
      assert.equal(cut.coverage.modules?.counts.unknown, 1);
      const short = await run("short", [LOG.header(3), LOG.found(1, 3, "Messages", "messages", 2), LOG.nofile(2, 3, "Notes", "notes"), LOG.end]);
      assert.equal(short.coverage.status, "partial");
      assert.ok(short.coverage.errors.some((e) => /says 3 modules would be parsed and 2 started/.test(e)), JSON.stringify(short.coverage.errors));
      const noend = await run("noend", [LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2)]);
      assert.equal(noend.coverage.status, "partial");
      assert.ok(noend.coverage.errors.some((e) => /does not end with its processing-completed line/.test(e)));
      // No module lines at all (a release that logs another way): every module is unknown, and the run is partial.
      const silent = await run("silent", [String.raw`printf 'a\tb\n1\t2\n' > "$d/_TSV Exports/Messages.tsv"`]);
      assert.equal(silent.coverage.status, "partial");
      assert.equal(silent.coverage.modules?.log_format_recognised, false);
      assert.ok(silent.coverage.errors.some((e) => /no module lines/.test(e)));
      // A traceback on stderr is a problem even if the exit status is 0.
      const trace = await run("trace", [LOG.header(1), LOG.found(1, 1, "Messages", "messages", 2), LOG.end, `echo "Traceback (most recent call last):" >&2; echo "  boom" >&2`]);
      assert.equal(trace.coverage.status, "partial");
      assert.equal(trace.coverage.modules?.tracebacks_on_stderr, 1);
      assert.match(await readFile(join(cwd, "trace", `${program}.stderr`), "utf8"), /Traceback/, `${label}'s stderr is kept whole`);
    });
  });

  test(`${recipeName} keeps every file the program leaves in its scratch tree, runs it from a directory under the output (a relative one too) and never writes the run directory`, async () => {
    await withCwd(async (cwd, bin) => {
      const tar = join(cwd, "work", "acq.tar");
      await build(TAR, tar, JSON.stringify([[marker, 16]]));
      // The program writes a log beside its report folder, a file in its working directory, one in its temp directory and a link in its working directory.
      await standin(bin, program, `${REPORT}\n${LOG.header(1)}\n${LOG.found(1, 1, "Messages", "messages", 2)}\n${LOG.end}
echo "log beside the report" > "$out/run-log.txt"; pwd > "$out/../cwd-seen.txt"; echo "left in cwd" > ./left-in-cwd.txt; echo "temp" > "$TMPDIR/left-in-tmp.txt"; ln -s /tmp ./linked-directory; mkdir -p "$TMPDIR/sub/deeper"`);
      // A read-only run directory: the recipe is started from it, as a job's worker is. The output is given relative to it, as a caller may.
      const runDir = join(cwd, "ro-run");
      await mkdir(runDir);
      await mkdir(join(cwd, "rel"));
      const out = join(cwd, "rel", "out-dir");
      await chmod(runDir, 0o555);
      const result = await recipe(recipeName, ["run", "--target", target(tar), "--out", "../rel/out-dir"], runDir, {}, bin);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(out);
      assert.equal(cov.status, "complete", JSON.stringify(cov));
      // The sibling file is kept, whole, beside the report; the report is where it was.
      assert.equal(await readFile(join(out, `${program}-run-files`, "run-log.txt"), "utf8"), "log beside the report\n");
      assert.equal(await exists(join(out, program, "_TSV Exports", "Messages.tsv")), true, "the one report folder is the report");
      assert.equal(cov.modules?.report_layout.startsWith("one report folder; 1 file(s) beside it"), true, JSON.stringify(cov.modules));
      // The program ran with its working directory and TMPDIR under the output, and what it left there is counted and kept (a link too).
      assert.equal((await readFile(join(out, "cwd-seen.txt"), "utf8")).trim().endsWith(`${program}-cwd`), true);
      assert.equal(await readFile(join(out, `${program}-cwd`, "left-in-cwd.txt"), "utf8"), "left in cwd\n");
      assert.equal(await readFile(join(out, `${program}-tmp`, "left-in-tmp.txt"), "utf8"), "temp\n");
      assert.deepEqual(cov.modules?.files_left_in_program_directories, { [`${program}-cwd`]: 2, [`${program}-tmp`]: 1 });
      // Nothing was written to the run directory, and the scratch directory is gone.
      assert.deepEqual(await readdir(runDir), []);
      assert.equal(await exists(join(out, `${program}-run`)), false);
      // A second run into the same output leaves the first run's coverage and report as they are.
      const before = (await readFile(join(out, "coverage.json"))).toString();
      const again = await recipe(recipeName, ["run", "--target", target(tar), "--out", "../rel/out-dir"], runDir, {}, bin);
      assert.equal(again.code, 2);
      assert.equal(JSON.parse(again.stdout).status, "refused");
      assert.equal((await readFile(join(out, "coverage.json"))).toString(), before, "the earlier coverage.json is untouched");
      assert.equal(await exists(join(out, program, "_TSV Exports", "Messages.tsv")), true);
    });
  });

  test(`${recipeName} dispatches a zip by its signature or its end record, and says a damaged one is not readable`, async () => {
    await withCwd(async (cwd) => {
      const good = join(cwd, "work", "good.zip");
      await build(`import sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], "w")\nz.writestr(sys.argv[2], b"x")\nz.close()\n`, good, marker);
      const detect = await recipe(recipeName, ["detect", "--target", target(good)], cwd);
      assert.equal(detect.code, 0, detect.stdout);
      assert.equal(JSON.parse(detect.stdout).applies, true);
      // Data before the first local header (a self-extracting archive): still a zip.
      const data = await readFile(good);
      const prefixed = join(cwd, "work", "prefixed.zip");
      await writeFile(prefixed, Buffer.concat([Buffer.alloc(100, 0x41), data]));
      assert.equal(JSON.parse((await recipe(recipeName, ["detect", "--target", target(prefixed)], cwd)).stdout).applies, true);
      // The end-of-central-directory record is cut off: whatever this Python's is_zipfile says, a zip that cannot be read is said so.
      const broken = join(cwd, "work", "broken.zip");
      await writeFile(broken, data.subarray(0, data.length - 12));
      const bad = await recipe(recipeName, ["detect", "--target", target(broken)], cwd);
      assert.equal(bad.code, 1);
      assert.match(JSON.parse(bad.stdout).why, /not a readable zip/);
      // A zip with no marker of this platform is not this recipe's.
      const other = join(cwd, "work", "other.zip");
      await build(`import sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], "w")\nz.writestr("readme.txt", b"x")\nz.close()\n`, other);
      assert.equal(JSON.parse((await recipe(recipeName, ["detect", "--target", target(other)], cwd)).stdout).applies, false);
    });
  });
}

// --- android-backup ---------------------------------------------------------------------

/**
 * An adb backup: the text header, then the tar (zlib-compressed when asked). `members` are [name, size] with
 * zero bytes of content; a member's content is streamed through the compressor, so 300 MiB of zeros costs a
 * few hundred KiB on disk.
 */
const AB = String.raw`
import io, json, sys, tarfile, zlib
path, spec = sys.argv[1], json.loads(sys.argv[2])
header = ("ANDROID BACKUP\n%s\n%s\n%s\n" % (spec.get("version", 5), 1 if spec.get("compress", True) else 0, spec.get("encryption", "none"))).encode()
if spec.get("encryption_lines"):
    header += ("\n".join(spec["encryption_lines"]) + "\n").encode()
with open(path, "wb") as out:
    out.write(header)
    comp = zlib.compressobj(9) if spec.get("compress", True) else None
    def emit(chunk):
        out.write(comp.compress(chunk) if comp else chunk)
    for name, size in spec.get("members", []):
        info = tarfile.TarInfo(name)
        info.size = size
        info.mtime = 1700000000
        emit(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
        remaining = size
        while remaining:
            n = min(remaining, 1 << 20)
            emit(b"\0" * n)
            remaining -= n
        pad = (-size) % 512
        if pad:
            emit(b"\0" * pad)
    if spec.get("long_header"):
        # An extended header (GNU long name) that declares a size it does not carry.
        info = tarfile.TarInfo("././@LongLink")
        info.type = tarfile.GNUTYPE_LONGNAME
        info.size = spec["long_header"]
        emit(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
    if spec.get("end", True):
        emit(b"\0" * 1024)
    if comp:
        tail = comp.flush()
        if spec.get("truncate_stream"):
            tail = b""
        out.write(tail)
`;

const SALT = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6";
const CHECK = "0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F0";
const IV = "00112233445566778899AABBCCDDEEFF";
const BLOB = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA98";

test("android-backup stops a payload that expands past its budget, says partial, and keeps the members it listed", async () => {
  // Each compressed piece was decompressed without a bound: the input was read in pieces and the output was not.
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "bomb.ab");
    await build(AB, ab, JSON.stringify({ members: [["apps/com.example/db/a.db", 512], ["apps/com.example/f/huge.bin", 300 * 1024 * 1024]] }));
    assert.ok((await stat(ab)).size < 2 * 1024 * 1024, "the bomb is small on disk");
    const out = join(cwd, "bomb");
    const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out, "--max-decompressed-bytes", String(16 * 1024 * 1024)], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    const cov = await coverage(out);
    assert.equal(cov.status, "partial");
    assert.equal(cov.payload_stream, "not_reached");
    assert.ok(cov.limits_hit.some((l) => /decompressed output budget of 16777216 bytes/.test(l)), JSON.stringify(cov.limits_hit));
    assert.ok((cov.decompressed_bytes ?? 0) <= 16 * 1024 * 1024);
    const members = (await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(members[0], "n\ttype\tpath\tbytes\tmtime_utc\tmode\tlink\tpath_b64");
    assert.match(members[1], /^0\tfile\tapps\/com\.example\/db\/a\.db\t512\t2023-11-14T22:13:20Z\t/);
    // Within a budget that holds it, the same backup is complete and the stream's end marker is verified.
    const small = join(cwd, "work", "small.ab");
    await build(AB, small, JSON.stringify({ members: [["apps/com.example/db/a.db", 512], ["shared/0/DCIM/p.jpg", 100000]] }));
    const ok = join(cwd, "small");
    assert.equal((await recipe("android-backup", ["run", "--target", target(small), "--out", ok], cwd)).code, 0);
    const done = await coverage(ok);
    assert.equal(done.status, "complete");
    assert.equal(done.payload_stream, "reached");
    assert.equal(done.tar_end, "reached");
    assert.equal(done.covered, "2 embedded tar members");
    // A stream cut off before its end marker is not complete.
    const cut = join(cwd, "work", "cut.ab");
    await build(AB, cut, JSON.stringify({ members: [["apps/a/db/x.db", 512]], truncate_stream: true }));
    const cutOut = join(cwd, "cut");
    await recipe("android-backup", ["run", "--target", target(cut), "--out", cutOut], cwd);
    const cutCov = await coverage(cutOut);
    assert.equal(cutCov.status, "partial");
    assert.equal(cutCov.payload_stream, "truncated");
  });
});

test("android-backup reports a version or a scheme it does not read as unsupported, and prints no key-derivation value", async () => {
  await withCwd(async (cwd) => {
    const v99 = join(cwd, "work", "v99.ab");
    await build(AB, v99, JSON.stringify({ version: 99, members: [["apps/a/db/x.db", 512]] }));
    const out99 = join(cwd, "v99");
    assert.equal((await recipe("android-backup", ["run", "--target", target(v99), "--out", out99], cwd)).code, 0);
    const cov99 = await coverage(out99);
    assert.equal(cov99.status, "partial");
    assert.match(cov99.covered, /version 99 is not one this recipe reads/);
    assert.ok(cov99.errors.some((e) => /unsupported: header version 99/.test(e)));
    assert.equal((await readFile(join(out99, "members.tsv"), "utf8")).trimEnd().split("\n").length, 1, "nothing was listed");
    // An unknown scheme is unsupported; AES-256's header is described by its shape, and its salts, IV and key blob are not printed.
    const odd = join(cwd, "work", "odd.ab");
    await build(AB, odd, JSON.stringify({ encryption: "ROT-13" }));
    const oddOut = join(cwd, "odd");
    await recipe("android-backup", ["run", "--target", target(odd), "--out", oddOut], cwd);
    assert.ok((await coverage(oddOut)).errors.some((e) => /unsupported: payload encryption scheme ROT-13/.test(e)));
    const aes = join(cwd, "work", "aes.ab");
    await build(AB, aes, JSON.stringify({ encryption: "AES-256", encryption_lines: [SALT, CHECK, "10000", IV, BLOB] }));
    const aesOut = join(cwd, "aes");
    const run = await recipe("android-backup", ["run", "--target", target(aes), "--out", aesOut], cwd);
    assert.equal(run.code, 0, run.stdout + run.stderr);
    const header = JSON.parse(await readFile(join(aesOut, "backup.json"), "utf8")) as { encryption: string; encryption_header: Record<string, unknown> };
    assert.equal(header.encryption, "AES-256");
    assert.deepEqual(header.encryption_header, {
      layout: "user salt, checksum salt, rounds, IV, master key blob (as the format documents it)",
      user_salt_chars: 64, checksum_salt_chars: 64, rounds: 10000, user_iv_chars: 32, master_key_blob_chars: 88, values_printed: false,
    });
    for (const secret of [SALT, CHECK, IV, BLOB]) {
      for (const f of await filesUnder(aesOut)) assert.equal(f.data.includes(Buffer.from(secret)), false, `${f.path} holds a header value`);
      assert.equal(run.stdout.includes(secret), false);
    }
    const aesCov = await coverage(aesOut);
    assert.equal(aesCov.status, "partial");
    assert.ok(aesCov.errors.some((e) => /AES-256; opening it needs a password/.test(e)));
    // detect still applies: the preparation of every adb backup is on the record.
    assert.equal(JSON.parse((await recipe("android-backup", ["detect", "--target", target(odd)], cwd)).stdout).applies, true);
  });
});

test("android-backup is complete only when the tar's end-of-archive block came, compressed or not", async () => {
  // A backup cut at a member boundary, or in the middle of a header, ended the listing quietly and was complete.
  await withCwd(async (cwd) => {
    for (const compress of [false, true]) {
      const name = compress ? "zlib" : "plain";
      const whole = join(cwd, "work", `${name}.ab`);
      await build(AB, whole, JSON.stringify({ compress, members: [["apps/a/db/x.db", 600], ["apps/a/db/y.db", 700], ["apps/a/db/z.db", 800]] }));
      const full = join(cwd, `${name}-full`);
      await recipe("android-backup", ["run", "--target", target(whole), "--out", full], cwd);
      const done = await coverage(full);
      assert.equal(done.status, "complete", JSON.stringify(done));
      assert.equal(done.tar_end, "reached");
      // No end block (the member list is whole, the marker is not): partial.
      const open = join(cwd, "work", `${name}-noend.ab`);
      await build(AB, open, JSON.stringify({ compress, end: false, members: [["apps/a/db/x.db", 600], ["apps/a/db/y.db", 700]] }));
      const noEnd = join(cwd, `${name}-noend`);
      await recipe("android-backup", ["run", "--target", target(open), "--out", noEnd], cwd);
      const c = await coverage(noEnd);
      assert.equal(c.status, "partial", `${name}: ${JSON.stringify(c)}`);
      assert.equal(c.tar_end, "missing");
      assert.ok(c.errors.some((e) => /without its end-of-archive block/.test(e)));
    }
    // An uncompressed file cut 200 bytes into the third member's header.
    const plain = join(cwd, "work", "plain.ab");
    const data = await readFile(plain);
    const cutAt = data.indexOf(Buffer.from("apps/a/db/z.db"));
    await writeFile(join(cwd, "work", "cut-header.ab"), data.subarray(0, cutAt + 200));
    await recipe("android-backup", ["run", "--target", target(join(cwd, "work", "cut-header.ab")), "--out", join(cwd, "cut-header")], cwd);
    const cut = await coverage(join(cwd, "cut-header"));
    assert.equal(cut.status, "partial");
    assert.equal(cut.tar_end, "missing");
  });
});

test("android-backup does not read an extended header that declares more than it will hold, and says so", async () => {
  // The tar library reads a GNU long name or a pax header whole into memory: 300 MiB declared in a 600-byte header.
  await withCwd(async (cwd) => {
    for (const compress of [false, true]) {
      const name = compress ? "zlib" : "plain";
      const ab = join(cwd, "work", `${name}-long.ab`);
      await build(AB, ab, JSON.stringify({ compress, long_header: 300 * 1024 * 1024, members: [["apps/a/db/x.db", 100]] }));
      const out = join(cwd, `${name}-long`);
      const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
      assert.equal(result.code, 0, result.stdout + result.stderr);
      const cov = await coverage(out);
      assert.equal(cov.status, "partial", JSON.stringify(cov));
      assert.ok(cov.limits_hit.some((l) => /extended header declares 314572800 bytes, over the limit of 1048576/.test(l)), JSON.stringify(cov.limits_hit));
      assert.equal((await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").length, 2, "the member before the header is listed");
    }
  });
});

test("android-backup prints only a scheme word from the header, and a line that is not one only as a length", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "secretish.ab");
    await build(AB, ab, JSON.stringify({ encryption: "deadbeef".repeat(8) }));
    const out = join(cwd, "secretish");
    const run = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
    const detect = await recipe("android-backup", ["detect", "--target", target(ab)], cwd);
    for (const f of await filesUnder(out)) assert.equal(f.data.includes(Buffer.from("deadbeef")), false, f.path);
    assert.equal(run.stdout.includes("deadbeef"), false);
    assert.equal(detect.stdout.includes("deadbeef"), false);
    assert.match(JSON.stringify(await coverage(out)), /not a scheme word: 64 characters, not printed/);
  });
});

test("android-backup lists a member whose name is not UTF-8 without raising, with its exact bytes", async () => {
  await withCwd(async (cwd) => {
    const ab = join(cwd, "work", "names.ab");
    await build(AB, ab, JSON.stringify({ compress: false, members: [["apps/com.example/db/\udcffbad\tname.db", 16], ["apps/com.example/db/plain.db", 8]] }));
    const out = join(cwd, "names");
    const result = await recipe("android-backup", ["run", "--target", target(ab), "--out", out], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.equal((await coverage(out)).status, "complete");
    const rows = (await readFile(join(out, "members.tsv"), "utf8")).trimEnd().split("\n").slice(1).map((l) => l.split("\t"));
    assert.equal(rows.length, 2);
    assert.equal(rows[0][2], "apps/com.example/db/\\xffbad\\tname.db");
    assert.equal(Buffer.from(rows[0][7], "base64").toString("latin1"), "apps/com.example/db/\xffbad\tname.db");
  });
});

// --- ios-filesystem ------------------------------------------------------------------------

test("ios-filesystem keeps a member's name as the archive spelled it, and both members of a duplicated database", async () => {
  // It stripped every leading dot and slash from a name, and a database that occurred twice kept only the last size.
  await withCwd(async (cwd) => {
    const tar = join(cwd, "work", "phone.tar");
    await build(TAR, tar, JSON.stringify([
      ["private/var/mobile/Library/SMS/sms.db", 16],
      ["private/var/mobile/Library/SMS/sms.db-wal", 3],
      ["..config/private/var/mobile/cache.sqlite", 7],
      ["./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata", 5],
      ["private/var/mobile/Library/SMS/sms.db", 20],
      ["private/var/mobile/Library/\udcffbytes.db", 9],
    ]));
    const out = join(cwd, "ios");
    const result = await recipe("ios-filesystem", ["run", "--target", target(tar), "--out", out], cwd);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    const cov = await coverage(out);
    assert.equal(cov.status, "complete");
    assert.equal(cov.covered, "6 tar members; 3 forensic structures; 4 SQLite families");
    const sqlite = (await readFile(join(out, "sqlite.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(sqlite[0], "path\tdb_bytes\twal_bytes\tshm_bytes\tjournal_bytes\tpath_b64\tmembers");
    const rows = Object.fromEntries(sqlite.slice(1).map((l) => { const c = l.split("\t"); return [c[0], c]; }));
    // The duplicate: both sizes, in archive order, and both member positions.
    const sms = rows["private/var/mobile/Library/SMS/sms.db"];
    assert.equal(sms[1], "16|20");
    assert.equal(sms[2], "3");
    assert.equal(sms[6], "db=0,wal=1,db=4");
    // The name is not trimmed: ..config is part of it, and so is a leading ./
    assert.ok(rows["..config/private/var/mobile/cache.sqlite"], Object.keys(rows).join());
    assert.ok(rows["./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"]);
    // A name that is not UTF-8: escaped, with its exact bytes.
    const odd = rows["private/var/mobile/Library/\\xffbytes.db"];
    assert.ok(odd, Object.keys(rows).join());
    assert.equal(Buffer.from(odd[5], "base64").toString("latin1"), "private/var/mobile/Library/\xffbytes.db");
    const artifacts = (await readFile(join(out, "artifacts.tsv"), "utf8")).trimEnd().split("\n");
    assert.equal(artifacts[0], "category\tpath\tbytes\tmtime_utc\ttype\tn\tpath_b64");
    const comm = artifacts.map((l) => l.split("\t")).filter((c) => c[0] === "communications");
    assert.ok(comm.some((c) => c[1] === "./private/var/mobile/Library/CallHistoryDB/CallHistory.storedata" && c[5] === "3"));
    assert.ok(comm.some((c) => c[1] === "private/var/mobile/Library/SMS/sms.db" && c[5] === "0"));
    assert.ok(comm.some((c) => c[1] === "private/var/mobile/Library/SMS/sms.db" && c[5] === "4"), "the second occurrence is its own row");
    // The scratch grouping file is gone.
    assert.equal(await exists(join(out, "sqlite-families.work.db")), false);
  });
});

test("the module receipt of the two LEAPP recipes is the same code", async () => {
  const between = (text: string, start: string, end: string): string => {
    const a = text.indexOf(start);
    const b = text.indexOf(end, a);
    assert.ok(a >= 0 && b > a, `${start} ... ${end} not found`);
    return text.slice(a, b);
  };
  const ios = await readFile(join(RECIPES, "ios-ileapp", "run.py"), "utf8");
  const android = await readFile(join(RECIPES, "android-aleapp", "run.py"), "utf8");
  const receipt = (t: string): string => between(t, "# The log lines a LEAPP", "# --- end of the module receipt").replace(/held equal to the one in the \w+ recipe/, "");
  assert.equal(receipt(ios), receipt(android));
});

