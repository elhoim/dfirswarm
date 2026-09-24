/**
 * Wave 3: the six tools written for the gaps the corpus left. Each one is
 * checked for the thing that makes it worth having rather than for the
 * happy path — a parser that guesses, a database read with its WAL ignored
 * or a scan that reports a missing binary as "no matches" is worse than no
 * tool at all.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { LIB, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

test("recyclebin_i parses $I metadata and refuses to guess at an unknown header", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    // Header 2: version, size, FILETIME, char count, UTF-16LE path.
    const path = "C:\\Users\\joker\\Confidential.rtf";
    const chars = path.length + 1;
    const v2 = Buffer.alloc(0x1c + chars * 2);
    v2.writeBigInt64LE(2n, 0x00);
    v2.writeBigInt64LE(439n, 0x08);
    // 2019-02-15T05:03:25Z as a FILETIME.
    const filetime = (BigInt(Date.UTC(2019, 1, 15, 5, 3, 25)) + 11644473600000n) * 10000n;
    v2.writeBigInt64LE(filetime, 0x10);
    v2.writeUInt32LE(chars, 0x18);
    Buffer.from(`${path}\0`, "utf16le").copy(v2, 0x1c);
    await writeFile(join(dir, "$IABCDEF.rtf"), v2);

    // An unknown header: the path must NOT be decoded from whatever is there.
    const bad = Buffer.alloc(0x40);
    bad.writeBigInt64LE(9n, 0x00);
    await writeFile(join(dir, "$IBADHDR.bin"), bad);

    const out = await runPy(join(LIB, "recyclebin_i", "run.py"), cwd, { path: "work/recycle" });
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as { entries: Array<Record<string, unknown>>; entry_count: number };
    assert.equal(body.entry_count, 2);
    const good = body.entries.find((e) => String(e.file).includes("ABCDEF"))!;
    assert.equal(good.original_path, path);
    assert.equal(good.original_size, 439);
    assert.equal(good.deleted_at, "2019-02-15T05:03:25Z");
    const unknown = body.entries.find((e) => String(e.file).includes("BADHDR"))!;
    assert.match(String(unknown.error), /unknown header version 9/);
    assert.equal(unknown.original_path, undefined, "an unknown layout must not produce a path");
  });
});

test("usn_journal skips the sparse front and decodes the reason bits", async () => {
  await withCwd(async (cwd) => {
    const name = "upload.aspx";
    const nameBytes = Buffer.from(name, "utf16le");
    const length = 0x3c + nameBytes.length;
    const rec = Buffer.alloc(length);
    rec.writeUInt32LE(length, 0x00);
    rec.writeUInt16LE(2, 0x04);
    rec.writeUInt16LE(0, 0x06);
    rec.writeBigUInt64LE((1n << 48n) | 33194n, 0x08); // reference + sequence
    rec.writeBigUInt64LE(5n, 0x10);
    rec.writeBigUInt64LE(4471n, 0x18);
    const filetime = (BigInt(Date.UTC(2026, 1, 11, 2, 57, 52)) + 11644473600000n) * 10000n;
    rec.writeBigInt64LE(filetime, 0x20);
    rec.writeUInt32LE(0x00000100 | 0x00000002, 0x28); // FILE_CREATE | DATA_EXTEND
    rec.writeUInt32LE(0, 0x2c);
    rec.writeUInt32LE(0, 0x30);
    rec.writeUInt32LE(0x20, 0x34); // ARCHIVE
    rec.writeUInt16LE(nameBytes.length, 0x38);
    rec.writeUInt16LE(0x3c, 0x3a);
    nameBytes.copy(rec, 0x3c);

    // $J is sparse: a long run of zeros before the first record.
    const journal = Buffer.concat([Buffer.alloc(4096), rec]);
    await writeFile(join(cwd, "work", "UsnJrnl_J"), journal);

    const out = await runPy(join(LIB, "usn_journal", "run.py"), cwd, { path: "work/UsnJrnl_J" });
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as {
      first_record_offset: number;
      records: Array<{ name: string; usn: number; reason: string[]; attributes: string[]; timestamp: string; file_reference: number; file_sequence: number }>;
    };
    assert.equal(body.first_record_offset, 4096, "the zeros at the front are skipped, and it says where it started");
    assert.equal(body.records.length, 1);
    const [r] = body.records;
    assert.equal(r.name, name);
    assert.equal(r.usn, 4471);
    assert.deepEqual(r.reason.sort(), ["DATA_EXTEND", "FILE_CREATE"]);
    assert.deepEqual(r.attributes, ["ARCHIVE"]);
    assert.equal(r.timestamp, "2026-02-11T02:57:52Z");
    assert.equal(r.file_reference, 33194);
    assert.equal(r.file_sequence, 1);

    // A filter that matches nothing is an empty list, not an error.
    const none = await runPy(join(LIB, "usn_journal", "run.py"), cwd, { path: "work/UsnJrnl_J", name: ".docx" });
    assert.equal(none.code, 0);
    assert.equal((JSON.parse(none.stdout) as { record_count: number }).record_count, 0);

    // A file with no record at all says so rather than returning nothing.
    await writeFile(join(cwd, "work", "empty_J"), Buffer.alloc(8192));
    const bad = await runPy(join(LIB, "usn_journal", "run.py"), cwd, { path: "work/empty_J" });
    assert.notEqual(bad.code, 0);
    assert.match(bad.stdout, /no USN_RECORD_V2 found/);
  });
});

test("browser_history replays the write-ahead log instead of reading around it", async () => {
  await withCwd(async (cwd) => {
    // A database whose last write is only in the WAL. Reading the main file
    // alone returns the state before the session, which is the part an
    // examiner wants — this is what made sqlite_query fail on these files.
    const db = join(cwd, "work", "History");
    const setup = await runPySnippet(
      [
        "import os, sqlite3, sys",
        "c = sqlite3.connect(sys.argv[1])",
        "c.execute('PRAGMA journal_mode=WAL')",
        "c.execute('PRAGMA wal_autocheckpoint=0')",
        "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT)')",
        "c.execute(\"INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 1, 0, 13350000000000000)\")",
        "c.commit()",
        "c.execute(\"INSERT INTO urls VALUES (2, 'http://203.0.113.24/upload.aspx', 'shell', 9, 1, 13350000060000000)\")",
        "c.commit()",
        "print('ok')",
        "sys.stdout.flush()",
        // Leave without closing, the way an image capture does: the WAL is
        // still unplayed on disk, which is the state these files arrive in.
        "os._exit(0)",
      ].join("\n"),
      [db],
      {},
    );
    assert.equal(setup.code, 0, setup.stderr);
    const wal = await readFile(`${db}-wal`).catch(() => null);
    assert.ok(wal && wal.length > 0, "the fixture must leave an unplayed WAL beside the database");

    const out = await runPy(join(LIB, "browser_history", "run.py"), cwd, { path: "work/History", query: "chrome_history" });
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as {
      rows: Array<{ url: string; last_visit_utc: string }>;
      sidecars_copied: string[];
      wal_replayed: boolean;
    };
    assert.equal(body.wal_replayed, true);
    assert.ok(body.sidecars_copied.includes("History-wal"));
    assert.deepEqual(body.rows.map((r) => r.url), [
      "http://203.0.113.24/upload.aspx",
      "http://example.test/a",
    ]);
    assert.match(body.rows[0].last_visit_utc, /^2024-/, "the Chrome epoch is converted, not printed raw");

    // The original is never touched.
    const after = await readFile(`${db}-wal`).catch(() => null);
    assert.ok(after && after.length > 0, "the evidence's WAL is still there afterwards");

    const write = await runPy(join(LIB, "browser_history", "run.py"), cwd, { path: "work/History", sql: "DELETE FROM urls" });
    assert.notEqual(write.code, 0);
    assert.match(write.stdout, /must be a SELECT, WITH or PRAGMA/);
  });
});

test("esedb_query and yara_scan say the binary is missing instead of reporting nothing found", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "not really an ESE database", "utf8");
    await writeFile(join(cwd, "work", "rules.yar"), "rule r { strings: $a = \"MZ\" condition: $a }", "utf8");
    // A PATH with python3 but neither of the two binaries. "No matches"
    // from a tool that is not installed would be a lie.
    const noPath = { PATH: `${bin}:/usr/bin:/bin` };
    const esedb = await runPy(join(LIB, "esedb_query", "run.py"), cwd, { path: "work/WebCacheV01.dat" }, undefined, noPath);
    assert.notEqual(esedb.code, 0);
    assert.match(esedb.stdout, /esedbexport is not on PATH/);
    assert.match(esedb.stdout, /libesedb/);

    const yara = await runPy(join(LIB, "yara_scan", "run.py"), cwd, { rules: "work/rules.yar", target: "work" }, undefined, noPath);
    assert.notEqual(yara.code, 0);
    assert.match(yara.stdout, /yara is not on PATH/);

    // And each refuses arguments it cannot use, before looking for a binary.
    const noFile = await runPy(join(LIB, "esedb_query", "run.py"), cwd, { path: "work/nope.dat" });
    assert.notEqual(noFile.code, 0);
    assert.match(noFile.stdout, /no such file/);
    const noRules = await runPy(join(LIB, "yara_scan", "run.py"), cwd, { rules: "work/nope.yar", target: "work" });
    assert.notEqual(noRules.code, 0);
    assert.match(noRules.stdout, /no such rules file/);
  });
});

test("esedb_query calls esedbexport only with options the Debian build has", async () => {
  // esedbexport 20181229, as the images carry it: -c -l -m -t -T -h -v -V and
  // nothing else; an unknown option is refused. It passed -q once and every
  // call in a real run failed on it.
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in", "utf8");
    await writeFile(
      join(bin, "esedbexport"),
      `#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
target = None
i = 0
while i < len(args) - 1:
    a = args[i]
    if a in ("-c", "-l", "-m", "-t", "-T"):
        if a == "-t":
            target = args[i + 1]
        i += 2
        continue
    if a in ("-h", "-v", "-V"):
        i += 1
        continue
    sys.stderr.write("esedbexport: invalid option -- '%s'\\nInvalid argument: %s\\n" % (a.lstrip("-"), a))
    sys.exit(1)
os.makedirs(target + ".export", exist_ok=True)
open(os.path.join(target + ".export", "Containers.0"), "w").write("ContainerId\\tName\\n1\\tContent\\n")
`,
      "utf8",
    );
    await chmod(join(bin, "esedbexport"), 0o755);
    for (const script of [join(LIB, "esedb_query", "run.py"), join(LIB, "..", "packs", "windows-forensics", "tools", "esedb_query", "run.py")]) {
      const r = await runPy(script, cwd, { path: "work/WebCacheV01.dat" }, bin);
      assert.doesNotMatch(r.stdout + r.stderr, /invalid option/, `${script}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, /Containers/, `${script}: ${r.stdout}${r.stderr}`);
    }
  });
});

test("amcache_apps names the layout it found, or says neither is there", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "Amcache.hve"), "not a hive", "utf8");
    const out = await runPy(join(LIB, "amcache_apps", "run.py"), cwd, { hive: "work/Amcache.hve" });
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string; hint?: string; looked_for?: string[] };
    // Either regipy is absent, or it is present and the file is not a hive.
    // Both are honest answers; an empty result would not be.
    assert.ok(
      /regipy is not installed/.test(body.error) || /could not open the hive/.test(body.error),
      `unexpected error: ${body.error}`,
    );
  });
});
