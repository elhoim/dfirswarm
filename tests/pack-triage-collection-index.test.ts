/**
 * triage-collection: collection_index is a census of the delivered objects with a hypothesis per source path. A hypothesis is
 * labelled one, an observed path comes only from a collector's own record, a mixed root is indexed, links are recorded and never
 * followed, every error is a row, an existing file is never replaced, and a time distribution is reported without a verdict.
 *
 * Fixtures are built by hand or from a format's own definition (the EWF signature, the columns of a real KAPE copy log); the
 * path probes are the five inputs of the review plus the root/ case, whose expected readings are written here, not read back.
 */
import assert from "node:assert/strict";
import { chmod, lstat, mkdir, readFile, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
  EWF_SIGNATURE, INDEX, KAPE_COPY_HEADER, asJob, body, exists, filesUnder, kapeCopyRow, link, put, readRows, refused, tool, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const AWS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

const byPath = (out: Json): Record<string, Json> => Object.fromEntries(out.entries.map((e: Json) => [e.in_collection, e]));

test("a path read by convention is a labelled hypothesis with its method, confidence and alternatives, and root/ is never stripped", async () => {
  await withCwd(async (cwd) => {
    for (const rel of ["C/Users/a/NTUSER.DAT", "[root]/etc/passwd", "uploads/auto/C%3A/Users/a/NTUSER.DAT", "collection/C/Users/a/NTUSER.DAT",
      "root/.bash_history", "C$/Windows/win.ini", "etc/hosts"]) await put(cwd, `inputs/c/${rel}`, "x");
    // a lower-case c beside an upper-case C cannot exist on a case-insensitive volume: its own root
    await put(cwd, "inputs/lower/c/config.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/c" }));
    const e = { ...byPath(out), ...byPath(body(await tool(INDEX, cwd, { root: "inputs/lower" }))) };
    const h = (rel: string) => e[rel].source_path_hypothesis;
    assert.equal(h("C/Users/a/NTUSER.DAT").path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(h("C/Users/a/NTUSER.DAT").confidence, "low", "a bare single letter is a weak signal");
    assert.equal(h("C$/Windows/win.ini").path, "C:\\Windows\\win.ini");
    assert.equal(h("C$/Windows/win.ini").confidence, "medium");
    assert.equal(h("[root]/etc/passwd").path, "/etc/passwd");
    assert.equal(h("[root]/etc/passwd").confidence, "medium");
    // A wrapper that needs the collector's own index is not decoded.
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").path, "uploads/auto/C%3A/Users/a/NTUSER.DAT");
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").confidence, "none");
    assert.deepEqual(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").unresolved_components, ["uploads", "auto", "C%3A"]);
    assert.equal(h("uploads/auto/C%3A/Users/a/NTUSER.DAT").alternatives[0].path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(h("collection/C/Users/a/NTUSER.DAT").path, "collection/C/Users/a/NTUSER.DAT");
    assert.equal(h("collection/C/Users/a/NTUSER.DAT").confidence, "none");
    assert.equal(h("c/config.txt").path, "C:\\config.txt");
    assert.equal(h("c/config.txt").confidence, "low");
    assert.equal(h("c/config.txt").alternatives[0].path, "/c/config.txt");
    // A real /root directory stays; the wrapper reading is the alternative.
    assert.equal(h("root/.bash_history").path, "/root/.bash_history");
    assert.deepEqual(h("root/.bash_history").unresolved_components, ["root"]);
    assert.equal(h("root/.bash_history").alternatives[0].path, "/.bash_history");
    assert.equal(h("etc/hosts").confidence, "none");
    for (const rel of Object.keys(e)) {
      assert.equal(e[rel].source_path_observed, null, "no collector record: nothing is observed");
      assert.equal(e[rel].source_path_mapping, "no_collector_mapping");
      assert.equal("original_path" in e[rel], false, "the old field is gone");
    }
    assert.equal(out.source_paths.observed.status, "no collector mapping available");
  });
});

test("a path a KAPE copy log records is observed, with its log and row; two matching rows are ambiguous and no row is nothing", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/k/C/Users/b/NTUSER.DAT", "hive");
    await put(cwd, "inputs/k/C/Users/c/NTUSER.DAT", "hive");
    await put(cwd, "inputs/k/C/other.txt", "x");
    const copy1 = [KAPE_COPY_HEADER,
      kapeCopyRow("C:\\Users\\a\\NTUSER.DAT", "D:\\out1\\C\\Users\\a\\NTUSER.DAT"),
      kapeCopyRow("C:\\Users\\b\\NTUSER.DAT", "D:\\out1\\C\\Users\\b\\NTUSER.DAT")].join("\r\n") + "\r\n";
    const copy2 = [KAPE_COPY_HEADER, kapeCopyRow("C:\\Users\\b\\NTUSER.DAT", "E:\\again\\C\\Users\\b\\NTUSER.DAT")].join("\r\n") + "\r\n";
    await put(cwd, "inputs/k/2026-02-14T09_12_00_1_CopyLog.csv", "\ufeff" + copy1);
    await put(cwd, "inputs/k/2026-02-15T09_12_00_2_CopyLog.csv", copy2);
    const out = body(await tool(INDEX, cwd, { root: "inputs/k" }));
    const e = byPath(out);
    const a = e["C/Users/a/NTUSER.DAT"];
    assert.equal(a.source_path_mapping, "observed");
    assert.equal(a.source_path_observed.path, "C:\\Users\\a\\NTUSER.DAT");
    assert.equal(a.source_path_observed.log, "2026-02-14T09_12_00_1_CopyLog.csv");
    assert.equal(a.source_path_observed.row, 1);
    assert.equal(a.source_path_observed.recorded_modified_utc_raw, "2026-01-02 03:04:05.678", "the log's own time, raw, beside the delivered one");
    assert.equal(a.source_path_hypothesis.path, "C:\\Users\\a\\NTUSER.DAT", "the hypothesis is still labelled one");
    const b = e["C/Users/b/NTUSER.DAT"];
    assert.equal(b.source_path_mapping, "ambiguous");
    assert.equal(b.source_path_observed, null);
    assert.equal(b.source_path_candidates.candidate_count, 2);
    assert.deepEqual(b.source_path_candidates.candidates.map((c: Json) => c.row), [2, 1]);
    assert.equal(e["C/Users/c/NTUSER.DAT"].source_path_mapping, "no_row_matched");
    assert.equal(e["C/Users/c/NTUSER.DAT"].source_path_observed, null);
    assert.deepEqual(out.source_paths.observed.files, { observed: 1, ambiguous: 1, no_row_matched: 4 });
    assert.equal(out.source_paths.observed.status, "read");
    assert.equal(out.source_paths.observed.rows_loaded, 3);
    assert.match(out.source_paths.observed.basis, /digests in the log are not compared/);
  });
});

test("a copy log that cannot be used for the mapping is named, the status is partial, and no path is observed from it", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/C/a.txt", "x");
    await put(cwd, "inputs/k/r_CopyLog.csv", "Foo,Bar\n1,2\n");
    const out = body(await tool(INDEX, cwd, { root: "inputs/k" }));
    assert.equal(out.status, "partial");
    assert.equal(out.source_paths.observed.status, "partial");
    assert.equal(out.source_paths.observed.logs_unsupported[0].log, "r_CopyLog.csv");
    assert.equal(byPath(out)["C/a.txt"].source_path_observed, null);
  });
});

test("a root that holds a disk image is indexed, the image says what it looks like, and the rest of the tree is still listed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/m/disk.E01", Buffer.concat([EWF_SIGNATURE, Buffer.alloc(100)]));
    await put(cwd, "inputs/m/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/m/memory.raw", Buffer.alloc(2000));
    const out = body(await tool(INDEX, cwd, { root: "inputs/m" }));
    assert.equal(out.census.regular_files, 3);
    const e = byPath(out);
    assert.equal(e["disk.E01"].object_class.class, "disk_container");
    assert.equal(e["disk.E01"].object_class.basis, "bytes");
    assert.match(e["disk.E01"].object_class.note, /not opened/);
    assert.equal(e["memory.raw"].object_class.class, "unknown");
    assert.equal(e["C/Users/a/NTUSER.DAT"].object_class, undefined, "a copied file carries no class");
    assert.match(e["disk.E01"].sha256, /^[0-9a-f]{64}$/);
    assert.equal(e["disk.E01"].source_path_hypothesis.confidence, "none");
  });
});

test("thirty files all dated one day are reported as a distribution fact with no cause, and every date is kept", async () => {
  await withCwd(async (cwd) => {
    const day = Date.UTC(2026, 1, 14, 9, 30) / 1000;
    for (let i = 0; i < 30; i++) {
      await put(cwd, `inputs/f/C/f${i}.txt`, "x");
      await utimes(join(cwd, `inputs/f/C/f${i}.txt`), day, day);
    }
    const out = body(await tool(INDEX, cwd, { root: "inputs/f" }));
    assert.equal(out.mtime_distribution_anomaly.dominant_date_utc, "2026-02-14");
    assert.equal(out.mtime_distribution_anomaly.files_on_that_date, 30);
    assert.equal(out.mtime_distribution_anomaly.regular_files, 30);
    assert.equal(out.mtime_distribution_anomaly.fraction, 1);
    assert.match(out.mtime_distribution_anomaly.not_established, /^the cause/);
    assert.equal(out.flat_timestamps, undefined);
    assert.doesNotMatch(JSON.stringify(out), /probably dropped|dropped the original|about the copy rather than the machine|every timestamp conclusion/i);
    assert.deepEqual(out.modification_dates, { "2026-02-14": 30 });
    // a spread of dates is no anomaly
    for (let i = 0; i < 12; i++) {
      await put(cwd, `inputs/g/f${i}.txt`, "x");
      const t = Date.UTC(2026, 0, 1 + i, 12) / 1000;
      await utimes(join(cwd, `inputs/g/f${i}.txt`), t, t);
    }
    const spread = body(await tool(INDEX, cwd, { root: "inputs/g" }));
    assert.equal(spread.mtime_distribution_anomaly, null);
    assert.equal(Object.keys(spread.modification_dates).length, 12, "every date, not the ten commonest");
  });
});

test("a modification time keeps the nanoseconds the file system holds, beside its raw epoch value", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/n/a.txt", "x");
    const ns = 1_771_070_123_456_789_012n;
    await utimes(join(cwd, "inputs/n/a.txt"), Number(ns / 1_000_000_000n), Number(ns / 1_000_000_000n) + 0.123456789);
    const real = (await stat(join(cwd, "inputs/n/a.txt"), { bigint: true })).mtimeNs;
    const out = body(await tool(INDEX, cwd, { root: "inputs/n" }));
    const row = out.entries[0];
    assert.equal(BigInt(row.modified_epoch_ns), real);
    const seconds = real / 1_000_000_000n;
    const when = new Date(Number(seconds) * 1000).toISOString().slice(0, 19);
    assert.equal(row.modified, `${when}.${String(real % 1_000_000_000n).padStart(9, "0")}Z`);
    assert.match(out.time_basis, /clock of the copy/);
  });
});

test("a link is recorded and never followed or hashed, a dangling one too; a pipe is recorded and not read", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "outside/secret.txt", "outside");
    await put(cwd, "inputs/l/a.txt", "x");
    await link(cwd, "inputs/l/to-file", join(cwd, "outside/secret.txt"));
    await link(cwd, "inputs/l/to-dir", join(cwd, "outside"));
    await symlink("missing-target", join(cwd, "inputs/l/dangling"));
    const { execFileSync } = await import("node:child_process");
    execFileSync("mkfifo", [join(cwd, "inputs/l/pipe")]);
    const out = body(await tool(INDEX, cwd, { root: "inputs/l" }));
    const e = byPath(out);
    assert.equal(out.census.regular_files, 1);
    assert.equal(out.census.symbolic_links, 3);
    assert.equal(out.census.special_files, 1);
    for (const name of ["to-file", "to-dir", "dangling"]) {
      assert.equal(e[name].kind, "symlink");
      assert.equal(e[name].followed, false);
      assert.equal(e[name].sha256, undefined);
    }
    assert.equal(e["to-file"].link_target, join(cwd, "outside/secret.txt"));
    assert.equal(e["dangling"].link_target, "missing-target");
    assert.equal(e["pipe"].kind, "special");
    assert.equal(e["pipe"].read, false);
    assert.equal(Object.keys(e).some((k) => k.startsWith("to-dir/")), false, "the directory behind a link is not walked");
  });
});

test("every object it could not list, stat or read is a row and an error with its reason, and the status is partial", async (t) => {
  if (process.getuid?.() === 0) return t.skip("running as root");
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/e/ok.txt", "x");
    await put(cwd, "inputs/e/locked/inner.txt", "x");
    await put(cwd, "inputs/e/unreadable.bin", "x", 0o000);
    await chmod(join(cwd, "inputs/e/locked"), 0o000);
    try {
      const out = body(await tool(INDEX, cwd, { root: "inputs/e" }));
      const e = byPath(out);
      assert.equal(out.status, "partial");
      assert.equal(out.census.errors, 2);
      assert.equal(e["locked"].kind, "unexamined");
      assert.match(e["locked"].error, /PermissionError/);
      assert.equal(e["unreadable.bin"].hash_status, "failed");
      assert.match(e["unreadable.bin"].hash_error, /PermissionError/);
      assert.equal(e["unreadable.bin"].sha256, null);
      assert.equal(out.hashing.failed, 1);
      assert.deepEqual(out.census.first_errors.map((x: Json) => x.path).sort(), ["inputs/e/locked", "inputs/e/unreadable.bin"]);
    } finally {
      await chmod(join(cwd, "inputs/e/locked"), 0o755);
      await chmod(join(cwd, "inputs/e/unreadable.bin"), 0o644);
    }
  });
});

test("an out_file inside the collection is refused before anything is read or written, and an existing file is never truncated or replaced", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/coll/a.txt", "x");
    const inside = refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/coll/index.jsonl" }));
    assert.match(inside.error, /out_file is inside the collection/);
    assert.equal(await exists(join(cwd, "work/coll/index.jsonl")), false);
    assert.deepEqual(await filesUnder(join(cwd, "work/coll")), ["a.txt"]);
    // an earlier answer at the name stays; this one is kept beside it and named
    await put(cwd, "work/index.jsonl", "KEEP\n");
    const out = body(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/index.jsonl" }));
    assert.equal(await readFile(join(cwd, "work/index.jsonl"), "utf8"), "KEEP\n");
    assert.equal(out.complete_index, "work/index.2.jsonl");
    assert.match(out.index.all_results_note, /a different file was already at work\/index\.jsonl and was kept/);
    const rows = await readRows(join(cwd, "work/index.2.jsonl"));
    assert.deepEqual(rows.map((r: Json) => r.in_collection), ["a.txt"]);
    // the same result again is the file already there
    const again = body(await tool(INDEX, cwd, { root: "work/coll", out_file: "work/index.jsonl" }));
    assert.equal(again.complete_index, "work/index.2.jsonl");
    // outside the run directory, under inputs/, and through a link are refused as before
    assert.match(refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "../escaped.jsonl" })).error, /must stay inside the run directory/);
    assert.match(refused(await tool(INDEX, cwd, { root: "work/coll", out_file: "inputs/x.jsonl" })).error, /cannot be under inputs\//);
  });
});

test("a default output that would lie inside the tree is excluded from the census and never listed as an object", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "work/s1/files/a.txt", "x");
    await put(cwd, "work/s1/files/b.txt", "y");
    const out = body(await tool(INDEX, cwd, { root: "work/s1", limit: 1 }));
    // the tree is work/s1, the spill file is work/s1/tool-output/...: it is this run's own file
    assert.equal(out.census.regular_files, 2);
    assert.equal(out.index.rows, 2);
    const rows = await readRows(join(cwd, out.index.all_results));
    assert.deepEqual(rows.map((r: Json) => r.in_collection), ["files/a.txt", "files/b.txt"]);
  });
});

test("contains filters the page; the file holds every object with matches_filter, and only the matching files are hashed", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/Users/a/NTUSER.DAT", "hive");
    await put(cwd, "inputs/c/C/Users/a/other.txt", "x");
    await put(cwd, "inputs/c/C/Windows/win.ini", "y");
    const out = body(await tool(INDEX, cwd, { root: "inputs/c", contains: "ntuser" }));
    assert.equal(out.entry_count, 1);
    assert.equal(out.entries_inline, 1);
    assert.equal(out.entries[0].in_collection, "C/Users/a/NTUSER.DAT");
    assert.equal(out.index.filter.contains, "ntuser");
    assert.equal(out.index.scope, "every object walked, with matches_filter on each row");
    assert.equal(out.hashing.hashed, 1);
    assert.equal(out.hashing.not_attempted_outside_filter, 2);
    const rows = await readRows(join(cwd, out.complete_index));
    assert.equal(rows.length, 3, "the complete index is not the filtered view");
    assert.deepEqual(rows.map((r: Json) => [r.in_collection, r.matches_filter]).sort(), [
      ["C/Users/a/NTUSER.DAT", true], ["C/Users/a/other.txt", false], ["C/Windows/win.ini", false]]);
    const outside = rows.find((r: Json) => r.in_collection.endsWith("win.ini"));
    assert.equal(outside.sha256, null);
    assert.match(outside.hash_status, /outside the contains filter/);
    // the filter also reads the hypothesis
    const hyp = body(await tool(INDEX, cwd, { root: "inputs/c", contains: "C:\\\\Windows" }));
    assert.equal(hyp.entry_count, 1);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs/c", contains: "(" })).error, /not a valid regex/);
  });
});

test("in a job the whole census is written to $OUT whatever the size, named as it will be cited, and a rerun neither crashes nor replaces it; the run directory is not written", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/j/C/a.txt", "x");
    await put(cwd, "inputs/j/C/b.txt", "y");
    await chmod(join(cwd, "work"), 0o555);
    await chmod(join(cwd, "inputs"), 0o555);
    try {
      const first = body(await asJob(INDEX, cwd, { root: "inputs/j" }, {}, "out", "j000950"));
      assert.match(first.complete_index, /^store\/jobs\/j000950\/out\/tool-output\/collection_index-[0-9a-f]{16}\.jsonl$/);
      assert.equal(first.inline_limited, false);
      assert.equal(first.index.rows, 2);
      const file = join(cwd, "out", first.complete_index.split("/out/")[1]);
      assert.equal((await readRows(file)).length, 2);
      const second = body(await asJob(INDEX, cwd, { root: "inputs/j" }, {}, "out", "j000950"));
      assert.notEqual(second.complete_index, first.complete_index);
      assert.equal((await readRows(file)).length, 2);
      // an explicit out_file outside $OUT is refused with the way to name one, not left to fail on a read-only file system
      const outside = refused(await asJob(INDEX, cwd, { root: "inputs/j", out_file: "work/index.jsonl" }, {}, "out", "j000950"));
      assert.match(outside.error, /not under this job's output directory/);
      assert.equal(await exists(join(cwd, "work/index.jsonl")), false);
      const named = body(await asJob(INDEX, cwd, { root: "inputs/j", out_file: join(cwd, "out/index.jsonl") }, {}, "out", "j000950"));
      assert.equal(named.complete_index, "store/jobs/j000950/out/index.jsonl");
    } finally {
      await chmod(join(cwd, "work"), 0o755);
      await chmod(join(cwd, "inputs"), 0o755);
    }
  });
});

test("outside a job the inline page is bounded by limit and the whole census goes under work/<agent>/tool-output", async () => {
  await withCwd(async (cwd) => {
    for (let i = 0; i < 5; i++) await put(cwd, `inputs/p/f${i}.txt`, `x${i}`);
    const out = body(await tool(INDEX, cwd, { root: "inputs/p", limit: 2 }));
    assert.equal(out.entries.length, 2);
    assert.equal(out.entry_count, 5);
    assert.equal(out.inline_limited, true);
    assert.match(out.complete_index, /^work\/s1\/tool-output\/collection_index-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await readRows(join(cwd, out.complete_index))).length, 5);
    const small = body(await tool(INDEX, cwd, { root: "inputs/p", limit: 50 }));
    assert.equal(small.complete_index, null, "everything fits inline: no file");
    assert.equal(small.inline_limited, false);
  });
});

test("a credential store is marked by its name and not hashed unless asked, in a job; the refusal outside a job is a JSON error", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/s/etc/shadow", "root:x:1:::\n");
    await put(cwd, "inputs/s/home/u/.ssh/id_ed25519", "key");
    await put(cwd, "inputs/s/home/u/.aws/credentials", "x");
    await put(cwd, "inputs/s/home/u/notes.txt", "x");
    await put(cwd, "inputs/s/credentials", "not under .aws");
    const out = body(await tool(INDEX, cwd, { root: "inputs/s" }));
    const e = byPath(out);
    for (const name of ["etc/shadow", "home/u/.ssh/id_ed25519", "home/u/.aws/credentials"]) {
      assert.ok(e[name].may_hold_secrets.kind, name);
      assert.equal(e[name].sha256, null, `${name} is not hashed by default`);
      assert.match(e[name].hash_status, /name marks a credential store/);
      assert.match(e[name].may_hold_secrets.basis, /name hint only/);
    }
    assert.equal(e["home/u/notes.txt"].may_hold_secrets, undefined);
    assert.match(e["home/u/notes.txt"].sha256, /^[0-9a-f]{64}$/);
    assert.equal(e["credentials"].may_hold_secrets, undefined, "credentials outside .aws is an ordinary name");
    assert.equal(out.hashing.not_attempted_credential_store_name, 3);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs/s", hash_credential_stores: true })).error, /refused outside a job/);
    const job = body(await asJob(INDEX, cwd, { root: "inputs/s", hash_credential_stores: true }, {}, "out", "j000960"));
    assert.equal(byPath(job)["etc/shadow"].sha256?.length, 64);
    assert.equal(job.hashing.not_attempted_credential_store_name, 0);
  });
});

test("a name shaped like an access key is withheld in every row and in the file; the real name goes to the sealed values file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, `inputs/w/home/${AWS_EXAMPLE_KEY_ID}/f.txt`, "x");
    await put(cwd, "inputs/w/GUID-{3F2504E0-4F89-11D3-9A0C-0305E82C3301}/g.txt", "x");
    await link(cwd, `inputs/w/link-${AWS_EXAMPLE_KEY_ID}`, "target");
    const plain = await tool(INDEX, cwd, { root: "inputs/w", limit: 1 });
    assert.ok(!plain.stdout.includes(AWS_EXAMPLE_KEY_ID));
    const out = body(plain);
    const file = await readFile(join(cwd, out.complete_index), "utf8");
    assert.ok(!file.includes(AWS_EXAMPLE_KEY_ID), "not in the file the answer names");
    assert.match(file, /<access-key-shaped text withheld, 20 characters>/);
    assert.match(file, /GUID-\{3F2504E0-4F89-11D3-9A0C-0305E82C3301\}/, "a GUID is a name, not a secret");
    assert.ok(out.withheld.strings_withheld >= 1);
    const job = await asJob(INDEX, cwd, { root: "inputs/w", write_values: true }, {}, "out", "j000970");
    assert.ok(!job.stdout.includes(AWS_EXAMPLE_KEY_ID));
    const answer = body(job);
    const wholeFile = await readFile(join(cwd, "out", answer.complete_index.split("/out/")[1]), "utf8");
    assert.ok(!wholeFile.includes(AWS_EXAMPLE_KEY_ID));
    const values = await readRows(join(cwd, "out/collection-index-values.jsonl"));
    assert.ok(values.length >= 2);
    assert.ok(values.some((v: Json) => String(v.value).includes(AWS_EXAMPLE_KEY_ID)));
    assert.equal((await stat(join(cwd, "out/collection-index-values.jsonl"))).mode & 0o777, 0o600);
    assert.match(refused(await asJob(INDEX, cwd, { root: "inputs/w", write_values: true }, {}, "out", "j000970")).error, /values file already exists/);
  });
});

test("a renamed-stream candidate is a labelled heuristic, SummaryInformation is a known stream name, and the old typo is gone", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/st/C/Users/a/report.txt_Zone.Identifier", "x");
    await put(cwd, "inputs/st/C/Users/a/report.doc_SummaryInformation", "x");
    await put(cwd, "inputs/st/C/Users/a/holiday_photos.jpg", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/st" }));
    const streams = out.possible_renamed_streams;
    assert.deepEqual(streams.map((s: Json) => [s.possible_original, s.known_stream]).sort(), [["report.doc:SummaryInformation", true], ["report.txt:Zone.Identifier", true]]);
    assert.match(streams[0].basis, /heuristic/);
    const script = await readFile(INDEX, "utf8");
    assert.ok(!script.includes("sumarryinformation"));
    assert.equal(out.possible_renamed_streams_table.matched, 2);
  });
});

test("a reserved device name is noted as an observation, not as something a collector did", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/r/C/LPT1.txt", "x");
    await put(cwd, "inputs/r/C/COM9", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/r" }));
    const e = byPath(out);
    assert.match(e["C/LPT1.txt"].notes[0], /whether a collector renamed it is not established/);
    assert.ok(e["C/COM9"].notes);
  });
});

test("bad arguments are JSON errors and a refusal leaves no file behind", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(INDEX, cwd, {})).error, /root is required/);
    assert.match(refused(await tool(INDEX, cwd, { root: "nope" })).error, /no such directory/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", limit: -1 })).error, /limit must be an integer/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", hash: "yes" })).error, /hash must be true or false/);
    assert.match(refused(await tool(INDEX, cwd, { root: "inputs", contains: "x".repeat(2001) })).error, /longer than 2000/);
    assert.deepEqual(await filesUnder(join(cwd, "work")), []);
  });
});

test("with hash false nothing is hashed and each row says so", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/h/a.txt", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/h", hash: false }));
    assert.equal(out.entries[0].sha256, null);
    assert.equal(out.entries[0].hash_status, "not_attempted: hash was false");
    assert.equal(out.hashing.not_attempted_hash_false, 1);
    assert.equal(out.hashing.hashed, 0);
  });
});

test("a file's digest is the SHA-256 of the whole file, whatever its size", async () => {
  await withCwd(async (cwd) => {
    const data = Buffer.alloc((3 << 20) + 17, 0x61);                // 3 MiB and a little over: more than one read
    await put(cwd, "inputs/d/big.bin", data);
    const out = body(await tool(INDEX, cwd, { root: "inputs/d" }));
    const { createHash } = await import("node:crypto");
    assert.equal(out.entries[0].sha256, createHash("sha256").update(data).digest("hex"));
    assert.equal(out.entries[0].hash_status, "hashed");
    assert.equal((await lstat(join(cwd, "inputs/d/big.bin"))).size, out.entries[0].bytes);
    // an empty file has the digest of nothing
    await writeFile(join(cwd, "inputs/d/empty"), "");
    const e = byPath(body(await tool(INDEX, cwd, { root: "inputs/d" })));
    assert.equal(e["empty"].sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

test("a parser name and a row number are on every row, and the census says what it covers", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/q/a.txt", "x");
    await put(cwd, "inputs/q/b/c.txt", "y");
    const out = body(await tool(INDEX, cwd, { root: "inputs/q" }));
    assert.equal(out.parser, "collection_index/3");
    assert.deepEqual(out.entries.map((e: Json) => e.row), [1, 2]);
    assert.deepEqual(out.entries.map((e: Json) => e.in_collection), ["a.txt", "b/c.txt"], "directories are sorted and visited in order");
    assert.equal(out.census.directories, 2);
    assert.equal(out.hashing.whole_file, true);
    assert.equal(out.status, "complete");
  });
});

const DEADLINE_CODE = `
import importlib.util, io, json, sys
script, root = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("lib", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.start_clock = lambda seconds: mod.DEADLINE.__setitem__(0, -1.0)      # a deadline already past: the monotonic clock is above it
sys.stdin = io.StringIO(json.dumps({"root": root}))
mod.main()
`;

test("when the time limit ends, the census stops, says how much was not listed, and the status is partial", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/a.txt", "x");
    await put(cwd, "inputs/t/b/c.txt", "y");
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const run = await runPySnippet(DEADLINE_CODE, [INDEX, join(cwd, "inputs/t")], null);
    assert.equal(run.code, 0, run.stderr);
    const out = JSON.parse(run.stdout);
    assert.equal(out.status, "partial");
    assert.match(out.census.stopped.reason, /time limit/);
    assert.equal(out.census.stopped.directories_not_listed, 1, "the root itself was not listed");
    assert.match(out.status_basis, /time limit/);
    assert.equal(out.census.regular_files, 0);
  });
});

test("a hash that the time limit ends is a row that says so, with the bytes read", async () => {
  await withCwd(async (cwd) => {
    const { runPySnippet } = await import("./tool-library-harness.ts");
    const code = `
import runpy, sys, time
ns = runpy.run_path(sys.argv[1], run_name="lib")
ns["DEADLINE"][0] = time.monotonic() - 1
try:
    ns["hash_file"](sys.argv[2], True, True)
except ns["HashStopped"] as stop:
    print("stopped after", stop.read)
`;
    await put(cwd, "inputs/t/big.bin", Buffer.alloc(3 << 20, 1));
    const run = await runPySnippet(code, [INDEX, join(cwd, "inputs/t/big.bin")], null);
    assert.equal(run.code, 0, run.stderr);
    assert.equal(run.stdout.trim(), `stopped after ${1 << 20}`);
  });
});

test("a file at the top of the collection has no directory to read a convention from, even when its name is a letter", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/C", "x");
    const out = body(await tool(INDEX, cwd, { root: "inputs/t" }));
    assert.equal(out.entries[0].source_path_hypothesis.path, "C");
    assert.equal(out.entries[0].source_path_hypothesis.confidence, "none");
  });
});

test("a file name that is not UTF-8 is listed with its bytes as an escape, in the answer and in the file, and never raises", async (t) => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/b"), { recursive: true });
    const name = Buffer.concat([Buffer.from(join(cwd, "inputs/b") + "/bad"), Buffer.from([0xff]), Buffer.from("name.txt")]);
    try {
      await writeFile(name, "x");
    } catch (error) {
      return t.skip(`this file system refuses a name that is not UTF-8 (${(error as NodeJS.ErrnoException).code})`);
    }
    const run = await tool(INDEX, cwd, { root: "inputs/b", limit: 1 });
    const out = body(run);
    assert.equal(out.entries[0].in_collection, "bad\udcffname.txt");
    assert.match(run.stdout, /bad\\udcffname\.txt/);
    const rows = await readRows(join(cwd, out.complete_index ?? "none")).catch(() => []);
    assert.ok(rows.length === 0 || rows[0].in_collection === "bad\udcffname.txt");
    const more = await tool(INDEX, cwd, { root: "inputs/b", out_file: "work/index.jsonl" });
    assert.equal((await readRows(join(cwd, body(more).complete_index)))[0].in_collection, "bad\udcffname.txt");
  });
});
