/**
 * triage-collection: collection_id classifies each object of a delivery on its own, names the collectors that left records by
 * the paths it found, reads every recognised log whole, and never turns an unrecognised or unreadable log into zero failures.
 *
 * Fixtures are built from the formats' own definitions (the EWF, VHDX and LiME signatures, a GPT header at offset 512, the
 * columns of a real KAPE copy log, JSON Lines for the Velociraptor index) or by hand. None is read back from the tool.
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, stat, utimes } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import {
  EWF_SIGNATURE, GPT_SIGNATURE, ID, KAPE_COPY_HEADER, LIME_MAGIC, VHDX_SIGNATURE, asJob, body, exists, kapeCopyRow, link, put, readRows,
  refused, sparse, tool, withCwd,
} from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const NUL = (n: number) => Buffer.alloc(n);
const AWS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE";            // the documented example access key id of AWS

test("a raw memory capture beside copied files makes the delivery mixed, each object classified, and nothing returns early", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/Windows/System32/config/SYSTEM", "regf");
    await put(cwd, "inputs/c/C/Users/a/NTUSER.DAT", "regf");
    await put(cwd, "inputs/c/memory.raw", Buffer.concat([LIME_MAGIC, Buffer.from([1, 0, 0, 0]), NUL(64)]));
    const out = body(await tool(ID, cwd, { root: "inputs/c" }));
    assert.equal(out.delivery.kind, "mixed");
    assert.equal(out.delivery.object_counts.memory_capture, 1);
    assert.equal(out.delivery.object_counts.logical_files, 2);
    assert.notEqual(out.delivery.object_counts.disk_container, 1);
    const memory = out.objects.find((o: Json) => o.path === "memory.raw");
    assert.equal(memory.class, "memory_capture");
    assert.equal(memory.basis, "bytes");
    // The old tool answered "disk image / physical image" for any top-level .raw and read nothing else.
    assert.equal(out.collector, undefined);
    assert.equal(out.evidence_kind, undefined);
    assert.equal(out.walk.files, 3);
    assert.deepEqual(out.delivery.not_observed, ["disk containers"]);
    assert.ok(out.artefact_families_by_name["the SYSTEM hive"], "the copied files were still examined");
  });
});

test("a name that says image or raw with no signature behind it is unknown, never a physical image", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/blob.raw", NUL(3000));
    await put(cwd, "inputs/c/note.txt", "hello");
    const out = body(await tool(ID, cwd, { root: "inputs/c" }));
    const blob = out.objects.find((o: Json) => o.path === "blob.raw");
    assert.equal(blob.class, "unknown");
    assert.equal(blob.basis, "extension only");
    assert.match(blob.evidence, /no recognised container or volume signature/);
    assert.equal(out.delivery.object_counts.disk_container, 0);
    assert.equal(out.delivery.kind, "mixed");
  });
});

test("disk containers are recognised by their own signatures; a raw image by its volume signatures, and only when it is large enough to be one", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/d/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await put(cwd, "inputs/d/vm/disk.vhdx", Buffer.concat([VHDX_SIGNATURE, NUL(100)]));
    // A raw disk: a boot signature at 510 and a GPT header at offset 512, 2 MiB long.
    await sparse(join(cwd, "inputs/d/raw/disk.dd"), 2 << 20, [[510, Buffer.from([0x55, 0xaa])], [512, GPT_SIGNATURE]]);
    // $Boot is 8 KiB and starts with an NTFS boot sector: a copied file, not a disk.
    await sparse(join(cwd, "inputs/d/C/$Boot"), 8192, [[3, Buffer.from("NTFS    ")], [510, Buffer.from([0x55, 0xaa])]]);
    const out = body(await tool(ID, cwd, { root: "inputs/d" }));
    const byPath = Object.fromEntries(out.objects.map((o: Json) => [o.path, o]));
    assert.equal(byPath["case.E01"].class, "disk_container");
    assert.match(byPath["case.E01"].format, /EWF/);
    assert.equal(byPath["case.E01"].basis, "bytes");
    assert.equal(byPath["vm/disk.vhdx"].class, "disk_container");
    assert.equal(byPath["raw/disk.dd"].class, "disk_container");
    assert.match(byPath["raw/disk.dd"].evidence, /GPT header at offset 512/);
    assert.equal(byPath["C/$Boot"], undefined, "an 8 KiB boot sector is a copied file");
    assert.equal(out.delivery.object_counts.disk_container, 3);
    assert.equal(out.delivery.object_counts.logical_files, 1);
    assert.equal(out.delivery.kind, "mixed");
  });
});

test("a delivery of one kind says that kind, and the kinds it did not see", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/only-image/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    const one = body(await tool(ID, cwd, { root: "inputs/only-image" }));
    assert.equal(one.delivery.kind, "disk_container");
    assert.deepEqual(one.delivery.not_observed, ["memory captures"]);
    await put(cwd, "inputs/logical/C/Windows/System32/config/SYSTEM", "regf");
    const logical = body(await tool(ID, cwd, { root: "inputs/logical" }));
    assert.equal(logical.delivery.kind, "logical");
    assert.deepEqual(logical.delivery.not_observed, ["disk containers", "memory captures"]);
    assert.match(logical.delivery.not_observed_basis, /limit of this delivery, not a finding about the source/);
    assert.equal(logical.cannot_contain, undefined, "no hard-coded list of what a delivery cannot contain");
    await mkdir(join(cwd, "inputs/empty"), { recursive: true });
    assert.equal(body(await tool(ID, cwd, { root: "inputs/empty" })).delivery.kind, "empty");
  });
});

test("two KAPE runs in one tree are two runs, each with its own logs and counts, and the whole skip row is kept", async () => {
  await withCwd(async (cwd) => {
    const run1 = "2026-02-14T09_12_00_1111111";
    const run2 = "2026-02-15T10_00_00_2222222";
    await put(cwd, `inputs/k/${run1}_CopyLog.csv`, "\ufeff" + [KAPE_COPY_HEADER, kapeCopyRow("C:\\a", "D:\\o1\\C\\a"), kapeCopyRow("C:\\b", "D:\\o1\\C\\b")].join("\r\n") + "\r\n");
    await put(cwd, `inputs/k/${run1}_SkipLog.csv`, "SourceFile,Reason\r\nC:\\pagefile.sys,File in use\r\nC:\\x,\"Access, denied\"\r\n");
    await put(cwd, `inputs/k/${run1}_ConsoleLog.txt`, "KAPE version 1.3.0.2\nother\n");
    await put(cwd, `inputs/k/${run2}_CopyLog.csv`, [KAPE_COPY_HEADER, kapeCopyRow("C:\\c", "D:\\o2\\C\\c")].join("\n") + "\n");
    await put(cwd, "inputs/k/C/a", "x");
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const kape = out.collector_candidates.find((c: Json) => c.collector === "KAPE");
    assert.equal(kape.runs.length, 2, "both runs are kept");
    const [r1, r2] = kape.runs;
    assert.equal(r1.run_id, run1);
    assert.equal(r1.files_in_copy_log, 2);
    assert.equal(r2.files_in_copy_log, 1);
    assert.deepEqual(r1.logs.map((l: Json) => l.kind), ["copy_log", "skip_log"]);
    assert.equal(r1.logs[0].status, "parsed");
    assert.equal(r1.collector_version.value, "1.3.0.2");
    assert.match(r1.collector_version.from, /ConsoleLog\.txt line 1/);
    assert.equal(r2.collector_version, "unknown");
    assert.equal(kape.observed_markers.length, 4);
    assert.equal(out.failed_target_count, 2);
    const reasons = out.failed_targets.map((f: Json) => [f.target, f.reason, f.outcome]);
    assert.deepEqual(reasons, [["C:\\pagefile.sys", "File in use", "skipped"], ["C:\\x", "Access, denied", "skipped"]]);
    assert.deepEqual(out.failed_targets[1].locator, { row: 2, line: 3 });
    assert.deepEqual(out.failed_targets[0].row_values, { SourceFile: "C:\\pagefile.sys", Reason: "File in use" });
    assert.equal(out.collector, undefined);
    assert.ok(out.layout_clues.every((c: Json) => !("collector" in c)), "a drive-letter directory is a clue, never an attribution");
  });
});

test("a skip log whose columns are not recognised is partial and keeps every row whole; it is never a count of zero", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/2026-02-14T09_12_00_1_SkipLog.csv", "Foo,Bar\nx,y\nz,w\n");
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const log = out.collector_candidates[0].runs[0].logs[0];
    assert.equal(log.status, "partial");
    assert.match(log.reason, /every row is kept whole/);
    assert.equal(out.status, "partial");
    assert.equal(out.failed_target_count, 2);
    assert.deepEqual(out.failed_targets[0].row_values, { Foo: "x", Bar: "y" });
    assert.equal(out.failed_targets[0].target, null);
    assert.equal(out.failed_target_count_complete, false);
    await put(cwd, "inputs/e/2026-02-14T09_12_00_1_SkipLog.csv", "");
    const empty = body(await tool(ID, cwd, { root: "inputs/e" }));
    assert.equal(empty.collector_candidates[0].runs[0].logs[0].status, "unsupported");
    assert.equal(empty.failed_target_count, null, "a log that could not be read gives no count, not zero");
  });
});

test("a malformed or oversized CSV row is counted and located, and the rest of the log is still read", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_SkipLog.csv", ["SourceFile,Reason", "C:\\a,locked", "C:\\b", "C:\\c,denied,extra", "C:\\d,ok", ""].join("\n"));
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    const log = out.collector_candidates[0].runs[0].logs[0];
    assert.equal(log.rows, 4);
    assert.equal(log.malformed_rows, 2);
    assert.deepEqual(log.problems.map((p: Json) => p.line), [3, 4]);
    assert.equal(log.status, "partial");
    assert.equal(out.failed_targets.filter((f: Json) => f.malformed).length, 2);
    assert.equal(out.failed_target_count, 4);
  });
});

test("a UAC log's summary line saying 0 errors is not a failure; an ERROR event is, with its line; an unmatched line is kept unlabelled", async () => {
  await withCwd(async (cwd) => {
    const lines = [
      "2026-02-14 09:12:00 +0000 INFO Starting collection",
      "2026-02-14 09:12:05 +0000 INFO Collection finished, 0 errors found",
      "",
    ].join("\n");
    await put(cwd, "inputs/u/uac.log", lines);
    const clean = body(await tool(ID, cwd, { root: "inputs/u" }));
    assert.equal(clean.failed_target_count, 0);
    assert.deepEqual(clean.failed_targets, []);
    assert.equal(clean.collector_candidates[0].collector, "UAC");
    assert.equal(clean.collector_candidates[0].runs[0].record.status, "parsed");
    assert.equal(clean.collector_candidates[0].runs[0].record.events, 2);
    assert.equal(clean.collector_candidates[0].runs[0].record.levels.INFO, 2);

    await put(cwd, "inputs/u2/uac.log", [
      "2026-02-14 09:12:00 +0000 INFO Starting collection",
      "2026-02-14 09:12:01 +0000 ERROR cannot read /proc/1/mem",
      "cannot say what this line is",
      "2026-02-14 09:12:09 +0000 WARNING a warning is not an error",
      "",
    ].join("\n"));
    const some = body(await tool(ID, cwd, { root: "inputs/u2" }));
    assert.equal(some.failed_target_count, 1);
    assert.equal(some.failed_targets[0].outcome, "error");
    assert.deepEqual(some.failed_targets[0].locator, { line: 2 });
    const record = some.collector_candidates[0].runs[0].record;
    assert.equal(record.unmatched_lines, 1);
    assert.equal(record.unlabelled_lines_with_failure_words, 1);
    assert.equal(record.unlabelled_examples[0].text, "cannot say what this line is");
    assert.equal(record.status, "partial");
    assert.equal(record.levels.WARNING, 1);
  });
});

test("a UAC log with no recognised event shape gives no failure count, not zero; directory names alone name no log", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/uac.log", "starting\nan error happened here\ndone\n");
    const out = body(await tool(ID, cwd, { root: "inputs/u" }));
    const record = out.collector_candidates[0].runs[0].record;
    assert.equal(record.status, "unsupported");
    assert.equal(record.unlabelled_lines_with_failure_words, 1);
    assert.equal(out.failed_target_count, null);
    assert.match(out.failed_target_count_basis, /not zero failures/);
    assert.equal(out.status, "partial");
    await mkdir(join(cwd, "inputs/d/[root]/etc"), { recursive: true });
    const dirs = body(await tool(ID, cwd, { root: "inputs/d" }));
    assert.equal(dirs.collector_candidates[0].collector, "UAC");
    assert.match(dirs.collector_candidates[0].basis, /directory names only/);
    assert.deepEqual(dirs.collector_candidates[0].runs, []);
    assert.equal(dirs.failed_target_count, null);
  });
});

test("a Velociraptor upload row with an error appears in the failures; every uploads.json is read; a bad row is located", async () => {
  await withCwd(async (cwd) => {
    const rows = [
      JSON.stringify({ _Source: "Windows.KapeFiles.Targets", vfs_path: "C:/Windows/a", Size: 10 }),
      JSON.stringify({ _Source: "Windows.KapeFiles.Targets", vfs_path: "C:/Windows/b", Error: "Access is denied." }),
      "this is not json",
      JSON.stringify({ _Source: "Linux.Sys.Pslist" }),
      "",
    ].join("\n");
    await put(cwd, "inputs/v/results/uploads.json", rows);
    await put(cwd, "inputs/v/more/uploads.json", JSON.stringify({ _Source: "Generic.Client.Info" }) + "\n");
    const out = body(await tool(ID, cwd, { root: "inputs/v" }));
    const v = out.collector_candidates.find((c: Json) => c.collector === "Velociraptor");
    assert.equal(v.runs.length, 2, "both indexes");
    const first = v.runs.find((r: Json) => r.log === "results/uploads.json").record;
    assert.equal(first.objects, 3);
    assert.equal(first.rows_with_error_field, 1);
    assert.equal(first.malformed_rows, 1);
    assert.deepEqual(first.problems, [{ line: 3, error: "not valid JSON" }]);
    assert.equal(first.status, "partial");
    assert.deepEqual(first.artefacts, { "Windows.KapeFiles.Targets": 2, "Linux.Sys.Pslist": 1 });
    assert.equal(out.failed_target_count, 1);
    assert.equal(out.failed_targets[0].collector, "Velociraptor");
    assert.equal(out.failed_targets[0].target, "C:/Windows/b");
    assert.equal(out.failed_targets[0].reason, "Access is denied.");
    assert.deepEqual(out.failed_targets[0].locator, { line: 2 });
  });
});

test("a Velociraptor index that is a JSON array, or has no object row, is unsupported and gives no count", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/v/uploads.json", JSON.stringify([{ _Source: "a" }]));
    const out = body(await tool(ID, cwd, { root: "inputs/v" }));
    const record = out.collector_candidates[0].runs[0].record;
    assert.equal(record.status, "unsupported");
    assert.match(record.reason, /JSON array, not JSON Lines/);
    assert.equal(out.failed_target_count, null);
    await put(cwd, "inputs/w/uploads.json", "garbage\n[1,2]\n");
    const garbage = body(await tool(ID, cwd, { root: "inputs/w" }));
    assert.equal(garbage.collector_candidates[0].runs[0].record.status, "unsupported");
    assert.equal(garbage.failed_target_count, null);
  });
});

test("an unreadable directory and a link are reported, never followed or dropped; a pipe does not hang the walk", async (t) => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/t/C/a", "x");
    await put(cwd, "outside/uploads.json", JSON.stringify({ _Source: "x", Error: "boom" }) + "\n");
    await link(cwd, "inputs/t/link-out", join(cwd, "outside"));
    execFileSync("mkfifo", [join(cwd, "inputs/t/pipe")]);
    await put(cwd, "inputs/t/locked/uploads.json", "{}\n");
    await chmod(join(cwd, "inputs/t/locked"), 0o000);
    try {
      const out = body(await tool(ID, cwd, { root: "inputs/t" }));
      assert.equal(out.walk.symbolic_links_not_followed, 1);
      assert.deepEqual(out.walk.first_links, ["link-out"]);
      assert.equal(out.walk.special_files_not_read, 1);
      assert.equal(out.collector_candidates.length, 0, "the link's target was not read");
      assert.equal(out.failed_target_count, null);
      if (process.getuid?.() !== 0) {
        assert.equal(out.walk.errors, 1);
        assert.match(out.walk.first_errors[0].path, /locked/);
        assert.equal(out.status, "partial");
        assert.match(out.status_basis, /could not be read|walk or read error/);
      } else t.diagnostic("running as root: the unreadable directory is readable");
    } finally {
      await chmod(join(cwd, "inputs/t/locked"), 0o755);
    }
  });
});

test("a log that was a link when the walk began is not read through it", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "secret-elsewhere.csv", "SourceFile,Reason\nC:\\x,y\n");
    await link(cwd, "inputs/k/r_SkipLog.csv", join(cwd, "secret-elsewhere.csv"));
    const out = body(await tool(ID, cwd, { root: "inputs/k" }));
    assert.equal(out.collector_candidates.length, 0);
    assert.equal(out.failed_target_count, null);
    assert.equal(out.walk.symbolic_links_not_followed, 1);
  });
});

test("bytes that are not UTF-8 in a log are counted and survive in valid JSON; a lone surrogate never raises", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/k/r_SkipLog.csv", Buffer.concat([Buffer.from("SourceFile,Reason\nC:\\caf"), Buffer.from([0xe9]), Buffer.from(",gone\n")]));
    const run = await tool(ID, cwd, { root: "inputs/k" });
    const out = body(run);
    assert.equal(out.collector_candidates[0].runs[0].logs[0].rows_with_undecodable_bytes, 1);
    assert.equal(out.failed_targets[0].target, "C:\\caf\udce9");
    assert.match(run.stdout, /caf\\udce9/, "written as an escape, readable as JSON, not a crash");
  });
});

test("a string shaped like a credential is withheld from every channel, and the real string goes to a sealed file only when asked, in a job", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/u/uac.log", [
      "2026-02-14 09:12:00 +0000 INFO Starting",
      `2026-02-14 09:12:01 +0000 ERROR cannot open /home/x/${AWS_EXAMPLE_KEY_ID}/credentials`,
      "",
    ].join("\n"));
    await put(cwd, `inputs/u/${AWS_EXAMPLE_KEY_ID}/f`, "x");
    // not a job, not asked: withheld, nothing written
    const plain = await tool(ID, cwd, { root: "inputs/u" });
    assert.ok(!plain.stdout.includes(AWS_EXAMPLE_KEY_ID), "the shaped string is not in the answer");
    const out = body(plain);
    assert.match(out.failed_targets[0].reason, /<access-key-shaped text withheld, 20 characters>/);
    assert.ok(out.withheld.strings_withheld >= 1);
    assert.equal(out.withheld.values.requested, false);
    // asked outside a job: refused by name, nothing written
    const outside = refused(await tool(ID, cwd, { root: "inputs/u", write_values: true }));
    assert.match(outside.error, /refused outside a job/);
    assert.equal(await exists(join(cwd, "collection-id-values.jsonl")), false);
    // in a job: the file is created first, 0600, holds the real line; the answer says where
    const job = await asJob(ID, cwd, { root: "inputs/u", write_values: true }, {}, "out", "j000900");
    assert.ok(!job.stdout.includes(AWS_EXAMPLE_KEY_ID));
    const answer = body(job);
    assert.equal(answer.withheld.values.values_file, "store/jobs/j000900/out/collection-id-values.jsonl");
    assert.equal(answer.withheld.values.contains_secret_values, true);
    const file = join(cwd, "out", "collection-id-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = await readRows(file);
    assert.equal(rows.length, answer.withheld.values.written);
    assert.ok(rows.some((r: Json) => String(r.value).includes(AWS_EXAMPLE_KEY_ID)));
    // a second run in the same job does not overwrite it: refused by name, the file is untouched
    const before = await readFile(file, "utf8");
    const again = refused(await asJob(ID, cwd, { root: "inputs/u", write_values: true }, {}, "out", "j000900"));
    assert.match(again.error, /values file already exists/);
    assert.equal(await readFile(file, "utf8"), before);
  });
});

test("with nothing to withhold the values file is an empty 0600 file and the answer says written 0", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/c/C/a", "x");
    const answer = body(await asJob(ID, cwd, { root: "inputs/c", write_values: true }, {}, "out", "j000901"));
    assert.equal(answer.withheld.values.written, 0);
    assert.equal(answer.withheld.values.contains_secret_values, false);
    const file = join(cwd, "out", "collection-id-values.jsonl");
    assert.equal((await stat(file)).size, 0);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
  });
});

test("a table longer than the limit goes whole to a file under $OUT in a job, a second run does not touch the first, and nothing is written elsewhere", async () => {
  await withCwd(async (cwd) => {
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 7; i++) rows.push(`C:\\f${i},reason ${i}`);
    await put(cwd, "inputs/k/r_SkipLog.csv", rows.join("\n") + "\n");
    await chmod(join(cwd, "work"), 0o555);
    await chmod(join(cwd, "inputs"), 0o555);
    try {
      const first = body(await asJob(ID, cwd, { root: "inputs/k", limit: 3 }, {}, "out", "j000902"));
      assert.equal(first.failed_targets.length, 3);
      assert.equal(first.failed_targets_table.matched, 7);
      assert.equal(first.failed_targets_table.truncated, true);
      assert.match(first.failed_targets_table.all_results, /^store\/jobs\/j000902\/out\/tool-output\/collection_id-failures-[0-9a-f]{16}\.jsonl$/);
      const file = join(cwd, "out", first.failed_targets_table.all_results.split("/out/")[1]);
      const kept = await readRows(file);
      assert.equal(kept.length, 7);
      assert.equal(kept[6].reason, "reason 6");
      const second = body(await asJob(ID, cwd, { root: "inputs/k", limit: 3 }, {}, "out", "j000902"));
      assert.notEqual(second.failed_targets_table.all_results, first.failed_targets_table.all_results);
      assert.equal((await readRows(file)).length, 7);
      assert.deepEqual((await readdirOut(cwd)).filter((f) => !f.startsWith("tool-output/")), []);
    } finally {
      await chmod(join(cwd, "work"), 0o755);
      await chmod(join(cwd, "inputs"), 0o755);
    }
  });
});

async function readdirOut(cwd: string): Promise<string[]> {
  const { filesUnder } = await import("./pack-triage-harness.ts");
  return filesUnder(join(cwd, "out"));
}

test("outside a job the whole table goes under work/<agent>/tool-output; where nothing can be written the answer is a JSON error, never a traceback", async () => {
  await withCwd(async (cwd) => {
    const rows = ["SourceFile,Reason"];
    for (let i = 0; i < 4; i++) rows.push(`C:\\f${i},r${i}`);
    await put(cwd, "inputs/k/r_SkipLog.csv", rows.join("\n") + "\n");
    const ok = body(await tool(ID, cwd, { root: "inputs/k", limit: 2 }));
    assert.match(ok.failed_targets_table.all_results, /^work\/s1\/tool-output\/collection_id-failures-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await readRows(join(cwd, ok.failed_targets_table.all_results))).length, 4);
    await mkdir(join(cwd, "ro"), { recursive: true });
    await chmod(join(cwd, "ro"), 0o555);
    try {
      if (process.getuid?.() === 0) return;
      const run = await tool(ID, join(cwd, "ro"), { root: join(cwd, "inputs/k"), limit: 2 });
      const error = refused(run);
      assert.match(error.error, /could not be written/);
    } finally {
      await chmod(join(cwd, "ro"), 0o755);
    }
  });
});

test("bad arguments are JSON errors", async () => {
  await withCwd(async (cwd) => {
    assert.match(refused(await tool(ID, cwd, {})).error, /root is required/);
    assert.match(refused(await tool(ID, cwd, { root: "nope" })).error, /no such directory/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", limit: 0 })).error, /limit must be an integer/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", write_values: "yes" })).error, /write_values must be true or false/);
    assert.match(refused(await tool(ID, cwd, { root: "inputs", time_limit_seconds: 0 })).error, /time_limit_seconds/);
  });
});

test("the files used as archive extensions are counted at the top level only; a nested archive is a copied file", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/collection.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    await put(cwd, "inputs/a/nested/inner.zip", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    await put(cwd, "inputs/a/nested/report.docx", Buffer.concat([Buffer.from("PK\x03\x04"), NUL(40)]));
    const out = body(await tool(ID, cwd, { root: "inputs/a" }));
    assert.equal(out.delivery.object_counts.archive, 1);
    assert.equal(out.delivery.nested_archives_named_like_archives, 1);
    assert.equal(out.delivery.kind, "mixed");
    assert.deepEqual(out.objects.map((o: Json) => o.path), ["collection.zip"]);
    assert.match(out.objects[0].note, /not opened/);
  });
});

test("utimes in the past does not matter: the answer carries no time verdict, and the tool never opens a container", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/a/case.E01", Buffer.concat([EWF_SIGNATURE, NUL(100)]));
    await utimes(join(cwd, "inputs/a/case.E01"), 1_000_000, 1_000_000);
    const out = body(await tool(ID, cwd, { root: "inputs/a" }));
    assert.doesNotMatch(JSON.stringify(out), /probably|physical image|no carving|unallocated/i);
  });
});

test("a directory name that is not UTF-8 does not stop the walk or the answer", async (t) => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "inputs/b"), { recursive: true });
    const { writeFile } = await import("node:fs/promises");
    const name = Buffer.concat([Buffer.from(join(cwd, "inputs/b") + "/bad"), Buffer.from([0xff]), Buffer.from(".E01")]);
    try {
      await writeFile(name, Buffer.concat([EWF_SIGNATURE, NUL(10)]));
    } catch (error) {
      return t.skip(`this file system refuses a name that is not UTF-8 (${(error as NodeJS.ErrnoException).code})`);
    }
    const run = await tool(ID, cwd, { root: "inputs/b" });
    const out = body(run);
    assert.equal(out.objects[0].path, "bad\udcff.E01");
    assert.equal(out.objects[0].class, "disk_container");
    assert.match(run.stdout, /bad\\udcff\.E01/);
  });
});

test("records of more than one collector in one tree are all named, each by its own paths, and none wins by order", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "inputs/m/uacdir/uac.log", "2026-02-14 09:12:00 +0000 INFO Starting\n");
    await put(cwd, "inputs/m/kapedir/r_CopyLog.csv", KAPE_COPY_HEADER + "\n" + kapeCopyRow("C:\\x", "D:\\o\\C\\x") + "\n");
    await put(cwd, "inputs/m/veloci/uploads.json", JSON.stringify({ _Source: "A" }) + "\n");
    await put(cwd, "inputs/m/C/data.bin", "x");                      // a drive-letter directory beside them: a clue, not a fourth collector
    const out = body(await tool(ID, cwd, { root: "inputs/m" }));
    assert.deepEqual(out.collector_candidates.map((c: Json) => c.collector).sort(), ["KAPE", "UAC", "Velociraptor"]);
    const markers = Object.fromEntries(out.collector_candidates.map((c: Json) => [c.collector, c.observed_markers]));
    assert.deepEqual(markers.UAC, ["uacdir/uac.log"]);
    assert.deepEqual(markers.KAPE, ["kapedir/r_CopyLog.csv"]);
    assert.deepEqual(markers.Velociraptor, ["veloci/uploads.json"]);
    assert.equal(out.layout_clues.length, 1);
    assert.deepEqual(out.layout_clues[0].compatible_with, ["a KAPE target tree", "CyLR output", "a hand-made copy"]);
  });
});
