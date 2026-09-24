/**
 * The artifact index. Evidence has arrived hashed since the inputs manifest
 * existed; a run's own output did not, so a report quoting a carved file had
 * no number a reader could check it against.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { artifactKind, hashArtifacts, sha256OfFile } from "../scripts/artifacts.ts";
import { recordFileVersion } from "../extensions/protocol.ts";

async function withSandbox(fn: (sandbox: string) => Promise<void>): Promise<void> {
  const sandbox = await mkdtemp(join(tmpdir(), "artifacts-"));
  try {
    await mkdir(join(sandbox, "work"), { recursive: true });
    await mkdir(join(sandbox, "traces"), { recursive: true });
    await writeFile(join(sandbox, "traces", "events.jsonl"), "", "utf8");
    await fn(sandbox);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}

const sha = (text: string) => createHash("sha256").update(text).digest("hex");

test("every file under work/ is hashed, however deep it sits", async () => {
  await withSandbox(async (sandbox) => {
    await mkdir(join(sandbox, "work", "exports", "csv"), { recursive: true });
    await writeFile(join(sandbox, "work", "report.md"), "# Report\n", "utf8");
    await writeFile(join(sandbox, "work", "timeline.csv"), "ts,event\n", "utf8");
    await writeFile(join(sandbox, "work", "exports", "csv", "deep.csv"), "a,b\n", "utf8");

    const index = await hashArtifacts(sandbox);
    const byPath = new Map(index.files.map((f) => [f.path, f]));
    assert.deepEqual([...byPath.keys()], [
      "work/exports/csv/deep.csv",
      "work/report.md",
      "work/timeline.csv",
    ]);
    assert.equal(byPath.get("work/report.md")?.sha256, sha("# Report\n"));
    assert.equal(byPath.get("work/exports/csv/deep.csv")?.sha256, sha("a,b\n"));
    // The console's own list stops at depth 3; the index must not, because
    // the package now ships everything and the manifest hashes everything.
    assert.equal(index.files.length, 3);
    assert.equal(index.bytes, "# Report\n".length + "ts,event\n".length + "a,b\n".length);
    assert.equal(index.packaged_bytes, index.bytes);
  });
});

test("extracted and quarantined material is hashed but marked not packaged", async () => {
  await withSandbox(async (sandbox) => {
    await mkdir(join(sandbox, "work", "extracted", "hives"), { recursive: true });
    await mkdir(join(sandbox, "work", "quarantine"), { recursive: true });
    await writeFile(join(sandbox, "work", "report.md"), "# Report\n", "utf8");
    await writeFile(join(sandbox, "work", "extracted", "hives", "SOFTWARE"), "hive bytes", "utf8");
    await writeFile(join(sandbox, "work", "quarantine", "shell.aspx"), "live sample", "utf8");

    const index = await hashArtifacts(sandbox);
    const byPath = new Map(index.files.map((f) => [f.path, f]));
    // The ledger cites these paths and sometimes their hashes, so a reader
    // has to be able to verify one without the package carrying the bytes.
    assert.equal(byPath.get("work/extracted/hives/SOFTWARE")?.sha256, sha("hive bytes"));
    assert.equal(byPath.get("work/extracted/hives/SOFTWARE")?.packaged, false);
    assert.equal(byPath.get("work/quarantine/shell.aspx")?.packaged, false);
    assert.equal(byPath.get("work/report.md")?.packaged, true);
    assert.equal(index.bytes, "# Report\n".length + "hive bytes".length + "live sample".length);
    assert.equal(index.packaged_bytes, "# Report\n".length);
    assert.deepEqual(index.unpackaged_dirs, ["extracted", "quarantine"]);
  });
});

test("a symlink is named and skipped, never followed", async () => {
  await withSandbox(async (sandbox) => {
    const outside = join(sandbox, "outside.txt");
    await writeFile(outside, "not the swarm's work", "utf8");
    await writeFile(join(sandbox, "work", "report.md"), "# Report\n", "utf8");
    await symlink(outside, join(sandbox, "work", "link.txt"));

    const index = await hashArtifacts(sandbox);
    assert.deepEqual(index.files.map((f) => f.path), ["work/report.md"]);
    assert.deepEqual(index.skipped, [
      { path: "work/link.txt", reason: "symbolic link, not followed" },
    ]);
  });
});

test("history names the last writer; a claim in the trace is not a write", async () => {
  await withSandbox(async (sandbox) => {
    await writeFile(join(sandbox, "work", "report.md"), "# Report\n", "utf8");
    await recordFileVersion(sandbox, "work/report.md", "s1a001");
    await writeFile(join(sandbox, "work", "report.md"), "# Edited\n", "utf8");
    await recordFileVersion(sandbox, "work/report.md", "s1a002");
    await writeFile(join(sandbox, "work", "notes.md"), "notes\n", "utf8");
    // A claim is a lease, not a write. The old index treated claim_file as
    // authorship, so a file nobody had snapshotted was attributed to whoever
    // last took the lock.
    await writeFile(
      join(sandbox, "traces", "events.jsonl"),
      `${JSON.stringify({ ts: "2026-09-20T10:07:00Z", agent: "s1a004", tool: "claim_file", args: { path: "work/notes.md" }, result: { ok: true } })}\n`,
      "utf8",
    );

    const index = await hashArtifacts(sandbox);
    const byPath = new Map(index.files.map((f) => [f.path, f]));
    assert.equal(byPath.get("work/report.md")?.last_written_by, "s1a002", "the last snapshot wins");
    assert.equal(byPath.get("work/report.md")?.revisions, 2);
    assert.equal(byPath.get("work/notes.md")?.last_written_by, null, "no snapshot, no writer");
    assert.equal(byPath.get("work/notes.md")?.revisions, 0);
  });
});

test("a file that changes gets a different hash, and an empty work/ is not an error", async () => {
  await withSandbox(async (sandbox) => {
    const empty = await hashArtifacts(sandbox);
    assert.deepEqual(empty.files, []);
    assert.equal(empty.bytes, 0);
    assert.deepEqual(empty.skipped, []);

    const file = join(sandbox, "work", "report.md");
    await writeFile(file, "first\n", "utf8");
    const before = await hashArtifacts(sandbox);
    await writeFile(file, "second\n", "utf8");
    const after = await hashArtifacts(sandbox);
    assert.notEqual(before.files[0].sha256, after.files[0].sha256);
    assert.equal(after.files[0].sha256, sha("second\n"));
  });
});

test("a large file hashes by streaming, not by reading it whole", async () => {
  await withSandbox(async (sandbox) => {
    // 4 MiB is past the default highWaterMark many times over, so this fails
    // if the implementation ever goes back to readFile on a gigabyte tree.
    const chunk = "0123456789abcdef".repeat(4096); // 64 KiB
    const body = chunk.repeat(64); // 4 MiB
    const file = join(sandbox, "work", "big.bin");
    await writeFile(file, body, "utf8");
    assert.equal(await sha256OfFile(file), sha(body));
    const index = await hashArtifacts(sandbox);
    assert.equal(index.files[0].bytes, body.length);
    assert.equal(index.files[0].sha256, sha(body));
  });
});

test("kind comes from the extension, and an unknown one is binary", () => {
  assert.equal(artifactKind("report.html"), "html");
  assert.equal(artifactKind("mark.svg"), "svg");
  assert.equal(artifactKind("shot.PNG"), "image");
  assert.equal(artifactKind("entries.jsonl"), "text");
  assert.equal(artifactKind("timeline.csv"), "text");
  assert.equal(artifactKind("notes.yaml"), "text");
  assert.equal(artifactKind("layout.yml"), "text");
  assert.equal(artifactKind("events.xml"), "text");
  assert.equal(artifactKind("SOFTWARE"), "text");
  assert.equal(artifactKind("image.E01"), "binary");
});

test("the index is in code-unit order, the same in every locale, because its hash is anchored", async () => {
  const sandbox = await mkdtemp(join(tmpdir(), "artifacts-order-"));
  try {
    await mkdir(join(sandbox, "work"), { recursive: true });
    // Names no case-insensitive file system folds together.
    for (const name of ["b", "C", "a", "ä", "ı", "Z"]) await writeFile(join(sandbox, "work", name), name);
    const index = await hashArtifacts(sandbox);
    // localeCompare gave a different order under en_US, da_DK, sv_SE and tr_TR.
    assert.deepEqual(index.files.map((f) => f.path), ["work/C", "work/Z", "work/a", "work/b", "work/ä", "work/ı"]);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});
