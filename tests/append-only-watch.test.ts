/**
 * The shell-write watch on the two append-only records: the ledger and the
 * trace. They grow while any shell runs, so they are compared for growth, not
 * equality: the bytes a record held before the call must still be its opening.
 *
 * On run s7099 the harness posted RECORD REWRITTEN for regipy reads that
 * touched nothing. The before-mark took its size from stat and its digest
 * from a read of the whole file, and between the two the collector appended
 * (four agents logging, and the tool_call event for the very shell about to
 * run). A digest over S+delta bytes can never match the S-byte prefix hashed
 * afterwards. The first test races the snapshot against appends the way the
 * collector does; the other two make sure a real rewrite is still caught.
 */
import assert from "node:assert/strict";
import { appendFile, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { diffWatchedPaths, EVENTS_REL, initSandbox, watchedPathHashes } from "../extensions/protocol.ts";

const line = (n: number) => JSON.stringify({ ts: `t${n}`, agent: "a1", tool: "post", args: {}, result: { ok: true } }) + "\n";

async function sandbox(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "append-only-watch-"));
  await initSandbox(root, { reset: true });
  await writeFile(join(root, EVENTS_REL), line(1) + line(2), "utf8");
  return root;
}

test("a record that only grew while the snapshot was taken is not a rewrite, however the appends interleave", async () => {
  const root = await sandbox();
  try {
    let n = 3;
    let reported = 0;
    for (let i = 0; i < 40; i++) {
      // Appends land while the snapshot is in flight, on both queues the
      // collector's writes can arrive on relative to the stat and the read.
      const pending = watchedPathHashes(root);
      setImmediate(() => void appendFile(join(root, EVENTS_REL), line(n++), "utf8"));
      setTimeout(() => void appendFile(join(root, EVENTS_REL), line(n++), "utf8"), 0);
      const before = await pending;
      await appendFile(join(root, EVENTS_REL), line(n++), "utf8");
      const reports = await diffWatchedPaths(root, before, "a0");
      if (reports.some((r) => r.path === EVENTS_REL)) reported += 1;
    }
    assert.equal(reported, 0, `an appended-to trace was reported as rewritten in ${reported} of 40 rounds`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a record that got shorter is a rewrite", async () => {
  const root = await sandbox();
  try {
    const before = await watchedPathHashes(root);
    const text = await readFile(join(root, EVENTS_REL), "utf8");
    await writeFile(join(root, EVENTS_REL), text.slice(0, -1), "utf8");
    const hit = (await diffWatchedPaths(root, before, "a0")).find((r) => r.path === EVENTS_REL);
    assert.ok(hit && hit.rewritten === true, `a shortened trace must be reported: ${JSON.stringify(hit)}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a record whose opening bytes changed is a rewrite, even when it also grew", async () => {
  const root = await sandbox();
  try {
    const before = await watchedPathHashes(root);
    const handle = await open(join(root, EVENTS_REL), "r+");
    try {
      await handle.write(Buffer.from("X"), 0, 1, 2); // one byte inside the first line
    } finally {
      await handle.close();
    }
    await appendFile(join(root, EVENTS_REL), line(3), "utf8");
    const hit = (await diffWatchedPaths(root, before, "a0")).find((r) => r.path === EVENTS_REL);
    assert.ok(hit && hit.rewritten === true, `a changed prefix must be reported: ${JSON.stringify(hit)}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
