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
import { applySessionUsage, diffWatchedPaths, EVENTS_REL, initSandbox, readBudget, recordEntry, watchedPathHashes, writeBudget } from "../extensions/protocol.ts";

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

test("a peer's record that merges into an earlier ledger entry is not a rewrite; a changed entry still is", async () => {
  const root = await mkdtemp(join(tmpdir(), "append-only-ledger-"));
  try {
    await initSandbox(root, { swarmId: "sl", agentIds: ["a0", "a1", "a2"] });
    const entry = { kind: "ioc", value: "evil.example.com", source: "dns.log", evidence: "grep evil dns.log" };
    assert.equal((await recordEntry({ sandboxRoot: root, agentId: "a0" }, entry)).ok, true);
    const before = await watchedPathHashes(root, "a1");
    // During a1's shell call, a2 cites the same indicator: an author is added.
    const merged = await recordEntry({ sandboxRoot: root, agentId: "a2" }, entry);
    assert.equal(merged.ok && (merged as { merged: boolean }).merged, true);
    const reports = await diffWatchedPaths(root, before, "a1");
    assert.deepEqual(reports.filter((r) => r.path.startsWith("ledger/")), [], "a merge is not blamed on a1's command");
    // A chained entry's value changed under the same shell: that is a rewrite.
    const again = await watchedPathHashes(root, "a1");
    const file = join(root, "ledger", "entries.jsonl");
    await writeFile(file, (await readFile(file, "utf8")).replace("evil.example.com", "benign.example.com"), "utf8");
    const rewritten = await diffWatchedPaths(root, again, "a1");
    assert.ok(rewritten.some((r) => r.path === "ledger/entries.jsonl" && r.rewritten), "a changed entry is reported");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("budget.json is replaced whole: a write never leaves it empty or cut short for a reader", async () => {
  const root = await mkdtemp(join(tmpdir(), "append-only-budget-"));
  try {
    await initSandbox(root, { swarmId: "sb", agentIds: ["a0"], capUsd: 20, wallClockMinutes: 240 });
    const budget = await readBudget(root);
    let stop = false;
    let torn = 0;
    const reader = (async () => {
      while (!stop) {
        const text = await readFile(join(root, "budget.json"), "utf8").catch(() => "");
        try {
          JSON.parse(text);
        } catch {
          torn += 1;
        }
        await new Promise((r) => setImmediate(r));
      }
    })();
    for (let i = 0; i < 200; i++) await writeBudget(root, { ...budget, spent_usd: i / 100 });
    stop = true;
    await reader;
    assert.equal(torn, 0, "a reader never saw a torn budget");
    assert.equal((await readBudget(root)).cap_usd, 20);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a budget.json that does not read is left alone by a usage report, never rebuilt from defaults", async () => {
  const root = await mkdtemp(join(tmpdir(), "append-only-budget-torn-"));
  try {
    await initSandbox(root, { swarmId: "sb", agentIds: ["a0"], capUsd: 20, wallClockMinutes: 240 });
    const file = join(root, "budget.json");
    const torn = (await readFile(file, "utf8")).slice(0, 40);
    await writeFile(file, torn, "utf8");
    await assert.rejects(applySessionUsage(root, "a0", { spent_usd: 1 } as never), /does not read/);
    assert.equal(await readFile(file, "utf8"), torn, "the file is as it was");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
