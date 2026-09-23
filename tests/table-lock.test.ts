/**
 * The lock-table mutex (withNamedLock / withTableLock).
 *
 * Found by model-checking the lease protocol in TLA+: the stale-lock break
 * could remove a live holder's lock. Two waiters that both judged one dead
 * lock stale could each remove it, the second removing the lock the first had
 * just taken. And the judgement itself asked `kill(pid, 0)`, which is
 * meaningless across the per-pane pid namespaces fsguard gives a Linux host:
 * a live holder in another pane looks dead, and an unrelated live pid looks
 * like a holder.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withTableLock } from "../extensions/protocol.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function sandbox(): Promise<{ root: string; lockDir: string }> {
  const root = await mkdtemp(join(tmpdir(), "table-lock-"));
  await mkdir(join(root, "locks"), { recursive: true });
  return { root, lockDir: join(root, "locks", ".table.lock") };
}

async function age(dir: string, ms: number): Promise<void> {
  const then = new Date(Date.now() - ms);
  await utimes(dir, then, then);
}

test("a live holder keeps its lock past the stale age, whatever pid it recorded", async () => {
  const { root, lockDir } = await sandbox();
  try {
    let releaseA!: () => void;
    const gate = new Promise<void>((r) => (releaseA = r));
    let aInside = false;
    let entered!: () => void;
    const aEntered = new Promise<void>((r) => (entered = r));
    const a = withTableLock(root, async () => {
      aInside = true;
      entered();
      await gate;
      aInside = false;
    });
    await aEntered;
    // What a peer in another pid namespace sees: a pid that is not live here.
    // The holder has also been in its critical section longer than the stale age.
    await writeFile(join(lockDir, "pid"), "999999999", "utf8");
    await age(lockDir, 20_000);
    // A live holder refreshes its lock; give it the time to do so.
    const until = Date.now() + 6_000;
    while (Date.now() < until && Date.now() - (await stat(lockDir)).mtimeMs > 10_000) await sleep(100);

    let bSawA: boolean | null = null;
    const b = withTableLock(root, async () => {
      bSawA = aInside;
    });
    await sleep(300);
    assert.equal(bSawA, null, "a second holder entered while the first was still inside");
    releaseA();
    await Promise.all([a, b]);
    assert.equal(bSawA, false, "the second holder entered while the first was still inside");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a stale lock is broken even when the pid it records is live", async () => {
  const { root, lockDir } = await sandbox();
  try {
    // A pid that is live here but is not the holder: in another pid namespace
    // it is someone else, or a recycled number. The holder stopped long ago.
    await mkdir(lockDir);
    await writeFile(join(lockDir, "pid"), String(process.pid), "utf8");
    await age(lockDir, 20_000);
    const started = Date.now();
    let ran = false;
    await withTableLock(root, async () => {
      ran = true;
    });
    assert.ok(ran);
    assert.ok(Date.now() - started < 5_000, `took ${Date.now() - started} ms to break a stale lock`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("only one waiter breaks a stale lock at a time, and it judges the age again first", async () => {
  const { root, lockDir } = await sandbox();
  try {
    await mkdir(lockDir);
    await writeFile(join(lockDir, "pid"), "999999999", "utf8");
    await age(lockDir, 20_000);
    // Another waiter is mid-break. Removing the lock now could remove the one
    // that waiter is about to take.
    await mkdir(`${lockDir}.break`);
    let ran = false;
    const waiter = withTableLock(root, async () => {
      ran = true;
    });
    await sleep(300);
    assert.equal(ran, false, "entered while another waiter was breaking the lock");
    assert.equal(await readFile(join(lockDir, "pid"), "utf8"), "999999999", "the lock was removed under another waiter's break");
    await rm(`${lockDir}.break`, { recursive: true, force: true });
    await waiter;
    assert.equal(ran, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a holder does not remove a lock that is no longer its own", async () => {
  const { root, lockDir } = await sandbox();
  try {
    await withTableLock(root, async () => {
      // Ours was broken while we stalled, and someone else took it.
      await rm(lockDir, { recursive: true, force: true });
      await mkdir(lockDir);
      await writeFile(join(lockDir, "pid"), "1", "utf8");
      await writeFile(join(lockDir, "owner"), "someone-else", "utf8");
    });
    assert.equal(await readFile(join(lockDir, "owner"), "utf8"), "someone-else", "released a lock someone else holds");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
