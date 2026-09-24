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
import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lockNamespace, TableLockLostError, tableLockTiming, withTableLock } from "../extensions/protocol.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
/** What a peer in another pid namespace, or another VM, records. */
const FOREIGN_NS = "linux:pid:[1]:another-boot";

/** A pid that was ours a moment ago and is gone now. */
function deadPid(): number {
  const out = execFileSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  return Number(out);
}

/** Collect the lost-lock warnings `fn` raises. */
async function warningsDuring(fn: () => Promise<void>): Promise<string[]> {
  const seen: string[] = [];
  const onWarning = (w: Error & { code?: string }) => {
    if (w.code === "DFIRSWARM_TABLE_LOCK_LOST") seen.push(w.message);
  };
  process.on("warning", onWarning);
  try {
    await fn();
    // emitWarning delivers on the next tick.
    await new Promise((r) => setImmediate(r));
  } finally {
    process.off("warning", onWarning);
  }
  return seen;
}

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
    // What a peer in another pid namespace sees: a pid that is not live here,
    // recorded in a namespace that is not ours. The holder has also been in its
    // critical section longer than the stale age.
    await writeFile(join(lockDir, "pid"), "999999999", "utf8");
    await writeFile(join(lockDir, "ns"), FOREIGN_NS, "utf8");
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

test("a stale lock from another namespace is broken even when the pid it records is live", async () => {
  const { root, lockDir } = await sandbox();
  try {
    // A pid that is live here but is not the holder: in another pid namespace
    // it is someone else, or a recycled number. The holder stopped long ago.
    await mkdir(lockDir);
    await writeFile(join(lockDir, "pid"), String(process.pid), "utf8");
    await writeFile(join(lockDir, "ns"), FOREIGN_NS, "utf8");
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

test("a holder does not remove a lock that is no longer its own, and says so", async () => {
  const { root, lockDir } = await sandbox();
  try {
    const warned = await warningsDuring(() =>
      withTableLock(root, async () => {
        // Ours was broken while we stalled, and someone else took it.
        await rm(lockDir, { recursive: true, force: true });
        await mkdir(lockDir);
        await writeFile(join(lockDir, "pid"), "1", "utf8");
        await writeFile(join(lockDir, "owner"), "someone-else", "utf8");
      }),
    );
    assert.equal(await readFile(join(lockDir, "owner"), "utf8"), "someone-else", "released a lock someone else holds");
    assert.equal(warned.length, 1, "a lost lock went unreported at release");
    assert.match(warned[0], /taken over/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a holder that stalls past the stale age keeps its lock from a peer that can see its pid", async () => {
  // The review's reproduction, with the 15 s stale age shortened to 1 s: a
  // holder blocks its event loop (as SIGSTOP, swap or a laptop asleep would),
  // so its heartbeat stops, for longer than the stale age.
  const { root } = await sandbox();
  const saved = { ...tableLockTiming };
  const inside = join(root, "inside");
  const left = join(root, "left");
  const child = spawn(
    process.execPath,
    [
      "--experimental-strip-types",
      "--input-type=module",
      "-e",
      `
        import { writeFileSync } from "node:fs";
        const m = await import(${JSON.stringify(pathToFileURL(join(ROOT, "extensions/protocol.ts")).href)});
        m.tableLockTiming.staleMs = 1000;
        m.tableLockTiming.heartbeatMs = 200;
        await m.withTableLock(${JSON.stringify(root)}, async () => {
          writeFileSync(${JSON.stringify(inside)}, "");
          const until = Date.now() + 2500;
          while (Date.now() < until) {}
          writeFileSync(${JSON.stringify(left)}, "");
        });
      `,
    ],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
  try {
    tableLockTiming.staleMs = 1000;
    const until = Date.now() + 20_000;
    while (!existsSync(inside) && Date.now() < until) await sleep(20);
    assert.ok(existsSync(inside), "the stalling holder never took the lock");
    let heldAlready: boolean | null = null;
    await withTableLock(root, async () => {
      heldAlready = !existsSync(left);
    });
    assert.equal(heldAlready, false, "entered while the stalled holder was still inside");
    assert.equal(await exited, 0);
  } finally {
    Object.assign(tableLockTiming, saved);
    child.kill();
    await rm(root, { recursive: true, force: true });
  }
});

test("a stale lock from our namespace whose holder is dead is broken", async () => {
  const { root, lockDir } = await sandbox();
  try {
    await mkdir(lockDir);
    await writeFile(join(lockDir, "pid"), String(deadPid()), "utf8");
    await writeFile(join(lockDir, "ns"), lockNamespace(), "utf8");
    await age(lockDir, 20_000);
    const started = Date.now();
    await withTableLock(root, async () => undefined);
    assert.ok(Date.now() - started < 5_000, `took ${Date.now() - started} ms to break a dead holder's lock`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("protocol.ts and the bash copies name this namespace alike", { skip: process.platform === "win32" }, () => {
  const block = execFileSync("sed", ["-n", "/^# >>> table lock/,/^# <<< table lock/p", join(ROOT, "scripts/reap.sh")], {
    encoding: "utf8",
  });
  const fromBash = execFileSync("bash", ["-c", `${block}\ntable_lock_ns`], { encoding: "utf8" });
  assert.equal(fromBash, lockNamespace());
  if (process.platform === "linux" || process.platform === "darwin") assert.notEqual(lockNamespace(), "");
});

test("a holder checks its lock is still its own before it commits a write", async () => {
  const { root, lockDir } = await sandbox();
  const target = join(root, "table.json");
  try {
    await withTableLock(root, async (held) => {
      await held.assertOwned();
    });
    const warned = await warningsDuring(async () => {
      await assert.rejects(
        withTableLock(root, async (held) => {
          // Broken while we stalled, and taken by someone else.
          await rm(lockDir, { recursive: true, force: true });
          await mkdir(lockDir);
          await writeFile(join(lockDir, "owner"), "someone-else", "utf8");
          await held.assertOwned();
          await writeFile(target, "lost update", "utf8");
        }),
        TableLockLostError,
      );
    });
    assert.equal(existsSync(target), false, "wrote after its lock was taken over");
    assert.equal(warned.length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
