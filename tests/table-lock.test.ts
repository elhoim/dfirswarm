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
import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
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
    assert.deepEqual(await readdir(join(root, "locks")), [], "a break or a release left something behind");
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

test("on macOS the namespace is the boot session, whatever the host is called now", { skip: process.platform !== "darwin" && "macOS only" }, () => {
  // A Mac with no HostName set takes its name from the network it is on. A
  // reap.sh or `swarm.sh say` run after a sleep on another network must still
  // print what the panes stamped, or a stalled holder's lock goes by age alone.
  const session = execFileSync("sysctl", ["-n", "kern.bootsessionuuid"], { encoding: "utf8" }).trim();
  assert.equal(lockNamespace(), `darwin:${session}`);
  const block = execFileSync("sed", ["-n", "/^# >>> table lock/,/^# <<< table lock/p", join(ROOT, "scripts/reap.sh")], {
    encoding: "utf8",
  });
  const renamed = execFileSync("bash", ["-c", `hostname() { echo renamed-by-another-network; }\n${block}\ntable_lock_ns`], {
    encoding: "utf8",
  });
  assert.equal(renamed, lockNamespace());
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

test("a lock's age is read on the filesystem's clock, not the waiter's", async () => {
  // A waiter whose clock runs a minute ahead of the one that stamped the lock
  // (a host judging a microVM guest's lock, an NFS client) must not see a
  // fresh lock as stale. Age is taken against a probe file's mtime instead.
  const { root, lockDir } = await sandbox();
  const saved = { ...tableLockTiming };
  const realNow = Date.now;
  try {
    await mkdir(lockDir);
    await writeFile(join(lockDir, "pid"), "999999999", "utf8");
    await writeFile(join(lockDir, "ns"), FOREIGN_NS, "utf8");
    tableLockTiming.waitMs = 1_000;
    Date.now = () => realNow() + 60_000;
    await assert.rejects(withTableLock(root, async () => undefined), /Timed out/);
    Date.now = realNow;
    assert.equal(await readFile(join(lockDir, "pid"), "utf8"), "999999999", "a fresh lock was broken on a skewed clock");
    assert.deepEqual((await readdir(join(root, "locks"))).sort(), [".table.lock"], "the probe was left behind");
  } finally {
    Date.now = realNow;
    Object.assign(tableLockTiming, saved);
    await rm(root, { recursive: true, force: true });
  }
});

test("a holder's heartbeat stops once its lock has been taken over", async () => {
  const { root, lockDir } = await sandbox();
  const saved = { ...tableLockTiming };
  try {
    tableLockTiming.heartbeatMs = 50;
    await warningsDuring(() =>
      withTableLock(root, async () => {
        const until = Date.now() + 2_000;
        while (!existsSync(join(lockDir, "beat")) && Date.now() < until) await sleep(20);
        assert.ok(existsSync(join(lockDir, "beat")), "the holder never refreshed its lock");
        // Broken while we stalled, and taken by someone else. A tick of the
        // heartbeat can be between its read of the owner and its write when
        // this happens (it read our token, and writes `beat` into whatever
        // directory is there by then): that one write can land in the middle of
        // the removal (ENOTEMPTY, which the retry covers) or after the swap.
        // What must not happen is a second one, so each round clears the file
        // and waits for six ticks; a heartbeat that keeps going puts it back
        // every round, one that has stopped leaves it absent after at most the
        // one round that met the stray write.
        await rm(lockDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 20 });
        await mkdir(lockDir);
        await writeFile(join(lockDir, "owner"), "someone-else", "utf8");
        const beat = join(lockDir, "beat");
        let rounds = 0;
        do {
          await rm(beat, { force: true });
          await sleep(300);
          rounds += 1;
        } while (existsSync(beat) && rounds < 4);
        assert.equal(existsSync(beat), false, "kept refreshing a lock that is someone else's");
      }),
    );
  } finally {
    Object.assign(tableLockTiming, saved);
    await rm(root, { recursive: true, force: true });
  }
});

test("a heartbeat tick that was in flight when the lock was taken over leaves one stray file, not a heartbeat that goes on", async () => {
  // The tick that read our token just before the take-over writes `beat` after
  // it. The test plays that tick by hand, at the one moment it can happen, so
  // the outcome does not depend on the host's timing: the stray file is
  // tolerated once, and a second one (the heartbeat still running) is not.
  const { root, lockDir } = await sandbox();
  const saved = { ...tableLockTiming };
  try {
    tableLockTiming.heartbeatMs = 50;
    await warningsDuring(() =>
      withTableLock(root, async () => {
        const until = Date.now() + 2_000;
        while (!existsSync(join(lockDir, "beat")) && Date.now() < until) await sleep(20);
        await rm(lockDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 20 });
        await mkdir(lockDir);
        await writeFile(join(lockDir, "owner"), "someone-else", "utf8");
        const beat = join(lockDir, "beat");
        await writeFile(beat, "stray", "utf8");
        let rounds = 0;
        do {
          await rm(beat, { force: true });
          await sleep(300);
          rounds += 1;
        } while (existsSync(beat) && rounds < 4);
        assert.equal(existsSync(beat), false, "the heartbeat went on after the stray write");
        assert.ok(rounds <= 2, `${rounds} rounds to settle`);
      }),
    );
  } finally {
    Object.assign(tableLockTiming, saved);
    await rm(root, { recursive: true, force: true });
  }
});

test("calls of one process take the lock in the order they asked and do not time out behind each other", async () => {
  // In a VM run the hub is the only writer. With the lock polled on disk, a call lost the poll to its own process's
  // other calls for ten seconds and failed (216 such failures in one run). The wait for another process's lock is
  // shortened here to less than one holder's time: no call of this process may fail on it.
  const { root } = await sandbox();
  const saved = { ...tableLockTiming };
  try {
    tableLockTiming.waitMs = 150;
    const order: number[] = [];
    const calls = Array.from({ length: 12 }, (_, i) =>
      withTableLock(root, async () => {
        order.push(i);
        await sleep(60);
        return i;
      }),
    );
    assert.deepEqual(await Promise.all(calls), Array.from({ length: 12 }, (_, i) => i));
    assert.deepEqual(order, Array.from({ length: 12 }, (_, i) => i), "in the order they asked");
    // A call that throws passes the lock on.
    await assert.rejects(withTableLock(root, async () => { throw new Error("boom"); }), /boom/);
    assert.equal(await withTableLock(root, async () => "after"), "after");
    // A call that gives up its place in the line does not stop the line.
    tableLockTiming.queueMs = 80;
    const slow = withTableLock(root, async () => { await sleep(300); return "slow"; });
    const quitter = withTableLock(root, async () => "never");
    const patient = (async () => { tableLockTiming.queueMs = 5000; return withTableLock(root, async () => "patient"); })();
    await assert.rejects(quitter, /Timed out waiting for locks\/\.table\.lock \(1 call\(s\) of this process were ahead/);
    assert.equal(await slow, "slow");
    assert.equal(await patient, "patient");
  } finally {
    Object.assign(tableLockTiming, saved);
    await rm(root, { recursive: true, force: true });
  }
});

test("each register has its own line: with a record held five seconds, a fold of usage and a post each finish in 100 ms, and 1,000 calls at once see no timeout", async () => {
  // Plan 2, A10. The ledger, the budget and the board shared one lock: a record that took seconds held every post and
  // every fold of usage behind it (P-10: 216 "Timed out waiting for locks/.table.lock" in one run). Each now has its own.
  const P = await import("../extensions/protocol.ts");
  const { F, ok, rec, run } = await import("./negative-bar-fixture.ts");
  const { S, a0, a1 } = await run();
  const slice = (n: number) => ({ spent_usd: n / 1000, tokens: n, calls: n, input: n, output: 0, cache_read: 0, cache_write: 0 }) as import("../extensions/protocol.ts").SessionUsageSlice;
  const finding = (i: number) => ({ kind: "finding", ...F, value: `the export's row ${i} is a header`, source: "the disk", evidence: `row ${i}`, refs: ["job:j000001/hits.txt"] });
  // Warm: the first call of each kind loads what it imports.
  await P.applySessionUsage(S, "a1", slice(1));
  await P.postMessage(a1, { tag: "result", body: "warm" });
  ok(await rec(a0, finding(0)));
  let entered!: () => void;
  const inside = new Promise<void>((r) => (entered = r));
  let slow = true;
  P.lockTestHooks.held = async (name) => {
    if (name === P.LEDGER_LOCK && slow) {
      slow = false;
      entered();
      await sleep(5000);
    }
  };
  try {
    const t0 = performance.now();
    const record = rec(a0, finding(1));
    await inside;
    const timed = async <T>(p: () => Promise<T>): Promise<number> => {
      const at = performance.now();
      await p();
      return performance.now() - at;
    };
    const [usage, post] = await Promise.all([timed(() => P.applySessionUsage(S, "a1", slice(2))), timed(() => P.postMessage(a1, { tag: "result", body: "while the ledger is held" }))]);
    assert.ok(usage < 100, `a fold of usage took ${usage.toFixed(1)} ms while a record held the ledger's lock`);
    assert.ok(post < 100, `a post took ${post.toFixed(1)} ms while a record held the ledger's lock`);
    ok(await record);
    assert.ok(performance.now() - t0 >= 5000, "the record did hold its lock for five seconds");
    process.stdout.write(`# with a record held 5 s: a fold of usage ${usage.toFixed(1)} ms, a post ${post.toFixed(1)} ms\n`);
  } finally {
    delete P.lockTestHooks.held;
  }
  // A thousand calls at once, of three registers, each on the run's own timings: none times out.
  const t1 = performance.now();
  const whole = P.appendOnlyReadStats.whole;
  const calls: Array<Promise<unknown>> = [];
  for (let i = 0; i < 1000; i++) {
    if (i % 20 === 0) calls.push(rec(a0, finding(100 + i)).then(ok));
    else if (i % 2) calls.push(P.applySessionUsage(S, i % 4 === 1 ? "a1" : "a2", slice(10 + i)));
    else calls.push(P.postMessage(a1, { tag: "result", body: `post ${i}` }));
  }
  const settled = await Promise.allSettled(calls);
  const failed = settled.filter((s): s is PromiseRejectedResult => s.status === "rejected");
  assert.deepEqual(failed.map((f) => String(f.reason?.message ?? f.reason)).slice(0, 3), [], `${failed.length} of 1,000 calls failed`);
  const posts = (await readdir(join(S, "threads", "main"))).filter((n) => /^\d{6}-a1\.md$/.test(n));
  assert.equal(posts.length, 2 + 450, "every post has its own id");
  assert.equal((await P.readLedger(S)).length, 2 + 50, "every record is in the ledger");
  assert.equal(P.appendOnlyReadStats.whole - whole, 0, "and none read the ledger whole: each read what was appended since");
  const budget = await P.readBudget(S);
  assert.equal(budget.agents.a2!.calls, 1009, "the last fold of each seat is the budget's");
  process.stdout.write(`# 1,000 calls (450 posts, 500 folds of usage, 50 records) in ${(performance.now() - t1).toFixed(0)} ms, none timed out\n`);
});

test("an append-only register is read from disk past what this process holds: an append is read alone, a rewrite whole", async () => {
  const P = await import("../extensions/protocol.ts");
  const { root } = await sandbox();
  try {
    const file = join(root, "entries.jsonl");
    const lines = Array.from({ length: 2000 }, (_, i) => `${JSON.stringify({ seq: i + 1, value: `entry ${i} ${"x".repeat(200)}` })}\n`);
    await writeFile(file, lines.join(""));
    const s0 = { ...P.appendOnlyReadStats };
    assert.equal(await P.readAppendOnlyText(file), lines.join(""));
    assert.equal(P.appendOnlyReadStats.whole - s0.whole, 1);
    assert.equal(await P.readAppendOnlyText(file), lines.join(""), "again, nothing read");
    assert.equal(P.appendOnlyReadStats.unchanged - s0.unchanged, 1);
    // An append, and a line still being written: read alone; the torn line is given as it stands and read again next time.
    const { appendFile } = await import("node:fs/promises");
    await appendFile(file, `{"seq":2001,"value":"çağrı"}\n{"seq":2002,"val`);
    assert.equal(await P.readAppendOnlyText(file), `${lines.join("")}{"seq":2001,"value":"çağrı"}\n{"seq":2002,"val`);
    await appendFile(file, `ue":"done"}\n`);
    const all = `${lines.join("")}{"seq":2001,"value":"çağrı"}\n{"seq":2002,"value":"done"}\n`;
    assert.equal(await P.readAppendOnlyText(file), all);
    assert.equal(P.appendOnlyReadStats.whole - s0.whole, 1, "the appends were read alone");
    assert.equal(P.appendOnlyReadStats.appended - s0.appended, 2);
    // Many readers at once read it once between them, and each sees all of it.
    const many = await Promise.all(Array.from({ length: 20 }, () => P.readAppendOnlyText(file)));
    assert.ok(many.every((t) => t === all));
    // Rewritten under the process: shorter, or longer with another end, or another file at the name. Each is read whole.
    await writeFile(file, lines.slice(0, 10).join(""));
    assert.equal(await P.readAppendOnlyText(file), lines.slice(0, 10).join(""));
    await writeFile(file, lines.slice(0, 9).join("") + lines[1999] + lines[0]);
    assert.equal(await P.readAppendOnlyText(file), lines.slice(0, 9).join("") + lines[1999] + lines[0]);
    await rm(file);
    assert.equal(await P.readAppendOnlyText(file), "", "a file that is not there reads as nothing");
    await writeFile(file, "a\n");
    assert.equal(await P.readAppendOnlyText(file), "a\n");
    assert.ok(P.appendOnlyHeldSize().files >= 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
