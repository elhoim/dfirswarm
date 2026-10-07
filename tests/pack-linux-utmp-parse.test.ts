/**
 * The Linux pack: utmp_parse, against glibc's struct utmp (384 bytes: type at 0x00, pid at 0x04, line at 0x08,
 * id at 0x28, user at 0x2c, host at 0x4c, exit at 0x14c, session at 0x150, tv_sec at 0x154, tv_usec at 0x158,
 * ut_addr_v6 at 0x15c, 20 unused bytes) and struct lastlog (a 32-bit or a 64-bit time, line[32], host[256]:
 * 292 or 296 bytes, indexed by UID).
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { mkdir, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { UTMP, body, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";

type Utmp = { type: number; pid?: number; line?: string; id?: string; user?: string; host?: string; session?: number; sec?: number; usec?: number; addr?: number[] };

/** glibc struct utmp, 384 bytes, from its field offsets (see the header). */
function utmp(o: Utmp, big = false): Buffer {
  const b = Buffer.alloc(384);
  const i16 = (v: number, at: number): void => void (big ? b.writeInt16BE(v, at) : b.writeInt16LE(v, at));
  const i32 = (v: number, at: number): void => void (big ? b.writeInt32BE(v, at) : b.writeInt32LE(v, at));
  i16(o.type, 0x00);
  i32(o.pid ?? 0, 0x04);
  b.write(o.line ?? "", 0x08, 32, "latin1");
  b.write(o.id ?? "", 0x28, 4, "latin1");
  b.write(o.user ?? "", 0x2c, 32, "latin1");
  b.write(o.host ?? "", 0x4c, 256, "latin1");
  i32(o.session ?? 0, 0x150);
  i32(o.sec ?? 0, 0x154);
  i32(o.usec ?? 0, 0x158);
  (o.addr ?? []).forEach((byte, k) => b.writeUInt8(byte, 0x15c + k));
  return b;
}

/** struct lastlog: a 32-bit time then line[32] and host[256] (292 bytes), or a 64-bit time (296 bytes). */
function lastlog(width: 292 | 296, sec: number, line: string, host: string, big = false): Buffer {
  const b = Buffer.alloc(width);
  if (width === 292) (big ? b.writeInt32BE(sec, 0) : b.writeInt32LE(sec, 0));
  else (big ? b.writeBigInt64BE(BigInt(sec), 0) : b.writeBigInt64LE(BigInt(sec), 0));
  const at = width === 292 ? 4 : 8;
  b.write(line, at, 32, "latin1");
  b.write(host, at + 32, 256, "latin1");
  return b;
}

const T0 = Date.UTC(2026, 1, 14, 9, 30, 0) / 1000;

test("utmp_parse refuses to choose a lastlog layout it cannot tell apart, and says which two it could not choose between", async () => {
  // 21608 = 74 * 292 = 73 * 296: both layouts divide it. A zero-filled file has nothing to decide on.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "lastlog"), Buffer.alloc(21608));
    const out = refused(await tool(UTMP, cwd, { path: "work/lastlog" }));
    assert.equal(out.ambiguous, true);
    assert.deepEqual([...out.candidates].sort(), ["lastlog-292", "lastlog-296"]);
    assert.match(out.error, /layout/);
    // Said by the caller, it is read as said, and the answer names the layout and that the caller chose it.
    const chosen = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-296" }));
    assert.equal(chosen.layout.name, "lastlog-296");
    assert.equal(chosen.layout.basis, "argument");
  });
});

test("utmp_parse lets structure decide a lastlog layout only where one layout reads every non-empty slot as text", async () => {
  await withCwd(async (cwd) => {
    // A 292-byte record for UID 2 in a 21608-byte file. Read as 296-byte slots its host field would start
    // inside the 4-byte time and run through binary bytes.
    const file = Buffer.alloc(21608);
    lastlog(292, T0, "pts/0", "203.0.113.9").copy(file, 2 * 292);
    await writeFile(join(cwd, "work", "lastlog"), file);
    const out = body(await tool(UTMP, cwd, { path: "work/lastlog" }));
    assert.equal(out.layout.name, "lastlog-292");
    assert.match(out.layout.basis, /structure/);
    const [row] = await rowsOf(cwd, out);
    assert.equal(row.uid, 2);
    assert.equal(row.host, "203.0.113.9");
    assert.equal(row.byte_offset, 584);
    assert.equal(row.epoch, T0);
    assert.equal(row.time, "2026-02-14T09:30:00Z");
  });
});

test("utmp_parse reads a 296-byte lastlog by its size and a 292-byte one the same way, with the UID slot of each record", async () => {
  await withCwd(async (cwd) => {
    const f296 = Buffer.concat([lastlog(296, 0, "", ""), lastlog(296, T0, "pts/1", "198.51.100.5"), lastlog(296, 0, "", "")]);
    const f292 = Buffer.concat([lastlog(292, 0, "", ""), lastlog(292, T0, "tty1", ""), lastlog(292, 0, "", "")]);
    await writeFile(join(cwd, "work", "lastlog"), f296);
    await mkdir(join(cwd, "work", "b"), { recursive: true });
    await writeFile(join(cwd, "work", "b", "lastlog"), f292);
    await writeFile(join(cwd, "work", "passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:1:100:Alice:/home/alice:/bin/bash\n");
    const a = body(await tool(UTMP, cwd, { path: "work/lastlog", passwd: "work/passwd" }));
    assert.equal(a.layout.name, "lastlog-296");
    assert.match(a.layout.basis, /size/);
    const rowA = (await rowsOf(cwd, a))[0];
    assert.deepEqual([rowA.uid, rowA.user, rowA.line, rowA.host, rowA.byte_offset], [1, "alice", "pts/1", "198.51.100.5", 296]);
    const b = body(await tool(UTMP, cwd, { path: "work/b/lastlog" }));
    assert.equal(b.layout.name, "lastlog-292");
    assert.equal((await rowsOf(cwd, b))[0].byte_offset, 292);
    assert.equal(b.slots_total, 3);
  });
});

test("utmp_parse does not turn a microsecond field out of range into a plausible time", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      utmp({ type: 7, pid: 10, line: "pts/0", user: "alice", sec: T0, usec: 2_000_000 }),
      utmp({ type: 7, pid: 11, line: "pts/1", user: "bob", sec: T0, usec: 250_000 }),
    ]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const rows = await rowsOf(cwd, body(await tool(UTMP, cwd, { path: "work/wtmp" })));
    assert.equal(rows[0].usec, 2_000_000, "the raw microseconds are kept");
    assert.equal(rows[0].epoch, T0, "the raw seconds are kept");
    assert.equal(rows[0].time, null, "2,000,000 is no microsecond count: no time is shown");
    assert.match(String(rows[0].time_error), /tv_usec/);
    assert.equal(rows[1].time, "2026-02-14T09:30:00.250000Z", "valid fractions are kept");
  });
});

test("utmp_parse locates each record and names the layout, the byte order and the short tail", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      utmp({ type: 2, line: "~", user: "reboot", host: "6.8.0", sec: T0 - 3600 }),
      utmp({ type: 7, pid: 1234, line: "pts/1", id: "ts/1", user: "root", host: "203.0.113.9", sec: T0, addr: [203, 0, 113, 9] }),
      Buffer.alloc(100, 0x41),
    ]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const out = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(out.layout.name, "utmp-384");
    assert.equal(out.layout.byte_order, "little");
    assert.match(out.layout.basis, /structure|argument|assum/);
    assert.equal(out.trailing_bytes, 100);
    assert.equal(out.trailing_offset, 768);
    assert.equal(out.all_records_read, false);
    const rows = await rowsOf(cwd, out);
    assert.deepEqual(rows.map((r) => [r.record_index, r.byte_offset, r.type]), [[0, 0, "BOOT_TIME"], [1, 384, "USER_PROCESS"]]);
    assert.equal(rows[1].address, "203.0.113.9");
    assert.equal(out.boots, 1);
  });
});

test("utmp_parse decides the byte order from the records' structure, and a caller can say it", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([utmp({ type: 2, user: "reboot", sec: T0 - 60 }, true), utmp({ type: 7, pid: 77, user: "root", line: "pts/2", sec: T0 }, true)]);
    await writeFile(join(cwd, "work", "wtmp"), file);
    const auto = body(await tool(UTMP, cwd, { path: "work/wtmp" }));
    assert.equal(auto.layout.byte_order, "big");
    assert.match(auto.layout.byte_order_basis, /structure/);
    assert.deepEqual((await rowsOf(cwd, auto)).map((r) => r.type), ["BOOT_TIME", "USER_PROCESS"]);
    assert.equal((await rowsOf(cwd, auto))[1].time, "2026-02-14T09:30:00Z");
    const little = body(await tool(UTMP, cwd, { path: "work/wtmp", byte_order: "little" }));
    assert.equal(little.layout.byte_order_basis, "argument");
    assert.ok((await rowsOf(cwd, little)).every((r) => r.type === "UNKNOWN"), "a type outside 0-9 is named unknown, not guessed");
    // A file of empty records cannot decide, and says so.
    await writeFile(join(cwd, "work", "empty"), Buffer.alloc(384 * 2));
    const empty = body(await tool(UTMP, cwd, { path: "work/empty" }));
    assert.equal(empty.layout.byte_order, "undetermined");
  });
});

test("utmp_parse refuses a SQLite accounting database and points at the SQLite tools", async () => {
  await withCwd(async (cwd) => {
    const header = Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(4096 - 16)]);
    await writeFile(join(cwd, "work", "wtmpdb.db"), header);
    const out = refused(await tool(UTMP, cwd, { path: "work/wtmpdb.db" }));
    assert.match(out.error, /SQLite/);
    assert.match(out.error, /sqlite_query/);
    assert.equal(out.format, "sqlite");
  });
});

test("utmp_parse finds one UID in a lastlog of three million slots, by seeking, and says what it did not read", async () => {
  // A sparse file: the slot of UID 3,000,000 holds a record and the 876 MB before it is a hole.
  await withCwd(async (cwd) => {
    const path = join(cwd, "work", "lastlog");
    const slot = lastlog(292, T0, "ssh", "203.0.113.50");
    await writeFile(path, Buffer.alloc(0));
    const { open } = await import("node:fs/promises");
    const fh = await open(path, "r+");
    await fh.write(slot, 0, slot.length, 3_000_000 * 292);
    await fh.close();
    await truncate(path, 3_000_001 * 292);
    const started = Date.now();
    const one = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", uids: [3_000_000, 5] }));
    assert.ok(Date.now() - started < 20_000);
    assert.equal(one.slots_total, 3_000_001);
    assert.equal(one.slots_read, 2);
    assert.equal(one.scope, "selected UIDs");
    const rows = await rowsOf(cwd, one);
    assert.equal(rows.length, 1);
    assert.deepEqual([rows[0].uid, rows[0].host, rows[0].byte_offset], [3_000_000, "203.0.113.50", 3_000_000 * 292]);
    // Without a selection the whole file is walked within a budget; what is left is named and can be resumed.
    const whole = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", max_seconds: 30 }));
    assert.equal((await rowsOf(cwd, whole))[0].uid, 3_000_000);
    assert.equal(whole.all_records_read, true);
    const partial = body(await tool(UTMP, cwd, { path: "work/lastlog", layout: "lastlog-292", start_uid: 1000, max_slots: 1000 }));
    assert.equal(partial.all_records_read, false);
    assert.equal(partial.next_uid, 2000);
    assert.equal(partial.slots_read, 1000);
  });
});
