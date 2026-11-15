/**
 * registry_recover's counts held to a second reader (IMPROVEMENT-PLAN-2 E11: "the value counts within 1% of a second reader's").
 * The tool compares its own counts with regfexport's when that program is in the image, and its tests held it to counts the
 * fixture declared. Here the second reader is independent of both the tool and the fixture's builder: a walk of the hive written
 * in this file from the format's layout (the base block's root cell, each key's subkey list as li, lf, lh or ri, each key's value
 * list), sharing no code with the tool, regipy or tests/windows-hive.ts. The hive is built by tests/windows-hive.ts, large enough
 * that a 1% difference is many keys: thousands of keys and values of every type the builder writes, a key with more subkeys than
 * one leaf list holds (an ri index over leaves), names compressed and in UTF-16. And the tool's stdout on that hive stays under
 * 1 MiB.
 */
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, body, tool } from "./windows-pack-harness.ts";
import { hive, type HiveKey } from "./windows-hive.ts";

/** The keys and the values a hive's tree holds, walked from its base block: each key and each value record counted once. */
export function secondCount(buf: Buffer): { keys: number; values: number } {
  const BINS = 0x1000;
  const data = (offset: number) => BINS + offset + 4;
  const sig = (offset: number) => buf.toString("latin1", data(offset), data(offset) + 2);
  const inside = (offset: number) => offset !== 0xffffffff && data(offset) + 4 <= buf.length;
  const keys = new Set<number>();
  const values = new Set<number>();
  const subkeysOf = (list: number, depth = 0): number[] => {
    if (!inside(list) || depth > 2) return [];
    const at = data(list);
    const n = buf.readUInt16LE(at + 2);
    const s = sig(list);
    const out: number[] = [];
    for (let i = 0; i < n; i++) {
      if (s === "li" || s === "ri") {
        const o = buf.readUInt32LE(at + 4 + 4 * i);
        if (s === "li") out.push(o);
        else out.push(...subkeysOf(o, depth + 1));
      } else if (s === "lf" || s === "lh") out.push(buf.readUInt32LE(at + 4 + 8 * i));
    }
    return out;
  };
  const stack = [buf.readUInt32LE(0x24)];
  while (stack.length) {
    const key = stack.pop()!;
    if (keys.has(key) || !inside(key) || sig(key) !== "nk") continue;
    keys.add(key);
    const at = data(key);
    if (buf.readUInt32LE(at + 0x14)) stack.push(...subkeysOf(buf.readUInt32LE(at + 0x1c)));
    const n = buf.readUInt32LE(at + 0x24);
    const list = buf.readUInt32LE(at + 0x28);
    if (n && inside(list)) for (let i = 0; i < n; i++) {
      const v = buf.readUInt32LE(data(list) + 4 * i);
      if (inside(v) && sig(v) === "vk") values.add(v);
    }
  }
  return { keys: keys.size, values: values.size };
}

/** A hive of a software key's shape: 40 vendors of 60 products, each with values of every type; one key with 70,000 subkeys (an ri index). */
function largeHive(): Buffer {
  const vendors: HiveKey[] = [];
  for (let v = 0; v < 40; v++) {
    const products: HiveKey[] = [];
    for (let p = 0; p < 60; p++) {
      products.push({
        name: p % 7 === 0 ? `Prodüct ${p} ✓` : `Product${p}`,
        values: [
          { name: "DisplayName", type: "sz", value: `Product ${p} of vendor ${v}` },
          { name: "Version", type: "dword", value: p * 7 + v },
          { name: "InstallDate", type: "qword", value: 133_443_104_000_000_000n + BigInt(p) },
          { name: "Blob", type: "binary", value: Buffer.alloc(300 + p, v) },
          { name: "Paths", type: "multi_sz", value: [`C:\\vendor${v}`, `D:\\p${p}`] },
          { name: "Expand", type: "expand_sz", value: "%SystemRoot%\\system32" },
        ],
      });
    }
    vendors.push({ name: `Vendor${v}`, values: [{ name: "", type: "sz", value: `default of ${v}` }], children: products });
  }
  const wide: HiveKey = { name: "Wide", children: Array.from({ length: 70_000 }, (_, i) => ({ name: `k${i}` })) };
  return hive({ name: "ROOT", values: [{ name: "Top", type: "sz", value: "root value" }], children: [{ name: "Software", children: [...vendors, wide] }] });
}

const within = (got: number, second: number) => Math.abs(got - second) <= Math.max(1, second * 0.01);

test("the second reader counts a small hive as its builder made it", () => {
  const small = hive({ name: "ROOT", values: [{ name: "a", type: "sz", value: "x" }], children: [{ name: "One", values: [{ name: "b", type: "dword", value: 1 }, { name: "c", type: "binary", value: Buffer.alloc(40) }] }, { name: "Two" }] });
  assert.deepEqual(secondCount(small), { keys: 3, values: 3 });
});

test("registry_recover's key and value counts are within 1% of a second reader's on a hive of 72,443 keys, and its stdout stays under 1 MiB", { skip: REGIPY, timeout: 600_000 }, async (t) => {
  const h = largeHive();
  const second = secondCount(h);
  assert.deepEqual(second, { keys: 1 + 1 + 40 + 40 * 60 + 1 + 70_000, values: 1 + 40 + 40 * 60 * 6 });
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "software.dat"), h);
    const run = await tool("registry_recover", cwd, { hive: "work/software.dat", limit: 5, export: true, max_seconds: 110 }, {}, bin);
    const stdoutBytes = Buffer.byteLength(run.stdout);
    const out = body<{ status: string; records: { keys: number; values: number; status?: string } }>(run);
    t.diagnostic(`second reader: ${second.keys} keys, ${second.values} values; registry_recover: ${out.records.keys} keys, ${out.records.values} values (${out.records.status ?? out.status}); stdout ${stdoutBytes} bytes`);
    assert.ok(stdoutBytes < 1 << 20, `stdout is ${stdoutBytes} bytes`);
    assert.ok(within(out.records.keys, second.keys), `${out.records.keys} keys, the second reader ${second.keys}`);
    assert.ok(within(out.records.values, second.values), `${out.records.values} values, the second reader ${second.values}`);
  });
});
