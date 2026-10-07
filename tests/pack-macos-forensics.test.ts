/**
 * The macOS pack's four tools, against fixtures the test builds from the
 * formats' own layouts and never from a tool's output.
 *
 * Binary property list (plist_read): Apple's CFBinaryPList layout. "bplist00",
 * then the objects (an ASCII string is 0x5N followed by N bytes, data 0x4N, an
 * integer 0x10 or 0x11 followed by 1 or 2 big-endian bytes, an array 0xAN with
 * N one-byte object refs, a dictionary 0xDN with N key refs and N value refs),
 * then the offset table, then a 32-byte trailer: 5 unused bytes, the sort
 * version, the size of an offset, the size of an object ref, the object count,
 * the top object and the offset table's offset (the last three big-endian
 * 8-byte integers).
 *
 * FSEvents (fsevents_parse): a record file is gzip, possibly several members end
 * to end, holding pages. A page is a 12-byte header (the magic "1SLD" or "2SLD",
 * four bytes of unknown, the page length as u32 little-endian, header included)
 * and then records to the end of the page: the path as NUL-terminated UTF-8, the
 * event id (u64), the flags (u32) and, in version 2 only, the node id (u64).
 *
 * plist_read follows the secret-safe output pattern of recovery_key_scan
 * (docs/packs.md, "Secrets and sensitive output"): what it prints and writes is
 * checked here for a value, a fragment, a digest and a head, in the answer and in
 * every file the answer names.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

const MAC = join(ROOT, "packs", "macos-forensics", "tools");
const PLIST = join(MAC, "plist_read", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
}

/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory. */
async function asJob(script: string, cwd: string, args: unknown): Promise<Run> {
  await mkdir(join(cwd, "out"), { recursive: true });
  return tool(script, cwd, args, { JOB_ID: "j-1", OUT: join(cwd, "out") });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string; [key: string]: unknown } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Run a Python fixture builder; its argv follows the code. */
async function build(code: string, ...args: string[]): Promise<void> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
}

// --- plist_read -----------------------------------------------------------------

type PlistValue = string | number | Buffer | PlistValue[] | { [key: string]: PlistValue };

/** A binary property list from Apple's layout (see the header), small enough for one-byte refs. */
function bplist(root: { [key: string]: PlistValue }): Buffer {
  const objects: Buffer[] = [];
  const add = (b: Buffer): number => objects.push(b) - 1;
  const length = (marker: number, n: number): Buffer => {
    if (n < 15) return Buffer.from([marker | n]);
    return Buffer.concat([Buffer.from([marker | 0x0f]), n < 256 ? Buffer.from([0x10, n]) : Buffer.from([0x11, n >> 8, n & 0xff])]);
  };
  const put = (v: PlistValue): number => {
    if (typeof v === "string") return add(Buffer.concat([length(0x50, v.length), Buffer.from(v, "ascii")]));
    if (typeof v === "number") return add(v < 256 ? Buffer.from([0x10, v]) : Buffer.from([0x11, v >> 8, v & 0xff]));
    if (Buffer.isBuffer(v)) return add(Buffer.concat([length(0x40, v.length), v]));
    if (Array.isArray(v)) {
      const at = add(Buffer.alloc(0));
      const refs = v.map(put);
      objects[at] = Buffer.concat([length(0xa0, v.length), Buffer.from(refs)]);
      return at;
    }
    const at = add(Buffer.alloc(0));
    const keys = Object.keys(v).map((k) => put(k));
    const vals = Object.values(v).map(put);
    objects[at] = Buffer.concat([length(0xd0, keys.length), Buffer.from(keys), Buffer.from(vals)]);
    return at;
  };
  put(root);
  const header = Buffer.from("bplist00", "ascii");
  let offset = header.length;
  const offsets = objects.map((o) => {
    const at = offset;
    offset += o.length;
    return at;
  });
  const table = Buffer.concat(offsets.map((o) => Buffer.from([o >> 8, o & 0xff])));
  const trailer = Buffer.alloc(32);
  trailer[6] = 2; // bytes per offset
  trailer[7] = 1; // bytes per object ref
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(0n, 16); // the top object is the first one made
  trailer.writeBigUInt64BE(BigInt(offset), 24);
  return Buffer.concat([header, ...objects, table, trailer]);
}

// A salted-PBKDF2-shaped verifier, 64 bytes, every byte distinct so no run of it is a pattern a header or an
// ordinary word could hold. These are test bytes, not a credential of anything.
const VERIFIER = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37 + 11) % 251));
const HINT = "my first dog and a number";

function accountPlist(): Buffer {
  return bplist({
    name: "alice",
    uid: 501,
    home: "/Users/alice",
    shell: "/bin/zsh",
    authentication_authority: [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>", ";SecureToken;"],
    ShadowHashData: [VERIFIER],
    hint: HINT,
    jpegphoto: Buffer.from(Array.from({ length: 40 }, (_, i) => 200 - i)),
  });
}

type PlistRow = {
  file: string;
  parser?: string;
  status: string;
  encoding?: string;
  bytes?: number;
  extracted_file_mtime?: string;
  modified?: string;
  key?: string;
  keys?: string[];
  value?: Record<string, unknown>;
  error?: string;
  reason?: string;
  binary_values?: number;
  withheld_values?: number;
};
type PlistAnswer = {
  status: string;
  files: PlistRow[];
  file_count: number;
  found: number;
  complete_files: string | null;
  inline_limited: boolean;
  counts: { matched: number; parsed: number; failed: number; skipped_over_a_bound: number; not_attempted: number };
  first_problems?: Record<string, { file: string; why: string }[]>;
  walk: { links_not_followed: number; files_not_matched: number };
  secret_bearing: { binary_values_not_printed: number; withheld_by_key_name: number };
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
};

/** Everything that must carry no secret: the answer and each file it names. */
async function printed(cwd: string, out: Run): Promise<string> {
  let all = out.stdout;
  const answer = JSON.parse(out.stdout) as PlistAnswer;
  if (answer.complete_files) all += "\n" + (await readFile(join(cwd, answer.complete_files), "utf8"));
  return all;
}

function assertNoVerifier(text: string): void {
  const b64 = VERIFIER.toString("base64");
  for (let i = 0; i + 16 <= b64.length; i += 4) assert.ok(!text.includes(b64.slice(i, i + 16)), "a run of the verifier's base64 is in the output");
  assert.ok(!text.includes(VERIFIER.toString("hex").slice(0, 16)), "the verifier's hex is in the output");
  assert.ok(!text.includes(sha256(VERIFIER)), "the verifier's sha256 is in the output");
  assert.doesNotMatch(text, /[0-9a-f]{64}/i, "a 64-hex digest is in the output");
  assert.doesNotMatch(text, /_sha256|_base64_head/);
  assert.ok(!text.includes(HINT), "the password hint is in the output");
}

test("the fixture is a binary property list by Apple's own layout", async () => {
  await withCwd(async (cwd) => {
    const file = join(cwd, "work", "alice.plist");
    await writeFile(file, accountPlist());
    // plistlib is the reference reader of the format here, not the tool under test.
    const code = `
import json, plistlib, sys
t = plistlib.load(open(sys.argv[1], "rb"))
print(json.dumps({"uid": t["uid"], "len": len(t["ShadowHashData"][0]), "hint": t["hint"], "keys": sorted(t)}))
`;
    const out = await runPySnippet(code, [file], null);
    assert.equal(out.code, 0, out.stderr);
    const got = JSON.parse(out.stdout) as { uid: number; len: number; hint: string; keys: string[] };
    assert.equal(got.uid, 501);
    assert.equal(got.len, 64);
    assert.equal(got.hint, HINT);
  });
});

test("plist_read prints no digest, head or verifier of an account plist, and says where the withheld values are", async () => {
  // It printed the sha256 of every binary value and a base64 head, and `max_blob: 0` still printed the digest.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    for (const args of [{ path: "work/alice.plist" }, { path: "work/alice.plist", max_blob: 0 }, { path: "work/alice.plist", max_blob: 4096 }]) {
      const out = await tool(PLIST, cwd, args);
      const answer = body<PlistAnswer>(out);
      assertNoVerifier(await printed(cwd, out));
      const row = answer.files[0];
      assert.equal(row.status, "parsed");
      assert.equal(row.encoding, "binary");
      // The ordinary keys are there, in full.
      const value = row.value as Record<string, unknown>;
      assert.equal(value.name, "alice");
      assert.equal(value.uid, 501);
      assert.equal(value.home, "/Users/alice");
      assert.deepEqual(value.authentication_authority, [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>", ";SecureToken;"]);
      // The verifier and the hint are locators: kind, length, a finding id.
      const shadow = value.ShadowHashData as { _withheld: string; _kind: string; _length: number; finding_id: string };
      assert.equal(shadow._kind, "array");
      assert.equal(shadow._length, 1);
      assert.match(shadow.finding_id, /^F\d{6}$/);
      const hint = value.hint as { _kind: string; _length: number };
      assert.equal(hint._kind, "string");
      assert.equal(hint._length, HINT.length);
      // An ordinary binary value is its length and kind, not a digest or a head.
      const photo = value.jpegphoto as { _binary_bytes: number; _kind: string; finding_id: string };
      assert.equal(photo._binary_bytes, 40);
      assert.equal(photo._kind, "data");
      assert.equal(row.withheld_values, 2);
      assert.equal(answer.secret_bearing.withheld_by_key_name, 2);
      assert.equal(answer.secret_values.requested, false);
      assert.equal(answer.secret_values.values_file, null);
    }
  });
});

test("plist_read returns only the keys a selection names, and withholds a secret-bearing key even when it is selected", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    const uid = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/alice.plist", key: "uid" }));
    assert.equal(uid.files[0].key, "uid");
    assert.equal(uid.files[0].value, 501);
    assert.equal(uid.files[0].keys, undefined, "a selection lists no other key");
    for (const key of ["ShadowHashData", "ShadowHashData.0", "hint"]) {
      const out = await tool(PLIST, cwd, { path: "work/alice.plist", key });
      const answer = body<PlistAnswer>(out);
      assertNoVerifier(out.stdout);
      const value = answer.files[0].value as { _withheld?: string; finding_id?: string };
      assert.ok(value._withheld, `${key} was printed`);
      assert.match(value.finding_id ?? "", /^F\d{6}$/);
    }
  });
});

test("plist_read writes values only on write_values, only in a job, only to a private file under $OUT", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    // Outside a job the request is refused and nothing is written.
    const outside = refused(await tool(PLIST, cwd, { path: "work/alice.plist", write_values: true }));
    assert.match(outside.error, /refused outside a job/);
    assert.deepEqual(await readdir(join(cwd, "work")), ["alice.plist"]);

    const run = await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true });
    const answer = body<PlistAnswer>(run);
    assertNoVerifier(await printed(cwd, run));
    assert.equal(answer.secret_values.requested, true);
    assert.equal(answer.secret_values.written, 3, "the verifier, the hint and the photo");
    assert.equal(answer.secret_values.contains_secret_values, true);
    assert.equal(answer.secret_values.values_file, "store/jobs/j-1/out/plist-values.jsonl");
    const file = join(cwd, "out", "plist-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; file: string; key_path: string; kind: string; length: number; value: unknown });
    const byPath = Object.fromEntries(rows.map((r) => [r.key_path, r]));
    assert.deepEqual(Object.keys(byPath).sort(), ["ShadowHashData", "hint", "jpegphoto"]);
    assert.equal(byPath.hint.value, HINT);
    assert.equal(byPath.hint.file, "work/alice.plist");
    const shadow = byPath.ShadowHashData.value as [{ _base64: string; _bytes: number; _truncated: boolean }];
    assert.equal(shadow[0]._base64, VERIFIER.toString("base64"));
    assert.equal(shadow[0]._bytes, 64);
    assert.equal(shadow[0]._truncated, false);
    // The ids in the answer are the ids in the file.
    const row = answer.files[0].value as Record<string, { finding_id: string }>;
    assert.equal(byPath.ShadowHashData.finding_id, row.ShadowHashData.finding_id);
    assert.equal(byPath.jpegphoto.finding_id, row.jpegphoto.finding_id);

    // A file already at that name is refused by name, before anything is read, and not touched.
    await writeFile(join(cwd, "out", "plist-values.jsonl"), "keep\n");
    const again = refused(await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true }));
    assert.match(again.error, /values file already exists/);
    assert.equal(await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8"), "keep\n");
  });
});

test("plist_read bounds a value written to the values file and says how much it left", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "alice.plist"), accountPlist());
    await asJob(PLIST, cwd, { path: "work/alice.plist", write_values: true, max_blob: 16 }).then((r) => body<PlistAnswer>(r));
    const rows = (await readFile(join(cwd, "out", "plist-values.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { key_path: string; value: unknown });
    const shadow = (rows.find((r) => r.key_path === "ShadowHashData")?.value as [{ _base64: string; _bytes: number; _bytes_written: number; _truncated: boolean }])[0];
    assert.equal(shadow._bytes, 64);
    assert.equal(shadow._bytes_written, 16);
    assert.equal(shadow._truncated, true);
    assert.equal(shadow._base64, VERIFIER.subarray(0, 16).toString("base64"));
  });
});

test("plist_read labels the file time as the extracted copy's and does not overwrite an out_file", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.plist"), bplist({ name: "x" }));
    const answer = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/a.plist" }));
    assert.match(answer.files[0].extracted_file_mtime ?? "", /^\d{4}-\d\d-\d\dT.*Z$/);
    assert.equal(answer.files[0].modified, undefined);
    assert.equal(answer.files[0].parser, "plist_read/3");

    await writeFile(join(cwd, "work", "keep.jsonl"), "precious\n");
    const clash = refused(await tool(PLIST, cwd, { path: "work/a.plist", out_file: "work/keep.jsonl" }));
    assert.match(clash.error, /already exists/);
    assert.equal(await readFile(join(cwd, "work", "keep.jsonl"), "utf8"), "precious\n");
    // A dangling link at the name is refused too, and nothing is written through it.
    await symlink("not-there.jsonl", join(cwd, "work", "dangling.jsonl"));
    refused(await tool(PLIST, cwd, { path: "work/a.plist", out_file: "work/dangling.jsonl" }));
    assert.equal(await exists(join(cwd, "work", "not-there.jsonl")), false);
  });
});

test("plist_read keeps going past a file it cannot read, one it will not read, a link and a tree too deep, and says each", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "plists");
    await mkdir(join(dir, "sub"), { recursive: true });
    await writeFile(join(dir, "a-good.plist"), bplist({ name: "good", n: 1 }));
    await writeFile(join(dir, "b-corrupt.plist"), Buffer.concat([Buffer.from("bplist00"), Buffer.alloc(40, 0xff)]));
    // A plist nested 5000 arrays deep: the converter recursed on it until Python gave up, and took the sweep with it.
    const deep = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">${"<array>".repeat(5000)}${"</array>".repeat(5000)}</plist>`;
    await writeFile(join(dir, "c-deep.plist"), deep);
    await writeFile(join(dir, "d-big.plist"), Buffer.alloc(250_000));
    await writeFile(join(dir, "sub", "e-also-good.btm"), bplist({ name: "also" }));
    await writeFile(join(dir, "notes.txt"), "not a plist");
    await writeFile(join(cwd, "work", "outside.plist"), bplist({ name: "outside" }));
    await symlink(join(cwd, "work", "outside.plist"), join(dir, "f-link.plist"));
    const out = await tool(PLIST, cwd, { path: "work/plists", max_file_bytes: 200_000, out_file: "work/all.jsonl" });
    const answer = body<PlistAnswer>(out);
    assert.equal(answer.status, "partial");
    assert.deepEqual(answer.counts, { matched: 5, parsed: 2, failed: 1, skipped_over_a_bound: 2, not_attempted: 0 });
    const byFile = Object.fromEntries(answer.files.map((r) => [r.file.split("/").pop(), r]));
    assert.equal(byFile["a-good.plist"].status, "parsed");
    assert.equal(byFile["b-corrupt.plist"].status, "failed");
    assert.match(byFile["b-corrupt.plist"].error ?? "", /\w/);
    assert.equal(byFile["c-deep.plist"].status, "skipped");
    assert.match(byFile["c-deep.plist"].reason ?? "", /max_depth/);
    assert.equal(byFile["d-big.plist"].status, "skipped");
    assert.match(byFile["d-big.plist"].reason ?? "", /max_file_bytes/);
    assert.equal(byFile["e-also-good.btm"].status, "parsed");
    assert.equal(byFile["f-link.plist"], undefined, "a link is not followed");
    assert.equal(answer.walk.links_not_followed, 1);
    assert.equal(answer.walk.files_not_matched, 1);
    assert.ok(answer.first_problems?.failed?.[0]?.file.endsWith("b-corrupt.plist"));
    // Every row is in the file as it was made, in path order.
    const rows = (await readFile(join(cwd, "work", "all.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as PlistRow);
    assert.equal(rows.length, answer.file_count);
    assert.deepEqual(rows.map((r) => r.file.split("/").pop()), ["a-good.plist", "b-corrupt.plist", "c-deep.plist", "d-big.plist", "e-also-good.btm"]);
  });
});

test("plist_read refuses over a node budget, names it, and still reads a selected part of that file", async () => {
  await withCwd(async (cwd) => {
    await build(
      `
import plistlib, sys
plistlib.dump({"small": {"a": 1}, "wide": list(range(5000))}, open(sys.argv[1], "wb"), fmt=plistlib.FMT_BINARY)
`,
      join(cwd, "work", "wide.plist"),
    );
    // Nothing parsed: the answer is whole, and the exit says so.
    const run = await tool(PLIST, cwd, { path: "work/wide.plist", max_nodes: 100 });
    assert.equal(run.code, 1);
    assert.doesNotMatch(run.stderr, /Traceback/);
    const whole = JSON.parse(run.stdout) as PlistAnswer;
    assert.equal(whole.status, "failed");
    assert.equal(whole.files[0].status, "skipped");
    assert.match(whole.files[0].reason ?? "", /max_nodes \(100\)/);
    const part = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/wide.plist", key: "small", max_nodes: 100 }));
    assert.equal(part.status, "complete");
    assert.deepEqual(part.files[0].value, { a: 1 });
  });
});

test("plist_read writes each file's row as it goes and stops at max_seconds with the rest counted, not dropped", async () => {
  // It parsed every file into memory before writing any, so an interrupted sweep left nothing.
  await withCwd(async (cwd) => {
    await build(
      `
import os, plistlib, sys
d = sys.argv[1]
os.makedirs(d)
for i in range(300):
    plistlib.dump({"n": i, "items": list(range(8000))}, open(os.path.join(d, "p%04d.plist" % i), "wb"), fmt=plistlib.FMT_BINARY)
`,
      join(cwd, "work", "many"),
    );
    const out = await tool(PLIST, cwd, { path: "work/many", max_seconds: 0.25, out_file: "work/many.jsonl", max_nodes: 100000 });
    const answer = body<PlistAnswer>(out);
    assert.equal(answer.status, "partial");
    assert.ok(answer.counts.parsed > 0 && answer.counts.parsed < 300, JSON.stringify(answer.counts));
    assert.equal(answer.counts.parsed + answer.counts.not_attempted, 300);
    assert.equal(answer.found, 300);
    assert.match(answer.first_problems?.not_attempted?.[0]?.why ?? "", /max_seconds/);
    const rows = (await readFile(join(cwd, "work", "many.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, answer.counts.parsed, "each parsed file is in the output file");
  });
});

test("plist_read pages a directory sweep losslessly when no out_file is named", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work", "p"), { recursive: true });
    for (let i = 0; i < 7; i++) await writeFile(join(cwd, "work", "p", `f${i}.plist`), bplist({ n: i }));
    const answer = body<PlistAnswer>(await tool(PLIST, cwd, { path: "work/p", limit: 3 }));
    assert.equal(answer.files.length, 3);
    assert.equal(answer.file_count, 7);
    assert.equal(answer.inline_limited, true);
    assert.match(answer.complete_files ?? "", /^work\/s1\/tool-output\/plist_read-.*\.jsonl$/);
    const rows = (await readFile(join(cwd, answer.complete_files as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as PlistRow);
    assert.deepEqual(rows.map((r) => (r.value as { n: number }).n), [0, 1, 2, 3, 4, 5, 6]);
  });
});

