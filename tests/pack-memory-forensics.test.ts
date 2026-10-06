/**
 * The memory-forensics pack's three tools, against fixtures the test builds
 * from the formats' own layouts and never from a tool's output.
 *
 * Plain Prefetch (mem_carve): a four-byte version at offset 0, then "SCCA" at 4,
 * the file size at 0x0C, the executable name as UTF-16LE from 0x10 (libscca's
 * format notes, and what prefetch_mam of the windows-forensics pack reads:
 * `data[4:8] == b"SCCA"`).
 *
 * Windows crash dump (mem_profile): DUMP_HEADER64, "PAGE" "DU64", a physical
 * memory descriptor at 0x88 (NumberOfRuns, padding, NumberOfPages, then runs of
 * BasePage and PageCount), the dump type at 0xF98. LiME: a 32-byte header of
 * the magic "EMiL", a version, the start and the inclusive end of the physical
 * range it frames, and 8 reserved bytes, followed by the range's bytes. ELF:
 * e_ident[EI_DATA] at byte 5 says the byte order of every later field.
 *
 * mem_fs: MemProcFS needs FUSE, which a test host may not have. A stub
 * `memprocfs` on PATH makes the directory a mount would have made, and a
 * `sitecustomize` module on PYTHONPATH makes `os.path.ismount` say so for a
 * directory with a `sys/` in it, the way the kernel's mount table does for a
 * real one. The stub removes its tree when it is terminated, as an unmount does.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";

const MEM = join(ROOT, "packs", "memory-forensics", "tools");
const WIN = join(ROOT, "packs", "windows-forensics", "tools");
const CARVE = join(MEM, "mem_carve", "run.py");
const PROFILE = join(MEM, "mem_profile", "run.py");
const FS = join(MEM, "mem_fs", "run.py");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(script, cwd, args, bin, { ...AGENT, ...env });
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

// --- mem_carve ------------------------------------------------------------------

type Hit = {
  kind: string;
  signature_offset: number;
  object_offset: number | null;
  page_aligned: boolean;
  validation: string;
  declared_bytes?: number;
  requested_bytes: number;
  available_bytes: number;
  extracted_to?: string;
  extracted_bytes?: number;
  extract_status?: string;
  sha256?: string;
};
type Carve = {
  hits: Hit[];
  hit_count: number;
  by_kind: Record<string, number>;
  extracted: number;
  extraction?: { max_extract: number; extracted: number; not_extracted: number; refused: number; failed: number };
  preview_limited: boolean;
  truncated?: boolean;
  complete_results?: string;
  coverage: { start: number; end: number; bytes_read: number; file_bytes: number; ended: string; address_space: string };
  problems: { offset: number; kind: string; problem: string }[];
};

/** A plain Prefetch file as libscca describes it: version, "SCCA", ..., file size, name. */
function plainPrefetch(version: number, name: string, runCount: number, lastRun: bigint): Buffer {
  const file = Buffer.alloc(0x130);
  file.writeUInt32LE(version, 0);
  file.write("SCCA", 4, "latin1");
  file.writeUInt32LE(0x0f, 8);
  file.writeUInt32LE(file.length, 0x0c);
  file.write(name, 0x10, "utf16le");
  file.writeUInt32LE(0xdeadbeef, 0x4c);
  file.writeBigUInt64LE(lastRun, 0x80);
  file.writeUInt32LE(runCount, 0xd0);
  return file;
}

/** The registry hive's base block fields the tool reads: "regf", major 1 at 0x14, minor at 0x18. */
function hiveBaseBlock(minor: number): Buffer {
  const block = Buffer.alloc(4096);
  block.write("regf", 0, "latin1");
  block.writeUInt32LE(1, 0x14);
  block.writeUInt32LE(minor, 0x18);
  return block;
}

test("mem_carve cuts a plain Prefetch record from its version field, which prefetch_mam needs", async () => {
  // The record's SCCA signature is at bytes 4-7. Cutting at the signature drops
  // the version field, and prefetch_mam's `data[4:8] == b"SCCA"` then fails on
  // every plain record the carve hands over.
  await withCwd(async (cwd) => {
    const FILETIME = 133_000_000_000_000_000n;
    const pf = plainPrefetch(30, "CALC.EXE", 7, FILETIME);
    const blob = Buffer.alloc(0x6000);
    pf.copy(blob, 0x3000);
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<Carve>(
      await tool(CARVE, cwd, { path: "work/memory.raw", kinds: ["prefetch record"], extract_to: "work/s1/carved" }),
    );
    assert.equal(out.hit_count, 1);
    const hit = out.hits[0];
    assert.equal(hit.signature_offset, 0x3004);
    assert.equal(hit.object_offset, 0x3000);
    assert.equal(hit.page_aligned, true, "the structure starts on a page boundary");
    assert.equal(hit.validation, "header plausible");
    assert.equal(hit.declared_bytes, 0x130);
    const cut = await readFile(hit.extracted_to as string);
    assert.deepEqual(cut.subarray(0, 8), pf.subarray(0, 8), "the extract begins with the version field and the signature");
    assert.deepEqual(cut.subarray(0, pf.length), pf);
    assert.equal(hit.sha256, sha256(cut));

    // The Windows pack's own Prefetch parser accepts it. (Its decompression
    // library is a stub: a plain record is never decompressed.)
    const stub = join(cwd, "pystub");
    await mkdir(join(stub, "dissect", "util", "compression"), { recursive: true });
    for (const init of ["dissect/__init__.py", "dissect/util/__init__.py", "dissect/util/compression/__init__.py"]) {
      await writeFile(join(stub, init), "", "utf8");
    }
    await writeFile(join(stub, "dissect", "util", "compression", "lzxpress_huffman.py"), "def decompress(data):\n    raise SystemExit('stub')\n", "utf8");
    const parsed = body<{ version: number; exe_name: string; run_count: number; compressed: boolean }>(
      await tool(join(WIN, "prefetch_mam", "run.py"), cwd, { path: hit.extracted_to as string }, { PYTHONPATH: stub }),
    );
    assert.equal(parsed.version, 30);
    assert.equal(parsed.exe_name, "CALC.EXE");
    assert.equal(parsed.run_count, 7);
    assert.equal(parsed.compressed, false);
  });
});

test("mem_carve does not claim a structure start for a Prefetch signature with no known version before it", async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(0x3000);
    blob.write("SCCA", 0x1004, "latin1"); // four bytes of zeros before it: not a Prefetch version
    blob.write("SCCA", 2, "latin1"); // too close to the start for a version field to precede it
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw", kinds: ["prefetch record"] }));
    assert.deepEqual(out.hits.map((h) => [h.signature_offset, h.object_offset, h.validation]), [
      [2, null, "unknown"],
      [0x1004, null, "unknown"],
    ]);
  });
});

test("mem_carve extracts the earliest candidates when max_extract is smaller than the hit count", async () => {
  // The extraction walked the signature table, so a hive at 0x1000 took the one
  // extract before a PE header at 0x200 that the sweep met first.
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(0x4000);
    hiveBaseBlock(5).copy(blob, 0x1000);
    blob.write("MZ\x90\x00\x03", 0x200, "latin1");
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<Carve>(
      await tool(CARVE, cwd, { path: "work/memory.raw", extract_to: "work/s1/carved", max_extract: 1 }),
    );
    assert.deepEqual(out.hits.map((h) => [h.kind, h.signature_offset]), [["PE header", 0x200], ["registry hive", 0x1000]]);
    assert.equal(out.hits[0].extracted_bytes, 0x4000 - 0x200);
    assert.equal(out.hits[1].extracted_to, undefined);
    assert.equal(out.extracted, 1);
    assert.deepEqual(out.extraction, { max_extract: 1, extracted: 1, not_extracted: 1, refused: 0, failed: 0 });
  });
});

test("mem_carve keeps a bounded preview and every hit in a file, by default, for a dense image", async () => {
  // 100,000 hits at 16-byte spacing. results_to without limit used to keep every
  // hit in the answer and in memory.
  await withCwd(async (cwd) => {
    const COUNT = 100_000;
    const blob = Buffer.alloc(COUNT * 16);
    for (let i = 0; i < COUNT; i++) blob.write("regf", i * 16, "latin1");
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw", results_to: "work/s1/hits.jsonl" }));
    assert.equal(out.hit_count, COUNT);
    assert.ok(out.hits.length <= 200, "the preview is bounded (%d)".replace("%d", String(out.hits.length)));
    assert.equal(out.preview_limited, true);
    const rows = (await readFile(join(cwd, "work", "s1", "hits.jsonl"), "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, COUNT);
    const offsets = rows.map((row) => (JSON.parse(row) as Hit).signature_offset);
    assert.ok(offsets.every((o, i) => o === i * 16), "every hit, in offset order");

    // With neither results_to nor limit the whole is kept all the same, and named.
    const implicit = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw" }));
    assert.equal(implicit.hit_count, COUNT);
    assert.ok(implicit.hits.length <= 200);
    assert.equal(implicit.truncated, true);
    assert.match(implicit.complete_results as string, /^work\/s1\/tool-output\/mem_carve-[0-9a-f]+\.jsonl$/);
    const whole = (await readFile(join(cwd, implicit.complete_results as string), "utf8")).trimEnd().split("\n");
    assert.equal(whole.length, COUNT);
  });
});

test("mem_carve refuses to write through a link or over a file in the extract directory, and says so", async () => {
  await withCwd(async (cwd) => {
    const blob = Buffer.alloc(0x2000);
    hiveBaseBlock(5).copy(blob, 0x1000);
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    await mkdir(join(cwd, "work", "s1", "carved"), { recursive: true });
    await writeFile(join(cwd, "work", "s1", "victim.txt"), "do not touch");
    const name = "000000001000-registry_hive.bin";
    await symlink(join(cwd, "work", "s1", "victim.txt"), join(cwd, "work", "s1", "carved", name));
    const out = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw", extract_to: "work/s1/carved" }));
    assert.equal(await readFile(join(cwd, "work", "s1", "victim.txt"), "utf8"), "do not touch");
    assert.equal(out.hit_count, 1);
    assert.equal(out.hits[0].extracted_to, undefined);
    assert.match(out.hits[0].extract_status as string, /^refused: /);
    assert.equal(out.extraction?.refused, 1);
    assert.equal(out.extraction?.extracted, 0);
    assert.equal(out.problems.length, 1);

    // A second run into a directory that already holds the first one's extract refuses it too.
    await mkdir(join(cwd, "work", "s1", "again"), { recursive: true });
    await writeFile(join(cwd, "work", "s1", "again", name), "an earlier extract");
    const second = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw", extract_to: "work/s1/again" }));
    assert.equal(second.extraction?.refused, 1);
    assert.equal(await readFile(join(cwd, "work", "s1", "again", name), "utf8"), "an earlier extract");
  });
});

test("mem_carve says whether each header is plausible, truncated or only a signature, with the lengths", async () => {
  await withCwd(async (cwd) => {
    const SIZE = 0x20000;
    const blob = Buffer.alloc(SIZE);
    hiveBaseBlock(5).copy(blob, 0x0000); // minor version 5: plausible
    hiveBaseBlock(99).copy(blob, 0x1000); // minor version 99: not a registry hive version
    blob.write("ElfChnk\u0000", 0x2000, "latin1");
    blob.writeUInt32LE(128, 0x2000 + 0x28); // EVTX chunk header size
    blob.write("bplist00", 0x13000, "latin1"); // no structural check: a signature only
    blob.write("regf", SIZE - 8, "latin1"); // eight bytes before the end of the file
    blob.write("ElfChnk\u0000", SIZE - 0x3000, "latin1"); // a chunk is 64 KiB; 12 KiB are left
    blob.writeUInt32LE(128, SIZE - 0x3000 + 0x28);
    await writeFile(join(cwd, "work", "memory.raw"), blob);
    const out = body<Carve>(await tool(CARVE, cwd, { path: "work/memory.raw" }));
    const byOffset = Object.fromEntries(out.hits.map((h) => [h.signature_offset, h]));
    assert.equal(byOffset[0].validation, "header plausible");
    assert.equal(byOffset[0x1000].validation, "header implausible");
    assert.equal(byOffset[0x2000].validation, "header plausible");
    assert.equal(byOffset[0x2000].declared_bytes, 65536);
    assert.equal(byOffset[0x13000].validation, "unknown");
    assert.equal(byOffset[SIZE - 8].validation, "truncated");
    assert.equal(byOffset[SIZE - 8].requested_bytes, 1 << 20);
    assert.equal(byOffset[SIZE - 8].available_bytes, 8);
    assert.equal(byOffset[SIZE - 0x3000].validation, "truncated", "the header declares more than the file holds");
    assert.equal(byOffset[SIZE - 0x3000].declared_bytes, 65536);
    assert.equal(byOffset[SIZE - 0x3000].available_bytes, 0x3000);
    assert.equal(out.coverage.ended, "end of range");
    assert.equal(out.coverage.bytes_read, SIZE);
    assert.equal(out.coverage.start, 0);
    assert.equal(out.coverage.end, SIZE);
  });
});

// --- mem_fs ---------------------------------------------------------------------

const SECRET_TOKEN = "Planted-Token-4f9aQ2-do-not-print";

/** What a stub MemProcFS serves: a process list, an environment block with a secret in it, and a binary memory region. */
function regionBytes(): Buffer {
  // 3 MiB and a bit, so the copy crosses its read size: every byte value, NULs and sequences that are not UTF-8,
  // and the planted token in the middle.
  const region = Buffer.alloc(3 * MIB + 77);
  for (let i = 0; i < region.length; i++) region[i] = (i * 131 + 7) & 0xff;
  region.write(SECRET_TOKEN, MIB + 5, "latin1");
  region[0] = 0xff; // never valid UTF-8
  return region;
}

const PROC_TEXT = "  PID  PPID  Name\n    4     0  System\n 1234   600  notepad.exe\n";
const ENV_TEXT = `COMPUTERNAME=HOST1\nAPI_TOKEN=${SECRET_TOKEN}\n`;

async function memfsStub(cwd: string, bin: string, mode = ""): Promise<Record<string, string>> {
  const tree = join(cwd, "stubtree");
  await mkdir(join(tree, "sys", "proc"), { recursive: true });
  await mkdir(join(tree, "name", "1234-notepad.exe", "minidump"), { recursive: true });
  await writeFile(join(tree, "sys", "proc", "proc.txt"), PROC_TEXT);
  await writeFile(join(tree, "name", "1234-notepad.exe", "environment.txt"), ENV_TEXT);
  await writeFile(join(tree, "name", "1234-notepad.exe", "minidump", "memory.dmp"), regionBytes());
  await writeFile(join(tree, "name", "1234-notepad.exe", "a b.txt"), "with a space\n");
  await writeFile(join(tree, "name", "1234-notepad.exe", "a_b.txt"), "with an underscore\n");
  const log = join(cwd, "stub-started.log");
  await writeFile(
    join(bin, "memprocfs"),
    `#!/usr/bin/env python3
import os, shutil, signal, sys, time
args = sys.argv[1:]
mount = args[args.index("-mount") + 1]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write("started " + " ".join(args) + "\\n")
print("stub memprocfs: initialising " + args[args.index("-device") + 1])
print("stub memprocfs: warning: slow device", file=sys.stderr, flush=True)
sys.stdout.flush()
if os.environ.get("STUB_MODE") == "exit":
    print("FUSE is not available: /dev/fuse is missing", file=sys.stderr)
    sys.exit(3)
def clear():
    for name in os.listdir(mount):
        p = os.path.join(mount, name)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
def bye(*_):
    clear()
    sys.exit(0)
signal.signal(signal.SIGTERM, bye)
if os.environ.get("STUB_MODE") != "never":
    tree = os.environ["STUB_TREE"]
    for name in sorted(os.listdir(tree), key=lambda n: n == "sys"):  # sys/ last: a mount shows it when it is up
        src, dst = os.path.join(tree, name), os.path.join(mount, name)
        shutil.copytree(src, dst) if os.path.isdir(src) else shutil.copy(src, dst)
while True:
    time.sleep(0.05)
`,
  );
  await chmod(join(bin, "memprocfs"), 0o755);
  // os.path.ismount says yes for a directory with a sys/ in it, the way the kernel's mount table does for a real mount.
  const shim = join(cwd, "mountshim");
  await mkdir(shim, { recursive: true });
  await writeFile(join(shim, "sitecustomize.py"), "import os, os.path\nos.path.ismount = lambda p: os.path.isdir(os.path.join(p, 'sys'))\n");
  return { PYTHONPATH: shim, STUB_TREE: tree, STUB_LOG: log, STUB_MODE: mode };
}

async function jobDir(cwd: string, id = "j000042"): Promise<{ out: string; job: Record<string, string> }> {
  const out = join(cwd, ".jobs", id);
  await mkdir(out, { recursive: true });
  return { out, job: { JOB_ID: id, OUT: out } };
}

type FsAnswer = {
  mode: string;
  mount: string;
  items?: { item_id: string; virtual_path: string; output?: string; bytes?: number; status: string }[];
  entries?: { name: string; directory: boolean; size?: number }[];
  entry_count?: number;
  counts?: Record<string, number>;
  complete?: boolean;
  logs: { stdout: string; stderr: string; stdout_bytes: number; stderr_bytes: number };
  secret_values?: { requested: boolean; written: number; values_dir: string | null; manifest: string | null; contains_secret_values: boolean };
  prerequisites?: Record<string, unknown>;
  phases?: Record<string, number>;
  content?: unknown;
};

test("mem_fs export writes the bytes of a virtual file exactly, in a job, and keeps no value in its answer", async () => {
  // A region came back as replacement-decoded text, and the mount was gone before
  // anything could read it. export copies the bytes, with their digest in a sealed
  // file beside them, and the answer says where they are, not what they are.
  await withCwd(async (cwd, bin) => {
    const env = await memfsStub(cwd, bin);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const { out, job } = await jobDir(cwd);
    const run = await tool(
      FS, cwd,
      {
        path: "inputs/memory.raw", mount: join(out, "mem"), mode: "export", write_values: true, timeout_seconds: 30,
        paths: ["name/1234-notepad.exe/minidump/memory.dmp", "name/1234-notepad.exe/environment.txt", "sys/proc/proc.txt"],
      },
      { ...env, ...job },
      bin,
    );
    const answer = body<FsAnswer>(run);
    assert.equal(answer.mode, "export");
    assert.deepEqual(answer.counts, { requested: 3, exported: 3, failed: 0, refused: 0, not_exported: 0, partial: 0, not_attempted: 0 });
    assert.equal(answer.complete, true);

    // Byte for byte, in $OUT, private.
    const region = regionBytes();
    const copy = await readFile(join(out, "mem_fs", "name", "1234-notepad.exe", "minidump", "memory.dmp"));
    assert.ok(copy.equals(region), "the exported bytes differ from the file's");
    assert.equal((await stat(join(out, "mem_fs", "name", "1234-notepad.exe", "minidump", "memory.dmp"))).mode & 0o777, 0o600);
    assert.equal(await readFile(join(out, "mem_fs", "sys", "proc", "proc.txt"), "utf8"), PROC_TEXT);

    // The digests are in the sealed manifest, computed here independently, and not in the answer.
    const rows = (await readFile(join(out, "mem_fs", "export-manifest.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(rows.length, 3);
    const byPath = Object.fromEntries(rows.map((r) => [r.virtual_path as string, r]));
    assert.equal(byPath["name/1234-notepad.exe/minidump/memory.dmp"].sha256, sha256(region));
    assert.equal(byPath["name/1234-notepad.exe/minidump/memory.dmp"].bytes, region.length);
    assert.equal(byPath["sys/proc/proc.txt"].sha256, sha256(PROC_TEXT));
    assert.doesNotMatch(run.stdout, /[0-9a-f]{64}/i, "a digest is in the answer");
    assert.ok(!run.stdout.includes(SECRET_TOKEN), "a planted secret is in the answer");
    assert.equal(answer.content, undefined);
    assert.equal(answer.secret_values?.contains_secret_values, true);
    assert.match(answer.secret_values?.values_dir as string, /^store\/jobs\/j000042\/out\/mem_fs$/);

    // The engine's own output is kept on success, and named.
    assert.match(await readFile(join(out, answer.logs.stdout.split("/").pop() as string), "utf8"), /stub memprocfs: initialising/);
    assert.match(await readFile(join(out, answer.logs.stderr.split("/").pop() as string), "utf8"), /warning: slow device/);
    assert.ok(answer.logs.stdout_bytes > 0 && answer.logs.stderr_bytes > 0);

    // And the mount is gone.
    assert.deepEqual(await readdir(join(out, "mem")), []);
  });
});

test("mem_fs text writes a text file to the job's output and refuses a binary one, rather than decoding it with replacements", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await memfsStub(cwd, bin);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const { out, job } = await jobDir(cwd);
    const base = { path: "inputs/memory.raw", mount: join(out, "mem"), mode: "text", write_values: true, timeout_seconds: 30 };

    const ok = await tool(FS, cwd, { ...base, list: "name/1234-notepad.exe/environment.txt" }, { ...env, ...job }, bin);
    const answer = body<FsAnswer & { text: { encoding: string; lines: number; bytes: number } }>(ok);
    assert.equal(answer.text.encoding, "utf-8");
    assert.equal(answer.text.lines, 2);
    assert.equal(await readFile(join(out, "mem_fs", "name", "1234-notepad.exe", "environment.txt"), "utf8"), ENV_TEXT);
    assert.ok(!ok.stdout.includes(SECRET_TOKEN), "the text's content is in the answer");

    const binary = await tool(FS, cwd, { ...base, mount: join(out, "mem2"), list: "name/1234-notepad.exe/minidump/memory.dmp" }, { ...env, ...job }, bin);
    const refusal = refused(binary);
    assert.match(refusal.error, /not text/);
    assert.match(refusal.error, /export/);
    assert.equal(await exists(join(out, "mem_fs", "name", "1234-notepad.exe", "minidump", "memory.dmp")), false, "a binary file was written as text");
    assert.ok(!binary.stdout.includes("�"), "a replacement character is in the answer");
  });
});

test("mem_fs gives no file content outside a job, starts nothing, and still lists", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await memfsStub(cwd, bin);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    for (const mode of ["export", "text"]) {
      const r = refused(await tool(
        FS, cwd,
        { path: "inputs/memory.raw", mount: "work/s1/mem", mode, write_values: true, paths: ["sys/proc/proc.txt"], list: "sys/proc/proc.txt" },
        env, bin,
      ));
      assert.match(r.error, /outside a job/, mode);
      assert.match(r.error, /secret_output/, mode);
    }
    // Without write_values the request is refused too.
    assert.match(refused(await tool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "export", paths: ["sys/proc/proc.txt"] }, env, bin)).error, /write_values/);
    assert.equal(await exists(env.STUB_LOG), false, "MemProcFS was started for a refused request");
    assert.equal(await exists(join(cwd, "work", "s1", "mem_fs")), false);

    // A listing is names and sizes: no value, and it works anywhere.
    const listed = body<FsAnswer>(await tool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/mem", mode: "list", list: "name/1234-notepad.exe", timeout_seconds: 30 }, env, bin));
    assert.equal(listed.mode, "list");
    assert.deepEqual(
      listed.entries?.map((e) => [e.name, e.directory, e.size]).sort(),
      [["a b.txt", false, 13], ["a_b.txt", false, 19], ["environment.txt", false, ENV_TEXT.length], ["minidump", true, undefined]].sort(),
    );
    assert.equal(listed.entry_count, 4);
    assert.ok(await exists(listed.logs.stdout), "the engine's stdout log is next to the mount");
    assert.ok(await exists(listed.logs.stderr));
  });
});

test("mem_fs names the phase that failed, with the engine's own output and what the host lacks", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    await mkdir(join(cwd, "work", "s1"), { recursive: true });
    // MemProcFS exits before it mounts: FUSE is not there.
    const exits = await memfsStub(cwd, bin, "exit");
    const early = refused(await tool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m1", mode: "list", timeout_seconds: 30 }, exits, bin));
    assert.equal(early.phase, "startup");
    assert.match(early.error, /exited before the mount appeared/);
    assert.match(early.stderr as string, /FUSE is not available/);
    assert.ok(early.prerequisites, "what the host has for FUSE is named");
    assert.ok(await exists(early.logs_dir ? String(early.logs_dir) : join(cwd, "work", "s1")), "the logs are kept");

    // MemProcFS runs and never mounts: the deadline, in the startup phase.
    const never = await memfsStub(cwd, bin, "never");
    const late = refused(await tool(FS, cwd, { path: "inputs/memory.raw", mount: "work/s1/m2", mode: "list", timeout_seconds: 3 }, never, bin));
    assert.equal(late.phase, "startup");
    assert.match(late.error, /did not appear within 3s/);
  });
});

test("mem_fs refuses a virtual path outside the mount, and a second path that lands on the same output name", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await memfsStub(cwd, bin);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const { out, job } = await jobDir(cwd);
    const base = { path: "inputs/memory.raw", mode: "export", write_values: true, timeout_seconds: 30 };
    const escape = refused(await tool(FS, cwd, { ...base, mount: join(out, "mem"), paths: ["../../etc/passwd"] }, { ...env, ...job }, bin));
    assert.match(escape.error, /inside the mount/);
    assert.equal(await exists(env.STUB_LOG), false, "MemProcFS was started for a path outside the mount");

    // "a b.txt" and "a_b.txt" are different virtual files; their output names are the same once spaces are replaced.
    const both = body<FsAnswer>(await tool(
      FS, cwd,
      { ...base, mount: join(out, "mem"), paths: ["name/1234-notepad.exe/a b.txt", "name/1234-notepad.exe/a_b.txt", "name/1234-notepad.exe/missing.txt"] },
      { ...env, ...job }, bin,
    ));
    assert.deepEqual(both.counts, { requested: 3, exported: 1, failed: 1, refused: 1, not_exported: 0, partial: 0, not_attempted: 0 });
    assert.equal(both.complete, false);
    assert.deepEqual(both.items?.map((i) => i.status.split(":")[0]), ["exported", "refused", "failed"]);
    assert.equal(await readFile(join(out, "mem_fs", "name", "1234-notepad.exe", "a_b.txt"), "utf8"), "with a space\n", "the first one kept its name; the second did not overwrite it");
  });
});

test("mem_fs does not export a file larger than max_bytes_per_path, and counts it", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await memfsStub(cwd, bin);
    await writeFile(join(cwd, "inputs", "memory.raw"), Buffer.alloc(4096));
    const { out, job } = await jobDir(cwd);
    const answer = body<FsAnswer>(await tool(
      FS, cwd,
      { path: "inputs/memory.raw", mount: join(out, "mem"), mode: "export", write_values: true, timeout_seconds: 30, max_bytes_per_path: 1000, paths: ["name/1234-notepad.exe/minidump/memory.dmp", "sys/proc/proc.txt"] },
      { ...env, ...job }, bin,
    ));
    assert.deepEqual(answer.counts, { requested: 2, exported: 1, failed: 0, refused: 0, not_exported: 1, partial: 0, not_attempted: 0 });
    assert.match(answer.items?.[0].status as string, /^not exported: .*exceeds max_bytes_per_path/);
    assert.equal(await exists(join(out, "mem_fs", "name", "1234-notepad.exe", "minidump", "memory.dmp")), false);
    assert.equal(answer.complete, false);
  });
});
