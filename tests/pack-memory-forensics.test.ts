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
