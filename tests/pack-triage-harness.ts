/**
 * Helpers the triage-collection suites share: running a pack tool as a call and as a job (JOB_ID and OUT set, the way the job
 * service runs it), and builders for the objects a delivered collection holds.
 *
 * Every fixture here is built from a format's own definition (the EWF file signature, the VHDX and QCOW signatures, the LiME
 * header, a GPT header, the column names of a real KAPE copy log) or by hand, never from a tool's output. Set
 * TRIAGE_TOOLS to a directory laid out as the pack's tools/ to run a suite against another copy of the tools (it is how the
 * suites were shown to fail on the code they replaced).
 */
import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ROOT, runPy } from "./tool-library-harness.ts";
export { withCwd } from "./tool-library-harness.ts";

export const TRIAGE = join(ROOT, "packs", "triage-collection");
export const TOOLS = process.env.TRIAGE_TOOLS ?? join(TRIAGE, "tools");
export const ID = join(TOOLS, "collection_id", "run.py");
export const INDEX = join(TOOLS, "collection_index", "run.py");
export const AGENT = { AGENT_ID: "s1" };

export type Run = { code: number | null; stdout: string; stderr: string };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export async function tool(script: string, cwd: string, args: unknown, env: Record<string, string> = {}): Promise<Run> {
  return runPy(script, cwd, args, undefined, { ...AGENT, ...env });
}

let jobs = 0;
/** The tool as a job runs it: JOB_ID and OUT set, OUT inside the run directory (`out`, or the directory named). */
export async function asJob(script: string, cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out", jobId?: string): Promise<Run> {
  await mkdir(join(cwd, outName), { recursive: true });
  jobs += 1;
  return tool(script, cwd, args, { JOB_ID: jobId ?? `j${String(jobs).padStart(6, "0")}`, OUT: join(cwd, outName), ...env });
}

export function body(out: Run): Json {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

/** An answer that is a refusal: a JSON error and a nonzero exit, never a traceback. */
export function refused(out: Run): Json {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout);
}

export async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

/** Every file under a directory, relative to it. */
export async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (d: string, prefix: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory()) await walk(join(d, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  await walk(dir, "");
  return out.sort();
}

export async function put(root: string, rel: string, data: string | Buffer, mode?: number): Promise<void> {
  const full = join(root, rel);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, data);
  if (mode !== undefined) await chmod(full, mode);
}

export async function link(root: string, rel: string, target: string): Promise<void> {
  await mkdir(join(root, rel, ".."), { recursive: true });
  await symlink(target, join(root, rel));
}

/** A sparse file of `size` bytes with `pieces` written at their offsets: a raw image without writing a megabyte of zeros. */
export async function sparse(path: string, size: number, pieces: Array<[number, Buffer]>): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, Buffer.alloc(0));
  await truncate(path, size);
  const { open } = await import("node:fs/promises");
  const fh = await open(path, "r+");
  try {
    for (const [offset, data] of pieces) await fh.write(data, 0, data.length, offset);
  } finally {
    await fh.close();
  }
}

// The column names of a real KAPE copy log (one KAPE release; the version is not known): the header row is the format
// description, the values below are made up.
export const KAPE_COPY_HEADER = "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration";

export function kapeCopyRow(source: string, destination: string, size = 1): string {
  const csv = (v: string) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return [
    "2026-02-14 09:12:00.123", csv(source), csv(destination), String(size), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "False",
    "2026-01-01 00:00:00.000", "2026-01-02 03:04:05.678", "2026-01-03 00:00:00.000", "0.0123",
  ].join(",");
}

export async function readRows(path: string): Promise<Json[]> {
  const text = await readFile(path, "utf8");
  return text.trimEnd() === "" ? [] : text.trimEnd().split("\n").map((l) => JSON.parse(l));
}

// Signatures, from the formats' own definitions.
export const EWF_SIGNATURE = Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]);       // EVF\t\r\n\xff\0
export const VHDX_SIGNATURE = Buffer.from("vhdxfile");
export const LIME_MAGIC = Buffer.from([0x45, 0x4d, 0x69, 0x4c]);                                  // 0x4C694D45 little-endian: "EMiL"
export const GPT_SIGNATURE = Buffer.from("EFI PART");
