/**
 * A write a job's worker refused, said where the agent reads the job's
 * result.
 *
 * In a worker the job starts in the run's directory, and it and the whole
 * run are read-only: only the job's own output directory ($OUT) and its
 * control directory are writable. A program that writes its log, its temp
 * files or its output where it stands fails there. On the Belka run
 * (s7827e1) the disk-timeline recipe and two agents' own jobs failed that
 * way, and each said only "exit 1".
 *
 * A job that ended non-zero is read for it: its stdout, its stderr, and
 * every stderr file it kept in $OUT (`*.stderr`, `*.err`, `stderr.log`,
 * `stderr.txt`: a recipe keeps each step's stderr beside its output, and an
 * agent's command sends a program's there as often as not). A line that says
 * "Read-only file system" counts unless the path it names is one the job may
 * write; a line that says "Permission denied" counts when it names a path
 * outside every directory the job may write (a relative one read from the
 * directory the job started in). Generic, on the error text alone: no
 * program is named or recognised. Every file is read whole, a line at a time.
 */
import { constants } from "node:fs";
import { open, opendir } from "node:fs/promises";
import { isAbsolute, join, normalize, relative, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";

export const READ_ONLY = "Read-only file system";
export const DENIED = "Permission denied";

/** What was refused: the first line that says so, where it is, and how many such lines there are. */
export type WriteRefused = {
  error: typeof READ_ONLY | typeof DENIED;
  /** The path that line names, as it names it resolved, or null when it names none. */
  path: string | null;
  /** Where that line is: `stdout.log`, `stderr.log`, or `out/<path>` for a file the job kept. */
  file: string;
  line: number;
  /** Every such line, in every file read. */
  lines: number;
  files: number;
};

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** A name a kept stderr file goes by. */
export function isStderrName(name: string): boolean {
  return /(^|[._-])(stderr|err)(\.(log|txt))?$/i.test(name);
}

/**
 * The path a line of error text names for its error, or null: Python's
 * `OSError: [Errno 30] Read-only file system: '<path>'`, coreutils'
 * `cannot create regular file '<path>': Permission denied`, Java's
 * `<path> (Read-only file system)`, a shell's or a C program's
 * `<path>: Permission denied`. A bare word with no slash and no extension
 * (`fopen: Permission denied`) is a function's name, not a path.
 */
export function pathIn(line: string, error: string): string | null {
  const e = escape(error);
  const forms = [
    new RegExp(`${e}: (['"])(.+?)\\1`),
    new RegExp(`['‘"]([^'’"]+)['’"]: ${e}`),
    new RegExp(`(\\S+) \\(${e}\\)`),
    new RegExp(`(?:^|: )([^:'"‘’]+?): ${e}`),
  ];
  for (const re of forms) {
    const m = re.exec(line);
    if (!m) continue;
    const p = (m[2] ?? m[1]).trim();
    if (!p) continue;
    if (p.includes("/") || /^[\w.@+-]+\.[A-Za-z0-9]{1,8}$/.test(p)) return p;
  }
  return null;
}

/** Whether `p` is `dir` or inside it. */
function within(p: string, dir: string): boolean {
  const r = relative(normalize(dir), normalize(p));
  return r === "" || (!r.startsWith("..") && !isAbsolute(r));
}

/**
 * Whether a line says a write the job may not make was refused: the error
 * and the path, or null.
 */
export function refusedIn(line: string, o: { cwd: string; writable: string[] }): { error: WriteRefused["error"]; path: string | null } | null {
  const error = line.includes(READ_ONLY) ? READ_ONLY : line.includes(DENIED) ? DENIED : null;
  if (!error) return null;
  const named = pathIn(line, error);
  const path = named === null ? null : isAbsolute(named) ? normalize(named) : resolve(o.cwd, named);
  if (path !== null && o.writable.some((w) => within(path, w))) return null;
  if (error === DENIED && path === null) return null;
  return { error, path };
}

/** Every line of a file, read whole through a descriptor that does not follow a link; nothing when it cannot be opened. */
async function eachLine(path: string, visit: (line: string, n: number) => void): Promise<void> {
  const fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => null);
  if (!fh) return;
  try {
    if (!(await fh.stat()).isFile()) return;
    const decoder = new StringDecoder("utf8");
    const buf = Buffer.alloc(1 << 20);
    let carry = "";
    let n = 0;
    for (let pos = 0; ; ) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
      if (!bytesRead) break;
      pos += bytesRead;
      const parts = (carry + decoder.write(buf.subarray(0, bytesRead))).split("\n");
      carry = parts.pop() ?? "";
      for (const l of parts) visit(l, ++n);
    }
    carry += decoder.end();
    if (carry) visit(carry, ++n);
  } finally {
    await fh.close();
  }
}

/** The stderr files a job kept under its output directory, by path relative to it; links are not followed. */
async function keptStderr(out: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (rel: string) => {
    const dir = await opendir(join(out, rel)).catch(() => null);
    if (!dir) return;
    for await (const d of dir) {
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isDirectory()) await walk(r);
      else if (d.isFile() && isStderrName(d.name)) found.push(r);
    }
  };
  await walk("");
  return found.sort();
}

/**
 * A write the job was refused, read from its control directory's stdout.log
 * and stderr.log and the stderr files it kept in `out`, or null. `cwd` is
 * where the job started (a relative path is read from there); `writable`,
 * every directory it may write, as the worker names them and as the host
 * does.
 */
export async function writeRefused(o: { ctl: string; out: string; cwd: string; writable: string[] }): Promise<WriteRefused | null> {
  const seen: { first: Omit<WriteRefused, "lines" | "files"> | null; lines: number; files: Set<string> } = { first: null, lines: 0, files: new Set() };
  const read = async (path: string, name: string) => {
    await eachLine(path, (line, n) => {
      const r = refusedIn(line, o);
      if (!r) return;
      seen.lines += 1;
      seen.files.add(name);
      seen.first ??= { ...r, file: name, line: n };
    });
  };
  await read(join(o.ctl, "stdout.log"), "stdout.log");
  await read(join(o.ctl, "stderr.log"), "stderr.log");
  for (const rel of await keptStderr(o.out)) await read(join(o.out, rel), `out/${rel}`);
  return seen.first ? { ...seen.first, lines: seen.lines, files: seen.files.size } : null;
}

/**
 * What the agent is told, whole: what was refused and where it says so (as
 * the store will hold it), that the working directory and the run are
 * read-only in a worker, the job's writable directory by name and path, and
 * what to do.
 */
export function writeRefusedWords(w: WriteRefused, o: { job: string; out: string }): string {
  const where = w.file.startsWith("out/") ? `job:${o.job}/${w.file.slice(4)}` : `store/jobs/${o.job}/${w.file}`;
  const said = `"${w.error}"${w.path ? ` on ${w.path}` : ""}, ${where} line ${w.line}`;
  const more = w.lines > 1 ? `; ${w.lines} such lines in ${w.files === 1 ? "that file" : `${w.files} files`}` : "";
  return `a write outside $OUT was refused (${said}${more}). In a worker the job starts in the run's directory, and it and the whole run are read-only: only this job's output directory, $OUT (${o.out}), is writable. Point the program's log, temp or output options there, or cd "$OUT" before running it`;
}
