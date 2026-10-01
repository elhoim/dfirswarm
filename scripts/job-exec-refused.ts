/**
 * A program a job's worker could not execute, said where the agent reads the
 * job's result.
 *
 * In a worker nothing can run where it stands in store/ (sealTree keeps a
 * sealed file read-only, mode 0444, with no execute bit), in work/extracted/
 * or work/quarantine/ (read-only and no-exec), in inputs/ (no-exec) or in the
 * job's own $OUT and control directory (no-exec). A program supplied to the
 * run (swarm.sh tool-supply), one unpacked from an archive into $OUT, or one
 * extracted from the evidence therefore fails there. On a live run (s3472f0)
 * two jobs failed that way, one with "exit 126" and one with "exit 127: a
 * program it runs is not in its image" (the loader's own words for a segment
 * it could not map), before a seat found the way: a copy in an executable
 * temporary directory inside the job.
 *
 * A job that ended non-zero is read for it, on the shell's and the loader's
 * own words only: the exit status 126 (the shell found the command and could
 * not execute it), with the "Permission denied" line that names the program
 * when there is one; and a line that carries the dynamic loader's "failed to
 * map segment from shared object", at any status. A "Permission denied" at
 * another status is not read here: nothing in the line tells a program that
 * could not be executed from a file that could not be written (a read-only
 * directory in $OUT), and a denied write is job-write-refused.ts's. The job's
 * stdout, its stderr and every stderr file it kept in $OUT are read whole, a
 * line at a time. Generic: no program is named or recognised.
 */
import { isAbsolute, join, normalize, resolve } from "node:path";
import { DENIED, eachLine, keptStderr, pathIn } from "./job-write-refused.ts";

/** The dynamic loader's refusal to map a segment of a program or library from a file system that cannot execute. */
export const LOADER_REFUSAL = "failed to map segment from shared object";

/** What was refused: the first line that says so (or none, when only the exit status does), and how many such lines there are. */
export type ExecRefused = {
  /** What the first line says; null when no line does and the exit status 126 alone is the sign. */
  error: typeof DENIED | typeof LOADER_REFUSAL | null;
  /** The path that line names, resolved, or null when it names none. */
  path: string | null;
  /** Where that line is: `stdout.log`, `stderr.log`, or `out/<path>` for a file the job kept. */
  file: string | null;
  line: number | null;
  /** Every such line, in every file read. */
  lines: number;
  files: number;
};

/**
 * Whether a line says a program could not be executed: the error and the
 * path it names (resolved from `cwd` when relative), or null. `exit` is the
 * job's status: a "Permission denied" counts at 126 only; the loader's
 * refusal counts at any.
 */
export function execRefusedIn(line: string, o: { cwd: string; exit: number | null }): { error: typeof DENIED | typeof LOADER_REFUSAL; path: string | null } | null {
  const resolved = (named: string | null | undefined) => (!named ? null : isAbsolute(named) ? normalize(named) : resolve(o.cwd, named));
  if (line.includes(LOADER_REFUSAL)) {
    // "<program>: error while loading shared libraries: <file it could not map>: failed to map segment from shared object"
    const named = /error while loading shared libraries: (.+?): failed to map segment from shared object/.exec(line)?.[1];
    return { error: LOADER_REFUSAL, path: resolved(named) };
  }
  if (o.exit === 126 && line.includes(DENIED)) return { error: DENIED, path: resolved(pathIn(line, DENIED)) };
  return null;
}

/**
 * A program the job could not execute, read from its control directory's
 * stdout.log and stderr.log and the stderr files it kept in `out`, or null.
 * `exit` is the status it ended with: 126 alone is enough (the shell's own
 * status for a command it found and could not execute), and says so when no
 * line names the program (its stderr may have gone into a file of the job's
 * own). `cwd` is where the job started (a relative path is read from there).
 */
export async function execRefused(o: { ctl: string; out: string; cwd: string; exit: number | null }): Promise<ExecRefused | null> {
  const seen: { first: Pick<ExecRefused, "error" | "path" | "file" | "line"> | null; lines: number; files: Set<string> } = { first: null, lines: 0, files: new Set() };
  const read = async (path: string, name: string) => {
    await eachLine(path, (line, n) => {
      const r = execRefusedIn(line, o);
      if (!r) return;
      seen.lines += 1;
      seen.files.add(name);
      seen.first ??= { ...r, file: name, line: n };
    });
  };
  await read(join(o.ctl, "stdout.log"), "stdout.log");
  await read(join(o.ctl, "stderr.log"), "stderr.log");
  for (const rel of await keptStderr(o.out)) await read(join(o.out, rel), `out/${rel}`);
  if (seen.first) return { ...seen.first, lines: seen.lines, files: seen.files.size };
  return o.exit === 126 ? { error: null, path: null, file: null, line: null, lines: 0, files: 0 } : null;
}

/**
 * What the agent is told, whole: what could not be executed and where it
 * says so (as the store will hold it), where nothing in a worker can be
 * executed and why, and what to do.
 */
export function execRefusedWords(x: ExecRefused, o: { job: string; out: string }): string {
  let head: string;
  if (x.error === null || x.file === null) {
    head = "a program it ran could not be executed: exit 126 is the shell's status for a program it found and could not run, and no line in stdout.log, stderr.log or a stderr file the job kept says which (if the program's stderr went into a file of the job's own, it is there)";
  } else {
    const where = x.file.startsWith("out/") ? `job:${o.job}/${x.file.slice(4)}` : `store/jobs/${o.job}/${x.file}`;
    const more = x.lines > 1 ? `; ${x.lines} such lines in ${x.files === 1 ? "that file" : `${x.files} files`}` : "";
    head = `a program it ran could not be executed ("${x.error}"${x.path ? ` on ${x.path}` : ""}, ${where} line ${x.line}${more})`;
  }
  return `${head}. Nothing a worker holds in store/, work/extracted/, work/quarantine/, inputs/ or its own $OUT can be executed where it stands: sealed files have no execute bit and the others are mounted no-exec. Copy the program, and every library it loads, into an executable temporary directory inside the job (for example one made with mktemp -d under /tmp, which is the worker VM's own), make it executable there and run it from that copy; what it writes that you want kept goes to $OUT (${o.out})`;
}
