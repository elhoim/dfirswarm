/**
 * What a seat's tool call names of a sensitive output.
 *
 * A sensitive output stays readable by every seat; the harness records each
 * access it can see. This is the part that decides, from one trace row of a
 * seat (the tool, its arguments) and the run's sensitive jobs, which of them
 * the call names and how sure that is. It is pure: the hub writes the lines
 * (`vm-hub.ts`), and a later reader of the record can ask the same question
 * of the same rows.
 *
 * It looks at what the call itself holds, never at what came back: a path
 * the read tools are given, a path, a blob digest, a catalogue generation or
 * alias or a job id in a command line, a root a command walks, a kept copy
 * of an earlier read. A path a program computes, a copy that was not a
 * recorded one, a program that opens a file by a name the command does not
 * hold are not seen; the record is a lower bound and says so.
 *
 * Nothing here holds a value or a digest of one. A blob is named by its part
 * (`blob`) and the row it was read in: the digest is in that row's command,
 * and a digest of a weak secret is the secret.
 */
import { isAbsolute, posix, relative } from "node:path";
import type { SensitiveIndex } from "./output-hygiene.ts";

/** The version of the matching below; a line carries it, so a later reader knows which rules made it. */
export const ACCESS_RULES = 1;

/** How the harness came to see the access: a path a tool was given, text a command held, a page an API call returned. */
export type AccessVia = "path" | "text" | "api_page";

/**
 * How sure it is. `certain`: bytes of the output were returned to the seat
 * (an API page). `path`: a read tool's path lies in the output. `text`: a
 * command's text names it. `maybe`: a command walks a root that holds it.
 */
export type AccessCertainty = "certain" | "path" | "text" | "maybe";

/** The part of a sensitive job's output that was reached. */
export type AccessPart = "out" | "log" | "blob" | "catalog" | "copy" | "stdout" | "stderr" | "run";

export type AccessHit = {
  /** The sensitive job; null for a reach that cannot be pinned to one (`candidates` then lists the ones it could hold). */
  job: string | null;
  candidates?: string[];
  via: AccessVia;
  certainty: AccessCertainty;
  part: AccessPart;
  /** What matched, from the run's directory: the path as the call named it (a blob by the part alone). */
  paths: string[];
};

/** The sensitive jobs of the run and how their bytes are recognised (output-hygiene `sensitiveIndex`). */
export type AccessIndex = Pick<SensitiveIndex, "jobs" | "content" | "genJob" | "aliasJob">;

/** A kept copy of an earlier access: the path it was kept as, to the sensitive job it holds. */
export type KeptCopies = ReadonlyMap<string, string>;

/** The tools whose argument is a path they read from. */
const PATH_TOOLS = new Set(["read", "grep", "find", "ls"]);
const SHELL_TOOLS = new Set(["bash", "powershell"]);

/** A job's files that say nothing of its content: its record, its manifest and its scope. */
const METADATA = /^(?:job|manifest|scope[\w.-]*|[\w.-]*\.manifest)\.json$/;
const PIPS = /^(?:[\w.-]+\.)?(?:stdout\.log|stderr\.log|pip-before\.txt|pip-after\.txt)$/;

/** The path a read tool was given: the fields the write guard looks for, in the same order. */
function toolPath(args: Record<string, unknown>): string | undefined {
  for (const key of ["path", "filePath", "file_path", "file"]) {
    const v = args[key];
    if (typeof v === "string" && v.trim()) return v;
  }
  return undefined;
}

/** A path named from the run's directory, or null when it points outside it. Collapses `.` and `..`. */
export function runRelative(sandbox: string, raw: string): string | null {
  const text = raw.trim();
  if (!text || text.includes("\0")) return null;
  const rel = isAbsolute(text) ? relative(sandbox, text) : text;
  if (isAbsolute(rel)) return null;
  const clean = posix.normalize(rel.split("\\").join("/")).replace(/\/+$/, "");
  if (clean === ".." || clean.startsWith("../")) return null;
  return clean === "." ? "" : clean;
}

/** One path, from the run's directory, to the sensitive job whose output it lies in; null when it lies in none. */
function pathJob(rel: string, ix: AccessIndex, copies: KeptCopies): { job: string; part: AccessPart; walk: boolean } | null {
  const job = /^store\/jobs\/([A-Za-z0-9_-]+)(?:\/(.*))?$/.exec(rel);
  if (job) {
    const [, id, rest = ""] = job;
    if (!ix.jobs.has(id)) return null;
    if (!rest) return { job: id, part: "out", walk: true };
    if (METADATA.test(rest)) return null;
    if (rest === "out" || rest.startsWith("out/")) return { job: id, part: "out", walk: false };
    // Another attempt's output sits beside it as `<attempt>.out/…`.
    if (/^[\w.-]+\.out(?:\/|$)/.test(rest)) return { job: id, part: "out", walk: false };
    return PIPS.test(rest) ? { job: id, part: "log", walk: false } : null;
  }
  const blob = /^store\/blobs\/([0-9a-f]{64})$/.exec(rel);
  if (blob) {
    const id = ix.content.get(blob[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "blob", walk: false } : null;
  }
  const gen = /^catalog\/gen\/([a-z0-9-]+)(?:\/|$)/.exec(rel);
  if (gen) {
    const id = ix.genJob.get(gen[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "catalog", walk: false } : null;
  }
  const alias = /^catalog\/([A-Za-z0-9._-]+)(?:\/|$)/.exec(rel);
  if (alias && alias[1] !== "gen" && alias[1] !== "revisions") {
    const id = ix.aliasJob.get(alias[1]);
    return id && ix.jobs.has(id) ? { job: id, part: "catalog", walk: false } : null;
  }
  for (const [kept, id] of copies) if (rel === kept || rel.startsWith(`${kept}/`)) return { job: id, part: "copy", walk: false };
  return null;
}

/** A path as it goes in a record: a blob is named by its part alone, since its name is the digest of its bytes. */
function shownPath(rel: string, part: AccessPart): string {
  return part === "blob" ? "store/blobs" : rel;
}

/** Whether a path is a root above many jobs' outputs: the store, its jobs or its blobs. */
function isRoot(rel: string): boolean {
  return rel === "store" || rel === "store/jobs" || rel === "store/blobs" || rel === "catalog" || rel === "catalog/gen";
}

function addHit(hits: Map<string, AccessHit>, job: string, part: AccessPart, via: AccessVia, certainty: AccessCertainty, path: string): void {
  const have = hits.get(job);
  if (!have) hits.set(job, { job, via, certainty, part, paths: [path] });
  else if (!have.paths.includes(path)) have.paths.push(path);
}

/** A glob over one path segment as the source of a regular expression: `*`, `?`, `[…]` and `{a,b}`. */
function globSource(seg: string): string {
  let out = "";
  for (let i = 0; i < seg.length; i += 1) {
    const c = seg[i];
    if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else if (c === "{") {
      const end = seg.indexOf("}", i);
      if (end < 0) out += "\\{";
      else {
        out += `(?:${seg.slice(i + 1, end).split(",").map(globSource).join("|")})`;
        i = end;
      }
    } else if (c === "[") {
      const end = seg.indexOf("]", i + 2);
      if (end < 0) out += "\\[";
      else {
        out += `[${seg.slice(i + 1, end).replace(/\\/g, "\\\\")}]`;
        i = end;
      }
    } else out += c.replace(/[.+^$()|\]\\}]/g, "\\$&");
  }
  return out;
}

/** A glob over one path segment as a regular expression; null for a segment that holds none. */
function segmentGlob(seg: string): RegExp | null {
  if (!/[*?[{]/.test(seg)) return null;
  try {
    return new RegExp(`^${globSource(seg)}$`);
  } catch {
    return null;
  }
}

/** The commands that read what they are given; a root or a glob named to anything else is not a reach. */
const READERS = /(?:^|[\s;&|(`'"=])(?:grep|egrep|fgrep|rg|ag|ack|find|tree|du|cat|head|tail|less|more|xargs|cp|rsync|tar|zip|7z|strings|xxd|hexdump|od|sort|sed|awk|wc|file|ls\s+-\w*R)\b/;
/** The ones that walk a directory they are given, which is what makes a bare `store` a root and not a word. */
const WALKERS = /(?:^|[\s;&|(`'"=])(?:grep\s+-\w*[rR]|grep\s+--recursive|egrep\s+-\w*[rR]|rg|ag|ack|find|tree|du|ls\s+-\w*R)\b/;
/** A word of a command: quotes and a leading `./` taken off. */
const SHELL_WORD = /[^\s"'`;|&<>()=]+/g;

function shellHits(cmd: string, sandbox: string, ix: AccessIndex, copies: KeptCopies): AccessHit[] {
  const hits = new Map<string, AccessHit>();
  const sensitive = [...ix.jobs.keys()];
  const rootReach = new Set<string>();

  // The paths the command holds, relative to the run when they lie in it.
  const words = new Set<string>();
  for (const m of cmd.matchAll(SHELL_WORD)) words.add(m[0]);
  // A path may also be joined to a prefix (`--path=store/…`, `$S/store/…`): search the text for the store's own names.
  const texts = new Set<string>();
  for (const m of cmd.matchAll(/(?:store\/(?:jobs|blobs)(?:\/[^\s"'`;|&<>()]*)?|catalog\/[^\s"'`;|&<>()]*|tool-output\/[^\s"'`;|&<>()]*)/g)) texts.add(m[0]);
  for (const t of texts) words.add(t);

  for (const w of words) {
    // The path of a word, in the run's directory; a word that is only part of one (`$S/store/jobs/j1/out/x`) is searched for the store's names.
    const rels = new Set<string>();
    const direct = runRelative(sandbox, w);
    if (direct !== null) rels.add(direct);
    const at = /(?:^|\/)((?:store\/(?:jobs|blobs)|catalog|tool-output)(?:\/.*)?)$/.exec(w);
    if (at) rels.add(posix.normalize(at[1]).replace(/\/+$/, ""));
    for (const rel of rels) {
      const found = pathJob(rel, ix, copies);
      if (found) {
        addHit(hits, found.job, found.part, "text", "text", shownPath(rel, found.part));
        continue;
      }
      if (isRoot(rel)) {
        // `store/jobs` is a directory of jobs whatever reads it; a bare `store` or `catalog` is a word unless something walks it.
        if (rel.includes("/") || WALKERS.test(cmd)) rootReach.add("*");
        continue;
      }
      // A glob over the jobs: store/jobs/j0000*/out/…
      const g = /^store\/jobs\/([^/]*[*?[{][^/]*)(?:\/.*)?$/.exec(rel);
      const re = g ? segmentGlob(g[1]) : null;
      if (re) {
        for (const id of sensitive) if (re.test(id)) rootReach.add(id);
        continue;
      }
      if (/^store\/(?:\*+|\*\/.*)$/.test(rel)) rootReach.add("*");
    }
  }

  // A job id the command holds on its own, with no path: it names the job.
  for (const m of cmd.matchAll(/(?<![A-Za-z0-9_-])j\d{6,}(?![A-Za-z0-9_-])/g)) {
    if (ix.jobs.has(m[0]) && !hits.has(m[0])) addHit(hits, m[0], "run", "text", "text", m[0]);
  }

  const out = [...hits.values()].sort((a, b) => (a.job! < b.job! ? -1 : a.job! > b.job! ? 1 : 0));
  // A root or a glob: only a command that reads or walks what it is given could reach the outputs under it.
  if (rootReach.size && (READERS.test(cmd) || WALKERS.test(cmd))) {
    const all = rootReach.has("*");
    const candidates = (all ? sensitive : [...rootReach]).filter((id) => !hits.has(id)).sort();
    if (candidates.length) out.push({ job: null, candidates, via: "text", certainty: "maybe", part: "run", paths: [] });
  }
  return out;
}

/**
 * The sensitive outputs one seat trace row names: for `read`, `grep`, `find`
 * and `ls`, the path the tool was given; for `bash` and `powershell`, the
 * command text. At most one entry per sensitive job, and one more for the
 * outputs a walked root could hold (`job: null`). Empty when the call names
 * none, or the run has no sensitive output.
 */
export function classifyTraceRow(row: { tool?: unknown; args?: unknown }, ix: AccessIndex, o: { sandbox: string; copies?: KeptCopies }): AccessHit[] {
  if (!ix.jobs.size && !(o.copies && o.copies.size)) return [];
  const tool = typeof row.tool === "string" ? row.tool : "";
  const args = row.args && typeof row.args === "object" ? (row.args as Record<string, unknown>) : {};
  const copies = o.copies ?? new Map<string, string>();
  if (SHELL_TOOLS.has(tool)) {
    return typeof args.command === "string" ? shellHits(args.command, o.sandbox, ix, copies) : [];
  }
  if (!PATH_TOOLS.has(tool)) return [];
  const raw = toolPath(args);
  // A search with no path searches the run's directory, where the tool is started.
  const rel = raw === undefined ? (tool === "grep" ? "" : null) : runRelative(o.sandbox, raw);
  if (rel === null) return [];
  const found = pathJob(rel, ix, copies);
  if (found) {
    // The job's own directory: a search walks it and reads its output; a read or a listing of it names files and holds none.
    if (found.walk && tool !== "grep") return [];
    return [{ job: found.job, via: "path", certainty: "path", part: found.part, paths: [shownPath(rel, found.part)] }];
  }
  // A root above many jobs, searched: it could read any of their outputs.
  if (tool === "grep" && (isRoot(rel) || rel === "")) {
    const candidates = [...ix.jobs.keys()].sort();
    return candidates.length ? [{ job: null, candidates, via: "path", certainty: "maybe", part: "run", paths: [rel] }] : [];
  }
  return [];
}

/**
 * A page of a sensitive job's output that an API answer returned to a seat:
 * certain, since the bytes were in the answer.
 */
export function apiPageHit(job: string, part: "stdout" | "stderr", path: string): AccessHit {
  return { job, via: "api_page", certainty: "certain", part, paths: [path] };
}
