/**
 * The image a job that names no profile runs in: the smallest of the run's
 * job images whose own record holds every program the job runs, and the
 * run's default image whenever that is not sure. In the three latest runs
 * 61 of 236, 16 of 71 and 12 of 90 jobs named no profile and booted the
 * image that holds every pack.
 *
 * Nothing here knows a program. What each image holds is its own record
 * (images/<profile>/image.json, copied at kickoff from the image's
 * /etc/dfirswarm/image.json): `on_path`, every program on its PATH by where
 * it is, and `binaries`, the programs its packs name and where each is. The
 * command is read as bash reads it, far enough to see which words run.
 *
 * Sure means all of this holds; anything else keeps the default image, and
 * the record says why:
 * - every program the command runs (the first word of each simple command,
 *   a bash builtin aside) is in the chosen image's record;
 * - every word of the command that names a program some image holds and
 *   another does not is in it too, so a program run through another
 *   (timeout, xargs, find -exec, bash -c '…') is not missed: a word that only
 *   mentions one can move the choice to a bigger image, never a smaller one;
 * - nothing runs a body the command line does not show: no heredoc or
 *   here-string, no quoted script (one that spans lines or holds a ;), no
 *   import, no program named by an expansion or by a path of the run, and no
 *   file of the agents' scratch (work/, tool-output/, tools/) named
 *   anywhere, since it may be the script that runs.
 *
 * An image built before its record listed every program on PATH records
 * only its packs' programs: a command that runs a shell utility then finds
 * it in no record, and keeps the default image, as before.
 *
 * Among the images that hold what a command runs, one whose record carries
 * pinned data for a program it runs (a symbol pack a program reads: the
 * record's `downloads` of kind `data`, each naming its `program`) is
 * preferred to a smaller image that holds the program and not its data.
 */
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";

/**
 * One job image as its record has it: how many packs, and every program it
 * holds, by name and by where it is; `whole` when the record lists every
 * program on its PATH, not only its packs' ones.
 */
export type ImageRecord = { profile: string; ref: string; packs: number; programs: Set<string>; paths: Set<string>; whole: boolean; data?: Set<string> };

/** How a job's image was chosen, and why: on its job_started line. */
export type ImageChoice = { how: "named" | "pack" | "programs" | "default"; why: string; programs?: string[] };

/** The run's job images whose record can be read; an image with none is never chosen by its programs. */
export async function readImageRecords(S: string, images: Record<string, string>): Promise<ImageRecord[]> {
  const out: ImageRecord[] = [];
  for (const [profile, ref] of Object.entries(images)) {
    let r: { packs?: unknown; binaries?: unknown; on_path?: unknown; downloads?: unknown };
    try {
      r = JSON.parse(await readFile(join(S, "images", profile, "image.json"), "utf8")) as typeof r;
    } catch {
      continue;
    }
    const programs = new Set<string>();
    const paths = new Set<string>();
    const binaries = r.binaries && typeof r.binaries === "object" ? (r.binaries as Record<string, unknown>) : {};
    for (const [name, where] of Object.entries(binaries)) {
      // A program a pack names that the build left out is recorded with no path: not held.
      if (typeof where !== "string" || !where) continue;
      programs.add(name);
      paths.add(where);
    }
    for (const where of Array.isArray(r.on_path) ? r.on_path : []) {
      if (typeof where !== "string" || !where.startsWith("/")) continue;
      paths.add(where);
      programs.add(basename(where));
    }
    // The programs this image holds pinned data for (a pack's `install.data`).
    const data = new Set<string>();
    const downloads = r.downloads && typeof r.downloads === "object" ? (r.downloads as Record<string, { kind?: unknown; program?: unknown }>) : {};
    for (const d of Object.values(downloads)) if (d && d.kind === "data" && typeof d.program === "string" && d.program) data.add(d.program);
    out.push({ profile, ref, packs: Array.isArray(r.packs) ? r.packs.length : 0, programs, paths, whole: Array.isArray(r.on_path), data });
  }
  return out;
}

let builtinsRead: Set<string> | null = null;
/**
 * bash's own builtins (cd, export, read, …), as the host's bash lists them:
 * they run in whichever image runs the script. A host without bash lists
 * none, and a builtin is then a program no record holds (the default image).
 */
export function bashBuiltins(): Set<string> {
  if (builtinsRead) return builtinsRead;
  const r = spawnSync("bash", ["-c", "compgen -b"], { encoding: "utf8", timeout: 10_000 });
  builtinsRead = new Set(r.status === 0 ? r.stdout.split("\n").map((l) => l.trim()).filter(Boolean) : []);
  return builtinsRead;
}

/** Reserved words after which the next word runs. */
const LEAD = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "time", "{", "coproc"]);
/** Reserved words that open or close something that is not a command (a list, a test, a pattern). */
const NOT_A_COMMAND = new Set(["for", "select", "case", "esac", "in", "function", "[[", "]]", "fi", "done", "}"]);

/** Where the ( at `at` closes, counting nested ones; the end of the text when it does not. */
function closing(text: string, at: number): number {
  let depth = 0;
  for (let k = at; k < text.length; k += 1) {
    if (text[k] === "(") depth += 1;
    else if (text[k] === ")" && --depth === 0) return k;
  }
  return text.length;
}

/**
 * A command read as bash reads it, far enough to see which words run: the
 * words of each simple command (split at ; & | ( ) and newlines, and inside
 * command substitutions, quotes and escapes resolved, redirections left
 * out), and what, if anything, hands bash a body the line does not show.
 */
export function commandShape(text: string): { commands: string[][]; hidden: string | null } {
  const commands: string[][] = [];
  let hidden: string | null = null;
  const hide = (why: string) => {
    hidden ??= why;
  };
  let words: string[] = [];
  let word = "";
  let open = false;
  // The word after a redirection is where it goes, not a word of the command.
  let target = false;
  const endWord = () => {
    if (open) {
      if (target) target = false;
      else words.push(word);
    }
    word = "";
    open = false;
  };
  const endCommand = () => {
    endWord();
    target = false;
    if (words.length) commands.push(words);
    words = [];
  };
  const inner = (body: string) => {
    const s = commandShape(body);
    commands.push(...s.commands);
    if (s.hidden) hide(s.hidden);
  };
  const quoted = (body: string) => {
    if (/[\n;]/.test(body)) hide("a quoted script (it spans lines or holds a ;) may run what the command line does not name");
  };
  const n = text.length;
  for (let i = 0; i < n; i += 1) {
    const c = text[i];
    if (c === "\\") {
      if (text[i + 1] !== "\n") {
        word += text[i + 1] ?? "";
        open = true;
      }
      i += 1;
      continue;
    }
    if (c === "'") {
      const end = text.indexOf("'", i + 1);
      const body = text.slice(i + 1, end < 0 ? n : end);
      quoted(body);
      word += body;
      open = true;
      i = end < 0 ? n : end;
      continue;
    }
    if (c === '"') {
      // To the closing quote; what runs inside ($( ) and ` `) is read as commands too.
      let j = i + 1;
      let body = "";
      while (j < n && text[j] !== '"') {
        if (text[j] === "\\" && j + 1 < n) {
          body += text[j + 1];
          j += 2;
        } else if (text[j] === "$" && text[j + 1] === "(") {
          const end = closing(text, j + 1);
          inner(text.slice(j + 2, end));
          body += text.slice(j, end + 1);
          j = end + 1;
        } else if (text[j] === "`") {
          const end = text.indexOf("`", j + 1) < 0 ? n : text.indexOf("`", j + 1);
          inner(text.slice(j + 1, end));
          j = end + 1;
        } else {
          body += text[j];
          j += 1;
        }
      }
      quoted(body);
      word += body;
      open = true;
      i = j;
      continue;
    }
    if (c === "#" && !open) {
      const end = text.indexOf("\n", i);
      i = (end < 0 ? n : end) - 1;
      continue;
    }
    if (c === "\n") {
      endCommand();
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      endWord();
      continue;
    }
    if (c === "<" && text[i + 1] === "<") {
      hide("a heredoc or here-string gives a program a body the command line does not name");
      endWord();
      target = true;
      i += text[i + 2] === "<" ? 2 : 1;
      continue;
    }
    if ((c === "<" || c === ">") && text[i + 1] === "(") {
      // A process substitution: its body runs.
      endWord();
      const end = closing(text, i + 1);
      inner(text.slice(i + 2, end));
      i = end;
      continue;
    }
    if (c === "<" || c === ">") {
      // 2>, &>: the number or & before it belongs to the redirection.
      if (open && /^[0-9]*&?$/.test(word)) {
        word = "";
        open = false;
      }
      endWord();
      while (text[i + 1] === ">" || text[i + 1] === "&" || text[i + 1] === "|") i += 1;
      // >&2 names a descriptor, not a word to skip.
      if (/[0-9-]/.test(text[i + 1] ?? "") && text[i] === "&") {
        while (/[0-9-]/.test(text[i + 1] ?? "")) i += 1;
        continue;
      }
      target = true;
      continue;
    }
    if (c === "$" && text[i + 1] === "(" && text[i + 2] === "(") {
      // $(( )): arithmetic, one word.
      const end = closing(text, i + 1);
      word += text.slice(i, end + 1);
      open = true;
      i = end;
      continue;
    }
    if (c === "(" && text[i + 1] === "(" && !open && !words.length) {
      // (( )): an arithmetic command, nothing that runs.
      i = closing(text, i);
      continue;
    }
    if (c === "(" && open && word.endsWith("=")) {
      // name=( … ): an array's elements, not commands.
      const end = closing(text, i);
      word += text.slice(i, end + 1);
      i = end;
      continue;
    }
    if (c === "$" && text[i + 1] === "(") {
      endCommand();
      i += 1;
      continue;
    }
    if (c === "`" || c === ";" || c === "&" || c === "|" || c === "(" || c === ")") {
      endCommand();
      continue;
    }
    word += c;
    open = true;
  }
  endCommand();
  return { commands, hidden };
}

/** Builtins that run the program named after them (their options aside), and those that run text as code. */
const RUN_NEXT = new Set(["exec", "command", "builtin"]);
const RUN_TEXT = new Set(["eval", "source", ".", "trap"]);

/** The word of a simple command that runs, reserved words and assignments passed over; null for none. */
function runs(words: string[]): { word: string } | { hidden: string } | null {
  for (let k = 0; k < words.length; k += 1) {
    const w = words[k];
    if (/^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/.test(w) || LEAD.has(w)) continue;
    if (NOT_A_COMMAND.has(w)) return null;
    if (RUN_TEXT.has(w)) return { hidden: `${w} runs text as code, which the command line does not name` };
    if (RUN_NEXT.has(w)) {
      while (words[k + 1]?.startsWith("-")) k += 1;
      continue;
    }
    return { word: w };
  }
  return null;
}

const list = (xs: string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

/**
 * The image for a job that names no profile, from the text it runs: the
 * smallest record (fewest packs, then fewest programs) that holds every
 * program it needs, or the default with the reason.
 */
export function chooseImage(text: string, records: ImageRecord[], fallback: { ref: string; profile: string | null }, builtins: Set<string> = bashBuiltins()): { profile: string | null; ref: string; choice: ImageChoice } {
  const keep = (why: string, programs?: string[]) => ({ ...fallback, choice: { how: "default" as const, why: `the run's default image: ${why}`, ...(programs?.length ? { programs } : {}) } });
  if (!records.length) return keep("no job image's record could be read (images/<profile>/image.json)");
  const shape = commandShape(text);
  if (shape.hidden) return keep(shape.hidden);
  if (/(^|[^A-Za-z0-9_.-])(work|tool-output|tools)\//.test(text)) return keep("it names a file of the agents' scratch (work/, tool-output/ or tools/), which may be the script that runs");
  if (/(^|[^A-Za-z0-9_.-])(import\s+[A-Za-z_]|from\s+[A-Za-z_][\w.]*\s+import\b)|\b(__import__|import_module|require)\s*\(/m.test(text)) return keep("it imports a library, which the records do not name by its import name");
  // What runs: each simple command's first word.
  const ran = new Set<string>();
  for (const words of shape.commands) {
    const r = runs(words);
    if (r !== null && "hidden" in r) return keep(r.hidden);
    const w = r?.word;
    if (w === undefined || builtins.has(w)) continue;
    if (/[$`*?[]/.test(w)) return keep(`the program ${w} is named by an expansion`);
    if (w.includes("/") && !w.startsWith("/")) return keep(`it runs ${w}, a file named by a relative path, not a program of an image`);
    ran.add(w);
  }
  // What else it names that some images hold and others do not.
  const held = (r: ImageRecord, p: string) => (p.startsWith("/") ? r.paths.has(p) : r.programs.has(p));
  const named = new Set<string>();
  for (const t of text.match(/[A-Za-z0-9_+][A-Za-z0-9_.+-]*/g) ?? []) {
    const w = t.replace(/\.+$/, "");
    if (!w || ran.has(w)) continue;
    const by = records.filter((r) => r.programs.has(w)).length;
    if (by > 0 && by < records.length) named.add(w);
  }
  const need = [...new Set([...ran, ...named])].sort();
  const nowhere = [...ran].filter((p) => !records.some((r) => held(r, p))).sort();
  if (nowhere.length) return keep(`${list(nowhere)} ${nowhere.length > 1 ? "are" : "is"} in no job image's record${records.some((r) => r.whole) ? "" : " (these records list only their packs' programs; an image built since lists every program on its PATH)"}`, need);
  // The programs of the command that an image holds pinned data for.
  const withData = (r: ImageRecord) => need.filter((p) => r.data?.has(p));
  const fits = records.filter((r) => need.every((p) => held(r, p))).sort((a, b) => withData(b).length - withData(a).length || a.packs - b.packs || a.programs.size - b.programs.size || a.profile.localeCompare(b.profile));
  if (!fits.length) return keep(`no one job image's record holds ${list(need)}`, need);
  const [best, ...also] = fits;
  const what = need.length ? `${list(need)} ${need.length > 1 ? "are" : "is"} in its record` : "the command runs nothing but bash's own builtins";
  const data = withData(best);
  const dataNote = data.length ? `; its record carries the data ${list(data)} reads` : "";
  return { profile: best.profile, ref: best.ref, choice: { how: "programs", why: `the smallest job image that holds what the command runs${data.length ? ", preferring one with the data it reads" : ""}: ${what}${dataNote}${also.length ? ` (also in ${list(also.map((r) => r.profile))})` : ""}`, ...(need.length ? { programs: need } : {}) } };
}
