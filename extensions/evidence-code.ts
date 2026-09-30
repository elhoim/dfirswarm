/**
 * Code from the evidence, run (the limits spec, item 3; c10 run sd9645b).
 *
 * What is pulled out of the evidence is read, never run: `work/extracted/`
 * and `work/quarantine/` are mounted no-exec in every VM, `inputs/` too, and
 * the prompt says "hash, strings, disassemble, parse; never run". On sd9645b
 * one seat's password-test jobs each wrote a small Node script and ran it
 * with `node`: the script read a crypto library recovered from a browser
 * cache blob (an earlier job's sealed output, store/jobs/<id>/out/…) and
 * evaluated it with `vm.runInContext` (or `runInThisContext`), then called
 * its routines per candidate. The run said so itself afterwards, on the
 * board and in a limitation. Nothing refused it, for two reasons that hold
 * for any interpreter: no-exec stops the kernel executing a file, not an
 * interpreter reading one (`python file.py`, `node file.js`, `eval` of its
 * bytes), and a job's output under store/ is not a no-exec area at all.
 *
 * A mount cannot tell reading from running when an interpreter does both,
 * so this does not refuse. It names, from a command's own words, a command
 * that runs or evaluates code from an evidence-derived place, so it is
 * flagged where it happens (the reply to the seat, the trace) and in the
 * report (the job's method record):
 * - `runs`: an interpreter, a shell or a browser given such a path as its
 *   script (its options first), fed one on its stdin, or piped one;
 * - `evaluates`: a construct of a language that evaluates code (`eval`,
 *   `exec`, `compile`, `new Function`, `vm.runIn…`, `vm.Script`, `runpy`,
 *   `importlib`, `require`/`import`) given such a path, or a name bound to
 *   what was read from one (`p = 'store/jobs/…'; sj = readFileSync(p);
 *   vm.runInContext(sj, ctx)`).
 * It reads words, not meaning: the words are languages' and shells', never a
 * forensic tool's; a script that takes its path from its arguments or its
 * environment, or recovered code copied elsewhere first, is not seen. A
 * flag says "may have": the seat or a reviewer says whether it did.
 *
 * A path that is an output of the seat's own command job (a helper an
 * earlier job of its own wrote) is said apart (`own`): code the seat wrote
 * itself is not the evidence's, and only the seat can say whether that job
 * wrote it or recovered it from the evidence, so it is still flagged, never
 * dropped. `require` of a JSON file loads data, not code, and is not
 * flagged (the Fable review of the limits branch, P3-4).
 */

/** Where evidence-derived bytes are, as a command names them: the evidence, what was extracted or quarantined from it, a job's sealed output, an import. */
export const EVIDENCE_AREAS = ["inputs/", "work/extracted/", "work/quarantine/", "store/jobs/", "store/imports/"] as const;

/** A job input that is evidence-derived: the evidence itself, an earlier job's output, an import, a catalogue member, an object by digest. */
const DERIVED_INPUT = /^(?:input|job|import|member|sha256):/;

/**
 * Programs that run their first operand as code: languages' interpreters,
 * shells, and a browser given a file. Their options come first; the first
 * word that is not one is the script.
 */
export const INTERPRETERS = [
  "python", "python2", "python3", "pypy", "pypy3", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "luajit",
  "Rscript", "tclsh", "java", "jshell", "groovy", "osascript", "pwsh", "powershell", "wscript", "cscript", "mshta",
  "bash", "sh", "zsh", "dash", "ksh", "fish", "busybox", "source", ".", "wine", "chromium", "chromium-browser", "google-chrome", "chrome", "firefox",
] as const;

/**
 * Constructs that evaluate code at run time, by language, each opening its
 * argument list: it counts only when what it is given comes from an
 * evidence-derived place (evaluatesEvidence). A method of the same name
 * (`re.exec(`, `re.compile(`) is not one.
 */
const EVALUATES: ReadonlyArray<[string, RegExp]> = [
  ["vm.runIn…", /\bvm\s*\.\s*(?:runIn\w+|compileFunction)\s*\(/g],
  ["vm.Script", /\bnew\s+vm\s*\.\s*(?:Script|SourceTextModule)\s*\(/g],
  ["new Function", /\bnew\s+Function\s*\(/g],
  ["eval", /(?<![.\w$])eval\s*\(/g],
  ["exec", /(?<![.\w$])exec\s*\(/g],
  ["execfile", /(?<![.\w$])execfile\s*\(/g],
  ["compile", /(?<![.\w$])compile\s*\(/g],
  ["runpy", /\brunpy\s*\.\s*run_\w+\s*\(/g],
  ["importlib", /\bimportlib\s*\.\s*(?:import_module|util\s*\.\s*spec_from_file_location)\s*\(/g],
  ["require", /(?<![.\w$])(?:require|import)\s*\(/g],
];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const AREAS = EVIDENCE_AREAS.map(escape).join("|");
/** Before an area, as a path names it: nothing, `./`, or an absolute directory (the run's own, as a VM mounts it). */
const LEAD = `(?:\\./|/(?:[^\\s'"=(:,<>\`;|&]*/)?)?`;
/** An evidence-derived path in a command's words, as it names it (a leading ./ or an absolute prefix up to the area is kept out). */
const AREA_PATH = new RegExp(`(?:^|[\\s'"=(:,<>\`])${LEAD}((?:${AREAS})[^\\s'";|&)<>\`,]*)`, "g");
/** A quoted evidence-derived path. */
const QUOTED_AREA = new RegExp(`['"\`]${LEAD}(?:${AREAS})`);
const WORDS = INTERPRETERS.map(escape).join("|");
/** An interpreter at the head of a command: after the start, a newline, `;`, `&`, `(`, a backtick, `$(`, or a pipe. */
const PROGRAM = `(?:^|[\\n;&(\`]|\\$\\(|\\|)\\s*(?:[A-Za-z_]\\w*=\\S*\\s+)*(?:/(?:[^\\s;&|(]*/)?)?(${WORDS})(?:\\d+(?:\\.\\d+)*)?(?:\\.exe)?`;
const SCRIPT = `['"]?${LEAD}((?:${AREAS})[^\\s'";|&)]*)`;
const RUNS_ARG = new RegExp(`${PROGRAM}\\s+(?:-{1,2}[A-Za-z][\\w-]*(?:=\\S+)?\\s+)*${SCRIPT}`, "m");
const RUNS_STDIN = new RegExp(`${PROGRAM}(?:\\s+-)?\\s*<\\s*${SCRIPT}`, "m");
const PIPED = new RegExp(`\\|\\s*(?:/(?:[^\\s;&|(]*/)?)?(${WORDS})(?:\\d+(?:\\.\\d+)*)?(?:\\s+-)?\\s*(?:$|[;&|)])`, "m");

/**
 * How a command runs evidence-derived code: `runs` (an interpreter, shell or
 * browser given such a path as its script) or `evaluates` (a construct that
 * evaluates code, given what was read from such a place), what did it, and
 * the evidence-derived paths or inputs it names; `own`, those of them that
 * are outputs of the seat's own command jobs, and the jobs (ownJobOutputs).
 */
export type EvidenceCode = { how: "runs" | "evaluates"; what: string; paths: string[]; own?: { paths: string[]; jobs: string[] } };

/** The evidence-derived paths a command names, each once, in order. */
export function evidencePaths(command: string): string[] {
  const out: string[] = [];
  for (const m of String(command ?? "").matchAll(AREA_PATH)) if (!out.includes(m[1])) out.push(m[1]);
  return out;
}

/**
 * A command's words with every quoted text that is more than one word (a
 * grep pattern, a code string) blanked: an interpreter's name inside a
 * pattern (`'a|bash|sudo'`) is not a command. A quoted path stays.
 */
function commandWords(text: string): string {
  return text.replace(/'[^'\n]*'|"(?:[^"\\\n]|\\.)*"/g, (q) => (/[\s|;&]/.test(q.slice(1, -1)) ? `${q[0]}${" ".repeat(Math.max(0, q.length - 2))}${q[0]}` : q));
}

/**
 * Whether a command (a shell command, or a job's) runs or evaluates code
 * from an evidence-derived place, from its words; for a job, the inputs it
 * declares are named with the paths. Null when it does not appear to. A
 * flag, never a refusal.
 */
export function evidenceCodeRun(command: string, inputs: readonly unknown[] = []): EvidenceCode | null {
  const text = String(command ?? "");
  if (!text.trim()) return null;
  const paths = evidencePaths(text);
  if (!paths.length) return null;
  const words = commandWords(text);
  const r = RUNS_ARG.exec(words) ?? RUNS_STDIN.exec(words);
  if (r) return { how: "runs", what: r[1], paths: [r[2]] };
  const piped = PIPED.exec(words);
  if (piped) return { how: "runs", what: piped[1], paths };
  const hit = evaluatesEvidence(text);
  return hit ? { how: "evaluates", what: hit, paths: [...paths, ...inputs.map(String).filter((x) => DERIVED_INPUT.test(x))] } : null;
}

/** The argument list a construct opens at `from` (just past its parenthesis), up to its closing one (at most 2,000 characters). */
function argsAt(text: string, from: number): string {
  let depth = 1;
  let i = from;
  for (; i < text.length && i < from + 2000; i += 1) {
    const c = text[i];
    if (c === "(") depth += 1;
    else if (c === ")" && --depth === 0) break;
  }
  return text.slice(from, i);
}

/**
 * Which evaluation construct in a command is given what it read from an
 * evidence-derived place, or null: its argument names such a path, or a
 * name bound to one. A name is bound by an assignment whose right side
 * names such a path or a name bound already (`p = 'store/jobs/…'; sj =
 * fs.readFileSync(p)`), or by `open('…') as f`. What a script reads from its
 * own arguments or its environment is not followed.
 */
export function evaluatesEvidence(text: string): string | null {
  const bound = new Set<string>();
  for (const m of text.matchAll(new RegExp(`open\\s*\\(\\s*['"]${LEAD}(?:${AREAS})[^)]*\\)\\s+as\\s+([A-Za-z_]\\w*)`, "g"))) bound.add(m[1]);
  const assigns = [...text.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]*)/g)].map((m) => ({ name: m[1], rhs: m[2] }));
  const names = (s: string) => [...bound].some((n) => new RegExp(`(?<![.\\w$])${escape(n)}(?![\\w$])`).test(s));
  for (let changed = true, round = 0; changed && round < 8; round += 1) {
    changed = false;
    for (const a of assigns) {
      if (bound.has(a.name) || !(QUOTED_AREA.test(a.rhs) || names(a.rhs))) continue;
      bound.add(a.name);
      changed = true;
    }
  }
  for (const [what, re] of EVALUATES) {
    for (const m of text.matchAll(re)) {
      const args = argsAt(text, m.index! + m[0].length);
      // A JSON file required is data, not code.
      if (what === "require" && /^\s*['"`][^'"`]*\.json['"`]\s*$/i.test(args)) continue;
      if (QUOTED_AREA.test(args) || names(args)) return what;
    }
  }
  return null;
}

/** The job an evidence-derived path or input is an output of (store/jobs/<id>/…, job:<id>/…), or null. */
export function outputJobOf(path: string): string | null {
  return /^(?:store\/jobs\/|job:)(j\d{6,})(?:\/|$)/.exec(path)?.[1] ?? null;
}

/** A job as a flag reads it: who asked for it, and its kind. */
export type JobOrigin = { requester?: { agent?: string } | null; spec?: { kind?: string } | null };

/**
 * The paths of a flag that are outputs of `seat`'s own command jobs (the
 * job record's requester is the seat, its kind command), and those jobs:
 * code the seat may have written itself. Said apart, never dropped: its own
 * command job may also have recovered what it runs from the evidence.
 */
export function ownJobOutputs(x: EvidenceCode, seat: string, job: (id: string) => JobOrigin | null | undefined): { paths: string[]; jobs: string[] } {
  const paths: string[] = [];
  const jobs: string[] = [];
  for (const p of x.paths) {
    const id = outputJobOf(p);
    const j = id ? job(id) : null;
    if (!id || !j || j.requester?.agent !== seat || j.spec?.kind !== "command") continue;
    paths.push(p);
    if (!jobs.includes(id)) jobs.push(id);
  }
  return { paths, jobs };
}

/** A flag with its own-job outputs read from the run's job records (store/jobs/<id>/job.json), when there are any. */
export async function withOwnJobOutputs(sandboxRoot: string, x: EvidenceCode, seat: string): Promise<EvidenceCode> {
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const records = new Map<string, JobOrigin | null>();
  for (const p of x.paths) {
    const id = outputJobOf(p);
    if (!id || records.has(id)) continue;
    records.set(id, await readFile(join(sandboxRoot, "store", "jobs", id, "job.json"), "utf8").then((t) => JSON.parse(t) as JobOrigin).catch(() => null));
  }
  const own = ownJobOutputs(x, seat, (id) => records.get(id));
  return own.paths.length ? { ...x, own } : x;
}

/** Whether every path a flag names is an output of the seat's own command jobs. */
export function onlyOwnOutputs(x: EvidenceCode): boolean {
  return Boolean(x.own?.paths.length) && x.paths.every((p) => x.own!.paths.includes(p));
}

/** What the seat is told when a command of its runs or evaluates evidence-derived code: the rule, why the mount did not stop it, and what to do instead. */
export function evidenceCodeNote(x: EvidenceCode, where: "job" | "shell"): string {
  const own = x.own?.paths.length ? ownWords(x) : "";
  return `Note from the harness: this ${where === "job" ? "job's command" : "command"} ${x.how === "runs" ? `runs ${x.paths.join(", ")} with ${x.what}` : `evaluates code (${x.what}) it read from ${x.paths.join(", ")}`}: code recovered from the evidence may have been executed.${own ? ` ${own}` : ""} What comes out of the evidence is read, never run: no-exec stops the kernel running a file, not an interpreter reading it, and a job's output under store/ is not no-exec at all. Reimplement what the recovered code does, or use a trusted program that does it, and cite the recovered code as what you read. If it did run, say so in the ledger (a limitation on what rests on it); if only running it will do, ask the operator first (lead_close needs_operator). This is flagged on the trace and in the report.`;
}

/** The own-job outputs of a flag in words: which paths, which jobs, and what that does and does not mean. */
export function ownWords(x: EvidenceCode): string {
  if (!x.own?.paths.length) return "";
  const all = onlyOwnOutputs(x);
  return `${all ? (x.own.paths.length === 1 ? "It is" : "Each is") : `Of these, ${x.own.paths.join(", ")} ${x.own.paths.length === 1 ? "is" : "are"}`} an output of ${x.own.jobs.length === 1 ? "a command job" : "command jobs"} this seat asked for (${x.own.jobs.join(", ")}): code the seat wrote there itself is not the evidence's; code ${x.own.jobs.length === 1 ? "that job" : "those jobs"} recovered from the evidence is.`;
}
