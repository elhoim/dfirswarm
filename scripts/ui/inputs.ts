/**
 * The inputs library: the directories the console may hand a swarm as
 * read-only inputs.
 *
 * A kickoff from the web form names a set, never a path. The server resolves
 * the name under one of the roots the operator chose, refuses anything that is
 * not a plain directory right there, and passes the resolved path to
 * `swarm.sh --inputs`. Without that, anyone on the LAN with the token could
 * point the swarm at any directory on the machine, and the agents would read
 * it and the artifacts route would serve it.
 *
 * Roots come from two places. `SWARM_INPUTS_ROOT` (or `swarm.sh ui
 * --inputs-root`, repeatable) names them when the server starts, PATH-style
 * with `:` between several. With `--allow-inputs-root-from-ui` the token
 * holder may also add one from the kickoff form; those are kept in
 * `inputs-roots.json` under the runs directory and survive a restart. The
 * flag is off by default, because a root added over the LAN is the one thing
 * the rule above exists to prevent.
 */
import { lstat, mkdir, readdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";

export type InputSet = {
  /** What a kickoff sends: the root's index and the name, `0:brief`. A bare name means root 0. */
  id: string;
  name: string;
  /** The root this set sits under. */
  root: string;
  root_index: number;
  files: number;
  bytes: number;
  /** Up to a few names, so the picker can show what a set holds. */
  sample: string[];
  /** Disk images directly under the set, the ones `--inputs-image` can attach: dmg, iso, img, sparseimage. */
  images: string[];
};

const IMAGE_EXT = /\.(dmg|iso|img|sparseimage)$/i;
const IMAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$/;

export type InputsRoot = {
  path: string;
  /** `env` when the server was started with it, `ui` when the token holder added it. */
  source: "env" | "ui";
  /** False when the directory is missing; the root stays listed so the operator can see why it is empty. */
  ok: boolean;
};

export class InputsError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const SET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SET_REF = /^(?:(\d{1,2}):)?([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/;
const SAMPLE = 5;
const MAX_WALK = 5000;
const MAX_ROOTS = 16;

export function validInputSetName(name: string): boolean {
  return SET_NAME.test(name) && name !== "." && name !== "..";
}

/** `a:b:c` → three roots, in order, empties and repeats dropped. */
export function parseInputsRoots(spec: string | string[] | undefined): string[] {
  const parts = Array.isArray(spec) ? spec : (spec ?? "").split(":");
  const out: string[] = [];
  for (const raw of parts) {
    const p = raw.trim();
    if (!p) continue;
    const abs = resolve(p);
    if (!out.includes(abs)) out.push(abs);
  }
  return out;
}

/** Count the regular files under a directory, capped, with a few names. */
async function summarize(dir: string): Promise<{ files: number; bytes: number; sample: string[] }> {
  let files = 0;
  let bytes = 0;
  const sample: string[] = [];
  async function walk(current: string, rel: string, depth: number): Promise<void> {
    if (files >= MAX_WALK || depth > 12) return;
    const entries = await readdir(current, { withFileTypes: true }).catch(() => []);
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (files >= MAX_WALK) return;
      const abs = join(current, entry.name);
      const key = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await walk(abs, key, depth + 1);
      } else if (entry.isFile()) {
        files += 1;
        const info = await stat(abs).catch(() => null);
        if (info) bytes += info.size;
        if (sample.length < SAMPLE) sample.push(key);
      }
    }
  }
  await walk(dir, "", 0);
  return { files, bytes, sample };
}

/** The sets under every root: each root's immediate subdirectories, not symlinks. */
export async function listInputSets(roots: string | string[] | undefined): Promise<InputSet[]> {
  const list = typeof roots === "string" ? parseInputsRoots(roots) : (roots ?? []);
  const out: InputSet[] = [];
  for (let i = 0; i < list.length; i++) {
    const base = resolve(list[i]);
    const entries = await readdir(base, { withFileTypes: true }).catch(() => []);
    const here: InputSet[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !validInputSetName(entry.name) || entry.name.startsWith(".")) continue;
      const dir = join(base, entry.name);
      const { files, bytes, sample } = await summarize(dir);
      const images = (await readdir(dir, { withFileTypes: true }).catch(() => []))
        .filter((f) => f.isFile() && IMAGE_EXT.test(f.name) && IMAGE_NAME.test(f.name))
        .map((f) => f.name)
        .sort();
      here.push({ id: `${i}:${entry.name}`, name: entry.name, root: base, root_index: i, files, bytes, sample, images });
    }
    out.push(...here.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)));
  }
  return out;
}

/**
 * The absolute directory a set reference stands for, or an error the route can
 * send back. `0:brief` names root 0's `brief`; a bare `brief` is root 0's too,
 * which is what a client from before there were several roots sends. The name
 * has to be a directory directly under that root, not a symlink, and what it
 * resolves to has to stay under the root.
 */
export async function resolveInputSet(roots: string | string[] | undefined, ref: unknown): Promise<string> {
  const list = typeof roots === "string" ? parseInputsRoots(roots) : (roots ?? []);
  if (list.length === 0) throw new InputsError(400, "inputs are not configured on this server (start it with --inputs-root DIR, or SWARM_INPUTS_ROOT)");
  const m = typeof ref === "string" ? SET_REF.exec(ref) : null;
  if (!m || m[2] === "." || m[2] === ".." || m[2].startsWith(".")) {
    throw new InputsError(400, "inputs must name a set: letters, digits, dot, dash or underscore");
  }
  const index = m[1] === undefined ? 0 : Number(m[1]);
  const name = m[2];
  const root = list[index];
  if (!root) throw new InputsError(404, `no inputs root ${index}`);
  const base = await realpath(resolve(root)).catch(() => null);
  if (!base) throw new InputsError(500, `inputs root ${root} does not exist`);
  const candidate = join(base, name);
  const info = await lstat(candidate).catch(() => null);
  if (!info || !info.isDirectory()) throw new InputsError(404, `no input set named ${name}`);
  const real = await realpath(candidate).catch(() => null);
  if (!real || (real !== base && !real.startsWith(base + sep))) {
    throw new InputsError(400, `input set ${name} points outside the inputs root`);
  }
  return real;
}

/**
 * The roots the token holder added from the form, kept beside the runs so a
 * restart keeps them. Only ever consulted when the server was started with
 * the flag that allows it.
 */
export class RootStore {
  private roots: string[] = [];
  private readonly file: string;
  constructor(file: string) {
    this.file = file;
  }

  async load(): Promise<string[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      this.roots = Array.isArray(raw) ? parseInputsRoots(raw.filter((x): x is string => typeof x === "string")) : [];
    } catch {
      this.roots = [];
    }
    return this.roots;
  }

  list(): string[] {
    return [...this.roots];
  }

  /** Add a directory. It has to be absolute and exist; what is stored is its real path. */
  async add(input: unknown, already: string[]): Promise<string> {
    const p = typeof input === "string" ? input.trim() : "";
    if (!p || !isAbsolute(p)) throw new InputsError(400, "path must be absolute");
    const real = await realpath(p).catch(() => null);
    if (!real) throw new InputsError(404, `${p} does not exist`);
    const info = await stat(real).catch(() => null);
    if (!info?.isDirectory()) throw new InputsError(400, `${p} is not a directory`);
    if (already.includes(real) || this.roots.includes(real)) throw new InputsError(409, `${real} is already an inputs root`);
    if (already.length + this.roots.length >= MAX_ROOTS) throw new InputsError(400, `at most ${MAX_ROOTS} inputs roots`);
    this.roots.push(real);
    await this.save();
    return real;
  }

  async remove(path: string): Promise<boolean> {
    const before = this.roots.length;
    this.roots = this.roots.filter((r) => r !== path);
    if (this.roots.length === before) return false;
    await this.save();
    return true;
  }

  private async save(): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    await writeFile(this.file, JSON.stringify(this.roots, null, 2) + "\n", "utf8");
  }
}

/** Each root with whether it is there, for the form to show. */
export async function describeRoots(env: string[], ui: string[]): Promise<InputsRoot[]> {
  const out: InputsRoot[] = [];
  for (const [list, source] of [[env, "env"], [ui, "ui"]] as const) {
    for (const path of list) {
      const info = await stat(path).catch(() => null);
      out.push({ path, source, ok: Boolean(info?.isDirectory()) });
    }
  }
  return out;
}

/**
 * A disk image inside a set, for `--inputs-image`: the set is resolved like any
 * other, and the file has to be a regular file directly under it with an
 * extension hdiutil can attach. macOS only; the route says so elsewhere.
 */
export async function resolveInputImage(roots: string | string[] | undefined, setRef: unknown, file: unknown): Promise<string> {
  const dir = await resolveInputSet(roots, setRef);
  if (typeof file !== "string" || !IMAGE_NAME.test(file) || !IMAGE_EXT.test(file) || file.includes("/")) {
    throw new InputsError(400, "inputs_image must name a dmg, iso, img or sparseimage file in the set");
  }
  const candidate = join(dir, file);
  const info = await lstat(candidate).catch(() => null);
  if (!info || !info.isFile()) throw new InputsError(404, `no image named ${file} in that set`);
  return candidate;
}
