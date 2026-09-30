/**
 * The inputs manifest (inputs.json): every file of the evidence with its
 * three digests, every link as the link it is, every special file by its
 * kind, how the evidence is held, and, for a copy, whether it matches its
 * source by names, kinds and sizes, and by content. Written at the kickoff
 * by swarm.sh (write_inputs_manifest) and read by the harness's inputs
 * check, custody and the report.
 *
 * It replaces the Python program swarm.sh carried, byte for byte: the same
 * walk (Python's os.walk, top-down, directories and names in code-point
 * order, links recorded and never followed), the same entries, the same
 * problems and exit status, and the same JSON (Python's json.dump with
 * indent 2: non-ASCII escaped, a float written as one). Its output is
 * compared with that program's in tests/inputs-manifest.test.sh.
 *
 *   node --experimental-strip-types scripts/inputs-manifest.ts <sandbox> <src> <enforce> <guard> <held> [verify] [quarantine] [<name> <src>]...
 */
import { createHash } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readlinkSync, readSync, statSync, unlinkSync, writeFileSync, type Stats } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json } | PyFloat;
/** A number Python writes as a float (json.dump gives 12.0, never 12). */
class PyFloat {
  readonly value: number;
  constructor(value: number) {
    this.value = value;
  }
}

const SEP = Buffer.from("/");
const join = (...parts: Buffer[]): Buffer => {
  const out: Buffer[] = [];
  for (const [i, p] of parts.entries()) {
    if (i && out.length && out[out.length - 1]![out[out.length - 1]!.length - 1] !== 0x2f) out.push(SEP);
    out.push(p);
  }
  return Buffer.concat(out);
};
const b = (s: string): Buffer => Buffer.from(s, "utf8");

/** Python's fsdecode (UTF-8 with surrogateescape) as code points: a byte that is no part of valid UTF-8 is U+DC80..U+DCFF. */
function codePoints(buf: Buffer): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < buf.length) {
    const c = buf[i]!;
    const need = c < 0x80 ? 0 : c >= 0xc2 && c <= 0xdf ? 1 : c >= 0xe0 && c <= 0xef ? 2 : c >= 0xf0 && c <= 0xf4 ? 3 : -1;
    if (need === 0) { out.push(c); i += 1; continue; }
    let ok = need > 0 && i + need <= buf.length - 1;
    let cp = need === 1 ? c & 0x1f : need === 2 ? c & 0x0f : c & 0x07;
    if (ok) {
      for (let k = 1; k <= need; k++) {
        const d = buf[i + k];
        if (d === undefined || (d & 0xc0) !== 0x80) { ok = false; break; }
        cp = (cp << 6) | (d & 0x3f);
      }
    }
    // Overlong forms, surrogates and values past U+10FFFF are not valid UTF-8.
    if (ok && ((need === 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) || (need === 3 && (cp < 0x10000 || cp > 0x10ffff)))) ok = false;
    if (ok) { out.push(cp); i += need + 1; }
    else { out.push(0xdc00 + c); i += 1; }
  }
  return out;
}

/** Python's str ordering over names as the os module decodes them: by code point. */
function pyCompare(a: Buffer, b2: Buffer): number {
  const x = codePoints(a);
  const y = codePoints(b2);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

/** bytes.decode("utf-8", "replace"), as Python does it. */
const disp = (raw: Buffer): string => new TextDecoder("utf-8", { fatal: false }).decode(raw);
function utf8Strict(raw: Buffer): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    return null;
  }
}

/**
 * A name is bytes on disk. One that is not UTF-8 (a Windows-1254 or Latin-1
 * name from an archive, on ext4) is kept exactly as base64 in `<key>_b64`,
 * with a readable `<key>` beside it; a reader opens the bytes.
 */
function named(entry: Record<string, Json>, key: string, raw: Buffer): void {
  const s = utf8Strict(raw);
  if (s !== null) {
    entry[key] = s;
  } else {
    entry[key] = disp(raw);
    entry[`${key}_b64`] = raw.toString("base64");
  }
}

function lstatOrNull(p: Buffer): Stats | null {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}
function statOrNull(p: Buffer): Stats | null {
  try {
    return statSync(p);
  } catch {
    return null;
  }
}
const isLink = (p: Buffer) => lstatOrNull(p)?.isSymbolicLink() === true;
const isDirFollow = (p: Buffer) => statOrNull(p)?.isDirectory() === true;
const isFileFollow = (p: Buffer) => statOrNull(p)?.isFile() === true;

/**
 * Python's os.walk(top), top-down, followlinks=False: each directory's names
 * split into those that are directories (following a link, as scandir's
 * is_dir does) and the rest; `onDir` may reorder the directory names, and
 * the walk descends into them in that order, never through a link. A
 * directory that cannot be listed is passed over, as os.walk does.
 */
function walk(top: Buffer, visit: (dirpath: Buffer, dirnames: Buffer[], filenames: Buffer[]) => void): void {
  let names: Buffer[];
  try {
    names = readdirSync(top, { encoding: "buffer" }) as Buffer[];
  } catch {
    return;
  }
  const dirnames: Buffer[] = [];
  const filenames: Buffer[] = [];
  for (const n of names) (isDirFollow(join(top, n)) ? dirnames : filenames).push(n);
  visit(top, dirnames, filenames);
  for (const d of dirnames) {
    const p = join(top, d);
    if (isLink(p)) continue;
    walk(p, visit);
  }
}

/** The bytes of `p` after `base/`, as os.path.relpath gives them for a path under base. */
function relUnder(p: Buffer, base: Buffer): Buffer {
  const prefix = base[base.length - 1] === 0x2f ? base : Buffer.concat([base, SEP]);
  return p.subarray(0, prefix.length).equals(prefix) ? p.subarray(prefix.length) : p;
}

/** The three digests from one read. */
function digests(p: Buffer): { sha256: string; sha1: string; md5: string } {
  const h256 = createHash("sha256");
  const h1 = createHash("sha1");
  const h5 = createHash("md5");
  const fd = openSync(p, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      const chunk = buf.subarray(0, n);
      h256.update(chunk);
      h1.update(chunk);
      h5.update(chunk);
    }
  } finally {
    closeSync(fd);
  }
  return { sha256: h256.digest("hex"), sha1: h1.digest("hex"), md5: h5.digest("hex") };
}

/** C's strerror for the errors a read can meet, as Python's OSError.strerror says them. */
const STRERROR: Record<string, string> = {
  ENOENT: "No such file or directory",
  EACCES: "Permission denied",
  EPERM: "Operation not permitted",
  EISDIR: "Is a directory",
  ENOTDIR: "Not a directory",
  EIO: "Input/output error",
  ELOOP: "Too many levels of symbolic links",
  ENAMETOOLONG: "File name too long",
  EMFILE: "Too many open files",
  ENXIO: "Device not configured",
  ETIMEDOUT: "Operation timed out",
};

type Kind = [string, number];
function kindSize(st: Stats): Kind {
  if (st.isSymbolicLink()) return ["link", 0];
  if (st.isFile()) return ["file", st.size];
  if (st.isDirectory()) return ["dir", 0];
  return ["special", 0];
}
const kkey = (k: Buffer) => k.toString("latin1");

/** Every name under `top`, as the copy was walked: links as links, each with its kind and size. */
function walkKinds(top: Buffer): Map<string, Kind> {
  const seen = new Map<string, Kind>();
  walk(top, (dirpath, dirnames, filenames) => {
    for (const n of [...dirnames, ...filenames]) {
      const p = join(dirpath, n);
      const st = lstatSync(p);
      seen.set(kkey(relUnder(p, top)), kindSize(st));
    }
  });
  return seen;
}

/** Python's json.dump(obj, indent=2): keys in order, non-ASCII escaped as \\uXXXX, a float as a float. */
function pyJson(v: Json, indent = ""): string {
  const next = `${indent}  `;
  if (v === null) return "null";
  if (v instanceof PyFloat) {
    const r = v.value;
    return Number.isInteger(r) ? `${r}.0` : String(r);
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return pyString(v);
  if (Array.isArray(v)) return v.length ? `[\n${v.map((x) => `${next}${pyJson(x, next)}`).join(",\n")}\n${indent}]` : "[]";
  const keys = Object.keys(v);
  return keys.length ? `{\n${keys.map((k) => `${next}${pyString(k)}: ${pyJson(v[k]!, next)}`).join(",\n")}\n${indent}}` : "{}";
}
function pyString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ch = s[i]!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += `\\u${c.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

/** Python's round(x, 1), for the seconds the content check took. */
const round1 = (x: number): number => Math.round(x * 10) / 10;

function utcStamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function writeInputsManifest(argv: string[]): number {
  const [sandboxArg, src, enforce, guard, held, verify = "0", quarantine = "0", ...pairs] = argv as [string, string, string, string, string, string?, string?, ...string[]];
  const sandbox = b(resolve(sandboxArg));
  const root = join(sandbox, b("inputs"));
  // The evidence's place as the operator's words give it (os.path.join over the sandbox as passed), for the messages.
  const rootSaid = disp(join(b(sandboxArg), b("inputs")));
  // (name, source, where it is under inputs/): one set is inputs/ itself.
  const sets: Array<{ name: string | null; src: Buffer; root: Buffer }> = [];
  for (let i = 0; i + 1 < pairs.length; i += 2) sets.push({ name: pairs[i]!, src: b(pairs[i + 1]!), root: join(root, b(pairs[i]!)) });
  if (!sets.length) sets.push({ name: null, src: b(src), root });
  const rel = (abs: Buffer) => relUnder(abs, sandbox);

  const files: Array<Record<string, Json>> = [];
  let total = 0;
  const spans: Array<[number, number, number]> = [];
  for (const set of sets) {
    const start = files.length;
    const startTotal = total;
    // A set held in place is the link at inputs/<name> (or inputs/ itself): the walk starts through it.
    walk(set.root, (dirpath, dirnames, filenames) => {
      dirnames.sort(pyCompare);
      // A link inside the evidence, to a file or to a directory, is recorded as the link it is, with its target, and never followed.
      const names = [...filenames, ...dirnames.filter((d) => isLink(join(dirpath, d)))].sort(pyCompare);
      for (const name of names) {
        const abs = join(dirpath, name);
        if (isLink(abs)) {
          const target = readlinkSync(abs, { encoding: "buffer" }) as Buffer;
          const entry: Record<string, Json> = {};
          named(entry, "path", rel(abs));
          entry.bytes = 0;
          entry.sha256 = createHash("sha256").update(Buffer.concat([b("link:"), target])).digest("hex");
          named(entry, "link", target);
          files.push(entry);
          continue;
        }
        if (!isFileFollow(abs)) {
          // A FIFO, a socket or a device node: recorded by its kind and never opened.
          const st = lstatSync(abs);
          const kind = st.isFIFO() ? "fifo" : st.isSocket() ? "socket" : st.isCharacterDevice() ? "char" : st.isBlockDevice() ? "block" : null;
          if (kind) {
            const entry: Record<string, Json> = {};
            named(entry, "path", rel(abs));
            entry.bytes = 0;
            entry.sha256 = createHash("sha256").update(`special:${kind}`).digest("hex");
            entry.special = kind;
            files.push(entry);
          }
          continue;
        }
        // The three digests a court and an imager's log speak in, from one read.
        const d = digests(abs);
        const st = statSync(abs, { bigint: true });
        total += Number(st.size);
        const entry: Record<string, Json> = {};
        named(entry, "path", rel(abs));
        entry.bytes = Number(st.size);
        entry.sha256 = d.sha256;
        entry.sha1 = d.sha1;
        entry.md5 = d.md5;
        // The stat after the chmod (copy) or as found (bind, image); the harness trusts the sha while these hold.
        entry.mtime_ms = Number(st.mtimeNs / 1000000n);
        entry.ctime_ms = Number(st.ctimeNs / 1000000n);
        if (held !== "copy") {
          entry.mode = (Number(st.mode) & 0o777).toString(8);
          entry.links = Number(st.nlink);
        }
        files.push(entry);
      }
    });
    spans.push([start, files.length, total - startTotal]);
  }

  // A copy is checked against its source, name by name, kind and size.
  const problems: string[] = [];
  if (held === "copy") {
    for (const set of sets) {
      const under = set.name === null ? Buffer.alloc(0) : Buffer.concat([b(set.name), SEP]);
      const source = new Map<string, Kind>();
      for (const name of readdirSync(set.src, { encoding: "buffer" }) as Buffer[]) {
        const p = join(set.src, name);
        const key = kkey(name);
        const subs = (base: string) => {
          for (const [sub, ks] of walkKinds(p)) source.set(`${base}/${sub}`, ks);
        };
        if (isLink(p) && isDirFollow(p)) {
          source.set(key, ["dir", 0]);
          subs(key);
        } else if (isLink(p) && isFileFollow(p)) {
          source.set(key, kindSize(statSync(p)));
        } else {
          source.set(key, kindSize(lstatSync(p)));
          if (source.get(key)![0] === "dir") subs(key);
        }
      }
      const copy = walkKinds(set.root);
      const byBytes = (a: string, c: string) => Buffer.compare(Buffer.from(a, "latin1"), Buffer.from(c, "latin1"));
      const said = (k: string) => disp(Buffer.concat([under, Buffer.from(k, "latin1")]));
      for (const key of [...source.keys()].sort(byBytes)) {
        const c = copy.get(key);
        const s = source.get(key)!;
        if (!c) problems.push(`not in the copy: ${said(key)}`);
        else if (c[0] !== s[0] || c[1] !== s[1]) problems.push(`differs from its source (${s[0]} ${s[1]}, copied as ${c[0]} ${c[1]}): ${said(key)}`);
      }
      for (const key of [...copy.keys()].filter((k) => !source.has(k)).sort(byBytes)) problems.push(`in the copy but not in the source: ${said(key)}`);
    }
  }

  // And, unless --no-verify-copy, by content: each copied file's source is read again and its SHA-256 compared.
  let contentCheck: { by: string; files: number; mismatches: number; seconds: PyFloat } | null = null;
  if (held === "copy" && verify === "1" && !problems.length) {
    const started = Date.now();
    const regular: Array<[Record<string, Json>, Buffer, Buffer]> = [];
    for (const [k, set] of sets.entries()) {
      const [lo, hi] = spans[k]!;
      const under = set.name === null ? b("inputs/") : Buffer.concat([b("inputs/"), b(set.name), SEP]);
      for (const e of files.slice(lo, hi)) if (!("special" in e) && !("link" in e) && !("link_b64" in e)) regular.push([e, set.src, under]);
    }
    const want = regular.reduce((s, [e]) => s + (e.bytes as number), 0);
    let done = 0;
    let nextNote = 2 * 2 ** 30;
    let hashed = 0;
    const differ: string[] = [];
    for (const [e, setSrc, under] of regular) {
      const raw = "path_b64" in e ? Buffer.from(e.path_b64 as string, "base64") : b(e.path as string);
      const sourcePath = join(setSrc, raw.subarray(under.length));
      const h = createHash("sha256");
      try {
        const fd = openSync(sourcePath, "r");
        try {
          const buf = Buffer.allocUnsafe(1 << 20);
          for (;;) {
            const n = readSync(fd, buf, 0, buf.length, null);
            if (n <= 0) break;
            h.update(buf.subarray(0, n));
            done += n;
            if (want > 2 * 2 ** 30 && done >= nextNote) {
              process.stderr.write(`Copy check:   ${(done / 2 ** 30).toFixed(1)} of ${(want / 2 ** 30).toFixed(1)} GiB read again from the source\n`);
              nextNote += 2 * 2 ** 30;
            }
          }
        } finally {
          closeSync(fd);
        }
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? "";
        differ.push(`could not be read again from its source (${STRERROR[code] ?? (err as Error).message}): ${disp(raw)}`);
        continue;
      }
      hashed += 1;
      if (h.digest("hex") !== e.sha256) differ.push(`differs from its source by content: ${disp(raw)}`);
    }
    contentCheck = { by: "content", files: hashed, mismatches: differ.length, seconds: new PyFloat(round1((Date.now() - started) / 1000)) };
    problems.push(...differ);
  }

  // Several sets: `source` names every one, and `sets` says which set each name under inputs/ is, and where it came from.
  const manifest: Record<string, Json> = { source: sets[0]!.name === null ? disp(b(src)) : sets.map((s) => disp(s.src)).join(", ") };
  if (sets[0]!.name !== null) {
    manifest.sets = sets.map((s, k) => ({ name: s.name!, path: `inputs/${s.name}`, source: disp(s.src), files: spans[k]![1] - spans[k]![0], bytes: spans[k]![2] }));
  }
  Object.assign(manifest, {
    copied_at: utcStamp(),
    files,
    bytes: total,
    enforce,
    guard,
    digests: ["sha256", "sha1", "md5"],
    quarantine: quarantine === "1",
  });
  const cc = contentCheck ? { by: contentCheck.by, files: contentCheck.files, mismatches: contentCheck.mismatches, seconds: contentCheck.seconds } : null;
  if (held === "copy") manifest.source_checked = problems.length ? (cc ?? "MISMATCH") : (cc ?? "names, kinds and sizes");
  // How the evidence is held, always said.
  manifest.held = held;
  if (held === "bind") manifest.bound = true;
  else if (held === "image") manifest.attached = true;
  // A manifest left read-only by an earlier kickoff is replaced, not written through.
  const out = join(sandbox, b("inputs.json"));
  if (lstatOrNull(out)) unlinkSync(out);
  writeFileSync(out, `${pyJson(manifest)}\n`);
  if (problems.length) {
    process.stderr.write(`BLOCKER: the copy of the evidence in ${rootSaid} does not match its source ${manifest.source as string} (${problems.length} name${problems.length === 1 ? "" : "s"}):\n`);
    for (const line of problems) process.stderr.write(`  ${line}\n`);
    process.stderr.write("A case-insensitive volume merges names that differ only in case or Unicode form, and a short read leaves a file short. Put the run on a volume that keeps the source's names (a case-sensitive APFS volume or the source's own file system), or use --inputs-bind to hold the evidence in place.\n");
    if (contentCheck && contentCheck.mismatches) process.stderr.write("A file that differs by content was changed while it was copied, or read short: make sure nothing writes to the source, and copy again.\n");
    return 4;
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(writeInputsManifest(process.argv.slice(2)));
