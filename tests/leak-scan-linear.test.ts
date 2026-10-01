/**
 * The package's hygiene scan (scripts/package-tools.ts leakScan) is linear
 * in the bytes it reads, whatever the number of words and digests it looks
 * for. On the Breadcrumbs run the package step's scan ran two hours at full
 * CPU: some 2,700 sensitive words and 1,600 sensitive digests, each searched
 * for on its own over every 32 MiB of a 1.37 GB job stderr.log. Here:
 *
 * - on random small packages it finds exactly what the old word-by-word
 *   search found (that search is kept below as the reference): text, bytes,
 *   UTF-16, JSON escapes, case, the short-word rule, binary files, digests;
 * - a word across a window boundary is found, and a short word whose longer
 *   run continues past the boundary is still judged by its context;
 * - a 64 MiB synthetic log with as many words and digests as that package
 *   had is scanned within a bound the old search could not meet (it took
 *   minutes for this much), and only the planted words are found.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readSync, writeSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { leakScan, SCAN_WINDOW, type LeakHit, type ScanToken } from "../scripts/package-tools.ts";
import { MultiMatch } from "../scripts/multi-match.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

// --- the old search, word by word, kept as the reference ------------------------------------

const SHORT_WORD = 8;
const RUN_WINDOW = 64;
const isDigit = (c: number | undefined) => c !== undefined && c >= 0x30 && c <= 0x39;
const isLetter = (c: number | undefined) => c !== undefined && ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a));
const isHex = (c: number | undefined) => isDigit(c) || (c !== undefined && ((c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)));
const isBase64 = (c: number | undefined) => isDigit(c) || isLetter(c) || c === 0x2b || c === 0x2f;
const isBase64Url = (c: number | undefined) => isDigit(c) || isLetter(c) || c === 0x2d || c === 0x5f;
function partOfLongerRun(at: (k: number) => number | undefined, n: number): boolean {
  if ((isDigit(at(0)) && isDigit(at(-1))) || (isDigit(at(n - 1)) && isDigit(at(n)))) return true;
  const run = (ok: (c: number | undefined) => boolean): [number, number] | null => {
    for (let k = 0; k < n; k += 1) if (!ok(at(k))) return null;
    let l = 0;
    while (l > -RUN_WINDOW && ok(at(l - 1))) l -= 1;
    let r = n;
    while (r < n + RUN_WINDOW && ok(at(r))) r += 1;
    return [l, r];
  };
  const own = ([l, r]: [number, number], t: (c: number | undefined) => boolean) => {
    for (let k = l; k < r; k += 1) if ((k < 0 || k >= n) && t(at(k))) return true;
    return false;
  };
  const hex = run(isHex);
  if (hex && hex[1] - hex[0] >= 16 && own(hex, isDigit)) return true;
  for (const ok of [isBase64, isBase64Url]) {
    const b = run(ok);
    if (!b || b[1] - b[0] < 20 || !own(b, isDigit) || !own(b, isLetter)) continue;
    let separators = 0;
    for (let k = b[0]; k < b[1]; k += 1) if (!isDigit(at(k)) && !isLetter(at(k))) separators += 1;
    if (separators * 8 < b[1] - b[0]) return true;
  }
  return false;
}
function holdsWord(text: string, word: string): boolean {
  if (!word) return false;
  const short = word.length < SHORT_WORD;
  for (let i = text.indexOf(word); i >= 0; i = text.indexOf(word, i + 1)) {
    if (short && partOfLongerRun((k) => (i + k >= 0 && i + k < text.length ? text.charCodeAt(i + k) : undefined), word.length)) continue;
    return true;
  }
  return false;
}
function bytesHoldWord(buf: Buffer, word: Buffer, unit: 1 | 2, short: boolean): boolean {
  if (!short) return buf.includes(word);
  for (let i = buf.indexOf(word); i >= 0; i = buf.indexOf(word, i + 1)) {
    const at = (k: number): number | undefined => {
      const j = i + k * unit;
      if (j < 0 || j + unit > buf.length) return undefined;
      return unit === 1 ? buf[j] : buf[j]! | (buf[j + 1]! << 8);
    };
    if (!partOfLongerRun(at, word.length / unit)) return true;
  }
  return false;
}
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    if (d.isDirectory()) out.push(...walk(p));
    else if (d.isFile()) out.push(p);
  }
  return out;
}
/** The scan as it was before it was made linear (one window: the files here are small). */
function referenceScan(dir: string, tokens: ScanToken[], o: { digests?: ReadonlySet<string>; filenames?: boolean } = {}): LeakHit[] {
  const hits: LeakHit[] = [];
  const norm = (s: string) => s.replace(/\\"/g, '"').replace(/\\\//g, "/").replace(/\\\\/g, "\\").toLowerCase().replace(/\\/g, "/");
  const wanted = tokens.map((t) => ({ ...t, n: norm(t.token), raw: [Buffer.from(t.token, "utf8"), Buffer.from(t.token, "utf16le"), Buffer.from(t.token.toLowerCase(), "utf8")] }));
  const digests = [...(o.digests ?? [])];
  for (const abs of walk(dir)) {
    const rel = relative(dir, abs).split("\\").join("/");
    const size = lstatSync(abs).size;
    const seen = new Set<string>();
    const note = (commit: string, entry: number, as: string, extra: { output?: string } = {}) => {
      if (seen.has(`${commit}\u0000${as}`)) return;
      seen.add(`${commit}\u0000${as}`);
      hits.push({ path: rel, entry, token_sha256: commit, as, ...(extra.output ? { output: extra.output } : {}) });
    };
    if (o.filenames) for (const w of wanted) if (holdsWord(norm(rel), w.n)) note(w.id ?? sha(w.token), w.seq, "filename", { output: w.output });
    const buf = Buffer.alloc(size);
    const fd = openSync(abs, "r");
    readSync(fd, buf, 0, size, 0);
    closeSync(fd);
    const text = !buf.subarray(0, 8192).includes(0) ? norm(buf.toString("utf8")) : null;
    for (const w of wanted) {
      if (text !== null && holdsWord(text, w.n)) note(w.id ?? sha(w.token), w.seq, "text", { output: w.output });
      else if (w.raw.some((b, k) => bytesHoldWord(buf, b, k === 1 ? 2 : 1, w.token.length < SHORT_WORD))) note(w.id ?? sha(w.token), w.seq, "bytes", { output: w.output });
    }
    if (text !== null) for (const d of digests) if (text.includes(d)) note(`digest:${d.slice(0, 12)}`, 0, "digest");
  }
  return hits;
}

// --- random packages ----------------------------------------------------------------------------

let seed = 20261001;
const rnd = (n: number) => {
  seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
  return (seed >>> 8) % n;
};
const pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)]!;
const ALPHA = "abcdefABCDEF0123456789xyz/\\\"._-+ :";
const randomWord = (min: number, max: number) => Array.from({ length: min + rnd(max - min + 1) }, () => pick([...ALPHA, "é", "ş", "ğ", "Ö"])).join("");
const sortHits = (h: LeakHit[]) => h.map((x) => `${x.path}|${x.entry}|${x.as}|${x.token_sha256}|${x.output ?? ""}`).sort();

test("on random small packages it finds exactly what the word-by-word search found", async () => {
  for (let round = 0; round < 60; round += 1) {
    const d = await mkdtemp(join(tmpdir(), "leak-eq-"));
    dirs.push(d);
    const tokens: ScanToken[] = Array.from({ length: 1 + rnd(12) }, (_, i) => ({ token: rnd(3) ? randomWord(4, 7) : randomWord(8, 24), seq: i + 1, ...(rnd(4) === 0 ? { output: `job j00000${i}, out/x`, id: `hidden-${i}` } : {}) }));
    const digests = new Set(Array.from({ length: rnd(4) }, () => sha(String(rnd(1e9)))));
    const pieces = () => {
      const out: string[] = [];
      for (let k = 0; k < 6 + rnd(20); k += 1) {
        const t = pick(tokens).token;
        out.push(
          pick([
            t,
            t.toUpperCase(),
            t.toLowerCase(),
            JSON.stringify(t).slice(1, -1),
            t.replace(/\//g, "\\"),
            `${randomWord(0, 6)}${t}${randomWord(0, 6)}`,
            `${"0123456789abcdef".repeat(2)}${t}${"fedcba9876543210".repeat(2)}`,
            `${randomWord(2, 30)}`,
            [...digests][0] ?? "nothing",
          ]),
        );
      }
      return out.join(pick([" ", "\n", "", ","]));
    };
    for (let f = 0; f < 3 + rnd(4); f += 1) {
      const body = pieces();
      const kind = rnd(4);
      const bytes = kind === 0 ? Buffer.from(body, "utf16le") : kind === 1 ? Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(body)]) : Buffer.from(body);
      const name = rnd(5) === 0 ? `${pick(tokens).token.replace(/[/\\]/g, "_")}.txt` : `f${f}.${pick(["txt", "json", "bin", "log"])}`;
      const sub = join(d, `sub${rnd(2)}`);
      await mkdir(sub, { recursive: true });
      await writeFile(join(sub, name), bytes);
    }
    const want = sortHits(referenceScan(d, tokens, { digests, filenames: true }));
    const got = sortHits(leakScan(d, tokens, { digests, filenames: true }).hits);
    assert.deepEqual(got, want, `round ${round}`);
  }
});

test("the matcher finds every occurrence of every pattern, overlapping ones too", () => {
  for (let round = 0; round < 200; round += 1) {
    const alpha = 2 + rnd(5);
    const pats = Array.from({ length: 1 + rnd(25) }, () => Buffer.from(Array.from({ length: rnd(6) }, () => 97 + rnd(alpha))));
    const text = Buffer.from(Array.from({ length: rnd(300) }, () => 97 + rnd(alpha)));
    const m = new MultiMatch(pats);
    const got = new Set<string>();
    m.scan(text, (id, end) => {
      for (const o of m.owners[id]!) got.add(`${o}@${end}`);
    });
    const want = new Set<string>();
    pats.forEach((p, i) => {
      if (!p.length) return;
      for (let j = text.indexOf(p); j >= 0; j = text.indexOf(p, j + 1)) want.add(`${i}@${j + p.length}`);
    });
    assert.deepEqual([...got].sort(), [...want].sort(), `round ${round}`);
  }
});

/** A file of `size` bytes of log-like text, with `planted` written at their offsets. */
function logFile(path: string, size: number, planted: Array<[number, string]>): void {
  const lines: string[] = [];
  for (let i = 0; lines.join("\n").length < 1 << 16; i += 1) lines.push(`2026-10-01T16:${String(i % 60).padStart(2, "0")}:07.435Z memprocfs[${7000 + (i % 977)}]: read 0x${(i * 4096).toString(16).padStart(12, "0")} size 4096 status 0 chunk ${i} of the scan, nothing matched`);
  const block = Buffer.from(`${lines.join("\n")}\n`);
  const fd = openSync(path, "w");
  try {
    for (let off = 0; off < size; off += block.length) writeSync(fd, block, 0, Math.min(block.length, size - off), off);
    for (const [at, text] of planted) writeSync(fd, Buffer.from(text), 0, Buffer.byteLength(text), at);
  } finally {
    closeSync(fd);
  }
}

test("a word across a window boundary is found; a short word's run past it still decides", async () => {
  const d = await mkdtemp(join(tmpdir(), "leak-edge-"));
  dirs.push(d);
  const W = SCAN_WINDOW;
  const long = "Kq7-vault-recovery-phrase-41d2";
  const pin = "4821";
  // The long word straddles the boundary; the PIN sits right before it as the start of a hex run that continues past it.
  logFile(join(d, "stderr.log"), W + 4096, [[W - 10, ` ${long} `], [W - 200, ` ${pin}abcdef0123456789abcdef `]]);
  const tokens: ScanToken[] = [{ token: long, seq: 7 }, { token: pin, seq: 8 }];
  const hits = leakScan(d, tokens).hits.map((h) => [h.path, h.entry, h.as]);
  assert.deepEqual(hits, [["stderr.log", 7, "text"]], "the long word across the boundary, never the PIN inside a hex run");
});

test("a 64 MiB log with 2,700 words and 1,600 digests is scanned within the bound, and only the planted ones are found", async () => {
  const d = await mkdtemp(join(tmpdir(), "leak-big-"));
  dirs.push(d);
  await mkdir(join(d, "store", "jobs", "j000445"), { recursive: true });
  const size = 64 * 1024 * 1024;
  const tokens: ScanToken[] = [];
  for (let i = 0; i < 2700; i += 1) {
    const len = i % 30 === 0 ? 4 + (i % 4) : 8 + rnd(300);
    tokens.push({ token: `${i}:${Array.from({ length: len }, () => pick([..."abcdefghijklmnopqrstuvwxyz ABCDEFGHIJ0123456789/._-"])).join("")}`.slice(0, Math.max(4, len)), seq: 1 + (i % 400) });
  }
  const digests = new Set(Array.from({ length: 1600 }, (_, i) => sha(`output ${i}`)));
  const plantedWord = tokens[1234]!;
  const plantedDigest = [...digests][777]!;
  logFile(join(d, "store", "jobs", "j000445", "stderr.log"), size, [
    [1000, ` ${plantedWord.token} `],
    [size / 2 + 13, ` sha256 ${plantedDigest} `],
    [size - 500, ` ${tokens[2]!.token} `],
  ]);
  const t0 = Date.now();
  const r = leakScan(d, tokens, { digests, filenames: true });
  const ms = Date.now() - t0;
  const found = r.hits.map((h) => `${h.entry}|${h.as}|${h.token_sha256}`).sort();
  assert.deepEqual(found, [`0|digest|digest:${plantedDigest.slice(0, 12)}`, `${plantedWord.seq}|text|${sha(plantedWord.token)}`, `${tokens[2]!.seq}|text|${sha(tokens[2]!.token)}`].sort());
  // The old search took minutes for this; the bound leaves a slow CI runner room.
  assert.ok(ms < 45_000, `the scan took ${ms} ms`);
  console.log(`# 64 MiB, ${tokens.length} words, ${digests.size} digests: ${ms} ms`);
});
