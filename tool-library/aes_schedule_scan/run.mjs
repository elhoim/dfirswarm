// aes_schedule_scan: find complete AES-128 and AES-256 expanded key schedules
// in a file or a memory image, at every byte alignment.
//
// A cipher that is in use keeps its expanded key in memory: 176 bytes for
// AES-128 and 240 for AES-256, laid out so that every word follows from the
// words before it (FIPS-197, section 5.2). This reads the source once, tests
// every position against the first relations of that expansion and checks a
// whole schedule only where they hold, in two byte orders: as the standard
// lays it out, and with the bytes of each 32-bit word reversed (the schedule
// as an array of little-endian words). It never prints a key: each distinct
// key goes to a private file (mode 0600) in out_dir, and the result names the
// offset, the key size, the byte order and the key's sha256, so the hash can
// go in the ledger and the file can be tried against the evidence.
//
// A hit is a lead, not a finding: the schedule may belong to any program or to
// nobody. What this does not test: AES-192, a schedule with decayed bits, a
// schedule split across pages, and the decryption (equivalent inverse)
// layout, which aes_inverse_scan reads.
//
// Args, JSON on stdin: path (the file), out_dir, start and length (a byte
// window of the file, default all of it), chunk_bytes, budget_seconds. A call
// that stops on its budget says complete=false and the start to carry on from.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const TOOL = "aes_schedule_scan";
const SCHEDULE = { 16: 176, 32: 240 }; // key bytes -> expanded schedule bytes
const MAX_REACH = 240;
const INLINE_HITS = 200;

function fail(message, extra = {}) {
  process.stdout.write(`${JSON.stringify({ ok: false, error: message, ...extra })}\n`);
  process.exit(1);
}

// --- the tables, built and then checked against the standard ----------------
function gmul(x, y) {
  let z = 0;
  while (y) {
    if (y & 1) z ^= x;
    x = ((x << 1) ^ (x & 128 ? 0x11b : 0)) & 255;
    y >>= 1;
  }
  return z;
}
function gpow(x, n) {
  let y = 1;
  while (n) {
    if (n & 1) y = gmul(y, x);
    x = gmul(x, x);
    n >>= 1;
  }
  return y;
}
const rol = (x, n) => ((x << n) | (x >> (8 - n))) & 255;
const SBOX = Uint8Array.from({ length: 256 }, (_, x) => {
  const y = x ? gpow(x, 254) : 0;
  return y ^ rol(y, 1) ^ rol(y, 2) ^ rol(y, 3) ^ rol(y, 4) ^ 0x63;
});

function expandKey(key) {
  const nk = key.length / 4;
  const total = SCHEDULE[key.length];
  const w = Buffer.alloc(total);
  key.copy(w);
  let rcon = 1;
  for (let p = key.length; p < total; p += 4) {
    let t = [w[p - 4], w[p - 3], w[p - 2], w[p - 1]];
    const i = p / 4;
    if (i % nk === 0) {
      t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
      rcon = gmul(rcon, 2);
    } else if (nk === 8 && i % nk === 4) {
      t = t.map((x) => SBOX[x]);
    }
    for (let j = 0; j < 4; j++) w[p + j] = w[p - key.length + j] ^ t[j];
  }
  return w;
}

// FIPS-197 appendix A: the S-box, and the last round key of a 128-bit and a
// 256-bit expansion. A table or an expansion that is wrong stops the tool here.
if (Buffer.from(SBOX.slice(0, 16)).toString("hex") !== "637c777bf26b6fc53001672bfed7ab76") fail("self-check failed: S-box");
for (const [key, last] of [
  ["2b7e151628aed2a6abf7158809cf4f3c", "d014f9a8c9ee2589e13f0cc8b6630ca6"],
  ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "fe4890d1e6188d0b046df344706c631e"],
]) {
  if (expandKey(Buffer.from(key, "hex")).subarray(-16).toString("hex") !== last) fail("self-check failed: key expansion");
}

// --- one position -----------------------------------------------------------
/** The key read from a schedule at b[p..], or null when the schedule is not a whole, correct one. */
function verify(b, p, keyBytes, reversedWords) {
  const total = SCHEDULE[keyBytes];
  if (p + total > b.length) return null;
  const at = (i) => b[p + (i & ~3) + (reversedWords ? 3 - (i & 3) : i & 3)];
  const key = Buffer.alloc(keyBytes);
  for (let i = 0; i < keyBytes; i++) key[i] = at(i);
  const expected = expandKey(key);
  for (let i = keyBytes; i < total; i++) if (expected[i] !== at(i)) return null;
  return key;
}

/** The hits in b at positions [from, to). */
function scanBuffer(b, from, to, counters, found) {
  for (let p = from; p < to; p++) {
    if (p + SCHEDULE[16] > b.length) break;
    // A region of zeros satisfies every relation below; skip it at once.
    if ((b[p] | b[p + 1] | b[p + 2] | b[p + 3] | b[p + 12] | b[p + 13] | b[p + 14] | b[p + 15] | b[p + 16] | b[p + 17] | b[p + 18] | b[p + 19] | b[p + 28] | b[p + 29] | b[p + 30] | b[p + 31] | b[p + 32] | b[p + 33] | b[p + 34] | b[p + 35]) === 0) continue;
    for (const keyBytes of [16, 32]) {
      if (p + SCHEDULE[keyBytes] > b.length) continue;
      const q = p + keyBytes;
      // The word after the first round's: w[Nk+1] = w[1] ^ w[Nk].
      if (b[q + 4] !== (b[p + 4] ^ b[q]) || b[q + 5] !== (b[p + 5] ^ b[q + 1]) || b[q + 6] !== (b[p + 6] ^ b[q + 2]) || b[q + 7] !== (b[p + 7] ^ b[q + 3])) continue;
      counters.prefilter++;
      const r = p + keyBytes - 4;
      for (const reversedWords of [false, true]) {
        // w[Nk] = w[0] ^ SubWord(RotWord(w[Nk-1])) ^ rcon(1), in either byte order.
        const first = reversedWords
          ? b[q] === (b[p] ^ SBOX[b[r + 3]]) && b[q + 1] === (b[p + 1] ^ SBOX[b[r]]) && b[q + 2] === (b[p + 2] ^ SBOX[b[r + 1]]) && b[q + 3] === (b[p + 3] ^ SBOX[b[r + 2]] ^ 1)
          : b[q] === (b[p] ^ SBOX[b[r + 1]] ^ 1) && b[q + 1] === (b[p + 1] ^ SBOX[b[r + 2]]) && b[q + 2] === (b[p + 2] ^ SBOX[b[r + 3]]) && b[q + 3] === (b[p + 3] ^ SBOX[b[r]]);
        if (!first) continue;
        counters.full++;
        const key = verify(b, p, keyBytes, reversedWords);
        if (key) found(p, keyBytes, reversedWords, key);
      }
    }
  }
}

// --- arguments, the output directory ----------------------------------------
let args;
try {
  args = JSON.parse(fs.readFileSync(0, "utf8") || "{}");
} catch (e) {
  fail("the arguments are not JSON", { reason: String(e.message ?? e) });
}
const whole = (name, dflt, low, high) => {
  const v = args[name] ?? dflt;
  if (typeof v !== "number" || !Number.isInteger(v) || v < low || v > high) fail(`${name} must be a whole number from ${low} to ${high}`, { got: v });
  return v;
};
if (typeof args.path !== "string" || !args.path) fail("path is required: the file or memory image to scan");
let size;
try {
  const st = fs.statSync(args.path);
  if (!st.isFile()) fail("path is not a regular file", { path: args.path });
  size = st.size;
} catch (e) {
  fail(`cannot read ${args.path}`, { reason: String(e.code ?? e.message ?? e) });
}
const chunk = whole("chunk_bytes", 16 * 1024 * 1024, MAX_REACH * 2, 1 << 30);
const start = whole("start", 0, 0, Number.MAX_SAFE_INTEGER);
const end = Math.min(size, start + whole("length", Math.max(0, size - start), 0, Number.MAX_SAFE_INTEGER));
const budget = args.budget_seconds ?? 90;
if (typeof budget !== "number" || !(budget > 0)) fail("budget_seconds must be a positive number", { got: budget });
if (start > size) fail("start is past the end of the file", { start, size });

/** A path with the links of its nearest existing part resolved, for a place that may not exist yet. */
function realish(p) {
  const rest = [];
  let here = p;
  while (!fs.existsSync(here) && path.dirname(here) !== here) {
    rest.unshift(path.basename(here));
    here = path.dirname(here);
  }
  return path.join(fs.realpathSync(here), ...rest);
}

/** Where out_dir lands: inside the run directory, never under inputs/, ledger/ or tools/. */
function resolveOutput(given) {
  const root = fs.realpathSync(process.cwd());
  const job = process.env.JOB_ID && process.env.OUT;
  const agent = (process.env.AGENT_ID || "tool").replace(/[^A-Za-z0-9_.-]/g, "_");
  const want = given ?? (job ? path.join(process.env.OUT, TOOL) : path.join("work", agent, TOOL));
  if (typeof want !== "string" || !want) fail("out_dir must be a path", { got: want });
  const dest = realish(path.resolve(root, want));
  if (dest === root || !dest.startsWith(root + path.sep)) fail("out_dir must be a directory inside the run directory", { out_dir: want });
  for (const owned of ["inputs", "ledger", "tools"]) {
    const place = path.join(root, owned);
    if (dest === place || dest.startsWith(place + path.sep)) fail(`out_dir cannot be under ${owned}/`, { out_dir: want });
  }
  return dest;
}
const outDir = resolveOutput(args.out_dir);
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

// --- the scan -----------------------------------------------------------------
const counters = { prefilter: 0, full: 0 };
const hits = [];
const seen = new Set();
const keyFiles = new Set();
function found(offset, keyBytes, reversedWords, key) {
  const id = `${offset}:${keyBytes}:${reversedWords}`;
  if (seen.has(id)) return;
  seen.add(id);
  const digest = createHash("sha256").update(key).digest("hex");
  const file = `key-${digest.slice(0, 16)}.bin`;
  if (!keyFiles.has(file)) {
    keyFiles.add(file);
    try {
      fs.writeFileSync(path.join(outDir, file), key, { flag: "wx", mode: 0o600 });
    } catch (e) {
      if (e.code !== "EEXIST" || !fs.readFileSync(path.join(outDir, file)).equals(key)) fail("cannot write a key file", { reason: String(e.code ?? e.message) });
    }
  }
  hits.push({ offset, offset_hex: `0x${offset.toString(16)}`, key_bits: keyBytes * 8, word_order: reversedWords ? "reversed-each-32bit-word" : "standard", schedule_bytes: SCHEDULE[keyBytes], key_sha256: digest, key_file: file });
}

const fd = fs.openSync(args.path, "r");
const started = performance.now();
let pos = start;
try {
  while (pos < end) {
    // At least one chunk a call, so that every call makes progress.
    if (pos > start && (performance.now() - started) / 1000 >= budget) break;
    const scanEnd = Math.min(end, pos + chunk);
    // The positions [pos, scanEnd) are tested; the bytes past scanEnd are read
    // so that a schedule that starts inside the chunk is whole.
    const readEnd = Math.min(size, scanEnd + MAX_REACH - 1);
    const buf = Buffer.allocUnsafe(readEnd - pos);
    let got = 0;
    while (got < buf.length) {
      const n = fs.readSync(fd, buf, got, buf.length - got, pos + got);
      if (!n) fail("the file ended before its size said", { at: pos + got, size });
      got += n;
    }
    scanBuffer(buf, 0, scanEnd - pos, counters, (p, kb, rw, key) => found(pos + p, kb, rw, key));
    pos = scanEnd;
  }
} finally {
  fs.closeSync(fd);
}

const complete = pos >= end;
const result = {
  ok: true,
  tool: TOOL,
  source: { path: args.path, bytes: size },
  window: { start, end },
  scanned_to: pos,
  complete,
  ...(complete ? {} : { next_start: pos }),
  chunk_bytes: chunk,
  all_byte_alignments: true,
  supported: "complete forward AES-128 and AES-256 schedules, standard byte order or each 32-bit word reversed",
  not_supported: "AES-192, decayed or fragmented schedules, the decryption (equivalent inverse) layout (aes_inverse_scan)",
  prefilter_candidates: counters.prefilter,
  full_schedule_checks: counters.full,
  seconds: (performance.now() - started) / 1000,
  hit_count: hits.length,
  hits,
  note: "A key is never printed. Each key_file holds the raw key bytes (mode 0600); key_sha256 is what to record in the ledger. A hit is a lead until it decrypts something the evidence holds.",
};
const resultFile = path.join(outDir, `${TOOL}.${start}.json`);
fs.writeFileSync(resultFile, JSON.stringify(result, null, 2));
const shown = { ...result, hits: hits.slice(0, INLINE_HITS), result_file: path.relative(process.cwd(), resultFile) };
if (hits.length > INLINE_HITS) shown.hits_inline = INLINE_HITS;
process.stdout.write(`${JSON.stringify(shown)}\n`);
