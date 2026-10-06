// aes_inverse_scan: find AES-128 and AES-256 key schedules stored the way a
// decryption routine keeps them, in a file or a memory image, at every byte
// alignment.
//
// The equivalent inverse cipher (FIPS-197, section 5.3.5) decrypts with the
// round keys of the encryption schedule in reverse use, with InvMixColumns
// applied to every one but the first and the last. A library that sets up a
// decryption key (OpenSSL's AES_set_decrypt_key, the AES-NI kernels) therefore
// holds a schedule that aes_schedule_scan, which tests the encryption layout,
// does not see. This finds it in four layouts: the rounds in reverse order
// (the usual one) or in forward order, each with the bytes of every 32-bit
// word as they are or reversed. A hit is checked whole: the key is read back
// from the first and second round keys, expanded, transformed the way the
// layout says, and compared with every byte of the schedule.
//
// It never prints a key: each distinct key (the original, encryption-side key)
// goes to a private file (mode 0600) in out_dir, and the result names the
// offset, the key size, the layout and the key's sha256 for the ledger. A hit
// is a lead: the schedule may belong to any program or to nobody.
//
// What it does not test: AES-192, decayed or fragmented schedules, and the
// plain encryption layout (aes_schedule_scan).
//
// Args, JSON on stdin: path (the file), out_dir, start and length (a byte
// window of the file, default all of it), chunk_bytes, budget_seconds. A call
// that stops on its budget says complete=false and the start to carry on from.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const TOOL = "aes_inverse_scan";
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
const MUL = {};
for (const n of [1, 2, 3, 9, 11, 13, 14]) MUL[n] = Uint8Array.from({ length: 256 }, (_, x) => gmul(x, n));

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

/** MixColumns (or its inverse) of one 4-byte column. */
function mixColumn(c, inverse) {
  const f = inverse ? [14, 11, 13, 9] : [2, 3, 1, 1];
  return [0, 1, 2, 3].map((i) => MUL[f[0]][c[i]] ^ MUL[f[1]][c[(i + 1) % 4]] ^ MUL[f[2]][c[(i + 2) % 4]] ^ MUL[f[3]][c[(i + 3) % 4]]);
}

// FIPS-197: the S-box, MixColumns on its example column and the inverse on all
// of a sweep of columns, and the last round key of a 128-bit and a 256-bit
// expansion. A table or an expansion that is wrong stops the tool here.
if (Buffer.from(SBOX.slice(0, 16)).toString("hex") !== "637c777bf26b6fc53001672bfed7ab76") fail("self-check failed: S-box");
if (Buffer.from(mixColumn([0xdb, 0x13, 0x53, 0x45], false)).toString("hex") !== "8e4da1bc") fail("self-check failed: MixColumns");
for (let x = 0; x < 256; x++) {
  const c = [x, (x + 1) & 255, (x + 53) & 255, (x + 199) & 255];
  if (mixColumn(mixColumn(c, true), false).some((v, i) => v !== c[i])) fail("self-check failed: InvMixColumns");
}
for (const [key, last] of [
  ["2b7e151628aed2a6abf7158809cf4f3c", "d014f9a8c9ee2589e13f0cc8b6630ca6"],
  ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "fe4890d1e6188d0b046df344706c631e"],
]) {
  if (expandKey(Buffer.from(key, "hex")).subarray(-16).toString("hex") !== last) fail("self-check failed: key expansion");
}

// --- the layouts ---------------------------------------------------------------
// Round k's key is stored at round index k (forward order) or Nr-k (reverse
// order), sixteen bytes each, rounds 1..Nr-1 InvMixColumns-transformed. The
// transform is linear and works word by word, so the key expansion's plain
// relation w[i] = w[i-Nk] ^ w[i-1] holds between stored words too: w9 = w5 ^ w8
// for AES-128 and w13 = w5 ^ w12 for AES-256, all in transformed rounds. That
// relation is the filter; a whole schedule is checked only where it holds.
const roundsOf = (keyBytes) => keyBytes / 4 + 6;
const wordOffset = (keyBytes, reverseRounds, w) => {
  const round = Math.floor(w / 4);
  return (reverseRounds ? roundsOf(keyBytes) - round : round) * 16 + 4 * (w % 4);
};
const RELATIONS = [];
for (const keyBytes of [16, 32]) {
  const [a, b, c] = keyBytes === 16 ? [5, 8, 9] : [5, 12, 13];
  for (const reverseRounds of [false, true]) {
    RELATIONS.push({ keyBytes, reverseRounds, a: wordOffset(keyBytes, reverseRounds, a), b: wordOffset(keyBytes, reverseRounds, b), c: wordOffset(keyBytes, reverseRounds, c) });
  }
}

/** The key read from a schedule at b[p..] laid out this way, or null when it is not a whole, correct one. */
function verify(b, p, keyBytes, reverseRounds, reversedWords) {
  const rounds = roundsOf(keyBytes);
  const total = SCHEDULE[keyBytes];
  if (p + total > b.length) return null;
  const at = (i) => b[p + (i & ~3) + (reversedWords ? 3 - (i & 3) : i & 3)];
  const first = (reverseRounds ? rounds : 0) * 16;
  const second = (reverseRounds ? rounds - 1 : 1) * 16;
  const key = Buffer.alloc(keyBytes);
  for (let j = 0; j < 16; j++) key[j] = at(first + j);
  if (keyBytes === 32) {
    // The second half of a 256-bit key is the first round's key, stored transformed.
    for (let j = 0; j < 16; j += 4) {
      const c = mixColumn([0, 1, 2, 3].map((i) => at(second + j + i)), false);
      for (let i = 0; i < 4; i++) key[16 + j + i] = c[i];
    }
  }
  const z = expandKey(key);
  for (let q = 16; q < (rounds) * 16; q += 4) {
    const c = mixColumn([z[q], z[q + 1], z[q + 2], z[q + 3]], true);
    for (let i = 0; i < 4; i++) z[q + i] = c[i];
  }
  for (let i = 0; i < total; i++) {
    const round = i >> 4;
    if (at(i) !== z[(reverseRounds ? rounds - round : round) * 16 + (i & 15)]) return null;
  }
  return key;
}

/** The hits in b at positions [from, to). */
function scanBuffer(b, from, to, counters, found) {
  for (let p = from; p < to; p++) {
    for (const rel of RELATIONS) {
      if (p + SCHEDULE[rel.keyBytes] > b.length) continue;
      const a = p + rel.a, bb = p + rel.b, c = p + rel.c;
      // The three words all zero satisfy the relation and say nothing.
      if ((b[a] | b[a + 1] | b[a + 2] | b[a + 3] | b[bb] | b[bb + 1] | b[bb + 2] | b[bb + 3] | b[c] | b[c + 1] | b[c + 2] | b[c + 3]) === 0) continue;
      if (b[c] !== (b[a] ^ b[bb]) || b[c + 1] !== (b[a + 1] ^ b[bb + 1]) || b[c + 2] !== (b[a + 2] ^ b[bb + 2]) || b[c + 3] !== (b[a + 3] ^ b[bb + 3])) continue;
      counters.prefilter++;
      for (const reversedWords of [false, true]) {
        counters.full++;
        const key = verify(b, p, rel.keyBytes, rel.reverseRounds, reversedWords);
        if (key) found(p, rel.keyBytes, rel.reverseRounds, reversedWords, key);
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
const budget = args.budget_seconds ?? 240;
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
function found(offset, keyBytes, reverseRounds, reversedWords, key) {
  const id = `${offset}:${keyBytes}:${reverseRounds}:${reversedWords}`;
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
  hits.push({ offset, offset_hex: `0x${offset.toString(16)}`, key_bits: keyBytes * 8, round_order: reverseRounds ? "reversed" : "forward", word_order: reversedWords ? "reversed-each-32bit-word" : "standard", schedule_bytes: SCHEDULE[keyBytes], key_sha256: digest, key_file: file });
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
    scanBuffer(buf, 0, scanEnd - pos, counters, (p, kb, rr, rw, key) => found(pos + p, kb, rr, rw, key));
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
  supported: "complete AES-128 and AES-256 equivalent-inverse schedules: InvMixColumns on the middle rounds, the first and last round as they are, rounds in forward or reverse order, bytes of each 32-bit word as they are or reversed",
  not_supported: "AES-192, decayed or fragmented schedules, the plain encryption layout (aes_schedule_scan)",
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
