/**
 * AES for the tests of aes_schedule_scan and aes_inverse_scan: the cipher, its
 * key expansion and the layouts a decryption routine stores a key in, written
 * here from FIPS-197 and checked against node's own AES before any scanner
 * test relies on them (see the first test of tests/tool-library-folded-runs).
 * Nothing in it is shared with the tools.
 */
import { createHash } from "node:crypto";

function gmul(a: number, b: number): number {
  let r = 0;
  for (; b; b >>= 1) {
    if (b & 1) r ^= a;
    a = ((a << 1) ^ (a & 0x80 ? 0x11b : 0)) & 0xff;
  }
  return r;
}

/** The S-box from its definition: the inverse in GF(2^8), then the affine map. */
export const SBOX: number[] = Array.from({ length: 256 }, (_, x) => {
  let inv = 0;
  if (x) for (let y = 1; y < 256; y++) if (gmul(x, y) === 1) inv = y;
  let s = inv;
  for (let k = 1; k <= 4; k++) s ^= ((inv << k) | (inv >> (8 - k))) & 0xff;
  return s ^ 0x63;
});
const INV_SBOX: number[] = [];
SBOX.forEach((v, i) => (INV_SBOX[v] = i));

/** The expanded key of 16 or 32 bytes: 176 or 240 bytes. */
export function expandKey(key: Buffer): Buffer {
  const nk = key.length / 4;
  const total = (nk + 6 + 1) * 16;
  const w = Buffer.alloc(total);
  key.copy(w);
  let rcon = 1;
  for (let i = nk; i < total / 4; i++) {
    let t = [...w.subarray(4 * (i - 1), 4 * i)];
    if (i % nk === 0) {
      t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
      rcon = gmul(rcon, 2);
    } else if (nk > 6 && i % nk === 4) {
      t = t.map((v) => SBOX[v]);
    }
    for (let j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - nk) + j] ^ t[j];
  }
  return w;
}

const column = (c: number[], m: number[]): number[] =>
  [0, 1, 2, 3].map((i) => gmul(c[i], m[0]) ^ gmul(c[(i + 1) % 4], m[1]) ^ gmul(c[(i + 2) % 4], m[2]) ^ gmul(c[(i + 3) % 4], m[3]));
const MIX = [2, 3, 1, 1];
const INV_MIX = [14, 11, 13, 9];

/** MixColumns, or its inverse, over the 16-byte state (and over a round key). */
export function mixState(s: number[], inverse: boolean): number[] {
  const out: number[] = [];
  for (let c = 0; c < 4; c++) out.push(...column(s.slice(4 * c, 4 * c + 4), inverse ? INV_MIX : MIX));
  return out;
}
// The state is the block in column order, so row r of column c is byte 4c+r.
const shift = (s: number[], dir: 1 | -1): number[] => s.map((_, i) => s[(4 * ((Math.floor(i / 4) + dir * (i % 4) + 4)) % 16 + (i % 4)) % 16]);
const xor = (a: number[], b: ArrayLike<number>): number[] => a.map((v, i) => v ^ b[i]);

export function encryptBlock(block: Buffer, schedule: Buffer): Buffer {
  const rounds = schedule.length / 16 - 1;
  let s = xor([...block], schedule.subarray(0, 16));
  for (let r = 1; r <= rounds; r++) {
    s = shift(s.map((v) => SBOX[v]), 1);
    if (r < rounds) s = mixState(s, false);
    s = xor(s, schedule.subarray(16 * r, 16 * r + 16));
  }
  return Buffer.from(s);
}

/** The equivalent inverse cipher (FIPS-197 5.3.5) over round keys given in the order it uses them. */
export function decryptBlockEquivalent(block: Buffer, usedKeys: Buffer[]): Buffer {
  const rounds = usedKeys.length - 1;
  let s = xor([...block], usedKeys[0]);
  for (let r = 1; r <= rounds; r++) {
    s = shift(s, -1).map((v) => INV_SBOX[v]);
    if (r < rounds) s = mixState(s, true);
    s = xor(s, usedKeys[r]);
  }
  return Buffer.from(s);
}

export type Layout = { reverseRounds: boolean; reverseWords: boolean };

/** The round keys of an expanded key, sixteen bytes each. */
export const roundKeys = (schedule: Buffer): Buffer[] => Array.from({ length: schedule.length / 16 }, (_, r) => schedule.subarray(16 * r, 16 * r + 16));

/**
 * The decryption schedule as a routine holds it: InvMixColumns on every round
 * key but the first and last, then in forward or reverse round order, then
 * the bytes of each word reversed or not.
 */
export function inverseSchedule(key: Buffer, layout: Layout): Buffer {
  const rks = roundKeys(expandKey(key));
  const last = rks.length - 1;
  const mixed = rks.map((rk, r) => (r === 0 || r === last ? Buffer.from(rk) : Buffer.from(mixState([...rk], true))));
  const ordered = layout.reverseRounds ? [...mixed].reverse() : mixed;
  return reverseWords(Buffer.concat(ordered), layout.reverseWords);
}

/** The bytes of every 32-bit word reversed (an array of little-endian words, read as bytes). */
export function reverseWords(b: Buffer, on: boolean): Buffer {
  if (!on) return Buffer.from(b);
  const out = Buffer.from(b);
  for (let i = 0; i < out.length; i += 4) out.subarray(i, i + 4).reverse();
  return out;
}

/** Deterministic noise: sha256 of a counter, as many bytes as asked. */
export function noise(n: number, seed: string): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; Buffer.concat(parts).length < n; i++) parts.push(createHash("sha256").update(`${seed}:${i}`).digest());
  return Buffer.concat(parts).subarray(0, n);
}

/** A key of the given size, from a label. */
export const keyFor = (bytes: 16 | 32, label: string): Buffer => noise(bytes, `key:${label}`);
