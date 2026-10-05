/**
 * Many byte patterns found in one pass over a buffer (Aho–Corasick): the
 * time a scan takes grows with the bytes read, not with how many patterns
 * are looked for. The package's hygiene scan (package-tools.ts leakScan)
 * looked for every sensitive word and every sensitive digest with its own
 * search over every 32 MiB of every file; on the Breadcrumbs run's package,
 * some 2,700 words and 1,600 digests over a 1.37 GB job stderr.log kept it at
 * full CPU for two hours. One automaton per form reads each byte once.
 *
 * Bytes only, no knowledge of what they are: the caller encodes what it
 * looks for and decides what a match means.
 */

/** A child lookup this wide or wider gets a full row of 256; narrower ones are a short sorted list. */
const DENSE_AT = 6;
/**
 * The shallowest states (breadth first, the root first) get a full row of
 * the automaton's own moves, fail links followed already: where a scan
 * spends nearly all its time, one lookup a byte. 4,096 rows are 4 MiB.
 */
const FULL_ROWS = 4096;

export class MultiMatch {
  /** Each distinct pattern's length in bytes, by its id (the index of its first occurrence in the list given). */
  readonly lengths: Int32Array;
  /** For each id, every index in the list given whose bytes are that pattern (duplicates share one id). */
  readonly owners: number[][];
  private readonly root = new Int32Array(256);
  private readonly fail: Int32Array;
  /** The pattern id ending exactly at a state, or -1. */
  private readonly term: Int32Array;
  /** The nearest state down the fail chain where a pattern ends, or 0. */
  private readonly dict: Int32Array;
  private readonly childStart: Int32Array;
  private readonly childCount: Uint16Array;
  private readonly childByte: Uint8Array;
  private readonly childTarget: Int32Array;
  private readonly denseIndex: Int32Array;
  private readonly dense: Int32Array;
  /** A state's full row in `rows`, or -1. */
  private readonly fullIndex: Int32Array;
  private readonly rows: Int32Array;
  /** 1 where a pattern ends at the state or down its dictionary links. */
  private readonly hasOut: Uint8Array;

  constructor(patterns: ReadonlyArray<Buffer>) {
    // The trie, built as first-child / next-sibling lists.
    let cap = 1024;
    let firstChild = new Int32Array(cap).fill(-1);
    let nextSibling = new Int32Array(cap).fill(-1);
    let byteOf = new Uint8Array(cap);
    let term = new Int32Array(cap).fill(-1);
    let states = 1;
    const grow = () => {
      const n = cap * 2;
      const fc = new Int32Array(n).fill(-1);
      fc.set(firstChild);
      const ns = new Int32Array(n).fill(-1);
      ns.set(nextSibling);
      const bo = new Uint8Array(n);
      bo.set(byteOf);
      const te = new Int32Array(n).fill(-1);
      te.set(term);
      firstChild = fc;
      nextSibling = ns;
      byteOf = bo;
      term = te;
      cap = n;
    };
    const lengths: number[] = [];
    const owners: number[][] = [];
    patterns.forEach((p, index) => {
      if (!p.length) return;
      let s = 0;
      for (let i = 0; i < p.length; i += 1) {
        const b = p[i]!;
        let c = firstChild[s]!;
        while (c !== -1 && byteOf[c] !== b) c = nextSibling[c]!;
        if (c === -1) {
          if (states === cap) grow();
          c = states;
          states += 1;
          byteOf[c] = b;
          nextSibling[c] = firstChild[s]!;
          firstChild[s] = c;
        }
        s = c;
      }
      if (term[s] === -1) {
        term[s] = lengths.length;
        lengths.push(p.length);
        owners.push([index]);
      } else {
        owners[term[s]!]!.push(index);
      }
    });
    this.lengths = Int32Array.from(lengths);
    this.owners = owners;
    // Compact: each state's children sorted by byte, in one array; wide ones also as a full row.
    this.childStart = new Int32Array(states);
    this.childCount = new Uint16Array(states);
    this.childByte = new Uint8Array(Math.max(1, states - 1));
    this.childTarget = new Int32Array(Math.max(1, states - 1));
    this.denseIndex = new Int32Array(states).fill(-1);
    let at = 0;
    let wide = 0;
    const kids: Array<[number, number]> = [];
    for (let s = 0; s < states; s += 1) {
      kids.length = 0;
      for (let c = firstChild[s]!; c !== -1; c = nextSibling[c]!) kids.push([byteOf[c]!, c]);
      kids.sort((a, b) => a[0] - b[0]);
      this.childStart[s] = at;
      this.childCount[s] = kids.length;
      for (const [b, c] of kids) {
        this.childByte[at] = b;
        this.childTarget[at] = c;
        at += 1;
      }
      if (s !== 0 && kids.length >= DENSE_AT) {
        this.denseIndex[s] = wide;
        wide += 1;
      }
    }
    this.dense = new Int32Array(wide * 256).fill(-1);
    for (let s = 1; s < states; s += 1) {
      const d = this.denseIndex[s]!;
      if (d < 0) continue;
      for (let k = this.childStart[s]!, e = k + this.childCount[s]!; k < e; k += 1) this.dense[d * 256 + this.childByte[k]!] = this.childTarget[k]!;
    }
    for (let k = 0, e = this.childCount[0]!; k < e; k += 1) this.root[this.childByte[k]!] = this.childTarget[k]!;
    this.term = term.subarray(0, states).slice();
    // Fail and dictionary links, breadth first.
    this.fail = new Int32Array(states);
    this.dict = new Int32Array(states);
    const queue = new Int32Array(states);
    let head = 0;
    let tail = 0;
    for (let k = 0, e = this.childCount[0]!; k < e; k += 1) queue[tail++] = this.childTarget[k]!;
    while (head < tail) {
      const s = queue[head++]!;
      for (let k = this.childStart[s]!, e = k + this.childCount[s]!; k < e; k += 1) {
        const b = this.childByte[k]!;
        const c = this.childTarget[k]!;
        let f = this.fail[s]!;
        let t = this.child(f, b);
        while (t === -1 && f !== 0) {
          f = this.fail[f]!;
          t = this.child(f, b);
        }
        const fc = t === -1 || t === c ? 0 : t;
        this.fail[c] = fc;
        this.dict[c] = this.term[fc] !== -1 ? fc : this.dict[fc]!;
        queue[tail++] = c;
      }
    }
    this.hasOut = new Uint8Array(states);
    for (let s = 1; s < states; s += 1) this.hasOut[s] = this.term[s] !== -1 || this.dict[s] !== 0 ? 1 : 0;
    // Full rows for the root and the shallowest states: a state's fail
    // target is shallower, so earlier in this order, and has its row already.
    const full = Math.min(states, FULL_ROWS);
    this.fullIndex = new Int32Array(states).fill(-1);
    this.rows = new Int32Array(full * 256);
    this.fullIndex[0] = 0;
    for (let b = 0; b < 256; b += 1) this.rows[b] = this.root[b]!;
    for (let k = 0; k < full - 1; k += 1) {
      const s = queue[k]!;
      const r = k + 1;
      this.fullIndex[s] = r;
      const fr = this.fullIndex[this.fail[s]!]! * 256;
      for (let b = 0; b < 256; b += 1) {
        const c = this.child(s, b);
        this.rows[r * 256 + b] = c !== -1 ? c : this.rows[fr + b]!;
      }
    }
  }

  /** The state reached from `s` on byte `b` along the trie alone, or -1 (the root's missing child is the root). */
  private child(s: number, b: number): number {
    if (s === 0) return this.root[b] || 0;
    const d = this.denseIndex[s]!;
    if (d >= 0) return this.dense[d * 256 + b]!;
    for (let k = this.childStart[s]!, e = k + this.childCount[s]!; k < e; k += 1) {
      const x = this.childByte[k]!;
      if (x === b) return this.childTarget[k]!;
      if (x > b) return -1;
    }
    return -1;
  }

  /**
   * Every occurrence of every pattern in `buf[from, to)`, as `hit(id, end)`
   * with `end` the index just past its last byte; overlapping occurrences
   * all reported. A scan starts at the root.
   */
  scan(buf: Uint8Array, hit: (id: number, end: number) => void, from = 0, to = buf.length): void {
    const term = this.term;
    const dict = this.dict;
    const fail = this.fail;
    const fullIndex = this.fullIndex;
    const rows = this.rows;
    const hasOut = this.hasOut;
    let s = 0;
    for (let i = from; i < to; i += 1) {
      const b = buf[i]!;
      const r = fullIndex[s]!;
      if (r >= 0) {
        s = rows[r * 256 + b]!;
      } else {
        let t = this.child(s, b);
        while (t === -1) {
          s = fail[s]!;
          const fr = fullIndex[s]!;
          t = fr >= 0 ? rows[fr * 256 + b]! : this.child(s, b);
        }
        s = t;
      }
      if (hasOut[s] === 0) continue;
      if (term[s] !== -1) hit(term[s]!, i + 1);
      for (let d = dict[s]!; d !== 0; d = dict[d]!) hit(term[d]!, i + 1);
    }
  }
}
