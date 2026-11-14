/**
 * The bound on what the hub answers a seat's board call with.
 *
 * A post has had a bound and a side file since the first runs; an answer
 * had none. On the run s5d814f the "Finish: not ready" line carried every
 * object a partial sweep had not searched (137,703 names) into `wait`,
 * `inbox`, `leads` and the hand-off: 76 MB answers, a request of 19 million
 * tokens, and all eight seats' links closed within ten minutes. Each source
 * of such text is bounded where it is made; this is the wall behind them. An
 * answer past the bound is a fault of the harness: what fits is sent, the
 * rest is cut where it is longest, and the whole is kept in a file of the
 * seat's own kept outputs that the answer names. The wall stands in the hub
 * (scripts/vm-hub.ts) and, for a host run, where board.ts runs the call in
 * the seat's own process.
 */

/**
 * The functions whose answers are read by code to find one item, not by a
 * model: a list cut to the bound would leave the item looked for out, and
 * the call would act on a wrong answer (a forged tool not registered, a
 * revision not restorable). They are exempt from the wall, and only they.
 *
 * - listFileHistory: board.ts restoreFileVersion looks the revision to
 *   restore up in it; an entry is under 300 bytes, so the wall would take
 *   about 900 revisions of one file.
 * - listForgedTools: the seat registers a tool from each manifest it lists
 *   and finds one by name to run it; a manifest is the forge's to bound.
 * - listLedger: the ledger tool (agent-swarm.ts) pages the window itself:
 *   it keeps the whole window among the seat's kept outputs and answers one
 *   page under the inbox bound, naming `next` and `remaining` from the
 *   window's count, which a cut window would make wrong. The window is at
 *   most 500 entries, each within the ledger's field limits.
 *
 * Everything else, a job's answer and a diff included, is held to the wall:
 * what does not fit is cut, and the whole is kept in a file the answer names.
 */
export const UNBOUNDED_FNS: ReadonlySet<string> = new Set(["listFileHistory", "listForgedTools", "listLedger"]);
/** The functions exempt from the wall where the seat's own process runs the call (a host run): nothing crosses a wire. */
export const HOST_UNBOUNDED_FNS: ReadonlySet<string> = UNBOUNDED_FNS;

export function rpcAnswerMax(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_RPC_ANSWER_MAX_BYTES);
  return Number.isFinite(n) && n >= 16 * 1024 ? Math.floor(n) : 256 * 1024;
}

export type RpcAnswer = { ok: boolean; result?: unknown; error?: string };
export type Kept = { path: string; bytes: number; sha256: string } | { write_error: string };
/** What an answer cut to the bound says of itself, at the top of an object answer (`answer_cut`): its whole size, the bound, where the whole is, and what was cut. */
export type AnswerCut = { fn: string; bytes: number; max: number; kept?: string; kept_sha256?: string; kept_error?: string; cut: string[]; note: string };

/** Bytes of the bound kept for what an answer says of its cut (answer_cut: the note, where the whole is, the list of cuts). */
const INFO_ROOM = 8 * 1024;
/** The most cuts an answer names, each at most this many characters. */
const CUTS_SHOWN = 20;
const CUT_CHARS = 200;

/**
 * The answer to send for `fn`: the answer itself within the bound; past it,
 * the answer with its largest parts cut until it fits (shrinkToFit: a long
 * text cut with a mark at the cut, a long list cut to its first items, at
 * least one kept), the whole kept by `keep`, and, on an object answer,
 * `answer_cut` saying how large it was, where the whole is and what was cut.
 * The run s5d814f's 76 MB answers closed every seat's link; an answer that
 * said only that it was too large left the seat without the part that fit.
 *
 * What leaves is always within the bound, measured as it is sent: an answer
 * whose shape alone is past the bound once every text and list in it is cut
 * (tens of thousands of short fields) is answered with a stub that says so
 * and names the file that keeps the whole, never sent over the bound with a
 * note that says it was cut.
 */
export async function boundRpcAnswer(fn: string, answer: RpcAnswer, keep: (text: string) => Promise<Kept>, max = rpcAnswerMax()): Promise<{ answer: RpcAnswer; cut?: { fn: string; bytes: number; max: number; kept?: string } }> {
  if (UNBOUNDED_FNS.has(fn)) return { answer };
  const text = JSON.stringify(answer);
  const bytes = Buffer.byteLength(text);
  if (bytes <= max) return { answer };
  const kept = await keep(text).catch((err: Error) => ({ write_error: err.message }) as Kept);
  const name = clip(fn, 120);
  const where = "path" in kept ? `kept whole at ${kept.path} (${kept.bytes} bytes, sha256 ${kept.sha256}): read it in pages (read with offset and limit) for the rest` : `the whole could not be kept (${clip(kept.write_error, 300)})`;
  const mark = "path" in kept ? `[cut by the answer bound: the whole answer is ${kept.path}]` : "[cut by the answer bound]";
  const keptInfo = "path" in kept ? { kept: kept.path, kept_sha256: kept.sha256 } : { kept_error: clip(kept.write_error, 300) };
  const cut = { fn, bytes, max, ...("path" in kept ? { kept: kept.path } : {}) };
  const ask = "This is a fault of the harness, not of your call: a narrower request (a filter, a page, an id) answers whole; tell the operator on the board";
  const cuts: string[] = [];
  // Room for the note and the list of cuts beside what is kept.
  const room = Math.max(1024, max - INFO_ROOM);
  const body = answer.ok ? answer.result : answer.error;
  const shrunk = shrinkToFit(body, room, mark, cuts);
  if (bytesOf(shrunk) <= room) {
    const note = `the hub's answer to ${name} was ${bytes} bytes, over the bound of ${max} on an answer: what did not fit is cut, ${where}. ${ask}`;
    const info: AnswerCut = { fn: name, bytes, max, ...keptInfo, cut: shownCuts(cuts), note };
    const out: RpcAnswer = answer.ok
      ? { ok: true, result: isPlainObject(shrunk) ? { ...shrunk, answer_cut: info } : typeof shrunk === "string" ? `${shrunk}\n(${note})` : shrunk }
      : { ok: false, error: `${String(shrunk)} (${note})` };
    if (bytesOf(out) <= max) return { answer: out, cut };
  }
  // Nothing of it fits: its shape alone is past the bound with every text and list in it cut. A stub says so and where the whole is.
  const note = `the hub's answer to ${name} was ${bytes} bytes, over the bound of ${max} on an answer, and none of it is sent: even with every text and list in it cut, its shape alone is past the bound; ${where}. ${ask}`;
  const info: AnswerCut = { fn: name, bytes, max, ...keptInfo, cut: [], note };
  const out: RpcAnswer = answer.ok && isPlainObject(body) ? { ok: true, result: { answer_cut: info } } : answer.ok && typeof body === "string" ? { ok: true, result: `(${note})` } : { ok: false, error: note };
  return { answer: out, cut };
}

function clip(text: string, n: number): string {
  return text.length <= n ? text : `${text.slice(0, n - 1)}…`;
}

/** The cuts an answer names: the first CUTS_SHOWN, each at most CUT_CHARS characters, and how many more. */
function shownCuts(cuts: string[]): string[] {
  const shown = cuts.slice(0, CUTS_SHOWN).map((c) => clip(c, CUT_CHARS));
  return cuts.length > CUTS_SHOWN ? [...shown, `and ${cuts.length - CUTS_SHOWN} more cuts`] : shown;
}

/**
 * A value as it is answered here, without a hub (a host run: the function
 * ran in this process): the same wall, the whole kept by `keep`. An answer
 * none of which fits is refused with what the hub would have said, as the
 * hub's refusal reaches a seat (board.ts callBoard).
 */
export async function boundLocalAnswer<T>(fn: string, value: T, keep: (text: string) => Promise<Kept>, max = rpcAnswerMax()): Promise<T> {
  if (HOST_UNBOUNDED_FNS.has(fn) || value === undefined) return value;
  let bounded: RpcAnswer;
  try {
    bounded = (await boundRpcAnswer(fn, { ok: true, result: value }, keep, max)).answer;
  } catch {
    // Not JSON (a value only this process can hold): it never crosses a wire, and is answered as it is.
    return value;
  }
  if (!bounded.ok) throw new Error(bounded.error);
  return bounded.result as T;
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

const bytesOf = (x: unknown): number => Buffer.byteLength(JSON.stringify(x) ?? "");

/** Rounds of the largest part first before every text, then every list, is cut to one length. */
const LARGEST_ROUNDS = 8;
/** A text is cut to no fewer characters than this. */
const TEXT_KEEP_MIN = 64;

type Part = { x: unknown; parent: unknown; key: string | number | null; up: number };

/** Every value in `v`, with where it sits (its parent, its key, the index of its parent's entry): walked without recursion, so a deep answer cannot end the walk. */
function parts(v: unknown): Part[] {
  const out: Part[] = [];
  const stack: Part[] = [{ x: v, parent: null, key: null, up: -1 }];
  while (stack.length) {
    const n = stack.pop()!;
    out.push(n);
    const here = out.length - 1;
    if (Array.isArray(n.x)) for (let i = n.x.length - 1; i >= 0; i--) stack.push({ x: n.x[i], parent: n.x, key: i, up: here });
    else if (isPlainObject(n.x)) for (const [k, y] of Object.entries(n.x).reverse()) stack.push({ x: y, parent: n.x, key: k, up: here });
  }
  return out;
}

/** Where a part sits, as the keys from the answer's top joined by dots ("(the answer)" for the top itself). */
function pathOf(all: Part[], i: number): string {
  const keys: Array<string | number> = [];
  for (let at = i; at >= 0 && all[at]!.key !== null; at = all[at]!.up) keys.unshift(all[at]!.key!);
  return keys.length ? keys.join(".") : "(the answer)";
}

/**
 * Cut `value` until its JSON is at most `room` bytes, and say what was cut
 * in `cuts`. Numbers, booleans, keys and short texts are never touched, so
 * the counts and states a caller reads stay as they were.
 *
 * 1. The largest part first, a few rounds: the largest string or list is cut
 *    by what is over (a string to its first characters and `mark`, a list to
 *    its first items, one at least). One long text or one long list most
 *    often holds what is over, and this cuts nothing else. A largest part
 *    that cannot take all that is over and is not half the answer is one of
 *    many alike, and is left to the next step.
 * 2. Then every text longer than one length is cut to it, the longest length
 *    that fits (found by halving, each try measured as it would be sent):
 *    two hundred texts of 10 KB each are cut alike in one pass, where cutting
 *    one a round ran out of rounds.
 * 3. Then every list longer than one count is cut to it, the same way.
 *
 * What is left over `room` after the three is the answer's shape itself
 * (tens of thousands of short fields); the caller does not send it.
 */
export function shrinkToFit(value: unknown, room: number, mark: string, cuts: string[]): unknown {
  let v = structuredClone(value);
  for (let round = 0; round < LARGEST_ROUNDS; round++) {
    const total = bytesOf(v);
    if (total <= room) return v;
    const over = total - room;
    const all = parts(v);
    let best = -1;
    let bestSize = 0;
    all.forEach((p, i) => {
      const cuttable = typeof p.x === "string" ? p.x.length > mark.length + TEXT_KEEP_MIN : Array.isArray(p.x) && p.x.length > 1;
      if (!cuttable) return;
      const size = bytesOf(p.x);
      if (size > bestSize) {
        best = i;
        bestSize = size;
      }
    });
    if (best < 0) break;
    const b = all[best] as Part & { x: string | unknown[] };
    const at = pathOf(all, best);
    let next: unknown;
    let said: string;
    let absorbs: boolean;
    if (typeof b.x === "string") {
      // JSON may take more bytes than characters; cut by what is over, as characters, and go round again if need be.
      const want = b.x.length - over - mark.length - 32;
      const keepChars = Math.max(TEXT_KEEP_MIN, want);
      absorbs = want >= TEXT_KEEP_MIN;
      next = `${b.x.slice(0, keepChars)}… ${mark}`;
      said = `${at}: ${keepChars} of ${b.x.length} characters`;
    } else {
      const xs = b.x;
      let size = bestSize;
      let n = xs.length;
      while (n > 1 && size > bestSize - over) {
        n -= 1;
        size -= bytesOf(xs[n]) + 1;
      }
      absorbs = size <= bestSize - over;
      next = xs.slice(0, n);
      said = `${at}: the first ${n} of ${xs.length} items`;
    }
    // A part that cannot take all that is over, and is not most of the answer, is one of many alike: they are cut together below.
    if (!absorbs && bestSize * 2 < total) break;
    cuts.push(said);
    if (b.key === null) v = next;
    else (b.parent as Record<string | number, unknown>)[b.key] = next;
  }
  if (bytesOf(v) <= room) return v;
  const tail = `… ${mark}`;
  const cutText = (x: string, c: number): string => (x.length > c + tail.length ? `${x.slice(0, c)}${tail}` : x);
  v = capAll(
    v,
    room,
    (c) => (_k: string, x: unknown) => (typeof x === "string" ? cutText(x, c) : x),
    parts(v).reduce((m, p) => (typeof p.x === "string" ? Math.max(m, p.x.length) : m), 0),
    TEXT_KEEP_MIN,
    (c, n) => cuts.push(`every text longer than ${c} characters (${n} of them): its first ${c} characters`),
    (c) => parts(v).filter((p) => typeof p.x === "string" && p.x.length > c + tail.length).length,
  );
  if (bytesOf(v) <= room) return v;
  v = capAll(
    v,
    room,
    (k) => (_key: string, x: unknown) => (Array.isArray(x) && x.length > k ? x.slice(0, k) : x),
    parts(v).reduce((m, p) => (Array.isArray(p.x) ? Math.max(m, p.x.length) : m), 0),
    1,
    (k, n) => cuts.push(`every list longer than ${k} items (${n} of them): its first ${k}`),
    (k) => parts(v).filter((p) => Array.isArray(p.x) && p.x.length > k).length,
  );
  return v;
}

/**
 * `v` with one length applied to every part it cuts (`cutAt(n)`, a JSON
 * replacer): the largest `n` from `least` to `most` whose answer fits
 * `room`, found by halving the ratio between what fits and what does not
 * (each try measured as it would be sent), or `least` when nothing does.
 * `said(n, count)` names the cut.
 */
function capAll(v: unknown, room: number, cutAt: (n: number) => (key: string, x: unknown) => unknown, most: number, least: number, said: (n: number, count: number) => void, count: (n: number) => number): unknown {
  if (most <= least) return v;
  const size = (n: number) => Buffer.byteLength(JSON.stringify(v, cutAt(n) as (this: unknown, key: string, x: unknown) => unknown) ?? "");
  let lo = least;
  let hi = most;
  if (size(lo) <= room) {
    // lo fits and hi does not: halve the ratio between them until they are close.
    while (hi - lo > 1 && hi / lo > 1.1) {
      const mid = Math.max(lo + 1, Math.min(hi - 1, Math.floor(Math.sqrt(lo * hi))));
      if (size(mid) <= room) lo = mid;
      else hi = mid;
    }
  }
  const n = count(lo);
  if (!n) return v;
  said(lo, n);
  return JSON.parse(JSON.stringify(v, cutAt(lo) as (this: unknown, key: string, x: unknown) => unknown));
}

/** One item of a list in a header or digest, cut to a bound with a mark that it was cut. */
export function boundItem(item: string, max = 400): string {
  return item.length <= max ? item : `${item.slice(0, max - 40)}… (${item.length} characters; whole in finish status)`;
}

/**
 * A list of gate items for a header that every answer carries: the caller's own first, each cut to a bound, at most
 * `show` of them, and the rest as a count. `mine` says which items are the caller's.
 */
export function boundItems(items: readonly string[], mine: (item: string) => boolean, o: { show?: number; each?: number } = {}): { text: string; total: number; own: number; shown: number } {
  const show = o.show ?? 6;
  const own = items.filter(mine);
  const others = items.filter((i) => !mine(i));
  const picked = [...own, ...others].slice(0, show).map((i) => boundItem(i, o.each ?? 400));
  const rest = items.length - picked.length;
  const text = `${picked.join("; ")}${rest > 0 ? `${picked.length ? "; " : ""}and ${rest} more (finish status lists every one)` : ""}`;
  return { text, total: items.length, own: own.length, shown: picked.length };
}
