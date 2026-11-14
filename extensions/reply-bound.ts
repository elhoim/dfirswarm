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

export function rpcAnswerMax(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_RPC_ANSWER_MAX_BYTES);
  return Number.isFinite(n) && n >= 16 * 1024 ? Math.floor(n) : 256 * 1024;
}

export type RpcAnswer = { ok: boolean; result?: unknown; error?: string };
export type Kept = { path: string; bytes: number; sha256: string } | { write_error: string };
/** What an answer cut to the bound says of itself, at the top of an object answer (`answer_cut`): its whole size, the bound, where the whole is, and what was cut. */
export type AnswerCut = { fn: string; bytes: number; max: number; kept?: string; kept_sha256?: string; kept_error?: string; cut: string[]; note: string };

/**
 * The answer to send for `fn`: the answer itself within the bound; past it,
 * the answer with its largest parts cut until it fits (a long text cut with
 * a mark at the cut, a long list cut to its first items, at least one kept),
 * the whole kept by `keep`, and, on an object answer, `answer_cut` saying
 * how large it was, where the whole is and what was cut. The run s5d814f's
 * 76 MB answers closed every seat's link; an answer that said only that it
 * was too large left the seat without the part that fit.
 */
export async function boundRpcAnswer(fn: string, answer: RpcAnswer, keep: (text: string) => Promise<Kept>, max = rpcAnswerMax()): Promise<{ answer: RpcAnswer; cut?: { fn: string; bytes: number; max: number; kept?: string } }> {
  if (UNBOUNDED_FNS.has(fn)) return { answer };
  const text = JSON.stringify(answer);
  const bytes = Buffer.byteLength(text);
  if (bytes <= max) return { answer };
  const kept = await keep(text).catch((err: Error) => ({ write_error: err.message }) as Kept);
  const where = "path" in kept ? `kept whole at ${kept.path} (${kept.bytes} bytes, sha256 ${kept.sha256}): read it in pages (read with offset and limit) for the rest` : `the whole could not be kept (${kept.write_error})`;
  const note = `the hub's answer to ${fn} was ${bytes} bytes, over the bound of ${max} on an answer: what did not fit is cut, ${where}. This is a fault of the harness, not of your call: a narrower request (a filter, a page, an id) answers whole; tell the operator on the board`;
  const mark = "path" in kept ? `[cut by the answer bound: the whole answer is ${kept.path}]` : "[cut by the answer bound]";
  const cuts: string[] = [];
  // Room for the note and the list of cuts beside what is kept.
  const room = Math.max(1024, max - 4096);
  const body = answer.ok ? answer.result : answer.error;
  const shrunk = shrinkToFit(body, room, mark, cuts);
  const info: AnswerCut = { fn, bytes, max, ...("path" in kept ? { kept: kept.path, kept_sha256: kept.sha256 } : { kept_error: kept.write_error }), cut: cuts.slice(0, 20), note };
  const out: RpcAnswer = answer.ok
    ? { ok: true, result: isPlainObject(shrunk) ? { ...shrunk, answer_cut: info } : typeof shrunk === "string" ? `${shrunk}\n(${note})` : shrunk }
    : { ok: false, error: `${String(shrunk)} (${note})` };
  return { answer: out, cut: { fn, bytes, max, ...("path" in kept ? { kept: kept.path } : {}) } };
}

/**
 * A value as it is answered here, without a hub (a host run: the function
 * ran in this process): the same wall, the whole kept by `keep`.
 */
export async function boundLocalAnswer<T>(fn: string, value: T, keep: (text: string) => Promise<Kept>, max = rpcAnswerMax()): Promise<T> {
  if (UNBOUNDED_FNS.has(fn) || value === undefined) return value;
  try {
    const { answer } = await boundRpcAnswer(fn, { ok: true, result: value }, keep, max);
    return answer.result as T;
  } catch {
    // Not JSON (a value only this process can hold): it never crosses a wire, and is answered as it is.
    return value;
  }
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

const bytesOf = (x: unknown): number => Buffer.byteLength(JSON.stringify(x) ?? "");

/**
 * Cut `value` until its JSON is at most `room` bytes: each round the largest
 * string or list in it is cut by what is over (a string to its first
 * characters and `mark`, a list to its first items, one at least), and what
 * was cut is said in `cuts`. Numbers, booleans and short fields are never
 * touched, so the counts and states a caller reads stay as they were.
 */
export function shrinkToFit(value: unknown, room: number, mark: string, cuts: string[]): unknown {
  let v = structuredClone(value);
  for (let round = 0; round < 64; round++) {
    const total = bytesOf(v);
    if (total <= room) return v;
    const over = total - room;
    let best: { size: number; path: Array<string | number>; parent: unknown; key: string | number | null } | null = null;
    const walk = (x: unknown, parent: unknown, key: string | number | null, path: Array<string | number>) => {
      if (typeof x === "string" || Array.isArray(x)) {
        const size = bytesOf(x);
        const cuttable = typeof x === "string" ? x.length > mark.length + 64 : x.length > 1;
        if (cuttable && (!best || size > best.size)) best = { size, path, parent, key };
      }
      if (Array.isArray(x)) x.forEach((y, i) => walk(y, x, i, [...path, i]));
      else if (isPlainObject(x)) for (const [k, y] of Object.entries(x)) walk(y, x, k, [...path, k]);
    };
    walk(v, null, null, []);
    if (!best) return v;
    const b = best as { size: number; path: Array<string | number>; parent: unknown; key: string | number | null };
    const at = b.path.length ? b.path.join(".") : "(the answer)";
    const target = b.key === null ? v : (b.parent as Record<string | number, unknown>)[b.key];
    let next: unknown;
    if (typeof target === "string") {
      // JSON may take more bytes than characters; cut by what is over, as characters, and go round again if need be.
      const keepChars = Math.max(64, target.length - over - mark.length - 32);
      next = `${target.slice(0, keepChars)}… ${mark}`;
      cuts.push(`${at}: ${keepChars} of ${target.length} characters`);
    } else {
      const xs = target as unknown[];
      let size = b.size;
      let n = xs.length;
      while (n > 1 && size > b.size - over) {
        n -= 1;
        size -= bytesOf(xs[n]) + 1;
      }
      next = xs.slice(0, n);
      cuts.push(`${at}: the first ${n} of ${xs.length} items`);
    }
    if (b.key === null) v = next;
    else (b.parent as Record<string | number, unknown>)[b.key] = next;
  }
  return v;
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
