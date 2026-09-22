/**
 * Paging, as arithmetic.
 *
 * A trace of 229 calls, a ledger of 57 entries and an artifact index of 131
 * files were all one endless column: past the first screenful, scrolling
 * stops telling you where you are. Paging gives a list a shape — "51–100 of
 * 229" — and a way back to a row you saw a minute ago.
 *
 * The arithmetic lives here rather than in the component because it is the
 * part that goes wrong: an off-by-one at the end of a page hides a row, and
 * a page that survives a filter change shows an empty one.
 */

/** Where one page sits in a list. `from`/`to` are 1-based and inclusive. */
export type Page = {
  /** 1-based, clamped into the list that exists. */
  page: number;
  pages: number;
  size: number;
  total: number;
  from: number;
  to: number;
  /** 0-based slice bounds, for `rows.slice(start, end)`. */
  start: number;
  end: number;
};

export function paginate(total: number, size: number, page: number): Page {
  const safeSize = Math.max(1, Math.floor(size) || 1);
  const pages = Math.max(1, Math.ceil(total / safeSize));
  const current = Math.min(Math.max(1, Math.floor(page) || 1), pages);
  const start = (current - 1) * safeSize;
  const end = Math.min(total, start + safeSize);
  return {
    page: current,
    pages,
    size: safeSize,
    total,
    start,
    end,
    from: total === 0 ? 0 : start + 1,
    to: end,
  };
}

/**
 * The page numbers to draw, with gaps.
 *
 * `[1, "gap", 7, 8, 9, "gap", 24]` — first and last are always reachable, and
 * the current page keeps its neighbours, so the control never grows with the
 * list. `span` is how many numbers sit around the current one.
 */
export function pageWindow(page: number, pages: number, span = 1): Array<number | "gap"> {
  if (pages <= 1) return [1];
  const wanted = new Set<number>([1, pages, page]);
  for (let i = 1; i <= span; i += 1) {
    if (page - i >= 1) wanted.add(page - i);
    if (page + i <= pages) wanted.add(page + i);
  }
  // A single missing number is a worse gap than the number itself.
  const sorted = [...wanted].sort((a, b) => a - b);
  const out: Array<number | "gap"> = [];
  let previous = 0;
  for (const n of sorted) {
    if (previous && n - previous === 2) out.push(previous + 1);
    else if (previous && n - previous > 2) out.push("gap");
    out.push(n);
    previous = n;
  }
  return out;
}

/** Which page a row index (0-based) falls on — for "jump to the newest". */
export function pageOf(index: number, size: number): number {
  return Math.floor(Math.max(0, index) / Math.max(1, size)) + 1;
}
