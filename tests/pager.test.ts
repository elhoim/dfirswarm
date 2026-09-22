import assert from "node:assert/strict";
import { test } from "node:test";
import { pageOf, pageWindow, paginate } from "../ui/src/lib/pager.ts";

test("a page knows where it sits, 1-based and inclusive", () => {
  const p = paginate(229, 50, 2);
  assert.deepEqual({ from: p.from, to: p.to, pages: p.pages }, { from: 51, to: 100, pages: 5 });
  assert.deepEqual({ start: p.start, end: p.end }, { start: 50, end: 100 }, "0-based bounds for slice()");
});

test("the last page is short, not wrong", () => {
  const p = paginate(229, 50, 5);
  assert.deepEqual({ from: p.from, to: p.to }, { from: 201, to: 229 });
  assert.equal(p.end - p.start, 29);
});

test("a page past the end is clamped instead of showing nothing", () => {
  // A filter narrows a list while page 9 is open: the fix is the last page,
  // not an empty screen with no explanation.
  assert.equal(paginate(30, 50, 9).page, 1);
  assert.equal(paginate(229, 50, 99).page, 5);
  assert.equal(paginate(229, 50, 0).page, 1);
  assert.equal(paginate(229, 50, -3).page, 1);
});

test("an empty list is one page that says zero", () => {
  const p = paginate(0, 50, 1);
  assert.deepEqual({ pages: p.pages, from: p.from, to: p.to, total: p.total }, { pages: 1, from: 0, to: 0, total: 0 });
});

test("a nonsense page size cannot divide by zero", () => {
  assert.equal(paginate(10, 0, 1).size, 1);
  assert.equal(paginate(10, Number.NaN, 1).size, 1);
});

test("the page control never grows with the list", () => {
  assert.deepEqual(pageWindow(1, 1), [1]);
  assert.deepEqual(pageWindow(1, 5), [1, 2, "gap", 5]);
  assert.deepEqual(pageWindow(8, 24), [1, "gap", 7, 8, 9, "gap", 24]);
  assert.deepEqual(pageWindow(3, 5), [1, 2, 3, 4, 5], "a single missing number is worse than the number");
  assert.deepEqual(pageWindow(24, 24), [1, "gap", 23, 24]);
});

test("a row index answers which page it is on, for following a live trace", () => {
  assert.equal(pageOf(0, 50), 1);
  assert.equal(pageOf(49, 50), 1);
  assert.equal(pageOf(50, 50), 2);
  assert.equal(pageOf(228, 50), 5);
});
