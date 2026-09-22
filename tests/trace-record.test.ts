import assert from "node:assert/strict";
import { test } from "node:test";
import { ARG_TRUNCATED_KEY, summarizeArgs } from "../extensions/protocol.ts";
import * as consoleSide from "../ui/src/lib/trace-record.ts";

test("the console and the harness agree on the archived clip marker", () => {
  assert.equal(consoleSide.ARG_TRUNCATED_KEY, ARG_TRUNCATED_KEY);
});

test("nothing is clipped, whatever its length", () => {
  // 80, then 2,000, then 20,000: every limit cut something real. The record
  // keeps the whole argument now; a base64 blob is the collector's problem.
  for (const length of [8_000, 21_000, 250_000]) {
    const body = "x".repeat(length);
    const out = summarizeArgs({ body });
    assert.equal(out.body, body, `${length} characters kept whole`);
    assert.equal(out[ARG_TRUNCATED_KEY], undefined, "nothing was clipped, so nothing claims to have been");
  }
});

test("a real shell command survives the trace", () => {
  const command = "ls -la catalog/ work/ 2>/dev/null; ls catalog/ | head; echo '---'; tar tf inputs/iphone.tar | head -40";
  const out = summarizeArgs({ command, timeout: 60 });
  assert.equal(out.command, command);
  assert.equal(out.timeout, 60);
  assert.equal(out[ARG_TRUNCATED_KEY], undefined);
});

test("a structure is recorded as a structure, however big", () => {
  // make_tool refusing a call recorded {name, runtime} and lost the params —
  // so the trace held `param "db" must match …` about something it did not have.
  const small = summarizeArgs({ name: "sqlite_query", params: { db: { type: "string" }, sql: { type: "string" } } });
  assert.deepEqual(small.params, { db: { type: "string" }, sql: { type: "string" } });
  const params: Record<string, string> = {};
  for (let i = 0; i < 4000; i += 1) params[`field_${i}`] = "a description of this field";
  const big = summarizeArgs({ params });
  assert.deepEqual(big.params, params, "a 100 KB structure is still a structure, not an opening");
  assert.equal(big[ARG_TRUNCATED_KEY], undefined);
});

test("null and undefined arguments are left out, and the meta key cannot be forged", () => {
  const out = summarizeArgs({ path: "work/x.md", missing: null, absent: undefined, [ARG_TRUNCATED_KEY]: { path: 99 } });
  assert.deepEqual(out, { path: "work/x.md" });
});

test("a value that cannot be serialised is skipped rather than guessed at", () => {
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const out = summarizeArgs({ ok: true, cyclic, fn: () => 1 });
  assert.deepEqual(out, { ok: true });
});
