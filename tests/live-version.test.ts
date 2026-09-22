/**
 * Which changes the finish line refetches on. The console runs the goal's
 * own shell checks through the server, so being too eager costs the host a
 * process and being too narrow leaves a swarm looking uncertified after it
 * has finished. Both have happened.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ALL_CHANGE_KINDS, CHECKS_CHANGE_KINDS, CHECKS_IGNORED_KINDS, shouldReloadChecks } from "../ui/src/lib/live-version.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("the finish line reloads on anything a check could read, and not on a lease or a spend fold", () => {
  // The shipped goals read work/, team.json, the trace, the ledger and the board.
  for (const kind of ["work", "done", "team", "events", "ledger", "threads", "inputs", "registry", "contract"]) {
    assert.equal(shouldReloadChecks([kind]), true, `${kind} can change a check's answer`);
  }
  for (const kind of CHECKS_IGNORED_KINDS) {
    assert.equal(shouldReloadChecks([kind]), false, `${kind} cannot`);
  }
  assert.equal(shouldReloadChecks(["locks", "budget"]), false, "the two together are still nothing to re-run for");
  assert.equal(shouldReloadChecks(["locks", "work"]), true, "one kind that matters is enough");
  assert.equal(shouldReloadChecks([]), false);
  assert.deepEqual(
    [...CHECKS_CHANGE_KINDS].sort(),
    ALL_CHANGE_KINDS.filter((k) => !CHECKS_IGNORED_KINDS.includes(k)).sort(),
  );
});

test("every kind the server can publish is one this list has an answer for", async () => {
  // A kind added to the bus and forgotten here would silently never reload
  // the finish line.
  const watch = await readFile(join(ROOT, "scripts", "ui", "watch.ts"), "utf8");
  const block = /export const SUPPRESSED_KINDS[^;]+;/.exec(watch)?.[0] ?? "";
  const suppressed = new Set([...block.matchAll(/"([a-z]+)"/g)].map((m) => m[1]));
  const declared = /export type ChangeKind =([\s\S]*?);/.exec(watch)?.[1] ?? "";
  const published = [...declared.matchAll(/\|?\s*"([a-z]+)"/g)].map((m) => m[1]).filter((k) => !suppressed.has(k));
  assert.ok(published.length > 5, "found the server's kind list");
  for (const kind of published) {
    assert.ok(ALL_CHANGE_KINDS.includes(kind as (typeof ALL_CHANGE_KINDS)[number]), `${kind} is published by the bus but unknown here`);
  }
});
