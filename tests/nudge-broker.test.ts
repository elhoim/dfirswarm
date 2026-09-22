/**
 * Who a pane may wake, and what it may cause them to be told.
 *
 * `tests/herdr-seal.test.sh` drives the broker over its socket; this covers
 * the two decisions it makes, at the resolution where the edge cases are
 * cheap to state.
 */
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { MESSAGES, claimHolds, messageFor, resolvePeer } from "../scripts/nudge-broker.mjs";

test("a peer is an id on the roster the broker was given, and nothing else is", () => {
  const roster = ["alpha", "bravo"];
  assert.equal(resolvePeer(roster, "bravo", "alpha").ok, true);

  // The sender is not a peer: an agent prompting itself is a loop, not a
  // nudge, and the caller has better ways to talk to itself.
  assert.equal(resolvePeer(roster, "alpha", "alpha").ok, false);

  // An id from another run, or no run at all. The ids of a concurrent case
  // are in runs/registry.json and reads are open, so this is a real attempt.
  assert.equal(resolvePeer(roster, "charlie", "alpha").ok, false);

  // The id reaches `herdr agent prompt` as an argument. It is matched
  // against a roster rather than sanitised, but the shape is checked first
  // so that nothing which is not an id gets as far as the lookup.
  for (const bad of ["../../etc/passwd", "a b", "-rf", "", "A", "x;id", "x\ny"]) {
    assert.equal(resolvePeer(roster, bad, "alpha").ok, false, `should refuse ${JSON.stringify(bad)}`);
  }
  assert.equal(resolvePeer(roster, 7 as unknown as string, "alpha").ok, false);
});

test("the roster is what the broker was handed, never a file a pane can write", () => {
  // It used to be read from `<sandbox>/team.json` per request. The write
  // guard leaves the sandbox writable to its own panes, so an agent could
  // append any id and then reach that pane — a check against a file the
  // caller controls is a spell-check, not a boundary. Passing the roster in
  // is what makes it one, and this asserts the shape of that.
  assert.equal(resolvePeer([], "alpha", "").ok, false);
  assert.equal(resolvePeer(undefined as unknown as string[], "alpha", "").ok, false);
  assert.equal(resolvePeer("alpha" as unknown as string[], "alpha", "").ok, false);
});

test("swarm_done is refused unless the run really is done", () => {
  const dir = mkdtempSync(join(tmpdir(), "nudge-broker-"));
  try {
    // Without this the broker was a kill switch: any pane, at any moment,
    // could tell every peer the swarm was over and to stop working. The
    // sentinel is written by the harness, in a directory a pane cannot
    // create it in under the write guard.
    assert.equal(claimHolds(dir, "swarm_done"), false);
    mkdirSync(join(dir, "done"), { recursive: true });
    writeFileSync(join(dir, "done", "SWARM_DONE"), "", "utf8");
    assert.equal(claimHolds(dir, "swarm_done"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the caller picks a kind; the words are the broker's", () => {
  assert.equal(messageFor("swarm_done"), MESSAGES.swarm_done);
  assert.match(MESSAGES.swarm_done, /done\/SWARM_DONE/);

  // The whole point of the broker over `herdr agent prompt`: an agent that
  // could choose the sentence could type anything into a peer's terminal,
  // which is prompt injection wearing the harness's voice.
  assert.equal(messageFor("anything else"), "");
  assert.equal(messageFor(""), "");
  assert.equal(messageFor(undefined as unknown as string), "");

  // A key off Object.prototype is not a kind. `messages[kind]` without an own
  // check would hand back a function for "constructor" and spawn herdr with
  // it as the message.
  for (const inherited of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    assert.equal(messageFor(inherited), "", `should refuse ${inherited}`);
  }
});
