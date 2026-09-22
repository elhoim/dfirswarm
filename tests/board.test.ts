import assert from "node:assert/strict";
import { test } from "node:test";
import { boardStats } from "../ui/src/lib/board.ts";
import type { TimedPost } from "../ui/src/lib/types.ts";

let seq = 0;
function post(from: string, tag: string, body: string, atSec: number, to = "all"): TimedPost {
  seq += 1;
  return {
    id: seq,
    thread: "main",
    from,
    to,
    tag: tag as TimedPost["tag"],
    body,
    path: `threads/main/${seq}.md`,
    at: new Date(Date.UTC(2026, 8, 20, 18, 0, atSec)).toISOString(),
  };
}

const TEAM = ["a0", "a1", "a2", "a3"];

test("the harness's own posts are counted, but they are not one of the team's voices", () => {
  const stats = boardStats(
    [post("a0", "intro", "taking the laptop", 0), post("system", "veto", "CLAIM VIOLATION: a1 wrote work/x", 5), post("a1", "result", "found it", 10)],
    TEAM,
  );
  assert.equal(stats.posts, 3);
  assert.equal(stats.system, 1);
  assert.equal(stats.speakers.length, 2, "system is not a speaker");
  assert.deepEqual(
    stats.tags.map((t) => [t.tag, t.n]),
    [["intro", 1], ["result", 1]],
    "the tag mix describes the team, so the harness's veto is not in it",
  );
  assert.equal(stats.friction.length, 1, "but a harness veto is still a moment the board caught");
  assert.equal(stats.friction[0].from, "system");
});

test("an agent that never posted is named, because silence is a finding", () => {
  const stats = boardStats([post("a0", "intro", "hello", 0)], TEAM);
  assert.deepEqual(stats.mute, ["a1", "a2", "a3"]);
});

test("naming is counted from the body, once per post, never yourself", () => {
  const stats = boardStats(
    [
      post("a0", "result", "a1 and a2 should look at this; a1 again in the same post", 0),
      post("a1", "ask", "a0 what did you mean? a0?", 5),
      post("a2", "result", "a2 is me, and I name nobody", 10),
      post("a3", "ask", "over to you", 15, "a0"),
    ],
    TEAM,
  );
  const pair = (from: string, to: string) => stats.mentions.find((m) => m.from === from && m.to === to)?.n ?? 0;
  assert.equal(pair("a0", "a1"), 1, "twice in one post is one post");
  assert.equal(pair("a0", "a2"), 1);
  assert.equal(pair("a1", "a0"), 1);
  assert.equal(pair("a2", "a2"), 0, "naming yourself is not talking to anyone");
  assert.equal(pair("a3", "a0"), 1, "an addressed post counts even when the body never says the name");
  assert.deepEqual(stats.unnamed, ["a3"], "nobody named a3");
});

test("the quiet is measured between the team's own posts, longest first", () => {
  const stats = boardStats(
    [post("a0", "intro", "one", 0), post("a1", "result", "two", 10), post("a2", "result", "three", 130), post("a3", "result", "four", 135)],
    TEAM,
  );
  assert.equal(stats.silences[0].ms, 120_000);
  assert.equal(stats.silences[0].before.from, "a1");
  assert.equal(stats.silences[0].after.from, "a2", "the post that ended it");
  assert.equal(stats.medianGapMs, 10_000, "gaps are 10s, 120s, 5s");
  assert.equal(stats.spanMs, 135_000);
});

test("a cited path is one under the run's own directories, with its punctuation trimmed", () => {
  const stats = boardStats(
    [
      post("a0", "result", "see `work/flags.md`, and work/flags.md again", 0),
      post("a1", "result", "inputs/case/laptop.E01 is untouched. Also notes.sqlite and /etc/passwd.", 5),
      post("system", "veto", "CLAIM VIOLATION on work/flags.md", 10),
    ],
    TEAM,
  );
  const by = new Map(stats.artefacts.map((a) => [a.path, a]));
  assert.equal(by.get("work/flags.md")?.n, 3, "twice in one post is twice; the harness's mention counts too");
  assert.deepEqual(by.get("work/flags.md")?.by, ["a0", "system"]);
  assert.equal(by.get("inputs/case/laptop.E01")?.n, 1);
  assert.equal(by.has("notes.sqlite"), false, "a bare filename in prose is not a citation");
  assert.equal(by.has("/etc/passwd"), false, "nor is a path outside the run");
});

test("an empty board answers with zeroes rather than throwing", () => {
  const stats = boardStats([], TEAM);
  assert.equal(stats.posts, 0);
  assert.equal(stats.spanMs, 0);
  assert.equal(stats.medianGapMs, 0);
  assert.equal(stats.busiest, null);
  assert.deepEqual(stats.mute, TEAM);
  assert.deepEqual(stats.silences, []);
});

test("posts from several threads are one board, ordered by the clock", () => {
  const a = post("a0", "result", "in main", 30);
  const b = { ...post("a1", "result", "in a side thread", 10), thread: "vault" };
  const stats = boardStats([a, b], TEAM);
  assert.equal(stats.threads, 2);
  assert.equal(stats.silences[0].before.from, "a1", "the earlier post came first even from another thread");
  assert.equal(stats.silences[0].ms, 20_000);
});
