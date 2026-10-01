/**
 * The changelog's fragments (scripts/changelog.ts): every fragment in
 * changelog.d/ is well formed, and folding puts them at the top of
 * `[Unreleased]`, newest first, and cuts a release when asked.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkFragment, fold, fragmentFiles, newestFirst } from "../scripts/changelog.ts";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("every fragment in changelog.d/ is well formed", () => {
  for (const f of fragmentFiles(ROOT)) assert.deepEqual(checkFragment(readFileSync(join(ROOT, f), "utf8")), [], f);
});

test("a fragment starts with a level-3 heading and holds none above it", () => {
  assert.deepEqual(checkFragment("### Added: a thing\n\nWhat and why.\n"), []);
  assert.deepEqual(checkFragment("### Fixed: x\n\n```sh\n# a comment in a block\n```\n"), []);
  assert.match(checkFragment("What and why.\n").join(), /does not start with a `### ` heading/);
  assert.match(checkFragment("### Added: x\n\n## [Unreleased]\n").join(), /above level 3/);
  assert.deepEqual(checkFragment("\n\n"), ["it is empty"]);
});

test("newest first: an uncommitted fragment first, then by when each landed, a tie by name", () => {
  assert.deepEqual(
    newestFirst([{ file: "a.md", landed: 5 }, { file: "c.md", landed: 9 }, { file: "b.md", landed: null }, { file: "d.md", landed: 9 }]),
    ["b.md", "c.md", "d.md", "a.md"],
  );
});

const LOG = [
  "# Changelog",
  "",
  "## [Unreleased]",
  "",
  "### Added: what was already there",
  "",
  "## [0.3.0] — 2026-09-17",
  "",
  "- the release",
  "",
  "[Unreleased]: https://github.com/halilozturkci/dfirswarm/compare/v0.3.0...HEAD",
  "[0.3.0]: https://github.com/halilozturkci/dfirswarm/releases/tag/v0.3.0",
  "",
].join("\n");

test("fold puts the fragments at the top of [Unreleased] and keeps what it held", () => {
  const out = fold(LOG, ["### Added: newer\n\nbody\n", "\n### Fixed: older\n"]);
  assert.equal(
    out,
    LOG.replace("## [Unreleased]\n\n", "## [Unreleased]\n\n### Added: newer\n\nbody\n\n### Fixed: older\n\n"),
  );
  assert.equal(fold(LOG, []), LOG, "nothing to fold changes nothing");
});

test("a release cuts [Unreleased] into the version and moves the links", () => {
  const out = fold(LOG, ["### Added: newer\n"], { version: "0.4.0", date: "2026-10-02" });
  assert.match(out, /## \[Unreleased\]\n\n## \[0\.4\.0\] — 2026-10-02\n\n### Added: newer\n\n### Added: what was already there\n/);
  assert.match(out, /\[Unreleased\]: https:\/\/github\.com\/halilozturkci\/dfirswarm\/compare\/v0\.4\.0\.\.\.HEAD\n\[0\.4\.0\]: https:\/\/github\.com\/halilozturkci\/dfirswarm\/compare\/v0\.3\.0\.\.\.v0\.4\.0\n\[0\.3\.0\]/);
  assert.throws(() => fold(LOG, [], { version: "0.3.0", date: "2026-10-02" }), /already has a 0\.3\.0 section/);
  assert.throws(() => fold(LOG, [], { version: "next", date: "2026-10-02" }), /MAJOR\.MINOR\.PATCH/);
  assert.throws(() => fold("# no section\n", []), /no "## \[Unreleased\]" line/);
});
