/**
 * Phase 4 (scripts/release-adapters.ts, scripts/certify.ts): an
 * OpenTimestamps proof of a release's signature when the ots client is
 * installed, and "unavailable" when it is not; a transparency log's receipt
 * from a command the operator names, kept whole; and a certification
 * template for a package that says what the package says of itself, the
 * verification run on it verbatim, what the checks do not establish, and
 * leaves the certifier's statements and signature blank. The ots client
 * here is a stand-in: no calendar is reached.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { draftRelease, runContext } from "../scripts/release.ts";
import { otsRelease, transparencyRelease } from "../scripts/release-adapters.ts";
import { readReleases, runLayout, verifyReleases } from "../scripts/release-record.ts";
import { certificationText, VERIFY_EXITS } from "../scripts/certify.ts";
import { custodyAnchorPath } from "../scripts/custody.ts";
import { reviewsPath } from "../scripts/review.ts";
import { cleanUp, script, stoppedRun } from "./release-fixture.ts";

after(cleanUp);
const quiet = () => undefined;

async function withPath<T>(dir: string, fn: () => T): Promise<T> {
  const was = process.env.PATH;
  process.env.PATH = `${dir}:/usr/bin:/bin`;
  try {
    return fn();
  } finally {
    process.env.PATH = was;
  }
}

test("OpenTimestamps: unavailable without the ots client; with it, the signature is stamped beside the release, and upgraded later", async () => {
  const r = await stoppedRun();
  await draftRelease(runContext(r.root, { run: r.id, runsDir: r.runs }), { home: r.home, say: quiet });
  const empty = await script("nothing", "exit 0");
  const none = await withPath(empty.dir, () => otsRelease(r.root));
  assert.equal(none.ok, false);
  assert.match(none.note, /^unavailable: the OpenTimestamps client \(ots\) is not on this host/);
  const ots = await script(
    "ots",
    `case "$1" in
  --version) echo "v0.7.2" ;;
  stamp) printf 'pending proof\\n' > "$2.ots" ;;
  upgrade) echo "Success! Timestamp complete" ;;
  info) echo "File sha256 hash: stand-in" ;;
esac`,
  );
  const stamped = await withPath(ots.dir, () => otsRelease(r.root));
  assert.equal(stamped.ok, true, stamped.note);
  assert.match(stamped.note, /the proof is pending until a Bitcoin block commits it/);
  const dir = readReleases(r.root)[0].dir;
  assert.ok(existsSync(join(dir, "release.json.sig.ots")));
  const up = await withPath(ots.dir, () => otsRelease(r.root, { upgrade: true }));
  assert.match(up.note, /Timestamp complete/);
  const info = await withPath(ots.dir, () => otsRelease(r.root));
  assert.match(info.note, /stand-in/);
  const v = await verifyReleases(runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root)));
  assert.equal(v.ok, true, "a proof beside the release is not in it");
});

test("a transparency log's receipt: the digest line on its stdin and the release's files in its environment, what it prints kept whole", async () => {
  const r = await stoppedRun();
  await draftRelease(runContext(r.root, { run: r.id, runsDir: r.runs }), { home: r.home, say: quiet });
  const rel = readReleases(r.root)[0];
  const log = await script("log", 'read -r line; printf \'{"logIndex": 42, "sha256": "%s", "line": "%s"}\\n\' "$DFS_RELEASE_SHA256" "$line"');
  const t = transparencyRelease(r.root, log.path);
  assert.equal(t.ok, true, t.note);
  const receipt = JSON.parse(readFileSync(join(rel.dir, "transparency-1.json"), "utf8")) as { exit: number; stdout: string; line: string };
  const said = JSON.parse(receipt.stdout) as { logIndex: number; sha256: string; line: string };
  assert.equal(said.logIndex, 42);
  assert.equal(said.sha256, rel.sha256);
  assert.equal(said.line, receipt.line);
  const failed = transparencyRelease(r.root, "echo 'log unreachable' >&2; exit 3");
  assert.equal(failed.ok, false);
  assert.match(failed.note, /exited 3; what it said is in transparency-2\.json/);
});

test("the certification template says what the package says of itself and the verification verbatim, and leaves the certifier's part blank", async () => {
  const r = await stoppedRun();
  await draftRelease(runContext(r.root, { run: r.id, runsDir: r.runs }), { home: r.home, say: quiet });
  // A package, as far as the template reads one: the manifest, the verdict, the releases.
  const { cp, writeFile, mkdir } = await import("node:fs/promises");
  const pkg = join(r.root, "package");
  await mkdir(pkg, { recursive: true });
  await cp(join(r.root, "release"), join(pkg, "release"), { recursive: true });
  await cp(join(r.root, "custody.json"), join(pkg, "custody.json"));
  await writeFile(join(pkg, "MANIFEST.txt"), `${"0".repeat(64)}  ./custody.json\n`);
  await writeFile(join(pkg, "PACKAGE-KIND.txt"), "record only\n");
  const text = certificationText({ pkg, target: "/cases/s4v4-package", verifyOutput: "Files:        1 of 1 re-hashed against MANIFEST.txt\nFILES VERIFIED, UNSIGNED: /cases/s4v4-package\n", verifyExit: 4, at: "2026-09-27T12:00:00Z" });
  assert.match(text, /^CERTIFICATION OF RECORDS GENERATED BY AN ELECTRONIC PROCESS\n\(a template, for a qualified person to complete and sign\)/);
  assert.match(text, /Federal Rules of Evidence 902\(13\) and 902\(14\)/);
  assert.match(text, /This is\nnot legal advice/);
  assert.match(text, /Its manifest: +MANIFEST\.txt, sha256 [0-9a-f]{64}, listing 1 file\(s\)/);
  assert.match(text, /Signed: +no\n/);
  assert.match(text, /v0: DRAFT, sealed by the install's machine key SHA256:\S+ \(not an examiner; adopted by no one\)/);
  assert.match(text, /No examiner adopted the report: every conclusion in it is the agents'\./);
  assert.match(text, / {3}\$ swarm\.sh verify \/cases\/s4v4-package\n {3}Files: {8}1 of 1 re-hashed against MANIFEST\.txt\n {3}FILES VERIFIED, UNSIGNED: \/cases\/s4v4-package\n {3}exit 4: every file matches the manifest, and the package is not signed/);
  assert.match(text, /Name: +_{10,}/);
  assert.match(text, /\[ \] The copy delivered is identified as a true copy by a process of digital identification/);
  assert.match(text, /That any conclusion is correct\./);
  assert.match(text, /ssh-keygen -Y sign -f <their key> -n dfirswarm-certification certification\.txt/);
  assert.equal(VERIFY_EXITS[1], "SOMETHING DOES NOT HOLD: the output above names it");
});
