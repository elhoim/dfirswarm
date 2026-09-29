/**
 * A release and the dynamic network's records (docs/adr/0012).
 *
 * Custody seals the network's two chains (network/grants.jsonl and
 * network/fetches.jsonl) by head and count, as it seals the lead and question
 * registers, and a release binds that verdict. Release verification holds
 * both network chains to it the way it holds the registers: appended to since
 * (a resume's continuation) is a prefix; cut, deleted or rewritten fails.
 */
import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import { custodyAnchorPath, takeCustody } from "../scripts/custody.ts";
import { appendNetEvents, FETCH_LOG, GRANTS_LOG } from "../scripts/net-grants.ts";
import { draftRelease, runContext } from "../scripts/release.ts";
import { runLayout, verifyReleases } from "../scripts/release-record.ts";
import { reviewsPath } from "../scripts/review.ts";
import { cleanUp, stoppedRun } from "./release-fixture.ts";

after(async () => {
  await cleanUp();
});

test("release verification holds the network's grants and fetches to the custody verdict the release binds: appended to is a prefix, cut or rewritten fails", async () => {
  const r = await stoppedRun({ id: "snrel" });
  await writeFile(join(r.root, "team.json"), JSON.stringify({ swarm_id: r.id, n: 1, agents: [{ id: "a0", role: "worker" }] }));
  // Records with no capture: what custody seals by head and count, and nothing it re-hashes.
  await appendNetEvents(r.root, GRANTS_LOG, [
    { by: "a0", ev: "request", request: "NR-1", adapter: "rdap_domain", lead: "L-1" },
    { by: "hub", ev: "decision", request: "NR-1", outcome: "refused", reasons: [] },
  ]);
  await appendNetEvents(r.root, FETCH_LOG, [{ by: "fetch", ev: "service_started", port: 1 }]);
  const custody = await takeCustody(r.root, { runsDir: r.runs });
  assert.ok(custody.seal?.network, "custody seals the network's chains");
  const ctx = runContext(r.root, { run: r.id, runsDir: r.runs });
  await draftRelease(ctx, { home: r.home, say: () => undefined });
  const layout = () => runLayout(r.root, reviewsPath(r.runs, r.id), custodyAnchorPath(r.root));
  const good = await verifyReleases(layout());
  assert.equal(good.ok, true, good.lines.join("\n"));

  for (const [rel, what] of [
    [GRANTS_LOG, "the network grants"],
    [FETCH_LOG, "the network fetches"],
  ] as const) {
    const text = await readFile(join(r.root, rel), "utf8");
    // Appended to after the verdict (a resume's continuation): the part it binds is intact.
    await appendNetEvents(r.root, rel, [{ by: "hub", ev: "note", text: "after the verdict" }]);
    const grown = await verifyReleases(layout());
    assert.equal(grown.ok, true, grown.lines.join("\n"));
    assert.match(grown.lines.join("\n"), new RegExp(`${what} it binds \\(\\d+ lines\\) is a prefix`));
    // Cut back past what it binds.
    const lines = text.split("\n").filter((l) => l.trim());
    await writeFile(join(r.root, rel), lines.length > 1 ? `${lines.slice(0, -1).join("\n")}\n` : "");
    const cut = await verifyReleases(layout());
    assert.equal(cut.ok, false, `${what} cut`);
    assert.match(cut.lines.join("\n"), new RegExp(`${what} here is not the one the custody verdict it binds sealed`));
    // Deleted.
    await rm(join(r.root, rel));
    assert.equal((await verifyReleases(layout())).ok, false, `${what} deleted`);
    // Rewritten in place, its hashes kept.
    await writeFile(join(r.root, rel), text.replace(/"by":"(a0|fetch)"/, '"by":"someone else"'));
    const rewritten = await verifyReleases(layout());
    assert.equal(rewritten.ok, false, `${what} rewritten`);
    assert.match(rewritten.lines.join("\n"), new RegExp(`${what}'s chain here is broken`));
    // As it was: verified again.
    await writeFile(join(r.root, rel), text);
    const restored = await verifyReleases(layout());
    assert.equal(restored.ok, true, restored.lines.join("\n"));
  }
});
