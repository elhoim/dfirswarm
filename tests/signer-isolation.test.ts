/**
 * The machine key kept as it was made (scripts/signers.ts machineSigner):
 * each time it is used, its directory is made its owner's alone again and
 * the key and its record 0600, whatever a restore or a umask left them as.
 * A key another user can read is a key another user can seal drafts with.
 * Keys are made in temporary directories; none is read or printed here.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { machineSigner } from "../scripts/signers.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});
async function tmp(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
const mode = (p: string) => statSync(p).mode & 0o777;

test("a machine key reused is made its owner's alone again: the directory 0700, the key and its record 0600", async () => {
  const home = await tmp("signer-isolation-");
  const made = machineSigner(home);
  assert.ok(!("why" in made), JSON.stringify(made));
  if ("why" in made) return;
  const dir = join(home, "machine");
  const key = join(dir, "release_ed25519");
  const meta = join(dir, "machine.json");
  // As a backup restored with the wrong modes, or a permissive umask, leaves them.
  chmodSync(dir, 0o755);
  chmodSync(key, 0o644);
  chmodSync(meta, 0o644);
  const again = machineSigner(home);
  assert.ok(!("why" in again), JSON.stringify(again));
  if ("why" in again) return;
  assert.equal(again.id, made.id, "the same key, not a new one");
  assert.equal(mode(dir), 0o700);
  assert.equal(mode(key), 0o600);
  assert.equal(mode(meta), 0o600);
});

test("only reading the machine key (create: false) enforces the same modes", async () => {
  const home = await tmp("signer-isolation-");
  const made = machineSigner(home);
  assert.ok(!("why" in made), JSON.stringify(made));
  const dir = join(home, "machine");
  chmodSync(dir, 0o711);
  chmodSync(join(dir, "release_ed25519"), 0o640);
  const read = machineSigner(home, { create: false });
  assert.ok(!("why" in read), JSON.stringify(read));
  assert.equal(mode(dir), 0o700);
  assert.equal(mode(join(dir, "release_ed25519")), 0o600);
  assert.equal(mode(join(dir, "machine.json")), 0o600);
});
