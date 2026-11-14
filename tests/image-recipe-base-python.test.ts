/**
 * The base pack's own Python set as the image recipe takes it (images/recipe.py, IMPROVEMENT-PLAN-2 item E8). cache_body decodes a
 * body stored with Content-Encoding br only with a brotli module of version 1.2 or later (its decoder bounds what one call returns),
 * and no image held one: Brotli 1.2.1 was locked only for the ccl_indexeddb_dump venv. It is in requires/python.txt and
 * requires/python.lock now, which every image that holds the base pack installs into its venv with hash checking. Held here: every
 * profile that holds the base pack carries the lock with Brotli at that version and its hashes, and names it in its Python notes.
 * Nothing is downloaded and no image is built: the recipe writes the build context only.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PYTHON3 } from "./host-gates.ts";

const ROOT = join(import.meta.dirname, "..");
const REQUIRES = join(ROOT, "packs", "computer-forensics-base", "requires");
const BROTLI = /^brotli==1\.2\.1 \\\n((?: {4}--hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)/m;

test("every image that holds the base pack installs Brotli 1.2.1 from the pack's own hash lock, the version and hashes the ccl venv pins", async () => {
  const lock = await readFile(join(REQUIRES, "python.lock"), "utf8");
  const ccl = await readFile(join(REQUIRES, "locks", "ccl_indexeddb_dump.txt"), "utf8");
  const ours = BROTLI.exec(lock)?.[1];
  assert.ok(ours, "requires/python.lock holds brotli==1.2.1 with its hashes");
  assert.equal(ours, BROTLI.exec(ccl)?.[1], "the same files as the ccl venv's lock");
  assert.match(await readFile(join(REQUIRES, "python.txt"), "utf8"), /^brotli==1\.2\.1 +# /m, "python.txt names it, with what it is for");
  // The lock is a hash lock install.py accepts (every line pinned, every file hashed).
  const check = spawnSync(PYTHON3, ["-c", "import importlib.util,sys\nspec=importlib.util.spec_from_file_location('install',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\nprint(m.lock_problem(open(sys.argv[2]).read()) or 'ok')", join(ROOT, "images", "install.py"), join(REQUIRES, "python.lock")], { encoding: "utf8" });
  assert.equal(check.stdout.trim(), "ok", check.stderr);

  const profiles = JSON.parse(spawnSync(PYTHON3, [join(ROOT, "images", "recipe.py"), "list"], { encoding: "utf8" }).stdout) as Record<string, { packs: string[] }>;
  const holding = Object.entries(profiles).filter(([, p]) => p.packs.includes("computer-forensics-base")).map(([name]) => name);
  assert.ok(holding.length >= 3, `${holding.join(", ")} hold the base pack`);
  const top = await mkdtemp(join(tmpdir(), "recipe-brotli-"));
  try {
    for (const profile of holding) {
      const out = join(top, profile);
      const r = spawnSync(PYTHON3, [join(ROOT, "images", "recipe.py"), "build", profile, "--out", out, "--allow-nonredistributable", "--symbol-set", "none"], { encoding: "utf8" });
      assert.equal(r.status, 0, `${profile}: ${r.stderr.slice(-400)}`);
      const spec = JSON.parse(await readFile(join(out, "spec.json"), "utf8")) as { python_notes: Array<{ requirement: string; pack: string }>; python_locks: Array<{ pack: string; name: string; sha256: string }> };
      assert.ok(spec.python_notes.some((n) => n.pack === "computer-forensics-base" && n.requirement === "brotli==1.2.1"), `${profile}: the notes list Brotli`);
      const ref = spec.python_locks.find((l) => l.pack === "computer-forensics-base");
      assert.ok(ref, `${profile}: the base pack's python.lock is installed`);
      const copied = await readFile(join(out, "locks", ref.name), "utf8");
      assert.equal(copied, lock, `${profile}: the lock the build copies is the pack's`);
      // install.py installs every python_locks entry into the image's venv, which is on PATH: the python3 cache_body runs is that venv's.
      assert.match(await readFile(join(out, "Dockerfile"), "utf8"), /install\.py/);
    }
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
