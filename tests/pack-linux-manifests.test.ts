/**
 * The Linux pack: the six tool manifests of the Linux pack: what each says it reads, and that it carries its
 * script's sha256.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, tool } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

test("every manifest says what its tool reads, the sha256 of its script, and a version above the one before", async () => {
  const expected: Record<string, { names?: string[]; magic?: string[]; extensions?: string[] }> = {
    auth_log: { names: ["auth.log*", "secure*"] },
    utmp_parse: { names: ["utmp", "wtmp", "btmp", "lastlog", "wtmp.*", "btmp.*"] },
    shell_history: { names: [".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".history", ".python_history", ".mysql_history", ".psql_history", ".rediscli_history", ".node_repl_history", "fish_history"] },
    cron_dump: { names: ["crontab", "*.timer"] },
    journal_export: { extensions: [".journal", ".journal~"], magic: ["4c504b5348485248"] },
    linux_triage: { extensions: [".e01", ".ex01", ".dd", ".img", ".raw", ".vhd", ".vhdx", ".vmdk", ".qcow2"] },
  };
  for (const [name, want] of Object.entries(expected)) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.ok(manifest.use, `${name} says what it reads`);
    for (const key of ["names", "extensions"] as const) if (want[key]) assert.deepEqual([...manifest.use[key]].sort(), [...want[key]!].sort(), `${name} use.${key}`);
    if (want.magic) assert.deepEqual(manifest.use.magic.map((m: Json) => m.hex), want.magic);
    const script = await readFile(join(TOOLS, name, "run.py"));
    assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"), `${name} sha256`);
    assert.ok(manifest.version >= 4 || name === "linux_triage" || name === "cron_dump", `${name} version raised`);
  }
});
