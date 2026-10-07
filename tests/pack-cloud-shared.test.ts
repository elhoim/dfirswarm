/**
 * The cloud pack's three tools share one block of code (the lossless page, the secret-safe values file, the withholding of
 * credential-shaped text, timestamps, the bounded JSON reader), copied into each because a tool is standalone. This suite holds
 * the copies equal, holds the three to withholding the same strings, and holds each manifest to what its script does.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SIGNIN, TOOLS, TRAIL, UAL, body, put, refused, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";

const NAMES = ["cloudtrail_parse", "signin_analyse", "ual_parse"] as const;
const SCRIPTS: Record<(typeof NAMES)[number], string> = { cloudtrail_parse: TRAIL, signin_analyse: SIGNIN, ual_parse: UAL };

const BEGIN = "# ---- BEGIN SHARED BLOCK";
const END = "# ---- END SHARED BLOCK";

async function sharedBlock(name: (typeof NAMES)[number]): Promise<string> {
  const text = await readFile(SCRIPTS[name], "utf8");
  const from = text.indexOf(BEGIN);
  const to = text.indexOf(END);
  assert.ok(from >= 0 && to > from, `${name} has the shared block`);
  return text.slice(from, text.indexOf("\n", to));
}

test("the shared block is identical in the three tools", async () => {
  const blocks = await Promise.all(NAMES.map(sharedBlock));
  assert.ok(blocks[0].length > 20000, "the block is the shared code, not a stub");
  assert.equal(blocks[1], blocks[0], "signin_analyse's copy equals cloudtrail_parse's");
  assert.equal(blocks[2], blocks[0], "ual_parse's copy equals cloudtrail_parse's");
});

// Names and values each tool must withhold alike. A name can be echoed in a path, in an error message, in a file name in a census.
const SHAPED: Array<[string, string]> = [
  ["a JSON Web Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"],
  ["a GitHub token", "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF3gH5"],
  // Built from parts: a literal that looks like a live token is refused by the host's push protection.
  ["a Slack token", "xox" + "b-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"],
  ["a Google API key", "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"],
  ["a Google access token", "ya29." + "a0AfH6SMBxExampleExampleExampleExample123456"],
  ["an Azure client secret", "abc8Q~Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii"],
  ["a value assigned to a credential name", "password=Hunter2-correct-horse"],
  ["a value assigned to a credential name", "client_secret=Zq9Xw7Vb6Nm5Lk4Jh3Gf2"],
  ["a long unbroken base64-like run", "Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii7Uu6Yy5Tt4Rr3Ee2Ww1Qq0Aa9Ss8Dd7Ff6Gg5Hh4Jj3Kk2Ll1Mm0Nn9Bb8Vv7Cc6Xx5Zz4Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii"],
];

test("the three tools withhold the same strings from an error message that names them", async () => {
  await withDir(async (cwd) => {
    for (const script of Object.values(SCRIPTS)) {
      for (const [why, value] of SHAPED) {
        const out = refused(await tool(script, cwd, { path: `work/ev/${value}` }));
        const text = JSON.stringify(out);
        assert.ok(!text.includes(value), `${script.split("/").slice(-2)[0]} printed ${why}`);
        assert.match(text, /withheld/, `${script.split("/").slice(-2)[0]} said it withheld ${why}`);
      }
    }
  });
});

test("names that are not shaped like a credential are not withheld: a CloudTrail file name, a long path, an S3 key", async () => {
  await withDir(async (cwd) => {
    const names = [
      "111122223333_CloudTrail_us-east-1_20260214T0900Z_AbCdEf123456.json.gz",
      "arn:aws:iam::111122223333:role/service-role/AmazonSageMaker-ExecutionRole-20200101T000001",
      "backups/2026/02/14/" + "very-long-lowercase-object-key-name-".repeat(5) + "end",
    ];
    for (const name of names) {
      const out = refused(await tool(TRAIL, cwd, { path: `work/ev/${name}` }));
      assert.ok(JSON.stringify(out).includes(name), `${name} is printed as it is`);
    }
  });
});

test("the three tools carry the same typed refusals: a non-object argument, a pipe and a bad limit are JSON errors, never a traceback", async () => {
  await withDir(async (cwd) => {
    for (const script of Object.values(SCRIPTS)) {
      const nonObject = await tool(script, cwd, [1, 2, 3] as unknown as object);
      assert.notEqual(nonObject.code, 0);
      assert.doesNotMatch(nonObject.stderr, /Traceback/);
      assert.match(JSON.parse(nonObject.stdout).error, /arguments must be a JSON object/);
      await put(cwd, "work/ev/a.json", "{}");
      for (const bad of [{ limit: 0 }, { limit: "5" }, { limit: true }, { time_limit_seconds: 0 }, { time_limit_seconds: 9999 }, { write_values: "yes" }, { max_expanded_bytes: 5 }]) {
        const out = refused(await tool(script, cwd, { path: "work/ev/a.json", ...bad }));
        assert.equal(out.status, "failed");
        assert.match(out.error, /must be/);
      }
    }
  });
});

test("every manifest says what its tool reads, carries its script's sha256, declares every argument the script reads and says what is and is not measured", async () => {
  const read = /(?:want_str|want_bool|want_int|want_str_list|want_regex)\(\s*args,\s*"([a-z_]+)"|args\.get\("([a-z_]+)"/g;
  for (const name of NAMES) {
    const manifest = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(SCRIPTS[name], "utf8");
    assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"), `${name} sha256`);
    assert.ok(manifest.version >= 4, `${name} version raised`);
    assert.ok(manifest.timeout_seconds > 580, `${name}: the most time_limit_seconds allows (580) is under the tool's timeout, so the tool stops itself before it is killed`);
    assert.match(manifest.params.time_limit_seconds.description, /default 540, at most 580/);
    assert.ok(manifest.use?.names?.length > 0, `${name} says what it reads`);
    assert.equal(manifest.use.extensions, undefined, `${name}: a bare .json or .csv would hint it for every such file`);
    const keys = new Set([...script.matchAll(read)].map((m) => m[1] ?? m[2]));
    // ual_parse reads its two time bounds through a loop over their names.
    if (name === "ual_parse") for (const key of ["since", "until"]) keys.add(key);
    assert.ok(keys.size >= 10, `${name} reads its arguments`);
    for (const key of keys) assert.ok(key in manifest.params, `${name} reads ${key} and does not declare it`);
    for (const key of Object.keys(manifest.params)) assert.ok(keys.has(key), `${name} declares ${key} and does not read it`);
    assert.match(manifest.description, /`status` and `status_basis`/, `${name} says its answers carry status`);
    assert.match(manifest.description, /NOT measured/, `${name} says what it does not measure`);
    assert.match(manifest.description, /secret_output: true/, `${name} says it can reach secrets`);
    assert.match(manifest.description, /never replaces a smaller|never replaced by a smaller/i, `${name} says its output is never replaced`);
    assert.doesNotMatch(manifest.example, /work\/[a-z]+\.jsonl/, `${name}'s example does not write where a job cannot`);
    // The old claims are gone from the description.
    assert.doesNotMatch(manifest.description, /first hour|shape of enumeration|resolves an assumed role back to the session that issued it|unfamiliar addresses|without treating records of unknown outcome as successes/i, name);
  }
});

test("the tools run on the oldest and the newest Python the images and the runners carry: no syntax or stdlib call newer than 3.11", async () => {
  for (const name of NAMES) {
    const script = await readFile(SCRIPTS[name], "utf8");
    assert.doesNotMatch(script, /\bf"[^"]*\{[^}]*"[^"]*"[^}]*\}/, `${name}: no nested quotes in an f-string (3.12 only)`);
    assert.doesNotMatch(script, /\bitertools\.batched|\bexcept\*|^type \w+ =/m, `${name}: no 3.12 or 3.13 only construct`);
    assert.doesNotMatch(script, /zipfile\.is_zipfile/, `${name}: no stdlib validator for dispatch`);
    const out = refused(await tool(SCRIPTS[name], process.cwd(), { path: "/nonexistent-for-cloud-test" }));
    assert.equal(out.status, "failed");
  }
});

test("an answer is ASCII: a non-ASCII or non-UTF-8 name is escaped, so a lone surrogate cannot raise on the way out", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/ünïcode-名前.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "u" }] }));
    const run = await tool(TRAIL, cwd, { path: "work/ev" });
    const out: Json = body(run);
    assert.equal(out.record_count, 1);
    // eslint-disable-next-line no-control-regex
    assert.match(run.stdout, /^[\x00-\x7f]*$/, "json.dumps escapes everything outside ASCII");
    assert.match(out.records[0].source_file, /n\u00ef|ünï/);
  });
});

test("a named pipe is never opened: as the path it is refused, and in a directory it is named and skipped", async () => {
  await withDir(async (cwd) => {
    try {
      execFileSync("mkfifo", [join(cwd, "work", "pipe.json")]);
    } catch {
      return; // no mkfifo on this platform
    }
    for (const script of Object.values(SCRIPTS)) {
      const out = refused(await tool(script, cwd, { path: "work/pipe.json" }));
      assert.equal(out.status, "failed");
      assert.match(out.error, /neither a regular file|regular file/);
    }
    await put(cwd, "work/ev/ok.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "p" }] }));
    execFileSync("mkfifo", [join(cwd, "work", "ev", "pipe.json")]);
    await put(cwd, "work/ev/audit.json", JSON.stringify([{ Operation: "Send", Id: "1", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }]));
    for (const script of [TRAIL, UAL]) {
      const out: Json = JSON.parse((await tool(script, cwd, { path: "work/ev" })).stdout);
      assert.ok(out.skipped.some((s: Json) => /not a regular file: it is not opened/.test(s.reason)), `${script}: the pipe is named`);
      assert.equal(out.skipped_count, 1);
    }
    const trail: Json = body(await tool(TRAIL, cwd, { path: "work/ev" }));
    assert.equal(trail.status, "partial", "a file that was not read is not a complete read");
  });
});

test("the tables say how many distinct values they could not count, and the sign-in analysis names the accounts it left out", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/ok.json", JSON.stringify({ Records: [{ eventName: "X", eventSource: "s3.amazonaws.com", eventTime: "2026-02-14T09:00:00Z", eventID: "p" }] }));
    const ct: Json = body(await tool(TRAIL, cwd, { path: "work/ev/ok.json" }));
    assert.deepEqual([ct.tables_uncounted.by_event, ct.tables_uncounted.by_identity, ct.tables_uncounted.by_address, ct.tables_uncounted.errors], [0, 0, 0, 0]);
    await put(cwd, "work/ev/ual.json", JSON.stringify([{ Operation: "Send", Id: "1", UserId: "a@b.c", CreationTime: "2026-02-14T09:00:00Z" }]));
    const ual: Json = body(await tool(UAL, cwd, { path: "work/ev/ual.json" }));
    assert.equal(ual.tables_uncounted.by_operation, 0);
    await put(cwd, "work/ev/s.json", JSON.stringify({ value: [{ id: "x", createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "a@b.c", ipAddress: "1.2.3.4", status: { errorCode: 0 } }] }));
    const si: Json = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json" }));
    assert.deepEqual([si.coverage.users_not_analysed_over_cap, si.coverage.users_not_analysed_named], [0, []]);
  });
});
