/**
 * Library wrappers must not eval caller JSON into the shell. These three
 * used to `eval "$(python3 -c … print(f"OUTPUT={d[\"output\"]}") …)"`, so
 * `output` of `x$(touch pwned)` or a pattern of `'; os.system("id"); '` ran
 * as code. They now json.load and pass values on argv / to re.search.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { failingStub, LIB, runPy, runPySnippet, runSh, withCwd } from "./tool-library-harness.ts";

type LibraryManifest = {
  name: string;
  runtime: string;
  entry: string;
  by: string;
  version: number;
  description: string;
  sha256: string;
};

async function libraryManifests(): Promise<LibraryManifest[]> {
  const dirs = await readdir(LIB, { withFileTypes: true });
  const out: LibraryManifest[] = [];
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    const raw = await readFile(join(LIB, d.name, "manifest.json"), "utf8").catch(() => null);
    if (raw) out.push(JSON.parse(raw) as LibraryManifest);
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

test("every library manifest hashes the script sitting next to it", async () => {
  // The harness refuses a tool whose bytes do not match its manifest, so a
  // script edited without rehashing is a tool that cannot be called at all.
  // Nothing else in the repo checks this, and the drift is invisible until
  // a run needs the tool.
  const manifests = await libraryManifests();
  assert.ok(manifests.length >= 30, `expected a populated library, got ${manifests.length}`);
  for (const m of manifests) {
    const bytes = await readFile(join(LIB, m.name, m.entry));
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      m.sha256,
      `${m.name}/${m.entry} does not hash to its manifest sha256`,
    );
  }
});

test("the library README lists what the manifests say", async () => {
  const manifests = await libraryManifests();
  const readme = await readFile(join(LIB, "README.md"), "utf8");
  const rows = readme
    .split("\n")
    .filter((line) => /^\| `[a-z0-9_]+` \|/.test(line))
    .map((line) => line.slice(2, -2).split(" | "));
  assert.deepEqual(
    rows.map((r) => r[0]),
    manifests.map((m) => `\`${m.name}\``),
    "the table must list every tool, in name order",
  );
  for (const [i, m] of manifests.entries()) {
    const [, runtime, by, version, what] = rows[i];
    assert.equal(runtime, m.runtime, `${m.name}: runtime`);
    assert.equal(by, `\`${m.by}\``, `${m.name}: author`);
    assert.equal(version, String(m.version), `${m.name}: version`);
    const one = m.description.split(/\s+/).join(" ");
    assert.equal(what, one.length <= 109 ? one : `${one.slice(0, 109)}\u2026`, `${m.name}: description`);
  }
});

test("library scripts do not contain eval", async () => {
  const names = ["icat_extract", "grep_filelist", "icat_root", "fls_root", "check_inputs", "volrun"];
  for (const name of names) {
    const py = await readFile(join(LIB, name, "run.py"), "utf8");
    assert.doesNotMatch(py, /\beval\s*\(/);
    const sh = join(LIB, name, "run.sh");
    await assert.rejects(readFile(sh), /ENOENT/, `${name}/run.sh must be gone`);
  }
});

test("icat_extract treats output as a path, not a shell command", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_extract", "run.py"), cwd, {
      inode: 12,
      output: "work/x$(touch pwned).bin",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null, "command substitution in output must not run");
    const body = JSON.parse(out.stdout) as { path: string; size: number };
    assert.equal(body.path, "work/x$(touch pwned).bin");
    assert.equal(body.size, Buffer.byteLength("extracted-bytes"));
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n0\ninputs\/AF-Case2\.E01\n12\n/);
    const saved = await readFile(join(cwd, "work", "x$(touch pwned).bin"), "utf8");
    assert.equal(saved, "extracted-bytes");
  });
});

test("icat_root treats inode and output as argv, not eval", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, {
      inode: "7; touch pwned",
      output: "work/out.txt; touch pwned",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n503808\ninputs\/Webserver\.E01\n7; touch pwned\n/);
    const saved = await readFile(join(cwd, "work", "out.txt; touch pwned"), "utf8");
    assert.equal(saved, "extracted-bytes");
  });
});

test("grep_filelist does not exec a pattern as Python", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "AF-Case2.E01", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "AF-Case2.E01", "p0", "filelist.txt"), "safe.txt\n", "utf8");
    const out = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, {
      pattern: "'; os.system(\"touch pwned\"); '",
    });
    assert.equal(out.code, 0, out.stderr);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null, "os.system in the pattern must not run");
    const hits = JSON.parse(out.stdout) as string[];
    assert.deepEqual(hits, []);
  });
});

test("icat_extract fails closed when the image is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "icat_extract", "run.py"), cwd, {
      inode: 12,
      output: "work/empty.bin",
      image: "inputs/no-such.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);
    const planted = await readFile(join(cwd, "work", "empty.bin")).catch(() => null);
    assert.equal(planted, null, "must not write a 0-byte extract for a missing image");
  });
});

test("fls_root reads JSON stdin and fails if the image is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "fls_root", "run.py"), cwd, {
      inode: 99,
      image: "inputs/no-such.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    assert.match(out.stdout, /not found/);

    await writeFile(
      join(bin, "fls"),
      `#!/bin/sh
printf '%s\\n' "$@" > "${cwd}/fls-args.txt"
printf 'd/d 2: .\\n'
`,
      "utf8",
    );
    await chmod(join(bin, "fls"), 0o755);
    const listed = await runPy(join(LIB, "fls_root", "run.py"), cwd, {
      inode: 1831425,
      recursive: true,
      image: "inputs/Webserver.E01",
      offset: 503808,
    }, bin);
    assert.equal(listed.code, 0, listed.stderr);
    const args = await readFile(join(cwd, "fls-args.txt"), "utf8");
    assert.match(args, /^-o\n503808\n-r\ninputs\/Webserver\.E01\n1831425\n/);
    assert.match(listed.stdout, /d\/d 2/);
  });
});

test("csearch fails when catalog files are absent instead of printing (no matches)", async () => {
  await withCwd(async (cwd) => {
    const out = await runPy(join(LIB, "csearch", "run.py"), cwd, {
      patterns: ["passwd"],
      files: ["filelist"],
    });
    assert.notEqual(out.code, 0);
    assert.doesNotMatch(out.stdout, /\(no matches\)/);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);

    await mkdir(join(cwd, "catalog", "case", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "case", "p0", "filelist.txt"), "etc/passwd\n", "utf8");
    const hit = await runPy(join(LIB, "csearch", "run.py"), cwd, {
      patterns: ["passwd"],
      files: ["filelist"],
      catalog_root: "catalog/case/p0",
    });
    assert.equal(hit.code, 0, hit.stderr);
    assert.match(hit.stdout, /\[filelist\] etc\/passwd/);
  });
});

test("chunk_needles fails closed when the E01 is missing", async () => {
  await withCwd(async (cwd, bin) => {
    const out = await runPy(join(LIB, "chunk_needles", "run.py"), cwd, {
      needles: "foo",
      inode: 12,
    }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string };
    assert.match(body.error, /not found/);
  });
});

test("check_inputs diffs inputs.json instead of always reporting OK", async () => {
  await withCwd(async (cwd) => {
    const missingMan = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.notEqual(missingMan.code, 0);
    assert.match(missingMan.stdout, /inputs\.json not found/);

    await writeFile(
      join(cwd, "inputs.json"),
      JSON.stringify({
        source: "/tmp/src",
        files: [{ path: "inputs/AF-Case2.E01", bytes: 4, sha256: "deadbeef" }],
        bytes: 4,
      }),
      "utf8",
    );
    const mismatch = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.notEqual(mismatch.code, 0);
    const bad = JSON.parse(mismatch.stdout) as { status: string; modified: string[] };
    assert.equal(bad.status, "FAIL");
    assert.ok(bad.modified.includes("inputs/AF-Case2.E01"));

    const { createHash } = await import("node:crypto");
    await rm(join(cwd, "inputs", "Webserver.E01"), { force: true });
    const bytes = await readFile(join(cwd, "inputs", "AF-Case2.E01"));
    const sha = createHash("sha256").update(bytes).digest("hex");
    await writeFile(
      join(cwd, "inputs.json"),
      JSON.stringify({
        source: "/tmp/src",
        files: [{ path: "inputs/AF-Case2.E01", bytes: bytes.length, sha256: sha }],
        bytes: bytes.length,
      }),
      "utf8",
    );
    const ok = await runPy(join(LIB, "check_inputs", "run.py"), cwd, {});
    assert.equal(ok.code, 0, ok.stderr);
    assert.equal((JSON.parse(ok.stdout) as { status: string }).status, "OK");
  });
});

test("volrun declares params and passes args as argv, not a shell string", async () => {
  const man = JSON.parse(await readFile(join(LIB, "volrun", "manifest.json"), "utf8")) as {
    params: Record<string, unknown>;
  };
  assert.ok(man.params.image);
  assert.ok(man.params.plugin);
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "inputs", "mem.dmp"), "dmp\n", "utf8");
    await writeFile(
      join(bin, "vol"),
      `#!/bin/sh
python3 -c 'import json,sys; json.dump(sys.argv[1:], open("vol-args.json","w"))' "$@"
`,
      "utf8",
    );
    await chmod(join(bin, "vol"), 0o755);
    const out = await runPy(join(LIB, "volrun", "run.py"), cwd, {
      image: "inputs/mem.dmp",
      plugin: "windows.pslist",
      args: ["--pid", "356; id"],
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const argv = JSON.parse(await readFile(join(cwd, "vol-args.json"), "utf8")) as string[];
    assert.deepEqual(argv, ["-f", "inputs/mem.dmp", "windows.pslist", "--pid", "356; id"]);
  });
});

function fakeAesBlob(): Buffer {
  // AES v2 header, no extensions, zeros for iv/enc/macs — HMAC will fail.
  return Buffer.concat([
    Buffer.from("AES"),
    Buffer.from([2, 0, 0, 0]),
    Buffer.alloc(16),
    Buffer.alloc(48),
    Buffer.alloc(32),
    Buffer.alloc(16),
    Buffer.from([16]),
    Buffer.alloc(32),
  ]);
}

test("aescrypt_v2_decrypt requires a password and does not write before HMAC", async () => {
  await withCwd(async (cwd) => {
    const src = join(cwd, "inputs", "secret.aes");
    await writeFile(src, fakeAesBlob());
    const noPw = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, { path: "inputs/secret.aes" });
    assert.notEqual(noPw.code, 0);
    assert.match(noPw.stdout, /password is required/);
    const nextToSource = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(nextToSource, null);

    const hmac = await runPy(
      join(LIB, "aescrypt_v2_decrypt", "run.py"),
      cwd,
      { path: "inputs/secret.aes", password: "wrong", output: "work/garbage.dec" },
      undefined,
      { AGENT_ID: "agent07" },
    );
    assert.notEqual(hmac.code, 0);
    assert.match(hmac.stdout, /HMAC failed/);
    const garbage = await readFile(join(cwd, "work", "garbage.dec")).catch(() => null);
    assert.equal(garbage, null, "HMAC failure must not leave plaintext-shaped bytes");
    const defaultNextTo = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(defaultNextTo, null);

    const underInputs = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/secret.aes",
      password: "wrong",
      output: "inputs/secret.aes.dec",
    });
    assert.notEqual(underInputs.code, 0);
    assert.match(underInputs.stdout, /inputs/);
    const leaked = await readFile(join(cwd, "inputs", "secret.aes.dec")).catch(() => null);
    assert.equal(leaked, null);
  });
});

/**
 * A BitLocker volume laid out the way libbde documents it, not the way the
 * parser happens to read it: a 64-byte FVE block header, a 48-byte metadata
 * header whose size field is repeated 12 bytes in, then variable-size
 * entries. A fixture written from the implementation would agree with
 * whatever offsets the implementation picked, so it would prove nothing.
 */
function fakeBitlockerVolume(): Buffer {
  const BLOCK_HEADER = 64;
  const METADATA_HEADER = 48;
  const VMK_ENTRY = 40;
  const buf = Buffer.alloc(0x20000, 0);
  buf.write("-FVE-FS-", 3, "ascii");
  // Volume header: three uint64 byte offsets to the metadata blocks.
  buf.writeBigUInt64LE(0x10000n, 0xa0);
  buf.writeBigUInt64LE(0x18000n, 0xa8);
  buf.writeBigUInt64LE(0x1c000n, 0xb0);
  // The old tool took its GUID and its encryption method from the sector
  // after the boot record. Both are decoys, and neither may be reported.
  buf.write("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", 512, "ascii");
  buf.writeUInt16LE(0x8000, 512 + 0x28);
  const guid = Buffer.from("a1b2c3d4e5f60718293a4b5c6d7e8f90", "hex");
  const keyGuid = Buffer.from("0f1e2d3c4b5a69788796a5b4c3d2e1f0", "hex");
  const writeMeta = (off: number) => {
    // FVE metadata block header.
    buf.write("-FVE-FS-", off, "ascii");
    buf.writeUInt16LE(BLOCK_HEADER, off + 8); // the block header's own size
    buf.writeUInt16LE(2, off + 10); // version
    buf.writeBigUInt64LE(0x20000n, off + 16); // encrypted volume size
    buf.writeUInt32LE(1, off + 28); // volume header sectors
    buf.writeBigUInt64LE(0x10000n, off + 32);
    buf.writeBigUInt64LE(0x18000n, off + 40);
    buf.writeBigUInt64LE(0x1c000n, off + 48);
    buf.writeBigUInt64LE(0n, off + 56); // volume header offset
    // FVE metadata header.
    const meta = off + BLOCK_HEADER;
    const metaSize = METADATA_HEADER + VMK_ENTRY;
    buf.writeUInt32LE(metaSize, meta); // the metadata, its entries included
    buf.writeUInt32LE(1, meta + 4); // version
    buf.writeUInt32LE(METADATA_HEADER, meta + 8);
    buf.writeUInt32LE(metaSize, meta + 12); // the copy the parser checks against
    guid.copy(buf, meta + 16);
    buf.writeUInt32LE(3, meta + 32); // next nonce counter
    buf.writeUInt32LE(0x8004, meta + 36); // AES-XTS 128
    buf.writeBigUInt64LE(0n, meta + 40); // creation time
    // One VMK entry, protected by a recovery password.
    const e = meta + METADATA_HEADER;
    buf.writeUInt16LE(VMK_ENTRY, e);
    buf.writeUInt16LE(2, e + 2); // entry type: volume master key
    buf.writeUInt16LE(2, e + 4); // value type
    buf.writeUInt16LE(1, e + 6); // version
    keyGuid.copy(buf, e + 8);
    buf.writeBigUInt64LE(0n, e + 24); // last modification time
    buf.writeUInt16LE(0x0800, e + 34); // protection type: recovery password
  };
  writeMeta(0x10000);
  writeMeta(0x18000);
  writeMeta(0x1c000);
  return buf;
}

test("fve_metadata reads header offsets, not the three sectors after the boot record", async () => {
  await withCwd(async (cwd) => {
    const img = join(cwd, "inputs", "bitlocker.raw");
    await writeFile(img, fakeBitlockerVolume());
    const out = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/bitlocker.raw" });
    assert.equal(out.code, 0, out.stderr + out.stdout);
    const body = JSON.parse(out.stdout) as {
      volume_guid: string;
      encryption_method: string;
      key_protectors: string[];
      recovery_password_protector: boolean;
      metadata_blocks: unknown[];
    };
    assert.doesNotMatch(out.stdout, /\nFVE metadata block/);
    assert.equal(body.volume_guid, "d4c3b2a1-f6e5-1807-293a-4b5c6d7e8f90");
    assert.notEqual(body.volume_guid, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    assert.equal(body.encryption_method, "AES-XTS 128");
    assert.deepEqual(body.key_protectors, ["recovery password"]);
    assert.equal(body.recovery_password_protector, true);
    assert.equal(body.metadata_blocks.length, 3);

    const missing = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/nope.raw" });
    assert.notEqual(missing.code, 0);
    assert.match(JSON.parse(missing.stdout).error, /not found/);
  });
});

test("fve_metadata refuses a metadata size that disagrees with its own copy", async () => {
  await withCwd(async (cwd) => {
    // The metadata header repeats its size 12 bytes in. Disagreement means
    // the read landed somewhere that is not a metadata header, and a
    // forensic answer from there would be plausible and wrong.
    const buf = fakeBitlockerVolume();
    buf.writeUInt32LE(0x4000, 0x10000 + 64 + 12);
    const img = join(cwd, "inputs", "torn.raw");
    await writeFile(img, buf);
    const out = await runPy(join(LIB, "fve_metadata", "run.py"), cwd, { path: "inputs/torn.raw" });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /disagrees with its copy/);
  });
});

test("icat_root says why icat failed instead of exiting on its code alone", async () => {
  await withCwd(async (cwd, bin) => {
    // A bare non-zero exit gave the agent an empty stdout and no way to tell
    // a bad inode from a missing image, so the next turn guessed.
    await writeFile(join(bin, "icat"), '#!/bin/sh\necho "cannot find inode" >&2\nexit 1\n', "utf8");
    await chmod(join(bin, "icat"), 0o755);
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 99 }, bin);
    assert.notEqual(out.code, 0);
    const body = JSON.parse(out.stdout) as { error: string; exit_code: number; stderr: string };
    assert.match(body.error, /icat failed/);
    assert.equal(body.exit_code, 1);
    assert.match(body.stderr, /cannot find inode/);
  });
});

test("grep_filelist names a bad pattern instead of raising re.error", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "catalog", "AF-Case2.E01", "p0"), { recursive: true });
    await writeFile(join(cwd, "catalog", "AF-Case2.E01", "p0", "filelist.txt"), "safe.txt\n", "utf8");
    const bad = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "unclosed[" });
    assert.notEqual(bad.code, 0);
    assert.match(JSON.parse(bad.stdout).error, /not a valid regular expression/);
  });
});

test("grep_filelist fails closed when the catalog filelist is absent", async () => {
  await withCwd(async (cwd) => {
    const out = await runPy(join(LIB, "grep_filelist", "run.py"), cwd, { pattern: "." });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /cannot read the catalog filelist/);
  });
});

test("aescrypt_v2_decrypt refuses an output that resolves back under inputs/", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "secret.aes"), fakeAesBlob());
    // "inputs/" is not a prefix of this path, but it is where the file lands,
    // and a decrypted secret written there would show up as tampering in the
    // next inputs check.
    const out = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/secret.aes",
      password: "pw",
      output: "work/../inputs/leaked.txt",
    });
    assert.notEqual(out.code, 0);
    assert.match(JSON.parse(out.stdout).error, /cannot be under inputs/);
    const leaked = await readFile(join(cwd, "inputs", "leaked.txt")).catch(() => null);
    assert.equal(leaked, null);
  });
});

test("aescrypt_v2_decrypt reports a truncated file instead of an IndexError", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "inputs", "stub.aes"), Buffer.concat([Buffer.from("AES"), Buffer.from([2, 0, 0, 0])]));
    const out = await runPy(join(LIB, "aescrypt_v2_decrypt", "run.py"), cwd, {
      path: "inputs/stub.aes",
      password: "pw",
      output: "work/stub.txt",
    });
    assert.notEqual(out.code, 0);
    assert.doesNotMatch(out.stderr, /Traceback/);
    assert.match(JSON.parse(out.stdout).error, /truncated/);
  });
});

test("master_icat reads its arguments once, so the output branch runs", async () => {
  await withCwd(async (cwd, bin) => {
    // Two `python3 -c` readers meant the second got EOF, and under `set -e`
    // the script died before icat ever ran.
    const out = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 42,
      output: "work/hdfs/out.bin",
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as { inode: number; output: string; size: number };
    assert.equal(body.inode, 42);
    assert.equal(body.output, "work/hdfs/out.bin");
    assert.equal(body.size, "extracted-bytes".length);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n2048\ninputs\/HDFS-Master\.E01\n42\n/);
  });
});

test("master_icat refuses an inode that is not a number and an escaping output", async () => {
  await withCwd(async (cwd, bin) => {
    const bad = await runSh(join(LIB, "master_icat", "run.sh"), cwd, { inode: "7; touch pwned" }, bin);
    assert.notEqual(bad.code, 0);
    assert.match(bad.stdout, /inode must be a non-negative integer/);
    const escaped = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 7,
      output: "../outside.bin",
    }, bin);
    assert.notEqual(escaped.code, 0);
    assert.match(escaped.stdout, /must stay inside the run directory/);
    const pwned = await readFile(join(cwd, "pwned")).catch(() => null);
    assert.equal(pwned, null);
  });
});

test("icat writers refuse an output that resolves under inputs/, and do not run icat", async () => {
  // A prefix check on the string the caller typed misses work/../inputs/x.
  // These four used to write there; aescrypt_v2_decrypt already refused it.
  const writers: Array<{ name: string; run: (cwd: string, bin: string, output: string) => Promise<{ code: number | null; stdout: string }> }> = [
    {
      name: "icat_extract",
      run: (cwd, bin, output) => runPy(join(LIB, "icat_extract", "run.py"), cwd, { inode: 7, output }, bin),
    },
    {
      name: "icat_root",
      run: (cwd, bin, output) => runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 7, output }, bin),
    },
    {
      name: "hdfs_node_icat",
      run: (cwd, bin, output) => runPy(join(LIB, "hdfs_node_icat", "run.py"), cwd, { inode: "7", output, node: "master" }, bin),
    },
    {
      name: "master_icat",
      run: (cwd, bin, output) => runSh(join(LIB, "master_icat", "run.sh"), cwd, { inode: 7, output }, bin),
    },
  ];
  for (const writer of writers) {
    await withCwd(async (cwd, bin) => {
      const out = await writer.run(cwd, bin, "work/../inputs/leaked.bin");
      assert.notEqual(out.code, 0, writer.name);
      assert.match(out.stdout, /cannot be under inputs/, writer.name);
      const leaked = await readFile(join(cwd, "inputs", "leaked.bin")).catch(() => null);
      assert.equal(leaked, null, writer.name);
      const args = await readFile(join(cwd, "icat-args.txt"), "utf8").catch(() => null);
      assert.equal(args, null, `${writer.name} must not reach icat`);
    });
  }
});

test("extract_stream returns the bytes, and an icat failure as JSON rather than base64", async () => {
  await withCwd(async (cwd, bin) => {
    const good = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "168-128-4",
      offset: 0,
    }, bin);
    assert.equal(good.code, 0, good.stderr);
    assert.equal(Buffer.from(good.stdout.trim(), "base64").toString("utf8"), "extracted-bytes");

    // It used to be `icat … 2>&1 | base64`: the error text was encoded as if
    // it were file content, and the pipe made the status base64's, so every
    // call exited 0. A caller decoding that got a plausible-looking blob.
    await failingStub(bin, "icat", "Error looking up inode: 9999");
    const bad = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "9999",
      offset: 0,
    }, bin);
    assert.equal(bad.code, 1, "a failed extraction must not exit 0");
    const body = JSON.parse(bad.stdout) as { error: string; status: number; stderr: string };
    assert.equal(body.error, "icat failed");
    assert.equal(body.status, 1);
    assert.match(body.stderr, /Error looking up inode/);
  });
});

test("extract_stream refuses arguments it cannot use", async () => {
  await withCwd(async (cwd, bin) => {
    const noImage = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, { inode: "5" }, bin);
    assert.notEqual(noImage.code, 0);
    assert.match(noImage.stdout, /image must be a single-line path/);
    const badOffset = await runSh(join(LIB, "extract_stream", "run.sh"), cwd, {
      image: "inputs/AF-Case2.E01",
      inode: "5",
      offset: -1,
    }, bin);
    assert.notEqual(badOffset.code, 0);
    assert.match(badOffset.stdout, /offset must be a non-negative sector count/);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8").catch(() => null);
    assert.equal(args, null, "a refused call must not reach icat");
  });
});

async function imgStubs(bin: string, sizeLine: string | null): Promise<void> {
  if (sizeLine === null) {
    await failingStub(bin, "img_stat", "Cannot determine file type");
  } else {
    const stat = join(bin, "img_stat");
    await writeFile(stat, `#!/bin/sh\necho "${sizeLine}"\n`, "utf8");
    await chmod(stat, 0o755);
  }
  const cat = join(bin, "img_cat");
  // 1024 bytes with the needle at offset 100 of the chunk.
  await writeFile(
    cat,
    `#!/bin/sh\npython3 -c 'import sys; sys.stdout.buffer.write(b"." * 100 + b"NEEDLE" + b"." * 918)'\n`,
    "utf8",
  );
  await chmod(cat, 0o755);
}

type Scan = {
  hits: { offset: number; sector: number }[];
  hit_count: number;
  media_size: number | null;
  media_size_source: string | null;
  reached_end: boolean;
  end: number;
};

test("sigscan_e01 scans the range img_stat gives it", async () => {
  await withCwd(async (cwd, bin) => {
    await imgStubs(bin, "Size of data in bytes: 4096");
    const out = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
      start: 512,
      length: 1024,
    }, bin);
    assert.equal(out.code, 0, out.stderr);
    const body = JSON.parse(out.stdout) as Scan;
    assert.equal(body.hit_count, 1);
    assert.equal(body.hits[0].offset, 612);
    assert.equal(body.hits[0].sector, 1);
    assert.equal(body.media_size, 4096);
    assert.equal(body.media_size_source, "img_stat");
    assert.equal(body.reached_end, true);
  });
});

test("sigscan_e01 refuses to invent a media size when img_stat cannot give one", async () => {
  await withCwd(async (cwd, bin) => {
    await imgStubs(bin, null);
    // It used to assume 42949672960 bytes — 40 GiB — and report that as the
    // image's size. On anything smaller it walked a range that does not
    // exist, read nothing, and called the result "no hits". A scan that says
    // a signature is absent has to have covered the span it names.
    const out = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
    }, bin);
    assert.equal(out.code, 1, out.stderr);
    assert.doesNotMatch(out.stdout, /42949672960/, "the hard-coded 40 GiB guess must be gone");
    const body = JSON.parse(out.stdout) as { error: string; img_stat: string };
    assert.match(body.error, /cannot determine the media size/);
    assert.match(body.img_stat, /Cannot determine file type/);

    // With an explicit length the caller has bounded the scan, so it runs.
    const bounded = await runPy(join(LIB, "sigscan_e01", "run.py"), cwd, {
      image: "inputs/AF-Case2.E01",
      needle_ascii: "NEEDLE",
      start: 512,
      length: 1024,
    }, bin);
    assert.equal(bounded.code, 0, bounded.stderr);
    const scan = JSON.parse(bounded.stdout) as Scan;
    assert.equal(scan.media_size, null);
    assert.equal(scan.media_size_source, "length argument");
    assert.equal(scan.end, 1536);
    assert.equal(scan.hit_count, 1);
  });
});

const RENDER_DRIVER = [
  "import importlib.util, json, sys, types",
  "stubs = {'regipy': {}, 'regipy.registry': {'RegistryHive': object},",
  "         'regipy.exceptions': {'RegistryKeyNotFoundException': type('E', (Exception,), {})}}",
  "for name, attrs in stubs.items():",
  "    mod = types.ModuleType(name)",
  "    for k, v in attrs.items():",
  "        setattr(mod, k, v)",
  "    sys.modules[name] = mod",
  "spec = importlib.util.spec_from_file_location('regkeys', sys.argv[1])",
  "mod = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(mod)",
  "out = []",
  "for case in json.load(sys.stdin):",
  "    raw = bytes.fromhex(case['hex']) if 'hex' in case else case['value']",
  "    value, encoding = mod.render(raw, case['type'])",
  "    out.append({'value': value, 'encoding': encoding})",
  "print(json.dumps(out))",
].join("\n");

test("regkeys renders a value by its registry type, so REG_BINARY stays hex", async () => {
  // Every bytes value used to be decoded utf-16-le with errors="replace",
  // which turned a ShimCache or UserAssist blob into mojibake that reads
  // like text; "replace" never raises, so the hex branch under it was dead.
  // regkv and reg_hive_query already answer hex for the same value.
  const sz = `${Buffer.from("C:\\Windows", "utf16le").toString("hex")}0000`;
  const multi = Buffer.from("a\u0000b\u0000", "utf16le").toString("hex");
  const binary = "deadbeef00ff";
  const out = await runPySnippet(RENDER_DRIVER, [join(LIB, "regkeys", "run.py")], [
    { type: "REG_SZ", hex: sz },
    { type: "REG_MULTI_SZ", hex: multi },
    { type: "REG_BINARY", hex: binary },
    { type: "REG_NONE", hex: binary },
    { type: "REG_DWORD", value: 1234 },
  ]);
  assert.equal(out.code, 0, out.stderr);
  const rendered = JSON.parse(out.stdout) as { value: unknown; encoding: string | null }[];
  assert.deepEqual(rendered[0], { value: "C:\\Windows", encoding: "utf-16-le" });
  assert.deepEqual(rendered[1], { value: ["a", "b"], encoding: "utf-16-le" });
  assert.deepEqual(rendered[2], { value: binary, encoding: "hex" });
  assert.deepEqual(rendered[3], { value: binary, encoding: "hex" });
  assert.deepEqual(rendered[4], { value: 1234, encoding: null });
});

test("the tools that name an image take one as a parameter", async () => {
  // Three of these hard-coded the image they were written for, so they were
  // unusable on any other case. A default is fine; no way to override it is
  // a tool the next run has to write again.
  for (const name of ["icat_root", "master_icat", "hdfs_node_icat", "fls_root", "sigscan_e01", "chunk_needles"]) {
    const manifest = JSON.parse(await readFile(join(LIB, name, "manifest.json"), "utf8")) as { params: Record<string, unknown> };
    const keys = Object.keys(manifest.params);
    assert.ok(
      keys.includes("image") || keys.includes("path") || keys.includes("e01"),
      `${name} names an image in its script but takes no parameter for one (params: ${keys.join(", ")})`,
    );
  }
});

test("icat_root and master_icat read the image they are given, not the one they were written for", async () => {
  await withCwd(async (cwd, bin) => {
    // The default image is not in this directory, and neither is the one
    // named here: both must be reported as missing rather than assumed.
    const out = await runPy(join(LIB, "icat_root", "run.py"), cwd, {
      inode: 12,
      image: "inputs/NotHere.E01",
    }, bin);
    assert.notEqual(out.code, 0);
    assert.match(out.stdout, /image not found/);
    assert.match(out.stdout, /NotHere\.E01/, "the message names the image it was given");

    await writeFile(join(cwd, "inputs", "Other.E01"), "img\n", "utf8");
    const ok = await runPy(join(LIB, "icat_root", "run.py"), cwd, { inode: 12, image: "inputs/Other.E01", offset: 2048 }, bin);
    assert.equal(ok.code, 0, ok.stderr);
    const args = await readFile(join(cwd, "icat-args.txt"), "utf8");
    assert.match(args, /^-o\n2048\ninputs\/Other\.E01\n12\n/, "the offset and image reached icat");

    const viaSh = await runSh(join(LIB, "master_icat", "run.sh"), cwd, {
      inode: 7,
      output: "work/out.bin",
      image: "inputs/Other.E01",
      offset: 63,
    }, bin);
    assert.equal(viaSh.code, 0, viaSh.stderr);
    const body = JSON.parse(viaSh.stdout) as { image: string; offset: number };
    assert.equal(body.image, "inputs/Other.E01");
    assert.equal(body.offset, 63);
  });
});

