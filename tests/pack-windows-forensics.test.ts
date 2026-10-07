/**
 * The windows-forensics pack's tools, against fixtures the test builds from the
 * formats' own layouts and never from a tool's output.
 *
 * Where each layout comes from:
 *   lnk_parse    MS-SHLLINK (the shell link header, LinkInfo, VolumeID,
 *                CommonNetworkRelativeLink), every offset from the start of its
 *                own structure.
 *   jumplist     the DestList stream as libyal's jump list format notes lay it out:
 *                a 32-byte header; an entry's fixed part of 114 bytes (version 1)
 *                or 130 bytes (versions 3 and 4) with the path length in
 *                characters at 0x70 or 0x80 and the path after it; a 4-byte
 *                trailer after the path in versions 3 and 4.
 *   registry     the regf layout (a 4096-byte base block, hbins of cells: nk, li,
 *                vk, value lists, data), written by `hive()` below.
 *   programs     a stub on PATH stands in for each program a tool calls
 *                (esedbexport, vshadowinfo, yara, zircolite, hayabusa, icat), written
 *                to behave as that program's documented output does.
 *
 * To see that a test fails on the code it was written against, point
 * WINDOWS_PACK_TOOLS at a copy of the pack's tools as they were before the fix:
 *
 *   git archive origin/claude/pack-standard-and-links packs/windows-forensics/tools | tar -x -C /tmp/old
 *   WINDOWS_PACK_TOOLS=/tmp/old/packs/windows-forensics/tools \
 *     node --experimental-strip-types --test tests/pack-windows-forensics.test.ts
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPy, withCwd } from "./tool-library-harness.ts";
import { hive } from "./windows-hive.ts";

const WIN = process.env.WINDOWS_PACK_TOOLS ?? join(ROOT, "packs", "windows-forensics", "tools");
const AGENT = { AGENT_ID: "s1" };

type Run = { code: number | null; stdout: string; stderr: string };

async function tool(name: string, cwd: string, args: unknown, env: Record<string, string> = {}, bin?: string): Promise<Run> {
  return runPy(join(WIN, name, "run.py"), cwd, args, bin, { ...AGENT, ...env });
}

function body<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

/** A refusal or a failure: a non-zero exit and a JSON answer with an `error`. */
function failed(out: Run): { error: string; [key: string]: unknown } {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string };
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

async function stub(bin: string, name: string, script: string): Promise<void> {
  await mkdir(bin, { recursive: true });
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\n${script}\n`, "utf8");
  await chmod(path, 0o755);
}

/** Run python3 with code, for fixtures a Buffer is awkward for. */
function py(code: string, ...args: string[]): string {
  const out = spawnSync("python3", ["-c", code, ...args], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  return out.stdout;
}

const u16 = (text: string): Buffer => Buffer.from(text, "utf16le");
const asciiz = (text: string): Buffer => Buffer.concat([Buffer.from(text, "latin1"), Buffer.from([0])]);
const u16z = (text: string): Buffer => Buffer.concat([u16(text), Buffer.from([0, 0])]);

// --- lnk_parse ------------------------------------------------------------------

const SHELL_LINK_CLSID = Buffer.from("0114020000000000c000000000000046", "hex");
const FILETIME_BASE = 133_443_104_000_000_000n + 1_234_567n; // 2023-11-13T00:53:20.1234567Z

/** The 76-byte ShellLinkHeader: HeaderSize, LinkCLSID, LinkFlags, FileAttributes, three FILETIMEs, FileSize, IconIndex, ShowCommand, HotKey, three reserved fields. */
function lnkHeader(flags: number, times: [bigint, bigint, bigint] = [FILETIME_BASE, FILETIME_BASE + 10_000_000n, FILETIME_BASE + 20_000_000n]): Buffer {
  const h = Buffer.alloc(0x4c);
  h.writeUInt32LE(0x4c, 0);
  SHELL_LINK_CLSID.copy(h, 4);
  h.writeUInt32LE(flags, 0x14);
  h.writeUInt32LE(0x20, 0x18);
  h.writeBigUInt64LE(times[0], 0x1c);
  h.writeBigUInt64LE(times[1], 0x24);
  h.writeBigUInt64LE(times[2], 0x2c);
  h.writeUInt32LE(4321, 0x34);
  h.writeUInt32LE(1, 0x3c);
  return h;
}

/** VolumeID: VolumeIDSize, DriveType, DriveSerialNumber, VolumeLabelOffset (0x10), then the ANSI label. */
function volumeId(driveType: number, serial: number, label: string): Buffer {
  const text = asciiz(label);
  const v = Buffer.alloc(0x10 + text.length);
  v.writeUInt32LE(v.length, 0);
  v.writeUInt32LE(driveType, 4);
  v.writeUInt32LE(serial, 8);
  v.writeUInt32LE(0x10, 12);
  text.copy(v, 0x10);
  return v;
}

/** CommonNetworkRelativeLink with the 0x14-byte fixed part: ValidDevice and ValidNetType, the net name, the device name. */
function networkLink(netName: string, deviceName: string, provider: number): Buffer {
  const net = asciiz(netName);
  const dev = asciiz(deviceName);
  const n = Buffer.alloc(0x14 + net.length + dev.length);
  n.writeUInt32LE(n.length, 0);
  n.writeUInt32LE(3, 4);
  n.writeUInt32LE(0x14, 8);
  n.writeUInt32LE(0x14 + net.length, 12);
  n.writeUInt32LE(provider, 16);
  net.copy(n, 0x14);
  dev.copy(n, 0x14 + net.length);
  return n;
}

/**
 * LinkInfo with a 0x1C-byte header (ANSI offsets only) or a 0x24-byte one (the two
 * Unicode offsets after them). Layout: LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags,
 * VolumeIDOffset, LocalBasePathOffset, CommonNetworkRelativeLinkOffset,
 * CommonPathSuffixOffset, [LocalBasePathOffsetUnicode, CommonPathSuffixOffsetUnicode].
 */
function linkInfo(o: { volume?: Buffer; localAnsi?: string; localUnicode?: string; network?: Buffer; suffixAnsi?: string; suffixUnicode?: string }): Buffer {
  const unicode = o.localUnicode !== undefined || o.suffixUnicode !== undefined;
  const headerSize = unicode ? 0x24 : 0x1c;
  const parts: Buffer[] = [];
  let at = headerSize;
  const place = (b: Buffer | undefined): number => {
    if (!b) return 0;
    const where = at;
    parts.push(b);
    at += b.length;
    return where;
  };
  const volumeOffset = place(o.volume);
  const localOffset = place(o.localAnsi === undefined ? undefined : asciiz(o.localAnsi));
  const networkOffset = place(o.network);
  const suffixOffset = place(asciiz(o.suffixAnsi ?? ""));
  const localUnicodeOffset = place(o.localUnicode === undefined ? undefined : u16z(o.localUnicode));
  const suffixUnicodeOffset = place(o.suffixUnicode === undefined ? undefined : u16z(o.suffixUnicode));
  const h = Buffer.alloc(headerSize);
  h.writeUInt32LE(at, 0);
  h.writeUInt32LE(headerSize, 4);
  h.writeUInt32LE((o.volume ? 1 : 0) | (o.network ? 2 : 0), 8);
  h.writeUInt32LE(volumeOffset, 12);
  h.writeUInt32LE(localOffset, 16);
  h.writeUInt32LE(networkOffset, 20);
  h.writeUInt32LE(suffixOffset, 24);
  if (unicode) {
    h.writeUInt32LE(localUnicodeOffset, 28);
    h.writeUInt32LE(suffixUnicodeOffset, 32);
  }
  return Buffer.concat([h, ...parts]);
}

type LnkOut = {
  ok: boolean;
  created: string | null;
  created_filetime: string;
  accessed: string | null;
  written: string | null;
  linkinfo_size?: number;
  linkinfo_header_size?: number;
  volume?: { drive_type: number; drive_type_name: string; serial_number: string; label: string };
  local_base_path?: string;
  local_base_path_ansi?: string | null;
  local_base_path_unicode?: string;
  common_path?: string;
  common_path_suffix_ansi?: string | null;
  network?: { net_name: string; device_name: string; provider_type: string; provider_name?: string };
  linkinfo_target?: string;
  linkinfo_target_kind?: string;
  problems: string[];
  structure_complete: boolean;
};

const TERMINAL = Buffer.alloc(4);

test("lnk_parse reads LinkInfo by the MS-SHLLINK layout: the local path, the volume serial, drive type and label", async () => {
  // The fields were unpacked in the wrong order (LinkInfoFlags taken for the volume
  // offset, the VolumeID offset for the local path's), so the local path came out as
  // one stray byte from inside the VolumeID, and no serial was read at all.
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({ volume: volumeId(3, 0x1a2b3c4d, "SYSTEM"), localAnsi: "C:\\case\\report.txt" }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "local.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/local.lnk", size: 4096 }));
    assert.equal(out.ok, true);
    assert.equal(out.local_base_path, "C:\\case\\report.txt");
    assert.equal(out.linkinfo_target, "C:\\case\\report.txt");
    assert.equal(out.linkinfo_target_kind, "local");
    assert.equal(out.volume?.serial_number, "1A2B3C4D");
    assert.equal(out.volume?.drive_type, 3);
    assert.equal(out.volume?.drive_type_name, "fixed");
    assert.equal(out.volume?.label, "SYSTEM");
    assert.equal(out.structure_complete, true);
    assert.deepEqual(out.problems, []);
  });
});

test("lnk_parse reads the Unicode path and suffix at their own offsets when the header is 0x24 bytes", async () => {
  // The ANSI path was decoded as UTF-16 and the Unicode offsets were never read.
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({
        volume: volumeId(2, 0xdeadbeef, "USBSTICK"),
        localAnsi: "C:\\case\\rapor",
        localUnicode: "C:\\case\\rapör",
        suffixAnsi: "notlar.txt",
        suffixUnicode: "notlär.txt",
      }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "unicode.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/unicode.lnk" }));
    assert.equal(out.linkinfo_header_size, 0x24);
    assert.equal(out.local_base_path_ansi, "C:\\case\\rapor");
    assert.equal(out.local_base_path_unicode, "C:\\case\\rapör");
    assert.equal(out.local_base_path, "C:\\case\\rapör", "the Unicode form is preferred where the file has one");
    assert.equal(out.common_path, "notlär.txt");
    assert.equal(out.linkinfo_target, "C:\\case\\rapör" + "notlär.txt");
    assert.equal(out.volume?.drive_type_name, "removable");
    assert.equal(out.volume?.serial_number, "DEADBEEF");
  });
});

test("lnk_parse reads a CommonNetworkRelativeLink: the share, the device and the provider, and joins the suffix", async () => {
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02),
      linkInfo({ network: networkLink("\\\\fileserver\\finance", "Z:", 0x00020000), suffixAnsi: "Q4.xlsx" }),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "unc.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/unc.lnk" }));
    assert.equal(out.network?.net_name, "\\\\fileserver\\finance");
    assert.equal(out.network?.device_name, "Z:");
    assert.equal(out.network?.provider_type, "0x00020000");
    assert.equal(out.linkinfo_target, "\\\\fileserver\\finance\\Q4.xlsx");
    assert.equal(out.linkinfo_target_kind, "network");
    assert.equal(out.volume, undefined, "a network link has no VolumeID, and none is invented");
  });
});

test("lnk_parse keeps the raw FILETIMEs beside the dates, with every fractional digit, by integer arithmetic", async () => {
  // 133443104001234567 ticks is 2023-11-13T00:53:20.1234567Z; a float division by ten
  // lost the last digits, and the raw value was not returned at all.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "t.lnk"), Buffer.concat([lnkHeader(0x00), TERMINAL]));
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/t.lnk" }));
    assert.equal(out.created_filetime, String(FILETIME_BASE));
    assert.equal(out.created, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.accessed, "2023-11-13T00:53:21.1234567Z");
    assert.equal(out.written, "2023-11-13T00:53:22.1234567Z");
  });
});

test("lnk_parse says a read that ends inside LinkInfo ends there, and does not read the strings after it from the wrong place", async () => {
  await withCwd(async (cwd) => {
    const lnk = Buffer.concat([
      lnkHeader(0x02 | 0x04 | 0x80),
      linkInfo({ volume: volumeId(3, 1, "X"), localAnsi: "C:\\a\\b.txt" }),
      Buffer.from([4, 0]),
      u16("name"),
      TERMINAL,
    ]);
    await writeFile(join(cwd, "work", "cut.lnk"), lnk);
    const out = body<LnkOut>(await tool("lnk_parse", cwd, { path: "work/cut.lnk", size: 0x4c + 20 }));
    assert.equal(out.structure_complete, false);
    assert.ok(out.problems.some((p) => /LinkInfo declares \d+ bytes and 20 were read/.test(p)), out.problems.join(" | "));
    assert.equal(out.local_base_path, undefined);
    // Read whole, the same file is complete and its string data is in place.
    const whole = body<LnkOut & { name: string }>(await tool("lnk_parse", cwd, { path: "work/cut.lnk" }));
    assert.equal(whole.structure_complete, true);
    assert.equal(whole.name, "name");
  });
});

test("lnk_parse refuses an arguments error and a file that is no link, with an error and a non-zero exit", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "no.lnk"), Buffer.alloc(200, 7));
    const notLink = failed(await tool("lnk_parse", cwd, { path: "work/no.lnk" }));
    assert.match(notLink.error, /not a LNK header/);
    assert.match(failed(await tool("lnk_parse", cwd, { path: "work/no.lnk", offset: -4 })).error, /offset must be a whole number/);
    assert.match(failed(await tool("lnk_parse", cwd, { path: "work/no.lnk", size: "big" })).error, /size must be a whole number/);
  });
});

// --- jumplist -------------------------------------------------------------------

const LNK_MAGIC = Buffer.from("4c0000000114020000000000c000000000000046", "hex");

// olefile reads a compound file; this stub reads a JSON map of stream names to hex,
// which is all jumplist asks of it.
const OLEFILE_STUB = String.raw`
import json


def isOleFile(path):
    return True


class _Stream:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class OleFileIO:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self._streams = json.load(fh)

    def listdir(self):
        return [[name] for name in self._streams]

    def get_size(self, name):
        return len(bytes.fromhex(self._streams[name]))

    def openstream(self, name):
        return _Stream(bytes.fromhex(self._streams[name]))

    def close(self):
        pass
`;

async function stubModule(cwd: string, files: Record<string, string>): Promise<Record<string, string>> {
  const dir = join(cwd, "pystub");
  for (const [name, text] of Object.entries(files)) {
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), text, "utf8");
  }
  return { PYTHONPATH: dir };
}

type DestEntry = { number: number; host: string; filetime: bigint; pin: number; path: string };

/** A DestList stream: a 32-byte header, then entries by their version's layout (114-byte fixed part in version 1; 130 bytes and a 4-byte trailer in 3 and 4). */
function destList(version: number, entries: DestEntry[]): Buffer {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(version, 0);
  header.writeUInt32LE(entries.length, 4);
  header.writeUInt32LE(entries.filter((e) => e.pin !== -1).length, 8);
  const fixed = version === 1 ? 114 : 130;
  const charsAt = version === 1 ? 0x70 : 0x80;
  const trailer = version === 1 ? 0 : 4;
  const rows = entries.map((e) => {
    const b = Buffer.alloc(fixed + e.path.length * 2 + trailer);
    b.write(e.host, 0x48, "latin1");
    b.writeUInt32LE(e.number, 0x58);
    b.writeUInt32LE(0x11223344, 0x5c);
    b.writeUInt32LE(0x55667788, 0x60);
    b.writeBigUInt64LE(e.filetime, 0x64);
    b.writeInt32LE(e.pin, 0x6c);
    if (version !== 1) for (let i = 0; i < 4; i++) b.writeUInt32LE(0xa1 + i, 0x70 + i * 4);
    b.writeUInt16LE(e.path.length, charsAt);
    b.write(e.path, fixed, "utf16le");
    return b;
  });
  return Buffer.concat([header, ...rows]);
}

type JumpEntry = {
  entry_number: number;
  stream: string;
  path: string;
  hostname: string;
  last_access: string | null;
  last_access_filetime: string;
  pin_status: number;
  pinned: boolean;
  access_count?: unknown;
};
type Jump = {
  status: string;
  files: Array<{
    file: string;
    format?: string;
    destlist_version?: number;
    entries: JumpEntry[];
    entry_count: number;
    problems?: string[];
    links: Array<{ stream?: string; is_link: boolean; path?: string; last_access?: string | null; carved?: boolean }>;
    method?: string;
    error?: string;
  }>;
  file_count: number;
  files_failed: number;
};

for (const version of [1, 3, 4]) {
  test(`jumplist reads a version ${version} DestList by its own layout: the path, the host, the last access and the pin state of every entry`, async () => {
    // One 118-byte layout with the path length at 0x74 was used for every version, so a version 3 or 4
    // list came back with three-NUL paths, a pin state of "pinned" for an unpinned entry, and no problem.
    await withCwd(async (cwd) => {
      const env = await stubModule(cwd, { "olefile.py": OLEFILE_STUB });
      const entries: DestEntry[] = [
        { number: 1, host: "WIN-DC01", filetime: 133_443_104_001_234_567n, pin: -1, path: "\\\\fileserver\\finance\\Q4.xlsx" },
        { number: 10, host: "WIN-DC01", filetime: 133_443_104_101_234_567n, pin: 3, path: "C:\\case\\report.txt" },
      ];
      const streams: Record<string, string> = { DestList: destList(version, entries).toString("hex") };
      streams["1"] = Buffer.concat([LNK_MAGIC, Buffer.from("one")]).toString("hex");
      streams["a"] = Buffer.concat([LNK_MAGIC, Buffer.from("ten")]).toString("hex");
      streams["b"] = Buffer.concat([LNK_MAGIC.subarray(0, 4), Buffer.alloc(30, 0x41)]).toString("hex");
      await writeFile(join(cwd, "work", "1b4dd67f29cb1962.automaticDestinations-ms"), JSON.stringify(streams), "utf8");
      const out = body<Jump>(await tool("jumplist", cwd, { path: "work/1b4dd67f29cb1962.automaticDestinations-ms" }, env));
      const file = out.files[0];
      assert.equal(out.status, "complete");
      assert.equal(file.destlist_version, version);
      assert.deepEqual(file.problems ?? [], []);
      assert.equal(file.entry_count, 2);
      const [first, second] = file.entries;
      assert.equal(first.path, "\\\\fileserver\\finance\\Q4.xlsx");
      assert.equal(first.hostname, "WIN-DC01");
      assert.equal(first.entry_number, 1);
      assert.equal(first.stream, "1");
      assert.equal(first.last_access, "2023-11-13T00:53:20.1234567Z");
      assert.equal(first.last_access_filetime, "133443104001234567");
      assert.equal(first.pinned, false);
      assert.equal(first.pin_status, -1);
      assert.equal(second.path, "C:\\case\\report.txt");
      assert.equal(second.stream, "a");
      assert.equal(second.pinned, true);
      assert.equal(second.pin_status, 3);
      assert.equal(second.last_access_filetime, "133443104101234567");
      assert.equal(second.last_access, "2023-11-13T00:53:30.1234567Z");
      assert.equal(first.access_count, undefined, "no access count is claimed");
      // The links carry the DestList's path by their stream name, and only a whole link header counts as a link.
      const byStream = Object.fromEntries(file.links.map((l) => [l.stream, l]));
      assert.equal(byStream["1"].path, "\\\\fileserver\\finance\\Q4.xlsx");
      assert.equal(byStream["a"].path, "C:\\case\\report.txt");
      assert.equal(byStream["b"].is_link, false, "four bytes of the header are not a link");
    });
  });
}

test("jumplist refuses a DestList version it does not read, with a problem and no entries, and the status says partial", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "olefile.py": OLEFILE_STUB });
    const odd = destList(3, [{ number: 1, host: "H", filetime: 133_443_104_000_000_000n, pin: -1, path: "C:\\a.txt" }]);
    odd.writeUInt32LE(2, 0);
    await writeFile(join(cwd, "work", "a.automaticDestinations-ms"), JSON.stringify({ DestList: odd.toString("hex") }), "utf8");
    const out = body<Jump>(await tool("jumplist", cwd, { path: "work/a.automaticDestinations-ms" }, env));
    assert.equal(out.status, "partial");
    assert.equal(out.files[0].entry_count, 0);
    assert.ok((out.files[0].problems ?? []).some((p) => /version 2 is not one this parser reads/.test(p)));
  });
});

test("jumplist reports a file it could not read as a failure with a count, and exits non-zero when none could be read", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.automaticDestinations-ms"), "not a compound file");
    // No olefile on this PYTHONPATH: every automaticDestinations file fails, loudly.
    const env = await stubModule(cwd, { "olefile.py": "def isOleFile(p):\n    return False\n" });
    const out = await tool("jumplist", cwd, { path: "work/x.automaticDestinations-ms" }, env);
    assert.notEqual(out.code, 0);
    const parsed = JSON.parse(out.stdout) as Jump;
    assert.equal(parsed.status, "failed");
    assert.equal(parsed.files_failed, 1);
  });
});

test("jumplist calls a customDestinations-ms split a carve, and marks each link carved", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "x.customDestinations-ms"), Buffer.concat([Buffer.from([2, 0, 0, 0]), LNK_MAGIC, Buffer.from("A".repeat(40)), LNK_MAGIC, Buffer.from("B".repeat(30))]));
    const out = body<Jump>(await tool("jumplist", cwd, { path: "work/x.customDestinations-ms" }));
    assert.match(out.files[0].method ?? "", /carved/);
    assert.ok(out.files[0].links.every((l) => l.carved === true));
    assert.equal(out.files[0].links.length, 2);
  });
});

// --- registry hives -------------------------------------------------------------

test("the hive fixture is a hive regipy opens, with the keys and typed values written into it", async () => {
  await withCwd(async (cwd) => {
    const bytes = hive({
      name: "ROOT",
      children: [
        { name: "A", values: [{ name: "s", type: "sz", value: "hello" }, { name: "d", type: "dword", value: 1700000000 }] },
        { name: "B", children: [{ name: "C", values: [{ name: "m", type: "multi_sz", value: ["x", "yz"] }, { name: "bin", type: "binary", value: Buffer.from([1, 2, 3, 4, 5, 6]) }] }] },
      ],
    });
    await writeFile(join(cwd, "work", "T.hve"), bytes);
    const out = py(
      [
        "import json, sys",
        "from regipy.registry import RegistryHive",
        "h = RegistryHive(sys.argv[1])",
        "a = h.get_key('\\\\A')",
        "c = h.get_key('\\\\B\\\\C')",
        "print(json.dumps({'a': [(v.name, v.value_type, str(v.value)) for v in a.iter_values()], 'c': [(v.name, v.value_type, str(v.value)) for v in c.iter_values()],",
        " 'subs': [k.name for k in h.root.iter_subkeys()] if hasattr(h, 'root') else []}))",
      ].join("\n"),
      join(cwd, "work", "T.hve"),
    );
    const got = JSON.parse(out) as { a: string[][]; c: string[][]; subs: string[] };
    assert.deepEqual(got.a.map((r) => r.slice(0, 2)), [["s", "REG_SZ"], ["d", "REG_DWORD"]]);
    assert.equal(got.a[0][2], "hello");
    assert.equal(got.a[1][2], "1700000000");
    assert.equal(got.c[0][1], "REG_MULTI_SZ");
    assert.equal(got.c[1][1], "REG_BINARY");
  });
});

// --- amcache_apps ---------------------------------------------------------------

type AmcacheOut = {
  status: string;
  layouts_found: string[];
  rows_by_layout: Record<string, number>;
  entries: Array<Record<string, unknown>>;
  entry_count: number;
  hive_dirty: boolean;
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
  rows_failed: number;
};

const SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

test("amcache_apps names the numbered values as regipy's Amcache plugin does, and reads the linker time as a Unix-epoch value, not a FILETIME", async () => {
  // `c` was labelled file_version (it is the file description; the version is `5`), and the linker
  // timestamp, a 32-bit Unix-epoch value from the PE header, was converted as a FILETIME: 1700000000
  // came out as 1601-01-01T00:02:50Z.
  await withCwd(async (cwd) => {
    const file = (name: string, values: Array<{ name: string; type: "sz" | "dword" | "qword"; value: string | number | bigint }>): { name: string; values: typeof values } => ({ name, values });
    const bytes = hive({
      name: "{11111111-2222-3333-4444-555555555555}",
      children: [
        {
          name: "Root",
          children: [
            {
              name: "File",
              children: [
                {
                  name: "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
                  children: [
                    file("1a2b", [
                      { name: "0", type: "sz", value: "Fixture Suite" },
                      { name: "1", type: "sz", value: "Fixture Corp" },
                      { name: "5", type: "sz", value: "1.2.3.4" },
                      { name: "c", type: "sz", value: "The fixture application" },
                      { name: "f", type: "dword", value: 1700000000 },
                      { name: "11", type: "qword", value: 133_443_104_001_234_567n },
                      { name: "15", type: "sz", value: "C:\\Fixtures\\app.exe" },
                      { name: "100", type: "sz", value: "0000" + "ab".repeat(16) },
                      { name: "101", type: "sz", value: "0000" + SHA1 },
                    ]),
                  ],
                },
              ],
            },
          ],
        },
      ],
    });
    await writeFile(join(cwd, "work", "Amcache.hve"), bytes);
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }));
    assert.deepEqual(out.layouts_found, ["File"]);
    const row = out.entries[0];
    assert.equal(row.layout, "File");
    assert.equal(row.file_version, "1.2.3.4", "value 5 is the file version");
    assert.equal(row.file_description, "The fixture application", "value c is the file description");
    assert.equal(row.file_version === row.file_description, false);
    assert.equal(row.linker_compile_time, 1700000000);
    assert.equal(row.linker_compile_time_utc, "2023-11-14T22:13:20Z", "a Unix-epoch value: 1700000000 is 2023, not 1601");
    assert.equal(row.last_modified_timestamp_filetime, "133443104001234567");
    assert.equal(row.last_modified_timestamp_utc, "2023-11-13T00:53:20.1234567Z");
    assert.equal(row.full_path, "C:\\Fixtures\\app.exe");
    assert.equal(row.sha1_raw, "0000" + SHA1, "the value as stored is kept");
    assert.equal(row.sha1, SHA1, "stripped of its four leading zeros only where it has that shape");
    assert.equal(row.link_date, undefined);
  });
});

test("amcache_apps reads both layouts when a hive has both, each row naming its own", async () => {
  // The older layout was read only when the Windows 10 tree was absent, so a hive that carried both
  // listed one tree and said nothing of the other.
  await withCwd(async (cwd) => {
    const bytes = hive({
      name: "{11111111-2222-3333-4444-555555555555}",
      children: [
        {
          name: "Root",
          children: [
            { name: "File", children: [{ name: "{vol}", children: [{ name: "7", values: [{ name: "15", type: "sz", value: "C:\\old\\legacy.exe" }] }] }] },
            {
              name: "InventoryApplicationFile",
              children: [
                {
                  name: "modern.exe|0123456789abcdef",
                  values: [
                    { name: "LowerCaseLongPath", type: "sz", value: "c:\\new\\modern.exe" },
                    { name: "FileId", type: "sz", value: "0000" + SHA1.toUpperCase() },
                    { name: "Publisher", type: "sz", value: "Modern Corp" },
                    { name: "LinkDate", type: "sz", value: "10/24/2023 10:14:55" },
                    { name: "OriginalFileName", type: "sz", value: "modern.exe" },
                  ],
                },
              ],
            },
          ],
        },
      ],
    });
    await writeFile(join(cwd, "work", "Amcache.hve"), bytes);
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }));
    assert.deepEqual([...out.layouts_found].sort(), ["File", "InventoryApplicationFile"]);
    assert.deepEqual(out.rows_by_layout, { File: 1, InventoryApplicationFile: 1 });
    assert.equal(out.entry_count, 2);
    const byLayout = Object.fromEntries(out.entries.map((r) => [r.layout as string, r]));
    assert.equal(byLayout.File.full_path, "C:\\old\\legacy.exe");
    assert.equal(byLayout.InventoryApplicationFile.LowerCaseLongPath, "c:\\new\\modern.exe");
    assert.equal(byLayout.InventoryApplicationFile.OriginalFileName, "modern.exe", "every named value is kept, not a chosen few");
    assert.equal(byLayout.InventoryApplicationFile.file_id_sha1, SHA1, "lower-cased, four zeros stripped");
    assert.equal(byLayout.InventoryApplicationFile.FileId, "0000" + SHA1.toUpperCase(), "and the value as stored is kept");
    assert.equal(out.status, "complete");
    assert.equal(out.hive_dirty, false);
  });
});

test("amcache_apps returns a path past 256 characters whole: regipy's default cut is not taken", async () => {
  await withCwd(async (cwd) => {
    const long = "c:\\users\\someone\\" + "nested\\".repeat(60) + "tool.exe";
    await writeFile(join(cwd, "work", "Amcache.hve"), hive({ name: "{r}", children: [{ name: "Root", children: [
      { name: "InventoryApplicationFile", children: [{ name: "tool.exe|1", values: [{ name: "LowerCaseLongPath", type: "sz", value: long }] }] },
      { name: "File", children: [{ name: "{vol}", children: [{ name: "9", values: [{ name: "15", type: "sz", value: long }] }] }] },
    ] }] }));
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }));
    const by = Object.fromEntries(out.entries.map((r) => [r.layout as string, r]));
    assert.ok(long.length > 256);
    assert.equal(by.InventoryApplicationFile.LowerCaseLongPath, long);
    assert.equal(by.File.full_path, long);
  });
});

test("amcache_apps says a hive is dirty, names the transaction logs beside it, and does not claim to have replayed them", async () => {
  await withCwd(async (cwd) => {
    const bytes = hive(
      { name: "{r}", children: [{ name: "Root", children: [{ name: "InventoryApplicationFile", children: [{ name: "a.exe|1", values: [{ name: "Name", type: "sz", value: "a.exe" }] }] }] }] },
      { primarySeq: 9, secondarySeq: 8 },
    );
    await writeFile(join(cwd, "work", "Amcache.hve"), bytes);
    await writeFile(join(cwd, "work", "Amcache.hve.LOG1"), Buffer.alloc(512));
    const out = body<AmcacheOut>(await tool("amcache_apps", cwd, { hive: "work/Amcache.hve" }));
    assert.equal(out.hive_dirty, true);
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/Amcache.hve.LOG1"]);
    assert.equal(out.transaction_logs_replayed, false);
  });
});

test("amcache_apps fails with the layouts it looked for when the hive holds neither", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "Other.hve"), hive({ name: "r", children: [{ name: "Root", children: [{ name: "Elsewhere" }] }] }));
    const err = failed(await tool("amcache_apps", cwd, { hive: "work/Other.hve" }));
    assert.match(err.error, /neither Amcache layout/);
    assert.deepEqual(err.looked_for, ["\\Root\\InventoryApplicationFile", "\\Root\\File"]);
  });
});

// --- browser_history ------------------------------------------------------------

type BrowserOut = {
  columns: string[];
  rows: Array<Record<string, unknown>>;
  row_count: number;
  results?: Array<{ rows: Array<Record<string, unknown>> }>;
  query_note?: string;
  sidecars_copied: string[];
  wal_present: boolean;
  wal_bytes: number;
  wal_checkpoint: { log_frames: number; checkpointed_frames: number };
  wal_frames_replayed: number;
  wal_replayed?: unknown;
  sensitive_columns_withheld: Array<{ table: string; column: string; cells_withheld: number; total_length: number }>;
  all_results?: string;
};

// Chromium's History: `urls` is one row per URL, `visits` one row per visit. 13344307200123456 is
// 1699833600.123456 s after the Unix epoch, the Chromium time base being microseconds since 1601.
const CHROME_HISTORY_FIXTURE = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);",
  "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);",
  "INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 2, 1, 13344307300123456);",
  "INSERT INTO visits VALUES (1, 1, 13344307200123456, 0, 805306369, 5000000);",
  "INSERT INTO visits VALUES (2, 1, 13344307300123456, 1, 0, 0);",
  "''')",
  "c.commit()",
].join("\n");

test("browser_history lists every visit with its raw time, transition and referring visit, and keeps the URL summary a summary", async () => {
  // The named queries read `urls` (one row per URL), so two visits to one URL came back as one row
  // under the name chrome_history; the visit table was never read.
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const visits = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_visits" }));
    assert.equal(visits.row_count, 2);
    assert.deepEqual(visits.rows.map((r) => r.visit_id), [1, 2]);
    assert.deepEqual(visits.rows.map((r) => r.transition_core), ["typed", "link"]);
    assert.equal(visits.rows[0].transition_raw, 805306369, "the raw value, qualifiers included, beside the core type");
    assert.equal(visits.rows[0].visit_time_raw, 13344307200123456);
    assert.equal(visits.rows[0].visit_utc, "2023-11-13T00:00:00.123456Z", "microseconds kept");
    assert.equal(visits.rows[1].from_visit, 1);
    assert.equal(visits.rows[0].url, "http://example.test/a");

    const summary = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.equal(summary.row_count, 1);
    assert.equal(summary.rows[0].visit_count, 2);

    // The old name still answers, as the summary it always was, and says so.
    const old = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_history" }));
    assert.equal(old.row_count, 1);
    assert.match(old.query_note ?? "", /one row per URL/);
    assert.match(old.query_note ?? "", /chrome_visits/);
  });
});

test("browser_history reads Firefox's moz_historyvisits joined to moz_places, with the visit type named and the raw value kept", async () => {
  await withCwd(async (cwd) => {
    py(
      [
        "import sqlite3, sys",
        "c = sqlite3.connect(sys.argv[1])",
        "c.executescript('''",
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);",
        "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);",
        "INSERT INTO moz_places VALUES (1, 'http://example.test/f', 'F', 2, 1699833700123456);",
        "INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1699833600123456, 2);",
        "INSERT INTO moz_historyvisits VALUES (2, 1, 1, 1699833700123456, 5);",
        "''')",
        "c.commit()",
      ].join("\n"),
      join(cwd, "work", "places.sqlite"),
    );
    const visits = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/places.sqlite", query: "firefox_visits" }));
    assert.equal(visits.row_count, 2);
    assert.deepEqual(visits.rows.map((r) => r.visit_type), ["typed", "redirect_permanent"]);
    assert.deepEqual(visits.rows.map((r) => r.visit_type_raw), [2, 5]);
    assert.equal(visits.rows[0].visit_utc, "2023-11-13T00:00:00.123456Z");
    const summary = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/places.sqlite", query: "firefox_url_summary" }));
    assert.equal(summary.row_count, 1);
  });
});

const WAL_FIXTURE = [
  "import os, sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.execute('PRAGMA journal_mode=WAL')",
  "c.execute('PRAGMA wal_autocheckpoint=0')",
  "c.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, typed_count INT, last_visit_time INT)')",
  "c.execute(\"INSERT INTO urls VALUES (1, 'http://example.test/a', 'A', 1, 0, 13350000000000000)\")",
  "c.commit()",
  "c.execute(\"INSERT INTO urls VALUES (2, 'http://203.0.113.24/upload.aspx', 'shell', 9, 1, 13350000060000000)\")",
  "c.commit()",
  "os._exit(0)",
].join("\n");

test("browser_history says how many frames of the write-ahead log SQLite replayed, not just that a -wal file was copied", async () => {
  // `wal_replayed` was true whenever a -wal sidecar existed, and said nothing of whether SQLite found a
  // valid log in it.
  await withCwd(async (cwd) => {
    py(WAL_FIXTURE, join(cwd, "work", "History"));
    const wal = await readFile(join(cwd, "work", "History-wal"));
    assert.ok(wal.length > 0, "the fixture must leave an unplayed WAL beside the database");
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "chrome_url_summary" }));
    assert.equal(out.wal_present, true);
    assert.equal(out.wal_bytes, wal.length);
    assert.ok(out.wal_frames_replayed >= 2, JSON.stringify(out.wal_checkpoint));
    assert.equal(out.wal_checkpoint.checkpointed_frames, out.wal_frames_replayed);
    assert.deepEqual(out.rows.map((r) => r.url), ["http://203.0.113.24/upload.aspx", "http://example.test/a"], "the row only the log holds is seen");
    assert.equal(out.wal_replayed, undefined, "the old flag is gone: it meant only that a sidecar was copied");
    // The original and its log are untouched.
    assert.deepEqual(await readFile(join(cwd, "work", "History-wal")), wal);
  });
});

test("browser_history reports a damaged -wal as present with no frames replayed", async () => {
  await withCwd(async (cwd) => {
    py(WAL_FIXTURE, join(cwd, "work", "History"));
    await writeFile(join(cwd, "work", "History-wal"), Buffer.alloc(8192, 0x41));
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.equal(out.wal_present, true);
    assert.equal(out.wal_frames_replayed, 0);
  });
});

test("browser_history opens its copy under an authorizer: a statement that begins like a read but writes is refused, and so is a pragma that sets", async () => {
  // The only guard was a textual prefix check, which `WITH ... INSERT` and `PRAGMA x = n` pass.
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const before = await readFile(join(cwd, "work", "History"));
    const insert = failed(await tool("browser_history", cwd, { path: "work/History", sql: "WITH x AS (SELECT 'http://evil.test/') INSERT INTO urls (url) SELECT * FROM x" }));
    assert.match(insert.error, /sqlite refused the query/);
    assert.match(String(insert.reason), /not authorized/);
    const pragma = failed(await tool("browser_history", cwd, { path: "work/History", sql: "PRAGMA user_version = 77" }));
    assert.match(String(pragma.reason), /not authorized/);
    const attach = failed(await tool("browser_history", cwd, { path: "work/History", sql: "WITH x AS (SELECT 1) SELECT * FROM x; ATTACH DATABASE 'work/other.db' AS o" }));
    assert.match(attach.error, /SELECT, WITH or PRAGMA/, "the prefix check still holds first");
    // Reports still work.
    const info = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", sql: "PRAGMA table_info(urls)" }));
    assert.ok(info.row_count >= 5);
    assert.deepEqual(await readFile(join(cwd, "work", "History")), before, "the evidence is never opened for writing");
    assert.equal(await exists(join(cwd, "work", "other.db")), false);
  });
});

const SENSITIVE_PASSWORD = "Summer2024!hunter2";
const SENSITIVE_COOKIE = "SESSIONTOKEN-9f8e7d6c5b4a-planted";
const SENSITIVE_BLOB = Buffer.from("v10" + "k3yM4t3r14l-planted-ciphertext-bytes", "latin1");

const LOGIN_FIXTURE = [
  "import sqlite3, sys",
  "c = sqlite3.connect(sys.argv[1])",
  "c.executescript('''",
  "CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_element TEXT, username_value TEXT, password_element TEXT, password_value BLOB, signon_realm TEXT, date_created INTEGER, times_used INTEGER);",
  "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER);",
  "CREATE TABLE token_service (service TEXT, encrypted_token BLOB);",
  "''')",
  "c.execute('INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?)', ('https://portal.example.test/', 'https://portal.example.test/login', 'user', 'alice', 'pass', sys.argv[2].encode('latin1'), 'https://portal.example.test/', 13344307200000000, 4))",
  "c.execute('INSERT INTO cookies VALUES (?,?,?,?,?,?,?)', (13344307200000000, '.example.test', 'sid', sys.argv[3], bytes.fromhex(sys.argv[4]), '/', 13344397200000000))",
  "c.execute('INSERT INTO token_service VALUES (?,?)', ('Gaia', bytes.fromhex(sys.argv[4])))",
  "c.commit()",
].join("\n");

async function everyFileUnder(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await everyFileUnder(full)));
    else out.push(full);
  }
  return out;
}

test("browser_history never echoes a password, a cookie value or an encrypted blob from Login Data or Cookies, in any query, and says which columns it withheld", async () => {
  // A SELECT * over `logins` and `cookies` printed password_value and the cookie values whole,
  // and `SELECT hex(...)` or `substr(...)` gave them back in any other shape.
  await withCwd(async (cwd) => {
    py(LOGIN_FIXTURE, join(cwd, "work", "Login Data"), SENSITIVE_PASSWORD, SENSITIVE_COOKIE, SENSITIVE_BLOB.toString("hex"));
    const queries = [
      "SELECT * FROM logins",
      "SELECT hex(password_value) AS h, length(password_value) AS n FROM logins",
      "SELECT substr(value, 1, 8) AS head, quote(encrypted_value) AS q FROM cookies",
      "SELECT * FROM cookies; SELECT * FROM token_service",
    ];
    for (const sql of queries) {
      const run = await tool("browser_history", cwd, { path: "work/Login Data", sql, limit: 1 });
      const out = body<BrowserOut>(run);
      const wholeAnswer = run.stdout + run.stderr;
      const encodings = [
        SENSITIVE_PASSWORD, SENSITIVE_COOKIE, SENSITIVE_BLOB.toString("latin1"),
        Buffer.from(SENSITIVE_PASSWORD).toString("hex"), Buffer.from(SENSITIVE_COOKIE).toString("hex"), SENSITIVE_BLOB.toString("hex"),
        Buffer.from(SENSITIVE_PASSWORD).toString("base64"), Buffer.from(SENSITIVE_COOKIE).toString("base64"), SENSITIVE_BLOB.toString("base64"),
        SENSITIVE_PASSWORD.slice(0, 6), SENSITIVE_COOKIE.slice(0, 12), "hunter2", "k3yM4t3r14l",
      ];
      for (const secret of encodings) assert.equal(wholeAnswer.toLowerCase().includes(secret.toLowerCase()), false, `${sql}: ${secret}`);
      assert.ok(out.sensitive_columns_withheld.length >= 3, sql);
      // And no file the answer names, nor anything the tool left under work/, holds one.
      for (const file of await everyFileUnder(join(cwd, "work"))) {
        if (file.endsWith("Login Data")) continue;
        const text = (await readFile(file)).toString("latin1").toLowerCase();
        for (const secret of encodings) assert.equal(text.includes(secret.toLowerCase()), false, `${file}: ${secret}`);
      }
    }
    const logins = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/Login Data", sql: "SELECT origin_url, username_value, password_value, times_used FROM logins" }));
    assert.equal(logins.rows[0].origin_url, "https://portal.example.test/");
    assert.equal(logins.rows[0].username_value, "alice", "a username is returned; it is not a secret");
    assert.equal(logins.rows[0].password_value, `[withheld: ${SENSITIVE_PASSWORD.length} bytes]`, "only the length of a withheld cell is left");
    assert.equal(logins.rows[0].times_used, 4);
    const withheld = Object.fromEntries(logins.sensitive_columns_withheld.map((w) => [`${w.table}.${w.column}`, w]));
    assert.equal(withheld["logins.password_value"].cells_withheld, 1);
    assert.equal(withheld["logins.password_value"].total_length, SENSITIVE_PASSWORD.length);
    assert.equal(withheld["cookies.value"].cells_withheld, 1);
    assert.equal(withheld["cookies.encrypted_value"].cells_withheld, 1);
    assert.equal(withheld["token_service.encrypted_token"].cells_withheld, 1, "a column whose name says token and encrypted is withheld in any table");
    // The disposable copy, which held the originals, is gone.
    const leftovers = [...(await readdir(join(cwd, "work"))), ...(await readdir(join(cwd, "work", "s1")).catch(() => [] as string[]))].filter((n) => n.startsWith(".browser-scratch"));
    assert.deepEqual(leftovers, []);
  });
});

test("browser_history keeps two result columns of one name apart, and says which it renamed", async () => {
  await withCwd(async (cwd) => {
    py(CHROME_HISTORY_FIXTURE, join(cwd, "work", "History"));
    const out = body<BrowserOut>(await tool("browser_history", cwd, { path: "work/History", sql: "SELECT u.id, v.id FROM urls u JOIN visits v ON v.url = u.id ORDER BY v.id" }));
    assert.deepEqual(out.columns, ["id", "id_2"]);
    assert.deepEqual(out.rows, [{ id: 1, id_2: 1 }, { id: 1, id_2: 2 }]);
  });
});

test("browser_history names a file that is not a database, with its first bytes and size, instead of an empty answer", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "History"), Buffer.from("this is not sqlite, it is only text padded out to a page".padEnd(4096, " ")));
    const err = failed(await tool("browser_history", cwd, { path: "work/History", query: "tables" }));
    assert.match(err.error, /not a SQLite database/);
    assert.equal(err.size, 4096);
    assert.equal(typeof err.first_bytes_hex, "string");
  });
});

// --- yara_scan ------------------------------------------------------------------

type YaraOut = {
  status: string;
  complete: boolean;
  timed_out: boolean;
  yara_exit_status: number;
  yara_argv: string[];
  rules_sha256: string;
  matches: Array<{ rule: string; file: string; string_matches: number }>;
  match_count: number;
  string_matches: Array<{ finding_id: string; rule: string; file: string; identifier: string; offset: number; offset_hex: string; length: number | null }>;
  string_match_count: number;
  string_matches_page: { all_results?: string };
  stderr_file: string | null;
  stderr_line_count: number;
  warnings: string[];
  secret_values: { requested: boolean; written: number; values_file: string | null; contains_secret_values: boolean };
};

const PLANTED = "password=Summer2024!";

/** A yara stand-in: it prints what yara 4.x prints for `-s -L` (`rule file`, then `0x<offset>:<length>:$id: <data>`). */
const YARA_STUB = (extra = ""): string => `
case "$1" in
  --version) echo 4.5.8; exit 0;;
  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;
esac
for last; do :; done
${extra}
echo "pw $last"
echo '0x6:20:$a: ${PLANTED}'
echo '0x21:4:$m: 4D 5A 90 00'
echo "other $last"
echo '0x40:3:$k: abc'
`;

test("yara_scan reports the rule, file, string identifier, offset and length of a match and never the matched bytes", async () => {
  // `-s` prints the matched bytes, and they went into the answer: a rule that found `password=` put
  // the password in stdout and in the job log.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB());
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), `xxxxxx${PLANTED}`);
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin);
    const out = body<YaraOut>(run);
    assert.equal(out.status, "complete");
    assert.equal(out.match_count, 2);
    assert.deepEqual(out.matches.map((m) => [m.rule, m.string_matches]), [["pw", 2], ["other", 1]]);
    assert.deepEqual(out.string_matches[0], { finding_id: "S000001", rule: "pw", file: "work/sample.bin", identifier: "$a", offset: 6, offset_hex: "0x6", length: 20 });
    assert.equal(out.string_match_count, 3);
    for (const piece of [PLANTED, "Summer2024", "password=", Buffer.from(PLANTED).toString("hex"), Buffer.from(PLANTED).toString("base64"), "4D 5A 90 00"]) {
      assert.equal((run.stdout + run.stderr).includes(piece), false, piece);
    }
    assert.equal(out.secret_values.requested, false);
    assert.equal(out.secret_values.written, 0);
    // Nothing the tool wrote holds them either: yara's text is read as a stream and dropped.
    const files = await everyFileUnder(join(cwd, "work"));
    for (const file of files) assert.equal((await readFile(file)).toString("latin1").includes("Summer2024") && !file.endsWith("sample.bin"), false, file);
    assert.ok(out.yara_argv.includes("-s") && out.yara_argv.includes("-L"));
    assert.match(out.rules_sha256, /^[0-9a-f]{64}$/);
  });
});

test("yara_scan writes the matched bytes only on write_matches, only in a job, only to a 0600 file under $OUT, with the finding ids of the answer", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB());
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    // Outside a job the request is refused and nothing is written.
    const refused = failed(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, {}, bin));
    assert.match(refused.error, /refused outside a job/);
    assert.deepEqual((await everyFileUnder(join(cwd, "work"))).filter((f) => f.includes("yara-matched")), []);
    // In a job.
    const outDir = join(cwd, "out");
    await mkdir(outDir, { recursive: true });
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, { JOB_ID: "j000007", OUT: outDir }, bin);
    const out = body<YaraOut>(run);
    assert.equal(out.secret_values.requested, true);
    assert.equal(out.secret_values.written, 3);
    assert.equal(out.secret_values.values_file, "store/jobs/j000007/out/yara-matched-strings.jsonl");
    assert.equal(out.secret_values.contains_secret_values, true);
    assert.equal(run.stdout.includes("Summer2024"), false, "even then the answer itself has no value");
    const file = join(outDir, "yara-matched-strings.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { finding_id: string; value: string; offset: number; length: number; identifier: string });
    assert.deepEqual(rows.map((r) => r.finding_id), out.string_matches.map((m) => m.finding_id));
    assert.equal(rows[0].value, PLANTED);
    assert.equal(rows[0].offset, 6);
    assert.equal(rows[0].length, 20);
    // A values file already there is refused by name before anything is scanned.
    const again = failed(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", write_matches: true }, { JOB_ID: "j000008", OUT: outDir }, bin));
    assert.match(again.error, /already exists/);
  });
});

test("yara_scan keeps the whole of a run it had to stop: status partial, complete false, the matches read before the time limit and the stderr file", async () => {
  // A timeout threw away everything yara had printed, and the answer was "did not finish".
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", YARA_STUB(`echo "warning: rule slow" >&2\n`).replace(`echo "other $last"`, `echo "other $last"\nsleep 30`));
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    const started = Date.now();
    const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", timeout_seconds: 2 }, {}, bin));
    assert.ok(Date.now() - started < 20_000, "the stub's sleep must have been killed, not waited for");
    assert.equal(out.status, "partial");
    assert.equal(out.complete, false);
    assert.equal(out.timed_out, true);
    assert.equal(out.match_count, 2, "the matches printed before the stop are kept");
    assert.deepEqual(out.warnings, ["warning: rule slow"], "warnings are kept, not suppressed with -w");
    assert.ok(out.stderr_file);
    assert.equal((await readFile(join(cwd, out.stderr_file as string), "utf8")).trim(), "warning: rule slow");
  });
});

test("yara_scan reports a yara that fails with a rule error as failed with its stderr, and a non-zero exit after matches as partial", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "rules.yar"), "rule pw { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    await stub(bin, "yara", `case "$1" in --version) echo 4.5.8; exit 0;; --help) echo '  -L, --print-string-length'; exit 0;; esac\necho 'rules.yar(1): error: syntax error, unexpected identifier' >&2\nexit 1`);
    const bad = JSON.parse((await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin)).stdout) as YaraOut;
    assert.equal(bad.status, "failed");
    assert.equal(bad.yara_exit_status, 1);
    assert.match(bad.warnings[0], /syntax error/);
    await stub(bin, "yara", YARA_STUB(`echo 'error scanning b: could not open file' >&2`).replace("\necho '0x40:3:$k: abc'", "\necho '0x40:3:$k: abc'\nexit 1"));
    const part = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" }, {}, bin));
    assert.equal(part.status, "partial");
    assert.equal(part.complete, false);
    assert.equal(part.match_count, 2);
  });
});

test("yara_scan pages its string matches past limit and keeps every one in the file the page names", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", `case "$1" in --version) echo 4.5.8; exit 0;; --help) echo '  -L, --print-string-length'; exit 0;; esac\nfor last; do :; done\necho "bulk $last"\ni=0; while [ $i -lt 450 ]; do printf '0x%x:4:$s: abcd\\n' $((i*16)); i=$((i+1)); done`);
    await writeFile(join(cwd, "work", "rules.yar"), "rule bulk { condition: true }");
    await writeFile(join(cwd, "work", "sample.bin"), "x");
    const out = body<YaraOut>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin", limit: 100 }, {}, bin));
    assert.equal(out.string_match_count, 450);
    assert.equal(out.string_matches.length, 100);
    const all = (await readFile(join(cwd, out.string_matches_page.all_results as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { offset: number });
    assert.equal(all.length, 450);
    assert.equal(all[449].offset, 449 * 16);
  });
});

test("yara_scan against the installed yara: the matched bytes stay out of the answer", async (t) => {
  if (spawnSync("yara", ["--version"]).status !== 0) return t.skip("yara is not installed on this host");
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "rules.yar"), 'rule pw { strings: $a = /password=[A-Za-z0-9!]+/ $w = "world" wide ascii nocase condition: any of them }');
    await writeFile(join(cwd, "work", "sample.bin"), `hello ${PLANTED} world`);
    const run = await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/sample.bin" });
    const out = body<YaraOut>(run);
    assert.equal(out.status, "complete");
    assert.equal(out.string_match_count, 2);
    assert.deepEqual(out.string_matches.map((m) => [m.identifier, m.offset, m.length]), [["$a", 6, 20], ["$w", 27, 5]]);
    assert.equal(run.stdout.includes("Summer2024"), false);
  });
});

// --- esedb_query ----------------------------------------------------------------

type EseOut = {
  status: string;
  complete: boolean;
  exporter_exit_status: number;
  exporter_version: string | null;
  timed_out: boolean;
  export_reused: boolean;
  stdout_file: string;
  stderr_file: string;
  tables?: string[];
  tables_in_partial_export?: string[];
  warning?: string;
  table?: string;
  columns?: string[];
  duplicate_columns_renamed?: string[];
  rows?: Array<Record<string, string | number>>;
  row_count?: number;
  candidates?: string[];
  db_sha256: string;
};

/** esedbexport as libesedb's utility behaves: `esedbexport -t <root> <db>` writes <root>.export/<table>.<index>, tab separated, and `-V` prints a version. */
const ESEDBEXPORT_STUB = (body: string): string => `
if [ "$1" = "-V" ]; then echo "esedbexport 20231020"; exit 0; fi
root="$2"
echo run >> "$COUNT_FILE"
mkdir -p "$root.export"
${body}
`;

test("esedb_query does not turn a failed export into a clean table listing: status partial, the exporter's output kept whole in files", async () => {
  // An export directory that existed was taken for success whatever the exporter's exit status, so a
  // run that died after one table listed that table as the database's contents.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'ContainerId\\tName\\n1\\tContent\\n' > "$root.export/Containers.4"\necho "libesedb: unable to open table 7: page checksum mismatch" >&2\necho "exporting table 1 of 12" \nexit 1`));
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.complete, false);
    assert.equal(out.exporter_exit_status, 1);
    assert.equal(out.exporter_version, "esedbexport 20231020");
    assert.equal(out.tables, undefined, "a partial export is never listed as the database's tables");
    assert.deepEqual(out.tables_in_partial_export, ["Containers"]);
    assert.match(out.warning ?? "", /PARTIAL export/);
    assert.match(await readFile(join(cwd, out.stderr_file), "utf8"), /page checksum mismatch/);
    assert.match(await readFile(join(cwd, out.stdout_file), "utf8"), /exporting table 1 of 12/);
    // Reading from it is allowed, and says so on every answer.
    const one = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(one.status, "partial");
    assert.equal(one.rows?.[0].Name, "Content");
  });
});

test("esedb_query refuses a table name that matches two export files and lists them, and reads one by its file name", async () => {
  // `hits[0]` took the first of the matches without a word.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\n1\\tfirst\\n' > "$root.export/Containers.4"\nprintf 'Id\\tName\\n2\\tsecond\\n' > "$root.export/Containers.12"`));
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const err = failed(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers" }, env, bin));
    assert.match(err.error, /more than one export file/);
    assert.deepEqual(err.candidates, ["Containers.12", "Containers.4"]);
    const second = body<EseOut>(await tool("esedb_query", cwd, { path: "work/WebCacheV01.dat", table: "Containers.12" }, env, bin));
    assert.equal(second.rows?.[0].Name, "second");
  });
});

test("esedb_query exports a database once, keeps the export under its digest, and reuses it for the next call", async () => {
  // The whole database was exported into a temp directory on every call, even to list the tables, and deleted.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\n1\\ta\\n' > "$root.export/T.0"`));
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in");
    const env = { COUNT_FILE: join(cwd, "count") };
    const first = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
    const second = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat", table: "T" }, env, bin));
    assert.equal(first.export_reused, false);
    assert.equal(second.export_reused, true);
    assert.equal((await readFile(join(cwd, "count"), "utf8")).trim().split("\n").length, 1, "the exporter ran once");
    assert.match(first.db_sha256, /^[0-9a-f]{64}$/);
    const manifest = JSON.parse(await readFile(join(cwd, "work", "s1", "esedb-export", first.db_sha256.slice(0, 16), "export-manifest.json"), "utf8")) as { db_sha256: string; exporter_exit_status: number; files: Record<string, unknown> };
    assert.equal(manifest.db_sha256, first.db_sha256);
    assert.equal(manifest.exporter_exit_status, 0);
    assert.deepEqual(Object.keys(manifest.files), ["T.0"]);
    // Changed bytes are another export.
    await writeFile(join(cwd, "work", "SRUDB.dat"), "ESE stand-in, changed");
    const third = body<EseOut>(await tool("esedb_query", cwd, { path: "work/SRUDB.dat" }, env, bin));
    assert.equal(third.export_reused, false);
  });
});

test("esedb_query numbers every row, keeps columns that share a name apart, and keeps a cell of any size whole", async () => {
  await withCwd(async (cwd, bin) => {
    const big = "x".repeat(2_000_000);
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\tName\\tName\\n1\\ta\\tb\\n2\\tc\\t${big}\\n' > "$root.export/Dup.2"`));
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", table: "Dup" }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.deepEqual(out.columns, ["Id", "Name", "Name"]);
    assert.deepEqual(out.duplicate_columns_renamed, ["Name_2"]);
    assert.deepEqual(out.rows?.map((r) => r._row), [1, 2]);
    assert.equal(out.rows?.[0].Name_2, "b");
    assert.equal((out.rows?.[1].Name_2 as string).length, 2_000_000);
  });
});

test("esedb_query keeps what a time-limited export wrote and says it was stopped", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "esedbexport", ESEDBEXPORT_STUB(`printf 'Id\\n1\\n' > "$root.export/Part.0"\nsleep 30`));
    await writeFile(join(cwd, "work", "x.edb"), "ESE stand-in");
    const started = Date.now();
    const out = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", export_timeout_seconds: 1 }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.ok(Date.now() - started < 20_000);
    assert.equal(out.status, "partial");
    assert.equal(out.timed_out, true);
    assert.deepEqual(out.tables_in_partial_export, ["Part"]);
    // A partial export is not reused as a complete one: the next call exports again.
    const again = body<EseOut>(await tool("esedb_query", cwd, { path: "work/x.edb", export_timeout_seconds: 1 }, { COUNT_FILE: join(cwd, "count") }, bin));
    assert.equal(again.export_reused, false);
  });
});

// --- sigma_hunt -----------------------------------------------------------------

type Detection = { rule: string; level: string | null; level_rank: number | null; record_id: number | null; time: string | null };
type HuntOut = {
  status: string;
  complete: boolean;
  exit_code: number;
  timed_out: boolean;
  run_dir: string;
  engine: string;
  engine_detections_read: number;
  detections: Detection[];
  detection_count: number;
  below_min_level: number;
  unknown_levels: Record<string, number>;
  malformed_lines: number;
  malformed_file: { path: string; bytes: number } | null;
  ruleset: { source: string; kind?: string; files?: number; digest: string | null };
  all_detections: { path: string; rows: number };
  engine_stderr: { path: string; bytes: number };
};

/** Hayabusa as it is called here: `hayabusa json-timeline -f|-d <input> -o <out> -w -q`, writing one JSON object per line to <out>. */
const HAYABUSA_STUB = (lines: string[], tail = ""): string => `
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
cat > "$out" <<'JSONL'
${lines.join("\n")}
JSONL
${tail}
`;

const hb = (title: string, level: string | undefined, id: number, time = "2026-09-01T10:00:00Z"): string =>
  JSON.stringify({ RuleTitle: title, ...(level === undefined ? {} : { Level: level }), Timestamp: time, EventID: 4688, Channel: "Security", Computer: "WS01", RecordID: id, Details: { Cmd: "x" } });

test("sigma_hunt ranks the level words Hayabusa writes (crit, med, info), and keeps a level it does not know instead of dropping it", async () => {
  // rank() was 0 for any word but the five full names, so a `crit` or `med` detection was filtered out
  // by min_level without a word.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "hayabusa", HAYABUSA_STUB([
      hb("Critical rule", "crit", 1, "2026-09-01T10:00:01Z"),
      hb("Medium rule", "med", 2, "2026-09-01T10:00:02Z"),
      hb("High rule", "high", 3, "2026-09-01T10:00:03Z"),
      hb("Info rule", "info", 4),
      hb("Low rule", "low", 5),
      hb("Odd rule", "evil", 6, "2026-09-01T10:00:06Z"),
      hb("Levelless rule", undefined, 7, "2026-09-01T10:00:07Z"),
    ]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const out = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa", min_level: "medium" }, {}, bin));
    assert.equal(out.status, "complete");
    assert.equal(out.engine_detections_read, 7);
    assert.deepEqual(out.detections.map((d) => d.rule), ["Odd rule", "Levelless rule", "Critical rule", "High rule", "Medium rule"], "unknown levels first, then critical down, nothing dropped but what min_level names");
    assert.deepEqual(out.detections.map((d) => d.level_rank), [null, null, 4, 3, 2]);
    assert.equal(out.below_min_level, 2, "info and low are below medium, and counted");
    assert.deepEqual(out.unknown_levels, { evil: 1, "(no level)": 1 });
    assert.equal(out.detection_count, 5);
    assert.equal(out.all_detections.rows, 5);
  });
});

test("sigma_hunt marks a run whose engine exited non-zero partial, and never reads an earlier run's result in its place", async () => {
  // It accepted any result file in out_dir whatever the engine's exit status, so an engine that failed
  // could be answered with the file an earlier invocation left.
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("First run", "high", 1)]));
    const first = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(first.status, "complete");
    // The engine now writes nothing and exits 0: the old result is not this run's.
    await stub(bin, "hayabusa", "exit 0");
    const stale = failed(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa" }, {}, bin));
    assert.match(stale.error, /wrote no result file/);
    // An engine that leaves a result and then fails is a partial run, with its exit status.
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("Second run", "high", 2)], `echo "engine: could not read channel Microsoft-Windows-X" >&2\nexit 3`));
    const partial = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(partial.status, "partial");
    assert.equal(partial.complete, false);
    assert.equal(partial.exit_code, 3);
    assert.deepEqual(partial.detections.map((d) => d.rule), ["Second run"]);
    assert.notEqual(partial.run_dir, first.run_dir, "each invocation has a directory of its own");
    assert.match(await readFile(join(cwd, partial.engine_stderr.path), "utf8"), /could not read channel/);
  });
});

test("sigma_hunt counts a line of the engine's result it cannot read, keeps it whole in a file, and says the run is partial", async () => {
  // A malformed JSON Lines row was passed over with `continue`: the detection it held was never counted.
  await withCwd(async (cwd, bin) => {
    const broken = '{"RuleTitle": "Cut off", "Level": "high", "Timestamp": "2026-09-01T1';
    await stub(bin, "hayabusa", HAYABUSA_STUB([hb("Good one", "high", 1), broken, hb("Good two", "high", 2, "2026-09-01T10:00:02Z")]));
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    const out = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.malformed_lines, 1);
    assert.equal(out.engine_detections_read, 2);
    assert.ok(out.malformed_file);
    assert.match(await readFile(join(cwd, out.malformed_file.path), "utf8"), /line 2\t\{"RuleTitle": "Cut off"/);
  });
});

test("sigma_hunt reads Hayabusa's pretty-printed objects as a stream, and records the ruleset's digest", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "Security.evtx"), "evtx");
    // Objects written one after another across lines (Hayabusa's default JSON timeline), not one per line.
    const pretty = [hb("A", "high", 1), hb("B", "critical", 2)].map((o) => JSON.stringify(JSON.parse(o), null, 2)).join("\n");
    await stub(bin, "hayabusa", HAYABUSA_STUB([pretty]));
    await mkdir(join(cwd, "work", "rules", "sub"), { recursive: true });
    await writeFile(join(cwd, "work", "rules", "a.yml"), "title: a\n");
    await writeFile(join(cwd, "work", "rules", "sub", "b.yml"), "title: b\n");
    const run = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa", rules: "work/rules" }, {}, bin));
    assert.deepEqual(run.detections.map((d) => d.rule), ["B", "A"]);
    assert.equal(run.status, "complete");
    assert.equal(run.ruleset.kind, "directory");
    assert.equal(run.ruleset.files, 2);
    assert.match(run.ruleset.digest ?? "", /^[0-9a-f]{64}$/);
    const noRules = body<HuntOut>(await tool("sigma_hunt", cwd, { path: "work/Security.evtx", out_dir: "work/hunt", engine: "hayabusa" }, {}, bin));
    assert.equal(noRules.ruleset.digest, null);
    assert.match(noRules.ruleset.source, /bundled rules/);
  });
});

test("sigma_hunt's merge sort orders detections by level and time across runs of rows spilled to disk", async () => {
  // The normalised detections were built and sorted whole in memory; they are now a bounded-memory merge.
  await withCwd(async (cwd) => {
    const out = py(
      [
        "import importlib.util, json, os, sys, random",
        "spec = importlib.util.spec_from_file_location('sh', sys.argv[1]); sh = importlib.util.module_from_spec(spec); spec.loader.exec_module(sh)",
        "sh.SORT_RUN_BYTES = 300",
        "random.seed(3)",
        "rows = [(random.choice([None, 0, 1, 2, 3, 4]), '2026-09-01T10:%02d:00Z' % random.randrange(60), i) for i in range(400)]",
        "s = sh.Sorted(sys.argv[2])",
        "for lvl, t, i in rows: s.add({'rule': 'r%d' % i, 'time': t, 'level_rank': lvl}, lvl)",
        "first, count = s.write(os.path.join(sys.argv[2], 'out.jsonl'), 5)",
        "got = [json.loads(l) for l in open(os.path.join(sys.argv[2], 'out.jsonl'))]",
        "want = sorted(rows, key=lambda r: (0 if r[0] is None else 1 + (4 - r[0]), r[1], r[2]))",
        "assert count == 400 and len(got) == 400 and len(first) == 5",
        "assert [g['rule'] for g in got] == ['r%d' % w[2] for w in want]",
        "assert len([n for n in os.listdir(sys.argv[2]) if n.startswith('.sort-')]) == 0",
        "print('ok')",
      ].join("\n"),
      join(WIN, "sigma_hunt", "run.py"),
      join(cwd, "work"),
    );
    assert.equal(out.trim(), "ok");
  });
});

// --- vss_stores -----------------------------------------------------------------

type VssOut = {
  status: string;
  stores: Array<{ store: number; identifier?: string; creation_time?: string; mount_argv: string[][]; mount_with: string }>;
  store_count: number;
  stores_claimed: number | null;
  problems: string[];
  exit_code: number;
  note?: string;
  error?: string;
  stderr_file: string;
  stdout_file: string;
};

/** vshadowinfo's report as libvshadow prints it: a header, `Number of stores`, then a `Store: n` block of tab-indented fields per snapshot. */
const SHADOW_REPORT = (claimed: number | null, shown: number): string => {
  const lines = ["vshadowinfo 20240504", "", "Volume Shadow Snapshot information:"];
  if (claimed !== null) lines.push(`\tNumber of stores:\t${claimed}`);
  for (let i = 1; i <= shown; i++) {
    lines.push("", `Store: ${i}`, `\tIdentifier\t\t: 0b3cd1ec-aaaa-bbbb-cccc-00000000000${i}`, `\tCreation time\t\t: Oct 14, 2023 16:14:3${i}.000000000 UTC`, "\tVolume size\t\t: 53 GiB (57982058496 bytes)");
  }
  return lines.join("\n");
};

const vshadowinfoStub = (report: string, stderr = "", exit = 0): string => `cat <<'REPORT'\n${report}\nREPORT\n${stderr ? `echo '${stderr}' >&2\n` : ""}exit ${exit}`;

test("vss_stores says failed, never 'no stores', when vshadowinfo fails, and keeps its whole stderr in a file", async () => {
  // A failing vshadowinfo left `stores` empty, and the tool printed "No shadow-copy stores were observed on this
  // volume": an absence-shaped answer for a failure.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub("", "vshadowinfo: unable to open volume.\nlibvshadow: unsupported format version 9", 1));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    const run = await tool("vss_stores", cwd, { image: "work/disk.raw", offset: 1048576 }, {}, bin);
    const out = failed(run) as unknown as VssOut;
    assert.equal(out.status, "failed");
    assert.equal(out.exit_code, 1);
    assert.doesNotMatch(run.stdout, /No shadow-copy stores were observed/);
    assert.match(out.note ?? "", /not a finding/);
    assert.match(await readFile(join(cwd, out.stderr_file), "utf8"), /unsupported format version 9/);
  });
});

test("vss_stores reports a count mismatch between the stores vshadowinfo claims and the stores it could read as partial", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(2, 1)));
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    const out = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.equal(out.status, "partial");
    assert.equal(out.stores_claimed, 2);
    assert.equal(out.store_count, 1);
    assert.ok(out.problems.some((p) => /reports 2 store\(s\) and 1 could be read/.test(p)));
    assert.match(out.note ?? "", /incomplete/);
  });
});

test("vss_stores reads a complete report, and quotes every operand of the mount command it suggests", async () => {
  // The suggested command interpolated the image path into a shell string without quoting.
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(2, 2)));
    await writeFile(join(cwd, "work", "my disk;touch pwned.raw"), Buffer.alloc(4096));
    const out = body<VssOut>(await tool("vss_stores", cwd, { image: "work/my disk;touch pwned.raw", offset: 4096 }, {}, bin));
    assert.equal(out.status, "complete");
    assert.equal(out.store_count, 2);
    assert.equal(out.stores[0].identifier, "0b3cd1ec-aaaa-bbbb-cccc-000000000001");
    assert.equal(out.stores[1].creation_time, "Oct 14, 2023 16:14:32.000000000 UTC");
    assert.deepEqual(out.stores[0].mount_argv[1], ["vshadowmount", "-o", "4096", "work/my disk;touch pwned.raw", "work/s1/vss/"]);
    assert.match(out.stores[0].mount_with, /'work\/my disk;touch pwned\.raw'/);
    assert.equal(out.problems.length, 0);
  });
});

test("vss_stores says zero stores only when vshadowinfo ran, exited 0 and reported zero itself, and words it as a bounded negative", async () => {
  await withCwd(async (cwd, bin) => {
    await writeFile(join(cwd, "work", "disk.raw"), Buffer.alloc(4096));
    await stub(bin, "vshadowinfo", vshadowinfoStub(SHADOW_REPORT(0, 0)));
    const none = body<VssOut>(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin));
    assert.equal(none.status, "complete");
    assert.equal(none.store_count, 0);
    assert.match(none.note ?? "", /reported 0 stores/);
    assert.match(none.note ?? "", /does not establish that none was ever made/);
    // An output it does not recognise is a failure, not zero stores.
    await stub(bin, "vshadowinfo", vshadowinfoStub("something else entirely"));
    const odd = failed(await tool("vss_stores", cwd, { image: "work/disk.raw" }, {}, bin)) as unknown as VssOut;
    assert.equal(odd.status, "failed");
    assert.ok(odd.problems.some((p) => /does not recognise its format/.test(p)));
  });
});

test("vss_stores says an EWF image has to be exposed raw first", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "vshadowinfo", vshadowinfoStub("", "unable to open volume", 1));
    await writeFile(join(cwd, "work", "disk.E01"), Buffer.concat([Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]), Buffer.alloc(100)]));
    const out = failed(await tool("vss_stores", cwd, { image: "work/disk.E01" }, {}, bin)) as unknown as VssOut;
    assert.ok(out.problems.some((p) => /EWF \(E01\) signature/.test(p)));
  });
});

// --- indx_carve -----------------------------------------------------------------

/**
 * An INDX record as MS-NTFS-style documentation lays it out (little-endian): "INDX", the update
 * sequence array offset (0x04) and count (0x06), the node header at 0x18 (offset of the first entry
 * from 0x18, live size, allocated size, flags), index entries (the MFT reference, entry length, key
 * length, flags, then the $FILE_NAME key at 0x10), and, in each 512-byte unit, the last two bytes
 * replaced by the update sequence number with the real bytes in the array.
 */
const INDX_TIME = 133_500_000_000_000_001n;

function indxFileName(parent: bigint, name: string): Buffer {
  const b = Buffer.alloc(0x42 + 2 * name.length);
  b.writeBigUInt64LE(parent | (1n << 48n), 0);
  for (let i = 0; i < 4; i++) b.writeBigUInt64LE(INDX_TIME + BigInt(i) * 10_000_000n, 8 + i * 8);
  b.writeBigUInt64LE(4096n, 0x28);
  b.writeUInt32LE(0x20, 0x38);
  b[0x40] = name.length;
  b[0x41] = 1;
  Buffer.from(name, "utf16le").copy(b, 0x42);
  return b;
}

function indxEntry(ref: bigint, content: Buffer, flags = 0, lengthOverride?: number): Buffer {
  let length = 0x10 + content.length;
  length += (8 - (length % 8)) % 8;
  const b = Buffer.alloc(length);
  b.writeBigUInt64LE(ref, 0);
  b.writeUInt16LE(lengthOverride ?? length, 8);
  b.writeUInt16LE(content.length, 10);
  b.writeUInt16LE(flags, 12);
  content.copy(b, 0x10);
  return b;
}

function indxBlock(vcn: number, live: Buffer[], slack: Buffer[], o: { usaCount?: number; breakUnit?: number } = {}): Buffer {
  const b = Buffer.alloc(4096);
  b.write("INDX", 0, "latin1");
  const usaOffset = 0x28;
  const usaCount = o.usaCount ?? 9;
  b.writeUInt16LE(usaOffset, 4);
  b.writeUInt16LE(usaCount, 6);
  b.writeBigUInt64LE(BigInt(vcn), 0x10);
  let at = 0x40;
  for (const e of [...live, indxEntry(0n, Buffer.alloc(0), 0x02)]) {
    e.copy(b, at);
    at += e.length;
  }
  const total = at - 0x18;
  for (const e of slack) {
    e.copy(b, at);
    at += e.length;
  }
  b.writeUInt32LE(0x40 - 0x18, 0x18);
  b.writeUInt32LE(total, 0x1c);
  b.writeUInt32LE(4096 - 0x18, 0x20);
  const sequence = Buffer.from([0x07, 0x00]);
  sequence.copy(b, usaOffset);
  for (let i = 1; i < 9; i++) {
    const end = i * 512 - 2;
    if (i < usaCount) b.copy(b, usaOffset + i * 2, end, end + 2);
    // A unit whose last two bytes do not carry the sequence number is a block torn between writes.
    (o.breakUnit === i ? Buffer.from([0xee, 0xee]) : sequence).copy(b, end);
  }
  return b;
}

type IndxOut = {
  status: string;
  blocks: number;
  blocks_fixup_failed: number;
  blocks_salvaged: number;
  entries_excluded_unreliable: number;
  entry_count: number;
  entries: Array<{ name: string; source: string; block_offset: number; fixup_ok: boolean; node_ok: boolean; salvaged: boolean; created: string | null; created_filetime: string }>;
  problems: Array<{ offset: number; why: string }>;
  note: string;
};

const indxSet = (n: number, tag: string): { live: Buffer[]; slack: Buffer[] } => ({
  live: [indxEntry(100n + BigInt(n), indxFileName(64n, `live-${tag}.txt`))],
  slack: [indxEntry(200n + BigInt(n), indxFileName(64n, `old-${tag}.txt`))],
});

test("indx_carve leaves out the entries of a block whose update sequence check failed, and marks them when asked for", async () => {
  // A block whose fixup failed was recorded under `problems`, but every entry carved from it was
  // emitted as if sound: a row looked as reliable as one from a good block.
  await withCwd(async (cwd) => {
    const good = indxSet(1, "good");
    const torn = indxSet(2, "torn");
    await writeFile(join(cwd, "work", "I30"), Buffer.concat([indxBlock(0, good.live, good.slack), indxBlock(1, torn.live, torn.slack, { breakUnit: 3 })]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.deepEqual(out.entries.map((e) => e.name).sort(), ["live-good.txt", "old-good.txt"]);
    assert.ok(out.entries.every((e) => e.fixup_ok === true && e.node_ok === true && e.salvaged === false && e.block_offset === 0));
    assert.equal(out.blocks, 2);
    assert.equal(out.blocks_fixup_failed, 1);
    assert.equal(out.blocks_salvaged, 1);
    assert.equal(out.entries_excluded_unreliable, 2, "what was left out is counted");
    assert.equal(out.status, "partial");
    assert.deepEqual(out.problems.map((p) => [p.offset, p.why]), [[4096, "sector 3 does not carry the update sequence number"]]);
    assert.match(out.note, /left out \(2\), unless include_unreliable is true/);

    const all = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", include_unreliable: true }));
    assert.equal(all.entry_count, 4);
    const torned = all.entries.filter((e) => e.block_offset === 4096);
    assert.equal(torned.length, 2);
    assert.ok(torned.every((e) => e.fixup_ok === false && e.salvaged === true), "every entry from the torn block carries the flag");
    assert.equal(all.entries_excluded_unreliable, 0);
  });
});

test("indx_carve checks the update sequence array covers the block, and a live entry's length against the live region, and names each failure", async () => {
  await withCwd(async (cwd) => {
    const a = indxSet(1, "short-usa");
    const b = indxSet(2, "bad-length");
    // The array claims 5 values for a block that has 8 units; and an entry whose length runs past the live region.
    const shortUsa = indxBlock(0, a.live, a.slack, { usaCount: 5 });
    const badLength = indxBlock(1, [indxEntry(300n, indxFileName(64n, "overlong.txt"), 0, 0x400)], b.slack);
    await writeFile(join(cwd, "work", "I30"), Buffer.concat([shortUsa, badLength]));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", include_unreliable: true }));
    assert.equal(out.blocks_salvaged, 2);
    assert.ok(out.problems.some((p) => p.offset === 0 && /holds 4 fixup value\(s\) and the block has 8 512-byte unit\(s\)/.test(p.why)), JSON.stringify(out.problems));
    assert.ok(out.problems.some((p) => p.offset === 4096 && /live entry at block offset \d+ has a length \(1024\)/.test(p.why)), JSON.stringify(out.problems));
    assert.ok(out.entries.every((e) => e.salvaged));
    const byDefault = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30" }));
    assert.equal(byDefault.entry_count, 0);
    assert.equal(byDefault.entries_excluded_unreliable > 0, true);
  });
});

test("indx_carve returns the raw FILETIMEs beside the dates and no longer says slack times are the set a timestomper does not reach", async () => {
  await withCwd(async (cwd) => {
    const s = indxSet(1, "x");
    await writeFile(join(cwd, "work", "I30"), indxBlock(0, s.live, s.slack));
    const out = body<IndxOut>(await tool("indx_carve", cwd, { path: "work/I30", slack_only: true }));
    assert.equal(out.entries.length, 1);
    assert.equal(out.entries[0].source, "slack");
    assert.equal(out.entries[0].created_filetime, "133500000000000001");
    assert.equal(out.entries[0].created, "2024-01-17T21:20:00.0000001Z");
    assert.doesNotMatch(out.note, /timestomper/);
    assert.match(out.note, /stale index material/);
    assert.match(out.note, /not evidence that they were left unaltered/);
  });
});

// --- prefetch_mam and mam_scan --------------------------------------------------

/**
 * A Prefetch (SCCA) file as the libscca layout notes lay it out: the version at 0, "SCCA" at 4,
 * the file size at 0x0C, the executable name (UTF-16LE, 60 bytes) at 0x10, the hash at 0x4C; the file
 * information from 0x54 (metrics offset and entries, trace chains offset and entries, filename strings
 * offset and size, volume information offset, entries and size); the last-run FILETIMEs (0x78 in version 17,
 * 0x80 after, one slot in 17 and 23, eight from 26) and the run count (0x90, 0x98, 0xD0) by version;
 * the filename strings as one UTF-16LE list of NUL-terminated names; and a volume entry (device path
 * offset and character count, creation FILETIME, serial number, then the path itself).
 */
type Scca = { version: number; exe: string; hash: number; runCount: number; lastRuns: bigint[]; names: string[]; device?: string; serial?: number; created?: bigint };

function scca(o: Scca): Buffer {
  const layout: Record<number, { lastAt: number; slots: number; countAt: number }> = {
    17: { lastAt: 0x78, slots: 1, countAt: 0x90 },
    23: { lastAt: 0x80, slots: 1, countAt: 0x98 },
    26: { lastAt: 0x80, slots: 8, countAt: 0xd0 },
    30: { lastAt: 0x80, slots: 8, countAt: 0xd0 },
  };
  const l = layout[o.version] ?? layout[30];
  const names = Buffer.concat(o.names.map((n) => u16z(n)));
  const namesAt = 0x200;
  const volsAt = namesAt + Math.ceil(names.length / 8) * 8;
  const device = o.device === undefined ? Buffer.alloc(0) : u16z(o.device);
  const b = Buffer.alloc(volsAt + 0x68 + device.length + 8);
  b.writeUInt32LE(o.version, 0);
  b.write("SCCA", 4, "latin1");
  b.writeUInt32LE(0x0f, 8);
  b.writeUInt32LE(b.length, 12);
  Buffer.from(o.exe, "utf16le").copy(b, 0x10);
  b.writeUInt32LE(o.hash, 0x4c);
  b.writeUInt32LE(0x138, 0x54);
  b.writeUInt32LE(o.names.length, 0x58);
  b.writeUInt32LE(0x138, 0x5c);
  b.writeUInt32LE(0, 0x60);
  b.writeUInt32LE(namesAt, 0x64);
  b.writeUInt32LE(names.length, 0x68);
  b.writeUInt32LE(volsAt, 0x6c);
  b.writeUInt32LE(o.device === undefined ? 0 : 1, 0x70);
  b.writeUInt32LE(0x68 + device.length, 0x74);
  o.lastRuns.slice(0, l.slots).forEach((t, i) => b.writeBigUInt64LE(t, l.lastAt + i * 8));
  b.writeUInt32LE(o.runCount, l.countAt);
  names.copy(b, namesAt);
  if (o.device !== undefined) {
    b.writeUInt32LE(0x68, volsAt);
    b.writeUInt32LE(o.device.length + 1, volsAt + 4);
    b.writeBigUInt64LE(o.created ?? 0n, volsAt + 8);
    b.writeUInt32LE(o.serial ?? 0, volsAt + 16);
    device.copy(b, volsAt + 0x68);
  }
  return b;
}

/**
 * Xpress Huffman (the MS-XCA LZ77+Huffman format MAM uses): chunks of up to 65536 output bytes, each a
 * 256-byte table of 512 four-bit code lengths and then a bit stream read as little-endian 16-bit words, most
 * significant bit first. Every symbol is given a 9-bit code here (a complete code: 512 symbols of length 9), so
 * symbol s has code s: literals are 0..255 and a match (offset 1, 3 to 17 bytes) is 256 + length - 3. A chunk
 * ends after the symbol that takes it to 65536 bytes and is followed by one zero word; the last by two.
 */
function xpressHuffman(ops: Array<number | { match: number }>): Buffer {
  const out: Buffer[] = [];
  let i = 0;
  while (i < ops.length) {
    let size = 0;
    const words: number[] = [];
    let acc = 0;
    let nbits = 0;
    const put = (symbol: number): void => {
      for (let b = 8; b >= 0; b--) {
        acc = (acc << 1) | ((symbol >> b) & 1);
        if (++nbits === 16) {
          words.push(acc);
          acc = 0;
          nbits = 0;
        }
      }
    };
    while (i < ops.length && size < 65536) {
      const op = ops[i++];
      if (typeof op === "number") {
        put(op);
        size += 1;
      } else {
        put(256 + op.match - 3);
        size += op.match;
      }
    }
    if (nbits) words.push(acc << (16 - nbits));
    words.push(0);
    if (i >= ops.length) words.push(0);
    out.push(Buffer.alloc(256, 0x99));
    const w = Buffer.alloc(words.length * 2);
    words.forEach((v, k) => w.writeUInt16LE(v, k * 2));
    out.push(w);
  }
  return Buffer.concat(out);
}

/** A MAM container: "MAM", the method byte, the declared uncompressed size, the compressed data. */
function mam(declared: number, compressed: Buffer, method = 4): Buffer {
  const head = Buffer.alloc(8);
  head.write("MAM", 0, "latin1");
  head[3] = method;
  head.writeUInt32LE(declared, 4);
  return Buffer.concat([head, compressed]);
}

const mamOf = (plain: Buffer): Buffer => mam(plain.length, xpressHuffman([...plain]));

type PrefetchOut = {
  status: string;
  container: { mam: boolean; declared_uncompressed_size?: number; decompressed_size?: number; bytes_past_declared_size?: number; why?: string; method?: number };
  version?: number;
  supported?: boolean;
  exe_name?: string;
  prefetch_hash?: string;
  run_count?: number | null;
  last_runs?: string[];
  last_runs_detail?: Array<{ slot: number; filetime: string; utc: string }>;
  filename_strings?: string[];
  volumes_decoded?: Array<{ device_path: string | null; serial_number: string; created_utc: string | null }>;
  volumes_claimed?: number;
  file_size_matches?: boolean;
  problems: string[];
  all_strings?: unknown;
};

const RUN_1 = 133_443_104_001_234_567n; // 2023-11-13T00:53:20.1234567Z
const SAMPLE_NAMES = [
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\USERS\\ÖZGÜR\\DOCUMENTS\\RAPOR-ÇALIŞMA.DOCX",
  "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}\\PROGRAM FILES\\EXAMPLE\\EXAMPLE.EXE",
];

function sample(version: number): Buffer {
  return scca({
    version,
    exe: "EXAMPLE.EXE",
    hash: 0xa1b2c3d4,
    runCount: 7,
    lastRuns: [RUN_1, RUN_1 + 10_000_000n, 0n, 0n, 0n, 0n, 0n, 0n],
    names: SAMPLE_NAMES,
    device: "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}",
    serial: 0x1a2b3c4d,
    created: RUN_1 - 5_000_000_000n,
  });
}

test("prefetch_mam reads a version 30 file by its layout: the run count, last runs by integer arithmetic, every filename string whole, and the first volume", async () => {
  // The strings were found by a regular expression that matched ASCII-range UTF-16 only, so a path with a
  // non-ASCII character was missed; the last-run fraction was rounded through a float.
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "EXAMPLE.EXE-A1B2C3D4.pf"), sample(30));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/EXAMPLE.EXE-A1B2C3D4.pf" }));
    assert.equal(out.status, "complete");
    assert.equal(out.container.mam, false);
    assert.equal(out.version, 30);
    assert.equal(out.exe_name, "EXAMPLE.EXE");
    assert.equal(out.prefetch_hash, "A1B2C3D4");
    assert.equal(out.run_count, 7);
    assert.deepEqual(out.last_runs, ["2023-11-13T00:53:20.1234567Z", "2023-11-13T00:53:21.1234567Z"]);
    assert.equal(out.last_runs_detail?.[0].filetime, String(RUN_1));
    assert.deepEqual(out.filename_strings, SAMPLE_NAMES, "the section the header locates, every name whole, non-ASCII included");
    assert.equal(out.volumes_decoded?.[0].device_path, "\\VOLUME{01d9aaaabbbb0000-1a2b3c4d}");
    assert.equal(out.volumes_decoded?.[0].serial_number, "1A2B3C4D");
    assert.equal(out.file_size_matches, true);
    assert.deepEqual(out.problems, []);
    assert.equal(out.all_strings, undefined, "the printable-run search is gone");
  });
});

test("prefetch_mam reads a version 23 file at its own offsets: the run count at 0x98 and one last-run slot", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "a.pf"), sample(23));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/a.pf" }));
    assert.equal(out.version, 23);
    assert.equal(out.run_count, 7);
    assert.deepEqual(out.last_runs, ["2023-11-13T00:53:20.1234567Z"]);
  });
});

test("prefetch_mam returns unsupported for a version it does not read, and interprets none of its version-dependent fields", async () => {
  // Version 99 was read as if it were 30: a last-run time and a run count came out of bytes that mean something else.
  await withCwd(async (cwd) => {
    const odd = sample(30);
    odd.writeUInt32LE(99, 0);
    await writeFile(join(cwd, "work", "odd.pf"), odd);
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/odd.pf" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.supported, false);
    assert.equal(out.version, 99);
    assert.equal(out.exe_name, "EXAMPLE.EXE", "the version-independent header is still read");
    assert.equal(out.last_runs, undefined);
    assert.equal(out.run_count, undefined);
    assert.equal(out.filename_strings, undefined);
    assert.match(out.problems[0], /version 99 is not one this parser reads/);
  });
});

test("prefetch_mam inflates a MAM-compressed file to the same reading as the plain one, and says what the container held", async () => {
  await withCwd(async (cwd) => {
    const plain = sample(30);
    await writeFile(join(cwd, "work", "c.pf"), mamOf(plain));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/c.pf" }));
    assert.equal(out.status, "complete");
    assert.equal(out.container.mam, true);
    assert.equal(out.container.declared_uncompressed_size, plain.length);
    assert.equal(out.container.decompressed_size! - out.container.bytes_past_declared_size!, plain.length);
    assert.ok(out.container.bytes_past_declared_size! < 64, "a few bytes past the declared size are the stream's own end");
    assert.deepEqual(out.filename_strings, SAMPLE_NAMES);
    assert.equal(out.run_count, 7);
    // A file larger than one 64 KiB chunk: several chunks of literals, each with its own table.
    const big = Buffer.concat([sample(30), Buffer.alloc(200_000, 0x5a)]);
    big.writeUInt32LE(big.length, 12);
    await writeFile(join(cwd, "work", "big.pf"), mamOf(big));
    const bigOut = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/big.pf" }));
    assert.equal(bigOut.container.declared_uncompressed_size, big.length);
    assert.deepEqual(bigOut.filename_strings, SAMPLE_NAMES);
  });
});

test("prefetch_mam refuses a MAM method it does not read, by name, and inflates nothing", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "v.pf"), mam(1000, Buffer.alloc(300), 0x84));
    const out = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/v.pf" }));
    assert.equal(out.status, "unsupported");
    assert.equal(out.container.method, 0x84);
    assert.match(out.container.why ?? "", /method byte 0x84 is not the Xpress Huffman method/);
    assert.match(out.problems[0], /checksum/);
  });
});

test("prefetch_mam stops a stream that inflates past its declared size at the cap, and does not hold the whole output", async () => {
  // The whole payload was decompressed before its size was looked at: a stream declared as 1 MiB could grow
  // to any size, since the decoder runs until its input ends. This one is declared 1 MiB and would inflate to
  // about 100 MiB: seven thousand matches of 17 bytes, repeated.
  await withCwd(async (cwd) => {
    const ops: Array<number | { match: number }> = [0x41];
    for (let i = 0; i < 6_000_000; i++) ops.push({ match: 17 });
    const bomb = mam(1024 * 1024, xpressHuffman(ops));
    await writeFile(join(cwd, "work", "bomb.pf"), bomb);
    const started = Date.now();
    const err = failed(await tool("prefetch_mam", cwd, { path: "work/bomb.pf" }));
    assert.match(err.error, /inflates past its declared size of 1048576 bytes plus 65536/);
    assert.equal(err.cap, 1048576 + 65536);
    assert.ok(Date.now() - started < 60_000, "the decoder was stopped at the cap, not run to the end of its input");
  });
});

test("prefetch_mam fails on a stream shorter than its declared size, and on a declared size past the cap", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "short.pf"), mam(5000, xpressHuffman([...Buffer.alloc(100, 0x41)])));
    assert.match(failed(await tool("prefetch_mam", cwd, { path: "work/short.pf" })).error, /ended before its declared uncompressed size/);
    await writeFile(join(cwd, "work", "huge.pf"), mam(0xffffffff, Buffer.alloc(300)));
    const huge = body<PrefetchOut>(await tool("prefetch_mam", cwd, { path: "work/huge.pf" }));
    assert.equal(huge.status, "unsupported");
    assert.match(huge.container.why ?? "", /past the 67108864 this tool will inflate/);
  });
});

type ScanOut = {
  status: string;
  count: number;
  hits: Array<{ offset: number; uncomp: number; version?: number; supported?: boolean; name?: string; run_count?: number; filename_strings?: string[]; last_runs?: string[]; problems?: string[] }>;
  candidates: number;
  parsed: number;
  failed: number;
  failed_by_reason: Record<string, number>;
  failures: Array<{ offset: number; reason: string }>;
  filtered_by_name: number;
  size_out_of_range: number;
  unsupported_variant_signatures: number;
};

test("mam_scan finds a record that straddles a scan window once, with the right offset, and reads it by its layout", async () => {
  await withCwd(async (cwd) => {
    const record = mamOf(sample(30));
    const junk = Buffer.alloc(4090, 0x2e);
    const dump = Buffer.concat([junk, record, Buffer.alloc(5000, 0x2e)]);
    await writeFile(join(cwd, "work", "mem.raw"), dump);
    // chunk 4096: the record begins 6 bytes before the first window ends, so its header straddles it.
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", chunk: 4096, min_uncomp: 256 }));
    assert.equal(out.count, 1);
    assert.equal(out.hits[0].offset, 4090);
    assert.equal(out.hits[0].name, "EXAMPLE.EXE");
    assert.equal(out.hits[0].run_count, 7);
    assert.deepEqual(out.hits[0].filename_strings, SAMPLE_NAMES);
    assert.equal(out.candidates, 1);
    assert.equal(out.failed, 0);
    assert.equal(out.status, "complete");
  });
});

test("mam_scan counts an unsupported version as parsed and unsupported, and every failure before the name filter drops anything", async () => {
  // A candidate that failed to decompress had no name, so a name filter dropped it without a trace; the
  // fixed 0x80 and 0xD0 offsets were applied to every version.
  await withCwd(async (cwd) => {
    const v99 = sample(30);
    v99.writeUInt32LE(99, 0);
    const rubbish = mam(2048, Buffer.from("this is not an xpress huffman stream at all".repeat(20)));
    const other = scca({ version: 30, exe: "OTHER.EXE", hash: 1, runCount: 2, lastRuns: [RUN_1], names: ["\\VOLUME{x}\\OTHER.EXE"] });
    const pad = (n: number): Buffer => Buffer.alloc(n, 0x2e);
    const dump = Buffer.concat([pad(100), mamOf(sample(30)), pad(60), mamOf(v99), pad(60), rubbish, pad(60), mamOf(other), pad(60), Buffer.from("MAM\x84\x00\x10\x00\x00", "latin1"), pad(100)]);
    await writeFile(join(cwd, "work", "mem.raw"), dump);
    const all = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200 }));
    assert.equal(all.candidates, 4);
    assert.equal(all.parsed, 3);
    assert.equal(all.failed, 1);
    assert.equal(Object.keys(all.failed_by_reason).length, 1);
    assert.equal(all.failures.length, 1);
    assert.match(all.failures[0].reason, /^(decompress_failed|stream_ended_before_declared_size|not_prefetch)/);
    assert.equal(all.unsupported_variant_signatures, 1);
    assert.equal(all.status, "partial");
    const unsupported = all.hits.find((h) => h.version === 99);
    assert.ok(unsupported, "an unsupported version is a hit, not a drop");
    assert.equal(unsupported.supported, false);
    assert.equal(unsupported.run_count, undefined);
    assert.equal(unsupported.last_runs, undefined);
    // With a name filter, the failure is still counted.
    const filtered = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 200, name_filter: "OTHER.EXE" }));
    assert.deepEqual(filtered.hits.map((h) => h.name), ["OTHER.EXE"]);
    assert.equal(filtered.parsed, 3);
    assert.equal(filtered.failed, 1, "the record that could not be read is counted, not lost to the filter");
    assert.equal(filtered.filtered_by_name, 2);
  });
});

test("mam_scan stops a candidate whose payload inflates past its declared size at that size", async () => {
  await withCwd(async (cwd) => {
    const ops: Array<number | { match: number }> = [0x41];
    for (let i = 0; i < 2_000_000; i++) ops.push({ match: 17 });
    await writeFile(join(cwd, "work", "mem.raw"), Buffer.concat([Buffer.alloc(64, 0x2e), mam(4096, xpressHuffman(ops)), Buffer.alloc(64, 0x2e)]));
    const started = Date.now();
    const out = body<ScanOut>(await tool("mam_scan", cwd, { path: "work/mem.raw", min_uncomp: 256 }));
    assert.equal(out.candidates, 1);
    assert.deepEqual(out.failed_by_reason, { not_prefetch: 1 });
    assert.ok(Date.now() - started < 30_000);
  });
});

test("prefetch_mam and mam_scan carry the same MAM, decompression and SCCA code", async () => {
  // The tools are standalone, so the shared reader is a copy; this holds the two copies identical.
  const mark = "# ---- Shared by prefetch_mam and mam_scan";
  const a = await readFile(join(WIN, "prefetch_mam", "run.py"), "utf8");
  const b = await readFile(join(WIN, "mam_scan", "run.py"), "utf8");
  const shared = (text: string, end: string): string => text.slice(text.indexOf(mark), text.indexOf(end)).trimEnd();
  const one = shared(a, "\n\n\ndef fail(");
  const two = shared(b, "\n\n\nSIG4 =");
  assert.ok(one.length > 3000, "the shared block was found");
  assert.ok(one === two, "the shared MAM and SCCA code differs between prefetch_mam and mam_scan");
});

// --- recyclebin_i ---------------------------------------------------------------

type RecycleEntry = {
  file: string;
  file_bytes?: number;
  header_version?: number;
  original_size?: number;
  deleted_at?: string | null;
  deleted_filetime?: string;
  original_path?: string;
  path_characters_declared?: number;
  truncated: boolean;
  trailing_bytes?: number;
  note?: string;
  error?: string;
  r_file: string | null;
  bin_directory_sid?: string;
};
type RecycleOut = { status: string; entries: RecycleEntry[]; entry_count: number; found: number; parsed: number; records_truncated: number; unknown_header: number; unreadable: number };

/** $I as documented: header (8), original size (8), deletion FILETIME (8); version 1 then holds 520 bytes of UTF-16LE path (544 in all); version 2 a 4-byte character count (the NUL included) and that many characters. */
function recycleV2(path: string, size: bigint, filetime: bigint, declared?: number): Buffer {
  const text = u16z(path);
  const b = Buffer.alloc(0x1c + text.length);
  b.writeBigUInt64LE(2n, 0);
  b.writeBigUInt64LE(size, 8);
  b.writeBigUInt64LE(filetime, 0x10);
  b.writeUInt32LE(declared ?? path.length + 1, 0x18);
  text.copy(b, 0x1c);
  return b;
}

function recycleV1(path: string, size: bigint, filetime: bigint): Buffer {
  const b = Buffer.alloc(544);
  b.writeBigUInt64LE(1n, 0);
  b.writeBigUInt64LE(size, 8);
  b.writeBigUInt64LE(filetime, 0x10);
  Buffer.from(path, "utf16le").copy(b, 0x18);
  return b;
}

test("recyclebin_i reads a complete version 2 and version 1 record, with the deletion time exact, the $R counterpart and the bin's SID", async () => {
  await withCwd(async (cwd) => {
    const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const dir = join(cwd, "work", "recycle", sid);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "$IABCDEF.rtf"), recycleV2("C:\\Users\\joker\\Confidential.rtf", 439n, RUN_1));
    await writeFile(join(dir, "$RABCDEF.rtf"), "content");
    await writeFile(join(dir, "$IGHIJKL.txt"), recycleV1("C:\\Users\\joker\\notes-ğüşiöç.txt", 12n, RUN_1 + 10_000_000n));
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    assert.equal(out.status, "complete");
    assert.equal(out.found, 2);
    assert.equal(out.parsed, 2);
    const [v2, v1] = out.entries;
    assert.equal(v2.original_path, "C:\\Users\\joker\\Confidential.rtf");
    assert.equal(v2.original_size, 439);
    assert.equal(v2.deleted_at, "2023-11-13T00:53:20.1234567Z");
    assert.equal(v2.deleted_filetime, String(RUN_1));
    assert.equal(v2.truncated, false);
    assert.equal(v2.r_file, "$RABCDEF.rtf");
    assert.equal(v2.bin_directory_sid, sid);
    assert.equal(v1.original_path, "C:\\Users\\joker\\notes-ğüşiöç.txt");
    assert.equal(v1.header_version, 1);
    assert.equal(v1.r_file, null, "no $R beside it");
    assert.deepEqual(out.entries.map((e) => e.file.split("/").pop()), ["$IABCDEF.rtf", "$IGHIJKL.txt"], "sorted traversal");
  });
});

test("recyclebin_i reports a truncated record as truncated, with the bytes it has, and does not return a short path as a whole one", async () => {
  // A 24-byte header returned an empty path with no error, and a record that claimed 100 characters and
  // supplied one returned "A" as if it were the whole path.
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "$IHEADER.bin"), recycleV1("", 5n, RUN_1).subarray(0, 24));
    const oneChar = recycleV2("A", 5n, RUN_1, 100);
    await writeFile(join(dir, "$ICLAIMS.bin"), oneChar);
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    assert.equal(out.status, "partial");
    assert.equal(out.records_truncated, 2);
    const claims = out.entries.find((e) => e.file.endsWith("$ICLAIMS.bin"))!;
    assert.equal(claims.truncated, true);
    assert.equal(claims.path_characters_declared, 100);
    assert.equal(claims.original_path, "A");
    assert.match(claims.note ?? "", /declares 100 path characters \(228 bytes in all\) and this file has 32 bytes/);
    const header = out.entries.find((e) => e.file.endsWith("$IHEADER.bin"))!;
    assert.equal(header.truncated, true);
    assert.match(header.note ?? "", /a version 1 record is 544 bytes and this file has 24/);
  });
});

test("recyclebin_i reads the whole of a long path, past the 4096 bytes it used to read, and names an unknown header and an oversize file", async () => {
  await withCwd(async (cwd) => {
    const dir = join(cwd, "work", "recycle");
    await mkdir(dir, { recursive: true });
    const long = "C:\\" + "d".repeat(3000) + "\\end.txt";
    await writeFile(join(dir, "$ILONG.txt"), recycleV2(long, 1n, RUN_1));
    const odd = Buffer.alloc(64);
    odd.writeBigUInt64LE(9n, 0);
    await writeFile(join(dir, "$IODD.bin"), odd);
    await writeFile(join(dir, "$IHUGE.bin"), Buffer.alloc(1024 * 1024 + 10));
    const out = body<RecycleOut>(await tool("recyclebin_i", cwd, { path: "work/recycle" }));
    const byName = Object.fromEntries(out.entries.map((e) => [e.file.split("/").pop(), e]));
    assert.equal(byName["$ILONG.txt"].original_path, long);
    assert.equal(byName["$ILONG.txt"].truncated, false);
    assert.match(byName["$IODD.bin"].error ?? "", /unknown header version 9/);
    assert.equal(byName["$IODD.bin"].original_path, undefined);
    assert.match(byName["$IHUGE.bin"].error ?? "", /not a \$I|a few hundred bytes/);
    assert.equal(out.unknown_header, 1);
    assert.equal(out.unreadable, 1);
    assert.equal(out.status, "partial");
  });
});

// --- utf16_urls -----------------------------------------------------------------

type UrlOut = {
  status: string;
  candidates: Array<{ encoding: string; offset: number; length_bytes: number; text: string; continued?: boolean; piece_of_a_longer_run?: boolean }>;
  candidate_count: number;
  by_encoding: { ascii: number; utf16le: number };
  groups: Array<{ text: string; encoding: string; occurrences: number; first_offset: number }>;
  distinct_count: number;
  groups_complete: boolean;
  filtered_out_by_contains: number;
  pieces: number;
  all_results?: string;
  urls?: unknown;
};

const wide = (text: string): Buffer => Buffer.from(text, "utf16le");

test("utf16_urls returns a URL of any length whole and keeps every occurrence with its own offset", async () => {
  // The ASCII pattern stopped after 300 characters without marking it, and a `seen` set dropped every
  // occurrence after the first, with its offset.
  await withCwd(async (cwd) => {
    const long = "https://example.test/" + "segment/".repeat(75) + "end?token=1";
    assert.ok(long.length > 600);
    const filler = Buffer.alloc(3000, 0xff);
    const file = Buffer.concat([filler, Buffer.from(long), filler, Buffer.from(long), filler]);
    await writeFile(join(cwd, "work", "mem.raw"), file);
    const out = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/mem.raw" }));
    assert.equal(out.candidate_count, 2);
    assert.deepEqual(out.candidates.map((c) => c.offset), [3000, 3000 + long.length + 3000]);
    assert.ok(out.candidates.every((c) => c.text === long && c.encoding === "ascii" && c.length_bytes === long.length));
    assert.equal(out.urls, undefined, "the field is `candidates` now");
    assert.equal(out.distinct_count, 1);
    assert.deepEqual(out.groups.map((g) => [g.occurrences, g.first_offset]), [[2, 3000]]);
  });
});

test("utf16_urls finds a URL that straddles a read window once, in ASCII and in UTF-16LE, and keeps a run longer than the carry whole in pieces", async () => {
  await withCwd(async (cwd) => {
    const chunk = 131072;
    const ascii = "http://straddle.test/path/to/a/page?id=7";
    const utf16 = wide("https://wide.test/visited/entry?x=1");
    const file = Buffer.alloc(chunk * 3, 0xff);
    Buffer.from(ascii).copy(file, chunk - 15);
    utf16.copy(file, chunk * 2 - 21);
    const big = "http://long.test/" + "a".repeat(200_000);
    const withBig = Buffer.concat([file, Buffer.from(big), Buffer.alloc(100, 0xff)]);
    await writeFile(join(cwd, "work", "mem.raw"), withBig);
    const out = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/mem.raw", chunk }));
    const small = out.candidates.filter((c) => !c.piece_of_a_longer_run);
    assert.deepEqual(small.map((c) => [c.encoding, c.offset, c.text]), [
      ["ascii", chunk - 15, ascii],
      ["utf16le", chunk * 2 - 21, "https://wide.test/visited/entry?x=1"],
    ]);
    const pieces = out.candidates.filter((c) => c.piece_of_a_longer_run);
    assert.ok(pieces.length >= 2, "a run past the carry is returned in pieces");
    assert.equal(pieces.map((p) => p.text).join(""), big, "every character of it is kept");
    assert.deepEqual(pieces.map((p) => p.continued), pieces.map((_, i) => i < pieces.length - 1));
    assert.equal(pieces[0].offset, chunk * 3);
    for (let i = 1; i < pieces.length; i++) assert.equal(pieces[i].offset, pieces[i - 1].offset + pieces[i - 1].length_bytes, "pieces are adjacent");
  });
});

test("utf16_urls keeps a UTF-16LE run only where it holds an anchor, applies `contains`, and counts what it filtered", async () => {
  await withCwd(async (cwd) => {
    const file = Buffer.concat([
      Buffer.alloc(50, 0xff),
      wide("Visited: someone@file:///C:/Users/x/report.docx"),
      Buffer.alloc(20, 0xff),
      wide("a long run of printable text in two byte characters that names no address at all"),
      Buffer.alloc(20, 0xff),
      wide("http://192.168.4.7/admin/panel"),
      Buffer.from("http://other.test/page-one"),
    ]);
    await writeFile(join(cwd, "work", "WebCacheV01.dat"), file);
    const all = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/WebCacheV01.dat" }));
    assert.deepEqual(all.candidates.map((c) => [c.encoding, c.text]), [
      ["ascii", "http://other.test/page-one"],
      ["utf16le", "Visited: someone@file:///C:/Users/x/report.docx"],
      ["utf16le", "http://192.168.4.7/admin/panel"],
    ], "the ASCII scan reports first, then the UTF-16LE scan; no run without an anchor is a candidate");
    const only = body<UrlOut>(await tool("utf16_urls", cwd, { path: "work/WebCacheV01.dat", contains: "192.168" }));
    assert.deepEqual(only.candidates.map((c) => c.text), ["http://192.168.4.7/admin/panel"]);
    assert.equal(only.filtered_out_by_contains, 2);
  });
});

// --- regkv ----------------------------------------------------------------------

type RegkvOut = {
  status: string;
  hive: string;
  key: string;
  values: Record<string, unknown>;
  value_types: Record<string, string>;
  value_lengths: Record<string, number | null>;
  subkeys: Array<{ name: string; subkeys: number; values: number; last_modified?: string; last_modified_filetime?: string; subkey_list?: Array<{ name: string }> }>;
  last_modified?: string;
  last_modified_filetime?: string;
  problems: Array<{ where: string; what: string; error: string }>;
  stopped_branches: Array<{ path: string; reason: string }>;
  stopped_branch_count: number;
  tree_complete: boolean;
  nodes?: Array<{ path: string; depth: number }>;
  node_count?: number;
  all_nodes?: string;
  hive_dirty: boolean;
  transaction_logs_beside_hive: string[];
  transaction_logs_replayed: boolean;
  sensitive_values_withheld: Array<{ key: string; name: string; type: string; length: number | null }>;
  hive_type: string | null;
};

test("regkv returns a value whole with its type and length: a binary value past 128 bytes, a string past 256 characters, a multi-string and a qword", async () => {
  // regipy trims a value to 256 characters by default, so a binary value came back cut at 128 bytes and a long
  // string at 256 characters, without a word; types were dropped.
  await withCwd(async (cwd) => {
    const blob = Buffer.from(Array.from({ length: 700 }, (_, i) => i % 251));
    const longText = "C:\\Program Files\\" + "Directory\\".repeat(60) + "tool.exe";
    await writeFile(join(cwd, "work", "NTUSER.DAT"), hive({
      name: "ROOT",
      children: [{ name: "Software", children: [{
        name: "Vendor",
        lastWritten: 133_443_104_001_234_567n,
        values: [
          { name: "Blob", type: "binary", value: blob },
          { name: "LongPath", type: "sz", value: longText },
          { name: "List", type: "multi_sz", value: ["alpha", "beta"] },
          { name: "Big", type: "qword", value: 0x1234_5678_9abc_def0n },
          { name: "Count", type: "dword", value: 7 },
        ],
      }] }],
    }));
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/NTUSER.DAT", key: "Software\\Vendor" }));
    assert.equal(out.status, "complete");
    assert.equal(out.values.Blob, blob.toString("hex"), "700 bytes, all of them");
    assert.equal(out.value_lengths.Blob, 700);
    assert.equal(out.value_types.Blob, "REG_BINARY");
    assert.equal(out.values.LongPath, longText);
    assert.equal(out.value_lengths.LongPath, longText.length);
    assert.deepEqual(out.values.List, ["alpha", "beta"]);
    assert.equal(out.value_types.List, "REG_MULTI_SZ");
    assert.equal(out.value_types.Big, "REG_QWORD");
    assert.equal(out.value_types.Count, "REG_DWORD");
    assert.equal(out.values.Count, 7);
    assert.equal(out.last_modified, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.last_modified_filetime, "133443104001234567");
  });
});

test("regkv says a hive is dirty and names the logs beside it, and does not claim to have replayed them", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "SYSTEM"), hive({ name: "ROOT", children: [{ name: "Select", values: [{ name: "Current", type: "dword", value: 1 }] }] }, { primarySeq: 12, secondarySeq: 11 }));
    await writeFile(join(cwd, "work", "SYSTEM.LOG1"), Buffer.alloc(512));
    await writeFile(join(cwd, "work", "SYSTEM.LOG2"), Buffer.alloc(512));
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SYSTEM", key: "Select" }));
    assert.equal(out.hive_dirty, true);
    assert.deepEqual(out.transaction_logs_beside_hive, ["work/SYSTEM.LOG1", "work/SYSTEM.LOG2"]);
    assert.equal(out.transaction_logs_replayed, false);
    assert.equal(out.hive, "work/SYSTEM");
  });
});

test("regkv lists every node of a recursive walk, names the branches it did not enter and why, and keeps the whole listing in a file past the inline page", async () => {
  // `walk()` returned [] for any key it could not open, and nothing said a branch had been left out.
  await withCwd(async (cwd) => {
    const wide = Array.from({ length: 30 }, (_, i) => ({ name: `Leaf${String(i).padStart(2, "0")}`, children: [{ name: "Deep", children: [{ name: "Deeper" }] }] }));
    await writeFile(join(cwd, "work", "SOFTWARE"), hive({ name: "ROOT", children: [{ name: "Tree", children: wide }] }));
    const out = body<RegkvOut>(await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Tree", recurse: true, depth: 1, limit: 10 }));
    assert.equal(out.node_count, 60, "30 leaves and the 30 keys below them; the third level is not entered");
    assert.equal(out.nodes!.length, 10);
    assert.ok(out.all_nodes, "the whole listing is in a file the answer names");
    assert.equal(out.stopped_branch_count, 30, "each Deep with a child of its own was not entered");
    assert.match(out.stopped_branches[0].reason, /depth limit \(1\)/);
    assert.equal(out.status, "partial");
    assert.equal(out.tree_complete, true);
    const rows = (await readFile(join(cwd, out.all_nodes as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { path: string; depth: number });
    assert.equal(rows.length, 60);
    assert.deepEqual(rows.slice(0, 2).map((r) => r.path), ["Tree\\Leaf00", "Tree\\Leaf01"]);
  });
});

test("regkv withholds the values that can be secrets, by name and by place, and says what it withheld", async () => {
  await withCwd(async (cwd) => {
    const pw = "Summer2024!hunter2";
    await writeFile(join(cwd, "work", "SOFTWARE"), hive({
      name: "ROOT",
      children: [{ name: "Winlogon", values: [
        { name: "DefaultUserName", type: "sz", value: "alice" },
        { name: "DefaultPassword", type: "sz", value: pw },
        { name: "AutoAdminLogon", type: "sz", value: "1" },
        { name: "PasswordExpiryWarning", type: "dword", value: 5 },
        { name: "Vpn_Token", type: "binary", value: Buffer.from("tok-" + pw) },
      ] }],
    }));
    const run = await tool("regkv", cwd, { hive: "work/SOFTWARE", key: "Winlogon" });
    const out = body<RegkvOut>(run);
    for (const piece of [pw, "hunter2", Buffer.from(pw).toString("hex"), Buffer.from(pw, "utf16le").toString("hex"), Buffer.from("tok-" + pw).toString("hex")]) {
      assert.equal(run.stdout.includes(piece), false, piece);
    }
    assert.equal(out.values.DefaultUserName, "alice");
    assert.equal(out.values.AutoAdminLogon, "1");
    assert.equal(out.values.PasswordExpiryWarning, 5, "a DWORD is not text or bytes: not withheld");
    assert.equal(out.values.DefaultPassword, `[withheld: ${pw.length} characters]`);
    assert.deepEqual(out.sensitive_values_withheld.map((w) => [w.name, w.type, w.length]).sort(), [
      ["DefaultPassword", "REG_SZ", pw.length],
      ["Vpn_Token", "REG_BINARY", pw.length + 4],
    ]);
  });
});

test("regkv withholds the V value of a SAM user and the secrets of a SECURITY hive, whatever their names", async () => {
  await withCwd(async (cwd) => {
    const verifier = Buffer.from("planted-verifier-material-0123456789abcdef");
    await writeFile(join(cwd, "work", "SAM"), hive({
      name: "ROOT",
      children: [{ name: "SAM", children: [{ name: "Domains", children: [{ name: "Account", children: [{ name: "Users", children: [
        { name: "000003E9", values: [{ name: "F", type: "binary", value: Buffer.alloc(80, 1) }, { name: "V", type: "binary", value: verifier }] },
      ] }] }] }] }],
    }));
    const run = await tool("regkv", cwd, { hive: "work/SAM", key: "SAM\\Domains\\Account\\Users\\000003E9" });
    const out = body<RegkvOut>(run);
    assert.equal(run.stdout.includes(verifier.toString("hex")), false);
    assert.equal(out.values.F, Buffer.alloc(80, 1).toString("hex"), "F is account metadata, returned");
    assert.match(String(out.values.V), /^\[withheld: \d+ bytes\]$/);
    assert.deepEqual(out.sensitive_values_withheld.map((w) => w.name), ["V"]);
    // A SECURITY hive's LSA secret and a cached logon, by where they are and what they are called.
    const lsa = Buffer.from("planted-lsa-secret-material-0123456789");
    await writeFile(join(cwd, "work", "SECURITY"), hive({
      name: "ROOT",
      children: [
        { name: "Policy", children: [{ name: "Secrets", children: [{ name: "DPAPI_SYSTEM", children: [{ name: "CurrVal", values: [{ name: "", type: "binary", value: lsa }] }] }] }] },
        { name: "Cache", values: [{ name: "NL$1", type: "binary", value: lsa }, { name: "NL$Control", type: "binary", value: Buffer.alloc(4, 1) }] },
      ],
    }));
    const secrets = await tool("regkv", cwd, { hive: "work/SECURITY", key: "Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal" });
    assert.equal(secrets.stdout.includes(lsa.toString("hex")), false);
    assert.equal(body<RegkvOut>(secrets).sensitive_values_withheld.length, 1);
    const cache = await tool("regkv", cwd, { hive: "work/SECURITY", key: "Cache" });
    assert.equal(cache.stdout.includes(lsa.toString("hex")), false);
    assert.deepEqual(body<RegkvOut>(cache).sensitive_values_withheld.map((w) => w.name), ["NL$1", "NL$Control"]);
  });
});

test("regkv reports a file that is not a hive as an error with a non-zero exit, not a traceback", async () => {
  await withCwd(async (cwd) => {
    await writeFile(join(cwd, "work", "junk"), Buffer.alloc(8192, 0x41));
    const err = failed(await tool("regkv", cwd, { hive: "work/junk", key: "x" }));
    assert.match(err.error, /could not read the hive/);
  });
});

// --- evtx_query -----------------------------------------------------------------

// python-evtx on a JSON description of chunks and records, with the calls evtx_query makes of it:
// Evtx(path) as a context manager; .chunks(); chunk.offset() and chunk.records(); record.offset(), .xml()
// and .unpack_qword(0x10) (the FILETIME in the record header).
const EVTX_QUERY_STUB = String.raw`
import json


class _Rec:
    def __init__(self, spec):
        self.spec = spec

    def offset(self):
        return self.spec["offset"]

    def xml(self):
        if "xml_error" in self.spec:
            raise ValueError(self.spec["xml_error"])
        return self.spec["xml"]

    def unpack_qword(self, off):
        assert off == 0x10
        return int(self.spec["filetime"])


class _Chunk:
    def __init__(self, spec):
        self.spec = spec

    def offset(self):
        return self.spec["offset"]

    def records(self):
        def gen():
            for r in self.spec["records"]:
                if "chain_error" in r:
                    raise ValueError(r["chain_error"])
                yield _Rec(r)
        return gen()


class Evtx:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self.spec = json.load(fh)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def chunks(self):
        for c in self.spec["chunks"]:
            if "enumeration_error" in c:
                raise ValueError(c["enumeration_error"])
            yield _Chunk(c)
`;

function eventXml(o: { eid: number; rec: number; time: string; channel?: string; data?: Record<string, string> }): string {
  const data = Object.entries(o.data ?? {}).map(([k, v]) => `<Data Name="${k}">${v}</Data>`).join("");
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"></Provider><EventID>${o.eid}</EventID><TimeCreated SystemTime="${o.time}"></TimeCreated><EventRecordID>${o.rec}</EventRecordID><Channel>${o.channel ?? "Security"}</Channel><Computer>WS01</Computer></System><EventData>${data}</EventData></Event>`;
}

type EvtxRec = { offset: number; xml?: string; xml_error?: string; filetime?: string; chain_error?: string };
type EvtxSpec = { chunks: Array<{ offset: number; records: EvtxRec[]; enumeration_error?: string }> };

const goodRec = (offset: number, eid: number, rec: number, time: string, data: Record<string, string> = {}): EvtxRec => ({
  offset,
  xml: eventXml({ eid, rec, time, data }),
  filetime: "133443104001234567",
});

type EvtxQueryOut = {
  status: string;
  records_examined: number;
  events_matched: number;
  parse_errors: number;
  count: number;
  events: Array<{ event_id: number; record_id: number; record_offset: number; chunk_offset: number; timestamp: string; record_filetime: string | null; record_time_utc: string | null; data: Record<string, string>; xml?: string }>;
  errors: Array<{ parse_error: string; record_offset?: number | null; chunk_offset?: number | null }>;
  problems: string[];
  result_file: string;
};

async function evtxCase(cwd: string, spec: EvtxSpec, args: Record<string, unknown> = {}): Promise<Run> {
  const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_QUERY_STUB });
  await writeFile(join(cwd, "work", "Security.evtx"), JSON.stringify(spec), "utf8");
  return tool("evtx_query", cwd, { path: "work/Security.evtx", ...args }, env);
}

test("evtx_query counts what matched apart from what it could not read: a record that does not parse is a parse error, not a match", async () => {
  // matched += 1 ran for broken and parse-error records alike, so `count` mixed evidence with failures.
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, {
      chunks: [{ offset: 4096, records: [
        goodRec(4608, 4624, 11, "2026-09-01 10:00:00.123456", { TargetUserName: "alice" }),
        { offset: 5000, xml_error: "BinXML template could not be expanded" },
        goodRec(5400, 4625, 13, "2026-09-01 10:00:02.000000", { TargetUserName: "bob" }),
      ] }],
    }));
    assert.equal(out.records_examined, 3);
    assert.equal(out.events_matched, 2);
    assert.equal(out.parse_errors, 1);
    assert.equal(out.count, 2, "count is the events that matched");
    assert.equal(out.status, "partial");
    assert.deepEqual(out.events.map((e) => [e.event_id, e.record_id, e.record_offset, e.chunk_offset]), [[4624, 11, 4608, 4096], [4625, 13, 5400, 4096]]);
    assert.equal(out.events[0].data.TargetUserName, "alice");
    assert.equal(out.errors.length, 1);
    assert.match(out.errors[0].parse_error, /^BinXML template could not be expanded/);
    assert.equal(out.errors[0].record_offset, 5000);
    assert.equal(out.events[0].xml, undefined, "the XML is in the result file, not inline");
    const rows = (await readFile(join(cwd, out.result_file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { xml?: string; parse_error?: string; record_offset: number });
    assert.equal(rows.length, 3);
    assert.deepEqual(rows.map((r) => r.record_offset), [4608, 5000, 5400]);
    assert.ok(rows[0].xml?.includes("<EventID>4624</EventID>"));
  });
});

test("evtx_query keeps the raw FILETIME of the record header beside its time, and the SystemTime the XML carries", async () => {
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, { chunks: [{ offset: 4096, records: [goodRec(4608, 4624, 11, "2026-09-01 10:00:00.123456")] }] }));
    assert.equal(out.events[0].record_filetime, "133443104001234567");
    assert.equal(out.events[0].record_time_utc, "2023-11-13T00:53:20.1234567Z");
    assert.equal(out.events[0].timestamp, "2026-09-01 10:00:00.123456");
    assert.equal(out.status, "complete");
  });
});

test("evtx_query ends a broken record chain with a row naming its chunk and goes on to the next chunk, and says when the chunks themselves could not be enumerated", async () => {
  await withCwd(async (cwd) => {
    const out = body<EvtxQueryOut>(await evtxCase(cwd, {
      chunks: [
        { offset: 4096, records: [goodRec(4608, 4624, 1, "2026-09-01 10:00:00.000000"), { offset: 4700, chain_error: "record length points past the chunk" }] },
        { offset: 69632, records: [goodRec(70144, 4624, 5, "2026-09-01 11:00:00.000000")] },
        { offset: 135168, records: [], enumeration_error: "unexpected end of file at chunk 3" },
      ],
    }));
    assert.deepEqual(out.events.map((e) => e.record_id), [1, 5], "the chunk after the broken chain is still read");
    assert.equal(out.parse_errors, 2);
    assert.match(out.errors[0].parse_error, /record chain of this chunk broke: record length points past the chunk/);
    assert.equal(out.errors[0].chunk_offset, 4096);
    assert.match(out.errors[1].parse_error, /chunk enumeration failed after offset 69632/);
    assert.ok(out.problems.some((p) => /could not be enumerated past offset 69632/.test(p)));
    assert.equal(out.status, "partial");
  });
});

test("evtx_query filters by event id, record range and a time prefix, and validates every argument before it opens an output file", async () => {
  // The skill said events could be "filtered by id or by a time prefix", and the tool had no time filter; a `limit`
  // of 0 was found only after the result file had been created.
  await withCwd(async (cwd) => {
    const spec: EvtxSpec = { chunks: [{ offset: 4096, records: [
      goodRec(4608, 4624, 1, "2026-09-01 09:59:59.000000"),
      goodRec(5000, 4624, 2, "2026-09-01 10:00:00.500000"),
      goodRec(5400, 4672, 3, "2026-09-01 10:05:00.000000"),
      goodRec(5800, 4624, 4, "2026-09-02 08:00:00.000000"),
    ] }] };
    const day = body<EvtxQueryOut>(await evtxCase(cwd, spec, { start_time: "2026-09-01", end_time: "2026-09-01" }));
    assert.deepEqual(day.events.map((e) => e.record_id), [1, 2, 3], "a date is a prefix: the whole of 2026-09-01");
    const window = body<EvtxQueryOut>(await evtxCase(cwd, spec, { start_time: "2026-09-01T10:00", end_time: "2026-09-01T10:00", event_ids: [4624] }));
    assert.deepEqual(window.events.map((e) => e.record_id), [2]);
    const range = body<EvtxQueryOut>(await evtxCase(cwd, spec, { start_record: 3, end_record: 4 }));
    assert.deepEqual(range.events.map((e) => e.record_id), [3, 4]);
    assert.equal(range.records_examined, 4, "records outside the filters are still examined, and counted");
    const bad = failed(await evtxCase(cwd, spec, { limit: 0, out_file: "work/s1/never.jsonl" }));
    assert.match(bad.error, /limit must be a whole number of at least 1/);
    assert.equal(await exists(join(cwd, "work", "s1", "never.jsonl")), false, "no output file was made for a refused call");
    assert.match(failed(await evtxCase(cwd, spec, { event_ids: ["4624"] })).error, /event_ids must be a list of whole numbers/);
  });
});

test("evtx_query says a file it cannot open is an error, not a traceback", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": EVTX_QUERY_STUB });
    await writeFile(join(cwd, "work", "junk.evtx"), "this is not an event log");
    const err = failed(await tool("evtx_query", cwd, { path: "work/junk.evtx" }, env));
    assert.match(err.error, /could not open the event log/);
  });
});

// --- evtx_carve -----------------------------------------------------------------

// python-evtx's ChunkHeader as evtx_carve calls it: ChunkHeader(buffer, 0), .verify(), .records() yielding records with
// .offset() and .xml(). A chunk here is the magic, then a first record number (u32 at 8) and a count (u32 at 12); a
// "chunk" whose first number is 0 is not one (the constructor refuses it, as python-evtx does a chunk it cannot read).
// The record's template, from the byte at 16, picks the XML: 1 holds two <Data Name="Path"> elements.
const CARVE_STUB = String.raw`
import struct


class _Record:
    def __init__(self, number, offset, variant):
        self._number, self._offset, self._variant = number, offset, variant

    def offset(self):
        return self._offset

    def xml(self):
        data = '<Data Name="Path">C:\\first.exe</Data><Data Name="Path">C:\\second.exe</Data><Data Name="User">svc</Data>' if self._variant == 1 else '<Data Name="n">%d</Data>' % self._number
        return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                '<Provider Name="Stub"/><EventID>4688</EventID><EventRecordID>%d</EventRecordID>'
                '<Channel>Security</Channel><Computer>HOST</Computer></System>'
                '<EventData>%s</EventData></Event>' % (self._number, data))


class ChunkHeader:
    def __init__(self, buf, offset):
        self._first, self._count = struct.unpack_from("<II", buf, offset + 8)
        self._variant = buf[offset + 16]
        if self._first == 0:
            raise ValueError("bad chunk header")

    def verify(self):
        return True

    def records(self):
        for i in range(self._count):
            yield _Record(self._first + i, 0x200 + i * 0x100, self._variant)
`;

type CarveOut = {
  status: string;
  records: Array<{ record_id: number; chunk_offset: number; data?: Record<string, string | string[]>; xml?: string }>;
  record_count: number;
  candidates: number;
  chunks_parsed: number;
  sweep_complete: boolean;
  resume_start: number | null;
  range_requested: { start: number; end: number; file_bytes: number };
  range_examined: { start: number; end: number };
  problems: Array<{ offset: number; why: string }>;
  problem_count: number;
  all_problems?: string;
  all_results?: string;
};

function carveChunk(buf: Buffer, at: number, first: number, count: number, variant = 0): void {
  buf.write("ElfChnk\u0000", at, "latin1");
  buf.writeUInt32LE(first, at + 8);
  buf.writeUInt32LE(count, at + 12);
  buf[at + 16] = variant;
}

test("evtx_carve keeps a repeated EventData name as a list and the whole XML in the result file even when the result is small", async () => {
  // `data[name] = ...` overwrote the first of two <Data Name="Path"> elements, and the XML was in the file only when
  // with_xml was set or the result overflowed the page.
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": CARVE_STUB });
    const blob = Buffer.alloc(70000, 0x2e);
    carveChunk(blob, 100, 1, 2, 1);
    await writeFile(join(cwd, "work", "blob.bin"), blob);
    const out = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin" }, env));
    assert.equal(out.record_count, 2);
    assert.deepEqual(out.records[0].data, { Path: ["C:\\first.exe", "C:\\second.exe"], User: "svc" });
    assert.equal(out.records[0].xml, undefined, "the inline summary has no XML unless asked");
    assert.ok(out.all_results, "the whole result is in a file even though it fits the page");
    const rows = (await readFile(join(cwd, out.all_results as string), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { xml: string; record_id: number });
    assert.equal(rows.length, 2);
    assert.ok(rows[0].xml.includes("C:\\first.exe") && rows[0].xml.includes("C:\\second.exe"));
    const withXml = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin", with_xml: true }, env));
    assert.ok(withXml.records[0].xml?.includes("C:\\second.exe"));
  });
});

test("evtx_carve stops a sweep over thousands of false signatures at candidate_limit, names where to resume, and pages its problems", async () => {
  // chunk_limit counted chunks that were built, so a blob of magic-shaped noise that never built one was swept
  // whole, with no bound on the work and every refusal in one list.
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": CARVE_STUB });
    const blob = Buffer.alloc(10_000 * 64);
    for (let i = 0; i < 10_000; i++) blob.write("ElfChnk\u0000", i * 64, "latin1");
    carveChunk(blob, 9990 * 64, 1, 1);   // a signature near the end is a real chunk
    await writeFile(join(cwd, "work", "noise.bin"), blob);
    const first = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/noise.bin", candidate_limit: 500 }, env));
    assert.equal(first.candidates, 500);
    assert.equal(first.sweep_complete, false);
    assert.equal(first.resume_start, 500 * 64);
    assert.equal(first.status, "partial");
    assert.equal(first.problem_count, 500);
    assert.equal(first.problems.length, 40, "problems are a page");
    const spilled = (await readFile(join(cwd, first.all_problems as string), "utf8")).trimEnd().split("\n");
    assert.equal(spilled.length, 500);
    assert.deepEqual(first.range_examined, { start: 0, end: 500 * 64 });
    assert.equal(first.range_requested.end, 10_000 * 64);
    // Carrying on from resume_start reads the rest, and the real chunk at the end is found.
    const rest = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/noise.bin", start: first.resume_start as number, candidate_limit: 20000 }, env));
    assert.equal(rest.sweep_complete, true);
    assert.equal(rest.record_count, 1);
  });
});

test("evtx_carve refuses a negative or empty range and a start past the file, and says the range it was asked to sweep", async () => {
  await withCwd(async (cwd) => {
    const env = await stubModule(cwd, { "Evtx/__init__.py": "", "Evtx/Evtx.py": CARVE_STUB });
    await writeFile(join(cwd, "work", "blob.bin"), Buffer.alloc(5000, 0x2e));
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: -5 }, env)).error, /start must be a whole number of at least 0/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", max_bytes: 0 }, env)).error, /max_bytes must be a whole number of at least 1/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", limit: 0 }, env)).error, /limit must be a whole number of at least 1/);
    assert.match(failed(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: 6000 }, env)).error, /start is past the end of the file/);
    const part = body<CarveOut>(await tool("evtx_carve", cwd, { path: "work/blob.bin", start: 1000, max_bytes: 2000 }, env));
    assert.deepEqual(part.range_requested, { start: 1000, end: 3000, file_bytes: 5000 });
    assert.deepEqual(part.range_examined, { start: 1000, end: 3000 });
  });
});
