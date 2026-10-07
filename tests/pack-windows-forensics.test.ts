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
