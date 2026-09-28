/**
 * Three tools folded into the library from recent runs, each made general
 * first: ledger_timeline (any run's ledger, what it leaves out chosen and
 * counted), contact_sheet (any directory, list or tar of images) and
 * nested_vdi (a VDI inside an image, located by parameters, not by one
 * case's numbers). Every fixture is built here from the documented layouts:
 * a ledger, a handful of drawn images, a FAT12 file system in a VDI whose
 * blocks are out of order, stored in four data runs of an outer volume with
 * one of them sparse. Nothing from a case is read.
 *
 * What needs a library the host may not have runs where it is: Pillow for the
 * sheets, pytsk3 for the guest's file systems, pyewf and ewfacquirestream for
 * an E01. Without them those tests are skipped and the rest still run: the
 * VDI header, its block map and the two-level read are plain Python.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { LIB, runPy, runPySnippet, withCwd } from "./tool-library-harness.ts";

type Run = { code: number | null; stdout: string; stderr: string };

const has = (code: string) => spawnSync("python3", ["-c", code], { encoding: "utf8" }).status === 0;
const HAS_PIL = has("import PIL.Image, PIL.ImageDraw");
const HAS_TSK = has("import pytsk3");
const HAS_PYEWF = has("import pyewf");
const HAS_EWF = HAS_PYEWF && spawnSync("sh", ["-c", "command -v ewfacquirestream"]).status === 0;

function ok<T>(out: Run): T {
  assert.equal(out.code, 0, out.stderr + out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as T;
}

function refused(out: Run): { error: string } & Record<string, unknown> {
  assert.notEqual(out.code, 0, out.stdout);
  assert.doesNotMatch(out.stderr, /Traceback/);
  return JSON.parse(out.stdout) as { error: string } & Record<string, unknown>;
}

async function build(code: string, ...args: string[]): Promise<string> {
  const out = await runPySnippet(code, args, null);
  assert.equal(out.code, 0, out.stderr);
  return out.stdout;
}

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

// --- ledger_timeline ---------------------------------------------------------------

const TIMELINE = join(LIB, "ledger_timeline", "run.py");

/** A ledger as the harness writes one: entries, attestations, disputes. */
async function writeLedger(cwd: string): Promise<void> {
  const e = (o: Record<string, unknown>) => ({ v: 3, by: "s01", authors: [o.by ?? "s01"], at: "2026-02-01T00:00:00Z", ...o });
  const entries = [
    e({ seq: 1, kind: "event", ts: "2026-01-10T09:00:00Z", value: "Archive tool installed", source: "Prefetch", clock: "NTFS $SI", precision: "second", hash: "h1" }),
    e({ seq: 2, kind: "event", ts: "2026-01-10T08:00:00Z", value: "User logged on | console", source: "Security.evtx 4624", by: "s02", hash: "h2" }),
    e({ seq: 3, kind: "ioc", value: "198.51.100.7", hash: "h3" }),
    e({ seq: 4, kind: "event", ts: "2026-01-10T09:30:00Z", value: "Copy at the wrong time", by: "s03", hash: "h4" }),
    e({ seq: 5, kind: "event", ts: "2026-01-10T09:31:00Z", value: "Files copied to a removable drive", supersedes: 4, because: "clock offset", by: "s03", hash: "h5" }),
    e({ seq: 6, kind: "event", ts: "2026-01-10T08:00:00Z", value: "The same logon in another log", rel: [{ to: 2, kind: "duplicates" }], by: "s04", hash: "h6" }),
    e({ seq: 7, kind: "event", ts: "2026-01-11T00:00:00Z", ts_raw: "2026-01-11", precision: "date", value: "The account's password is written in a note", sensitive: true, by: "s02", hash: "h7" }),
    e({ seq: 8, kind: "finding", value: "Data left by USB", hash: "h8" }),
    e({ seq: 9, kind: "event", ts: "2026-01-09T21:00:00Z", ts_raw: "2026-01-10T00:00:00+03:00", value: "Mail with the token abc-SECRET-123 received", by: "s05", hash: "h9" }),
    e({ seq: 10, kind: "hypothesis", ts: "2026-01-10T10:00:00Z", value: "A second drive was used", status: "open", by: "s05", hash: "h10" }),
  ];
  await mkdir(join(cwd, "ledger"), { recursive: true });
  // A torn last line: counted and named, never a traceback.
  await writeFile(join(cwd, "ledger", "entries.jsonl"), `${entries.map((x) => JSON.stringify(x)).join("\n")}\n{"torn\n`);
  await writeFile(
    join(cwd, "ledger", "attestations.jsonl"),
    [{ seq: 1, by: "s06", at: "x" }, { v: 2, act: "attest", seq: 1, target: "h5", by: "s07", at: "x" }].map((x) => JSON.stringify(x)).join("\n") + "\n",
  );
  await writeFile(
    join(cwd, "ledger", "disputes.jsonl"),
    [
      { v: 1, act: "dispute", seq: 1, target: "h1", by: "s08", at: "x", why: "the prefetch is from another host" },
      { v: 1, act: "dispute", seq: 2, target: "h2", by: "s09", at: "x", why: "unsure" },
      { v: 1, act: "withdraw", seq: 3, target: "h2", by: "s09", at: "x", why: "resolved" },
    ].map((x) => JSON.stringify(x)).join("\n") + "\n",
  );
}

test("ledger_timeline writes the standing dated entries in time order, and counts each one it leaves out", async () => {
  await withCwd(async (cwd) => {
    await writeLedger(cwd);
    type Body = { rows: number; entries_read: number; left_out: Record<string, number>; sensitive_withheld: number; sha256: string; unreadable_lines: { entries: number[] }; first: string; last: string };
    const out = ok<Body>(
      await runPy(TIMELINE, cwd, {
        output: "work/s01/timeline.md",
        redact: ["abc-[A-Z]+-\\d+"],
        columns: ["time", "event", "clock", "by", "entry"],
        title: "Copy timeline",
        note: "All times UTC.",
      }),
    );
    assert.equal(out.entries_read, 10);
    assert.equal(out.rows, 5);
    assert.deepEqual(out.left_out, { not_asked_kind: 3, undated: 0, superseded: 1, duplicate: 1, excluded: 0, outside_range: 0, not_matched: 0, sensitive: 0 });
    assert.equal(out.sensitive_withheld, 1);
    assert.deepEqual(out.unreadable_lines.entries, [11], "the torn line is named by its number");
    const md = await readFile(join(cwd, "work", "s01", "timeline.md"), "utf8");
    assert.equal(sha256(md), out.sha256, "the answer hashes the file it wrote");
    assert.match(md, /^# Copy timeline\n\nAll times UTC\.\n/);
    const rows = md.split("\n").filter((l) => /^\| .*\[E-\d+\]/.test(l));
    assert.deepEqual(rows.map((l) => /\[E-(\d+)\]/.exec(l)![1]), ["9", "2", "1", "5", "7"], "in time order, the correction in place of what it corrects");
    assert.match(rows[0], /^\| 2026-01-09T21:00:00Z \(as written: 2026-01-10T00:00:00\+03:00\) \| Mail with the token \[withheld\] received \|/);
    assert.match(rows[1], /User logged on \\\| console/, "a pipe in a value does not break the table");
    assert.doesNotMatch(rows[1], /disputed/, "a withdrawn dispute is not shown");
    assert.match(rows[2], /Archive tool installed \(disputed by s08: the prefetch is from another host\) \| NTFS \$SI \| s01, s06 \|/);
    assert.match(rows[3], /corrects E-4: clock offset; attested by s07/);
    assert.match(rows[4], /^\| 2026-01-11 \| \[sensitive: withheld; see E-7 in the ledger\] \|/, "a date alone stays a date, and a sensitive entry keeps its number only");
    assert.doesNotMatch(md, /password|SECRET/);
    assert.match(rows[0], /\(\.\.\/\.\.\/ledger\/ledger\.md\)/, "E-n links to the rendered ledger, relative to the output");
  });
});

test("ledger_timeline takes the kinds, range, exclusions and format it is given, and writes nowhere the harness owns", async () => {
  await withCwd(async (cwd) => {
    await writeLedger(cwd);
    type Body = { rows: number; left_out: Record<string, number>; format: string };
    const csv = ok<Body>(
      await runPy(TIMELINE, cwd, {
        output: "work/s01/t.csv",
        kinds: ["event", "hypothesis"],
        include_superseded: true,
        keep_duplicates: true,
        sensitive: "keep",
        since: "2026-01-10",
        until: "2026-01-10T09:30:00",
        columns: ["entry", "time", "event"],
      }),
    );
    assert.equal(csv.format, "csv");
    const lines = (await readFile(join(cwd, "work", "s01", "t.csv"), "utf8")).trimEnd().split("\n");
    assert.deepEqual(lines, [
      "entry,time,event",
      "E-2,2026-01-10T08:00:00Z,User logged on | console",
      "E-6,2026-01-10T08:00:00Z,The same logon in another log (duplicates E-2)",
      "E-1,2026-01-10T09:00:00Z,Archive tool installed (disputed by s08: the prefetch is from another host)",
      "E-4,2026-01-10T09:30:00Z,Copy at the wrong time (superseded by E-5)",
    ]);
    assert.equal(csv.left_out.outside_range, 4, "until is inclusive at the precision given; the rest is counted");

    const narrowed = ok<Body>(await runPy(TIMELINE, cwd, { output: "work/s01/n.jsonl", exclude: ["#2", 9], match: "copied|logon|installed" }));
    assert.equal(narrowed.format, "jsonl");
    const kept = (await readFile(join(cwd, "work", "s01", "n.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as { entry: string; marks: string[] });
    assert.deepEqual(kept.map((r) => r.entry), ["E-1", "E-5"]);
    assert.deepEqual(narrowed.left_out, { not_asked_kind: 3, undated: 0, superseded: 1, duplicate: 1, excluded: 2, outside_range: 0, not_matched: 1, sensitive: 0 });

    const dropped = ok<Body>(await runPy(TIMELINE, cwd, { output: "work/s01/d.md", sensitive: "drop" }));
    assert.equal(dropped.left_out.sensitive, 1);

    for (const output of ["ledger/timeline.md", "inputs/timeline.md", "tools/x/timeline.md", "../elsewhere.md"]) {
      assert.match(refused(await runPy(TIMELINE, cwd, { output })).error, /cannot be under|inside the run directory/, output);
    }
    assert.match(refused(await runPy(TIMELINE, cwd, { output: "work/a.md", match: "(unclosed" })).error, /not a valid regex/);
    assert.match(refused(await runPy(TIMELINE, cwd, { output: "work/a.md", kinds: ["events"] })).error, /unknown kinds/);
    assert.match(refused(await runPy(TIMELINE, cwd, { output: "work/a.md", columns: ["when"] })).error, /unknown columns/);
    assert.match(refused(await runPy(TIMELINE, cwd, { output: "work/a.md", since: "last week" })).error, /ISO 8601/);
    assert.match(refused(await runPy(TIMELINE, cwd, { output: "work/a.md", ledger: "work/none.jsonl" })).error, /no ledger at work\/none\.jsonl/);
  });
});

// --- contact_sheet -----------------------------------------------------------------

const SHEET = join(LIB, "contact_sheet", "run.py");

/** Seven drawn JPEGs, an exact copy, a re-encoded PNG of one, a transparent PNG, a broken JPEG, an empty file and a text file. */
const IMAGES = String.raw`
import os, shutil, sys, tarfile
from PIL import Image, ImageDraw
root = sys.argv[1]
os.makedirs(os.path.join(root, "a"), exist_ok=True)
os.makedirs(os.path.join(root, "b"), exist_ok=True)
for i in range(7):
    im = Image.new("RGB", (300 + i * 10, 200), (i * 35, 255 - i * 30, (i * 70) % 256))
    ImageDraw.Draw(im).ellipse([20 + i * 10, 20, 120 + i * 10, 150], fill=(255, 255, 0))
    im.save(os.path.join(root, "a", "img%02d.jpg" % i), quality=92)
shutil.copy(os.path.join(root, "a", "img03.jpg"), os.path.join(root, "b", "copy_of_03.jpg"))
Image.open(os.path.join(root, "a", "img05.jpg")).save(os.path.join(root, "b", "img05_again.png"))
rgba = Image.new("RGBA", (120, 80), (255, 0, 0, 0))
ImageDraw.Draw(rgba).rectangle([10, 10, 60, 60], fill=(0, 0, 255, 255))
rgba.save(os.path.join(root, "b", "transparent.png"))
open(os.path.join(root, "b", "broken.jpg"), "wb").write(b"\xff\xd8\xff\xe0 not really a jpeg")
open(os.path.join(root, "b", "empty.png"), "wb").write(b"")
open(os.path.join(root, "b", "notes.txt"), "w").write("not an image")
with tarfile.open(sys.argv[2], "w") as tf:
    tf.add(root, arcname="pics")
`;

type Sheet = { sheet: number; file: string; sha256: string; tiles: number; first_n: number; last_n: number };
type SheetBody = { complete: boolean; candidates: number; counts: Record<string, number>; distinct_tiled: number; sheets: Sheet[]; index: string; manifest: string; processed?: number; again?: boolean; labels_note?: string };

test("contact_sheet says Pillow is missing instead of failing on an import", async () => {
  await withCwd(async (cwd) => {
    // A PIL that cannot be imported, ahead of any real one.
    await mkdir(join(cwd, "stub", "PIL"), { recursive: true });
    await writeFile(join(cwd, "stub", "PIL", "__init__.py"), "raise ImportError('no PIL here')\n");
    await mkdir(join(cwd, "work", "pics"), { recursive: true });
    const out = refused(await runPy(SHEET, cwd, { input: "work/pics", out_dir: "work/s01/cs" }, undefined, { PYTHONPATH: join(cwd, "stub") }));
    assert.match(out.error, /^Pillow is not installed$/);
  });
});

test("contact_sheet tiles each distinct image once, lists every file, and keeps the whole label in the index", { skip: HAS_PIL ? false : "Pillow is not installed here" }, async () => {
  await withCwd(async (cwd) => {
    await build(IMAGES, join(cwd, "work", "pics"), join(cwd, "work", "pics.tar"));
    const out = ok<SheetBody>(await runPy(SHEET, cwd, { input: "work/pics", out_dir: "work/s01/cs", columns: 3, rows: 2, tile: 96, label: "{n:03d} {name} {w}x{h} {sha8}" }));
    assert.equal(out.complete, true);
    assert.equal(out.candidates, 12, "notes.txt is not an image by its name; every other file is looked at");
    assert.deepEqual(out.counts, { decoded_unique: 9, empty: 1, exact_duplicate: 1, undecodable: 1 });
    assert.deepEqual(out.sheets.map((s) => [s.sheet, s.tiles, s.first_n, s.last_n]), [[1, 6, 1, 6], [2, 3, 7, 9]]);
    for (const s of out.sheets) assert.equal(sha256(await readFile(join(cwd, s.file))), s.sha256);
    assert.equal((await readdir(join(cwd, "work", "s01", "cs", "tiles"))).length, 9);
    const manifest = (await readFile(join(cwd, out.manifest), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(manifest.length, 12, "one row per file looked at");
    const copy = manifest.find((r) => r.path === "work/pics/b/copy_of_03.jpg")!;
    assert.deepEqual([copy.status, copy.duplicate_of, copy.duplicate_of_n], ["exact_duplicate", "work/pics/a/img03.jpg", 4]);
    assert.match(String(manifest.find((r) => r.path === "work/pics/b/broken.jpg")!.error), /UnidentifiedImageError|cannot identify|truncated/i);
    const index = (await readFile(join(cwd, out.index), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(index.length, 9);
    const four = index.find((r) => r.n === 4)!;
    assert.deepEqual([four.sheet, four.tile, four.row, four.col, four.path, four.duplicates], [1, 4, 2, 1, "work/pics/a/img03.jpg", 1]);
    assert.match(String(four.label), /^004 img03\.jpg 330x200 [0-9a-f]{8}$/);

    // The same call again is answered from what is there.
    const again = ok<SheetBody>(await runPy(SHEET, cwd, { input: "work/pics", out_dir: "work/s01/cs", columns: 3, rows: 2, tile: 96, label: "{n:03d} {name} {w}x{h} {sha8}" }));
    assert.equal(again.again, true);
    assert.deepEqual(again.sheets, out.sheets);

    // Look-alikes: the PNG made from one of the JPEGs is folded into it.
    const look = ok<SheetBody>(await runPy(SHEET, cwd, { input: "work/pics", out_dir: "work/s01/cs-look", dedup: "ahash" }));
    assert.deepEqual(look.counts, { decoded_unique: 8, empty: 1, exact_duplicate: 1, looks_duplicate: 1, undecodable: 1 });
    const every = ok<SheetBody>(await runPy(SHEET, cwd, { input: "work/pics", out_dir: "work/s01/cs-all", dedup: "none" }));
    assert.equal(every.distinct_tiled, 10);

    // A tar is read in place: its members are tiled and nothing is unpacked.
    const tar = ok<SheetBody & { source: string }>(await runPy(SHEET, cwd, { archive: "work/pics.tar", out_dir: "work/s01/cs-tar" }));
    assert.equal(tar.source, "archive");
    assert.deepEqual(tar.counts, out.counts);
    assert.deepEqual((await readdir(join(cwd, "work"))).sort(), ["pics", "pics.tar", "s01"]);

    // A list is taken as given, a missing path listed as unreadable.
    await writeFile(join(cwd, "work", "list.txt"), "work/pics/a/img00.jpg\nwork/pics/a/nothere.jpg\nwork/pics/a/img00.jpg\n");
    const listed = ok<SheetBody>(await runPy(SHEET, cwd, { list_file: "work/list.txt", out_dir: "work/s01/cs-list" }));
    assert.deepEqual(listed.counts, { decoded_unique: 1, exact_duplicate: 1, unreadable: 1 });
  });
});

test("contact_sheet carries on over several calls to the same sheets, and refuses what it cannot do", { skip: HAS_PIL ? false : "Pillow is not installed here" }, async () => {
  await withCwd(async (cwd) => {
    await build(IMAGES, join(cwd, "work", "pics"), join(cwd, "work", "pics.tar"));
    const args = { input: "work/pics", columns: 2, rows: 2, tile: 64 };
    const whole = ok<SheetBody>(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/one" }));
    // budget_seconds 0: one file per call, each call keeping what it did.
    let last: SheetBody | undefined;
    let calls = 0;
    do {
      last = ok<SheetBody>(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/many", budget_seconds: 0 }));
      calls += 1;
      if (!last.complete) assert.equal(last.processed, calls);
    } while (!last.complete && calls < 50);
    assert.equal(calls, 12, "one call per file; the last one also makes the sheets");
    assert.deepEqual(last.sheets.map((s) => s.sha256), whole.sheets.map((s) => s.sha256), "the same sheets as one call makes");
    assert.equal(
      await readFile(join(cwd, "work", "s01", "many", "index.jsonl"), "utf8"),
      (await readFile(join(cwd, "work", "s01", "one", "index.jsonl"), "utf8")),
    );

    assert.match(refused(await runPy(SHEET, cwd, { ...args, tile: 96, out_dir: "work/s01/many" })).error, /other arguments/);
    await mkdir(join(cwd, "work", "s01", "busy"), { recursive: true });
    await writeFile(join(cwd, "work", "s01", "busy", "x.txt"), "someone else's");
    assert.match(refused(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/busy" })).error, /not this tool's work/);
    assert.match(refused(await runPy(SHEET, cwd, { ...args, out_dir: "inputs/cs" })).error, /cannot be under inputs/);
    assert.match(refused(await runPy(SHEET, cwd, { input: "work/pics", archive: "work/pics.tar", out_dir: "work/s01/x" })).error, /exactly one of/);
    const attr = refused(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/y", label: "{name.__class__}" }));
    assert.match(attr.error, /only these fields/);
    assert.match(refused(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/z", label: "{name:d}" })).error, /does not format/);
    assert.match(refused(await runPy(SHEET, cwd, { ...args, out_dir: "work/s01/w", tile: 8 })).error, /tile must be a whole number from 32/);
  });
});

// --- nested_vdi --------------------------------------------------------------------

const VDI = join(LIB, "nested_vdi", "run.py");

/**
 * The guest: an MBR and one FAT12 partition at sector 64 (HELLO.TXT over six
 * clusters, DOCS/NOTE.TXT), and a patterned block outside it. The VDI: 16
 * blocks of 256 KiB with 32 bytes of extra data each, blocks 0-4 and 10
 * allocated in shuffled slots, the rest free or zero. The outer image: a
 * volume at sector 128 with 4096-byte clusters holding the VDI in four runs
 * out of order, the second sparse; every other byte is 0x5A, so a wrong
 * mapping reads as garbage, not as zeros. Also the same VDI contiguous at
 * byte 8192 of a volume at sector 63, with no runs.
 */
const VDI_FIXTURE = String.raw`
import hashlib, json, os, struct, sys
out = sys.argv[1]
S = 512

def fat12(hidden):
    total, reserved, nfats, root_entries, fatsz = 2048, 1, 2, 512, 6
    boot = bytearray(S)
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, S, 1, reserved, nfats, root_entries, total, 0xF8, fatsz, 32, 2, hidden, 0)
    boot[36], boot[38] = 0x80, 0x29
    struct.pack_into("<I", boot, 39, 0x1234ABCD)
    boot[43:54] = b"SYNTHETIC  "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xAA"
    fat = bytearray(fatsz * S)
    def link(n, v):
        o = n * 3 // 2
        if n % 2 == 0:
            fat[o] = v & 0xFF
            fat[o + 1] = (fat[o + 1] & 0xF0) | ((v >> 8) & 0x0F)
        else:
            fat[o] = (fat[o] & 0x0F) | ((v & 0x0F) << 4)
            fat[o + 1] = (v >> 4) & 0xFF
    link(0, 0xFF8)
    link(1, 0xFFF)
    date = ((2024 - 1980) << 9) | (3 << 5) | 1
    hms = (10 << 11) | (20 << 5) | (30 // 2)
    def entry(name, attr, cluster, size):
        e = bytearray(32)
        e[0:11] = name
        e[11] = attr
        struct.pack_into("<HHH", e, 14, hms, date, date)
        struct.pack_into("<HHHI", e, 22, hms, date, cluster, size)
        return bytes(e)
    hello = b"".join(b"line %04d of a synthetic text file\n" % i for i in range(90))[:3000]
    note = b"a note in a subdirectory\n" * 4
    data_start = reserved + nfats * fatsz + root_entries * 32 // S
    fs = bytearray(total * S)
    fs[0:S] = boot
    root = entry(b"SYNTHETIC  ", 0x08, 0, 0) + entry(b"HELLO   TXT", 0x20, 2, len(hello)) + entry(b"DOCS       ", 0x10, 8, 0)
    for c in range(2, 7):
        link(c, c + 1)
    for c in (7, 8, 9):
        link(c, 0xFFF)
    for k in range(nfats):
        o = (reserved + k * fatsz) * S
        fs[o:o + len(fat)] = fat
    o = (reserved + nfats * fatsz) * S
    fs[o:o + len(root)] = root
    cl = lambda n: (data_start + n - 2) * S
    fs[cl(2):cl(2) + len(hello)] = hello
    sub = entry(b".          ", 0x10, 8, 0) + entry(b"..         ", 0x10, 0, 0) + entry(b"NOTE    TXT", 0x20, 9, len(note))
    fs[cl(8):cl(8) + len(sub)] = sub
    fs[cl(9):cl(9) + len(note)] = note
    return bytes(fs), hello, note

BLOCK, EXTRA, BLOCKS = 256 * 1024, 32, 16
guest = bytearray(BLOCKS * BLOCK)
fs, hello, note = fat12(64)
guest[64 * S:64 * S + len(fs)] = fs
struct.pack_into("<B3sB3sII", guest, 446, 0, b"\0\0\0", 0x01, b"\0\0\0", 64, 2048)
guest[510:512] = b"\x55\xAA"
guest[10 * BLOCK:11 * BLOCK] = bytes((i * 7 + 3) & 0xFF for i in range(BLOCK))
slots = {0: 3, 1: 0, 2: 4, 3: 1, 4: 2, 10: 5}
bmap = []
for b in range(BLOCKS):
    if b in slots:
        bmap.append(slots[b])
    else:
        assert not any(guest[b * BLOCK:(b + 1) * BLOCK])
        bmap.append(0xFFFFFFFF if b % 2 else 0xFFFFFFFE)
header = bytearray(0x200)
header[0:40] = b"<<< Oracle VM VirtualBox Disk Image >>>\n"
struct.pack_into("<IIIII", header, 0x40, 0xBEDA107F, 0x00010001, 0x190, 1, 0)
header[0x54:0x54 + 17] = b"synthetic fixture"
struct.pack_into("<II", header, 0x154, 0x200, 0x400)
struct.pack_into("<IIII", header, 0x15C, 0, 0, 0, 512)
struct.pack_into("<Q", header, 0x170, len(guest))
struct.pack_into("<IIII", header, 0x178, BLOCK, EXTRA, BLOCKS, len(slots))
header[0x188:0x198] = bytes(range(16))
vdi = bytearray(0x400 + len(slots) * (EXTRA + BLOCK))
vdi[0:0x200] = header
struct.pack_into("<%dI" % BLOCKS, vdi, 0x200, *bmap)
for b, s in slots.items():
    o = 0x400 + s * (EXTRA + BLOCK)
    vdi[o:o + EXTRA] = b"\xEE" * EXTRA
    vdi[o + EXTRA:o + EXTRA + BLOCK] = guest[b * BLOCK:(b + 1) * BLOCK]
CS, VOL = 4096, 128
nclusters = -(-len(vdi) // CS)
runs = [[400, 70], [None, 50], [20, 150], [700, nclusters - 270]]
padded = bytes(vdi) + bytes(nclusters * CS - len(vdi))
assert not any(padded[70 * CS:120 * CS]), "the sparse run must cover zeros"
outer = bytearray(b"\x5A" * (VOL * S + 800 * CS))
vcn = 0
for lcn, n in runs:
    if lcn is not None:
        outer[VOL * S + lcn * CS:VOL * S + (lcn + n) * CS] = padded[vcn * CS:(vcn + n) * CS]
    vcn += n
open(os.path.join(out, "outer.raw"), "wb").write(outer)
open(os.path.join(out, "runs.json"), "w").write(json.dumps({"runs": runs}))
open(os.path.join(out, "runs.txt"), "w").write("# lcn clusters\n" + "".join("%s %d\n" % ("sparse" if l is None else l, n) for l, n in runs))
open(os.path.join(out, "runs-short.json"), "w").write(json.dumps(runs[:3]))
flat = bytearray(b"\x5A" * (63 * S + 8192 + len(vdi) + 4096))
flat[63 * S + 8192:63 * S + 8192 + len(vdi)] = vdi
open(os.path.join(out, "flat.raw"), "wb").write(flat)
diff = bytearray(outer)
struct.pack_into("<I", diff, VOL * S + 400 * CS + 0x4C, 4)
open(os.path.join(out, "diff.raw"), "wb").write(diff)
open(os.path.join(out, "guest.bin"), "wb").write(guest)
print(json.dumps({"hello_sha256": hashlib.sha256(hello).hexdigest(), "note": note.decode(), "clusters": nclusters}))
`;

type Where = { image_format: string; volume_offset_bytes: number; host: Record<string, unknown>; vdi_offset: number };
type Info = Where & { vdi: Record<string, unknown>; partitions?: Array<Record<string, unknown>>; partitions_error?: string; warning?: string };
type ReadBody = Where & { sha256: string; hex?: string; zeros_from_unallocated_blocks: number; zeros_from_sparse_runs: number };
type Fixture = { hello_sha256: string; note: string; clusters: number };

async function vdiFixture(cwd: string): Promise<Fixture> {
  return JSON.parse(await build(VDI_FIXTURE, join(cwd, "inputs"))) as Fixture;
}

const IN_RUNS = { image: "inputs/outer.raw", offset: 128, runs_file: "inputs/runs.json" };

test("nested_vdi reads a VDI through its data runs and its block map, and says what it cannot", async () => {
  await withCwd(async (cwd) => {
    const fx = await vdiFixture(cwd);
    const guest = await readFile(join(cwd, "inputs", "guest.bin"));
    const info = ok<Info>(await runPy(VDI, cwd, IN_RUNS));
    assert.equal(info.image_format, "raw");
    assert.deepEqual(info.host, { kind: "data runs", runs: 4, cluster_size: 4096, clusters: fx.clusters, sparse_clusters: 50, bytes: fx.clusters * 4096 });
    assert.deepEqual(
      Object.fromEntries(["version", "image_type", "disk_size", "block_size", "block_extra", "blocks", "allocated_in_header", "allocated_in_map", "free", "zero", "past_end_of_host", "offset_block_map", "offset_data", "uuid"].map((k) => [k, info.vdi[k]])),
      { version: "1.1", image_type: "dynamic", disk_size: 4194304, block_size: 262144, block_extra: 32, blocks: 16, allocated_in_header: 6, allocated_in_map: 6, free: 6, zero: 4, past_end_of_host: 0, offset_block_map: 512, offset_data: 1024, uuid: "03020100-0504-0706-0809-0a0b0c0d0e0f" },
    );
    if (HAS_TSK) {
      const fat = info.partitions!.filter((p) => p.file_system);
      assert.deepEqual(fat.map((p) => [p.start, p.length, p.file_system]), [[64, 2048, "FAT12"]]);
    } else {
      assert.match(info.partitions_error ?? "", /pytsk3 is not installed/);
    }

    // Guest bytes across the end of block 0 (slot 3) into block 1 (slot 0).
    const at = 262144 - 100;
    const across = ok<ReadBody>(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", at, length: 300 }));
    assert.equal(across.hex, guest.subarray(at, at + 300).toString("hex"));
    const pattern = ok<ReadBody>(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", at: 10 * 262144 + 5, length: 16 }));
    assert.equal(pattern.hex, guest.subarray(10 * 262144 + 5, 10 * 262144 + 21).toString("hex"));

    // The whole guest disk, written out on request only, is the disk.
    const all = ok<ReadBody & { output: string }>(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", length: guest.length, output: "work/s01/guest.img" }));
    assert.equal(all.sha256, sha256(guest));
    assert.equal(sha256(await readFile(join(cwd, "work", "s01", "guest.img"))), sha256(guest));
    assert.equal(all.zeros_from_unallocated_blocks, 10 * 262144, "the ten blocks that are not allocated read as zeros, and are counted");
    assert.equal(all.zeros_from_sparse_runs, 50 * 4096);

    // The runs as text lines read the same; the same VDI with no runs, at an offset in a volume, too.
    const text = ok<ReadBody>(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 128, runs_file: "inputs/runs.txt", action: "read", at, length: 300 }));
    assert.equal(text.hex, across.hex);
    const inline = ok<ReadBody>(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 128, runs: [[400, 70], ["sparse", 50], { lcn: 20, clusters: 150 }, [700, fx.clusters - 270]], action: "read", at, length: 300 }));
    assert.equal(inline.hex, across.hex);
    const flat = ok<Info>(await runPy(VDI, cwd, { image: "inputs/flat.raw", offset: 63, vdi_offset: 8192 }));
    assert.deepEqual(flat.host, { kind: "contiguous in the volume", bytes: 1618624 - 63 * 512 });
    assert.equal(flat.vdi.allocated_in_map, 6);
    const flatAll = ok<ReadBody>(await runPy(VDI, cwd, { image: "inputs/flat.raw", offset: 63, vdi_offset: 8192, action: "read", length: guest.length, output: "work/s01/flat.img" }));
    assert.equal(flatAll.sha256, sha256(guest));

    // Wrong numbers are said as wrong, with what was found instead.
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 128, runs_file: "inputs/runs.json", vdi_offset: 512 })).error, /no VDI header at vdi_offset 512: the signature at \+0x40 is/);
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 0 })).error, /no VDI header at vdi_offset 0/);
    const short = ok<Info>(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 128, runs_file: "inputs/runs-short.json" }));
    assert.equal(short.vdi.past_end_of_host, 2, "the blocks stored past the runs given are counted");
    assert.match(short.warning ?? "", /2 allocated blocks lie past the end/);
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/outer.raw", offset: 128, runs_file: "inputs/runs-short.json", action: "read", at: 10 * 262144, length: 16 })).error, /past the \d+ bytes the data runs give/);
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/diff.raw", offset: 128, runs_file: "inputs/runs.json" })).error, /a differencing VDI: its unallocated blocks are in its parent/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, runs: [[400, 0]], runs_file: undefined })).error, /run 0 is not an lcn/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, runs: [[1_000_000, 70]], runs_file: undefined })).error, /could not be read: run 0 \(lcn 1000000, 70 clusters\) reaches past the end of the image/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", length: 8192 })).error, /more than 4096 bytes go to a file/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", length: 16, output: "inputs/x.bin" })).error, /cannot be under inputs/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "read", at: guest.length - 8, length: 16 })).error, /past the 4194304-byte guest disk/);
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/nothere.E01" })).error, /image not found: inputs\/nothere\.E01/);
    // An EWF signature on something that is not an E01: said as either, never a traceback.
    await writeFile(join(cwd, "inputs", "fake.E01"), Buffer.concat([Buffer.from("EVF\x09\x0d\x0a\xff\x00", "latin1"), Buffer.alloc(64)]));
    assert.match(refused(await runPy(VDI, cwd, { image: "inputs/fake.E01" })).error, HAS_PYEWF ? /^libewf could not open inputs\/fake\.E01/ : /^pyewf is not installed$/);
    if (!HAS_TSK) assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "ls" })).error, /^pytsk3 is not installed$/);
  });
});

test("nested_vdi lists and extracts the guest's files through both levels", { skip: HAS_TSK ? false : "pytsk3 is not installed here" }, async () => {
  await withCwd(async (cwd) => {
    const fx = await vdiFixture(cwd);
    type Entry = { path: string; type: string; inode: number; size: number; allocated: boolean; mtime: string | null };
    type Ls = { matched: number; returned: number; truncated: boolean; all_results?: string; entries: Entry[]; partition: Record<string, unknown> };
    const root = ok<Ls>(await runPy(VDI, cwd, { ...IN_RUNS, action: "ls" }));
    assert.equal(root.partition.file_system, "FAT12");
    const hello = root.entries.find((e) => e.path === "/HELLO.TXT")!;
    assert.deepEqual([hello.type, hello.size, hello.allocated, hello.mtime], ["file", 3000, true, "2024-03-01T10:20:30Z"]);
    assert.equal(root.entries.find((e) => e.path === "/DOCS")!.type, "dir");

    // Recursive, one entry a page: every entry is kept in the file it names.
    const deep = ok<Ls>(await runPy(VDI, cwd, { ...IN_RUNS, action: "ls", recursive: true, limit: 1 }, undefined, { AGENT_ID: "s01" }));
    assert.equal(deep.returned, 1);
    assert.equal(deep.truncated, true);
    assert.match(deep.all_results ?? "", /^work\/s01\/tool-output\/nested_vdi-[0-9a-f]{16}\.jsonl$/);
    const every = (await readFile(join(cwd, deep.all_results!), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l) as Entry);
    assert.equal(every.length, deep.matched);
    assert.ok(every.some((e) => e.path === "/DOCS/NOTE.TXT" && e.size === 100));

    const note = ok<{ sha256: string; size: number }>(await runPy(VDI, cwd, { ...IN_RUNS, action: "extract", path: "/DOCS/NOTE.TXT", output: "work/s01/note.txt" }));
    assert.equal(await readFile(join(cwd, "work", "s01", "note.txt"), "utf8"), fx.note);
    assert.equal(note.size, 100);
    const byInode = ok<{ sha256: string }>(await runPy(VDI, cwd, { ...IN_RUNS, action: "extract", inode: hello.inode, output: "work/s01/hello.txt" }));
    assert.equal(byInode.sha256, fx.hello_sha256, "a file over six clusters, read across the shuffled blocks");
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "extract", path: "/DOCS", output: "work/s01/d" })).error, /is a directory/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "extract", path: "/NOPE.TXT", output: "work/s01/n" })).error, /cannot open \/NOPE\.TXT/);
    assert.match(refused(await runPy(VDI, cwd, { ...IN_RUNS, action: "ls", partition: 2112 })).error, /no file system at partition 2112/);
  });
});

test("nested_vdi reads the outer image as an E01", { skip: HAS_EWF && HAS_TSK ? false : "pyewf, pytsk3 or ewfacquirestream is not here" }, async () => {
  await withCwd(async (cwd) => {
    const fx = await vdiFixture(cwd);
    const made = spawnSync("sh", ["-c", `ewfacquirestream -q -t "${join(cwd, "inputs", "outer")}" < "${join(cwd, "inputs", "outer.raw")}"`], { encoding: "utf8" });
    assert.equal(made.status, 0, made.stderr);
    const e01 = { image: "inputs/outer.E01", offset: 128, runs_file: "inputs/runs.json" };
    const info = ok<Info>(await runPy(VDI, cwd, e01));
    assert.equal(info.image_format, "ewf");
    const all = ok<ReadBody>(await runPy(VDI, cwd, { ...e01, action: "read", length: 4194304, output: "work/s01/guest.img" }));
    assert.equal(all.sha256, sha256(await readFile(join(cwd, "inputs", "guest.bin"))));
    const hello = ok<{ sha256: string }>(await runPy(VDI, cwd, { ...e01, action: "extract", path: "/HELLO.TXT", output: "work/s01/hello.txt" }));
    assert.equal(hello.sha256, fx.hello_sha256);
  });
});
