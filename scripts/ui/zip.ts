/**
 * A run's package as one zip the examiner downloads: `swarm.sh package`
 * writes a directory (`<sandbox>/package`, MANIFEST.txt with every file's
 * sha256, and the signature when it was signed), and `swarm.sh verify`
 * takes that directory or a zip of it. The console zips the directory as it
 * is, into its own temp directory, and serves that file.
 *
 * What goes in is what a handover should hold and nothing it should not:
 * regular files only, each opened without following a link; a link, a FIFO
 * or a device in the package is left out and named, never read through.
 * Nothing is cut: a file past what a plain zip can hold (4 GiB, 65,535
 * entries) refuses the zip and says so, and the directory stays the thing
 * to hand over.
 */
import { createHash } from "node:crypto";
import { lstat, open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";
import { openRegular } from "../regular-file.ts";

export type ZipResult = { files: number; bytes: number; left_out: Array<{ path: string; why: string }> };

const ZIP_MAX = 0xffffffff;
const ENTRIES_MAX = 0xffff;

function dosTime(d: Date): { time: number; date: number } {
  const year = Math.max(1980, d.getFullYear());
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

async function walk(root: string, rel: string, out: string[], leftOut: ZipResult["left_out"]): Promise<void> {
  for (const name of (await readdir(join(root, rel))).sort()) {
    const r = rel ? `${rel}/${name}` : name;
    const st = await lstat(join(root, r));
    if (st.isSymbolicLink()) leftOut.push({ path: r, why: "a link" });
    else if (st.isDirectory()) await walk(root, r, out, leftOut);
    else if (st.isFile()) out.push(r);
    else leftOut.push({ path: r, why: "not a regular file" });
  }
}

/** Zip `dir` into `outFile`, every entry under `prefix/`. Throws when the package is past a plain zip's limits. */
export async function zipDirectory(dir: string, outFile: string, prefix: string): Promise<ZipResult> {
  const top = await lstat(dir);
  if (top.isSymbolicLink() || !top.isDirectory()) throw new Error(`${dir} is not a directory`);
  const files: string[] = [];
  const leftOut: ZipResult["left_out"] = [];
  await walk(dir, "", files, leftOut);
  if (files.length > ENTRIES_MAX) throw new Error(`the package has ${files.length} files, more than a plain zip holds (${ENTRIES_MAX}); hand over the directory`);
  const out = await open(outFile, "wx", 0o600);
  const central: Buffer[] = [];
  let offset = 0;
  let total = 0;
  try {
    for (const rel of files) {
      const opened = await openRegular(join(dir, rel));
      if ("why" in opened) {
        leftOut.push({ path: rel, why: opened.why });
        continue;
      }
      let data: Buffer;
      try {
        if (opened.size > ZIP_MAX) throw new Error(`${rel} is ${opened.size} bytes, past what a plain zip holds; hand over the directory`);
        data = await opened.handle.readFile();
      } finally {
        await opened.handle.close();
      }
      const crc = crc32(data);
      const deflated = deflateRawSync(data);
      const stored = deflated.length >= data.length;
      const body = stored ? data : deflated;
      const name = Buffer.from(`${prefix}/${rel}`, "utf8");
      const { time, date } = dosTime(opened.mtime);
      if (offset > ZIP_MAX || offset + 30 + name.length + body.length > ZIP_MAX) throw new Error("the package is past what a plain zip holds (4 GiB); hand over the directory");
      const local = Buffer.alloc(30);
      local.writeUInt32LE(0x04034b50, 0);
      local.writeUInt16LE(20, 4);
      local.writeUInt16LE(0x0800, 6); // names are UTF-8
      local.writeUInt16LE(stored ? 0 : 8, 8);
      local.writeUInt16LE(time, 10);
      local.writeUInt16LE(date, 12);
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(body.length, 18);
      local.writeUInt32LE(data.length, 22);
      local.writeUInt16LE(name.length, 26);
      local.writeUInt16LE(0, 28);
      await out.write(local);
      await out.write(name);
      await out.write(body);
      const entry = Buffer.alloc(46);
      entry.writeUInt32LE(0x02014b50, 0);
      entry.writeUInt16LE((3 << 8) | 20, 4); // made on unix, zip 2.0
      entry.writeUInt16LE(20, 6);
      entry.writeUInt16LE(0x0800, 8);
      entry.writeUInt16LE(stored ? 0 : 8, 10);
      entry.writeUInt16LE(time, 12);
      entry.writeUInt16LE(date, 14);
      entry.writeUInt32LE(crc, 16);
      entry.writeUInt32LE(body.length, 20);
      entry.writeUInt32LE(data.length, 24);
      entry.writeUInt16LE(name.length, 28);
      entry.writeUInt32LE(((0o100644 & 0xffff) << 16) >>> 0, 38);
      entry.writeUInt32LE(offset, 42);
      central.push(entry, name);
      offset += 30 + name.length + body.length;
      total += data.length;
    }
    const centralBuf = Buffer.concat(central);
    if (offset + centralBuf.length > ZIP_MAX) throw new Error("the package is past what a plain zip holds (4 GiB); hand over the directory");
    await out.write(centralBuf);
    const entries = central.length / 2;
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(entries, 8);
    end.writeUInt16LE(entries, 10);
    end.writeUInt32LE(centralBuf.length, 12);
    end.writeUInt32LE(offset, 16);
    await out.write(end);
    return { files: entries, bytes: total, left_out: leftOut };
  } finally {
    await out.close();
  }
}

export type PackageInfo = {
  present: boolean;
  /** Why a package in the run's place was not read (a link, not a directory), or null. */
  error: string | null;
  dir: string;
  /** When MANIFEST.txt was written. */
  made_at: string | null;
  /** The files MANIFEST.txt names. */
  files: number;
  manifest_sha256: string | null;
  signed: boolean;
  /** SIGNER.txt as `swarm.sh package --sign` wrote it: who signed, the key's fingerprint, when. */
  signer: string[];
};

/** What `swarm.sh package` left in `<sandbox>/package`, read without following a link. */
export async function packageInfo(sandbox: string): Promise<PackageInfo> {
  const dir = join(sandbox, "package");
  const none: PackageInfo = { present: false, error: null, dir, made_at: null, files: 0, manifest_sha256: null, signed: false, signer: [] };
  const st = await lstat(dir).catch(() => null);
  if (!st) return none;
  if (st.isSymbolicLink() || !st.isDirectory()) return { ...none, error: `${dir} is ${st.isSymbolicLink() ? "a link" : "not a directory"}; it is not read` };
  const manifest = await openRegular(join(dir, "MANIFEST.txt"));
  if ("why" in manifest) return { ...none, error: manifest.why === "missing" ? "the package has no MANIFEST.txt: swarm.sh package did not finish" : `MANIFEST.txt is ${manifest.why}` };
  let text: string;
  try {
    text = (await manifest.handle.readFile()).toString("utf8");
  } finally {
    await manifest.handle.close();
  }
  const sig = await lstat(join(dir, "MANIFEST.txt.sig")).catch(() => null);
  const signer = await openRegular(join(dir, "SIGNER.txt"));
  let signerLines: string[] = [];
  if (!("why" in signer)) {
    try {
      signerLines = (await signer.handle.readFile()).toString("utf8").split("\n").map((l) => l.trim()).filter(Boolean);
    } finally {
      await signer.handle.close();
    }
  }
  return {
    present: true,
    error: null,
    dir,
    made_at: manifest.mtime.toISOString(),
    files: text.split("\n").filter((l) => l.trim()).length,
    manifest_sha256: createHash("sha256").update(text).digest("hex"),
    signed: Boolean(sig && sig.isFile() && !sig.isSymbolicLink()),
    signer: signerLines,
  };
}
