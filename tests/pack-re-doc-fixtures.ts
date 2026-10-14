/**
 * Fixtures for doc_structure, built from the format specifications and never from the tool's output:
 *   - OLE compound files: [MS-CFB] (the 512-byte header, the FAT, the DIFAT, the mini FAT, 128-byte directory entries
 *     whose siblings form a binary tree, the mini stream below the 4096-byte cutoff);
 *   - VBA projects: [MS-OVBA] (the dir stream's records, a module stream = a cache + a compressed container, and a
 *     compressor that writes literal tokens, plus a hand-made copy token);
 *   - the encryption structures: [MS-OFFCRYPTO] EncryptionInfo (standard and agile), [MS-DOC] FIB flags, [MS-XLS]
 *     FILEPASS and BOUNDSHEET8, [MS-PPT] CurrentUserAtom;
 *   - PDF: ISO 32000-1 (objects, xref tables and streams, trailers, incremental updates, object streams);
 *   - RTF: the RTF specification (groups, control words, \binN, \object/\objdata hex data) and [MS-OLEDS] ObjectHeader.
 */
import { deflateSync } from "node:zlib";
import { u16, u32, u64 } from "./pack-re-harness.ts";

// --- MS-CFB --------------------------------------------------------------------------------------------------------------

export type OleNode = { name: string; data?: Buffer; children?: OleNode[]; clsid?: Buffer; created?: bigint; modified?: bigint };
export type CfbOptions = {
  major?: 3 | 4;
  /** Entries written but linked from no storage (orphans), in the root's directory. */
  orphans?: OleNode[];
  /** Extra 128-byte directory records appended raw (to build hostile directories). */
  rawEntries?: Buffer[];
  rootClsid?: Buffer;
  rootModified?: bigint;
};

const FREESECT = 0xffffffff, ENDOFCHAIN = 0xfffffffe, FATSECT = 0xfffffffd, DIFSECT = 0xfffffffc, NOSTREAM = 0xffffffff;

function compareNames(a: string, b: string): number {
  // [MS-CFB] 2.6.4: shorter names sort first, then by upper-cased UTF-16 code units.
  if (a.length !== b.length) return a.length - b.length;
  const x = a.toUpperCase(), y = b.toUpperCase();
  return x < y ? -1 : x > y ? 1 : 0;
}

function dirEntry(name: string, kind: number, o: { left?: number; right?: number; child?: number; start?: number; size?: bigint | number; clsid?: Buffer; created?: bigint; modified?: bigint }): Buffer {
  const e = Buffer.alloc(128);
  const raw = Buffer.from(name, "utf16le");
  if (raw.length > 62) throw new Error("name too long");
  raw.copy(e, 0);
  e.writeUInt16LE(kind === 0 ? 0 : raw.length + 2, 64);
  e[66] = kind;
  e[67] = 1; // black
  e.writeUInt32LE(o.left ?? NOSTREAM, 68);
  e.writeUInt32LE(o.right ?? NOSTREAM, 72);
  e.writeUInt32LE(o.child ?? NOSTREAM, 76);
  if (o.clsid) o.clsid.copy(e, 80);
  e.writeBigUInt64LE(o.created ?? 0n, 100);
  e.writeBigUInt64LE(o.modified ?? 0n, 108);
  e.writeUInt32LE(o.start ?? 0, 116);
  e.writeBigUInt64LE(BigInt(o.size ?? 0), 120);
  return e;
}

type Flat = { node: OleNode; kind: 1 | 2; sid: number; children: Flat[] };

export function buildCfb(top: OleNode[], o: CfbOptions = {}): Buffer {
  const major = o.major ?? 3;
  const ss = major === 3 ? 512 : 4096;
  // 1. Flatten: sid 0 is the root; the rest are numbered depth-first.
  const flat: Flat[] = [];
  const make = (nodes: OleNode[]): Flat[] =>
    nodes.map((node) => {
      const f: Flat = { node, kind: node.children ? 1 : 2, sid: 0, children: [] };
      return f;
    });
  const number = (list: Flat[]): void => {
    for (const f of list) {
      f.sid = flat.length + 1;
      flat.push(f);
      if (f.node.children) {
        f.children = make(f.node.children);
        number(f.children);
      }
    }
  };
  const roots = make(top);
  number(roots);
  const orphanFlat = make(o.orphans ?? []);
  for (const f of orphanFlat) {
    f.sid = flat.length + 1;
    flat.push(f);
  }
  // 2. Streams: below the cutoff -> the mini stream; otherwise regular sectors.
  const mini: Buffer[] = [];
  const miniFat: number[] = [];
  const startOf = new Map<Flat, number>();
  const regular: { f: Flat; data: Buffer }[] = [];
  for (const f of flat) {
    if (f.kind !== 2) continue;
    const data = f.node.data ?? Buffer.alloc(0);
    if (data.length === 0) continue;
    if (data.length < 4096) {
      const count = Math.ceil(data.length / 64);
      const first = miniFat.length;
      for (let i = 0; i < count; i++) {
        miniFat.push(i === count - 1 ? ENDOFCHAIN : first + i + 1);
        const piece = Buffer.alloc(64);
        data.subarray(i * 64, (i + 1) * 64).copy(piece);
        mini.push(piece);
      }
      startOf.set(f, first);
    } else regular.push({ f, data });
  }
  const miniStream = Buffer.concat(mini);
  const perSector = ss / 4;
  const miniFatSectors = Math.ceil(miniFat.length / perSector);
  const miniStreamSectors = Math.ceil(miniStream.length / ss);
  const dirCount = 1 + flat.length + (o.rawEntries?.length ?? 0);
  const dirSectors = Math.ceil(dirCount / (ss / 128));
  const regSectors = regular.map((r) => Math.ceil(r.data.length / ss));
  const dataSectors = dirSectors + miniFatSectors + miniStreamSectors + regSectors.reduce((a, b) => a + b, 0);
  // 3. How many FAT (and DIFAT) sectors: they are in the FAT themselves.
  let fatSectors = 1, difatSectors = 0;
  for (;;) {
    difatSectors = fatSectors > 109 ? Math.ceil((fatSectors - 109) / (perSector - 1)) : 0;
    const total = fatSectors + difatSectors + dataSectors;
    if (fatSectors * perSector >= total) break;
    fatSectors++;
  }
  // 4. Sector numbers.
  let next = 0;
  const fatIds = Array.from({ length: fatSectors }, () => next++);
  const difatIds = Array.from({ length: difatSectors }, () => next++);
  const dirIds = Array.from({ length: dirSectors }, () => next++);
  const miniFatIds = Array.from({ length: miniFatSectors }, () => next++);
  const miniStreamIds = Array.from({ length: miniStreamSectors }, () => next++);
  const regIds = regSectors.map((n) => Array.from({ length: n }, () => next++));
  const fat = new Array<number>(fatSectors * perSector).fill(FREESECT);
  for (const id of fatIds) fat[id] = FATSECT;
  for (const id of difatIds) fat[id] = DIFSECT;
  const chain = (ids: number[]): void => ids.forEach((id, i) => (fat[id] = i === ids.length - 1 ? ENDOFCHAIN : ids[i + 1]!));
  chain(dirIds);
  chain(miniFatIds);
  chain(miniStreamIds);
  regIds.forEach(chain);
  regular.forEach((r, i) => startOf.set(r.f, regIds[i]![0]!));
  // 5. The directory: each storage's children form a binary tree built from the sorted names.
  const entries: Buffer[] = [];
  const treeRoot = (list: Flat[]): { root: number; links: Map<Flat, [number, number]> } => {
    const sorted = [...list].sort((a, b) => compareNames(a.node.name, b.node.name));
    const links = new Map<Flat, [number, number]>();
    const build = (lo: number, hi: number): number => {
      if (lo > hi) return NOSTREAM;
      const mid = (lo + hi) >> 1;
      const f = sorted[mid]!;
      links.set(f, [build(lo, mid - 1), build(mid + 1, hi)]);
      return f.sid;
    };
    return { root: build(0, sorted.length - 1), links };
  };
  const allLinks = new Map<Flat, [number, number]>();
  const rootTree = treeRoot(roots);
  rootTree.links.forEach((v, k) => allLinks.set(k, v));
  const childRoot = new Map<Flat, number>();
  const visit = (list: Flat[]): void => {
    for (const f of list) {
      if (f.children.length) {
        const t = treeRoot(f.children);
        t.links.forEach((v, k) => allLinks.set(k, v));
        childRoot.set(f, t.root);
        visit(f.children);
      }
    }
  };
  visit(roots);
  entries.push(dirEntry("Root Entry", 5, { child: roots.length ? rootTree.root : NOSTREAM, start: miniStreamIds.length ? miniStreamIds[0]! : ENDOFCHAIN, size: miniStream.length, clsid: o.rootClsid, modified: o.rootModified }));
  for (const f of flat) {
    const [left, right] = allLinks.get(f) ?? [NOSTREAM, NOSTREAM];
    const isOrphan = orphanFlat.includes(f);
    entries.push(
      dirEntry(f.node.name, f.kind, {
        left: isOrphan ? NOSTREAM : left,
        right: isOrphan ? NOSTREAM : right,
        child: f.kind === 1 ? childRoot.get(f) ?? NOSTREAM : NOSTREAM,
        start: f.kind === 2 ? (startOf.get(f) ?? ENDOFCHAIN) : 0,
        size: f.kind === 2 ? (f.node.data?.length ?? 0) : 0,
        clsid: f.node.clsid,
        created: f.node.created,
        modified: f.node.modified,
      }),
    );
  }
  for (const raw of o.rawEntries ?? []) entries.push(raw);
  while (entries.length % (ss / 128)) entries.push(dirEntry("", 0, {}));
  // 6. Assemble the sectors.
  const total = next;
  const body = Buffer.alloc(total * ss);
  const put = (id: number, data: Buffer): void => void data.copy(body, id * ss);
  fatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss);
    for (let k = 0; k < perSector; k++) b.writeUInt32LE(fat[i * perSector + k]! >>> 0, k * 4);
    put(id, b);
  });
  difatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss, 0xff);
    const from = 109 + i * (perSector - 1);
    for (let k = 0; k < perSector - 1; k++) b.writeUInt32LE((fatIds[from + k] ?? FREESECT) >>> 0, k * 4);
    b.writeUInt32LE((i === difatIds.length - 1 ? ENDOFCHAIN : difatIds[i + 1]!) >>> 0, (perSector - 1) * 4);
    put(id, b);
  });
  dirIds.forEach((id, i) => put(id, Buffer.concat(entries).subarray(i * ss, (i + 1) * ss)));
  miniFatIds.forEach((id, i) => {
    const b = Buffer.alloc(ss, 0xff);
    for (let k = 0; k < perSector; k++) if (miniFat[i * perSector + k] !== undefined) b.writeUInt32LE(miniFat[i * perSector + k]! >>> 0, k * 4);
    put(id, b);
  });
  miniStreamIds.forEach((id, i) => put(id, miniStream.subarray(i * ss, (i + 1) * ss)));
  regular.forEach((r, i) => regIds[i]!.forEach((id, k) => put(id, r.data.subarray(k * ss, (k + 1) * ss))));
  // 7. The header.
  const head = Buffer.alloc(512);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(head, 0);
  head.writeUInt16LE(0x003e, 24);
  head.writeUInt16LE(major, 26);
  head.writeUInt16LE(0xfffe, 28);
  head.writeUInt16LE(major === 3 ? 9 : 12, 30);
  head.writeUInt16LE(6, 32);
  head.writeUInt32LE(major === 4 ? dirSectors : 0, 40);
  head.writeUInt32LE(fatSectors, 44);
  head.writeUInt32LE(dirIds[0]!, 48);
  head.writeUInt32LE(4096, 56);
  head.writeUInt32LE(miniFatIds.length ? miniFatIds[0]! : ENDOFCHAIN, 60);
  head.writeUInt32LE(miniFatSectors, 64);
  head.writeUInt32LE(difatIds.length ? difatIds[0]! : ENDOFCHAIN, 68);
  head.writeUInt32LE(difatSectors, 72);
  for (let k = 0; k < 109; k++) head.writeUInt32LE((fatIds[k] ?? FREESECT) >>> 0, 76 + k * 4);
  const first = major === 4 ? Buffer.concat([head, Buffer.alloc(4096 - 512)]) : head;
  return Buffer.concat([first, body]);
}

/** The offset of sector `n` in a built file (header sector included). */
export const sectorAt = (n: number, major: 3 | 4 = 3): number => (n + 1) * (major === 3 ? 512 : 4096);

/** A FILETIME for a UTC instant given in milliseconds. */
export const filetime = (ms: number): bigint => (BigInt(ms) + 11644473600000n) * 10000n;

// --- MS-OVBA -------------------------------------------------------------------------------------------------------------

/** A compressed container made of literal tokens only: valid, and independent of the decompressor's copy handling. */
export function ovbaCompress(data: Buffer): Buffer {
  const chunks: Buffer[] = [Buffer.from([1])];
  for (let at = 0; at < data.length || at === 0; at += 3640) {
    const piece = data.subarray(at, at + 3640);
    const body: number[] = [];
    for (let i = 0; i < piece.length; i += 8) {
      body.push(0);
      for (const b of piece.subarray(i, i + 8)) body.push(b);
    }
    const size = body.length + 2;
    chunks.push(u16(((size - 3) & 0x0fff) | (3 << 12) | 0x8000), Buffer.from(body));
    if (piece.length === 0) break;
  }
  return Buffer.concat(chunks);
}

/** One chunk whose last six bytes are a copy token: "abcabcabc". */
export const OVBA_COPY_CHUNK = Buffer.concat([Buffer.from([1]), u16(((8 - 3) & 0x0fff) | (3 << 12) | 0x8000), Buffer.from([0x08, 0x61, 0x62, 0x63, 0x03, 0x20])]);

function rec(id: number, data: Buffer | string = Buffer.alloc(0)): Buffer {
  const d = typeof data === "string" ? Buffer.from(data, "latin1") : data;
  return Buffer.concat([u16(id), u32(d.length), d]);
}

export type VbaModule = { name: string; source: Buffer | string; type?: "procedural" | "class"; cache?: Buffer; compressed?: Buffer };

/** The decompressed `dir` stream of a VBA project ([MS-OVBA] 2.3.4.2). */
export function vbaDirStream(modules: VbaModule[], cacheLens: number[], o: { declared?: number; codepage?: number; name?: string } = {}): Buffer {
  const parts: Buffer[] = [
    rec(0x0001, u32(1)), rec(0x0002, u32(0x409)), rec(0x0014, u32(0x409)), rec(0x0003, u16(o.codepage ?? 1252)),
    rec(0x0004, o.name ?? "VBAProject"), rec(0x0005), rec(0x0040), rec(0x0006), rec(0x003d), rec(0x0007, u32(0)), rec(0x0008, u32(2)),
    // PROJECTVERSION: Id, Reserved (4), VersionMajor (4), VersionMinor (2)
    Buffer.concat([u16(0x0009), u32(4), u32(1), u16(1)]),
    rec(0x000c), rec(0x003c),
    rec(0x0016, "stdole"), rec(0x003e, Buffer.from("stdole", "utf16le")),
    rec(0x000d, Buffer.concat([u32(4), Buffer.from("*\\G{}"), u32(0), u16(0)])),
    rec(0x000f, u16(o.declared ?? modules.length)), rec(0x0013, u16(0xffff)),
  ];
  modules.forEach((m, i) => {
    parts.push(
      rec(0x0019, m.name), rec(0x0047, Buffer.from(m.name, "utf16le")), rec(0x001a, m.name), rec(0x0032, Buffer.from(m.name, "utf16le")),
      rec(0x001c), rec(0x0048), rec(0x0031, u32(cacheLens[i]!)), rec(0x001e, u32(0)), rec(0x002c, u16(0xffff)),
      rec(m.type === "class" ? 0x0022 : 0x0021), rec(0x002b),
    );
  });
  parts.push(rec(0x0010));
  return Buffer.concat(parts);
}

/** A vbaProject.bin-shaped compound file: VBA/dir, VBA/_VBA_PROJECT, VBA/<modules>, PROJECT. */
export function buildVbaProject(modules: VbaModule[], o: { project?: string; declared?: number; storage?: string; major?: 3 | 4 } = {}): Buffer {
  const cacheLens = modules.map((m) => (m.cache ?? Buffer.alloc(24, 0xab)).length);
  const vba: OleNode = {
    name: "VBA",
    children: [
      { name: "dir", data: ovbaCompress(vbaDirStream(modules, cacheLens, { declared: o.declared })) },
      { name: "_VBA_PROJECT", data: Buffer.concat([u16(0x61cc), u16(0xffff), Buffer.from([0]), u16(0), Buffer.alloc(40, 0x11)]) },
      ...modules.map((m, i) => ({
        name: m.name,
        data: Buffer.concat([m.cache ?? Buffer.alloc(24, 0xab), m.compressed ?? ovbaCompress(typeof m.source === "string" ? Buffer.from(m.source, "latin1") : m.source)]),
      })),
    ],
  };
  const project: OleNode = { name: "PROJECT", data: Buffer.from(o.project ?? 'ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\nName="VBAProject"\r\n', "latin1") };
  const tree: OleNode[] = o.storage ? [{ name: o.storage, children: [vba, project] }] : [vba, project];
  return buildCfb(tree, { major: o.major });
}

// --- encryption structures ----------------------------------------------------------------------------------------------

/** [MS-OFFCRYPTO] 2.3.3 standard EncryptionInfo with a recognisable salt and verifier. */
export function standardEncryptionInfo(o: { alg?: number; hash?: number; bits?: number; salt?: Buffer; verifier?: Buffer; verifierHash?: Buffer } = {}): Buffer {
  const header = Buffer.concat([u32(0x24), u32(0), u32(o.alg ?? 0x660e), u32(o.hash ?? 0x8004), u32(o.bits ?? 128), u32(0x18), u32(0), u32(0), Buffer.from("Microsoft Enhanced RSA and AES Cryptographic Provider\0", "utf16le")]);
  const verifier = Buffer.concat([u32(16), o.salt ?? Buffer.from("SALTSALTSALTSALT"), o.verifier ?? Buffer.from("VERIFIERVERIFIER"), u32(20), o.verifierHash ?? Buffer.from("VERIFIERHASH_32BYTES_VERIFIERHAS")]);
  return Buffer.concat([u16(3), u16(2), u32(0x24), u32(header.length), header, verifier]);
}

/** [MS-OFFCRYPTO] 2.3.4.10 agile EncryptionInfo: version 4.4, reserved 0x40, then the XML descriptor. */
export function agileEncryptionInfo(o: { keyBits?: number; spin?: number; salt?: string; encryptedKey?: string } = {}): Buffer {
  const xml =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">` +
    `<keyData saltSize="16" blockSize="16" keyBits="${o.keyBits ?? 256}" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${o.salt ?? "U0FMVFNBTFRTQUxUU0FMVA=="}"/>` +
    `<dataIntegrity encryptedHmacKey="ZW5jcnlwdGVkSG1hY0tleQ==" encryptedHmacValue="ZW5jcnlwdGVkSG1hY1ZhbHVl"/>` +
    `<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><p:encryptedKey spinCount="${o.spin ?? 100000}" saltSize="16" blockSize="16" keyBits="${o.keyBits ?? 256}" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="${o.salt ?? "U0FMVFNBTFRTQUxUU0FMVA=="}" encryptedVerifierHashInput="${"VkVSSUZJRVJJTlBVVA=="}" encryptedVerifierHashValue="${o.encryptedKey ?? "VkVSSUZJRVJIQVNIVkFMVUU="}" encryptedKeyValue="RU5DUllQVEVES0VZVkFMVUU="/></keyEncryptor></keyEncryptors></encryption>`;
  return Buffer.concat([u16(4), u16(4), u32(0x40), Buffer.from(xml, "utf8")]);
}

/** [MS-DOC] 2.5.1 FIB base: wIdent, nFib, ..., the flags word at 0x0A (fEncrypted bit 8, fWhichTblStm bit 9, fObfuscated bit 15). */
export function wordFib(o: { encrypted?: boolean; obfuscated?: boolean; table1?: boolean } = {}): Buffer {
  const b = Buffer.alloc(512);
  b.writeUInt16LE(0xa5ec, 0);
  b.writeUInt16LE(0x00c1, 2);
  let flags = 0;
  if (o.encrypted) flags |= 0x0100;
  if (o.table1 ?? true) flags |= 0x0200;
  if (o.obfuscated) flags |= 0x8000;
  b.writeUInt16LE(flags, 0x0a);
  return b;
}

const biff = (type: number, data: Buffer): Buffer => Buffer.concat([u16(type), u16(data.length), data]);

/** [MS-XLS] a BIFF8 globals substream: BOF, an optional FILEPASS, BOUNDSHEET8 records, EOF. */
export function excelWorkbook(o: { filepass?: { type: 0 | 1; major?: number; minor?: number }; sheets?: { name: string; state?: number; kind?: number }[]; noEof?: boolean } = {}): Buffer {
  const parts: Buffer[] = [biff(0x0809, Buffer.concat([u16(0x0600), u16(0x0005), u16(0x0dbb), u16(0x07cc), u32(0), u32(0x06)]))];
  if (o.filepass) {
    parts.push(biff(0x002f, o.filepass.type === 0 ? Buffer.concat([u16(0), u16(0x1234), u16(0x5678)]) : Buffer.concat([u16(1), u16(o.filepass.major ?? 1), u16(o.filepass.minor ?? 1), Buffer.alloc(48, 0x77)])));
  }
  for (const s of o.sheets ?? []) {
    parts.push(biff(0x0085, Buffer.concat([u32(0x1000), Buffer.from([s.state ?? 0, s.kind ?? 0]), Buffer.from([s.name.length, 1]), Buffer.from(s.name, "utf16le")])));
  }
  if (!o.noEof) parts.push(biff(0x000a, Buffer.alloc(0)));
  return Buffer.concat(parts);
}

/** [MS-PPT] 2.3.2 CurrentUserAtom: record header, size 0x14, headerToken, ... */
export function currentUser(token: number): Buffer {
  return Buffer.concat([u16(0), u16(0x0ff6), u32(0x1c), u32(0x14), u32(token), Buffer.alloc(16)]);
}

// --- PDF -----------------------------------------------------------------------------------------------------------------

export type PdfObj = { num: number; body: string; stream?: Buffer; gen?: number; extra?: string };

/** The bytes of `1 0 obj ... endobj`, with a stream when given (the dictionary's /Length is written unless the body already holds one). */
export function pdfObject(o: PdfObj): Buffer {
  const head = `${o.num} ${o.gen ?? 0} obj\n`;
  if (!o.stream) return Buffer.from(`${head}${o.body}\nendobj\n`, "latin1");
  const dict = /\/Length\b/.test(o.body) ? o.body : o.body.replace(/>>\s*$/, ` /Length ${o.stream.length} >>`);
  return Buffer.concat([Buffer.from(`${head}${dict}\nstream\n`, "latin1"), o.stream, Buffer.from("\nendstream\nendobj\n", "latin1")]);
}

/** A PDF with a classic cross-reference table over the objects given, in the order given. */
export function buildPdf(objects: PdfObj[], trailer: string, o: { header?: string; prefix?: Buffer; free?: number[] } = {}): { file: Buffer; offsets: Map<number, number>; xrefAt: number } {
  const parts: Buffer[] = [Buffer.from(o.header ?? "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const offsets = new Map<number, number>();
  for (const ob of objects) {
    offsets.set(ob.num, at);
    const b = pdfObject(ob);
    parts.push(b);
    at += b.length;
  }
  const max = Math.max(...objects.map((x) => x.num)) + 1;
  let xref = `xref\n0 ${max}\n`;
  for (let n = 0; n < max; n++) {
    const off = offsets.get(n);
    xref += n === 0 || off === undefined ? `0000000000 ${n === 0 ? "65535" : "00000"} f \n` : `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  const body = Buffer.from(`${xref}trailer\n<< /Size ${max} ${trailer} >>\nstartxref\n${at}\n%%EOF\n`, "latin1");
  return { file: Buffer.concat([...(o.prefix ? [o.prefix] : []), ...parts, body]), offsets, xrefAt: at };
}

/** A PDF 1.5 file whose cross-reference is a stream (W [1 2 1], Flate, PNG Up predictor) and whose objects 3.. may sit in an object stream. */
export function buildPdfWithStreams(o: { objstmExtra?: Buffer } = {}): { file: Buffer; objstmNum: number; compressed: number[] } {
  // Objects: 1 catalog, 2 pages, 4 an object stream holding objects 5 (page) and 6 (an action dictionary); 7 the xref stream.
  const inner = ["<< /Type /Page /Parent 2 0 R /Annots [ 6 0 R ] >>", "<< /S /URI /URI (http://example.test/x) >>"];
  let header = "";
  let bodyText = "";
  const nums = [5, 6];
  inner.forEach((text, i) => {
    header += `${nums[i]} ${bodyText.length} `;
    bodyText += text + "\n";
  });
  const objstmData = deflateSync(Buffer.concat([Buffer.from(header + bodyText, "latin1"), o.objstmExtra ?? Buffer.alloc(0)]));
  const parts: Buffer[] = [Buffer.from("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  let at = parts[0]!.length;
  const offs = new Map<number, number>();
  const add = (o: PdfObj): void => {
    offs.set(o.num, at);
    const b = pdfObject(o);
    parts.push(b);
    at += b.length;
  };
  add({ num: 1, body: "<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>" });
  add({ num: 2, body: "<< /Type /Pages /Kids [ 5 0 R ] /Count 1 >>" });
  add({ num: 4, body: `<< /Type /ObjStm /N 2 /First ${header.length} /Filter /FlateDecode >>`, stream: objstmData });
  // The xref stream: entries for objects 0..7 as (type, field2, field3), each row 4 bytes, with the PNG "Up" predictor (filter byte 2).
  const xrefAt = at;
  const rows: number[][] = [
    [0, 0, 255],
    [1, offs.get(1)!, 0],
    [1, offs.get(2)!, 0],
    [0, 0, 0],
    [1, offs.get(4)!, 0],
    [2, 4, 0],
    [2, 4, 1],
    [1, xrefAt, 0],
  ];
  const raw = rows.map((r) => Buffer.from([r[0]!, (r[1]! >> 8) & 0xff, r[1]! & 0xff, r[2]!]));
  const filtered: Buffer[] = [];
  let prev = Buffer.alloc(4);
  for (const row of raw) {
    filtered.push(Buffer.concat([Buffer.from([2]), Buffer.from(row.map((b, i) => (b - prev[i]! + 256) & 0xff))]));
    prev = row;
  }
  add({
    num: 7,
    body: `<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >> >>`,
    stream: deflateSync(Buffer.concat(filtered)),
  });
  parts.push(Buffer.from(`startxref\n${xrefAt}\n%%EOF\n`, "latin1"));
  return { file: Buffer.concat(parts), objstmNum: 4, compressed: [5, 6] };
}

// --- RTF + OLE 1.0 ---------------------------------------------------------------------------------------------------------

/** [MS-OLEDS] 2.2.4 ObjectHeader + native data, as an embedded object (format ID 2). */
export function ole1Object(className: string, native: Buffer): Buffer {
  const lps = (s: string): Buffer => Buffer.concat([u32(s.length + 1), Buffer.from(s + "\0", "latin1")]);
  return Buffer.concat([u32(0x501), u32(2), lps(className), u32(0), u32(0), u32(native.length), native]);
}

export const hex = (b: Buffer, wrap = 0): string => {
  const h = b.toString("hex");
  return wrap ? h.replace(new RegExp(`(.{${wrap}})`, "g"), "$1\n") : h;
};

export { u16, u32, u64 };
