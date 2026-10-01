/**
 * A synthetic AccessData AD1 logical image, built in code from the layout
 * the public descriptions of the format give (AD1-tools' libad1, pyad1) and
 * the base pack's reader follows: no evidence file is read or kept. Every
 * segment file starts with a 512-byte header ("ADSEGMENTEDFILE", its index,
 * the number of segments, its size in 64 KiB fragments, the header's size);
 * the image's data runs on from segment to segment and opens with the
 * logical image header ("ADLOGICALIMAGE", version, chunk size, the image's
 * own metadata, the first item, the data source name). An item is a node of
 * the tree with its metadata chain and, for a file, a chunk table of zlib
 * streams.
 */
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";

export type Ad1Node = {
  name: string | Buffer;
  folder?: boolean;
  content?: Buffer;
  children?: Ad1Node[];
  /** Metadata entries written instead of the usual ones: [category, key, text]. */
  meta?: Array<[number, number, string | Buffer]>;
  /** The image records an MD5 that is not the content's. */
  wrongMd5?: boolean;
  /** Compressed chunks written as they are, with `size` as the item's size. */
  chunks?: Buffer[];
  size?: number;
};

export const md5 = (b: Buffer): string => createHash("md5").update(b).digest("hex");
export const sha1 = (b: Buffer): string => createHash("sha1").update(b).digest("hex");
export const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/** The times every node carries unless it says otherwise: accessed, modified, changed. */
export const TIMES: Array<[number, number, string]> = [
  [5, 7, "20240102T030405.123456"],
  [5, 8, "20240102T030406.654321"],
  [5, 9, "20240101T000000"],
];

function metaFor(node: Ad1Node): Array<[number, number, Buffer]> {
  const B = (v: string | Buffer) => (Buffer.isBuffer(v) ? v : Buffer.from(v));
  if (node.meta) return node.meta.map(([c, k, v]) => [c, k, B(v)]);
  const times = TIMES.map(([c, k, v]) => [c, k, B(v)] as [number, number, Buffer]);
  if (node.folder) return [[2, 2, B("3")], ...times];
  const c = node.content ?? Buffer.alloc(0);
  return [
    [1, 0x5001, B(node.wrongMd5 ? "0".repeat(32) : md5(c))],
    [1, 0x5002, B(sha1(c))],
    [2, 2, B("1")],
    [3, 3, B(String(c.length))],
    [4, 0x1002, B("false")],
    ...times,
  ];
}

/**
 * The image's data (logical address 0 onwards) and each node's item
 * address, so a test can damage it where it means to.
 */
export function ad1Data(tree: Ad1Node[], opts: { chunkSize?: number; version?: number; source?: string } = {}): { data: Buffer; addr: Map<Ad1Node, number> } {
  const chunkSize = opts.chunkSize ?? 65536;
  const parts: Buffer[] = [];
  let len = 0;
  const put = (b: Buffer): number => {
    const at = len;
    parts.push(b);
    len += b.length;
    return at;
  };
  const header = Buffer.alloc(92);
  put(header);
  const source = Buffer.from(opts.source ?? "synthetic source [NTFS]");
  const sourceAt = put(source);
  header.write("ADLOGICALIMAGE", 0, "latin1");
  header.writeUInt32LE(opts.version ?? 4, 16);
  header.writeUInt32LE(1, 20);
  header.writeUInt32LE(chunkSize, 24);
  header.writeUInt32LE(source.length, 44);
  header.write("AD", 48, "latin1");
  header.writeBigUInt64LE(BigInt(sourceAt), 52);
  const addr = new Map<Ad1Node, number>();
  const chain = (nodes: Ad1Node[]): number => {
    let first = 0;
    let prev: Buffer | null = null;
    for (const node of nodes) {
      const name = Buffer.isBuffer(node.name) ? node.name : Buffer.from(node.name);
      const h = Buffer.alloc(48 + name.length + 8);
      const at = put(h);
      addr.set(node, at);
      if (prev) prev.writeBigUInt64LE(BigInt(at), 0);
      else first = at;
      prev = h;
      h.writeUInt32LE(node.folder ? 5 : 0, 40);
      h.writeUInt32LE(name.length, 44);
      name.copy(h, 48);
      let mprev: Buffer | null = null;
      for (const [c, k, v] of metaFor(node)) {
        const m = Buffer.alloc(20 + v.length);
        const mat = put(m);
        if (mprev) mprev.writeBigUInt64LE(BigInt(mat), 0);
        else h.writeBigUInt64LE(BigInt(mat), 16);
        mprev = m;
        m.writeUInt32LE(c, 8);
        m.writeUInt32LE(k, 12);
        m.writeUInt32LE(v.length, 16);
        v.copy(m, 20);
      }
      const content = node.content ?? Buffer.alloc(0);
      const pieces = node.chunks ?? [];
      if (!node.chunks) for (let i = 0; i < content.length; i += chunkSize) pieces.push(deflateSync(content.subarray(i, i + chunkSize)));
      if (!node.folder && pieces.length) {
        const table = Buffer.alloc(8 + 8 * (pieces.length + 1));
        h.writeBigUInt64LE(BigInt(put(table)), 24);
        table.writeBigUInt64LE(BigInt(pieces.length), 0);
        pieces.forEach((p, i) => table.writeBigUInt64LE(BigInt(put(p)), 8 + 8 * i));
        table.writeBigUInt64LE(BigInt(len), 8 + 8 * pieces.length);
      }
      h.writeBigUInt64LE(BigInt(node.size ?? content.length), 32);
      if (node.children?.length) h.writeBigUInt64LE(BigInt(chain(node.children)), 8);
    }
    return first;
  };
  header.writeBigUInt64LE(BigInt(chain(tree)), 36);
  const own = Buffer.alloc(20 + source.length);
  header.writeBigUInt64LE(BigInt(put(own)), 28);
  own.writeUInt32LE(1, 8);
  own.writeUInt32LE(0x10002, 12);
  own.writeUInt32LE(source.length, 16);
  source.copy(own, 20);
  return { data: Buffer.concat(parts), addr };
}

/** The segment files of an image's data, each `fragments` 64 KiB fragments long at most. */
export function ad1Segments(data: Buffer, fragments = 24000): Buffer[] {
  const span = fragments * 65536 - 512;
  const count = Math.max(1, Math.ceil(data.length / span));
  const out: Buffer[] = [];
  for (let k = 0; k < count; k += 1) {
    const head = Buffer.alloc(512);
    head.write("ADSEGMENTEDFILE", 0, "latin1");
    head.writeUInt32LE(k + 1, 0x18);
    head.writeUInt32LE(count, 0x1c);
    head.writeUInt32LE(fragments, 0x22);
    head.writeUInt32LE(512, 0x28);
    out.push(Buffer.concat([head, data.subarray(k * span, (k + 1) * span)]));
  }
  return out;
}

/** One-segment image of a tree. */
export function ad1Image(tree: Ad1Node[], opts: { chunkSize?: number; version?: number; source?: string } = {}): Buffer {
  return ad1Segments(ad1Data(tree, opts).data)[0];
}
