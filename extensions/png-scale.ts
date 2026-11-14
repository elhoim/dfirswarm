/**
 * An image made small enough for a model to look at.
 *
 * `read` hands a model an image whole. In the runs the median image a seat
 * read was 0.3 to 1.7 MB (contact sheets, frames, renderings), 32 in one
 * seat's cycle, and the seat that reads most pays for it in context. A
 * model does not see more in an image past about 1,568 pixels on its long
 * side. Every image a seat reads is brought to at most LONG_SIDE_MAX pixels
 * on its long side and at most TARGET_BYTES (imageForModel): through the
 * image library Pi itself resizes with (Photon, which reads PNG of every
 * depth and interlace, JPEG, GIF and WebP, and writes PNG or JPEG, whichever
 * is under the bytes), and, where that library cannot be loaded, through the
 * PNG reader and writer here. Pi's own resize stops at 2,000 pixels and
 * 4.5 MB, so a JPEG, a 16-bit or an interlaced PNG used to reach the model at
 * that size, and a PNG of 1,568 pixels or less at any size.
 *
 * The PNG code here reads every PNG the format allows (grey, RGB, palette,
 * with or without alpha, at 1 to 16 bits, plain or interlaced), averages
 * blocks of pixels down, and writes RGB or RGBA with a filter chosen a row at
 * a time. image_crop uses it to give a region at the original's resolution.
 */
import { deflateSync, inflateSync } from "node:zlib";
import { resizeImage } from "@earendil-works/pi-coding-agent";

export const LONG_SIDE_MAX = 1568;
/** The most bytes an image a seat reads is sent to the model with. */
export const TARGET_BYTES = 300 * 1024;

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = crcTable[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(body.length, 0);
  head.write(type, 4, "latin1");
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
  return Buffer.concat([head, body, tail]);
}

export type Decoded = { width: number; height: number; channels: 3 | 4; pixels: Buffer };

/** The seven passes of an interlaced PNG (Adam7): where each starts and how far apart its pixels are. */
const ADAM7 = [
  { x: 0, y: 0, dx: 8, dy: 8 },
  { x: 4, y: 0, dx: 8, dy: 8 },
  { x: 0, y: 4, dx: 4, dy: 8 },
  { x: 2, y: 0, dx: 4, dy: 4 },
  { x: 0, y: 2, dx: 2, dy: 4 },
  { x: 1, y: 0, dx: 2, dy: 2 },
  { x: 0, y: 1, dx: 1, dy: 2 },
];
const DEPTHS: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };

/** Undo the filters of `rows` rows of `stride` bytes at `at` in `raw`, `bpp` bytes a pixel (at least 1). Null on a filter the format does not have. */
function unfilter(raw: Buffer, at: number, rows: number, stride: number, bpp: number): Buffer | null {
  const out = Buffer.alloc(stride * rows);
  for (let y = 0; y < rows; y += 1) {
    const filter = raw[at + y * (stride + 1)]!;
    const src = at + y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const a = x >= bpp ? out[dst + x - bpp]! : 0;
      const b = y > 0 ? out[dst - stride + x]! : 0;
      const c = x >= bpp && y > 0 ? out[dst - stride + x - bpp]! : 0;
      let v = raw[src + x]!;
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      } else if (filter !== 0) return null;
      out[dst + x] = v & 0xff;
    }
  }
  return out;
}

/**
 * The pixels of a PNG as 8-bit RGB or RGBA, or null for anything this does not read (a file that is not a PNG, a cut or
 * corrupt one, one larger than 120 M pixels). Every colour type at every depth the format allows, plain or interlaced:
 * a 16-bit sample keeps its high byte, a 1, 2 or 4-bit grey is spread over 0 to 255.
 */
export function decodePng(png: Buffer): Decoded | null {
  if (png.length < 33 || !png.subarray(0, 8).equals(SIG)) return null;
  let off = 8;
  let width = 0, height = 0, depth = 0, type = 0, interlace = 0;
  let palette: Buffer | null = null;
  let trns: Buffer | null = null;
  const idat: Buffer[] = [];
  while (off + 12 <= png.length) {
    const len = png.readUInt32BE(off);
    const name = png.toString("latin1", off + 4, off + 8);
    const body = png.subarray(off + 8, off + 8 + len);
    if (body.length !== len) return null;
    if (name === "IHDR") {
      if (len < 13) return null;
      width = body.readUInt32BE(0); height = body.readUInt32BE(4); depth = body[8]!; type = body[9]!; interlace = body[12]!;
    } else if (name === "PLTE") palette = Buffer.from(body);
    else if (name === "tRNS") trns = Buffer.from(body);
    else if (name === "IDAT") idat.push(body);
    else if (name === "IEND") break;
    off += 12 + len;
  }
  if (!width || !height || !DEPTHS[type]?.includes(depth) || (interlace !== 0 && interlace !== 1) || !idat.length) return null;
  if (width > 20000 || height > 20000 || width * height > 120_000_000) return null;
  const inCh = type === 0 ? 1 : type === 2 ? 3 : type === 3 ? 1 : type === 4 ? 2 : 4;
  if (type === 3 && !palette) return null;
  let raw: Buffer;
  try {
    raw = inflateSync(Buffer.concat(idat));
  } catch {
    return null;
  }
  const bits = inCh * depth;
  const bpp = Math.max(1, bits >> 3);
  const alpha = type === 4 || type === 6 || (type === 3 && trns !== null);
  const channels: 3 | 4 = alpha ? 4 : 3;
  const pixels = Buffer.alloc(width * height * channels);
  const top = (1 << depth) - 1;
  /** Sample `s` of pixel `i` in an unfiltered row, as 8 bits (for an index, the index itself). */
  const sample = (row: Buffer, rowAt: number, i: number, s: number, index: boolean): number => {
    if (depth === 8) return row[rowAt + i * inCh + s]!;
    if (depth === 16) return row[rowAt + (i * inCh + s) * 2]!;
    const bit = (i * inCh + s) * depth;
    const v = (row[rowAt + (bit >> 3)]! >> (8 - depth - (bit & 7))) & top;
    return index ? v : Math.round((v * 255) / top);
  };
  const passes = interlace ? ADAM7 : [{ x: 0, y: 0, dx: 1, dy: 1 }];
  let at = 0;
  for (const pass of passes) {
    const pw = Math.ceil((width - pass.x) / pass.dx);
    const ph = Math.ceil((height - pass.y) / pass.dy);
    if (pw <= 0 || ph <= 0) continue;
    const stride = Math.ceil((pw * bits) / 8);
    if (raw.length < at + (stride + 1) * ph) return null;
    const rows = unfilter(raw, at, ph, stride, bpp);
    if (!rows) return null;
    at += (stride + 1) * ph;
    for (let j = 0; j < ph; j += 1) {
      const rowAt = j * stride;
      const y = pass.y + j * pass.dy;
      for (let i = 0; i < pw; i += 1) {
        const o = (y * width + pass.x + i * pass.dx) * channels;
        if (type === 0) { const g = sample(rows, rowAt, i, 0, false); pixels[o] = g; pixels[o + 1] = g; pixels[o + 2] = g; }
        else if (type === 2) { pixels[o] = sample(rows, rowAt, i, 0, false); pixels[o + 1] = sample(rows, rowAt, i, 1, false); pixels[o + 2] = sample(rows, rowAt, i, 2, false); }
        else if (type === 3) {
          const k = sample(rows, rowAt, i, 0, true);
          pixels[o] = palette![k * 3] ?? 0; pixels[o + 1] = palette![k * 3 + 1] ?? 0; pixels[o + 2] = palette![k * 3 + 2] ?? 0;
          if (alpha) pixels[o + 3] = trns![k] ?? 255;
        } else if (type === 4) { const g = sample(rows, rowAt, i, 0, false); pixels[o] = g; pixels[o + 1] = g; pixels[o + 2] = g; pixels[o + 3] = sample(rows, rowAt, i, 1, false); }
        else { for (let c = 0; c < 4; c += 1) pixels[o + c] = sample(rows, rowAt, i, c, false); }
      }
    }
  }
  return { width, height, channels, pixels };
}

/** The width and height a PNG says it has, from its header alone; null for anything else. */
export function pngSize(png: Buffer): { width: number; height: number } | null {
  if (png.length < 24 || !png.subarray(0, 8).equals(SIG) || png.toString("latin1", 12, 16) !== "IHDR") return null;
  return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) };
}

/** The width and height a JPEG says it has, from its first frame header; null for anything else. */
export function jpegSize(jpg: Buffer): { width: number; height: number } | null {
  if (jpg.length < 4 || jpg[0] !== 0xff || jpg[1] !== 0xd8) return null;
  let off = 2;
  while (off + 9 < jpg.length) {
    if (jpg[off] !== 0xff) return null;
    const marker = jpg[off + 1]!;
    if (marker === 0xff) {
      off += 1;
      continue;
    }
    const len = jpg.readUInt16BE(off + 2);
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) return { height: jpg.readUInt16BE(off + 5), width: jpg.readUInt16BE(off + 7) };
    off += 2 + len;
  }
  return null;
}

/**
 * A PNG of the pixels, RGB or RGBA at 8 bits. Each row takes the filter that leaves it the smallest sum of bytes (the
 * format's own advice), which is what makes a picture's PNG small; with none, a contact sheet's was two to three
 * times larger.
 */
export function encodePng(img: Decoded, o: { level?: number } = {}): Buffer {
  const stride = img.width * img.channels;
  const bpp = img.channels;
  const raw = Buffer.alloc((stride + 1) * img.height);
  const cand = Array.from({ length: 5 }, () => Buffer.alloc(stride));
  for (let y = 0; y < img.height; y += 1) {
    const row = img.pixels.subarray(y * stride, (y + 1) * stride);
    const up = y > 0 ? img.pixels.subarray((y - 1) * stride, y * stride) : null;
    let best = 0;
    let bestSum = Infinity;
    for (let f = 0; f < 5; f += 1) {
      const out = cand[f]!;
      let sum = 0;
      for (let x = 0; x < stride; x += 1) {
        const a = x >= bpp ? row[x - bpp]! : 0;
        const b = up ? up[x]! : 0;
        const c = up && x >= bpp ? up[x - bpp]! : 0;
        let pred = 0;
        if (f === 1) pred = a;
        else if (f === 2) pred = b;
        else if (f === 3) pred = (a + b) >> 1;
        else if (f === 4) {
          const p = a + b - c;
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          pred = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
        }
        const v = (row[x]! - pred) & 0xff;
        out[x] = v;
        sum += v < 128 ? v : 256 - v;
        if (sum >= bestSum) break;
      }
      if (sum < bestSum) {
        bestSum = sum;
        best = f;
      }
    }
    raw[y * (stride + 1)] = best;
    // The chosen candidate is whole only if its loop ran to the end: it did, since it is the smallest.
    cand[best]!.copy(raw, y * (stride + 1) + 1);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(img.width, 0);
  ihdr.writeUInt32BE(img.height, 4);
  ihdr[8] = 8;
  ihdr[9] = img.channels === 4 ? 6 : 2;
  return Buffer.concat([SIG, chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw, { level: o.level ?? 9 })), chunk("IEND", Buffer.alloc(0))]);
}

/** The image with its long side at most `max`, each new pixel the mean of the block it stands for. */
export function scaleDown(img: Decoded, max = LONG_SIDE_MAX): Decoded {
  const long = Math.max(img.width, img.height);
  if (long <= max) return img;
  const w = Math.max(1, Math.round((img.width * max) / long));
  const h = Math.max(1, Math.round((img.height * max) / long));
  const out = Buffer.alloc(w * h * img.channels);
  const ch = img.channels;
  for (let y = 0; y < h; y += 1) {
    const y0 = Math.floor((y * img.height) / h);
    const y1 = Math.max(y0 + 1, Math.floor(((y + 1) * img.height) / h));
    for (let x = 0; x < w; x += 1) {
      const x0 = Math.floor((x * img.width) / w);
      const x1 = Math.max(x0 + 1, Math.floor(((x + 1) * img.width) / w));
      const sum = [0, 0, 0, 0];
      let n = 0;
      for (let yy = y0; yy < y1; yy += 1) {
        let p = (yy * img.width + x0) * ch;
        for (let xx = x0; xx < x1; xx += 1, p += ch) {
          for (let c = 0; c < ch; c += 1) sum[c]! += img.pixels[p + c]!;
          n += 1;
        }
      }
      const o = (y * w + x) * ch;
      for (let c = 0; c < ch; c += 1) out[o + c] = Math.round(sum[c]! / n);
    }
  }
  return { width: w, height: h, channels: ch, pixels: out };
}

export type Scaled = { data: Buffer; from: { width: number; height: number; bytes: number }; to: { width: number; height: number; bytes: number } };

/** The smallest long side the byte target may take an image down to; past it the target is not met, and that is said. */
const LONG_SIDE_FLOOR = 256;

/**
 * A PNG for a model, with no library: at most `max` pixels on its long side and at most `maxBytes`, made smaller a
 * quarter at a time until it fits (a picture of noise does not fit at 1,568 pixels in any lossless form). Null when it
 * is within both already, or when this cannot read it.
 */
export function pngForModel(png: Buffer, o: { max?: number; maxBytes?: number } = {}): Scaled | null {
  const max = o.max ?? LONG_SIDE_MAX;
  const target = o.maxBytes ?? TARGET_BYTES;
  const head = pngSize(png);
  if (head && Math.max(head.width, head.height) <= max && png.length <= target) return null;
  const img = decodePng(png);
  if (!img) return null;
  const long = Math.max(img.width, img.height);
  if (long <= max && png.length <= target) return null;
  let side = Math.min(max, long);
  let small = scaleDown(img, side);
  let data = encodePng(small);
  while (data.length > target && side > LONG_SIDE_FLOOR) {
    side = Math.max(LONG_SIDE_FLOOR, Math.floor(side * 0.75));
    small = scaleDown(img, side);
    data = encodePng(small);
  }
  if (data.length >= png.length && long <= max) return null;
  return { data, from: { width: img.width, height: img.height, bytes: png.length }, to: { width: small.width, height: small.height, bytes: data.length } };
}

/** An image as the model is sent it, and from what. */
export type ForModel = Scaled & { mimeType: string; via: "pi-photon" | "png" };

/** The resizer Pi itself uses (Photon), or a stand-in; null for none (the PNG code here is used). */
export type Resizer = (bytes: Uint8Array, mimeType: string, options: { maxWidth: number; maxHeight: number; maxBytes: number }) => Promise<{ data: string; mimeType: string; originalWidth: number; originalHeight: number; width: number; height: number; wasResized: boolean } | null>;

/**
 * Every image a seat reads, for the model: at most `max` pixels on its long side and at most `maxBytes`, as PNG or
 * JPEG, whichever Pi's resizer finds under the bytes (it tries PNG first, then JPEG at falling quality, then smaller
 * sizes). Where the resizer cannot be loaded or cannot read the image, a PNG goes through the code above. Null when
 * the image is within both bounds already; `{ error }` when nothing here can make it so (a JPEG with no resizer), and
 * it goes to the model as it is.
 */
export async function imageForModel(bytes: Buffer, mimeType: string, o: { max?: number; maxBytes?: number; resize?: Resizer | null } = {}): Promise<ForModel | null | { error: string }> {
  const max = o.max ?? LONG_SIDE_MAX;
  const target = o.maxBytes ?? TARGET_BYTES;
  const head = mimeType === "image/png" ? pngSize(bytes) : mimeType === "image/jpeg" ? jpegSize(bytes) : null;
  if (head && Math.max(head.width, head.height) <= max && bytes.length <= target) return null;
  const resize = o.resize === undefined ? (resizeImage as unknown as Resizer) : o.resize;
  if (resize) {
    // Pi's resizer counts bytes as base64: a target of n bytes is 4n/3 of it.
    const r = await resize(bytes, mimeType, { maxWidth: max, maxHeight: max, maxBytes: Math.floor((target * 4) / 3) }).catch(() => null);
    if (r) {
      const data = Buffer.from(r.data, "base64");
      if (!r.wasResized && Math.max(r.width, r.height) <= max && data.length <= target) return null;
      if (Math.max(r.width, r.height) <= max && data.length <= target) {
        return { data, mimeType: r.mimeType, via: "pi-photon", from: { width: r.originalWidth, height: r.originalHeight, bytes: bytes.length }, to: { width: r.width, height: r.height, bytes: data.length } };
      }
    }
  }
  if (mimeType === "image/png") {
    const s = pngForModel(bytes, { max, maxBytes: target });
    return s ? { ...s, mimeType: "image/png", via: "png" } : null;
  }
  return { error: `the image (${mimeType}, ${bytes.length} bytes) could not be scaled here: Pi's image library did not load or could not read it, and only a PNG is read without it` };
}

/** Pi's own line under an image it resized (formatDimensionNote): the original's size and the size shown. */
const PI_DIMENSIONS = /\[Image: original (\d+)x(\d+), displayed at (\d+)x(\d+)\. Multiply coordinates by [\d.]+ to map to original image\.\]/;

type Part = Record<string, unknown>;
export type ReadScaled = { from: { width: number; height: number; bytes?: number }; to: { width: number; height: number; bytes: number }; mimeType: string; via: ForModel["via"] };

/**
 * The content of a `read` of an image, for the model: each image at most LONG_SIDE_MAX pixels on its long side and
 * TARGET_BYTES (imageForModel), under the file's own name. Pi's line on the size it showed is made to say the size now
 * shown and the factor to the original's pixels, and a line names the file the image is (`path`), unchanged on disk,
 * and image_crop for a region at full resolution. Null when nothing changed.
 */
export async function scaleReadImages(content: readonly Part[], o: { path?: string; fileBytes?: number; resize?: Resizer | null } = {}): Promise<{ content: Part[]; scaled: ReadScaled[]; unscaled: string[] } | null> {
  const piNote = content.find((p) => p?.type === "text" && typeof p.text === "string" && PI_DIMENSIONS.test(p.text as string));
  const pi = piNote ? PI_DIMENSIONS.exec(piNote.text as string) : null;
  const scaled: ReadScaled[] = [];
  const unscaled: string[] = [];
  const out: Part[] = [];
  for (const part of content) {
    if (part?.type !== "image" || typeof part.data !== "string") {
      out.push(part);
      continue;
    }
    const mimeType = typeof part.mimeType === "string" ? part.mimeType : "image/png";
    const r = await imageForModel(Buffer.from(part.data, "base64"), mimeType, o.resize === undefined ? {} : { resize: o.resize }).catch((err: Error) => ({ error: err.message }));
    if (!r) {
      out.push(part);
      continue;
    }
    if ("error" in r) {
      unscaled.push(r.error);
      out.push(part);
      continue;
    }
    // The original is the file, not what Pi had already made of it: Pi's line names the file's own size.
    const from = pi ? { width: Number(pi[1]), height: Number(pi[2]) } : { width: r.from.width, height: r.from.height };
    scaled.push({ from: { ...from, ...(o.fileBytes !== undefined ? { bytes: o.fileBytes } : {}) }, to: r.to, mimeType: r.mimeType, via: r.via });
    out.push({ ...part, data: r.data.toString("base64"), mimeType: r.mimeType });
  }
  if (!scaled.length && !unscaled.length) return null;
  const shown = scaled[0];
  // Pi's own first line names the type it sent, and its size line (when it resized) the size it showed: both say what is shown now.
  const next = out.map((p) => {
    if (!shown || p?.type !== "text" || typeof p.text !== "string") return p;
    let text = p.text.replace(/^Read image file \[[^\]]+\]/, `Read image file [${shown.mimeType}]`);
    if (p === piNote && pi) text = text.replace(PI_DIMENSIONS, `[Image: original ${shown.from.width}x${shown.from.height}, displayed at ${shown.to.width}x${shown.to.height}. Multiply coordinates by ${(shown.from.width / shown.to.width).toFixed(2)} to map to original image.]`);
    return text === p.text ? p : { ...p, text };
  });
  const name = o.path ? `${o.path}` : "the file you read";
  const lines: string[] = [];
  for (const s of scaled) {
    lines.push(`The image above is ${name}, scaled for viewing to ${s.to.width}x${s.to.height} (${s.to.bytes} bytes, ${s.mimeType}) from ${s.from.width}x${s.from.height}${s.from.bytes !== undefined ? ` (${s.from.bytes} bytes)` : ""}. The file itself is unchanged${o.path ? ` at ${o.path}` : ""}: cite it and crop it by that name. For detail too small to read here (small text, a code, single pixels), crop a region at full resolution with image_crop (a PNG; x and y in the original's pixels), or in a job for another format.`);
  }
  for (const e of unscaled) lines.push(`The image above is ${name} as it was read: ${e}.`);
  return { content: [...next, { type: "text", text: lines.join("\n") }], scaled, unscaled };
}

/** The most pixels a crop may hold (a 1568 x 1568 square): past it the crop is scaled down, and said. */
export const CROP_PIXELS_MAX = LONG_SIDE_MAX * LONG_SIDE_MAX;

export type Cropped = { png: Buffer; region: { x: number; y: number; width: number; height: number }; from: { width: number; height: number }; scaled_to?: { width: number; height: number } };

/**
 * A region of a PNG at its own resolution, for detail a scaled view loses (small text, a code, single pixels). The
 * region is clipped to the image; one that lies wholly outside it, or a file that is not a PNG this reads, is refused
 * with why. A region larger than CROP_PIXELS_MAX is scaled down to fit, and says so.
 */
export function cropPng(png: Buffer, r: { x: number; y: number; width: number; height: number }): Cropped | { error: string } {
  const img = decodePng(png);
  if (!img) return { error: "this is not a PNG that can be read here (another format, or a cut or corrupt PNG): crop it in a job" };
  const x0 = Math.max(0, Math.floor(r.x));
  const y0 = Math.max(0, Math.floor(r.y));
  const x1 = Math.min(img.width, Math.floor(r.x + r.width));
  const y1 = Math.min(img.height, Math.floor(r.y + r.height));
  if (x1 <= x0 || y1 <= y0) return { error: `the region (${r.x}, ${r.y}, ${r.width} x ${r.height}) lies outside the image, which is ${img.width} x ${img.height}` };
  const w = x1 - x0;
  const h = y1 - y0;
  const c = img.channels;
  const pixels = Buffer.alloc(w * h * c);
  for (let y = 0; y < h; y += 1) img.pixels.copy(pixels, y * w * c, ((y0 + y) * img.width + x0) * c, ((y0 + y) * img.width + x1) * c);
  let out: Decoded = { width: w, height: h, channels: c, pixels };
  let scaled_to: { width: number; height: number } | undefined;
  if (w * h > CROP_PIXELS_MAX) {
    out = scaleDown(out, LONG_SIDE_MAX);
    scaled_to = { width: out.width, height: out.height };
  }
  return { png: encodePng(out), region: { x: x0, y: y0, width: w, height: h }, from: { width: img.width, height: img.height }, ...(scaled_to ? { scaled_to } : {}) };
}
