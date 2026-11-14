/**
 * An image a seat reads is made small enough to look at before it goes to
 * the model; what cannot be read is left alone.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import { decodePng, encodePng, imageForModel, jpegSize, LONG_SIDE_MAX, pngForModel, scaleDown, scaleReadImages, TARGET_BYTES, type Decoded } from "../extensions/png-scale.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function gradient(w: number, h: number, channels: 3 | 4): Decoded {
  const pixels = Buffer.alloc(w * h * channels);
  for (let y = 0; y < h; y += 1) for (let x = 0; x < w; x += 1) {
    const o = (y * w + x) * channels;
    pixels[o] = (x * 7 + y * 3) & 0xff; pixels[o + 1] = (x * 13) & 0xff; pixels[o + 2] = (y * 11 + x) & 0xff;
    if (channels === 4) pixels[o + 3] = 255 - (x & 0x7f);
  }
  return { width: w, height: h, channels, pixels };
}

/** A picture that changes slowly, as a photograph or a rendering mostly does. */
function smooth(w: number, h: number): Decoded {
  const pixels = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y += 1) for (let x = 0; x < w; x += 1) {
    const o = (y * w + x) * 3;
    pixels[o] = Math.round((x * 255) / w); pixels[o + 1] = Math.round((y * 255) / h); pixels[o + 2] = 128;
  }
  return { width: w, height: h, channels: 3, pixels };
}

/** Pixels with no pattern a compressor can find: the worst case for the bytes. */
function noise(w: number, h: number, channels: 3 | 4): Decoded {
  const pixels = Buffer.alloc(w * h * channels);
  let x = 0x9e3779b9;
  for (let i = 0; i < pixels.length; i += 1) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    pixels[i] = x & 0xff;
  }
  return { width: w, height: h, channels, pixels };
}

/** A PNG of the pixels with no filter (each row's filter byte 0), for the size a filter saves. */
function unfiltered(img: Decoded): Buffer {
  const stride = img.width * img.channels;
  const raw = Buffer.alloc((stride + 1) * img.height);
  for (let y = 0; y < img.height; y += 1) img.pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  return pngOf(img.width, img.height, 8, img.channels === 4 ? 6 : 2, 0, raw);
}

function pngOf(w: number, h: number, depth: number, type: number, interlace: number, raw: Buffer, extra: Buffer[] = []): Buffer {
  const chunk = chunkOf;
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = depth; ihdr[9] = type; ihdr[12] = interlace;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), ...extra, chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

/**
 * A PNG written the way another program would: any depth and colour type, plain or interlaced (Adam7), filter 0. `sample`
 * gives a pixel's samples as the format stores them (for 16 bits, high byte then low byte of each).
 */
function rawPng(w: number, h: number, depth: number, type: number, sample: (x: number, y: number) => number[], o: { interlace?: 0 | 1; palette?: Buffer; trns?: Buffer } = {}): Buffer {
  const passes = o.interlace ? [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]] : [[0, 0, 1, 1]];
  const perPixel = depth >= 8 ? null : depth;
  const parts: Buffer[] = [];
  for (const [px, py, dx, dy] of passes) {
    const pw = Math.ceil((w - px!) / dx!), ph = Math.ceil((h - py!) / dy!);
    if (pw <= 0 || ph <= 0) continue;
    for (let j = 0; j < ph; j += 1) {
      const samples: number[] = [];
      for (let i = 0; i < pw; i += 1) samples.push(...sample(px! + i * dx!, py! + j * dy!));
      let row: Buffer;
      if (perPixel) {
        row = Buffer.alloc(Math.ceil((samples.length * perPixel) / 8));
        samples.forEach((v, k) => { const bit = k * perPixel; row[bit >> 3] |= v << (8 - perPixel - (bit & 7)); });
      } else row = Buffer.from(samples);
      parts.push(Buffer.from([0]), row);
    }
  }
  const extra: Buffer[] = [];
  if (o.palette) extra.push(chunkOf("PLTE", o.palette));
  if (o.trns) extra.push(chunkOf("tRNS", o.trns));
  return pngOf(w, h, depth, type, o.interlace ?? 0, Buffer.concat(parts), extra);
}

function chunkOf(name: string, body: Buffer): Buffer {
  const crcT = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  let c = 0xffffffff;
  const head = Buffer.alloc(8); head.writeUInt32BE(body.length, 0); head.write(name, 4, "latin1");
  for (const v of Buffer.concat([head.subarray(4), body])) c = crcT[(c ^ v) & 0xff]! ^ (c >>> 8);
  const tail = Buffer.alloc(4); tail.writeUInt32BE((c ^ 0xffffffff) >>> 0, 0);
  return Buffer.concat([head, body, tail]);
}

test("what is written is read back pixel for pixel, with and without alpha", () => {
  for (const ch of [3, 4] as const) {
    const img = gradient(37, 23, ch);
    const back = decodePng(encodePng(img));
    assert.ok(back);
    assert.deepEqual([back!.width, back!.height, back!.channels], [37, 23, ch]);
    assert.ok(back!.pixels.equals(img.pixels));
  }
});

test("a PNG written by another program is read: a QR symbol from the generator (grey, filter 0) keeps its modules after scaling", () => {
  const dir = mkdtempSync(join(tmpdir(), "pngscale-"));
  execFileSync("python3", ["-I", join(ROOT, "scripts", "lib", "qrgen.py"), "dfirswarm-probe", join(dir, "q.png"), "--scale", "100"]);
  const png = readFileSync(join(dir, "q.png"));
  const img = decodePng(png)!;
  assert.deepEqual([img.width, img.height, img.channels], [2900, 2900, 3]);
  const small = scaleDown(img);
  assert.equal(Math.max(small.width, small.height), LONG_SIDE_MAX);
  // The centre of the top-left finder is dark, the quiet zone is light, in both.
  const at = (d: Decoded, fx: number, fy: number) => d.pixels[(Math.floor(fy * d.height) * d.width + Math.floor(fx * d.width)) * d.channels]!;
  for (const d of [img, small]) {
    assert.ok(at(d, 7.5 / 29, 7.5 / 29) < 40, "finder centre dark");
    assert.ok(at(d, 1 / 29, 1 / 29) > 215, "quiet zone light");
  }
});

test("a PNG is brought within 1,568 pixels and 300 KB without a library: a large one, a small-in-pixels but heavy one; a small one, a JPEG and a broken file are left alone", () => {
  const big = encodePng(gradient(3200, 1800, 3));
  const s = pngForModel(big)!;
  assert.ok(s, "scaled");
  assert.deepEqual([s.from.width, s.from.height], [3200, 1800]);
  assert.deepEqual([s.to.width, s.to.height], [1568, 882]);
  assert.ok(s.to.bytes <= TARGET_BYTES, `${s.to.bytes} bytes`);
  assert.ok(decodePng(s.data), "what comes out is a PNG this reads");
  // 1,200 pixels of noise: within the long side, far over the bytes. It used to pass whole at any size.
  const heavy = encodePng(noise(1200, 1200, 3));
  assert.ok(heavy.length > 3 * TARGET_BYTES);
  const h = pngForModel(heavy)!;
  assert.ok(h && h.to.bytes <= TARGET_BYTES && Math.max(h.to.width, h.to.height) < 1200, JSON.stringify(h?.to));
  assert.equal(pngForModel(encodePng(gradient(800, 600, 3))), null, "already small in pixels and bytes");
  assert.equal(pngForModel(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(400_000)])), null, "a JPEG is not read here");
  assert.equal(pngForModel(Buffer.concat([big.subarray(0, 60), Buffer.alloc(400_000)])), null, "a PNG cut short");
  assert.equal(decodePng(Buffer.alloc(10)), null);
  // The writer chooses a filter a row at a time: a picture is far smaller than with none.
  assert.ok(encodePng(gradient(800, 600, 3)).length < unfiltered(gradient(800, 600, 3)).length / 2);
});

test("every PNG the format allows is read: 16-bit, 1, 2 and 4-bit grey and palette, grey with alpha, and interlaced", () => {
  const w = 37, h = 23;
  const rgb16 = (x: number, y: number) => [(x * 7) & 0xff, (y * 11) & 0xff, (x + y) & 0xff];
  // 16-bit RGB: each sample's high byte is the 8-bit value, the low byte noise.
  for (const interlace of [0, 1] as const) {
    const png = rawPng(w, h, 16, 2, (x, y) => rgb16(x, y).flatMap((v) => [v, (x * 31 + y) & 0xff]), { interlace });
    const d = decodePng(png)!;
    assert.ok(d, `16-bit, interlace ${interlace}`);
    assert.deepEqual([d.width, d.height, d.channels], [w, h, 3]);
    for (const [x, y] of [[0, 0], [36, 22], [5, 17], [20, 3]] as const) assert.deepEqual([...d.pixels.subarray((y * w + x) * 3, (y * w + x) * 3 + 3)], rgb16(x, y), `16-bit (${x}, ${y}), interlace ${interlace}`);
  }
  // 8-bit RGBA, interlaced: pixel for pixel.
  const rgba = (x: number, y: number) => [(x * 5) & 0xff, (y * 9) & 0xff, (x ^ y) & 0xff, (255 - x) & 0xff];
  const ai = decodePng(rawPng(w, h, 8, 6, rgba, { interlace: 1 }))!;
  assert.ok(ai && ai.channels === 4);
  for (let y = 0; y < h; y += 1) for (let x = 0; x < w; x += 1) assert.deepEqual([...ai.pixels.subarray((y * w + x) * 4, (y * w + x) * 4 + 4)], rgba(x, y), `RGBA interlaced (${x}, ${y})`);
  // Grey at 1, 2 and 4 bits, spread over 0 to 255.
  for (const depth of [1, 2, 4] as const) {
    const top = (1 << depth) - 1;
    for (const interlace of [0, 1] as const) {
      const d = decodePng(rawPng(w, h, depth, 0, (x, y) => [(x + y) % (top + 1)], { interlace }))!;
      assert.ok(d, `grey ${depth}-bit`);
      for (const [x, y] of [[0, 0], [36, 22], [9, 4]] as const) assert.equal(d.pixels[(y * w + x) * 3], Math.round((((x + y) % (top + 1)) * 255) / top), `grey ${depth}-bit (${x}, ${y}), interlace ${interlace}`);
    }
  }
  // A 2-bit palette with transparency.
  const palette = Buffer.from([255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9]);
  const p = decodePng(rawPng(w, h, 2, 3, (x, y) => [(x * 3 + y) % 4], { palette, trns: Buffer.from([255, 128, 0]) }))!;
  assert.ok(p && p.channels === 4);
  const at = (x: number, y: number) => [...p.pixels.subarray((y * w + x) * 4, (y * w + x) * 4 + 4)];
  assert.deepEqual(at(0, 0), [255, 0, 0, 255]);
  assert.deepEqual(at(0, 1), [0, 255, 0, 128]);
  assert.deepEqual(at(0, 2), [0, 0, 255, 0]);
  assert.deepEqual(at(1, 0), [9, 9, 9, 255], "an index past tRNS is opaque");
  // Grey with alpha at 16 bits.
  const ga = decodePng(rawPng(w, h, 16, 4, (x, y) => [x, 0, y, 0]))!;
  assert.deepEqual([...ga.pixels.subarray((5 * w + 7) * 4, (5 * w + 7) * 4 + 4)], [7, 7, 7, 5]);
});

test("every image a seat reads is brought within 1,568 pixels and 300 KB: PNG of every kind, JPEG, through Pi's own image library", async () => {
  const pi = (await import("@earendil-works/pi-coding-agent")).resizeImage;
  // A JPEG of 2,400 pixels, written by Pi's library (there is no JPEG writer here): noise has no PNG under 8 MB.
  const made = await pi(encodePng(noise(2400, 1600, 3)), "image/png", { maxWidth: 2400, maxHeight: 2400, maxBytes: 8 * 1024 * 1024 });
  assert.equal(made?.mimeType, "image/jpeg");
  const jpeg = Buffer.from(made!.data, "base64");
  assert.deepEqual(jpegSize(jpeg), { width: 2400, height: 1600 });
  const images: Array<[string, Buffer, string]> = [
    ["a large PNG of noise", encodePng(noise(3000, 2000, 3)), "image/png"],
    ["a 1,200-pixel PNG of 4 MB", encodePng(noise(1200, 1200, 3)), "image/png"],
    ["a JPEG of 2,400 pixels", jpeg, "image/jpeg"],
    ["a 16-bit PNG", rawPng(2000, 1500, 16, 2, (x, y) => [x & 0xff, x >> 8, y & 0xff, y >> 8, (x ^ y) & 0xff, 0]), "image/png"],
    ["an interlaced PNG", rawPng(1900, 1700, 8, 2, (x, y) => [(x * 3) & 0xff, (y * 5) & 0xff, ((x * y) >> 4) & 0xff], { interlace: 1 }), "image/png"],
  ];
  const sizes: number[] = [];
  for (const [what, bytes, mime] of images) {
    const r = await imageForModel(bytes, mime);
    assert.ok(r && !("error" in r), `${what}: ${JSON.stringify(r)}`);
    if (!r || "error" in r) continue;
    assert.ok(Math.max(r.to.width, r.to.height) <= LONG_SIDE_MAX, `${what}: ${r.to.width}x${r.to.height}`);
    assert.ok(r.data.length <= TARGET_BYTES, `${what}: ${r.data.length} bytes`);
    assert.equal(r.via, "pi-photon");
    sizes.push(r.data.length);
  }
  sizes.sort((a, b) => a - b);
  assert.ok(sizes[Math.floor(sizes.length / 2)]! < TARGET_BYTES, "the median image is under 300 KB");
  assert.equal(await imageForModel(encodePng(gradient(800, 600, 3)), "image/png"), null, "within both bounds: as it is");
  // Without Pi's library: a PNG of any kind through the code here, a JPEG said and left.
  for (const [what, bytes] of [["16-bit", images[3]![1]], ["interlaced", images[4]![1]]] as const) {
    const r = await imageForModel(bytes, "image/png", { resize: null });
    assert.ok(r && !("error" in r) && r.via === "png" && r.data.length <= TARGET_BYTES && Math.max(r.to.width, r.to.height) <= LONG_SIDE_MAX, `${what} without the library: ${JSON.stringify(r && !("error" in r) ? r.to : r)}`);
  }
  const lone = await imageForModel(jpeg, "image/jpeg", { resize: null });
  assert.ok(lone && "error" in lone && /only a PNG is read without it/.test(lone.error));
});

test("a read's content: the image scaled under the file's own name, Pi's size line made true, and image_crop named", async () => {
  const big = encodePng(smooth(2000, 1500));
  const content = [{ type: "text", text: "Read image file [image/png]\n[Image: original 4000x3000, displayed at 2000x1500. Multiply coordinates by 2.00 to map to original image.]" }, { type: "image", data: big.toString("base64"), mimeType: "image/png" }];
  const out = await scaleReadImages(content, { path: "store/jobs/j000004/out/sheet-01.png", fileBytes: 9_000_000 });
  assert.ok(out);
  const image = out!.content.find((p) => p.type === "image")!;
  const shown = Buffer.from(String(image.data), "base64");
  assert.ok(shown.length <= TARGET_BYTES);
  const text = out!.content.filter((p) => p.type === "text").map((p) => String(p.text)).join("\n");
  assert.match(text, /\[Image: original 4000x3000, displayed at 1568x1176\. Multiply coordinates by 2\.55 to map to original image\.\]/, "Pi's line says what is shown now");
  assert.match(text, /The image above is store\/jobs\/j000004\/out\/sheet-01\.png, scaled for viewing to 1568x1176 \(\d+ bytes, image\/(png|jpeg)\) from 4000x3000 \(9000000 bytes\)\. The file itself is unchanged at store\/jobs\/j000004\/out\/sheet-01\.png: cite it and crop it by that name\./);
  assert.match(text, /image_crop \(a PNG; x and y in the original's pixels\)/);
  assert.equal(await scaleReadImages([{ type: "text", text: "Read image file [image/png]" }, { type: "image", data: encodePng(gradient(300, 200, 3)).toString("base64"), mimeType: "image/png" }]), null, "a small image: nothing to change");
});

test("Pi loader: an image a seat reads reaches the model within 1,568 pixels and 300 KB, named by its file", async (t) => {
  const REPO = join(ROOT);
  const loader = join(process.env.PI_PACKAGE_DIR ?? join(REPO, "node_modules", "@earendil-works", "pi-coding-agent"), "dist", "core", "extensions", "loader.js");
  const { existsSync } = await import("node:fs");
  if (!existsSync(loader)) return t.skip("Pi package not found");
  const { initSandbox } = await import("../extensions/protocol.ts");
  const S = mkdtempSync(join(tmpdir(), "pngscale-hook-"));
  await initSandbox(S, { reset: true, agentIds: ["agent00"] });
  const keys = ["AGENT_ID", "SWARM_BOARD_SOCKET", "SWARM_TRACE_SOCKET", "SWARM_SELF_COMPACT", "SWARM_IMAGE_SCALE"];
  const was = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.AGENT_ID = "agent00";
  for (const k of keys.slice(1)) delete process.env[k];
  try {
    const { loadExtensions } = (await import(loader)) as { loadExtensions: (paths: string[], cwd: string) => Promise<{ extensions: Array<{ handlers: Map<string, Array<(e: unknown, c: unknown) => Promise<unknown>>> }>; errors: unknown[] }> };
    const out = await loadExtensions([join(REPO, "extensions", "agent-swarm.ts")], S);
    assert.deepEqual(out.errors, []);
    const ctx = { cwd: S, hasUI: false, ui: {}, abort: () => undefined, shutdown: () => undefined };
    const png = encodePng(noise(1500, 1100, 3));
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(join(S, "work", "agent00"), { recursive: true });
    writeFileSync(join(S, "work", "agent00", "frame.png"), png);
    const content = [{ type: "text", text: "Read image file [image/png]" }, { type: "image", data: png.toString("base64"), mimeType: "image/png" }];
    let result: { content?: Array<Record<string, unknown>> } | undefined;
    for (const h of out.extensions[0]!.handlers.get("tool_result") ?? []) result = ((await h({ type: "tool_result", toolName: "read", toolCallId: "r1", input: { path: "work/agent00/frame.png" }, content, isError: false }, ctx)) as typeof result) ?? result;
    const parts = result?.content ?? [];
    const image = parts.find((p) => p.type === "image");
    assert.ok(image, "the image is still there");
    const shown = Buffer.from(String(image!.data), "base64");
    assert.ok(shown.length <= TARGET_BYTES, `${shown.length} bytes reach the model (the file is ${png.length})`);
    assert.equal(parts[0]!.text, `Read image file [${image!.mimeType}]`, "Pi's line names the type the model is sent");
    const size = image!.mimeType === "image/png" ? decodePng(shown) : jpegSize(shown);
    assert.ok(size && Math.max(size.width, size.height) <= LONG_SIDE_MAX);
    assert.match(parts.map((p) => String(p.text ?? "")).join("\n"), new RegExp(`The image above is work/agent00/frame\\.png, scaled for viewing .* from 1500x1100 \\(${png.length} bytes\\)`));
  } finally {
    for (const [k, v] of Object.entries(was)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test("a crop is the region at the original's resolution, clipped to the image; a large one is scaled and says so; one outside the image is refused", async () => {
  const { cropPng, decodePng, encodePng, CROP_PIXELS_MAX } = await import("../extensions/png-scale.ts");
  const w = 300, h = 200;
  const px = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y += 1) for (let x = 0; x < w; x += 1) px.set([x % 256, y % 256, (x + y) % 256], (y * w + x) * 3);
  const png = encodePng({ width: w, height: h, channels: 3, pixels: px });
  const c = cropPng(png, { x: 10, y: 20, width: 5, height: 4 });
  assert.ok(!("error" in c));
  if ("error" in c) return;
  assert.deepEqual([c.region, c.from, c.scaled_to], [{ x: 10, y: 20, width: 5, height: 4 }, { width: w, height: h }, undefined]);
  const d = decodePng(c.png)!;
  assert.deepEqual([...d.pixels.subarray(0, 3)], [10, 20, 30], "the crop's first pixel is the original's (10, 20)");
  assert.deepEqual([...d.pixels.subarray((3 * 5 + 4) * 3, (3 * 5 + 4) * 3 + 3)], [14, 23, 37], "and its last is (14, 23)");
  const clipped = cropPng(png, { x: 290, y: 190, width: 50, height: 50 });
  assert.ok(!("error" in clipped) && clipped.region.width === 10 && clipped.region.height === 10);
  const outside = cropPng(png, { x: 400, y: 0, width: 5, height: 5 });
  assert.ok("error" in outside && /lies outside the image, which is 300 x 200/.test(outside.error));
  assert.ok("error" in cropPng(Buffer.from("not a png"), { x: 0, y: 0, width: 1, height: 1 }));
  assert.ok(CROP_PIXELS_MAX >= 1568 * 1568);
  const big = encodePng({ width: 2000, height: 1600, channels: 3, pixels: Buffer.alloc(2000 * 1600 * 3, 7) });
  const scaled = cropPng(big, { x: 0, y: 0, width: 2000, height: 1600 });
  assert.ok(!("error" in scaled) && scaled.scaled_to && Math.max(scaled.scaled_to.width, scaled.scaled_to.height) <= 1568);
});
