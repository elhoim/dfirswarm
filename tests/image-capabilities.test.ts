/**
 * What each job image can do is found by known-answer probes and told to the seats.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { cacheCapabilities, cacheName, capabilitiesPost, OCR_LINE, probeImages, probeScript, readProbe, seedCapabilities, withPackTools, type Capability } from "../scripts/image-capabilities.ts";
import { probeQrBase64, type HubCall } from "../scripts/supply-probe.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The probe script run on this host with `bin` first on PATH (stand-ins for programs), in a fresh $OUT. */
function runProbe(script: string, bin: string): Capability[] {
  const dir = mkdtempSync(join(tmpdir(), "imgcap-"));
  writeFileSync(join(dir, "probe.sh"), script);
  const out = execFileSync("bash", [join(dir, "probe.sh")], { cwd: dir, env: { ...process.env, OUT: dir, PATH: `${bin}:${process.env.PATH}` }, encoding: "utf8", timeout: 180_000 });
  return readProbe(out);
}
const stub = (bin: string, name: string, body: string) => {
  writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
  chmodSync(join(bin, name), 0o755);
};
const hasPillow = (() => {
  try {
    execFileSync("python3", ["-c", "import PIL"], { stdio: "ignore", cwd: tmpdir() });
    return true;
  } catch {
    return false;
  }
})();

test("the probe script is valid shell and answers one line a capability on this host, whatever it holds", () => {
  const dir = mkdtempSync(join(tmpdir(), "imgcap-"));
  const script = join(dir, "probe.sh");
  writeFileSync(script, probeScript("iVBORw0KGgo="));
  execFileSync("bash", ["-n", script]);
  const out = execFileSync("bash", [script], { env: { ...process.env, OUT: dir }, encoding: "utf8", timeout: 120_000 });
  const caps = readProbe(out);
  assert.deepEqual(caps.map((c) => c.id), ["disasm-x86-64", "qr-decode", "video-decode", "image-read", "ocr", "brotli", "numpy", "compile-c", "crypto-lib"]);
  for (const c of caps) assert.ok(c.ok ? Boolean(c.by) : Boolean(c.said), `${c.id} says with what, or why not`);
});

test("one probe job per image; the post says what works with what and what does not; an image that could not be probed says so", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [];
  const call: HubCall = async (fn, arg) => {
    calls.push([fn, arg]);
    if (fn === "jobSubmit") return arg.profile === "mobile" ? { ok: false, reason: "no job image for profile mobile" } : { ok: true, job: { job: arg.profile === "disk" ? "j000002" : "j000003" } };
    return arg.job_id === "j000002"
      ? { ok: true, job: { state: "committed" }, stdout: { text: "cap disasm-x86-64 no objdump here disassembles only elf64-littleaarch64; no r2, no capstone\ncap image-read ok python3 Pillow\ncap ocr no no OCR engine: text in a picture is read by eye (the read tool) only\n" } }
      : { ok: true, job: { state: "committed" }, stdout: { text: "cap disasm-x86-64 ok r2 -a x86 -b 64\ncap image-read ok python3 Pillow\n" } };
  };
  const r = await probeImages(call, ["disk", "re", "mobile"], { qr: "QUJD", sleep: async () => undefined });
  assert.deepEqual(calls.filter(([fn]) => fn === "jobSubmit").map(([, a]) => a.profile), ["disk", "re", "mobile"]);
  assert.ok(Array.isArray(r.disk) && Array.isArray(r.re) && !Array.isArray(r.mobile));
  const post = capabilitiesPost(r);
  assert.match(post, /- disk: WORKS: read a PNG's pixels \(python3 Pillow\)\. DOES NOT: disassemble x86-64 code: objdump here disassembles only elf64-littleaarch64; no r2, no capstone; read text from a picture: no OCR engine/);
  assert.match(post, /- re: WORKS: disassemble x86-64 code \(r2 -a x86 -b 64\)/);
  assert.match(post, /- mobile: not tested \(no job image for profile mobile\)/);
  assert.match(post, /your own VM is not a job image/);
  assert.ok(post.length < 2500);
});

test("a QR symbol the image's programs cannot read is read by the qr_read pack tool, and the probe says so rather than no", () => {
  const run = mkdtempSync(join(tmpdir(), "imgcap-run-"));
  mkdirSync(join(run, "tools", "qr_read"), { recursive: true });
  for (const f of ["run.py", "manifest.json"]) copyFileSync(join(ROOT, "packs", "computer-forensics-base", "tools", "qr_read", f), join(run, "tools", "qr_read", f));
  const bin = mkdtempSync(join(tmpdir(), "imgcap-bin-"));
  stub(bin, "zbarimg", 'echo "zbarimg: no decode delegate for this image format" >&2; exit 2');
  const caps = runProbe(probeScript(probeQrBase64(), { runRoot: run }), bin);
  const qr = caps.find((c) => c.id === "qr-decode")!;
  assert.equal(qr.ok, true, `the pack tool did not read the probe: ${qr.said}`);
  assert.equal(qr.by, "the qr_read pack tool (job_run tool: qr_read)");
  // With no pack tool in the run, a "no" names that too (a host with cv2 or pyzbar says ok, by them).
  const bare = runProbe(probeScript(probeQrBase64()), bin).find((c) => c.id === "qr-decode")!;
  if (!bare.ok) assert.equal(bare.said, "no program here decodes a QR symbol from a PNG, and this run has no qr_read pack tool");
  else assert.match(String(bare.by), /^python3 (cv2|pyzbar)$/);
});

test("OCR is a known-answer test: a rendered line read back whole passes, a wrong reading does not, and no engine is said", () => {
  const bin = mkdtempSync(join(tmpdir(), "imgcap-bin-"));
  stub(bin, "tesseract", `test -s "$1" || exit 3; echo "${OCR_LINE}"`);
  const good = runProbe(probeScript("iVBORw0KGgo="), bin).find((c) => c.id === "ocr")!;
  if (hasPillow) assert.deepEqual([good.ok, good.by], [true, "tesseract"]);
  else assert.equal(good.said, "tesseract is there; no Pillow here renders the known line it is tested on, so it was not tested");
  stub(bin, "tesseract", 'echo "kn0wn answ3r 42l7"');
  const bad = runProbe(probeScript("iVBORw0KGgo="), bin).find((c) => c.id === "ocr")!;
  assert.equal(bad.ok, false, "a tesseract that only starts is not an OCR engine");
  if (hasPillow) assert.equal(bad.said, `tesseract is there and read the known line "${OCR_LINE}" as "kn0wn answ3r 42l7"`);
  const script = probeScript("iVBORw0KGgo=");
  assert.doesNotMatch(script, /tesseract --version/);
  assert.match(script, /tesseract ocr\.png stdout --psm 7/);
});

test("a real tesseract reads the probe's rendered line, where this host has one and Pillow", (t) => {
  try {
    execFileSync("sh", ["-c", "command -v tesseract"], { stdio: "ignore" });
  } catch {
    t.skip("no tesseract on this host");
    return;
  }
  if (!hasPillow) {
    t.skip("no Pillow for this host's python3");
    return;
  }
  const ocr = runProbe(probeScript("iVBORw0KGgo="), mkdtempSync(join(tmpdir(), "imgcap-bin-"))).find((c) => c.id === "ocr")!;
  assert.deepEqual([ocr.ok, ocr.by, ocr.said], [true, "tesseract", undefined]);
});

test("where a pack tool reads it in one image, no image is said to lack it; the post and the contract say so", () => {
  const r = withPackTools({
    base: [{ id: "qr-decode", what: "decode a QR symbol from a PNG", ok: true, by: "the qr_read pack tool (job_run tool: qr_read)" }],
    re: [{ id: "qr-decode", what: "decode a QR symbol from a PNG", ok: false, said: "no program in this image decodes a QR symbol from a PNG, and the qr_read pack tool could not read the test symbol here" }, { id: "ocr", what: "read text from a picture", ok: false, said: "no OCR engine" }],
    mobile: { error: "not accepted" },
  });
  const re = r.re as Capability[];
  assert.equal(re[0]!.ok, true);
  assert.equal(re[0]!.by, "the qr_read pack tool, which job_run tool: qr_read runs in its own pack's image");
  assert.match(String(re[0]!.in_this_image), /^no program in this image/);
  assert.equal(re[1]!.ok, false, "a capability no pack tool gives stays no");
  const post = capabilitiesPost(r);
  assert.doesNotMatch(post, /decode a QR symbol from a PNG: no program/);
  assert.match(post, /- re: WORKS: decode a QR symbol from a PNG \(the qr_read pack tool, which job_run tool: qr_read runs in its own pack's image\)\. DOES NOT: read text from a picture: no OCR engine\./);
});

test("the seed puts an earlier run's result for the same image into SWARM.md before a seat reads it, said pending; this run's result replaces it", async () => {
  const sb = mkdtempSync(join(tmpdir(), "imgcap-sb-"));
  const cache = mkdtempSync(join(tmpdir(), "imgcap-cache-"));
  const images = { disk: "dfirswarm-disk:dev-arm64", re: "dfirswarm-re:dev-arm64" };
  await cacheCapabilities(cache, images, { disk: [{ id: "disasm-x86-64", what: "disassemble x86-64 code", ok: false, said: "objdump here disassembles only elf64-littleaarch64; no r2, no capstone" }], re: { error: "the probe job j000003 did not finish (cancelled)" } });
  assert.equal(cacheName("dfirswarm-disk:dev-arm64"), "dfirswarm-disk_dev-arm64.json");
  const cached = JSON.parse(readFileSync(join(cache, "dfirswarm-disk_dev-arm64.json"), "utf8")) as { image: string; capabilities: Capability[] };
  assert.equal(cached.image, "dfirswarm-disk:dev-arm64");
  assert.throws(() => readFileSync(join(cache, "dfirswarm-re_dev-arm64.json")), "an image not tested whole is not cached");
  const seed = await seedCapabilities(sb, images, cache);
  assert.equal(seed.pending, true);
  assert.deepEqual(Object.keys(seed.images as object), ["disk"]);
  const goal = join(sb, "goal.md");
  writeFileSync(goal, "## Goal\n\nx\n\n## Definition of done\n\nd\n");
  const render = () => {
    execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "render-contract.ts"), join(ROOT, "prompts", "swarm.md.template"), join(sb, "SWARM.md"), goal, "`a0`", "5", "60", "1", "sw1", sb]);
    return readFileSync(join(sb, "SWARM.md"), "utf8");
  };
  let md = render();
  assert.match(md, /^## Job image capabilities$/m);
  assert.match(md, /As an earlier run of the same image found it \(disk \d{4}-/);
  assert.match(md, /- disk: WORKS: none of the tested\. DOES NOT: disassemble x86-64 code: objdump here disassembles only elf64-littleaarch64; no r2, no capstone\./);
  assert.match(md, /This run's own result is posted to everyone on the board as JOB IMAGE CAPABILITIES/);
  // No cache: the section says the result is coming, and where.
  await seedCapabilities(sb, images, null);
  md = render();
  assert.match(md, /The result is posted to everyone on the board as JOB IMAGE CAPABILITIES within minutes of the start, and written to `job-capabilities\.json`; it is not in yet\./);
  // This run's result: no pending words, its own lines.
  writeFileSync(join(sb, "job-capabilities.json"), JSON.stringify({ at: "2026-11-14T00:00:00Z", images: { disk: [{ id: "ocr", what: "read text from a picture", ok: true, by: "tesseract" }] } }));
  md = render();
  assert.match(md, /- disk: WORKS: read text from a picture \(tesseract\)\. DOES NOT: none of the tested\./);
  assert.doesNotMatch(md, /earlier run|not in yet/);
});
