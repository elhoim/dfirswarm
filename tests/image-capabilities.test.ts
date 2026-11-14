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
  else assert.deepEqual([good.ok, good.untested, good.said], [false, true, "tesseract is there, and no Pillow here renders the known line it is tested on: whether it reads text was not tested"]);
  stub(bin, "tesseract", 'echo "kn0wn answ3r 42l7"');
  const bad = runProbe(probeScript("iVBORw0KGgo="), bin).find((c) => c.id === "ocr")!;
  assert.equal(bad.ok, false, "a tesseract that only starts is not an OCR engine");
  if (hasPillow) assert.equal(bad.said, `tesseract is there and read the known line "${OCR_LINE}" as "kn0wn answ3r 42l7"`);
  const script = probeScript("iVBORw0KGgo=");
  assert.doesNotMatch(script, /tesseract --version/);
  assert.match(script, /tesseract ocr\.png stdout --psm 7/);
});

test("an OCR engine with no Pillow to render its test line is said NOT TESTED, never absent: not under DOES NOT, nor 'not there'", () => {
  // The probe's line, as an image without Pillow prints it, whatever this host has.
  const caps = readProbe(
    "cap image-read no no Pillow and no ImageMagick that reads a PNG\n" +
      "cap ocr untested tesseract is there, and no Pillow here renders the known line it is tested on: whether it reads text was not tested\n" +
      "cap brotli ok python3 brotli\n",
  );
  const ocr = caps.find((c) => c.id === "ocr")!;
  assert.deepEqual([ocr.ok, ocr.untested, ocr.by], [false, true, undefined]);
  const post = capabilitiesPost({ base: caps });
  assert.match(post, /- base: WORKS: inflate brotli \(python3 brotli\)\. DOES NOT: read a PNG's pixels: no Pillow and no ImageMagick that reads a PNG\. NOT TESTED \(not known either way\): read text from a picture: tesseract is there/);
  assert.doesNotMatch(post, /DOES NOT:[^.]*read text from a picture/);
  assert.match(post, /One NOT TESTED is not known either way: it is not missing/);
  // The script says untested for that case, and no for an image with no engine.
  const script = probeScript("iVBORw0KGgo=");
  assert.match(script, /say ocr untested "tesseract is there, and no Pillow here renders/);
  assert.match(script, /say ocr no "no OCR engine/);
  // Where Pillow is not on this host, the real probe says the same.
  if (!hasPillow) {
    const bin = mkdtempSync(join(tmpdir(), "imgcap-bin-"));
    stub(bin, "tesseract", `echo "${OCR_LINE}"`);
    const real = runProbe(script, bin).find((c) => c.id === "ocr")!;
    assert.deepEqual([real.ok, real.untested], [false, true]);
  }
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
  const D1 = `sha256:${"1".repeat(64)}`;
  const D2 = `sha256:${"2".repeat(64)}`;
  const digests = { disk: D1, re: `sha256:${"3".repeat(64)}` };
  await cacheCapabilities(cache, images, { disk: [{ id: "disasm-x86-64", what: "disassemble x86-64 code", ok: false, said: "objdump here disassembles only elf64-littleaarch64; no r2, no capstone" }], re: { error: "the probe job j000003 did not finish (cancelled)" } }, digests);
  assert.equal(cacheName(D1), `sha256_${"1".repeat(64)}.json`);
  const cached = JSON.parse(readFileSync(join(cache, cacheName(D1)), "utf8")) as { image: string; digest: string; capabilities: Capability[] };
  assert.deepEqual([cached.image, cached.digest], ["dfirswarm-disk:dev-arm64", D1]);
  assert.throws(() => readFileSync(join(cache, cacheName(digests.re))), "an image not tested whole is not cached");
  assert.throws(() => readFileSync(join(cache, "dfirswarm-disk_dev-arm64.json")), "the cache is not kept by the image's tag");
  // The image rebuilt under the same tag is another digest: the earlier run's result is not said to be its.
  const rebuilt = await seedCapabilities(sb, images, cache, { disk: D2 });
  assert.deepEqual(Object.keys(rebuilt.images as object), [], "a rebuilt image was shown an earlier image's result");
  const unknown = await seedCapabilities(sb, images, cache, {});
  assert.deepEqual(Object.keys(unknown.images as object), [], "an image whose digest is not known was shown a result");
  const seed = await seedCapabilities(sb, images, cache, digests);
  assert.equal(seed.pending, true);
  assert.deepEqual(Object.keys(seed.images as object), ["disk"]);
  assert.equal((seed.cached as Record<string, { digest: string }>).disk.digest, D1);
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
  // An untested capability reaches the contract as not known, never as absent.
  writeFileSync(join(sb, "job-capabilities.json"), JSON.stringify({ at: "2026-11-14T00:00:00Z", images: { disk: [{ id: "ocr", what: "read text from a picture", ok: false, untested: true, said: "tesseract is there, and no Pillow here renders the known line it is tested on: whether it reads text was not tested" }] } }));
  md = render();
  assert.match(md, /- disk: WORKS: none of the tested\. DOES NOT: none of the tested\. NOT TESTED \(not known either way\): read text from a picture: tesseract is there/);
});

test("the kickoff reads each job image's digest where it looks for the image, and hands the digests to the seed and the probe", () => {
  // plan_job_images as the kickoff runs it, with vm.ts's image-digest answered here: each image a digest of its own.
  const sh = join(ROOT, "scripts", "swarm.sh");
  const out = execFileSync(
    "bash",
    [
      "-c",
      `set -euo pipefail
eval "$(sed -n '/^vm_arch()/,/^}/p; /^vm_ref_for_profile()/,/^}/p; /^plan_job_images()/,/^}/p' "$1")"
vm_cli() { [ "$1 $2" = "image-digest --image" ] || return 1; printf '{"digest": "sha256:%064d"}\\n' "$(printf '%s' "$3" | cksum | cut -d' ' -f1)"; }
ROOT="$2"; start_agents=1; CHECK_ONLY=0; SWARM_IMAGES_LOCK=/nonexistent
plan_job_images "$2/packs/computer-forensics-base" "dfirswarm-core:dev-test"
printf '%s\\n%s\\n' "$job_images_json" "$job_image_digests_json"`,
      "_",
      sh,
      ROOT,
    ],
    { encoding: "utf8", cwd: tmpdir() },
  );
  const [images, digests] = out.trim().split("\n").map((l) => JSON.parse(l) as Record<string, string>);
  assert.ok(Object.keys(images!).length > 0, out);
  assert.deepEqual(Object.keys(digests!).sort(), Object.keys(images!).sort(), `every image the run has has its digest: ${out}`);
  for (const d of Object.values(digests!)) assert.match(d, /^sha256:[0-9a-f]{64}$/);
  if (Object.keys(images!).length > 1) assert.equal(new Set(Object.values(digests!)).size, new Set(Object.values(images!)).size, `each image its own digest: ${out}`);
  const body = readFileSync(sh, "utf8");
  assert.match(body, /image-capabilities\.ts" "\$sandbox" --seed --images "\$images" --digests "\$digests"/);
  assert.match(body, /--images "\$images" --digests "\$digests" --cache "\$\(image_capabilities_cache\)" > >\(log_stamper/);
});
