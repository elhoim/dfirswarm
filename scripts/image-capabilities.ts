/**
 * What each job image of a run can do, found by known-answer probes run in
 * a worker VM of that image right after kickoff, and told to the seats.
 *
 *   image-capabilities.ts <sandbox> --hub-admin SOCKET --profiles disk,re,full [--images JSON] [--digests JSON] [--cache DIR]
 *   image-capabilities.ts <sandbox> --seed --images JSON [--digests JSON] [--cache DIR]
 *
 * The seed (before the contract is rendered) writes job-capabilities.json as
 * pending, with what an earlier run found in each image of the same digest
 * (--cache, one file an image, named for its digest; --digests gives each
 * profile's, as the kickoff read it), so SWARM.md says what the images can do,
 * and that this run tests them again, before a seat reads it. An image rebuilt
 * under the same name is another image: an earlier run's result is not its.
 * The probe (started as soon as the hub is up, before the seats' VMs) writes
 * the result there and in the cache, and posts it to every seat.
 *
 * The seats of eight runs spent 25 to 30 jobs a run finding out what their
 * images held, and still believed wrong things: `objdump` is in every image
 * and disassembles only the image's own architecture (three runs decoded
 * x86-64 opcodes by hand); Pillow is in the job images and not in the seat
 * VM, where seats tested for it and then wrote PNG decoders; no image reads
 * text from a picture. The fixed toolbox table says a program is present, not
 * what it does. One job per image answers that, with an input whose answer
 * is known, and the answer goes on the board and into job-capabilities.json.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { probeQrBase64, PROBE_PAYLOAD, type HubCall } from "./supply-probe.ts";

/**
 * One capability of an image: `ok` when the known answer was read; `untested` (and not ok) when the probe could not
 * set up its test here (the OCR engine is there, and nothing renders the line it is tested on), which says nothing
 * of whether the image can do it; otherwise it does not, and `said` says why.
 */
export type Capability = { id: string; what: string; ok: boolean; untested?: boolean; by?: string; said?: string; in_this_image?: string };

/** The line the OCR probe renders and must read back. */
export const OCR_LINE = "known answer 4217";

const shq = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

/**
 * One shell script that tries each capability and prints a line `cap <id> <ok|no> <by or why>` for each.
 * `runRoot`: the run's directory, whose tools/ every job sees at that path: a pack tool that does the work (qr_read)
 * is tried there too, so that no image is said to lack what a pack tool gives.
 */
export function probeScript(qrPngBase64: string, o: { runRoot?: string } = {}): string {
  // x86-64 bytes for: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
  const X86 = "554889e531c05dc3";
  const qrTool = o.runRoot ? shq(join(o.runRoot, "tools", "qr_read", "run.py")) : "''";
  return [
    "set +e",
    'cd "$OUT" || exit 1',
    `printf %s '${qrPngBase64}' | base64 -d > probe.png`,
    `printf %s '${X86}' | xxd -r -p > code.bin 2>/dev/null || python3 -c "import sys;open('code.bin','wb').write(bytes.fromhex('${X86}'))"`,
    'say() { printf "cap %s %s %s\\n" "$1" "$2" "$3"; }',
    // disassembly of x86-64: any of objdump (multi-arch), radare2, capstone
    'd=""; if objdump -D -b binary -m i386:x86-64 code.bin 2>/dev/null | grep -q "push.*rbp"; then d="objdump -m i386:x86-64"; elif command -v r2 >/dev/null 2>&1 && r2 -q -a x86 -b 64 -c "pd 5" code.bin 2>/dev/null | grep -q "push rbp"; then d="r2 -a x86 -b 64"; elif python3 -c "import capstone;m=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);assert next(m.disasm(open(\'code.bin\',\'rb\').read(),0)).mnemonic==\'push\'" 2>/dev/null; then d="python3 capstone"; fi',
    'if [ -n "$d" ]; then say disasm-x86-64 ok "$d"; else say disasm-x86-64 no "objdump here disassembles only $(objdump -i 2>/dev/null | sed -n 2p | tr -d " " || echo its-own-architecture); no r2, no capstone"; fi',
    // A QR symbol: a program of the image, or the base pack's qr_read (standard library alone), whose payload file must hold the known answer.
    `q=${qrTool}; qr=""`,
    `if [ "$(zbarimg -q --raw probe.png 2>/dev/null)" = "${PROBE_PAYLOAD}" ]; then qr=zbarimg`,
    `elif [ -n "$q" ] && [ -f "$q" ] && printf '{"image": "%s"}' "$OUT/probe.png" | python3 "$q" > qr.json 2>/dev/null; p="$(find "$OUT" -name '*.payload.bin' 2>/dev/null | head -n 1)"; [ -n "$p" ] && [ "$(cat "$p")" = "${PROBE_PAYLOAD}" ]; then qr="the qr_read pack tool (job_run tool: qr_read)"`,
    `elif python3 -c "import cv2;d=cv2.QRCodeDetector();assert d.detectAndDecode(cv2.imread('probe.png'))[0]=='${PROBE_PAYLOAD}'" 2>/dev/null; then qr="python3 cv2"`,
    `elif python3 -c "from pyzbar.pyzbar import decode;from PIL import Image;assert decode(Image.open('probe.png'))[0].data==b'${PROBE_PAYLOAD}'" 2>/dev/null; then qr="python3 pyzbar"; fi`,
    'p="$(find "$OUT" -name \'*.payload.bin\' 2>/dev/null | head -n 1)"; [ -n "$p" ] && rm -rf "$(dirname "$p")"; rm -f qr.json',
    'if [ -n "$qr" ]; then say qr-decode ok "$qr"; elif [ -n "$q" ] && [ -f "$q" ]; then say qr-decode no "no program in this image decodes a QR symbol from a PNG, and the qr_read pack tool could not read the test symbol here (job_run tool: qr_read runs it in its own pack\'s image)"; else say qr-decode no "no program here decodes a QR symbol from a PNG, and this run has no qr_read pack tool"; fi',
    'if ffmpeg -v error -f lavfi -i testsrc=duration=1:size=64x64:rate=5 -c:v mpeg4 p.mp4 2>/dev/null && [ "$(ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 p.mp4 2>/dev/null)" = 5 ]; then say video-decode ok "ffmpeg, ffprobe"; else say video-decode no "no ffmpeg here that writes and reads back a clip"; fi',
    'if python3 -c "from PIL import Image;im=Image.open(\'probe.png\');assert im.size[0]>20" 2>/dev/null; then say image-read ok "python3 Pillow"; elif (magick probe.png probe.pnm || convert probe.png probe.pnm) 2>/dev/null; then say image-read ok ImageMagick; else say image-read no "no Pillow and no ImageMagick that reads a PNG"; fi',
    // OCR: a line rendered with Pillow (a scalable font where Pillow has one, else its bitmap font at four times), read back whole.
    "if command -v tesseract >/dev/null 2>&1; then",
    "  if python3 - <<'PY' 2>/dev/null",
    "from PIL import Image, ImageDraw, ImageFont",
    `t = ${JSON.stringify(OCR_LINE)}`,
    "try:",
    "    f = ImageFont.load_default(size=36)",
    "except Exception:",
    "    f = None",
    "if f is not None and f.getbbox(t)[3] >= 20:",
    "    l, tp, r, b = f.getbbox(t)",
    "    im = Image.new('L', (r + 40, b + 40), 255)",
    "    ImageDraw.Draw(im).text((20, 20), t, fill=0, font=f)",
    "else:",
    "    bf = ImageFont.load_default_imagefont() if hasattr(ImageFont, 'load_default_imagefont') else ImageFont.load_default()",
    "    im = Image.new('L', (16 + 6 * len(t), 24), 255)",
    "    ImageDraw.Draw(im).text((8, 6), t, fill=0, font=bf)",
    "    im = im.resize((im.width * 4, im.height * 4), Image.NEAREST)",
    "im.save('ocr.png')",
    "PY",
    "  then",
    `    o="$(tesseract ocr.png stdout --psm 7 2>/dev/null | tr -s ' \\n\\t' '   ' | sed 's/^ *//; s/ *$//')"`,
    `    if [ "$o" = "${OCR_LINE}" ]; then say ocr ok tesseract; else say ocr no "tesseract is there and read the known line \\"${OCR_LINE}\\" as \\"$o\\""; fi`,
    '  else say ocr untested "tesseract is there, and no Pillow here renders the known line it is tested on: whether it reads text was not tested"; fi',
    'else say ocr no "no OCR engine: text in a picture is read by eye (the read tool) only"; fi',
    'if python3 -c "import brotli;assert brotli.decompress(brotli.compress(b\'x\'))==b\'x\'" 2>/dev/null; then say brotli ok "python3 brotli"; else say brotli no "no brotli: a br-encoded cache body is not inflated here"; fi',
    'if python3 -c "import numpy" 2>/dev/null; then say numpy ok "python3 numpy"; else say numpy no "no numpy"; fi',
    'if command -v gcc >/dev/null 2>&1 && printf "int main(){return 0;}" > t.c && gcc t.c -o /tmp/t.out 2>/dev/null && /tmp/t.out; then say compile-c ok gcc; else say compile-c no "no working C compiler (and $OUT is no-exec: build under /tmp)"; fi',
    'if python3 -c "from Crypto.Cipher import ChaCha20" 2>/dev/null || python3 -c "from cryptography.hazmat.primitives.ciphers import algorithms" 2>/dev/null; then say crypto-lib ok "python3 cryptography or pycryptodome"; else say crypto-lib no "no Python crypto library: use the pack tools, or write the primitive"; fi',
    "rm -f probe.png code.bin p.mp4 probe.pnm t.c ocr.png",
    "exit 0",
  ].join("\n");
}

const WHAT: Record<string, string> = {
  "disasm-x86-64": "disassemble x86-64 code",
  "qr-decode": "decode a QR symbol from a PNG",
  "video-decode": "write and decode a video clip",
  "image-read": "read a PNG's pixels",
  ocr: "read text from a picture",
  brotli: "inflate brotli",
  numpy: "numpy",
  "compile-c": "compile and run C",
  "crypto-lib": "a Python crypto library",
};

/** The probe job's stdout, read: one capability per `cap` line; a capability with no line was not tried. */
export function readProbe(stdout: string): Capability[] {
  const out: Capability[] = [];
  for (const line of stdout.split("\n")) {
    const m = /^cap (\S+) (ok|no|untested) (.*)$/.exec(line.trim());
    if (!m) continue;
    out.push({ id: m[1]!, what: WHAT[m[1]!] ?? m[1]!, ok: m[2] === "ok", ...(m[2] === "untested" ? { untested: true } : {}), ...(m[2] === "ok" ? { by: m[3]!.trim() } : { said: m[3]!.trim() }) });
  }
  return out;
}

export type ByProfile = Record<string, Capability[] | { error: string }>;

/**
 * A capability a pack tool gives is the run's wherever a job runs: `job_run tool:` runs a pack tool in its own pack's
 * image. So where one image's probe read the known answer with a pack tool, an image that has no program for it is
 * not said to lack it: it is said to have it by that tool, and what this image alone holds is kept beside it.
 */
export function withPackTools(byProfile: ByProfile): ByProfile {
  const tool = new Map<string, string>();
  for (const caps of Object.values(byProfile)) {
    if (!Array.isArray(caps)) continue;
    for (const c of caps) {
      const m = c.ok ? /^the (\S+) pack tool/.exec(c.by ?? "") : null;
      if (m && !tool.has(c.id)) tool.set(c.id, m[1]!);
    }
  }
  const out: ByProfile = {};
  for (const [profile, caps] of Object.entries(byProfile)) {
    out[profile] = !Array.isArray(caps)
      ? caps
      : caps.map((c) => (c.ok || !tool.has(c.id) ? c : { id: c.id, what: c.what, ok: true, by: `the ${tool.get(c.id)} pack tool, which job_run tool: ${tool.get(c.id)} runs in its own pack's image`, in_this_image: c.said ?? "" }));
  }
  return out;
}

/** One line an image: what works and with what, what does not, and what could not be tested there (never said absent). */
export function capabilityLines(byProfile: ByProfile): string[] {
  return Object.entries(byProfile).map(([profile, caps]) => {
    if (!Array.isArray(caps)) return `- ${profile}: not tested (${caps.error})`;
    const yes = caps.filter((c) => c.ok).map((c) => `${c.what} (${c.by})`);
    const no = caps.filter((c) => !c.ok && !c.untested).map((c) => `${c.what}: ${c.said}`);
    const unknown = caps.filter((c) => !c.ok && c.untested).map((c) => `${c.what}: ${c.said}`);
    return `- ${profile}: WORKS: ${yes.join("; ") || "none of the tested"}. DOES NOT: ${no.join("; ") || "none of the tested"}.${unknown.length ? ` NOT TESTED (not known either way): ${unknown.join("; ")}.` : ""}`;
  });
}

/** The post the seats get: per image, what works and with what, what does not, and what was not tested. */
export function capabilitiesPost(byProfile: ByProfile): string {
  return `JOB IMAGE CAPABILITIES, each tested in a worker VM of that image with an input whose answer is known (job_run profile: <name> picks the image; your own VM is not a job image and holds less):\n${capabilityLines(byProfile).join("\n")}\nA capability that does not work in any image is not there: do not probe for it again, ask the operator for a program (a request), or use a pack tool that does not need it. One NOT TESTED is not known either way: it is not missing, try it on your own input in a job before you rely on it or say it is not there. The whole is in job-capabilities.json.`;
}

/**
 * The file name an image's cached result has: its digest (sha256:<hex>), with every character a file name cannot take
 * replaced. Never its reference: a tag names whatever was last built or pulled under it.
 */
export const cacheName = (digest: string) => `${digest.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;

const DIGEST = /^sha256:[0-9a-f]{64}$/;

type CacheEntry = { image: string; digest: string; profile: string; at: string; capabilities: Capability[] };

/**
 * job-capabilities.json before the probe: pending, with what an earlier run found in each image of the same digest
 * (`digests`, profile to digest, as the kickoff read it on this host; a profile with none has no earlier result). A
 * cached line is said to be an earlier run's (when, and which image) until this run's own result replaces it.
 */
export async function seedCapabilities(sandbox: string, images: Record<string, string>, cacheDir: string | null, digests: Record<string, string | null> = {}): Promise<Record<string, unknown>> {
  const cached: Record<string, { image: string; digest: string; tested_at: string }> = {};
  const found: ByProfile = {};
  for (const [profile, ref] of Object.entries(images)) {
    if (!cacheDir) break;
    const digest = digests[profile];
    if (!digest || !DIGEST.test(digest)) continue;
    const e = await readFile(join(cacheDir, cacheName(digest)), "utf8").then((t) => JSON.parse(t) as CacheEntry).catch(() => null);
    if (!e || e.digest !== digest || !Array.isArray(e.capabilities) || !e.capabilities.length) continue;
    found[profile] = e.capabilities;
    cached[profile] = { image: ref, digest, tested_at: String(e.at) };
  }
  const rec = { pending: true, seeded_at: new Date().toISOString(), profiles: Object.keys(images), images: found, cached };
  await writeFile(join(sandbox, "job-capabilities.json"), `${JSON.stringify(rec, null, 2)}\n`);
  return rec;
}

/** Each image's result kept for the next run of the same image, by its digest (only what was tested whole). */
export async function cacheCapabilities(cacheDir: string, images: Record<string, string>, raw: ByProfile, digests: Record<string, string | null> = {}): Promise<void> {
  await mkdir(cacheDir, { recursive: true });
  const at = new Date().toISOString();
  for (const [profile, caps] of Object.entries(raw)) {
    const ref = images[profile];
    const digest = digests[profile];
    if (!ref || !digest || !DIGEST.test(digest) || !Array.isArray(caps) || !caps.length) continue;
    await writeFile(join(cacheDir, cacheName(digest)), `${JSON.stringify({ image: ref, digest, profile, at, capabilities: caps } satisfies CacheEntry, null, 2)}\n`);
  }
}

export async function probeImages(call: HubCall, profiles: string[], o: { qr?: string; timeoutS?: number; sleep?: (ms: number) => Promise<void>; runRoot?: string } = {}): Promise<ByProfile> {
  const script = probeScript(o.qr ?? probeQrBase64(), { runRoot: o.runRoot });
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const out: Record<string, Capability[] | { error: string }> = {};
  const ids = new Map<string, string>();
  for (const profile of profiles) {
    const sub = await call("jobSubmit", { command: script, inputs: [], profile, timeout_seconds: 180, note: `known-answer capability probes of the ${profile} job image` });
    const id = String((sub.job as { job?: string } | undefined)?.job ?? "");
    if (sub.ok !== true || !id) out[profile] = { error: String(sub.reason ?? "the probe job was not accepted") };
    else ids.set(profile, id);
  }
  const until = Date.now() + (o.timeoutS ?? 900) * 1000;
  for (const [profile, id] of ids) {
    let st: Record<string, unknown> = {};
    for (;;) {
      st = await call("jobStatus", { job_id: id });
      const state = String((st.job as { state?: string } | undefined)?.state ?? "");
      if (state === "committed" || state === "cancelled" || Date.now() > until) break;
      await sleep(2000);
    }
    const state = String((st.job as { state?: string } | undefined)?.state ?? "");
    const caps = readProbe(String((st.stdout as { text?: string } | undefined)?.text ?? ""));
    out[profile] = state === "committed" && caps.length ? caps : { error: `the probe job ${id} ${state === "committed" ? "printed nothing" : `did not finish (${state || "no state"})`}` };
  }
  return out;
}

async function main(argv: string[]): Promise<number> {
  const [sandbox, ...rest] = argv;
  const opt = (name: string) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
  const admin = opt("--hub-admin");
  const profiles = (opt("--profiles") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const cacheDir = opt("--cache") ?? null;
  let images: Record<string, string> = {};
  let digests: Record<string, string | null> = {};
  try {
    images = JSON.parse(opt("--images") ?? "{}") as Record<string, string>;
    digests = JSON.parse(opt("--digests") ?? "{}") as Record<string, string | null>;
  } catch {
    console.error("image-capabilities: --images takes a JSON object of profile to image reference, --digests one of profile to digest");
    return 2;
  }
  if (sandbox && rest.includes("--seed")) {
    const rec = await seedCapabilities(sandbox, images, cacheDir, digests);
    console.log(JSON.stringify(rec));
    return 0;
  }
  if (!sandbox || !admin || !profiles.length) {
    console.error("usage: image-capabilities.ts <sandbox> --hub-admin SOCKET --profiles NAME[,NAME] [--images JSON] [--digests JSON] [--cache DIR]\n       image-capabilities.ts <sandbox> --seed --images JSON [--digests JSON] [--cache DIR]");
    return 2;
  }
  const call: HubCall = (fn, arg) =>
    new Promise((resolve, reject) => {
      let answer = "";
      const socket = connect(admin);
      socket.setTimeout(60_000, () => { socket.destroy(); reject(new Error("the hub did not answer")); });
      socket.setEncoding("utf8");
      socket.on("error", reject);
      socket.on("data", (c) => (answer += c));
      socket.on("close", () => { try { resolve(JSON.parse(answer.trim().split("\n")[0] ?? "{}") as Record<string, unknown>); } catch (err) { reject(err as Error); } });
      socket.on("connect", () => socket.write(`${JSON.stringify({ op: "call", fn, args: [sandbox, arg] })}\n`));
    });
  const raw = await probeImages(call, profiles, { runRoot: sandbox });
  const result = withPackTools(raw);
  // This run's own result replaces the seed (pending, and an earlier run's lines) whole.
  await writeFile(join(sandbox, "job-capabilities.json"), `${JSON.stringify({ at: new Date().toISOString(), profiles, images: result }, null, 2)}\n`);
  if (cacheDir) await cacheCapabilities(cacheDir, images, raw, digests).catch(() => undefined);
  await call("systemPost", { tag: "result", to: "all", key: "job-capabilities", body: capabilitiesPost(result) }).catch(() => undefined);
  console.log(JSON.stringify(result));
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => { console.error(`image-capabilities: ${(err as Error).message}`); process.exit(1); });
}
