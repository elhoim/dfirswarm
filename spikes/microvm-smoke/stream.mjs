// What Pi's bash tool would need from a box, checked through the SDK:
//   1. 64 MiB of binary stdout arrives byte for byte, stderr apart, exit code intact
//   2. three commands streaming at once do not bleed into each other
//   3. a timeout ends the command and leaves nothing running
//   4. kill() ends a command that ignores SIGTERM
//   5. a second process reattaches to the same box by name (a Pi restart)
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { Sandbox } from "microsandbox";

const IMAGE = "python:3.12-slim-bookworm";
const name = `smoke-stream-${process.pid}`;
const results = [];
const check = (label, ok, detail) => {
  results.push({ label, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
};

// Seeded bytes: the guest writes them, the host recomputes them independently.
const generator = (seed, chunks) => `
import hashlib, random, sys
r = random.Random(${seed}); h = hashlib.sha256(); out = sys.stdout.buffer; n = 0
for i in range(${chunks}):
    b = r.randbytes(65536); out.write(b); h.update(b); n += len(b)
    if i % 256 == 0: sys.stderr.write(f"progress {i}\\n"); sys.stderr.flush()
out.flush(); sys.stderr.write(f"guest sha256={h.hexdigest()} bytes={n}\\n"); sys.exit(7)
`;
const expected = (seed, chunks) =>
  execFileSync("python3", ["-c", `import hashlib, random
r = random.Random(${seed}); h = hashlib.sha256()
for _ in range(${chunks}): h.update(r.randbytes(65536))
print(h.hexdigest())`]).toString().trim();

async function drain(handle) {
  const h = createHash("sha256");
  let bytes = 0, stderr = "", text = "", code = null;
  for await (const ev of handle) {
    if (ev.kind === "stdout") {
      h.update(ev.data); bytes += ev.data.length;
      if (text.length < 4096) text += Buffer.from(ev.data).toString("utf8");
    }
    else if (ev.kind === "stderr") stderr += Buffer.from(ev.data).toString("utf8");
    else if (ev.kind === "exited") code = ev.code;
  }
  return { sha: h.digest("hex"), bytes, stderr, text, code };
}

const sb = await Sandbox.builder(name).image(IMAGE).cpus(2).memory(1024).disableNetwork().detached(true).create();
try {
  // 1. lossless binary stream
  const t0 = Date.now();
  const one = await drain(await sb.execStreamWith("python3", (b) => b.args(["-c", generator(42, 1024)])));
  const secs = (Date.now() - t0) / 1000;
  const want = expected(42, 1024);
  check("64 MiB binary stdout is byte-identical", one.sha === want && one.bytes === 64 * 2 ** 20,
    `${one.bytes} bytes in ${secs.toFixed(1)}s, host ${one.sha.slice(0, 16)} vs expected ${want.slice(0, 16)}`);
  check("stderr kept apart from stdout", /progress 0\n/.test(one.stderr) && one.stderr.includes(`guest sha256=${want}`));
  check("exit code 7 propagated", one.code === 7, `got ${one.code}`);

  // 2. three concurrent streams
  const seeds = [1, 2, 3];
  const outs = await Promise.all(seeds.map(async (s) =>
    drain(await sb.execStreamWith("python3", (b) => b.args(["-c", generator(s, 128)])))));
  const clean = outs.every((o, i) => o.sha === expected(seeds[i], 128) && o.bytes === 8 * 2 ** 20);
  check("three concurrent 8 MiB streams stay separate", clean);

  // 3. timeout. In 0.7.2 the SDK honours .timeout() on execWith and on the
  // CLI, but not on a stream; the harness keeps its own clock and kills.
  const t1 = Date.now();
  const sdkTimed = await drain(await sb.execStreamWith("sh", (b) =>
    b.args(["-c", "sleep 8"]).timeout(2000)));
  const sdkWaited = (Date.now() - t1) / 1000;
  check("SDK .timeout() is honoured on a stream (known gap in 0.7.2)", sdkWaited < 6,
    `returned after ${sdkWaited.toFixed(1)}s with code ${sdkTimed.code}`);

  const t2 = Date.now();
  const timed = await sb.execStreamWith("sh", (b) => b.args(["-c", "echo started; sleep 30; echo never"]));
  const clock = setTimeout(() => timed.kill().catch(() => {}), 2000);
  const out = await drain(timed);
  clearTimeout(clock);
  const waited = (Date.now() - t2) / 1000;
  const left = (await sb.exec("sh", ["-c", "ps -eo comm | grep -c '^sleep$' || true"])).stdout().trim();
  check("harness clock + kill() enforces a 2 s timeout", waited < 5 && !out.text.includes("never"),
    `returned after ${waited.toFixed(1)}s with code ${out.code}, stdout ${JSON.stringify(out.text.trim())}`);
  check("nothing left running after the timeout", left === "0", `sleep processes: ${left}`);

  // 4. kill a command that ignores SIGTERM
  const stubborn = await sb.execStreamWith("sh", (b) => b.args(["-c", "trap '' TERM; echo ready; sleep 60"]));
  await new Promise((r) => setTimeout(r, 500));
  const t3 = Date.now();
  await stubborn.kill();
  const killed = await drain(stubborn);
  check("kill() ends a command that ignores SIGTERM", (Date.now() - t3) < 5000, `code ${killed.code}`);

  // 5. reattach from a second process
  await sb.exec("sh", ["-c", "echo left-by-first-process > /root/marker"]);
  await sb.detach();
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { Sandbox } from "microsandbox";
    const box = await (await Sandbox.get(${JSON.stringify(name)})).connect();
    const out = await box.exec("cat", ["/root/marker"]);
    console.log(out.stdout().trim());
    await box.detach();
  `], { cwd: import.meta.dirname, encoding: "utf8" });
  check("a second process reattaches by name and sees the same box",
    child.stdout.trim() === "left-by-first-process", (child.stdout + child.stderr).trim().slice(0, 200));
} finally {
  const handle = await Sandbox.get(name);
  await handle.kill().catch(() => {});
  await handle.remove().catch(() => {});
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
