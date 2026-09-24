/**
 * Real microVMs, the way a run makes them (scripts/vm.ts) and serves them
 * (scripts/vm-hub.ts). Needs a host that can boot one — macOS on Apple
 * silicon, or Linux with /dev/kvm — and the base image (VM_TEST_IMAGE,
 * default dfirswarm-base:dev-<arch>). Skipped otherwise, unless
 * DFIRSWARM_VM_TESTS=1 says the host must be able to (CI's KVM job).
 *
 *   npm run test:vm
 *
 * What it proves, each against the host's own view of the files:
 *   - guest root cannot write the run's floor, the evidence or the trace, by
 *     writing, remounting or unmounting — and unmounting a writable hole
 *     leaves the read-only floor, not the host;
 *   - a VM reaches its allowed host and nothing else, by name or by address;
 *   - a secret never enters the guest, only its placeholder;
 *   - two VMs posting and recording at once through the hub lose nothing and
 *     never share an id — the failure the shared directory had;
 *   - finish snapshots and removes a run's VMs, and reap touches only the VMs
 *     its own registry recorded.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { initSandbox, readLedger } from "../extensions/protocol.ts";
import { Hub } from "../scripts/vm-hub.ts";
import { createVms, finishRun, imageCatalog, msbBinary, probeHost, reapVms, registryLabel, runVms, vmName, type VmSpec } from "../scripts/vm.ts";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARCH = process.arch === "arm64" ? "arm64" : "amd64";
const IMAGE = process.env.VM_TEST_IMAGE || `dfirswarm-base:dev-${ARCH}`;
const REQUIRED = process.env.DFIRSWARM_VM_TESTS === "1";

let skip: string | false = false;
const cleanups: Array<() => Promise<unknown>> = [];

before(async () => {
  const probe = await probeHost(IMAGE).catch((err: Error) => ({ ok: false, reasons: [err.message], image_present: false }));
  if (!probe.ok || probe.image_present === false) {
    skip = `this host cannot run the VM tests (${probe.ok ? `no image ${IMAGE}` : probe.reasons.join("; ")})`;
    if (REQUIRED) throw new Error(skip);
  }
});

after(async () => {
  for (const c of cleanups.reverse()) await c().catch(() => undefined);
});

function msb(...args: string[]): string {
  return execFileSync(msbBinary(), args, { encoding: "utf8", timeout: 120_000 });
}

/** Run a shell command in a VM as its root; stdout, whatever the exit. */
function inVm(name: string, script: string): string {
  try {
    return execFileSync(msbBinary(), ["exec", name, "--", "sh", "-c", script], { encoding: "utf8", timeout: 120_000 });
  } catch (err) {
    return String((err as { stdout?: string }).stdout ?? "");
  }
}

async function fingerprint(root: string, skipDirs: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, e.name);
      const rel = relative(root, abs);
      if (skipDirs.some((s) => rel === s || rel.startsWith(`${s}/`))) continue;
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) out.set(rel, createHash("sha256").update(await readFile(abs)).digest("hex") + `:${(await stat(abs)).mode}`);
    }
  }
  await walk(root);
  return out;
}

type Rig = { run: string; sandbox: string; hub: Hub; hubDir: string; spec: VmSpec; lines: Record<string, unknown>[]; evidence: string };

/** A sandbox, its evidence, a hub and a stand-in collector; the VMs are made by the test. */
async function rig(run: string, agents: string[], extra: Partial<VmSpec> = {}): Promise<Rig> {
  const base = await mkdtemp(join(tmpdir(), "vmit-"));
  const sandbox = join(base, "runs", run);
  await mkdir(sandbox, { recursive: true });
  await initSandbox(sandbox, { swarmId: run, agentIds: agents, capUsd: 1, wallClockMinutes: 30 });
  const evidence = join(base, "evidence");
  await mkdir(join(evidence, "mail"), { recursive: true });
  await writeFile(join(evidence, "notes.txt"), "case notes\n");
  await writeFile(join(evidence, "mail", "a.bin"), "suspect bytes");
  const { symlink } = await import("node:fs/promises");
  await symlink(evidence, join(sandbox, "inputs"));
  for (const a of agents) {
    await mkdir(join(sandbox, "tool-output", a), { recursive: true });
    await mkdir(join(sandbox, ".pi-sessions", a), { recursive: true });
  }
  await writeFile(join(sandbox, "traces", "events.jsonl"), '{"ts":"t","agent":"system","tool":"agent_start","args":{},"result":{}}\n');
  const hubDir = await mkdtemp("/tmp/dfh-");
  const lines: Record<string, unknown>[] = [];
  const collectorPath = join(hubDir, "col.sock");
  const collector: Server = createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let cut;
      while ((cut = buffer.indexOf("\n")) >= 0) {
        lines.push(JSON.parse(buffer.slice(0, cut)));
        buffer = buffer.slice(cut + 1);
        socket.write('{"ok":true}\n');
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((r) => collector.listen(collectorPath, () => r()));
  const hub = new Hub({ sandbox, dir: hubDir, agents, tokens: {}, collector: collectorPath, backstop: false, quiet: true, settleMs: 0 });
  await hub.start();
  const spec: VmSpec = {
    run,
    sandbox,
    image: IMAGE,
    pull: "never",
    cpus: 1,
    memory_mib: 1024,
    max_duration_sec: 1800,
    hub_dir: hubDir,
    mounts: [
      { host: join(ROOT, "extensions"), readonly: true },
      { host: evidence, readonly: true, noexec: true },
    ],
    env: { SWARM_ID: run },
    agents: agents.map((id) => ({ id, model: "none/none" })),
    allow_hosts: [],
    providers: [],
    records_dir: join(sandbox, "vm"),
    registry: join(base, "runs", "registry.json"),
    ...extra,
  };
  cleanups.push(async () => {
    for (const a of agents) {
      try {
        msb("stop", vmName(run, a));
      } catch {
        // already stopped
      }
      try {
        msb("rm", vmName(run, a));
      } catch {
        // already removed
      }
    }
    await hub.stop();
    collector.close();
    await rm(hubDir, { recursive: true, force: true });
    await rm(base, { recursive: true, force: true });
  });
  return { run, sandbox, hub, hubDir, spec, lines, evidence };
}

test("guest root cannot change the run's floor, the evidence or the trace, by any of the ways it could try", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt1", ["vmt100"]);
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, [], JSON.stringify(created.failures));
  const name = vmName(r.run, "vmt100");
  const floorBefore = await fingerprint(r.sandbox, ["work", "tool-output", ".pi-sessions", "vm"]);
  const evidenceBefore = await fingerprint(r.evidence, []);
  const S = r.sandbox;
  const out = inVm(name, `
    w() { if ( printf x >> "$1" ) 2>/dev/null; then echo "WROTE $1"; else echo "refused $1"; fi; }
    w "${S}/traces/events.jsonl"; w "${S}/SWARM.md"; w "${S}/inputs/notes.txt"; w "${S}/budget.json"
    mount -o remount,rw "${S}" 2>/dev/null; mount -o remount,rw "${r.evidence}" 2>/dev/null
    printf 'remounted: '; w "${S}/SWARM.md"
    printf 'remounted: '; w "${r.evidence}/notes.txt"
    umount "${S}/work" 2>/dev/null; w "${S}/work/after-umount.txt"
    umount "${S}/.pi-sessions/vmt100" 2>/dev/null; w "${S}/.pi-sessions/vmt100/planted"
    umount "${S}" 2>/dev/null; mkdir -p "${S}/traces" 2>/dev/null; w "${S}/traces/events.jsonl"
    rm -rf "${r.evidence}/notes.txt" 2>/dev/null; chmod 777 "${r.evidence}/mail/a.bin" 2>/dev/null; echo done
  `);
  assert.match(out, /refused .*events\.jsonl/);
  assert.match(out, /refused .*SWARM\.md/);
  assert.match(out, /refused .*inputs\/notes\.txt/);
  // The guest kernel may flip its own flag (it does, measured); the share is
  // read-only on the host side, and that is what refuses the write.
  assert.match(out, /remounted: refused .*SWARM\.md/);
  assert.match(out, /remounted: refused .*notes\.txt/);
  assert.doesNotMatch(out, /WROTE/, out);
  assert.match(out, /refused .*after-umount\.txt/, "unmounting work/ leaves the read-only floor, not a writable host");
  const floorAfter = await fingerprint(r.sandbox, ["work", "tool-output", ".pi-sessions", "vm"]);
  const evidenceAfter = await fingerprint(r.evidence, []);
  assert.deepEqual([...floorAfter], [...floorBefore], "the host's copy of the run's floor did not change");
  assert.deepEqual([...evidenceAfter], [...evidenceBefore], "the host's evidence did not change, in bytes or mode");
  assert.ok(!existsSync(join(r.sandbox, "work", "after-umount.txt")));
  assert.ok(!existsSync(join(r.sandbox, ".pi-sessions", "vmt100", "planted")), "a write after unmounting the session hole never reached the host");
});

test("a VM reaches its allowed host and the names under an allowed suffix, and no other name or address", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt2", ["vmt200"], { allow_hosts: ["registry.npmjs.org", "*.github.com"] });
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const name = vmName(r.run, "vmt200");
  const out = inVm(name, `
    code() { curl -s -o /dev/null -m 15 -w '%{http_code}' "$1" 2>/dev/null || echo fail; }
    echo "allowed=$(code https://registry.npmjs.org/)"
    echo "suffix=$(code https://api.github.com/)"
    echo "denied=$(code https://example.com/)"
    echo "ip=$(code https://1.1.1.1/)"
    getent hosts example.com >/dev/null 2>&1 && echo "resolved=yes" || echo "resolved=no"
  `);
  assert.match(out, /allowed=(200|301|302|304)/, out);
  assert.match(out, /suffix=(200|301|302|304|403)/, `a name under an allowed *.suffix is reachable\n${out}`);
  assert.match(out, /denied=(000|fail)/, out);
  assert.match(out, /ip=(000|fail)/, out);
  assert.match(out, /resolved=no/, "a name outside the rules does not resolve");
});

test("a local model's port on the host is reachable through the host gateway, and no other port", async (t) => {
  if (skip) return t.skip(skip);
  // In its own process: inVm() blocks this one while the guest calls it.
  const { spawn } = await import("node:child_process");
  const port = 18000 + Math.floor(Math.random() * 1000);
  const srv = spawn(process.execPath, ["-e", `require("node:http").createServer((q, s) => s.end("local model here\\n")).listen(${port}, "127.0.0.1")`], { stdio: "ignore" });
  cleanups.push(async () => srv.kill());
  await new Promise((r) => setTimeout(r, 500));
  const r = await rig("vmt7", ["vmt700"], { providers: [{ provider: "lmstudio", kind: "local", hosts: [], port }] });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const out = inVm(vmName(r.run, "vmt700"), `
    curl -s -m 5 http://host.microsandbox.internal:${port}/ || echo refused-model
    curl -s -m 5 http://host.microsandbox.internal:${port + 1}/ || echo refused-other-port
    curl -s -m 5 https://example.com/ >/dev/null && echo reached-public || echo refused-public
  `);
  assert.match(out, /local model here/, out);
  assert.match(out, /refused-other-port/, "only the model's port is open on the host");
  assert.match(out, /refused-public/);
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt700.json"), "utf8"));
  assert.deepEqual(record.network.host_ports, [port]);
});

test("a secret never enters the guest: the VM holds its placeholder", async (t) => {
  if (skip) return t.skip(skip);
  const base = await mkdtemp(join(tmpdir(), "vmsec-"));
  cleanups.push(() => rm(base, { recursive: true, force: true }));
  const value = `dfirswarm-test-secret-${createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16)}`;
  await writeFile(join(base, "secret"), value);
  const r = await rig("vmt3", ["vmt300"], { pack_secrets: [{ name: "VT_API_KEY", value_file: join(base, "secret"), hosts: ["www.virustotal.com"] }] });
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const name = vmName(r.run, "vmt300");
  const out = inVm(name, `printf 'env=%s\\n' "$VT_API_KEY"; (env; cat /proc/1/environ 2>/dev/null; grep -rs "${value}" /root /etc /run /tmp) | grep -c "${value}" || true`);
  assert.match(out, /env=dfirswarm-secret-vtapikey-[0-9a-f]{24}/, `the guest holds a placeholder under the secret's own name\n${out}`);
  assert.match(out, /^0$/m, "the value is nowhere in the guest's environment or files");
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt300.json"), "utf8"));
  assert.deepEqual(record.secrets, [{ name: "VT_API_KEY", hosts: ["www.virustotal.com"] }], "the record names the secret and its host, never its value");
  assert.ok(!JSON.stringify(record).includes(value));
  // Nor on the host, at rest: msb keeps a sandbox's configuration under its
  // home, and the value must not be in it (msb's own CLI refuses an inline
  // value for that reason; the SDK path is checked here).
  const msbHome = process.env.MSB_HOME || join(process.env.HOME || "", ".microsandbox");
  let atRest = "";
  try {
    atRest = execFileSync("grep", ["-rls", value, join(msbHome, "sandboxes", name), r.sandbox, r.hubDir], { encoding: "utf8" }).trim();
  } catch {
    atRest = ""; // grep exits 1 when nothing matches
  }
  assert.equal(atRest, "", `the value is on the host's disk in: ${atRest}`);
});

test("two VMs posting and recording at once through the hub lose nothing and never share an id", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt4", ["vmt400", "vmt401"]);
  const created = await createVms(r.spec);
  assert.deepEqual(created.failures, []);
  const N = 40;
  const script = (who: string) => `
    /.msb/scripts/dfirswarm-bridge
    cd "${r.sandbox}" && node --experimental-strip-types --no-warnings --input-type=module -e '
      const B = await import("${join(ROOT, "extensions", "board.ts")}");
      const ctx = { sandboxRoot: process.cwd(), agentId: "${who}" };
      await Promise.all(Array.from({ length: ${N} }, async (_, i) => {
        await B.postMessage(ctx, { tag: "result", body: "${who} post " + i });
        const rec = await B.recordEntry(ctx, { kind: "ioc", value: "${who}-ioc-" + i, source: "test", evidence: "sha256sum test", confidence: "low" });
        if (!rec.ok) throw new Error(rec.reason);
      }));
      console.log("sent");
    ' 2>&1`;
  // Async, so this process — which is the hub — keeps answering; and with
  // stdin closed, because `msb exec` relays stdin and waits for its end.
  const { spawn } = await import("node:child_process");
  const run = (name: string, who: string) =>
    new Promise<string>((done) => {
      const child = spawn(msbBinary(), ["exec", name, "--", "sh", "-c", script(who)], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      const timer = setTimeout(() => child.kill(), 300_000);
      child.on("close", () => {
        clearTimeout(timer);
        done(out);
      });
    });
  const [a, b] = await Promise.all([run(vmName(r.run, "vmt400"), "vmt400"), run(vmName(r.run, "vmt401"), "vmt401")]);
  assert.match(a, /sent/, a);
  assert.match(b, /sent/, b);
  const posts = (await readdir(join(r.sandbox, "threads", "main"))).filter((f) => f.endsWith(".md"));
  assert.equal(posts.length, 2 * N, "every post landed");
  const ids = posts.map((f) => f.slice(0, 6));
  assert.equal(new Set(ids).size, ids.length, "no two posts share an id");
  for (const who of ["vmt400", "vmt401"]) assert.equal(posts.filter((f) => f.endsWith(`-${who}.md`)).length, N, `${who}'s posts are all its own`);
  const ledger = await readLedger(r.sandbox);
  assert.equal(ledger.length, 2 * N, "every ledger record landed");
  assert.deepEqual([...new Set(ledger.map((e) => e.by))].sort(), ["vmt400", "vmt401"]);
});

test("finish keeps each disk and removes the VMs; reap touches only its own registry's VMs", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt5", ["vmt500"]);
  const other = await rig("vmt6", ["vmt600"], { registry: "/somewhere/else/registry.json" });
  assert.deepEqual((await createVms(r.spec)).failures, []);
  assert.deepEqual((await createVms(other.spec)).failures, []);
  const vms = await runVms();
  const mine = vms.find((v) => v.name === vmName("vmt6", "vmt600"));
  assert.equal(mine?.registry, registryLabel("/somewhere/else/registry.json"));

  const finished = await finishRun("vmt5", r.sandbox);
  assert.equal(finished.length, 1);
  assert.ok(finished[0].snapshot && existsSync(finished[0].snapshot), `a snapshot was kept: ${JSON.stringify(finished)}`);
  const record = JSON.parse(await readFile(join(r.sandbox, "vm", "vmt500.json"), "utf8"));
  assert.equal(record.snapshot.sha256, createHash("sha256").update(readFileSync(finished[0].snapshot as string)).digest("hex"));
  assert.ok(record.stopped_at);
  assert.equal((await runVms("vmt5")).length, 0, "the run's VM is gone");
  assert.equal((await finishRun("vmt5", r.sandbox)).length, 0, "a second finish is a no-op");

  // vmt6's registry has no running run: a reap of *that* registry removes it,
  // and a reap of any other registry never does.
  await mkdir(dirname(r.spec.registry as string), { recursive: true });
  await writeFile(r.spec.registry as string, JSON.stringify({ runs: [] }));
  assert.deepEqual(await reapVms({ registry: r.spec.registry }), [], "a reap of another registry leaves vmt6 alone");
  assert.equal((await runVms("vmt6")).length, 1);
  assert.deepEqual(await reapVms({ run: "vmt6" }), [vmName("vmt6", "vmt600")], "named outright, it is reaped");
  assert.equal((await runVms("vmt6")).length, 0);
});

/** A 1.44 MB FAT12 volume holding HELLO.TXT: a disk image the catalog knows, made here. */
function floppy(): Buffer {
  const img = Buffer.alloc(2880 * 512);
  img.set([0xeb, 0x3c, 0x90], 0);
  img.write("MSWIN4.1", 3, "ascii");
  img.writeUInt16LE(512, 11); // bytes per sector
  img[13] = 1; // sectors per cluster
  img.writeUInt16LE(1, 14); // reserved sectors
  img[16] = 2; // FATs
  img.writeUInt16LE(224, 17); // root entries
  img.writeUInt16LE(2880, 19); // sectors
  img[21] = 0xf0;
  img.writeUInt16LE(9, 22); // sectors per FAT
  img.writeUInt16LE(18, 24);
  img.writeUInt16LE(2, 26);
  img[38] = 0x29;
  img.writeUInt32LE(0x1234abcd, 39);
  img.write("SYNTHETIC  FAT12   ", 43, "ascii");
  img.writeUInt16LE(0xaa55, 510);
  for (const fat of [1, 10]) img.set([0xf0, 0xff, 0xff, 0xff, 0x0f, 0x00], fat * 512);
  const root = 19 * 512;
  img.write("SYNTHETIC  ", root, "ascii");
  img[root + 11] = 0x08; // volume label
  img.write("HELLO   TXT", root + 32, "ascii");
  img[root + 32 + 11] = 0x20;
  img.writeUInt16LE(2, root + 32 + 26); // first cluster
  img.writeUInt32LE(6, root + 32 + 28); // size
  img.write("hello\n", 33 * 512, "ascii");
  return img;
}

test("the catalog runs in a throwaway VM of the image, with the image's tools, and leaves the evidence and no VM behind", async (t) => {
  if (skip) return t.skip(skip);
  const r = await rig("vmt8", ["vmt800"]);
  await writeFile(join(r.evidence, "floppy.img"), floppy());
  const sandbox = realpathSync(r.sandbox);
  // Mounted where inputs/ points, as the kickoff does (it links the real path).
  const evidence = readlinkSync(join(sandbox, "inputs"));
  const evidenceBefore = await fingerprint(evidence, []);
  const floorBefore = await fingerprint(sandbox, ["catalog"]);

  // What the image holds decides what the catalog can build; the host's own
  // tools must not show through.
  assert.deepEqual((await createVms(r.spec)).failures, []);
  const imageHasTsk = inVm(vmName(r.run, "vmt800"), "command -v fsstat >/dev/null && command -v fls >/dev/null && echo yes || echo no").trim() === "yes";

  // With the run's allowed hosts, as a kickoff with --allow-host passes them.
  const result = await imageCatalog(IMAGE, sandbox, [evidence], { memoryMib: 1024, allowHosts: ["registry.npmjs.org", "*.github.com"] });
  assert.equal(result.code, 0, result.output);
  const readme = await readFile(join(sandbox, "catalog", "README.md"), "utf8");
  if (imageHasTsk) {
    assert.match(readme, /^Summary: 1 disk image\(s\)/, readme);
    assert.match(await readFile(join(sandbox, "catalog", "floppy.img", "p0", "filelist.txt"), "utf8"), /HELLO\.TXT/);
  } else {
    assert.match(readme, /^Summary: 0 disk image\(s\)/, `an image without The Sleuth Kit catalogued a disk: the host's tools showed through\n${readme}`);
  }
  assert.deepEqual([...(await fingerprint(evidence, []))], [...evidenceBefore], "the evidence did not change");
  assert.deepEqual([...(await fingerprint(sandbox, ["catalog", "vm"]))], [...floorBefore].filter(([k]) => !k.startsWith("vm/")), "the catalog wrote nothing but catalog/");
  assert.doesNotMatch(msb("list"), /dfs-catalog-/, "the catalog's VM is gone");
});
