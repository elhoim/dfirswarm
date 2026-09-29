/**
 * msb rotates a running VM's secret in place (B10, scripts/vm.ts
 * renewSeatSecrets): the check the host-side renewal of the seats' tokens
 * rests on, against a real microVM. Needs a host that can boot one and the
 * base image (VM_TEST_IMAGE, default dfirswarm-base:dev-<arch>); skipped
 * otherwise, unless DFIRSWARM_VM_TESTS=1 says the host must be able to.
 *
 *   npm run test:vm
 *
 * Verified on msb 0.7.2 (2026-09-28): the dry run plans the rotation as
 * "rotated", disposition "live"; applied with policy no_restart it is
 * applied with the VM still running, and the guest's variable is the same
 * placeholder before and after.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { msbBinary, probeHost } from "../scripts/vm.ts";

const ARCH = process.arch === "arm64" ? "arm64" : "amd64";
const IMAGE = process.env.VM_TEST_IMAGE || `dfirswarm-base:dev-${ARCH}`;
const REQUIRED = process.env.DFIRSWARM_VM_TESTS === "1";

test("a running VM's secret is rotated live: no restart, the guest keeps its placeholder", async (t) => {
  const probe = await probeHost(IMAGE).catch((err: Error) => ({ ok: false, reasons: [err.message], image_present: false }));
  if (!probe.ok || probe.image_present === false) {
    const why = `this host cannot run the VM tests (${probe.ok ? `no image ${IMAGE}` : (probe as { reasons: string[] }).reasons.join("; ")})`;
    if (REQUIRED) throw new Error(why);
    t.skip(why);
    return;
  }
  process.env.MSB_PATH ??= msbBinary();
  const M = await import("microsandbox");
  const name = `dfs-rotation-${Date.now().toString(36)}`;
  type Guest = { shell(s: string): Promise<{ stdout(): string }>; stop(): Promise<void>; ping(): Promise<unknown> };
  type Builder = { image(i: string): Builder; pullPolicy(p: string): Builder; cpus(n: number): Builder; memory(n: number): Builder; detached(b: boolean): Builder; secretEnv(e: string, v: string, h: string): Builder; create(): Promise<Guest> };
  let sb: Guest | null = null;
  try {
    sb = await (M.Sandbox.builder(name) as unknown as Builder).image(IMAGE).pullPolicy("never").cpus(1).memory(512).detached(true).secretEnv("ROTATION_KEY", "value-one", "rotation.example").create();
    const before = (await sb.shell("printenv ROTATION_KEY")).stdout().trim();
    const h = await M.Sandbox.get(name);
    const dry = await h.modify({ secrets: { ROTATION_KEY: { value: "value-two" } }, dryRun: true });
    const change = dry.changes.find((c) => c.kind === "secret" && c.name === "ROTATION_KEY") as { change: string; disposition: string } | undefined;
    assert.deepEqual([change?.change, change?.disposition, dry.applied], ["rotated", "live", false]);
    const applied = await h.modify({ secrets: { ROTATION_KEY: { value: "value-two" } }, policy: "no_restart" });
    assert.equal(applied.applied, true);
    assert.equal((await sb.shell("printenv ROTATION_KEY")).stdout().trim(), before, "the guest keeps its placeholder");
    assert.notEqual(before, "value-one", "the guest never held the value");
    await sb.ping();
  } finally {
    await sb?.stop().catch(() => undefined);
    await M.Sandbox.remove(name).catch(() => undefined);
  }
});
