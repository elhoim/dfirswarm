/**
 * The VM manager's decisions, at the resolution where they are cheap to
 * check: what a guest's Pi is given instead of a credential, which files a
 * guest's Pi configuration is made of, the order of a VM's mounts, what a
 * VM's probe must say for the kickoff to go on, and which VMs a reap may
 * touch. No VM is started here (tests/vm-integration.test.ts does that).
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import {
  guestPiConfig,
  hostGatewayUrl,
  mountsFor,
  placeholderFor,
  probeVerdict,
  registryLabel,
  vmName,
  type ResolvedSecret,
  type VmSpec,
} from "../scripts/vm.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

/** What Pi does with a Codex token before it sends it: the account id out of the JWT payload. */
function piCodexAccountId(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const payload = JSON.parse(atob(parts[1]));
  const id = payload?.["https://api.openai.com/auth"]?.chatgpt_account_id;
  if (!id) throw new Error("No account ID in token");
  return id;
}

function spec(over: Partial<VmSpec> = {}): VmSpec {
  return {
    run: "s1a2b",
    sandbox: "/runs/s1a2b",
    image: "dfirswarm-base:dev-arm64",
    hub_dir: "/tmp/dfs-s1a2b.x",
    mounts: [{ host: "/repo/extensions", readonly: true }],
    env: {},
    agents: [{ id: "s1a2b00", model: "openai/gpt-5.4-mini" }],
    allow_hosts: [],
    providers: [],
    records_dir: "/runs/s1a2b/vm",
    ...over,
  };
}

test("a placeholder is shaped the way Pi reads the credential it stands for", () => {
  const anthropic = placeholderFor("anthropic", "oauth");
  assert.match(anthropic, /sk-ant-oat/, "Pi sends a subscription bearer only for a token that says sk-ant-oat");
  const codex = placeholderFor("openai-codex", "oauth", "acct-1234");
  assert.equal(piCodexAccountId(codex), "acct-1234", "Pi reads the account id out of the Codex token's payload");
  const key = placeholderFor("openai", "api_key");
  assert.match(key, /^dfirswarm-secret-openai-[0-9a-f]{24}$/);
  assert.notEqual(placeholderFor("openai", "api_key"), key, "each placeholder is unguessable, not a fixed word");
});

test("a guest's Pi configuration holds placeholders and never a credential", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vm-pi-"));
  dirs.push(dir);
  await writeFile(join(dir, "auth.json"), JSON.stringify({
    anthropic: { type: "oauth", access: "sk-ant-oat01-REAL-ACCESS", refresh: "REAL-REFRESH", expires: 1 },
    "openai-codex": { type: "oauth", access: "REAL.CODEX.TOKEN", refresh: "REAL-REFRESH-2", expires: 1, accountId: "acct-9" },
    openai: { type: "api_key", key: "sk-REAL-OPENAI" },
  }));
  await writeFile(join(dir, "models.json"), JSON.stringify({
    providers: {
      "azure-foundry": { baseUrl: "https://x.services.ai.azure.com/openai/v1", api: "openai-completions", apiKey: "REAL-AZURE-KEY", models: [{ id: "m" }] },
      lmstudio: { baseUrl: "http://127.0.0.1:1234/v1", api: "openai-completions", apiKey: "local", models: [{ id: "q" }] },
      unused: { baseUrl: "https://unused.example/v1", apiKey: "REAL-UNUSED" },
    },
  }));
  await writeFile(join(dir, "settings.json"), JSON.stringify({ defaultThinkingLevel: "medium" }));
  const s = spec({
    pi_agent_dir: dir,
    providers: [
      { provider: "anthropic", kind: "oauth", hosts: ["api.anthropic.com"] },
      { provider: "openai-codex", kind: "oauth", hosts: ["chatgpt.com"] },
      { provider: "openai", kind: "api_key", hosts: ["api.openai.com"] },
      { provider: "azure-foundry", kind: "api_key", hosts: ["x.services.ai.azure.com"] },
      { provider: "lmstudio", kind: "local", hosts: [], port: 1234 },
    ],
  });
  const secrets: ResolvedSecret[] = [
    { provider: "anthropic", kind: "oauth", placeholder: placeholderFor("anthropic", "oauth"), value: "sk-ant-oat01-REAL-ACCESS", hosts: ["api.anthropic.com"] },
    { provider: "openai-codex", kind: "oauth", placeholder: placeholderFor("openai-codex", "oauth", "acct-9"), value: "REAL.CODEX.TOKEN", hosts: ["chatgpt.com"], accountId: "acct-9" },
    { provider: "openai", kind: "api_key", placeholder: placeholderFor("openai", "api_key"), value: "sk-REAL-OPENAI", hosts: ["api.openai.com"] },
    { provider: "azure-foundry", kind: "api_key", placeholder: placeholderFor("azure-foundry", "api_key"), value: "REAL-AZURE-KEY", hosts: ["x.services.ai.azure.com"] },
  ];
  const cfg = guestPiConfig(s, secrets);
  const everything = `${cfg.auth}\n${cfg.models}\n${cfg.settings}`;
  for (const real of ["REAL-ACCESS", "REAL-REFRESH", "REAL.CODEX.TOKEN", "sk-REAL-OPENAI", "REAL-AZURE-KEY", "REAL-UNUSED"]) {
    assert.ok(!everything.includes(real), `the guest's Pi files must not carry ${real}`);
  }
  const auth = JSON.parse(cfg.auth);
  assert.equal(auth.anthropic.access, secrets[0].placeholder);
  assert.ok(auth.anthropic.expires > Date.UTC(2090, 0, 1), "a guest never refreshes: its token does not expire in the run");
  assert.equal(auth["openai-codex"].accountId, "acct-9");
  assert.equal(auth.openai.key, secrets[2].placeholder);
  assert.equal(auth["azure-foundry"], undefined, "a models.json provider carries its placeholder in models.json");
  const models = JSON.parse(cfg.models ?? "{}");
  assert.deepEqual(Object.keys(models.providers).sort(), ["azure-foundry", "lmstudio"], "only the team's providers cross");
  assert.equal(models.providers["azure-foundry"].apiKey, secrets[3].placeholder);
  assert.equal(models.providers.lmstudio.baseUrl, "http://host.microsandbox.internal:1234/v1", "a local server is reached through the host gateway");
  assert.equal(JSON.parse(cfg.settings ?? "{}").defaultThinkingLevel, "medium", "the operator's settings travel");
});

test("a local server's address becomes the host gateway, and nothing else changes", () => {
  assert.equal(hostGatewayUrl("http://localhost:11434"), "http://host.microsandbox.internal:11434");
  assert.equal(hostGatewayUrl("http://127.0.0.1:1234/v1"), "http://host.microsandbox.internal:1234/v1");
  assert.equal(hostGatewayUrl("https://api.example.com/v1"), "https://api.example.com/v1");
  assert.equal(hostGatewayUrl("not a url"), "not a url");
});

test("a VM's mounts: the run's floor read-only first, then the agent's own writable holes", () => {
  const m = mountsFor(spec({ late_mounts: [{ host: "/runs/s1a2b/work/quarantine", noexec: true }] }), "s1a2b00");
  assert.deepEqual(m[0], { host: "/runs/s1a2b", readonly: true }, "the floor comes first, read-only");
  const writable = m.filter((x) => !x.readonly).map((x) => x.host);
  assert.deepEqual(writable, [
    "/runs/s1a2b/work",
    "/runs/s1a2b/tool-output/s1a2b00",
    "/runs/s1a2b/.pi-sessions/s1a2b00",
    "/runs/s1a2b/work/quarantine",
  ]);
  assert.ok(!writable.some((h) => h.includes("s1a2b01")), "never a peer's directory");
  assert.equal(m.at(-1)?.noexec, true, "a no-exec hole inside work/ is mounted after work/");
});

test("the kickoff goes on only when a VM's own probe says what the run needs", () => {
  const good = { base: "ro", work: "rw", tool_output: "rw", session: "rw", inputs: "ro", hub: true, pi: "0.87.0" };
  assert.deepEqual(probeVerdict(good, true), []);
  assert.deepEqual(probeVerdict({ ...good, inputs: "absent" }, false), [], "no evidence, nothing to check there");
  assert.match(probeVerdict({ ...good, base: "rw" }, true).join(), /floor is rw/);
  assert.match(probeVerdict({ ...good, inputs: "rw" }, true).join(), /inputs\/ is rw/);
  assert.match(probeVerdict({ ...good, hub: false, hub_error: "refused" }, true).join(), /hub is not reachable \(refused\)/);
  assert.match(probeVerdict({ ...good, pi: "error: ENOENT" }, true).join(), /pi does not run/);
  assert.match(probeVerdict({}, true).join(), /floor/);
});

test("a VM's name and its registry label are stable, and two registries never share a label", () => {
  assert.equal(vmName("s1a2b", "s1a2b00"), "dfs-s1a2b-s1a2b00");
  assert.equal(registryLabel("/a/runs/registry.json"), registryLabel("/a/runs/../runs/registry.json"));
  assert.notEqual(registryLabel("/a/runs/registry.json"), registryLabel("/b/runs/registry.json"));
  assert.match(registryLabel("/a/runs/registry.json"), /^[0-9a-f]{16}$/);
});
