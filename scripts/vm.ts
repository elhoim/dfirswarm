#!/usr/bin/env node
/**
 * One microVM per agent, with Pi inside, brought up and put away by the
 * harness. Agents never make VMs; they get the one the kickoff gave them.
 *
 * What goes in, and why each is shaped the way it is:
 *
 * **The same paths as the host.** The sandbox, the harness code and the
 * evidence are mounted in the guest at the paths they have on the host, so
 * every path a pane, the trace, the registry or a check names means the same
 * file on both sides and nothing is ever translated.
 *
 * **A read-only floor with writable holes, never the reverse.** The sandbox
 * is mounted read-only as a whole; `work/`, the agent's own `tool-output/`
 * and its own Pi session directory are mounted writable on top. A read-only
 * mount inside a writable one is not a boundary — guest root unmounted one
 * and wrote through the parent (measured, spikes/microvm-smoke) — while a
 * writable mount inside a read-only one, unmounted, leaves the read-only
 * floor. The board's files are not writable at all: the hub writes them
 * (scripts/vm-hub.ts).
 *
 * **Structured, not parsed.** Mounts, network rules and secrets go through
 * the SDK's builders. `msb create --mount-dir` misparsed a long mount spec
 * (`…/sbx:ro` became a read-write mount at `…/sbxo`, measured) and would put
 * every value on argv.
 *
 * **No credential enters a guest.** A provider key or subscription token is
 * resolved on the host by Pi itself (`pi auth print-api-key`,
 * `pi auth print-bearer-token --min-expiry`, which refreshes a subscription
 * on the host for the whole run) and handed to msb as a secret bound to the
 * provider's hosts. The guest's Pi holds a placeholder; msb swaps in the
 * value on the way out over TLS, to those hosts only.
 *
 *   node --experimental-strip-types scripts/vm.ts probe  [--image REF]
 *   node --experimental-strip-types scripts/vm.ts create --spec FILE
 *   node --experimental-strip-types scripts/vm.ts finish --run ID --sandbox DIR [--no-snapshot]
 *   node --experimental-strip-types scripts/vm.ts reap   [--run ID] [--registry FILE]
 *   node --experimental-strip-types scripts/vm.ts list   [--run ID]
 *   node --experimental-strip-types scripts/vm.ts msb-path
 */
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, existsSync, readFileSync, realpathSync } from "node:fs";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
/** The vsock port every VM's hub link uses; the host end is the agent's own socket. */
export const HUB_PORT = 5000;
/** Where the extension in the guest finds the hub (the bridge listens here). */
export const GUEST_HUB_SOCKET = "/run/dfirswarm/hub.sock";
export const LABEL_RUN = "dev.dfirswarm.run";
export const LABEL_AGENT = "dev.dfirswarm.agent";
/**
 * Which registry the run is in, as a short digest of its path. One machine
 * can hold several (a worktree's runs/, a case under --sandbox, a test's
 * temp directory), and a reap reads only one: it may remove only the VMs of
 * runs that registry knows about.
 */
export const LABEL_REGISTRY = "dev.dfirswarm.registry";

export function registryLabel(registryPath: string): string {
  return createHash("sha256").update(resolve(registryPath)).digest("hex").slice(0, 16);
}
/** An OAuth credential in a guest never refreshes: its expiry is set past any run. */
const GUEST_OAUTH_EXPIRES = Date.UTC(2099, 0, 1);

export type Mount = { host: string; guest?: string; readonly?: boolean; noexec?: boolean };

export type ProviderSpec = {
  provider: string;
  /** `api_key` (Pi's store, models.json or the environment), `oauth`, or `local` (no credential). */
  kind: "api_key" | "oauth" | "local";
  /** Hosts the credential may go to, and the only hosts this provider's traffic may reach. */
  hosts: string[];
  /** For `local`: the host's port the guest may reach through the host gateway. */
  port?: number;
};

export type PackSecretSpec = { name: string; value_file?: string; hosts: string[] };

export type VmSpec = {
  run: string;
  sandbox: string;
  image: string;
  pull?: "always" | "if-missing" | "never";
  cpus?: number;
  memory_mib?: number;
  root_disk_mib?: number;
  max_duration_sec?: number;
  /** Where the hub's per-agent sockets are. */
  hub_dir: string;
  /** Mounted into every VM, at the same path unless `guest` says otherwise. */
  mounts: Mount[];
  /** Mounted after the agent's own writable directories: no-exec holes inside work/. */
  late_mounts?: Mount[];
  /** `--no-netguard`: every public host, as the operator asked. */
  open_net?: boolean;
  env: Record<string, string>;
  agents: Array<{ id: string; model: string; env?: Record<string, string> }>;
  /** Hosts every VM may reach on 443: provider hosts, `--allow-host`, install indexes. */
  allow_hosts: string[];
  providers: ProviderSpec[];
  pack_secrets?: PackSecretSpec[];
  /** The host's `pi`, which resolves credentials. */
  pi_bin?: string;
  /** How long a subscription token must stay valid (Pi's duration syntax, `90m`). */
  min_token_validity?: string;
  /** Pi's agent directory on the host: models.json and settings.json are read from it. */
  pi_agent_dir?: string;
  records_dir: string;
  snapshot_dir?: string;
  /** The run registry this run is recorded in (labels the VMs for the reaper). */
  registry?: string;
};

/** The msb binary this repository pins, for the pane's `msb exec` and the CLI calls. */
export function msbBinary(): string {
  const plat = process.platform === "darwin" ? `darwin-${process.arch}` : `linux-${process.arch === "x64" ? "x64" : process.arch}-gnu`;
  const require = createRequire(import.meta.url);
  try {
    const pkg = require.resolve(`@superradcompany/microsandbox-${plat}/package.json`);
    const bin = join(dirname(pkg), "bin", "msb");
    if (existsSync(bin)) return bin;
  } catch {
    // fall through to PATH
  }
  return "msb";
}

export function vmName(run: string, agent: string): string {
  return `dfs-${run}-${agent}`;
}

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * The string the guest's Pi holds instead of a credential. msb replaces it
 * with the real value in a request's headers, to the secret's hosts only.
 * Two providers look inside the credential, so their placeholders are shaped
 * like one: Pi sends an Anthropic token as a subscription bearer only when it
 * contains `sk-ant-oat`, and reads the ChatGPT account id out of the Codex
 * token's JWT payload. The account id is an identifier, not a secret.
 */
export function placeholderFor(provider: string, kind: ProviderSpec["kind"], accountId?: string): string {
  const salt = randomBytes(12).toString("hex");
  if (kind === "oauth" && provider === "anthropic") return `sk-ant-oat01-dfirswarm-${salt}`;
  if (kind === "oauth" && provider === "openai-codex") {
    const header = base64url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const payload = base64url(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: accountId ?? "" }, dfirswarm: "placeholder" }));
    return `${header}.${payload}.dfirswarm${salt}`;
  }
  return `dfirswarm-secret-${provider.replace(/[^a-zA-Z0-9]/g, "")}-${salt}`;
}

function run(cmd: string, args: string[], options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    execFile(cmd, args, { timeout: options.timeoutMs ?? 120_000, maxBuffer: 64 * 1024 * 1024, env: options.env ?? process.env }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === "number" ? ((err as { code: number }).code) : 1) : 0;
      done({ code, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

export type ResolvedSecret = { provider: string; kind: ProviderSpec["kind"]; placeholder: string; value: string; hosts: string[]; accountId?: string };

/**
 * Every credential the team needs, resolved on the host by Pi's own commands
 * and held in this process's memory only. Throws with the reason when Pi
 * cannot produce one — the kickoff turns that into a BLOCKER.
 */
export async function resolveSecrets(spec: VmSpec): Promise<ResolvedSecret[]> {
  const pi = spec.pi_bin || "pi";
  const out: ResolvedSecret[] = [];
  for (const p of spec.providers) {
    if (p.kind === "local") continue;
    let value = "";
    let accountId: string | undefined;
    if (p.kind === "oauth") {
      const r = await run(pi, ["auth", "print-bearer-token", "--provider", p.provider, "--min-expiry", spec.min_token_validity || "2h"]);
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi could not produce a ${p.provider} subscription token valid for the run: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
      if (p.provider === "openai-codex") accountId = codexAccountId(value, spec.pi_agent_dir);
    } else {
      const r = await run(pi, ["auth", "print-api-key", "--provider", p.provider]);
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi has no key for ${p.provider}: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
    }
    out.push({ provider: p.provider, kind: p.kind, placeholder: placeholderFor(p.provider, p.kind, accountId), value, hosts: p.hosts, ...(accountId ? { accountId } : {}) });
  }
  return out;
}

/** The Codex account id: in Pi's store beside the token, or in the token's own payload. */
function codexAccountId(token: string, piAgentDir?: string): string {
  try {
    const auth = JSON.parse(readFileSync(join(piAgentDir || join(process.env.HOME || "", ".pi", "agent"), "auth.json"), "utf8"));
    const stored = auth?.["openai-codex"]?.accountId;
    if (typeof stored === "string" && stored) return stored;
  } catch {
    // read it from the token instead
  }
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    const id = payload?.["https://api.openai.com/auth"]?.chatgpt_account_id;
    if (typeof id === "string") return id;
  } catch {
    // nothing to read
  }
  return "";
}

/**
 * The guest's own Pi configuration: an auth store of placeholders, the
 * operator's custom providers with their keys swapped for placeholders and
 * a local server reached through the host gateway, and the operator's
 * settings. Nothing in these files is a credential.
 */
export function guestPiConfig(spec: VmSpec, secrets: ResolvedSecret[]): { auth: string; models: string | null; settings: string | null } {
  const dir = spec.pi_agent_dir || join(process.env.HOME || "", ".pi", "agent");
  const auth: Record<string, unknown> = {};
  let models: Record<string, unknown> | null = null;
  try {
    models = JSON.parse(readFileSync(join(dir, "models.json"), "utf8")) as Record<string, unknown>;
  } catch {
    models = null;
  }
  const providers = (models?.providers ?? {}) as Record<string, Record<string, unknown>>;
  const keep: Record<string, Record<string, unknown>> = {};
  for (const p of spec.providers) {
    const secret = secrets.find((s) => s.provider === p.provider);
    const custom = providers[p.provider];
    if (custom) {
      const copy = { ...custom };
      if (secret && "apiKey" in copy) copy.apiKey = secret.placeholder;
      if (p.kind === "local" && typeof copy.baseUrl === "string") copy.baseUrl = hostGatewayUrl(copy.baseUrl);
      keep[p.provider] = copy;
    }
    if (!secret) continue;
    if (secret.kind === "oauth") {
      auth[p.provider] = {
        type: "oauth",
        access: secret.placeholder,
        refresh: "dfirswarm-vm-never-refreshes",
        expires: GUEST_OAUTH_EXPIRES,
        ...(secret.accountId ? { accountId: secret.accountId } : {}),
      };
    } else if (!custom || !("apiKey" in custom)) {
      auth[p.provider] = { type: "api_key", key: secret.placeholder };
    }
  }
  let settings: string | null = null;
  try {
    settings = readFileSync(join(dir, "settings.json"), "utf8");
  } catch {
    settings = null;
  }
  return {
    auth: `${JSON.stringify(auth, null, 2)}\n`,
    models: Object.keys(keep).length ? `${JSON.stringify({ ...(models ?? {}), providers: keep }, null, 2)}\n` : null,
    settings,
  };
}

/** A local server's URL as the guest reaches it: through msb's host gateway. */
export function hostGatewayUrl(url: string): string {
  try {
    const u = new URL(url);
    if (["127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"].includes(u.hostname)) u.hostname = "host.microsandbox.internal";
    return u.toString().replace(/\/$/, url.endsWith("/") ? "/" : "");
  } catch {
    return url;
  }
}

/**
 * The guest's side of the hub link: a socat bridge from a Unix socket to the
 * vsock port. The SDK mounts a script as written — no shebang is added.
 */
export const BRIDGE_SCRIPT = `#!/bin/sh
set -e
mkdir -p /run/dfirswarm
if [ ! -S ${GUEST_HUB_SOCKET} ]; then
  setsid socat UNIX-LISTEN:${GUEST_HUB_SOCKET},fork,mode=600,backlog=256 VSOCK-CONNECT:2:${HUB_PORT} </dev/null >>/run/dfirswarm/bridge.log 2>&1 &
  i=0
  while [ ! -S ${GUEST_HUB_SOCKET} ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
fi
[ -S ${GUEST_HUB_SOCKET} ]
`;

/**
 * What the pane runs inside the VM: the bridge, then Pi in the sandbox with
 * the kickoff as its first message. A pane that is restarted asks for the
 * kickoff again, which is what a fresh Pi needs.
 */
export const PI_SCRIPT = `#!/bin/sh
/.msb/scripts/dfirswarm-bridge
cd "$SWARM_SANDBOX"
if [ "$SWARM_ALLOW_INSTALL" = 1 ] && [ -n "$SWARM_TOOLCHAIN" ]; then
  # --allow-install: pip lays packages into the run, where every agent's VM
  # sees them and the toolchain record reads them, as on the host.
  pyv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  export PIP_PREFIX="$SWARM_TOOLCHAIN"
  export PYTHONPATH="$SWARM_TOOLCHAIN/lib/python$pyv/site-packages\${PYTHONPATH:+:$PYTHONPATH}"
  export PATH="$SWARM_TOOLCHAIN/bin:$PATH"
fi
if [ -n "$SWARM_KICKOFF" ] && [ -f "$SWARM_KICKOFF" ]; then
  exec pi "$@" "$(cat "$SWARM_KICKOFF")"
fi
exec pi "$@"
`;

/**
 * Measured, not assumed: what this VM can write, whether it reaches the hub,
 * and what it is running. The kickoff refuses a VM whose answers are wrong.
 */
export const PROBE_SCRIPT = `#!/bin/sh
/.msb/scripts/dfirswarm-bridge >/dev/null 2>&1 || true
exec python3 - <<'PY'
import errno, json, os, socket, subprocess
S = os.environ.get("SWARM_SANDBOX", "")
A = os.environ.get("AGENT_ID", "")
def can_write(path):
    try:
        with open(path, "w") as f:
            f.write("probe")
        os.unlink(path)
        return "rw"
    except OSError as e:
        return "ro" if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM) else "error:" + errno.errorcode.get(e.errno, str(e.errno))
out = {"agent": A, "sandbox": S}
out["base"] = can_write(os.path.join(S, ".vm-probe-" + A))
out["work"] = can_write(os.path.join(S, "work", ".vm-probe-" + A))
out["tool_output"] = can_write(os.path.join(S, "tool-output", A, ".vm-probe"))
out["session"] = can_write(os.path.join(S, ".pi-sessions", A, ".vm-probe"))
inputs = os.path.join(S, "inputs")
if os.path.exists(inputs):
    out["inputs"] = can_write(os.path.join(os.path.realpath(inputs), ".vm-probe"))
    out["inputs_files"] = sum(len(f) for _, _, f in os.walk(inputs, followlinks=True))
else:
    out["inputs"] = "absent"
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect("${GUEST_HUB_SOCKET}")
    s.sendall(b'{"t":"rpc","fn":"swarmDoneExists","args":[null]}\\n')
    data = b""
    while not data.endswith(b"\\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    out["hub"] = json.loads(data.decode() or "{}").get("ok") is True
except Exception as e:
    out["hub"] = False
    out["hub_error"] = str(e)
try:
    out["pi"] = subprocess.run(["pi", "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
except Exception as e:
    out["pi"] = "error: " + str(e)
try:
    out["image"] = json.load(open("/etc/dfirswarm/image.json"))
except Exception:
    out["image"] = None
out["kernel"] = os.uname().release
mounts = []
for line in open("/proc/mounts"):
    parts = line.split()
    if len(parts) > 3 and parts[2] == "virtiofs" and parts[1] != "/.msb":
        mounts.append({"path": parts[1].replace("\\\\040", " "), "mode": "ro" if "ro" in parts[3].split(",") else "rw"})
out["mounts"] = mounts
print(json.dumps(out))
PY
`;

/** What each agent's VM must find, or the kickoff stops. */
export function probeVerdict(probe: Record<string, unknown>, expectInputs: boolean): string[] {
  const wrong: string[] = [];
  if (probe.base !== "ro") wrong.push(`the sandbox floor is ${String(probe.base)}, not read-only`);
  if (probe.work !== "rw") wrong.push(`work/ is ${String(probe.work)}, not writable`);
  if (probe.tool_output !== "rw") wrong.push(`its tool-output/ is ${String(probe.tool_output)}, not writable`);
  if (probe.session !== "rw") wrong.push(`its Pi session directory is ${String(probe.session)}, not writable`);
  if (expectInputs && probe.inputs !== "ro") wrong.push(`inputs/ is ${String(probe.inputs)}, not read-only`);
  if (probe.hub !== true) wrong.push(`the hub is not reachable (${String(probe.hub_error ?? "no answer")})`);
  if (typeof probe.pi !== "string" || !/^\d+\.\d+/.test(probe.pi)) wrong.push(`pi does not run (${String(probe.pi)})`);
  return wrong;
}

/** Every mount one agent's VM gets: the run's own, then this agent's writable holes. */
export function mountsFor(spec: VmSpec, agent: string): Mount[] {
  const S = spec.sandbox;
  return [
    { host: S, readonly: true },
    ...spec.mounts,
    { host: join(S, "work") },
    { host: join(S, "tool-output", agent) },
    { host: join(S, ".pi-sessions", agent) },
    ...(spec.late_mounts ?? []),
  ];
}

type SdkModule = typeof import("microsandbox");
/** The SDK's secret builder, as far as this file uses it. */
type SecretB = { env(v: string): SecretB; value(v: string): SecretB; placeholder(p: string): SecretB; allow(h: string): SecretB };
type TlsB = { interceptedPorts(p: number[]): TlsB; bypass(h: string): TlsB };

async function sdk(): Promise<SdkModule> {
  return import("microsandbox");
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

export type VmRecord = {
  agent: string;
  name: string;
  run: string;
  runtime: { name: "microsandbox"; version: string };
  image: { ref: string; manifest_digest: string | null; description: unknown };
  cpus: number;
  memory_mib: number;
  max_duration_sec: number | null;
  mounts: Array<{ host: string; guest: string; mode: "ro" | "rw"; noexec?: boolean }>;
  network: { default: "deny" | "public"; allow_hosts: string[]; host_ports: number[] };
  secrets: Array<{ name: string; hosts: string[] }>;
  probe: Record<string, unknown>;
  created_at: string;
  stopped_at?: string;
  snapshot?: { path: string; sha256: string; bytes: number; integrity: boolean } | { error: string };
};

async function msbVersion(): Promise<string> {
  const r = await run(msbBinary(), ["--version"], { timeoutMs: 20_000 });
  return r.stdout.trim().replace(/^msb\s+/, "") || "unknown";
}

async function createOne(
  M: SdkModule,
  spec: VmSpec,
  agent: VmSpec["agents"][number],
  secrets: ResolvedSecret[],
  piConfig: ReturnType<typeof guestPiConfig>,
): Promise<VmRecord> {
  const name = vmName(spec.run, agent.id);
  const mounts = mountsFor(spec, agent.id);
  for (const m of mounts) if (!m.readonly) await mkdir(m.host, { recursive: true });
  const hostPorts = spec.providers.filter((p) => p.kind === "local" && p.port).map((p) => p.port as number);
  const allowHosts = [...new Set([...spec.allow_hosts, ...spec.providers.flatMap((p) => (p.kind === "local" ? [] : p.hosts))])].sort();
  const packSecrets: Array<{ name: string; value: string; hosts: string[] }> = [];
  for (const s of spec.pack_secrets ?? []) {
    const value = s.value_file ? (await readFile(s.value_file, "utf8").catch(() => "")).trim() : process.env[s.name] ?? "";
    if (value) packSecrets.push({ name: s.name, value, hosts: s.hosts });
  }

  const policy = new M.NetworkPolicyBuilder().defaultDeny();
  if (spec.open_net) policy.egress((r) => r.allowPublic());
  if (allowHosts.length) policy.egress((r) => r.tcp().port(443).allowDomains(allowHosts));
  for (const port of hostPorts) policy.egress((r) => r.tcp().port(port).allowHost());

  const env: Record<string, string> = {
    ...spec.env,
    ...(agent.env ?? {}),
    AGENT_ID: agent.id,
    SWARM_SANDBOX: spec.sandbox,
    SWARM_BOARD_SOCKET: GUEST_HUB_SOCKET,
    SWARM_TRACE_SOCKET: GUEST_HUB_SOCKET,
    SWARM_NUDGE_SOCKET: GUEST_HUB_SOCKET,
    SWARM_ISOLATION: "microvm",
  };

  let builder = M.Sandbox.builder(name)
    .image(spec.image)
    .pullPolicy(spec.pull ?? "if-missing")
    .cpus(spec.cpus ?? 2)
    .memory(spec.memory_mib ?? 2048)
    .rootDisk(spec.root_disk_mib ?? 8192)
    .detached(true)
    .replace()
    .workdir(spec.sandbox)
    .labels({ [LABEL_RUN]: spec.run, [LABEL_AGENT]: agent.id, ...(spec.registry ? { [LABEL_REGISTRY]: registryLabel(spec.registry) } : {}) })
    .envs(env)
    .vsock(join(spec.hub_dir, `${agent.id}.sock`), HUB_PORT)
    .scripts({ "dfirswarm-bridge": BRIDGE_SCRIPT, "dfirswarm-pi": PI_SCRIPT, "dfirswarm-probe": PROBE_SCRIPT })
    .patch((p) => {
      p.mkdir("/root/.pi/agent");
      p.text("/root/.pi/agent/auth.json", piConfig.auth, { mode: 0o600 });
      if (piConfig.models) p.text("/root/.pi/agent/models.json", piConfig.models);
      if (piConfig.settings) p.text("/root/.pi/agent/settings.json", piConfig.settings);
      return p;
    })
    .network((n) => {
      n.policyFromBuilder(policy);
      // A secret is swapped in on the way out over TLS, so the hosts that
      // receive one are intercepted — the SDK leaves interception off unless
      // it is configured (the CLI turns it on by itself). Every other allowed
      // host keeps its own TLS end to end: a package index verified against
      // the tool's own CA bundle, not msb's.
      const secretHosts = new Set([...secrets.flatMap((s) => s.hosts), ...packSecrets.flatMap((s) => s.hosts)]);
      if (secretHosts.size) {
        n.tls((t: TlsB) => {
          t.interceptedPorts([443]);
          for (const h of allowHosts) if (!secretHosts.has(h)) t.bypass(h);
          return t;
        });
      }
      for (const s of secrets) {
        n.secret((b: SecretB) => {
          b.env(`DFIRSWARM_${s.provider.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}_CREDENTIAL`).value(s.value).placeholder(s.placeholder);
          for (const h of s.hosts) b.allow(h);
          return b;
        });
      }
      for (const s of packSecrets) {
        n.secret((b: SecretB) => {
          b.env(s.name).value(s.value);
          for (const h of s.hosts) b.allow(h);
          return b;
        });
      }
      return n;
    });
  if (spec.max_duration_sec) builder = builder.maxDuration(spec.max_duration_sec);
  for (const m of mounts) {
    // The guest path is the path as the harness names it; the host side is
    // resolved, because msb does not follow a symlink on the way to a share
    // (/var -> /private/var on macOS failed the boot with ENOTDIR, measured).
    const hostPath = realpathSync(m.host);
    builder = builder.volume(m.guest ?? m.host, (v) => {
      v.bind(hostPath);
      if (m.readonly) v.readonly();
      if (m.noexec) v.noexec();
      return v;
    });
  }
  const sandbox = await builder.create();
  let probe: Record<string, unknown> = {};
  try {
    const out = await sandbox.exec("/.msb/scripts/dfirswarm-probe", []);
    const text = out.stdout().trim().split("\n").pop() ?? "";
    probe = JSON.parse(text) as Record<string, unknown>;
  } catch (err) {
    probe = { error: err instanceof Error ? err.message : String(err) };
  }
  let digest: string | null = null;
  try {
    const cfg = (await sandbox.config()) as unknown as { image?: { Oci?: { reference?: string } }; manifest_digest?: string; manifestDigest?: string };
    digest = cfg.manifest_digest ?? cfg.manifestDigest ?? null;
  } catch {
    digest = null;
  }
  if (!digest) {
    const r = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
    try {
      digest = (JSON.parse(r.stdout) as { config?: { manifest_digest?: string } }).config?.manifest_digest ?? null;
    } catch {
      digest = null;
    }
  }
  const record: VmRecord = {
    agent: agent.id,
    name,
    run: spec.run,
    runtime: { name: "microsandbox", version: await msbVersion() },
    image: { ref: spec.image, manifest_digest: digest, description: probe.image ?? null },
    cpus: spec.cpus ?? 2,
    memory_mib: spec.memory_mib ?? 2048,
    max_duration_sec: spec.max_duration_sec ?? null,
    mounts: mounts.map((m) => ({ host: m.host, guest: m.guest ?? m.host, mode: m.readonly ? "ro" : "rw", ...(m.noexec ? { noexec: true } : {}) })),
    network: { default: spec.open_net ? "public" : "deny", allow_hosts: allowHosts, host_ports: hostPorts },
    secrets: [
      ...secrets.map((s) => ({ name: `${s.provider} (${s.kind === "oauth" ? "subscription token" : "API key"})`, hosts: s.hosts })),
      ...packSecrets.map((s) => ({ name: s.name, hosts: s.hosts })),
    ],
    probe,
    created_at: new Date().toISOString(),
  };
  await mkdir(spec.records_dir, { recursive: true });
  await writeFile(join(spec.records_dir, `${agent.id}.json`), `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

export async function createVms(spec: VmSpec): Promise<{ records: VmRecord[]; failures: Array<{ agent: string; reasons: string[] }> }> {
  const M = await sdk();
  const secrets = await resolveSecrets(spec);
  const piConfig = guestPiConfig(spec, secrets);
  const expectInputs = existsSync(join(spec.sandbox, "inputs"));
  const settled = await Promise.allSettled(spec.agents.map((a) => createOne(M, spec, a, secrets, piConfig)));
  const records: VmRecord[] = [];
  const failures: Array<{ agent: string; reasons: string[] }> = [];
  settled.forEach((r, i) => {
    const agent = spec.agents[i].id;
    if (r.status === "rejected") {
      failures.push({ agent, reasons: [r.reason instanceof Error ? r.reason.message : String(r.reason)] });
      return;
    }
    records.push(r.value);
    const wrong = probeVerdict(r.value.probe, expectInputs);
    if (wrong.length) failures.push({ agent, reasons: wrong });
  });
  return { records, failures };
}

/** This run's VMs, from msb's own list by label. */
export async function runVms(runId?: string): Promise<Array<{ name: string; status: string; run: string; agent: string; registry: string }>> {
  // A bare-key label filter matches nothing in msb 0.7.2; without a run,
  // every VM is listed and its labels decide.
  const args = ["list", "--format", "json"];
  if (runId) args.push("--label", `${LABEL_RUN}=${runId}`);
  const r = await run(msbBinary(), args, { timeoutMs: 30_000 });
  if (r.code !== 0) return [];
  let rows: unknown;
  try {
    rows = JSON.parse(r.stdout || "[]");
  } catch {
    return [];
  }
  const list = Array.isArray(rows) ? rows : Array.isArray((rows as { sandboxes?: unknown[] })?.sandboxes) ? (rows as { sandboxes: unknown[] }).sandboxes : [];
  const out: Array<{ name: string; status: string; run: string; agent: string; registry: string }> = [];
  for (const row of list) {
    const o = row as Record<string, unknown>;
    const name = String(o.name ?? "");
    if (!name) continue;
    // `msb list` filters by label and does not print them (0.7.2); a VM's
    // labels are in its own configuration.
    let labels = (o.labels ?? {}) as Record<string, string>;
    if (!Object.keys(labels).length) {
      const inspect = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
      try {
        labels = (JSON.parse(inspect.stdout) as { config?: { labels?: Record<string, string> } }).config?.labels ?? {};
      } catch {
        labels = {};
      }
    }
    const vm = { name, status: String(o.status ?? "").toLowerCase(), run: labels[LABEL_RUN] ?? "", agent: labels[LABEL_AGENT] ?? "", registry: labels[LABEL_REGISTRY] ?? "" };
    if (vm.run && (!runId || vm.run === runId)) out.push(vm);
  }
  return out;
}

/**
 * Put a run's VMs away: stop each, keep its disk as a snapshot with msb's
 * integrity record (unless told not to), remove it, and write down where the
 * snapshot is and its sha256. Safe to run twice.
 */
export async function finishRun(runId: string, sandbox: string, options: { snapshot?: boolean } = {}): Promise<Array<{ agent: string; name: string; snapshot?: string; error?: string }>> {
  const msb = msbBinary();
  const records = join(sandbox, "vm");
  const snapDir = `${sandbox}.vm-snapshots`;
  const out: Array<{ agent: string; name: string; snapshot?: string; error?: string }> = [];
  for (const vm of await runVms(runId)) {
    const agent = vm.agent || vm.name.replace(`dfs-${runId}-`, "");
    const entry: { agent: string; name: string; snapshot?: string; error?: string } = { agent, name: vm.name };
    await run(msb, ["stop", vm.name], { timeoutMs: 120_000 });
    const recordFile = join(records, `${agent}.json`);
    let record: VmRecord | null = null;
    try {
      record = JSON.parse(await readFile(recordFile, "utf8")) as VmRecord;
    } catch {
      record = null;
    }
    if (options.snapshot !== false) {
      await mkdir(snapDir, { recursive: true });
      const file = join(snapDir, `${agent}.msb`);
      await rm(file, { force: true });
      const r = await run(msb, ["snapshot", "create", "--from-sandbox", vm.name, "--integrity", "--label", `run=${runId}`, "--label", `agent=${agent}`, "-o", file, "--quiet"], { timeoutMs: 15 * 60_000 });
      if (r.code === 0 && existsSync(file)) {
        const bytes = (await stat(file)).size;
        const sha = await sha256File(file);
        entry.snapshot = file;
        if (record) record.snapshot = { path: file, sha256: sha, bytes, integrity: true };
      } else {
        entry.error = (r.stderr || r.stdout).trim() || `snapshot exit ${r.code}`;
        if (record) record.snapshot = { error: entry.error };
      }
    }
    await run(msb, ["rm", vm.name], { timeoutMs: 60_000 });
    if (record) {
      record.stopped_at = new Date().toISOString();
      await writeFile(recordFile, `${JSON.stringify(record, null, 2)}\n`).catch(() => undefined);
    }
    out.push(entry);
  }
  return out;
}

/**
 * VMs whose run is over: this registry recorded them and does not say the
 * run is running (or still being prepared). Removed without a snapshot — a
 * run that was stopped properly already has one. A VM labelled for another
 * registry, or for none, is never touched; `--run` names one run outright.
 */
export async function reapVms(options: { run?: string; registry?: string } = {}): Promise<string[]> {
  const live = new Set<string>();
  let mine = "";
  if (!options.run) {
    if (!options.registry || !existsSync(options.registry)) return [];
    mine = registryLabel(options.registry);
    try {
      const reg = JSON.parse(readFileSync(options.registry, "utf8")) as { runs?: Array<{ id?: string; state?: string }> };
      for (const r of reg.runs ?? []) if ((r.state === "running" || r.state === "prepared") && r.id) live.add(r.id);
    } catch {
      // an unreadable registry reaps nothing
      return [];
    }
  }
  const removed: string[] = [];
  for (const vm of await runVms(options.run)) {
    if (!options.run && (vm.registry !== mine || live.has(vm.run))) continue;
    await run(msbBinary(), ["stop", vm.name], { timeoutMs: 120_000 });
    const r = await run(msbBinary(), ["rm", vm.name], { timeoutMs: 60_000 });
    if (r.code === 0) removed.push(vm.name);
  }
  return removed;
}

/** Can this host run a VM at all, and is the image here? */
export async function probeHost(image?: string): Promise<{ ok: boolean; msb: string; version: string; reasons: string[]; image_present?: boolean }> {
  const msb = msbBinary();
  const reasons: string[] = [];
  const v = await run(msb, ["--version"], { timeoutMs: 20_000 });
  if (v.code !== 0) return { ok: false, msb, version: "", reasons: [`msb does not run: ${v.stderr.trim() || v.code}`] };
  const doctor = await run(msb, ["doctor"], { timeoutMs: 60_000 });
  if (doctor.code !== 0) reasons.push(`msb doctor: ${(doctor.stdout + doctor.stderr).trim().split("\n").slice(-3).join(" ")}`);
  let image_present: boolean | undefined;
  if (image) {
    const r = await run(msb, ["image", "inspect", image], { timeoutMs: 30_000 });
    image_present = r.code === 0;
  }
  return { ok: reasons.length === 0, msb, version: v.stdout.trim(), reasons, ...(image !== undefined ? { image_present } : {}) };
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  const opt = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  switch (cmd) {
    case "msb-path":
      console.log(msbBinary());
      return;
    case "probe": {
      const r = await probeHost(opt("--image"));
      console.log(JSON.stringify(r));
      process.exit(r.ok ? 0 : 1);
    }
    case "create": {
      const file = opt("--spec");
      if (!file) throw new Error("create needs --spec FILE");
      const spec = JSON.parse(await readFile(file, "utf8")) as VmSpec;
      let result;
      try {
        result = await createVms(spec);
      } catch (err) {
        console.log(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }));
        process.exit(1);
      }
      console.log(JSON.stringify({ ok: result.failures.length === 0, vms: result.records.map((r) => ({ agent: r.agent, name: r.name, digest: r.image.manifest_digest })), failures: result.failures }));
      process.exit(result.failures.length ? 1 : 0);
    }
    case "finish": {
      const runId = opt("--run");
      const sandbox = opt("--sandbox");
      if (!runId || !sandbox) throw new Error("finish needs --run ID --sandbox DIR");
      const out = await finishRun(runId, resolve(sandbox), { snapshot: !rest.includes("--no-snapshot") });
      console.log(JSON.stringify({ ok: out.every((o) => !o.error), vms: out }));
      return;
    }
    case "list": {
      console.log(JSON.stringify({ ok: true, vms: await runVms(opt("--run")) }));
      return;
    }
    case "reap": {
      const removed = await reapVms({ run: opt("--run"), registry: opt("--registry") });
      console.log(JSON.stringify({ ok: true, removed }));
      return;
    }
    default:
      console.error("usage: vm.ts probe|create|finish|reap|msb-path (see the header)");
      process.exit(2);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => {
    console.error(`vm: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

export { ROOT };
