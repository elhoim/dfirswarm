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
 *   node --experimental-strip-types scripts/vm.ts finish --run ID --sandbox DIR [--no-snapshot] [--agent ID]
 *   node --experimental-strip-types scripts/vm.ts reap   [--run ID] [--registry FILE]
 *   node --experimental-strip-types scripts/vm.ts list   [--run ID]
 *   node --experimental-strip-types scripts/vm.ts toolbox --image REF --out FILE [--preset SETS] [--required]
 *   node --experimental-strip-types scripts/vm.ts catalog --image REF --sandbox DIR [--evidence DIR]... [--allow-host H]... [--memory MIB]
 *   node --experimental-strip-types scripts/vm.ts msb-path
 */
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, existsSync, readFileSync, realpathSync } from "node:fs";
import { mkdir, readFile, rm, stat, writeFile, readdir } from "node:fs/promises";
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

export type ResolvedSecret = {
  provider: string;
  kind: ProviderSpec["kind"];
  placeholder: string;
  value: string;
  hosts: string[];
  accountId?: string;
  /** Set when this is one variable of the provider's `env` block in Pi's store (an Azure key, say), not the provider's key itself. */
  envKey?: string;
};

/** A name under which a value is a credential: what may not cross into a VM in clear. */
export function secretLikeName(name: string): boolean {
  return /key|token|secret|password|passwd|credential|authorization/i.test(name);
}

/**
 * Every credential the team needs, resolved on the host by Pi's own commands
 * and held in this process's memory only. Throws with the reason when Pi
 * cannot produce one — the kickoff turns that into a BLOCKER.
 */
export async function resolveSecrets(spec: VmSpec): Promise<ResolvedSecret[]> {
  const pi = spec.pi_bin || "pi";
  // Pi reads the store the kickoff chose (--env PI_CODING_AGENT_DIR), not this process's.
  const env = spec.pi_agent_dir ? { ...process.env, PI_CODING_AGENT_DIR: spec.pi_agent_dir } : process.env;
  const dir = spec.pi_agent_dir || join(process.env.HOME || "", ".pi", "agent");
  const out: ResolvedSecret[] = [];
  let store: Record<string, Record<string, unknown>> = {};
  try {
    store = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as Record<string, Record<string, unknown>>;
  } catch {
    store = {};
  }
  let models: Record<string, Record<string, unknown>> = {};
  try {
    models = ((JSON.parse(readFileSync(join(dir, "models.json"), "utf8")) as { providers?: Record<string, Record<string, unknown>> }).providers ?? {});
  } catch {
    models = {};
  }
  for (const p of spec.providers) {
    if (p.kind === "local") continue;
    let value = "";
    let accountId: string | undefined;
    if (p.kind === "oauth") {
      const r = await run(pi, ["auth", "print-bearer-token", "--provider", p.provider, "--min-expiry", spec.min_token_validity || "2h"], { env });
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi could not produce a ${p.provider} subscription token valid for the run: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
      if (p.provider === "openai-codex") accountId = codexAccountId(value, spec.pi_agent_dir);
    } else {
      const r = await run(pi, ["auth", "print-api-key", "--provider", p.provider], { env });
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`pi has no key for ${p.provider}: ${r.stderr.trim() || `exit ${r.code}`}`);
      value = r.stdout.trim();
    }
    out.push({ provider: p.provider, kind: p.kind, placeholder: placeholderFor(p.provider, p.kind, accountId), value, hosts: p.hosts, ...(accountId ? { accountId } : {}) });
    // The provider's `env` block in Pi's store (Azure keeps its resource and
    // version there, and may keep a key): a variable named like a credential
    // is one, and crosses as its own placeholder bound to the same hosts.
    const block = store[p.provider]?.env;
    if (block && typeof block === "object") {
      for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
        if (typeof v !== "string" || !v || !secretLikeName(k)) continue;
        out.push({ provider: p.provider, kind: "api_key", placeholder: `dfirswarm-secret-${k.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}`, value: v, hosts: p.hosts, envKey: k });
      }
    }
    // A custom provider's headers (models.json): a literal under a credential
    // name is a credential and crosses as a placeholder; a value Pi would
    // resolve at request time ($ENV, !command) has no host-side value to
    // swap in, and is refused rather than sent in clear.
    const headers = models[p.provider]?.headers;
    if (headers && typeof headers === "object") {
      for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
        if (typeof v !== "string" || !secretLikeName(k)) continue;
        if (/^\s*[$!]/.test(v)) throw new Error(`models.json: provider ${p.provider} header ${k} is resolved by Pi at request time (${v.slice(0, 1)}…), which a VM cannot do without the value; put the literal in the store or the header`);
        out.push({ provider: p.provider, kind: "api_key", placeholder: `dfirswarm-secret-hdr-${k.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}`, value: v, hosts: p.hosts, envKey: `header:${k}` });
      }
    }
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
  let store: Record<string, Record<string, unknown>> = {};
  try {
    store = JSON.parse(readFileSync(join(dir, "auth.json"), "utf8")) as Record<string, Record<string, unknown>>;
  } catch {
    store = {};
  }
  for (const p of spec.providers) {
    const secret = secrets.find((s) => s.provider === p.provider && !s.envKey);
    const extras = secrets.filter((s) => s.provider === p.provider && s.envKey);
    const custom = providers[p.provider];
    if (custom) {
      const copy = { ...custom };
      if (secret && "apiKey" in copy) copy.apiKey = secret.placeholder;
      if (p.kind === "local" && typeof copy.baseUrl === "string") copy.baseUrl = hostGatewayUrl(copy.baseUrl);
      if (copy.headers && typeof copy.headers === "object") {
        const headers = { ...(copy.headers as Record<string, unknown>) };
        for (const s of extras) if (s.envKey?.startsWith("header:")) headers[s.envKey.slice(7)] = s.placeholder;
        copy.headers = headers;
      }
      keep[p.provider] = copy;
    }
    if (!secret) continue;
    // The provider's env block travels with its non-credential settings as
    // they are (a resource name, an API version) and its credentials as
    // placeholders; nothing else of the store's entry does.
    const block = store[p.provider]?.env;
    const guestEnv: Record<string, string> = {};
    if (block && typeof block === "object") {
      for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
        if (typeof v !== "string") continue;
        const swapped = extras.find((s) => s.envKey === k);
        if (swapped) guestEnv[k] = swapped.placeholder;
        else if (!secretLikeName(k)) guestEnv[k] = v;
      }
    }
    const env = Object.keys(guestEnv).length ? { env: guestEnv } : {};
    if (secret.kind === "oauth") {
      auth[p.provider] = {
        type: "oauth",
        access: secret.placeholder,
        refresh: "dfirswarm-vm-never-refreshes",
        expires: GUEST_OAUTH_EXPIRES,
        ...(secret.accountId ? { accountId: secret.accountId } : {}),
        ...env,
      };
    } else if (!custom || !("apiKey" in custom)) {
      auth[p.provider] = { type: "api_key", key: secret.placeholder, ...env };
    } else if (Object.keys(guestEnv).length) {
      auth[p.provider] = { type: "api_key", key: secret.placeholder, ...env };
    }
  }
  // The operator's settings, less what names this host: a proxy the guest
  // cannot reach, package and extension paths that are not in the image.
  let settings: string | null = null;
  try {
    const parsed = JSON.parse(readFileSync(join(dir, "settings.json"), "utf8")) as Record<string, unknown>;
    for (const k of ["httpProxy", "packages", "extensions", "shellPath"]) delete parsed[k];
    settings = `${JSON.stringify(parsed, null, 2)}\n`;
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
  # -t 600: a caller that sends its request and closes its writing side
  # still gets the answer; socat's default gives the hub half a second.
  setsid socat -t 600 UNIX-LISTEN:${GUEST_HUB_SOCKET},fork,mode=600,backlog=256 VSOCK-CONNECT:2:${HUB_PORT} </dev/null >>/run/dfirswarm/bridge.log 2>&1 &
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
  # --allow-install: pip lays packages into this VM's own disk, on its own
  # PATH and import path. Never a directory shared with the other VMs: a
  # shared prefix at the head of every seat's PATH let one seat put code in
  # front of every other's python. The seat's extension inventories it and
  # sends the list to the hub for toolchain.json.
  pyv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  mkdir -p "$SWARM_TOOLCHAIN"
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
def can_exec(path):
    try:
        with open(path, "w") as f:
            f.write("#!/bin/sh\\necho ran\\n")
        os.chmod(path, 0o755)
        r = subprocess.run([path], capture_output=True, text=True, timeout=30)
        os.unlink(path)
        return "exec" if "ran" in r.stdout else "noexec"
    except PermissionError:
        try:
            os.unlink(path)
        except OSError:
            pass
        return "noexec"
    except OSError as e:
        return "error:" + errno.errorcode.get(e.errno, str(e.errno))
out["base"] = can_write(os.path.join(S, ".vm-probe-" + A))
out["work"] = can_write(os.path.join(S, "work", ".vm-probe-" + A))
out["scratch"] = can_write(os.path.join(S, "work", A, ".vm-probe"))
out["extracted"] = can_write(os.path.join(S, "work", "extracted", A, ".vm-probe"))
out["extracted_exec"] = can_exec(os.path.join(S, "work", "extracted", A, ".vm-probe.sh"))
out["quarantine_exec"] = can_exec(os.path.join(S, "work", "quarantine", A, ".vm-probe.sh"))
out["tool_output"] = can_write(os.path.join(S, "tool-output", A, ".vm-probe"))
out["session"] = can_write(os.path.join(S, ".pi-sessions", A, ".vm-probe"))
inputs = os.path.join(S, "inputs")
if os.path.exists(inputs):
    out["inputs"] = can_write(os.path.join(os.path.realpath(inputs), ".vm-probe"))
    # Names, the way the manifest counts them: files, and links as links
    # (never followed — a link loop would never end).
    n = 0
    for root, dirs, files in os.walk(os.path.realpath(inputs)):
        n += len(files) + sum(1 for d in dirs if os.path.islink(os.path.join(root, d)))
    out["inputs_files"] = n
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
export function probeVerdict(probe: Record<string, unknown>, expectInputs: boolean, expectedInputFiles?: number): string[] {
  const wrong: string[] = [];
  if (probe.base !== "ro") wrong.push(`the sandbox floor is ${String(probe.base)}, not read-only`);
  if (probe.work !== "ro") wrong.push(`the shared work/ is ${String(probe.work)}, not read-only`);
  if (probe.scratch !== "rw") wrong.push(`its own work/<id>/ is ${String(probe.scratch)}, not writable`);
  if (probe.extracted !== "rw") wrong.push(`its own work/extracted/<id>/ is ${String(probe.extracted)}, not writable`);
  if (probe.extracted_exec !== "noexec") wrong.push(`work/extracted/<id>/ can execute (${String(probe.extracted_exec)})`);
  if (probe.quarantine_exec !== "noexec") wrong.push(`work/quarantine/<id>/ can execute (${String(probe.quarantine_exec)})`);
  if (probe.tool_output !== "rw") wrong.push(`its tool-output/ is ${String(probe.tool_output)}, not writable`);
  if (probe.session !== "rw") wrong.push(`its Pi session directory is ${String(probe.session)}, not writable`);
  if (expectInputs && probe.inputs !== "ro") wrong.push(`inputs/ is ${String(probe.inputs)}, not read-only`);
  if (expectInputs && typeof expectedInputFiles === "number" && typeof probe.inputs_files === "number" && probe.inputs_files !== expectedInputFiles) {
    wrong.push(`the VM sees ${probe.inputs_files} evidence name(s) where the manifest lists ${expectedInputFiles}`);
  }
  if (probe.hub !== true) wrong.push(`the hub is not reachable (${String(probe.hub_error ?? "no answer")})`);
  if (typeof probe.pi !== "string" || !/^\d+\.\d+/.test(probe.pi)) wrong.push(`pi does not run (${String(probe.pi)})`);
  return wrong;
}

/** Every mount one agent's VM gets: the run's own, then this agent's writable holes. */
export function mountsFor(spec: VmSpec, agent: string): Mount[] {
  const S = spec.sandbox;
  // `work/` is part of the read-only floor: the agent's own directories are
  // the writable holes on it, and what a peer wrote is read-only here. One
  // writable `work/` shared by every VM let any seat rewrite any other's
  // findings without a record (measured, and the ADR's own finding). A
  // shared deliverable is published through the hub (protocol.ts
  // publishFile). The extracted and quarantined material cannot execute.
  return [
    { host: S, readonly: true },
    ...spec.mounts,
    { host: join(S, "work", agent) },
    { host: join(S, "work", "extracted", agent), noexec: true },
    { host: join(S, "work", "quarantine", agent), noexec: true },
    { host: join(S, "tool-output", agent) },
    { host: join(S, ".pi-sessions", agent) },
    ...(spec.late_mounts ?? []),
  ];
}

type SdkModule = typeof import("microsandbox");
/** The SDK's secret builder, as far as this file uses it. */
type SecretB = { env(v: string): SecretB; value(v: string): SecretB; placeholder(p: string): SecretB; allow(h: string): SecretB };
type TlsB = { interceptedPorts(p: number[]): TlsB; bypass(h: string): TlsB };
type PolicyB = InstanceType<SdkModule["NetworkPolicyBuilder"]>;

/** Egress to the allowlist's hosts, one msb rule per port and kind (see egressRules). */
function allowEgress(policy: PolicyB, hosts: string[]): PolicyB {
  for (const rule of egressRules(hosts)) {
    if (rule.domains.length) policy.egress((r) => r.tcp().port(rule.port).allowDomains(rule.domains));
    if (rule.suffixes.length) policy.egress((r) => r.tcp().port(rule.port).allowDomainSuffixes(rule.suffixes));
    for (const ip of rule.ips) policy.egress((r) => r.tcp().port(rule.port).allow((d) => d.ip(ip)));
  }
  return policy;
}

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

/** The providers one seat's VM needs: its own model's, the summary model's, and every local one (no credential). */
export function seatProviders(spec: VmSpec, agent: VmSpec["agents"][number]): ProviderSpec[] {
  const mine = new Set([agent.model.split("/")[0], ...(spec.env?.SWARM_COMPACT_MODEL ? [spec.env.SWARM_COMPACT_MODEL.split("/")[0]] : [])]);
  return spec.providers.filter((p) => p.kind === "local" || mine.has(p.provider));
}

async function createOne(
  M: SdkModule,
  spec: VmSpec,
  agent: VmSpec["agents"][number],
  allSecrets: ResolvedSecret[],
): Promise<VmRecord> {
  const name = vmName(spec.run, agent.id);
  const mounts = mountsFor(spec, agent.id);
  for (const m of mounts) if (!m.readonly) await mkdir(m.host, { recursive: true });
  // Least privilege per seat: this VM holds the credentials of the model it
  // runs and of the summary model, reaches those providers' hosts, and no
  // other seat's.
  const providers = seatProviders(spec, agent);
  const mine = new Set(providers.map((p) => p.provider));
  const secrets = allSecrets.filter((s) => mine.has(s.provider));
  const piConfig = guestPiConfig({ ...spec, providers }, secrets);
  const hostPorts = providers.filter((p) => p.kind === "local" && p.port).map((p) => p.port as number);
  const allowHosts = [...new Set([...spec.allow_hosts, ...providers.flatMap((p) => (p.kind === "local" ? [] : p.hosts)), ...(spec.pack_secrets ?? []).flatMap((s) => s.hosts ?? [])])].sort();
  // A pack's secrets: the value is read here, on the host, from the store
  // `pack install` wrote (KEY=VALUE lines, or one bare value), and the VM
  // gets a placeholder under the secret's own name, which the pack's tool
  // reads from its environment and msb swaps for the value on the way to
  // the pack's hosts and nowhere else.
  const packSecrets: Array<{ name: string; value: string; hosts: string[]; placeholder: string }> = [];
  for (const s of spec.pack_secrets ?? []) {
    if (!s.hosts?.length) continue;
    let value = process.env[s.name] ?? "";
    if (s.value_file) {
      const text = await readFile(s.value_file, "utf8").catch(() => "");
      const line = text.split(/\r?\n/).find((l) => l.startsWith(`${s.name}=`));
      value = line ? line.slice(s.name.length + 1) : text.includes("=") ? "" : text.trim();
    }
    if (value) packSecrets.push({ name: s.name, value, hosts: s.hosts, placeholder: `dfirswarm-secret-${s.name.toLowerCase().replace(/[^a-z0-9]/g, "")}-${randomBytes(12).toString("hex")}` });
  }

  const policy = new M.NetworkPolicyBuilder().defaultDeny();
  if (spec.open_net) policy.egress((r) => r.allowPublic());
  allowEgress(policy, allowHosts);
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

  // Never `.replace()`: a VM of this name is another run's, or this run's
  // twin on another registry, and replacing it sends it SIGTERM. Run ids
  // are short, and the same one on two registries is a collision to refuse.
  if ((await runVms()).some((v) => v.name === name)) throw new Error(`a VM named ${name} exists already (another run with this id?); refusing to replace it`);
  let builder = M.Sandbox.builder(name)
    .image(spec.image)
    .pullPolicy(spec.pull ?? "if-missing")
    .cpus(spec.cpus ?? 2)
    .memory(spec.memory_mib ?? 2048)
    .rootDisk(spec.root_disk_mib ?? 8192)
    .detached(true)
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
          for (const h of tlsBypass(allowHosts)) if (!secretHosts.has(h)) t.bypass(h);
          return t;
        });
      }
      for (const s of secrets) {
        n.secret((b: SecretB) => {
          const label = s.envKey ? s.envKey.replace(/^header:/, "HEADER_") : `${s.provider}_CREDENTIAL`;
          b.env(`DFIRSWARM_${label.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}`).value(s.value).placeholder(s.placeholder);
          for (const h of s.hosts) b.allow(h);
          return b;
        });
      }
      for (const s of packSecrets) {
        n.secret((b: SecretB) => {
          b.env(s.name).value(s.value).placeholder(s.placeholder);
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
  const expectInputs = existsSync(join(spec.sandbox, "inputs"));
  let expectedInputFiles: number | undefined;
  try {
    expectedInputFiles = (JSON.parse(readFileSync(join(spec.sandbox, "inputs.json"), "utf8")) as { files?: unknown[] }).files?.length;
  } catch {
    expectedInputFiles = undefined;
  }
  const settled = await Promise.allSettled(spec.agents.map((a) => createOne(M, spec, a, secrets)));
  const records: VmRecord[] = [];
  const failures: Array<{ agent: string; reasons: string[] }> = [];
  settled.forEach((r, i) => {
    const agent = spec.agents[i].id;
    if (r.status === "rejected") {
      failures.push({ agent, reasons: [r.reason instanceof Error ? r.reason.message : String(r.reason)] });
      return;
    }
    records.push(r.value);
    const wrong = probeVerdict(r.value.probe, expectInputs, expectedInputFiles);
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
  // A list that failed is not an empty list: read as one, `stop` said a run
  // was put away while its VMs were up.
  if (r.code !== 0) throw new Error(`msb list failed: ${(r.stderr || r.stdout).trim() || `exit ${r.code}`}`);
  let rows: unknown;
  try {
    rows = JSON.parse(r.stdout || "[]");
  } catch {
    throw new Error("msb list answered something that is not JSON");
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
export type FinishEntry = { agent: string; name: string; snapshot?: string; error?: string; kept?: true };

/**
 * Put a run's VMs away: stop, snapshot, keep the logs, remove, record. One
 * finish at a time per run (the hub's own and an operator's `stop` used to
 * race on the same snapshot file); a VM whose snapshot failed is stopped and
 * kept, never removed, since removing it is the one step that cannot be
 * undone; and every msb step's outcome is in the entry, not swallowed.
 */
export async function finishRun(runId: string, sandbox: string, options: { snapshot?: boolean; agent?: string } = {}): Promise<FinishEntry[]> {
  const msb = msbBinary();
  const records = join(sandbox, "vm");
  const snapDir = `${sandbox}.vm-snapshots`;
  const out: FinishEntry[] = [];
  await mkdir(records, { recursive: true });
  const lock = join(records, ".finish.lock");
  let held = false;
  for (let i = 0; i < 20 && !held; i++) {
    try {
      await mkdir(lock);
      held = true;
    } catch {
      const age = await stat(lock).then((s) => Date.now() - s.mtimeMs).catch(() => 0);
      if (age > 30 * 60_000) await rm(lock, { recursive: true, force: true });
      else await new Promise((r) => setTimeout(r, 3000));
    }
  }
  if (!held) throw new Error(`another finish of run ${runId} is in progress (${lock})`);
  try {
  for (const vm of await runVms(runId)) {
    const agent = vm.agent || vm.name.replace(`dfs-${runId}-`, "");
    if (options.agent && agent !== options.agent) continue;
    const entry: FinishEntry = { agent, name: vm.name };
    const stopped = await run(msb, ["stop", vm.name], { timeoutMs: 120_000 });
    if (stopped.code !== 0 && !/not running|already stopped|stopped/i.test(`${stopped.stdout}${stopped.stderr}`)) {
      entry.error = `msb stop: ${(stopped.stderr || stopped.stdout).trim() || `exit ${stopped.code}`}`;
      entry.kept = true;
      out.push(entry);
      continue;
    }
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
        entry.kept = true;
        if (record) record.snapshot = { error: entry.error };
      }
    }
    // The VM's own logs (the runtime's, the guest kernel's, its execs) go
    // with it when it is removed; keep them beside the disk.
    const logs = join(process.env.MSB_HOME || join(process.env.HOME || "", ".microsandbox"), "sandboxes", vm.name, "logs");
    if (existsSync(logs)) {
      const keep = join(snapDir, `${agent}.logs`);
      await mkdir(keep, { recursive: true });
      const { readdir: ls, copyFile } = await import("node:fs/promises");
      for (const f of await ls(logs).catch(() => [])) await copyFile(join(logs, f), join(keep, f)).catch(() => undefined);
      if (record) (record as VmRecord & { logs?: string }).logs = keep;
    }
    if (!entry.kept) {
      const removed = await run(msb, ["rm", vm.name], { timeoutMs: 60_000 });
      if (removed.code !== 0) {
        entry.error = `msb rm: ${(removed.stderr || removed.stdout).trim() || `exit ${removed.code}`}`;
        entry.kept = true;
      }
    }
    if (record) {
      record.stopped_at = new Date().toISOString();
      if (entry.kept) (record as VmRecord & { kept?: string }).kept = entry.error;
      await writeFile(recordFile, `${JSON.stringify(record, null, 2)}\n`).catch(() => undefined);
    }
    out.push(entry);
  }
  } finally {
    await rm(lock, { recursive: true, force: true });
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

/**
 * The toolbox check (scripts/toolbox.sh) run where the agents will run: in
 * a throwaway VM of the run's image, offline. On the host it described the
 * host, which an agent in a VM never touches. Returns the check's exit code
 * (3: a required tool is missing) and the toolbox.json it wrote.
 */
export async function imageToolbox(image: string, preset: string, required: boolean): Promise<{ code: number; json: string; output: string }> {
  const M = await sdk();
  const { mkdtemp, copyFile } = await import("node:fs/promises");
  const tmp = await mkdtemp("/tmp/dfs-tb-");
  const name = `dfs-toolbox-${randomBytes(6).toString("hex")}`;
  try {
    await copyFile(join(ROOT, "scripts", "toolbox.sh"), join(tmp, "toolbox.sh"));
    await mkdir(join(tmp, "sbx"), { recursive: true });
    const sandbox = await M.Sandbox.builder(name)
      .image(image)
      .pullPolicy("if-missing")
      .cpus(1)
      .memory(1024)
      .maxDuration(1800)
      .labels({ [LABEL_RUN]: "toolbox", [LABEL_AGENT]: "toolbox" })
      .disableNetwork()
      .detached(true)
      .volume("/tb", (v) => v.bind(realpathSync(tmp)))
      .create();
    const out = await sandbox.exec("bash", ["/tb/toolbox.sh", "/tb/sbx", preset, ...(required ? ["--required"] : [])]);
    const json = await readFile(join(tmp, "sbx", "toolbox.json"), "utf8").catch(() => "");
    return { code: out.code, json, output: `${out.stdout()}${out.stderr()}` };
  } finally {
    await run(msbBinary(), ["stop", name], { timeoutMs: 60_000 });
    await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
    await rm(tmp, { recursive: true, force: true });
  }
}

/**
 * The evidence catalog (scripts/evidence-catalog.sh) run in a throwaway VM of
 * the run's image, before any agent starts: the tools it calls are the
 * image's, and a host that holds no forensic tools (by design) still gets a
 * first pass. The sandbox is mounted writable for this one harness step; the
 * evidence read-only. The network is off unless the operator allowed hosts
 * for the run (`--allow-host`), which then reach the catalog as they reach
 * the agents: Volatility fetches a Windows kernel's symbols the first time,
 * and on the host the catalog had the host's network.
 */
export async function imageCatalog(
  image: string,
  sandbox: string,
  evidence: string[],
  options: { cpus?: number; memoryMib?: number; allowHosts?: string[]; openNet?: boolean; run?: string; maxDurationSec?: number } = {},
): Promise<{ code: number; output: string; digest?: string }> {
  const M = await sdk();
  const name = `dfs-catalog-${randomBytes(6).toString("hex")}`;
  // The parser runs over hostile evidence as root in this VM: it may write
  // catalog/ and nothing else of the run. The run's floor — the manifest
  // custody compares against, the contract, the trace — is read-only here.
  await mkdir(join(sandbox, "catalog"), { recursive: true });
  try {
    let builder = M.Sandbox.builder(name)
      .image(image)
      .pullPolicy("if-missing")
      .cpus(options.cpus ?? 2)
      .memory(options.memoryMib ?? 2048)
      .maxDuration(options.maxDurationSec ?? 4 * 3600)
      .labels({ [LABEL_RUN]: options.run ?? "catalog", [LABEL_AGENT]: "catalog", ...(options.run ? {} : {}) });
    if (options.openNet) {
      // --no-netguard: the catalog reaches what the agents reach.
      const policy = new M.NetworkPolicyBuilder().defaultDeny();
      policy.egress((r) => r.allowPublic());
      builder = builder.network((n) => n.policyFromBuilder(policy));
    } else if (options.allowHosts?.length) {
      const policy = allowEgress(new M.NetworkPolicyBuilder().defaultDeny(), options.allowHosts);
      builder = builder.network((n) => n.policyFromBuilder(policy));
    } else {
      builder = builder.disableNetwork();
    }
    builder = builder
      .detached(true)
      .replace()
      .workdir(sandbox)
      .envs({
        SWARM_CATALOG_STEP_TIMEOUT: process.env.SWARM_CATALOG_STEP_TIMEOUT ?? "900",
        ...(process.env.SWARM_CATALOG_MEMORY_PROBE_TIMEOUT ? { SWARM_CATALOG_MEMORY_PROBE_TIMEOUT: process.env.SWARM_CATALOG_MEMORY_PROBE_TIMEOUT } : {}),
      })
      .volume(sandbox, (v) => v.bind(realpathSync(sandbox)).readonly())
      .volume(join(sandbox, "catalog"), (v) => v.bind(realpathSync(join(sandbox, "catalog"))))
      .volume(join(ROOT, "scripts"), (v) => v.bind(realpathSync(join(ROOT, "scripts"))).readonly());
    for (const e of evidence) builder = builder.volume(e, (v) => v.bind(realpathSync(e)).readonly().noexec());
    const vm = await builder.create();
    const out = await vm.exec("bash", [join(ROOT, "scripts", "evidence-catalog.sh"), sandbox]);
    const digest = await imageDigest(name);
    return { code: out.code, output: `${out.stdout()}${out.stderr()}`, ...(digest ? { digest } : {}) };
  } finally {
    await run(msbBinary(), ["stop", name], { timeoutMs: 120_000 });
    await run(msbBinary(), ["rm", name], { timeoutMs: 60_000 });
  }
}

/**
 * The host allowlist's own syntax (scripts/netguard-proxy.mjs: an exact host,
 * `.suffix` or `*.suffix` for the names under it, `host:port`, an address) as
 * msb egress rules, one per port. Without this a `--allow-host
 * '*.blob.core.windows.net'` that works on the host would match nothing in a
 * VM.
 */
export function egressRules(hosts: string[]): Array<{ port: number; domains: string[]; suffixes: string[]; ips: string[] }> {
  const byPort = new Map<number, { port: number; domains: string[]; suffixes: string[]; ips: string[] }>();
  for (const raw of hosts) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;
    let host = entry;
    let port = 443;
    const m = entry.match(/^(.*):(\d+)$/);
    if (m && !entry.startsWith("[")) {
      host = m[1];
      port = Number.parseInt(m[2], 10);
    }
    if (host.startsWith("*.")) host = host.slice(1);
    const rule = byPort.get(port) ?? { port, domains: [], suffixes: [], ips: [] };
    byPort.set(port, rule);
    if (host.startsWith(".")) rule.suffixes.push(host);
    else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) rule.ips.push(host.replace(/^\[|\]$/g, ""));
    else rule.domains.push(host);
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

/** The same allowlist as TLS bypass patterns: a suffix is `*.suffix` to msb. */
export function tlsBypass(hosts: string[]): string[] {
  return egressRules(hosts).flatMap((r) => [...r.domains, ...r.suffixes.map((s) => `*${s}`)]);
}

/** catalog.json beside catalog/: the image and every file's sha256, written on the host after the VM is gone. */
export async function writeCatalogRecord(sandbox: string, image: string, digest: string | null): Promise<void> {
  const root = join(sandbox, "catalog");
  const files: Array<{ path: string; bytes: number; sha256: string }> = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const abs = join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) await walk(abs);
      else if (e.isFile()) files.push({ path: `catalog/${abs.slice(root.length + 1)}`, bytes: (await stat(abs)).size, sha256: await sha256File(abs) });
    }
  };
  await walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  await writeFile(join(sandbox, "catalog.json"), `${JSON.stringify({ at: new Date().toISOString(), image, manifest_digest: digest, files }, null, 2)}\n`);
}

/** The manifest digest of the image a VM was made from, from msb's own record of it. */
export async function imageDigest(name: string): Promise<string | null> {
  const r = await run(msbBinary(), ["inspect", name, "--format", "json"], { timeoutMs: 30_000 });
  if (r.code !== 0) return null;
  try {
    return (JSON.parse(r.stdout) as { config?: { manifest_digest?: string } }).config?.manifest_digest ?? null;
  } catch {
    return null;
  }
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
      const out = await finishRun(runId, resolve(sandbox), { snapshot: !rest.includes("--no-snapshot"), agent: opt("--agent") });
      const ok = out.every((o) => !o.error);
      console.log(JSON.stringify({ ok, vms: out }));
      process.exit(ok ? 0 : 1);
    }
    case "toolbox": {
      const image = opt("--image");
      const preset = opt("--preset") ?? "dfir";
      const out = opt("--out");
      if (!image || !out) throw new Error("toolbox needs --image REF --out FILE [--preset SETS] [--required]");
      const r = await imageToolbox(image, preset, rest.includes("--required"));
      if (r.json) await writeFile(out, r.json);
      // The script names the file at its guest path; the operator reads the host's.
      process.stderr.write(r.output.replaceAll("/tb/sbx/toolbox.json", out));
      process.exit(r.json ? r.code : 1);
    }
    case "catalog": {
      const image = opt("--image");
      const sandbox = opt("--sandbox");
      if (!image || !sandbox) throw new Error("catalog needs --image REF --sandbox DIR [--evidence DIR]... [--allow-host H]... [--open-net] [--memory MIB] [--cpus N] [--run ID]");
      const evidence: string[] = [];
      const allowHosts: string[] = [];
      rest.forEach((a, i) => {
        if (a === "--evidence" && rest[i + 1]) evidence.push(rest[i + 1]);
        if (a === "--allow-host" && rest[i + 1]) allowHosts.push(...rest[i + 1].split(",").filter(Boolean));
      });
      const r = await imageCatalog(image, resolve(sandbox), evidence, {
        memoryMib: opt("--memory") ? Number(opt("--memory")) : undefined,
        cpus: opt("--cpus") ? Number(opt("--cpus")) : undefined,
        allowHosts,
        openNet: rest.includes("--open-net"),
        run: opt("--run"),
      });
      process.stdout.write(r.output);
      // What the catalog was built with, beside it: the image it booted and
      // the sha256 of every file it wrote, so a catalog cannot be changed
      // after the fact without it showing.
      await writeCatalogRecord(resolve(sandbox), image, r.digest ?? null).catch((err: Error) => process.stderr.write(`catalog record: ${err.message}\n`));
      process.exit(r.code);
    }
    case "list": {
      try {
        console.log(JSON.stringify({ ok: true, vms: await runVms(opt("--run")) }));
      } catch (err) {
        console.log(JSON.stringify({ ok: false, error: (err as Error).message }));
        process.exit(1);
      }
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
