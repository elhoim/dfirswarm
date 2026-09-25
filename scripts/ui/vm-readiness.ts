/**
 * Can this machine run the agents in microVMs, asked before Start: the
 * platform, msb and its doctor, the image, and whether N VMs of a size fit.
 * Read-only: it runs `vm.ts probe` and `vm.ts capacity`, which boot nothing,
 * and says where the runs directory is when it sits in a synced folder. The
 * kickoff asks the same things and refuses on them; this says so before the
 * operator presses Start instead of in the job's BLOCKER after.
 */
import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { join } from "node:path";

/** The msb the harness was measured against (ADR 0009); another version is said, not refused. */
export const MEASURED_MSB = "0.7.2";

export type VmReadiness = {
  checked_at: string;
  /** Everything the kickoff would refuse on is clear. */
  ok: boolean;
  /** Why a VM run would be refused here, each in the kickoff's words; empty when ok. */
  reasons: string[];
  /** What is worth knowing that does not stop a run. */
  warnings: string[];
  msb: { path: string; version: string; measured: string; matches: boolean } | null;
  /** msb doctor's whole output when it failed. */
  doctor_output: string | null;
  image: { ref: string; present: boolean; digest: string | null } | null;
  capacity: { ok: boolean; blockers: string[]; warnings: string[]; host: { mem_mib: number; cpus: number } | null } | null;
  /** The runs directory and the synced folder it is in, if any: a copy of the evidence or the VMs' disks there needs allow_synced_folder. */
  runs_dir: { path: string; synced: string | null };
};

export type VmReadinessQuery = { image?: string; n?: number; cpus?: number; memory?: number };

type Run = { code: number; stdout: string; stderr: string };

function runVmCli(root: string, args: string[], timeoutMs: number): Promise<Run> {
  return new Promise((done) => {
    execFile(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", join(root, "scripts", "vm.ts"), ...args],
      { timeout: timeoutMs, env: process.env, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => done({ code: err ? (typeof (err as NodeJS.ErrnoException & { code?: unknown }).code === "number" ? Number((err as { code: number }).code) : 1) : 0, stdout: String(stdout), stderr: String(stderr) }),
    );
  });
}

/** The synced folder a path is in, as swarm.sh synced_folder_of names it; null when none. */
export function syncedFolderOf(path: string): string | null {
  const m = path.match(/\/Library\/CloudStorage\/([^/]+)/);
  if (m) return m[1];
  if (path.includes("/Library/Mobile Documents/")) return "iCloud Drive";
  if (/\/Dropbox(\/|$)/.test(path)) return "Dropbox";
  if (/\/OneDrive/.test(path) || path.includes("/Google Drive/")) return "a synced drive";
  return null;
}

function lastJson(text: string): Record<string, unknown> | null {
  const lines = text.trim().split("\n").reverse();
  for (const line of lines) {
    try {
      const v = JSON.parse(line) as unknown;
      if (v && typeof v === "object") return v as Record<string, unknown>;
    } catch {
      // not the JSON line
    }
  }
  return null;
}

export async function checkVmReadiness(root: string, runsDir: string, q: VmReadinessQuery): Promise<VmReadiness> {
  const reasons: string[] = [];
  const warnings: string[] = [];
  const probe = await runVmCli(root, ["probe", ...(q.image ? ["--image", q.image] : [])], 90_000);
  const p = lastJson(probe.stdout);
  let msb: VmReadiness["msb"] = null;
  let doctor: string | null = null;
  let image: VmReadiness["image"] = null;
  if (!p) {
    reasons.push(`vm.ts probe gave no answer (exit ${probe.code})${probe.stderr.trim() ? `: ${probe.stderr.trim()}` : ""}`);
  } else {
    for (const r of Array.isArray(p.reasons) ? p.reasons : []) reasons.push(String(r));
    const version = typeof p.version === "string" ? p.version.replace(/^msb\s+/, "") : "";
    if (version) {
      msb = { path: String(p.msb ?? "msb"), version, measured: MEASURED_MSB, matches: version.includes(MEASURED_MSB) };
      if (!msb.matches) warnings.push(`msb ${version} is not the ${MEASURED_MSB} the harness was measured against; the kickoff warns about it too`);
    }
    if (typeof p.doctor_output === "string") doctor = p.doctor_output;
    if (q.image) {
      image = { ref: q.image, present: p.image_present === true, digest: typeof p.image_digest === "string" ? p.image_digest : null };
      if (!image.present) reasons.push(`the image ${q.image} is not on this host; build it (images/README.md) or pull it before Start`);
    }
  }
  let capacity: VmReadiness["capacity"] = null;
  if (q.n && q.cpus && q.memory) {
    const c = await runVmCli(root, ["capacity", "--n", String(q.n), "--cpus", String(q.cpus), "--memory", String(q.memory)], 30_000);
    const v = lastJson(c.stdout);
    if (v) {
      const blockers = Array.isArray(v.blockers) ? v.blockers.map(String) : [];
      const warns = Array.isArray(v.warnings) ? v.warnings.map(String) : [];
      const host = v.host && typeof v.host === "object" ? (v.host as { mem_mib?: unknown; cpus?: unknown }) : null;
      capacity = { ok: blockers.length === 0, blockers, warnings: warns, host: host ? { mem_mib: Number(host.mem_mib) || 0, cpus: Number(host.cpus) || 0 } : null };
      reasons.push(...blockers);
      warnings.push(...warns);
    }
  }
  const resolved = await realpath(runsDir).catch(() => runsDir);
  const synced = syncedFolderOf(resolved);
  if (synced) warnings.push(`the runs directory is in ${synced}: a copy of the evidence or the VMs' disks there is refused unless allow_synced_folder is set (or name a vm_snapshot_dir outside it)`);
  return {
    checked_at: new Date().toISOString(),
    ok: reasons.length === 0,
    reasons,
    warnings,
    msb,
    doctor_output: doctor,
    image,
    capacity,
    runs_dir: { path: resolved, synced },
  };
}

/** The flags `swarm.sh help start` documents, so the form offers only what this harness has (e.g. --model-gateway). */
export function startFlags(root: string): Promise<string[]> {
  return new Promise((done) => {
    execFile("bash", [join(root, "scripts", "swarm.sh"), "help", "start"], { timeout: 20_000, env: process.env, maxBuffer: 4 * 1024 * 1024 }, (_err, stdout, stderr) => {
      const text = `${stdout}\n${stderr}`;
      done([...new Set(text.match(/--[a-z][a-z0-9-]+/g) ?? [])].sort());
    });
  });
}
