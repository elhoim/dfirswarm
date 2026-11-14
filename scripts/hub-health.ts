/**
 * What the hub writes about itself each minute, and when it takes a heap
 * snapshot.
 *
 * Three post-mortems could not separate causes because nothing recorded the
 * host or the hub while a run slowed: whether the shared machine or the
 * run's own sweeps made a hub slow, which structure filled a heap, how late
 * the event loop was. The snapshot Node writes at the heap limit was 0 bytes
 * on the run s17fdfe: the hub died while writing it. So the hub samples
 * itself and the host on the trace (hub_health), and takes its snapshot at
 * 60% of the limit, once, while it still can.
 */
import { execFile } from "node:child_process";
import { open, readFile, rm } from "node:fs/promises";
import { cpus, freemem, loadavg, totalmem } from "node:os";
import { join } from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";
import v8 from "node:v8";

export type HubHealth = {
  rss_mb: number;
  heap_used_mb: number;
  heap_limit_mb: number;
  external_mb: number;
  /** The event loop's delay over the last sample period: how late a timer fired, in ms. */
  loop_p50_ms: number;
  loop_p99_ms: number;
  loop_max_ms: number;
  /** The host: load average over one minute, cores, memory free of total. */
  host_load1: number;
  host_cpus: number;
  host_free_mb: number;
  host_total_mb: number;
  /**
   * The memory pressure the host's own kernel reports (memoryPressure): its
   * level, where it came from, and on Linux the share of the last ten
   * seconds some or all tasks waited on memory. Free memory alone said
   * nothing on macOS, which keeps it full of cache.
   */
  mem_pressure: PressureLevel;
  mem_pressure_from: PressureSource;
  mem_some_avg10?: number;
  mem_full_avg10?: number;
  /** How fast the disk under the hub's directory took a write and its fsync this minute (diskSpeed); null when it could not be measured. */
  disk_write_mb_s: number | null;
  disk_fsync_ms: number | null;
  disk_error?: string;
  /**
   * The sizes of the hub's own large structures, by name: each one's count
   * and, where it holds bytes, `<name>_bytes` (transfers held, the answers
   * kept for a retry, the store sweeps and the ledger read and kept, prompts
   * queued, jobs).
   */
  holds: Record<string, number>;
};

export type PressureLevel = "normal" | "warn" | "critical" | null;
export type PressureSource = "macos" | "linux-psi" | "freemem";
export type Pressure = { mem_pressure: PressureLevel; mem_pressure_from: PressureSource; mem_some_avg10?: number; mem_full_avg10?: number };

/** What a host says when nothing can be read of it: no pressure known, measured by free memory. */
const UNKNOWN_PRESSURE: Pressure = { mem_pressure: null, mem_pressure_from: "freemem" };
/** Disk and pressure are measured on the minute; a sample taken without them says so. */
const UNMEASURED_DISK = { disk_write_mb_s: null, disk_fsync_ms: null } as const;

/**
 * The host's memory pressure as its kernel reports it: on macOS the level
 * the memory status keeps (`sysctl kern.memorystatus_vm_pressure_level`: 1
 * normal, 2 warn, 4 critical; the level `memory_pressure` prints); on Linux
 * the pressure stall information (/proc/pressure/memory: critical when all
 * tasks waited 10% of the last ten seconds, warn when some did); elsewhere,
 * or when neither can be read, free memory of the total (under 5% critical,
 * under 15% warn).
 */
export async function memoryPressure(o: { platform?: NodeJS.Platform; psiFile?: string; sysctl?: () => Promise<string>; free?: number; total?: number } = {}): Promise<Pressure> {
  const platform = o.platform ?? process.platform;
  if (platform === "darwin") {
    const run = o.sysctl ?? (() => new Promise<string>((resolve, reject) => execFile("/usr/sbin/sysctl", ["-n", "kern.memorystatus_vm_pressure_level"], { timeout: 2000 }, (err, out) => (err ? reject(err) : resolve(String(out))))));
    const level = Number((await run().catch(() => "")).trim());
    if (level === 1 || level === 2 || level === 4) return { mem_pressure: level === 1 ? "normal" : level === 2 ? "warn" : "critical", mem_pressure_from: "macos" };
  }
  if (platform === "linux" || o.psiFile) {
    const text = await readFile(o.psiFile ?? "/proc/pressure/memory", "utf8").catch(() => "");
    const avg = (kind: string) => {
      const m = new RegExp(`^${kind} avg10=([0-9.]+)`, "m").exec(text);
      return m ? Number(m[1]) : NaN;
    };
    const some = avg("some");
    const full = avg("full");
    if (Number.isFinite(some)) {
      return { mem_pressure: full >= 10 ? "critical" : some >= 10 ? "warn" : "normal", mem_pressure_from: "linux-psi", mem_some_avg10: some, ...(Number.isFinite(full) ? { mem_full_avg10: full } : {}) };
    }
  }
  const free = o.free ?? freemem();
  const total = o.total ?? totalmem();
  if (!(total > 0)) return UNKNOWN_PRESSURE;
  const share = free / total;
  return { mem_pressure: share < 0.05 ? "critical" : share < 0.15 ? "warn" : "normal", mem_pressure_from: "freemem" };
}

/**
 * How fast the disk under `dir` is now: `bytes` written to a file of its own
 * there, then fsync'd, timed, and the file removed. A shared machine whose
 * disk was slow made a hub slow while nothing said so.
 */
export async function diskSpeed(dir: string, bytes = 1024 * 1024): Promise<{ disk_write_mb_s: number | null; disk_fsync_ms: number | null; disk_error?: string }> {
  const file = join(dir, `.disk-probe.${process.pid}`);
  const data = Buffer.alloc(bytes, 0x5a);
  let fh: Awaited<ReturnType<typeof open>> | null = null;
  try {
    const t0 = performance.now();
    fh = await open(file, "w", 0o600);
    await fh.write(data, 0, data.length, 0);
    const t1 = performance.now();
    await fh.sync();
    const t2 = performance.now();
    const secs = Math.max(t2 - t0, 0.001) / 1000;
    return { disk_write_mb_s: Math.round((bytes / 2 ** 20 / secs) * 10) / 10, disk_fsync_ms: Math.round((t2 - t1) * 10) / 10 };
  } catch (err) {
    return { ...UNMEASURED_DISK, disk_error: (err as Error).message.slice(0, 200) };
  } finally {
    await fh?.close().catch(() => undefined);
    await rm(file, { force: true }).catch(() => undefined);
  }
}

const mb = (x: number) => Math.round(x / 2 ** 20);

export function loopMonitor(): { read(): { p50: number; p99: number; max: number }; stop(): void } {
  const h = monitorEventLoopDelay({ resolution: 20 });
  h.enable();
  return {
    read() {
      const out = { p50: Math.round(h.percentile(50) / 1e6), p99: Math.round(h.percentile(99) / 1e6), max: Math.round(h.max / 1e6) };
      h.reset();
      return out;
    },
    stop: () => h.disable(),
  };
}

export function sampleHealth(loop: { p50: number; p99: number; max: number }, holds: Record<string, number> = {}, host: { pressure?: Pressure; disk?: { disk_write_mb_s: number | null; disk_fsync_ms: number | null; disk_error?: string } } = {}): HubHealth {
  const m = process.memoryUsage();
  return {
    rss_mb: mb(m.rss),
    heap_used_mb: mb(m.heapUsed),
    heap_limit_mb: mb(v8.getHeapStatistics().heap_size_limit),
    external_mb: mb(m.external),
    loop_p50_ms: loop.p50,
    loop_p99_ms: loop.p99,
    loop_max_ms: loop.max,
    host_load1: Math.round(loadavg()[0]! * 100) / 100,
    host_cpus: cpus().length,
    host_free_mb: mb(freemem()),
    host_total_mb: mb(totalmem()),
    ...(host.pressure ?? UNKNOWN_PRESSURE),
    ...(host.disk ?? UNMEASURED_DISK),
    holds,
  };
}

/** How often the hub samples itself (SWARM_HUB_HEALTH_MS; a test shortens it): each minute. */
export function healthEveryMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_HUB_HEALTH_MS);
  return Number.isFinite(n) && n >= 100 ? Math.floor(n) : 60_000;
}

/** The share of the heap limit at which the hub takes its one snapshot (SWARM_HUB_SNAPSHOT_AT, 0 for never). */
export function snapshotAt(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_HUB_SNAPSHOT_AT);
  return env.SWARM_HUB_SNAPSHOT_AT !== undefined && Number.isFinite(n) && n >= 0 && n < 1 ? n : 0.6;
}

/** Whether a snapshot is due: the heap is past the line and none was taken yet. */
export function snapshotDue(h: { heap_used_mb: number; heap_limit_mb: number }, taken: boolean, at = snapshotAt()): boolean {
  return !taken && at > 0 && h.heap_limit_mb > 0 && h.heap_used_mb > at * h.heap_limit_mb;
}

/** The share of the heap limit past which a supervised hub restarts itself at a quiet moment (SWARM_HUB_RECYCLE_AT, 0 for never). */
export function recycleAt(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_HUB_RECYCLE_AT);
  return env.SWARM_HUB_RECYCLE_AT !== undefined && Number.isFinite(n) && n >= 0 && n < 1 ? n : 0.85;
}

/**
 * Whether the hub should end now so that its keeper starts it again with --resume: its heap is past recycleAt, it is
 * kept by hub-supervise (a hub nobody restarts must not end itself), no seat's call is in flight, and no job runs or
 * waits to be sealed (a queued or committed job is on the journal and replayed whole). Two hubs of the runs s082123 and
 * s17fdfe ran out of heap mid-call and took every seat's board with them; a restart at a quiet moment costs a few
 * seconds of links that reconnect.
 */
export function recycleDue(h: { heap_used_mb: number; heap_limit_mb: number }, o: { supervised: boolean; callsInFlight: number; jobsBusy: number }, at = recycleAt()): { due: boolean; why: string } {
  if (!(at > 0) || !(h.heap_limit_mb > 0) || h.heap_used_mb <= at * h.heap_limit_mb) return { due: false, why: "below the line" };
  if (!o.supervised) return { due: false, why: "no keeper would start it again" };
  if (o.callsInFlight > 0) return { due: false, why: `${o.callsInFlight} call(s) in flight` };
  if (o.jobsBusy > 0) return { due: false, why: `${o.jobsBusy} job(s) running or waiting to be sealed` };
  return { due: true, why: `heap ${h.heap_used_mb} of ${h.heap_limit_mb} MB, past ${Math.round(at * 100)}%, with no call in flight and no job running` };
}
