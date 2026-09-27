/**
 * Phase 4 adapters for a release's digest, each optional and each said as
 * unavailable when its tool is not there:
 *
 * - OpenTimestamps: the `ots` client stamps the release's signature
 *   (release.json.sig.ots); the proof is pending until a Bitcoin block
 *   commits it, and `--upgrade` completes it later. Free, and verifiable
 *   offline once complete;
 * - a transparency log: a command the operator names receives the digest
 *   line on stdin and the release's files in its environment
 *   (DFS_RELEASE_JSON, DFS_RELEASE_SIG, DFS_RELEASE_SHA256); what it prints
 *   is kept whole as the receipt (transparency-<k>.json). Which log, and
 *   which client, is the operator's choice: nothing here knows one.
 *
 * Neither is inside a release: both are about its bytes, kept beside them.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { digestLine, pickRelease } from "./release-record.ts";

const fileSha = (p: string): string | null => {
  try {
    return createHash("sha256").update(readFileSync(p)).digest("hex");
  } catch {
    return null;
  }
};

function nextName(dir: string, stem: string, ext: string): string {
  let k = 1;
  while (existsSync(join(dir, `${stem}-${k}.${ext}`))) k += 1;
  return join(dir, `${stem}-${k}.${ext}`);
}

/** An OpenTimestamps proof of a release's signature (release.json.sig.ots), when the ots client is on this host. */
export function otsRelease(S: string, o: { version?: number; upgrade?: boolean } = {}): { ok: boolean; note: string } {
  const r = pickRelease(S, o.version);
  const sig = join(r.dir, "release.json.sig");
  const which = spawnSync("ots", ["--version"], { encoding: "utf8" });
  if ((which.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return { ok: false, note: "unavailable: the OpenTimestamps client (ots) is not on this host; pip install opentimestamps-client adds it" };
  if (!existsSync(`${sig}.ots`)) {
    const p = spawnSync("ots", ["stamp", sig], { encoding: "utf8", timeout: 120_000 });
    if (p.status !== 0 || !existsSync(`${sig}.ots`)) return { ok: false, note: `ots stamp failed: ${`${p.stderr}${p.stdout}`.trim() || `exit ${p.status}`}` };
    return { ok: true, note: `release v${r.version}'s signature was sent to the OpenTimestamps calendars (release.json.sig.ots): the proof is pending until a Bitcoin block commits it; swarm.sh releases <id> --ots --upgrade completes it later` };
  }
  if (o.upgrade) {
    const p = spawnSync("ots", ["upgrade", `${sig}.ots`], { encoding: "utf8", timeout: 120_000 });
    return { ok: p.status === 0, note: `${`${p.stdout}${p.stderr}`.trim() || `exit ${p.status}`}` };
  }
  const info = spawnSync("ots", ["info", `${sig}.ots`], { encoding: "utf8" });
  return { ok: info.status === 0, note: `${info.stdout ?? ""}`.trim() || "an OpenTimestamps proof is beside the signature" };
}

/**
 * A transparency log's receipt for a release: `command` is run with bash,
 * the digest line on stdin and the release's files named in the
 * environment (DFS_RELEASE_JSON, DFS_RELEASE_SIG, DFS_RELEASE_SHA256); what
 * it prints is kept whole as the receipt (transparency-<k>.json). The log
 * and its client are the operator's choice; nothing here knows one.
 */
export function transparencyRelease(S: string, command: string, version?: number): { ok: boolean; note: string } {
  const r = pickRelease(S, version);
  const sigSha = fileSha(join(r.dir, "release.json.sig"));
  const line = digestLine(r.record, r.sha256, sigSha);
  const p = spawnSync("bash", ["-c", command], { input: `${line}\n`, encoding: "utf8", timeout: 300_000, env: { ...process.env, DFS_RELEASE_JSON: join(r.dir, "release.json"), DFS_RELEASE_SIG: join(r.dir, "release.json.sig"), DFS_RELEASE_SHA256: r.sha256, DFS_RELEASE_VERSION: String(r.version), DFS_RUN: String(r.record.run ?? "") } });
  const file = nextName(r.dir, "transparency", "json");
  writeFileSync(file, `${JSON.stringify({ kind: "transparency-log", command, at: new Date().toISOString(), exit: p.status, stdout: p.stdout ?? "", stderr: p.stderr ?? "", line }, null, 2)}\n`, { mode: 0o444, flag: "wx" });
  return { ok: p.status === 0, note: p.status === 0 ? `the log answered; its receipt is ${basename(file)}` : `the log command exited ${p.status ?? p.signal}; what it said is in ${basename(file)}` };
}
