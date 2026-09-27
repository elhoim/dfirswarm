/**
 * A release's witnesses: what stands outside this host's account for a
 * release's digest, each kept beside the release and never inside it
 * (scripts/release-record.ts says what a release is).
 *
 * - an RFC 3161 token over the release's signature, checked against the
 *   authority's CA when one is named; obtained later (an air-gapped lab's
 *   `swarm.sh timestamp`), it dates the proof of existence from then;
 * - a mirror of the digest line: a command that receives it on stdin (its
 *   output kept whole as the receipt), a directory another custodian keeps
 *   (a file per release, never written over), or a printed line with a
 *   QR-ready string for the case file.
 *
 * What each proves is said where it is written. The anchor beside the run is
 * this account's own file; a mirror in a folder of the same account is too.
 * An object-locked bucket, or a records custodian's separately administered
 * archive, is the independent copy; a signed git remote is a witness of when
 * a line was pushed, not a write-once store.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { timestampFile, verifyTimestampToken } from "./custody-checks.ts";
import { digestLine, pickRelease, qrString, releaseSigPath, RELEASE_DIR } from "./release-record.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const fileSha = (p: string): string | null => {
  try {
    return sha256(readFileSync(p));
  } catch {
    return null;
  }
};

/**
 * An RFC 3161 token over a release's signature (release.json.sig, or
 * release.json.p7s for an e-signature), checked
 * against the authority's CA when one is named. The token dates the
 * signature, and with it the release, from the authority's time: obtained
 * later, the proof of existence is from then, and timestamp.json says so.
 */
export async function timestampRelease(dir: string, o: { url: string; ca: string | null; releaseAt: string }): Promise<{ ok: true; note: string; verified: boolean | null } | { ok: false; why: string }> {
  const sig = releaseSigPath(dir);
  if (!existsSync(sig)) return { ok: false, why: "the release has no signature to timestamp" };
  if (existsSync(`${sig}.tsr`)) return { ok: false, why: `the release is timestamped already (${basename(sig)}.tsr)` };
  const r = await timestampFile(sig, o.url);
  if (!r.ok) return { ok: false, why: r.why };
  const checked = o.ca ? await verifyTimestampToken(r.tsr, sig, o.ca) : null;
  const obtained = new Date().toISOString();
  const later = Date.parse(obtained) - Date.parse(o.releaseAt) > 10 * 60_000;
  const rec = {
    kind: "dfirswarm-release-timestamp",
    obtained_at: obtained,
    authority: o.url,
    gen_time: r.gen_time,
    token: { file: `${basename(sig)}.tsr`, sha256: r.sha256 },
    imprint_of: { file: basename(sig), sha256: sha256(readFileSync(sig)) },
    signature: checked ? { verified: checked.verified, ca: o.ca, ca_sha256: o.ca && existsSync(o.ca) ? sha256(readFileSync(o.ca)) : null, detail: checked.detail } : { verified: null, ca: null, detail: "imprint only: no CA was named, so the authority's signature on the token was not checked" },
    note: later
      ? `Obtained ${obtained}, after the release was sealed (${o.releaseAt}): the release's proof of existence dates from the token's time (${r.gen_time ?? "unread"}), not from the release's own.`
      : `Obtained when the release was sealed: the release existed by the token's time (${r.gen_time ?? "unread"}).`,
  };
  writeFileSync(join(dir, "timestamp.json"), `${JSON.stringify(rec, null, 2)}\n`, { mode: 0o444, flag: "wx" });
  if (checked && checked.verified !== true) return { ok: true, verified: checked.verified, note: `token from ${o.url} (${r.gen_time ?? "time unread"}) ${checked.verified === false ? "DOES NOT VERIFY" : "could not be checked"} against ${o.ca}: ${checked.detail}` };
  return { ok: true, verified: checked?.verified ?? null, note: `token from ${o.url}, ${r.gen_time ?? "time unread"}${checked ? `, verified against ${o.ca}` : ", imprint only (no CA named)"}${later ? "; obtained after the release: the proof of existence dates from the token" : ""}` };
}

function nextName(dir: string, stem: string, ext: string): string {
  let k = 1;
  while (existsSync(join(dir, `${stem}-${k}.${ext}`))) k += 1;
  return join(dir, `${stem}-${k}.${ext}`);
}

/**
 * The release's digest line to an independent copy, and a record of it
 * beside the release (mirror-<k>.json):
 * - cmd:COMMAND: run with bash, the line on its stdin; its output is the
 *   receipt, kept whole;
 * - dir:PATH: a file per release written there, never over one (an
 *   object-locked bucket's mount or a records custodian's share is the
 *   independent copy; a folder of the same account is not);
 * - print: the line and a QR-ready string in case-file.txt, printed for the
 *   case file.
 * A signed git remote is a witness of when a line was pushed, not a
 * write-once store.
 */
export function mirrorRelease(S: string, dir: string, target: string): { ok: true; note: string } | { ok: false; why: string } {
  const version = Number(basename(dir).slice(1));
  const r = pickRelease(S, version);
  const sigSha = fileSha(releaseSigPath(dir));
  const line = digestLine(r.record, r.sha256, sigSha);
  const qr = qrString(r.record, r.sha256);
  const at = new Date().toISOString();
  let rec: Record<string, unknown>;
  let result: { ok: true; note: string } | { ok: false; why: string };
  if (target.startsWith("cmd:")) {
    const cmd = target.slice(4);
    const p = spawnSync("bash", ["-c", cmd], { input: `${line}\n`, encoding: "utf8", timeout: 120_000, env: { ...process.env, DFS_RELEASE_JSON: join(dir, "release.json"), DFS_RELEASE_SIG: releaseSigPath(dir), DFS_RELEASE_SHA256: r.sha256, DFS_RELEASE_VERSION: String(r.version), DFS_RUN: String(r.record.run ?? "") } });
    rec = { kind: "command", command: cmd, at, exit: p.status, stdout: p.stdout ?? "", stderr: p.stderr ?? "", line };
    result = p.status === 0 ? { ok: true, note: `the digest line went to the command (exit 0); its receipt is kept whole in ${basename(nextName(dir, "mirror", "json"))}` } : { ok: false, why: `the command exited ${p.status ?? p.signal}` };
  } else if (target.startsWith("dir:")) {
    const to = resolve(target.slice(4));
    if (!existsSync(to)) return { ok: false, why: `${to} does not exist (a mirror directory is made by whoever keeps it, not here)` };
    const file = join(to, `${r.record.run ?? "run"}-v${r.version}-${r.sha256.slice(0, 12)}.txt`);
    try {
      writeFileSync(file, `${line}\n${qr}\n`, { flag: "wx", mode: 0o444 });
      rec = { kind: "directory", path: file, at, line, sha256: sha256(`${line}\n${qr}\n`) };
      result = { ok: true, note: `the digest line is in ${file}` };
    } catch (err) {
      return { ok: false, why: `${file} could not be written (${(err as NodeJS.ErrnoException).code ?? (err as Error).message}); nothing there is written over` };
    }
  } else if (target === "print") {
    const file = join(dir, "case-file.txt");
    const text = [
      `DFIR Swarm release, for the case file`,
      ``,
      line,
      ``,
      `QR-ready (alphanumeric): ${qr}`,
      ``,
      `Check it: swarm.sh verify <package> finds release v${r.version} and says whether its release.json has sha256 ${r.sha256}.`,
      "",
    ].join("\n");
    if (!existsSync(file)) writeFileSync(file, text, { mode: 0o444 });
    rec = { kind: "print", path: `${RELEASE_DIR}/v${r.version}/case-file.txt`, at, line, qr };
    result = { ok: true, note: `${line}\n              QR-ready: ${qr} (release/v${r.version}/case-file.txt)` };
  } else return { ok: false, why: `${JSON.stringify(target)} is not a mirror: cmd:COMMAND, dir:PATH or print` };
  writeFileSync(nextName(dir, "mirror", "json"), `${JSON.stringify(rec, null, 2)}\n`, { mode: 0o444, flag: "wx" });
  return result;
}
