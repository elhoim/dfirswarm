#!/usr/bin/env node
/**
 * The artifact index: every file a run wrote under `work/`, with its sha256.
 *
 *   node --experimental-strip-types scripts/artifacts.ts <sandbox>
 *
 * A run's evidence arrives hashed — `inputs.json` has a sha256 per file — and
 * until now its *output* did not. A report that quotes a carved file, and a
 * package that ships it, had no number a reader could check the file against.
 * This writes that number for everything under `work/`.
 *
 * Two directories are hashed but not shipped. `work/extracted/` and
 * `work/quarantine/` hold material pulled out of the evidence: in the
 * measured corpus that is gigabytes of it, some of it live malware, and
 * `swarm.sh package` deliberately leaves it in the sandbox. Leaving it out of
 * the *index* as well would be a different mistake, because the ledger cites
 * those paths and sometimes their hashes. So they are listed with
 * `packaged: false` and their bytes stay where they are.
 *
 * Symlinks are never followed and never hashed. A link an agent's shell
 * dropped under `work/` points wherever it likes, and a hash of what it
 * points at would be a hash of a file the swarm did not write. Each file is
 * opened as a regular file (no link, no waiting on a FIFO a live VM swapped
 * in) and hashed through the handle that was checked.
 *
 * The order is by code unit, not by locale: the index's sha256 is anchored
 * outside the run, and the same files must give the same digest from any
 * shell, in any language.
 *
 * Who last wrote a file comes from `history/`, not from the trace. A claim
 * is a lease, not a write; the snapshot is what names the writer.
 */
import { readdir } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { listFileHistory, sha256File } from "../extensions/protocol.ts";
import { artifactKind, type ArtifactKind } from "./artifact-kind.ts";
import { hashRegularFile, type Expiry } from "./regular-file.ts";

export { artifactKind, type ArtifactKind } from "./artifact-kind.ts";

/** Directories under `work/` whose bytes stay in the sandbox. */
export const UNPACKAGED_DIRS = ["extracted", "quarantine"] as const;

export type ArtifactEntry = {
  /** Sandbox-relative, always `work/...`, always forward slashes. */
  path: string;
  bytes: number;
  mtime: string;
  sha256: string;
  kind: ArtifactKind;
  /** False for anything under the directories in `UNPACKAGED_DIRS`. */
  packaged: boolean;
  /** How many revisions `history/` holds for this path. */
  revisions: number;
  /** The last agent `history/` attributes a write of this path to. */
  last_written_by: string | null;
};

export type ArtifactIndex = {
  generated_at: string;
  /** Files the index could hash, sorted by path. */
  files: ArtifactEntry[];
  /** Every file's bytes, including the unpackaged ones. */
  bytes: number;
  /** Only the bytes `package` will carry. */
  packaged_bytes: number;
  /** Directory names under `work/` that are hashed but not shipped. */
  unpackaged_dirs: string[];
  /** What was skipped and why: a symlink, a device, a file that vanished. */
  skipped: Array<{ path: string; reason: string }>;
};

export async function sha256OfFile(abs: string): Promise<string> {
  return sha256File(abs);
}

function isUnpackaged(rel: string): boolean {
  const top = rel.split("/")[0];
  return (UNPACKAGED_DIRS as readonly string[]).includes(top);
}

/** An order that is the same in every locale: plain UTF-16 code units. */
export function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * `expiry` is custody's deadline: past it, the files not yet hashed are
 * listed as skipped with that reason rather than the index holding the stop.
 */
export async function hashArtifacts(sandbox: string, options: { expiry?: Expiry } = {}): Promise<ArtifactIndex> {
  const root = resolve(sandbox, "work");
  const files: ArtifactEntry[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.name === ".gitkeep") continue;
      const abs = join(dir, entry.name);
      const rel = relative(root, abs).split(sep).join("/");
      if (entry.isSymbolicLink()) {
        skipped.push({ path: `work/${rel}`, reason: "symbolic link, not followed" });
        continue;
      }
      if (entry.isDirectory()) {
        await walk(abs);
        continue;
      }
      if (!entry.isFile()) {
        skipped.push({ path: `work/${rel}`, reason: "not a regular file" });
        continue;
      }
      if (options.expiry?.over) {
        skipped.push({ path: `work/${rel}`, reason: "not hashed: the deadline passed" });
        continue;
      }
      const hashed = await hashRegularFile(abs, { expiry: options.expiry }).catch((err: Error) => ({ why: err.message }));
      if (hashed === null) {
        skipped.push({ path: `work/${rel}`, reason: "not hashed: the deadline passed" });
        continue;
      }
      if ("why" in hashed) {
        skipped.push({ path: `work/${rel}`, reason: hashed.why === "missing" ? "vanished before it could be read" : hashed.why });
        continue;
      }
      const key = `work/${rel}`;
      const history = await listFileHistory(sandbox, key).catch(() => []);
      files.push({
        path: key,
        bytes: hashed.size,
        mtime: hashed.mtime.toISOString(),
        sha256: hashed.sha256,
        kind: artifactKind(entry.name),
        packaged: !isUnpackaged(rel),
        revisions: history.length,
        last_written_by: history.at(-1)?.agent ?? null,
      });
    }
  }

  await walk(root);
  files.sort((a, b) => byCodeUnit(a.path, b.path));
  skipped.sort((a, b) => byCodeUnit(a.path, b.path));
  return {
    generated_at: new Date().toISOString(),
    files,
    bytes: files.reduce((n, f) => n + f.bytes, 0),
    packaged_bytes: files.reduce((n, f) => n + (f.packaged ? f.bytes : 0), 0),
    unpackaged_dirs: [...UNPACKAGED_DIRS],
    skipped,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const sandbox = process.argv[2];
  if (!sandbox) {
    console.error("Usage: artifacts.ts <sandbox>");
    process.exit(2);
  }
  const index = await hashArtifacts(sandbox);
  process.stdout.write(`${JSON.stringify(index, null, 2)}\n`);
}
