/**
 * What a run installed, derived rather than declared.
 *
 * `--allow-install` lets a case reach for the library it needs — and recorded
 * nothing at all about what arrived. A forensic report has to be able to
 * answer "which version of pybde decrypted this volume, and was it the one
 * the index says it is". `docs/safety.md` asked agents to write their installs
 * into the ledger by hand, which is a request, not a record.
 *
 * So the harness reads the packages' own metadata: every `*.dist-info` under
 * the run's `PYTHONUSERBASE`, its `METADATA` name and version, the installer,
 * the index it came from when pip left `direct_url.json`, and the sha256 of
 * the package's `RECORD` — which is itself the list of sha256 of every file
 * that package installed. An entry nobody can produce by claiming it.
 */
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

/** Where `--allow-install` points pip, relative to the sandbox. */
export const TOOLCHAIN_DIR = "work/.toolchain";
export const TOOLCHAIN_REL = "toolchain.json";

export type InstalledPackage = {
  name: string;
  version: string;
  /** `pip`, or whatever wrote INSTALLER. */
  installer: string;
  /** sha256 of the package's own RECORD file: a fingerprint of every file it laid down. */
  record_sha256: string;
  /** Where it came from, when pip recorded it (`direct_url.json`). */
  source?: string;
  /** dist-info directory, relative to the sandbox. */
  path: string;
};

export type ToolchainRecord = {
  checked_at: string;
  dir: string;
  packages: InstalledPackage[];
};

async function readIfPresent(file: string): Promise<string> {
  return readFile(file, "utf8").catch(() => "");
}

function metadataField(text: string, field: string): string {
  // dist-info METADATA is RFC 822-ish: `Name: pybde` on its own line.
  const match = text.match(new RegExp(`^${field}:[ \\t]*(.+)$`, "mi"));
  return match ? match[1].trim() : "";
}

/** Every `site-packages` under the toolchain, whatever python version made it. */
async function sitePackageDirs(root: string): Promise<string[]> {
  const out: string[] = [];
  const lib = join(root, "lib");
  for (const entry of await readdir(lib, { withFileTypes: true }).catch(() => [])) {
    if (!entry.isDirectory()) continue;
    const candidate = join(lib, entry.name, "site-packages");
    if (await stat(candidate).then((s) => s.isDirectory()).catch(() => false)) out.push(candidate);
  }
  // Some layouts put it directly under the prefix.
  const flat = join(root, "site-packages");
  if (await stat(flat).then((s) => s.isDirectory()).catch(() => false)) out.push(flat);
  return out;
}

/**
 * Read the toolchain as it stands. Returns an empty list — not null — when
 * nothing was installed, so a run with `--allow-install` and no installs
 * records that fact rather than leaving a gap a reader has to interpret.
 */
export async function readToolchain(sandboxRoot: string): Promise<ToolchainRecord> {
  const root = join(sandboxRoot, TOOLCHAIN_DIR);
  const packages: InstalledPackage[] = [];
  for (const site of await sitePackageDirs(root)) {
    for (const entry of await readdir(site, { withFileTypes: true }).catch(() => [])) {
      if (!entry.isDirectory() || !entry.name.endsWith(".dist-info")) continue;
      const dist = join(site, entry.name);
      const metadata = await readIfPresent(join(dist, "METADATA"));
      const record = await readIfPresent(join(dist, "RECORD"));
      const installer = (await readIfPresent(join(dist, "INSTALLER"))).trim();
      let source = "";
      const directUrl = await readIfPresent(join(dist, "direct_url.json"));
      if (directUrl) {
        try {
          source = String((JSON.parse(directUrl) as { url?: unknown }).url ?? "");
        } catch {
          // a malformed direct_url.json is not worth failing the inventory for
        }
      }
      packages.push({
        name: metadataField(metadata, "Name") || entry.name.replace(/-[^-]*\.dist-info$/, ""),
        version: metadataField(metadata, "Version") || "unknown",
        installer: installer || "unknown",
        record_sha256: record ? createHash("sha256").update(record).digest("hex") : "",
        ...(source ? { source } : {}),
        path: dist.slice(sandboxRoot.length + 1),
      });
    }
  }
  packages.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { checked_at: new Date().toISOString(), dir: TOOLCHAIN_DIR, packages };
}

/** `name@version`, the key a reader compares two inventories on. */
export function packageKeys(record: ToolchainRecord): string[] {
  return record.packages.map((p) => `${p.name}@${p.version}`);
}

/** What appeared between two inventories. */
export function newPackages(before: ToolchainRecord | null, after: ToolchainRecord): InstalledPackage[] {
  const had = new Set(before ? packageKeys(before) : []);
  return after.packages.filter((p) => !had.has(`${p.name}@${p.version}`));
}
