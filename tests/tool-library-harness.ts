/**
 * Spawn helpers for the tool-library suites. The library tools are
 * standalone directories, so the tests drive them as subprocesses with a
 * stub `icat` on PATH.
 */
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const LIB = join(ROOT, "tool-library");

export async function runPy(
  script: string,
  cwd: string,
  stdin: unknown,
  extraPath?: string,
  extraEnv?: Record<string, string>,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const env = { ...process.env, ...extraEnv };
  if (extraPath) env.PATH = `${extraPath}:${env.PATH ?? ""}`;
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [script], { cwd, env });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    child.stdin.end(JSON.stringify(stdin));
  });
}

export async function runSh(
  script: string,
  cwd: string,
  stdin: unknown,
  extraPath?: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const env = { ...process.env };
  if (extraPath) env.PATH = `${extraPath}:${env.PATH ?? ""}`;
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [script], { cwd, env });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    child.stdin.end(JSON.stringify(stdin));
  });
}

export async function runPySnippet(
  code: string,
  args: string[],
  stdin: unknown,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["-c", code, ...args]);
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stderr.on("data", (c: Buffer) => stderr.push(c));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
    child.stdin.end(JSON.stringify(stdin));
  });
}

export async function withCwd(fn: (cwd: string, bin: string) => Promise<void>): Promise<void> {
  const cwd = await mkdtemp(join(tmpdir(), "lib-eval-"));
  const bin = join(cwd, "bin");
  try {
    await mkdir(bin, { recursive: true });
    await mkdir(join(cwd, "work"), { recursive: true });
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await writeFile(join(cwd, "inputs", "AF-Case2.E01"), "img\n", "utf8");
    await writeFile(join(cwd, "inputs", "Webserver.E01"), "img\n", "utf8");
    const icat = join(bin, "icat");
    await writeFile(
      icat,
      `#!/bin/sh
printf '%s\\n' "$@" > "${cwd}/icat-args.txt"
printf 'extracted-bytes'
`,
      "utf8",
    );
    await chmod(icat, 0o755);
    await fn(cwd, bin);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

export async function failingStub(bin: string, name: string, message: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\necho "${message}" >&2\nexit 1\n`, "utf8");
  await chmod(path, 0o755);
}
