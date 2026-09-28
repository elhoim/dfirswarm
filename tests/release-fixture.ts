/**
 * A stopped run for the release tests: track P's ledger version 4 fixture
 * (tests/fixtures/ledger-v4: answers, attestations, disputes, a job that
 * timed out) with a trace that carries every entry's record line, a report,
 * a registry naming the run with the kickoff's `examiner` string, and
 * custody taken. Keys are made in the run's own temporary home.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { custodyAnchorPath, takeCustody } from "../scripts/custody.ts";

export const FIXTURE = join(import.meta.dirname, "fixtures", "ledger-v4");
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

const made: string[] = [];
export async function cleanUp(): Promise<void> {
  for (const d of made) {
    spawnSync("chmod", ["-R", "u+w", d]);
    await rm(d, { recursive: true, force: true });
  }
}

export type StoppedRun = { runs: string; root: string; home: string; id: string };

/** A stopped run of the v4 fixture, custody taken; `report` is work/report.md's text. */
export async function stoppedRun(o: { id?: string; report?: string; registry?: Record<string, unknown> } = {}): Promise<StoppedRun> {
  const base = await mkdtemp(join(tmpdir(), "release-run-"));
  made.push(base);
  const id = o.id ?? "s4v4";
  const runs = join(base, "runs");
  const home = join(base, "home");
  const root = join(runs, id);
  await mkdir(home, { recursive: true });
  await mkdir(root, { recursive: true });
  await cp(join(FIXTURE, "ledger"), join(root, "ledger"), { recursive: true });
  await cp(join(FIXTURE, "store"), join(root, "store"), { recursive: true });
  const entries = (await readFile(join(root, "ledger", "entries.jsonl"), "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { seq: number; hash: string; by: string; at: string });
  let prev = "";
  let trace = "";
  for (const e of entries) {
    const line = JSON.stringify({ ts: e.at, agent: e.by, tool: "record", args: {}, result: { ok: true, seq: e.seq, hash: e.hash }, prev });
    trace += `${line}\n`;
    prev = sha(line);
  }
  await mkdir(join(root, "traces"), { recursive: true });
  await writeFile(join(root, "traces", "events.jsonl"), trace);
  await mkdir(join(root, "work"), { recursive: true });
  await writeFile(join(root, "work", "report.md"), o.report ?? "# Report\n\nThe intruder uploaded shell.php through the upload handler [#14].\n");
  await writeFile(join(root, "SWARM.md"), "# Goal\n\n1. How did the intruder get in?\n2. What did they run?\n3. What did they take?\n");
  await writeFile(custodyAnchorPath(root), JSON.stringify({ run: id, started_at: "2026-09-27T10:00:00Z" }));
  await writeFile(join(runs, "registry.json"), JSON.stringify({ runs: [{ id, sandbox: root, state: "done", examiner: "Claude (CTF round 5, macOS)", provenance: { harness_commit: "0123abcd" }, ...(o.registry ?? {}) }] }));
  await takeCustody(root, { runsDir: runs });
  return { runs, root, home, id };
}

/** An executable script in a directory of its own, for PATH or SWARM_CHROME. */
export async function script(name: string, body: string): Promise<{ dir: string; path: string }> {
  const dir = await mkdtemp(join(tmpdir(), "release-bin-"));
  made.push(dir);
  const path = join(dir, name);
  await writeFile(path, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return { dir, path };
}

/** A stand-in for Chrome's --print-to-pdf: writes a small PDF where it is told. */
export async function fakeChrome(): Promise<string> {
  return (
    await script(
      "chrome",
      `for a in "$@"; do case "$a" in --print-to-pdf=*) out="\${a#--print-to-pdf=}" ;; esac; done
printf '%%PDF-1.4\\n%% a stand-in print\\n' > "$out"`,
    )
  ).path;
}

/** Whether this host's openssl has the ts command. */
export function opensslTs(): boolean {
  const r = spawnSync("openssl", ["ts", "-help"], { encoding: "utf8" });
  return !r.error && /-verify|-reply/.test(`${r.stdout}${r.stderr}`);
}

/** A CA and a timestamping certificate it signed, and a reply function: an RFC 3161 authority made for the test. */
export async function testPki(): Promise<{ ca: string; otherCa: string; reply: (query: Buffer) => Buffer }> {
  const dir = await mkdtemp(join(tmpdir(), "release-tsa-"));
  made.push(dir);
  const ssl = (...args: string[]) => spawnSync("openssl", args, { cwd: dir, stdio: "pipe" });
  for (const name of ["ca", "other"]) ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.pem`, "-days", "2", "-subj", `/CN=Test ${name}`, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr", "-subj", "/CN=Test TSA");
  await writeFile(join(dir, "ext.cnf"), "extendedKeyUsage=critical,timeStamping\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n");
  ssl("x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.pem", "-days", "2", "-extfile", "ext.cnf");
  await writeFile(join(dir, "serial"), "01\n");
  await writeFile(
    join(dir, "tsa.cnf"),
    `[ tsa ]\ndefault_tsa = tsa1\n[ tsa1 ]\nserial = ${join(dir, "serial")}\ncrypto_device = builtin\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n`,
  );
  let n = 0;
  const reply = (query: Buffer) => {
    n += 1;
    const q = join(dir, `q${n}.tsq`);
    const r = join(dir, `r${n}.tsr`);
    writeFileSync(q, query);
    ssl("ts", "-reply", "-config", "tsa.cnf", "-queryfile", q, "-signer", "tsa.pem", "-inkey", "tsa.key", "-out", r);
    return readFileSync(r);
  };
  return { ca: join(dir, "ca.pem"), otherCa: join(dir, "other.pem"), reply };
}

/** An RFC 3161 authority on a local port: the test PKI's replies, or a stand-in that carries the digest and a time. */
export async function tsaServer(reply?: (query: Buffer) => Buffer): Promise<{ url: string; close: () => void }> {
  const genTime = Buffer.from("20260927120000Z", "latin1");
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      let resp: Buffer;
      if (reply) resp = reply(body);
      else {
        const at = body.indexOf(Buffer.from([0x04, 0x20]));
        const digest = body.subarray(at + 2, at + 34);
        const status = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
        const token = Buffer.concat([Buffer.from([0x04, 0x20]), digest, Buffer.from([0x18, genTime.length]), genTime]);
        resp = Buffer.concat([Buffer.from([0x30, status.length + token.length]), status, token]);
      }
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(resp);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return { url: `http://127.0.0.1:${(server.address() as { port: number }).port}/tsa`, close: () => server.close() };
}
