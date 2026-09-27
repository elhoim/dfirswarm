/**
 * A throwaway e-signature token for the tests: SoftHSM2 in a temporary
 * directory, a CA of its own, and a signing certificate on the token whose
 * subject carries a serialNumber the way a qualified certificate's carries a
 * national identity number, so the tests can hold every output to never
 * showing it. Nothing here touches a real token. When SoftHSM2, OpenSC's
 * pkcs11-tool, OpenSSL 3 or libp11's provider is missing, `softToken()`
 * says why and the tests skip.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { opensslBinary, pkcs11ToolBinary, providerDir } from "../scripts/pkcs11.ts";

/** The serialNumber the test certificate's subject carries: no output may show it. */
export const SUBJECT_SERIAL = "98765432109";
/** The test token's user PIN: a test value, made here for this throwaway token. */
export const TEST_PIN = "dfs-test-pin-1234";

const MODULES = ["/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"];

/** `ca` is the root (the trust anchor); `intermediate` the issuing CA below it, which signed the token's certificates. */
export type SoftToken = { dir: string; module: string; id: string; ca: string; intermediate: string; env: Record<string, string>; otherCert: (o: { keyUsage?: string; days?: number; id: string }) => void; cleanup: () => void };

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv, input?: string): void {
  const r = spawnSync(cmd, args, { env, input, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${cmd} ${args[0]} failed: ${r.stderr || r.stdout}`);
}

/** A token with one signing certificate under id 0416, or why there cannot be one here. */
export function softToken(): SoftToken | { why: string } {
  const module = process.env.DFIRSWARM_TEST_SOFTHSM_MODULE ?? MODULES.find((m) => existsSync(m));
  if (!module) return { why: "SoftHSM2 is not installed (brew install softhsm, or apt install softhsm2)" };
  const util = spawnSync("softhsm2-util", ["--version"], { encoding: "utf8" });
  if (util.status !== 0) return { why: "softhsm2-util is not on PATH" };
  const ossl = opensslBinary();
  if ("why" in ossl) return ossl;
  const prov = providerDir();
  if ("why" in prov) return prov;
  const tool = pkcs11ToolBinary();
  if ("why" in tool) return tool;
  const dir = mkdtempSync(join(tmpdir(), "dfs-softhsm-"));
  const conf = join(dir, "softhsm2.conf");
  writeFileSync(conf, `directories.tokendir = ${join(dir, "tokens")}\nobjectstore.backend = file\nlog.level = ERROR\n`);
  spawnSync("mkdir", ["-p", join(dir, "tokens")]);
  const env = { ...process.env, SOFTHSM2_CONF: conf } as NodeJS.ProcessEnv;
  const o = ossl.path;
  run("softhsm2-util", ["--init-token", "--free", "--label", "dfs-test", "--so-pin", "so-pin-87654321", "--pin", TEST_PIN], env);
  // A root, and the qualified CA it certifies, as a national trust service provider's chain is laid out.
  run(o, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "root.key"), "-out", join(dir, "root.pem"), "-days", "30", "-subj", "/CN=DFIR Swarm Test Root/O=Test Trust Services", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], env);
  run(o, ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "ca.key"), "-out", join(dir, "ca.csr"), "-subj", "/CN=DFIR Swarm Test Qualified CA/O=Test Trust Services"], env);
  writeFileSync(join(dir, "ca-ext.cnf"), "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n");
  run(o, ["x509", "-req", "-in", join(dir, "ca.csr"), "-CA", join(dir, "root.pem"), "-CAkey", join(dir, "root.key"), "-CAcreateserial", "-out", join(dir, "ca.pem"), "-days", "30", "-extfile", join(dir, "ca-ext.cnf")], env);
  const make = (id: string, keyUsage: string, days: number, cn: string) => {
    const key = join(dir, `signer-${id}.key`);
    run(o, ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key], env);
    run(o, ["req", "-new", "-key", key, "-out", join(dir, `signer-${id}.csr`), "-subj", `/C=TR/serialNumber=${SUBJECT_SERIAL}/CN=${cn}`], env);
    // keyUsage as asked, and a qcStatements extension carrying QcCompliance (0.4.0.1862.1.1).
    writeFileSync(join(dir, `ext-${id}.cnf`), `keyUsage=critical,${keyUsage}\nbasicConstraints=critical,CA:FALSE\n1.3.6.1.5.5.7.1.3=DER:30:0a:30:08:06:06:04:00:8e:46:01:01\n`);
    const x509 = ["x509", "-req", "-in", join(dir, `signer-${id}.csr`), "-CA", join(dir, "ca.pem"), "-CAkey", join(dir, "ca.key"), "-CAcreateserial", "-out", join(dir, `signer-${id}.pem`), "-extfile", join(dir, `ext-${id}.cnf`)];
    if (days >= 0) x509.push("-days", String(days));
    else x509.push("-not_before", "20200101000000Z", "-not_after", "20210101000000Z");
    run(o, x509, env);
    run(o, ["x509", "-in", join(dir, `signer-${id}.pem`), "-outform", "DER", "-out", join(dir, `signer-${id}.der`)], env);
    run("softhsm2-util", ["--import", key, "--token", "dfs-test", "--label", cn, "--id", id, "--pin", TEST_PIN], env);
    run(tool.path, ["--module", module, "--login", "--pin", TEST_PIN, "--write-object", join(dir, `signer-${id}.der`), "--type", "cert", "--id", id, "--label", cn], env);
    rmSync(key, { force: true });
  };
  make("0416", "digitalSignature,nonRepudiation", 20, "Ada Examiner");
  return {
    dir,
    module,
    id: "0416",
    ca: join(dir, "root.pem"),
    intermediate: join(dir, "ca.pem"),
    env: { SOFTHSM2_CONF: conf },
    otherCert: ({ keyUsage = "digitalSignature,nonRepudiation", days = 20, id }) => make(id, keyUsage, days, `Other ${id}`),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
