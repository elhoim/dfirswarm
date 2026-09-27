/**
 * An X.509 signing certificate on a PKCS#11 token (a qualified e-signature
 * card, an HSM, SoftHSM in the tests), as scripts/signers.ts enrols it and
 * scripts/release.ts signs with it.
 *
 * - The certificate is read from the token without the PIN (pkcs11-tool,
 *   from OpenSC): a certificate is a public object.
 * - A signature is a CAdES-BES detached CMS made by OpenSSL 3 through
 *   libp11's provider (pkcs11prov): `openssl cms -sign -cades -binary -md
 *   sha256`, the key named by a PKCS#11 URI whose PIN is read from
 *   `pin-source=file:/dev/fd/3` (scripts/secret-io.ts).
 * - A signature is checked with `openssl cms -verify`: against the trust
 *   anchors in a CA file when one is given (the issuing CA's intermediate
 *   certificates from the CMS itself, where they were put at signing, or from
 *   a file of their own), else "signature valid; certificate chain not
 *   checked". The anchors' sha256 values are said with the result: a root
 *   fetched over plain HTTP is only as good as the comparison of that value
 *   with the national trust list (in Türkiye, BTK's list of certification
 *   service providers). The signer's certificate inside the CMS is always
 *   held to the fingerprint the record names.
 *
 * Privacy. A qualified certificate's subject can carry a national identity
 * number (the subject's serialNumber). Nothing here prints a subject: what
 * is shown is the CN, the issuer's CN and O, the validity and the
 * fingerprint. The provider and pkcs11-tool print slot tables, key labels
 * (the holder's name) and subjects when they are chatty; their output is
 * captured, never passed on, and only a failure's kind is reported. The
 * certificate itself travels inside every CMS signature, as with any
 * e-signed document.
 */
import { spawnSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { runWithSecret, signingEnv } from "./secret-io.ts";

export type CertInfo = {
  pem: string;
  sha256: string;
  cn: string | null;
  /** The issuer's CN and O only. */
  issuer: string;
  not_before: string;
  not_after: string;
  key_usage: string[];
  qc_statement: boolean;
  /** The statement ids the qcStatements extension carries (0.4.0.1862.1.1 is QcCompliance). */
  qc_statements: string[];
};

/** The fingerprint a pkcs11 signer is named by: the certificate's sha256, marked so it is never read as an ssh key's. */
export function certFingerprint(sha256hex: string): string {
  return `X509-SHA256:${sha256hex}`;
}

// --- a certificate's fields, read from its DER -------------------------------------------------

type Tlv = { tag: number; start: number; header: number; len: number; end: number };

function tlv(b: Buffer, at: number): Tlv {
  const tag = b[at];
  let len = b[at + 1];
  let header = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error("a DER length this reader does not take");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    header = 2 + n;
  }
  const end = at + header + len;
  if (end > b.length) throw new Error("a DER value runs past its end");
  return { tag, start: at, header, len, end };
}

function children(b: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.start + parent.header;
  while (at < parent.end) {
    const t = tlv(b, at);
    out.push(t);
    at = t.end;
  }
  return out;
}

function oidString(v: Buffer): string {
  const parts: number[] = [Math.floor(v[0] / 40), v[0] % 40];
  let n = 0;
  for (let i = 1; i < v.length; i++) {
    n = n * 128 + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join(".");
}

const KEY_USAGE_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];

/** keyUsage and qcStatements, from the certificate's extensions. */
export function certExtensions(der: Buffer): { key_usage: string[]; qc_statement: boolean; qc_statements: string[] } {
  const cert = tlv(der, 0);
  const tbs = children(der, cert)[0];
  const ext = children(der, tbs).find((t) => t.tag === 0xa3);
  const out = { key_usage: [] as string[], qc_statement: false, qc_statements: [] as string[] };
  if (!ext) return out;
  const list = children(der, ext)[0];
  for (const e of children(der, list)) {
    const parts = children(der, e);
    const oid = oidString(der.subarray(parts[0].start + parts[0].header, parts[0].end));
    const value = parts[parts.length - 1];
    const inner = tlv(der, value.start + value.header);
    if (oid === "2.5.29.15" && inner.tag === 0x03) {
      const bytes = der.subarray(inner.start + inner.header + 1, inner.end);
      KEY_USAGE_BITS.forEach((name, i) => {
        const byte = bytes[Math.floor(i / 8)] ?? 0;
        if (byte & (0x80 >> i % 8)) out.key_usage.push(name);
      });
    } else if (oid === "1.3.6.1.5.5.7.1.3") {
      out.qc_statement = true;
      for (const st of children(der, inner)) {
        const id = children(der, st)[0];
        if (id?.tag === 0x06) out.qc_statements.push(oidString(der.subarray(id.start + id.header, id.end)));
      }
    }
  }
  return out;
}

const dnField = (dn: string, key: string): string | null => {
  for (const line of dn.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0 && line.slice(0, i) === key) return line.slice(i + 1);
  }
  return null;
};

/** What is kept and shown of a certificate: never its subject beyond the CN. */
export function certInfo(pemOrDer: string | Buffer): CertInfo {
  const c = new X509Certificate(pemOrDer);
  const der = c.raw;
  const pem = c.toString();
  const ext = certExtensions(der);
  const issuer = [dnField(c.issuer, "CN"), dnField(c.issuer, "O")].filter(Boolean).join(", ") || "(no CN or O)";
  return {
    pem,
    sha256: createHash("sha256").update(der).digest("hex"),
    cn: dnField(c.subject, "CN"),
    issuer,
    not_before: new Date(c.validFrom).toISOString(),
    not_after: new Date(c.validTo).toISOString(),
    ...ext,
  };
}

/** The certificates in a PEM file or text, each by its DER sha256 and CN (a CA's: no person's subject). */
export function pemCerts(text: string): Array<{ pem: string; sha256: string; cn: string | null }> {
  const out: Array<{ pem: string; sha256: string; cn: string | null }> = [];
  for (const m of text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)) {
    const c = new X509Certificate(m[0]);
    out.push({ pem: c.toString(), sha256: createHash("sha256").update(c.raw).digest("hex"), cn: dnField(c.subject, "CN") });
  }
  return out;
}

/** A CA file's anchors, said by their sha256, for a verify line. */
function anchorsWords(file: string): string {
  try {
    const certs = pemCerts(readFileSync(file, "utf8"));
    return certs.length ? certs.map((c) => `${c.cn ?? "?"} sha256 ${c.sha256}`).join("; ") : "no certificate in it";
  } catch {
    return "unreadable";
  }
}

/** Why a certificate cannot sign a release (none: it can). */
export function certRefusal(info: CertInfo, now = new Date()): string | null {
  const missing = ["digitalSignature", "nonRepudiation"].filter((u) => !info.key_usage.includes(u));
  if (missing.length) return `the certificate's key usage lacks ${missing.join(" and ")} (it has ${info.key_usage.join(", ") || "none"}): it is not a signing certificate`;
  if (Date.parse(info.not_after) < now.getTime()) return `the certificate expired at ${info.not_after}`;
  if (Date.parse(info.not_before) > now.getTime()) return `the certificate is not valid before ${info.not_before}`;
  return null;
}

// --- the programs ---------------------------------------------------------------------------------

function onPath(name: string): string | null {
  for (const d of (process.env.PATH ?? "").split(delimiter)) {
    const p = join(d, name);
    try {
      if (statSync(p).isFile()) return p;
    } catch {
      // not here
    }
  }
  return null;
}

/**
 * OpenSSL 3, which the provider needs: DFIRSWARM_OPENSSL, then Homebrew's
 * (macOS ships LibreSSL as /usr/bin/openssl), then the one on PATH.
 */
export function opensslBinary(env: NodeJS.ProcessEnv = process.env): { path: string } | { why: string } {
  const candidates = [env.DFIRSWARM_OPENSSL, "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl", onPath("openssl")].filter((p): p is string => Boolean(p));
  for (const p of candidates) {
    if (!existsSync(p)) continue;
    const r = spawnSync(p, ["version"], { encoding: "utf8" });
    if (r.status === 0 && /^OpenSSL 3\./.test(r.stdout)) return { path: p };
  }
  return { why: "no OpenSSL 3 found (DFIRSWARM_OPENSSL, Homebrew's openssl@3, or openssl on PATH): an e-signature is made through OpenSSL 3's PKCS#11 provider" };
}

/** Where libp11's provider (pkcs11prov) is: DFIRSWARM_OSSL_MODULES, or the usual places. */
export function providerDir(env: NodeJS.ProcessEnv = process.env): { dir: string } | { why: string } {
  const candidates = [env.DFIRSWARM_OSSL_MODULES, env.OPENSSL_MODULES, "/opt/homebrew/lib/ossl-modules", "/usr/local/lib/ossl-modules", "/usr/lib/x86_64-linux-gnu/ossl-modules", "/usr/lib/aarch64-linux-gnu/ossl-modules", "/usr/lib64/ossl-modules", "/usr/lib/ossl-modules"].filter((p): p is string => Boolean(p));
  for (const d of candidates) {
    if (["pkcs11prov.dylib", "pkcs11prov.so", "pkcs11.so"].some((f) => existsSync(join(d, f)))) return { dir: d };
  }
  return { why: "libp11's OpenSSL provider (pkcs11prov) was not found: install libp11 (brew install libp11), or name its directory with DFIRSWARM_OSSL_MODULES" };
}

export function pkcs11ToolBinary(env: NodeJS.ProcessEnv = process.env): { path: string } | { why: string } {
  const p = env.DFIRSWARM_PKCS11_TOOL || onPath("pkcs11-tool") || ["/opt/homebrew/bin/pkcs11-tool", "/usr/local/bin/pkcs11-tool"].find((x) => existsSync(x));
  return p && existsSync(p) ? { path: p } : { why: "pkcs11-tool (OpenSC) was not found: install opensc, or name it with DFIRSWARM_PKCS11_TOOL" };
}

// --- URIs -------------------------------------------------------------------------------------------

const HEX = /^(?:[0-9a-fA-F]{2})+$/;

/** A PKCS#11 URI's attribute, percent-decoded to bytes. */
function uriAttr(uri: string, name: string): Buffer | null {
  const body = uri.replace(/^pkcs11:/, "").split("?")[0];
  for (const part of body.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) {
      const v = part.slice(i + 1);
      const bytes: number[] = [];
      for (let k = 0; k < v.length; k++) {
        if (v[k] === "%" && /^[0-9a-fA-F]{2}$/.test(v.slice(k + 1, k + 3))) {
          bytes.push(parseInt(v.slice(k + 1, k + 3), 16));
          k += 2;
        } else bytes.push(...Buffer.from(v[k], "utf8"));
      }
      return Buffer.from(bytes);
    }
  }
  return null;
}

/**
 * The URI a token's key is named by, with no PIN and no type in it (the
 * signer adds `type=private` and the pin-source), and the object's id as hex.
 */
export function tokenUri(o: { uri?: string; id?: string }): { uri: string; id: string; token: string | null } | { why: string } {
  if (o.uri) {
    if (!o.uri.startsWith("pkcs11:")) return { why: `${o.uri} is not a PKCS#11 URI (pkcs11:…)` };
    const kept = o.uri
      .replace(/^pkcs11:/, "")
      .split("?")[0]
      .split(";")
      .filter((p) => p && !/^(pin-value|pin-source|type)=/.test(p));
    const id = uriAttr(o.uri, "id");
    if (!id?.length) return { why: "the URI names no object id (id=…): give --pkcs11-id HEX or a URI with one" };
    const token = uriAttr(o.uri, "token");
    return { uri: `pkcs11:${kept.join(";")}`, id: id.toString("hex"), token: token ? token.toString("utf8") : null };
  }
  const id = (o.id ?? "").replace(/[:\s]/g, "").toLowerCase();
  if (!HEX.test(id)) return { why: `${JSON.stringify(o.id ?? "")} is not an object id in hex (--pkcs11-id)` };
  return { uri: `pkcs11:id=${id.match(/../g)?.map((h) => `%${h}`).join("")}`, id, token: null };
}

// --- reading the certificate --------------------------------------------------------------------

/** Nothing the tools print is passed on: only what kind of failure it was. */
export function toolFailure(out: string, what: string): string {
  const t = out.toLowerCase();
  if (/ckr_pin_incorrect|login failed|login to token failed|pin incorrect/.test(t)) return `${what}: the token refused the PIN`;
  if (/ckr_pin_locked|pin locked|pin is locked/.test(t)) return `${what}: the token's PIN is locked`;
  if (/no slot|no token|token not present|ckr_token_not_present|no present token|slot not found/.test(t)) return `${what}: no token is present (is it plugged in?)`;
  if (/could not load|failed to load|cannot load|pkcs11 module|c_initialize/.test(t)) return `${what}: the PKCS#11 module could not be loaded`;
  if (/could not find private key|private key was not found|no private key/.test(t)) return `${what}: the token has no private key under that id`;
  const codes = [...new Set(out.match(/CKR_[A-Z_]+/g) ?? [])];
  return `${what} failed${codes.length ? ` (${codes.join(", ")})` : ""}; the tool's own output is not shown, because it can carry the certificate holder's name and identity number`;
}

/** The certificate under `id` on the token the module serves, read without the PIN. */
export function readTokenCert(o: { module: string; id: string; token?: string | null; env?: NodeJS.ProcessEnv }): { der: Buffer; info: CertInfo } | { why: string } {
  if (!existsSync(o.module)) return { why: `no PKCS#11 module at ${o.module} (--pkcs11-module)` };
  const tool = pkcs11ToolBinary(o.env);
  if ("why" in tool) return tool;
  const args = ["--module", o.module, "--read-object", "--type", "cert", "--id", o.id];
  if (o.token) args.push("--token-label", o.token);
  const r = spawnSync(tool.path, args, { env: { ...(o.env ?? process.env), PKCS11_DEBUG_LEVEL: "3" }, stdio: ["ignore", "pipe", "pipe"], timeout: 60_000, maxBuffer: 16 * 1024 * 1024 });
  const der = Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.from(String(r.stdout ?? ""));
  if (r.status !== 0 || !der.length || der[0] !== 0x30) return { why: toolFailure(String(r.stderr ?? ""), "reading the certificate from the token") };
  try {
    return { der, info: certInfo(der) };
  } catch (err) {
    return { why: `what the token holds under id ${o.id} is not a certificate this reader takes (${(err as Error).message})` };
  }
}

// --- signing and checking -------------------------------------------------------------------------

/**
 * A CAdES-BES detached signature over `file` at `<file>.p7s`, made on the
 * token with the PIN from `pin` (fd 3). The certificate the signature names
 * is the enrolled one; before anything is signed the token's own is read and
 * held to its fingerprint.
 */
export function cmsSign(o: { file: string; module: string; uri: string; id: string; token?: string | null; certPem: string; certSha256: string; chainPem?: string | null; pin: Buffer; env?: NodeJS.ProcessEnv }): { ok: true; sig: string; sha256: string; openssl: string } | { ok: false; why: string; wrongSecret?: boolean } {
  const onToken = readTokenCert({ module: o.module, id: o.id, token: o.token, env: o.env });
  if ("why" in onToken) return { ok: false, why: onToken.why };
  if (onToken.info.sha256 !== o.certSha256) return { ok: false, why: `the token's certificate under id ${o.id} is not the enrolled one (${certFingerprint(onToken.info.sha256)}, enrolled ${certFingerprint(o.certSha256)}): nothing was signed` };
  const ossl = opensslBinary(o.env);
  if ("why" in ossl) return { ok: false, why: ossl.why };
  const prov = providerDir(o.env);
  if ("why" in prov) return { ok: false, why: prov.why };
  const scratch = mkdtempSync(join(tmpdir(), "dfs-cms-"));
  const sig = `${o.file}.p7s`;
  try {
    const cert = join(scratch, "signer.pem");
    writeFileSync(cert, o.certPem, { mode: 0o600 });
    // The issuing CA's intermediates go into the CMS, so a verifier needs only the root.
    const chain = o.chainPem ? join(scratch, "chain.pem") : null;
    if (chain) writeFileSync(chain, o.chainPem as string, { mode: 0o600 });
    rmSync(sig, { force: true });
    const env = { ...signingEnv(o.env ?? process.env, { dropAgent: true }), PKCS11_MODULE_PATH: o.module, PKCS11_DEBUG_LEVEL: "3" };
    const r = runWithSecret(
      ossl.path,
      ["cms", "-sign", "-cades", "-binary", "-md", "sha256", "-provider-path", prov.dir, "-provider", "pkcs11prov", "-provider", "default", "-inkey", `${o.uri};type=private;pin-source=file:/dev/fd/3`, "-signer", cert, ...(chain ? ["-certfile", chain] : []), "-in", o.file, "-outform", "DER", "-out", sig],
      o.pin,
      { env, timeoutMs: 180_000 },
    );
    if (r.code !== 0 || !existsSync(sig)) {
      const why = toolFailure(`${r.out}\n${r.err}`, "signing on the token");
      return { ok: false, why, wrongSecret: /refused the PIN/.test(why) };
    }
    return { ok: true, sig, sha256: createHash("sha256").update(readFileSync(sig)).digest("hex"), openssl: ossl.path };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * What a CMS signature over `file` shows: whether it verifies, whether its
 * chain was checked (only against a CA file given), and whether the signer's
 * certificate inside it is the one the record names.
 */
export function cmsVerify(o: { file: string; sig: string; certSha256: string; ca?: string; intermediates?: string; env?: NodeJS.ProcessEnv }): { state: "verified" | "unchecked" | "bad"; detail: string; cert: CertInfo | null } {
  if (!existsSync(o.sig)) return { state: "bad", detail: `no signature at ${o.sig}`, cert: null };
  if (!existsSync(o.file)) return { state: "bad", detail: `no file at ${o.file}`, cert: null };
  if (o.ca && !existsSync(o.ca)) return { state: "bad", detail: `no CA file at ${o.ca}`, cert: null };
  if (o.intermediates && !existsSync(o.intermediates)) return { state: "bad", detail: `no intermediate certificates at ${o.intermediates}`, cert: null };
  const ossl = opensslBinary(o.env);
  if ("why" in ossl) return { state: "bad", detail: ossl.why, cert: null };
  const scratch = mkdtempSync(join(tmpdir(), "dfs-cmsv-"));
  try {
    const signer = join(scratch, "signer.pem");
    const args = ["cms", "-verify", "-binary", "-inform", "DER", "-in", o.sig, "-content", o.file, "-out", "/dev/null", "-signer", signer, "-purpose", "any"];
    if (o.ca) args.push("-CAfile", o.ca);
    else args.push("-noverify");
    if (o.ca && o.intermediates) args.push("-certfile", o.intermediates);
    const r = spawnSync(ossl.path, args, { encoding: "utf8", env: o.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
    if (r.status !== 0 || !existsSync(signer)) {
      const err = r.stderr ?? "";
      const chain = !/content verify error|digest failure|signature failure|bad signature/i.test(err) && /certificate verify error|unable to get local issuer|self.signed|certificate has expired/i.test(err);
      return { state: "bad", detail: chain ? `the signature's certificate chain does not verify against the trust anchor(s) in ${o.ca} (${anchorsWords(o.ca as string)})${o.intermediates ? `, with the intermediates in ${o.intermediates}` : ""}` : "DOES NOT VERIFY: the CMS signature is not over these bytes, or is not a signature", cert: null };
    }
    let cert: CertInfo | null = null;
    try {
      cert = certInfo(readFileSync(signer, "utf8"));
    } catch {
      cert = null;
    }
    if (!cert) return { state: "bad", detail: "the signature verifies, and the certificate inside it could not be read", cert: null };
    if (cert.sha256 !== o.certSha256) return { state: "bad", detail: `the signature verifies under a certificate (${certFingerprint(cert.sha256)}) that is not the one the record names (${certFingerprint(o.certSha256)})`, cert };
    return o.ca
      ? { state: "verified", detail: `signature valid, by ${cert.cn ?? "?"} (${certFingerprint(cert.sha256)}), its chain verified against the trust anchor(s) in ${o.ca} (${anchorsWords(o.ca)})${o.intermediates ? `, with the intermediates in ${o.intermediates}` : ""}`, cert }
      : { state: "unchecked", detail: `signature valid, by ${cert.cn ?? "?"} (${certFingerprint(cert.sha256)}); certificate chain not checked (--ca FILE)`, cert };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
