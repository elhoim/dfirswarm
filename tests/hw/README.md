# Hardware signing tests

These tests use a real FIDO key or a real e-signature token, so they never run
in `npm test` or `npm run test:bash`. Each one runs only with
`DFIRSWARM_HW_TESTS=1`, from a terminal, with the person who owns the key at
the keyboard. The scripts say when to touch the key and when to type a PIN.
They never read or print a private key, never take a PIN from anywhere but the
terminal, and keep everything they make (keys, runs, the console's runs
directory) in a temporary directory that is removed at the end. They never
write to the real `~/.dfirswarm`.

## What they need

- Node 22.19 or later, `jq`, `curl`, and the repository's `npm install`.
- **FIDO** (`fido.sh`, `console.sh` with `DFIRSWARM_HW_KIND=fido`): a FIDO2
  key (a YubiKey) plugged into this computer, and an `ssh-keygen` with FIDO
  support. macOS's own `/usr/bin/ssh-keygen` has none; install Homebrew's
  (`brew install openssh libfido2`; it need not be linked). The product finds
  it by itself, or takes `DFIRSWARM_SSH_KEYGEN=/path/to/ssh-keygen`.
- **E-signature** (`eimza.sh`, `console.sh` with `DFIRSWARM_HW_KIND=pkcs11`):
  the token plugged in, its PKCS#11 module (for a SafeNet eToken,
  `/usr/local/lib/libeTPkcs11.dylib`), OpenSC's `pkcs11-tool`, OpenSSL 3 and
  libp11's provider (`brew install opensc libp11 openssl@3`), and the
  issuer's CA certificates as PEM files.

The CA certificates are public, but a root fetched over plain HTTP is only as
good as the check of its fingerprint against the national trust list: in
Türkiye, BTK's list of electronic certificate service providers. Compare the
root's sha256 with it before you use it. Do not put the certificates, or any
PIN, in the repository.

## Running them

```bash
# 1. A FIDO key: enrol it (one touch), sign a release on the command line
#    (answer y, then one touch), verify it against the register line.
DFIRSWARM_HW_TESTS=1 bash tests/hw/fido.sh
#    With DFIRSWARM_HW_FIDO_VERIFY=1 the key is made verify-required: every
#    signature then asks for the FIDO PIN as well as a touch.

# 2. The e-signature token: enrol its certificate (no PIN), sign a release
#    (answer y, then type the e-imza PIN), verify without and with the CA.
DFIRSWARM_HW_TESTS=1 \
DFIRSWARM_HW_CA=/path/to/root.pem \
DFIRSWARM_HW_CA_INTERMEDIATE=/path/to/intermediate.pem \
  bash tests/hw/eimza.sh
#    DFIRSWARM_HW_PKCS11_MODULE and DFIRSWARM_HW_PKCS11_ID name another module
#    or object (the defaults are the SafeNet module and the certificate id this
#    was built with). With DFIRSWARM_HW_CA_INTERMEDIATE the intermediate is
#    enrolled with --pkcs11-chain and travels inside each signature, so verify
#    needs only the root. DFIRSWARM_HW_PDF=1 also prints and signs the PDF
#    (Chrome, Chromium or Edge needed).

# 3. The console's seal path: the console on loopback with a token, the
#    release prepared through its API, the prepared bytes fetched and hashed,
#    and the seal sent with the secret read here with echo off and piped into
#    the request body (never in an argument).
DFIRSWARM_HW_TESTS=1 bash tests/hw/console.sh                          # a FIDO key: touch it twice
DFIRSWARM_HW_TESTS=1 DFIRSWARM_HW_KIND=pkcs11 bash tests/hw/console.sh # the token: type the PIN once
```

Each script prints `ok - …` for every step and ends with `…: all checks
passed`, or stops at the first `FAIL:`.

## What each checks

- `fido.sh`: which `ssh-keygen` is used and why; the key is made on the
  authenticator and enrolled as a FIDO key with a register line; release v1
  is signed with a touch, records `key_kind: fido`, the consent as confirmed
  and the `ssh-keygen` that signed; `verify` against the register passes, and
  v0 reads as the machine's self-checked seal.
- `eimza.sh`: the certificate is enrolled without the PIN and shown by CN,
  issuer, validity and fingerprint; the release is a CAdES-BES CMS
  (`release.json.p7s`, with the signing-certificate-v2 attribute) made on the
  token; `verify` says "certificate chain not checked" without a CA (exit 3)
  and verifies the chain against the root, naming the anchor's sha256.
  The certificate's subject carries a national identity number: the script
  reads it from the token once, holds it in a variable it never prints, and
  fails if any output of the product (the enrolment, `examiner show`, the
  signature's output, `release.json`, `verify`) carries it.
- `console.sh`: the console takes the key; the bytes fetched from the pending
  report are the ones prepared; the seal from the console writes release v1
  with `via: console` and the consent confirmed, and puts it on the operator's
  record.

## Tried without the hardware

`eimza.sh` and `console.sh` (pkcs11) were run end to end against a SoftHSM2
token made by `tests/pkcs11-fixture.ts`, through a pseudo-terminal, before
they were handed over. `fido.sh` and `console.sh` with a FIDO key have not
been run: they need the key and a person to touch it.
