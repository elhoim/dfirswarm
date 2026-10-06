---
id: credentials/material
title: Credential material, and how to talk about it
when: You must say whether credentials were exposed or taken.
needs: [processes/injection]
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol, aeskeyfind]
---

Memory is where credentials are in the clear, and that is the point for an
attacker and the risk for you.

What is there, on Windows: the LSA secrets and cached domain credentials, the
SAM hashes, Kerberos tickets, and — depending on the build and configuration —
plaintext in `lsass.exe`. On Linux: SSH agent keys, credentials in environment
blocks, and anything a process read from a file and kept.

**The examination question is almost never "what is the password".** It is
whether an attacker could have taken them, and the evidence for that is not the
credential itself:

- a process that opened a handle to `lsass.exe` with read rights,
- a minidump written to disk, or the `MiniDumpWriteDump` path in a process that
  had no reason to call it,
- a known tool's signature, by hash or by YARA rule,
- the registry showing WDigest re-enabled, which puts plaintext back in memory
  on a build that had stopped doing it.

**Handle the material itself with care.** Do not copy recovered credentials into
the report, the board, or the ledger. Cite the artefact and the offset and say
what class of material it is. A report that quotes a live domain password has
created a new incident; a report that says "cached credentials for three domain
accounts were present in the region dumped at offset 0x…, hash recorded in the
ledger" has said the same thing safely.

Where the goal explicitly asks for a recovered secret — a container password,
say — record the hash in the ledger and hand the value over through the channel
the operator named, not through the report.

**Key schedules.** A cipher that is in use keeps its expanded key in memory: 176
bytes for AES-128, 240 for AES-256, laid out so that each round key follows from
the one before it. `aeskeyfind -q IMAGE` tests every position against that
relation and prints the keys it finds, tolerating a few decayed bits (`-t`
raises the tolerance and the false positives with it; `-v` adds the offset it
was found at, `AT BYTE` in hexadecimal, and the expanded key). A hit is a lead
and nothing more: the schedule may belong to the browser, to
a library, or to nobody, so say which offset it was at and which tool and
threshold found it, and call it established only when it decrypts something the
evidence holds. Its absence is a statement about the layout the tool tests (the
standard AES-128 and AES-256 schedules, byte for byte), not about whether a key
was ever in memory. Two layouts it does not test are in the tool library
(`--tools-from tool-library`): `aes_schedule_scan` also reads the schedule with
the bytes of each 32-bit word reversed, and `aes_inverse_scan` reads one stored
as a decryption routine keeps it (the middle round keys transformed, the rounds
in either order). Neither prints a key: it goes to a private file in the
tool's `out_dir`, which by default is `work/quarantine/<your id>/` (in a job,
`$OUT/quarantine/`), and the answer gives the offset, the layout and the key's
sha256 to record in the ledger. A key file is live material from the evidence
and a handover package leaves `work/quarantine/` in the sandbox; a key file
anywhere else, and a job's outputs in a package that carries outputs, travel
with it unless the hit is recorded as a sensitive ledger entry that cites the
file (a redacted package then withholds it) or the scan ran as a
`secret_output` job. Record where the key was found and its hash, and hand
the value over through the channel the operator named.

`aeskeyfind` comes with the memory and `full` images. A host run has it only if
the operator installed it (Debian packages it for amd64 and i386 only); without
it this check was not run, and the report says so.
