---
id: credentials/material
title: Credential material, and how to talk about it
when: You must say whether credentials were exposed or taken.
needs: [processes/injection]
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol]
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
