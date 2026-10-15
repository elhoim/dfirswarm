---
id: credentials/key-schedules
title: AES key schedules in a memory image
when: Searching an image for AES-128 or AES-256 key schedules with aeskeyfind.
needs: []
tools: []
requires_host: [aeskeyfind]
---

Use only if you search an image for AES key schedules. Not for other credential material (`credentials/material`).

**Key schedules.** `aeskeyfind` tests every position of an image against the
AES-128 and AES-256 expanded-key layout and tolerates a few decayed bits. Run it as
a `secret_output` job (`aeskeyfind -q -v IMAGE`; `-v` adds the offset in
hexadecimal, and its help names the rest). Its stdout carries the keys: take the
offsets and the count, not the keys; never put one on a command line or in a file
under `work/`. A hit shows that bytes laid out like a schedule are at that offset.
It does not show which application or artefact used it, that it is in use (a
library may keep a schedule it no longer needs), or that it opens anything.
Establish it only by opening something the evidence holds, with the authority the
case gives, through a reader that takes the key from a sealed file. A negative
covers the two standard layouts, the bytes read and the threshold used; it does
not say no key was in memory, and AES-192, other ciphers and other layouts are not
examined. The tool library (`--tools-from tool-library`) has two more layouts,
`aes_schedule_scan` (the bytes of each word reversed) and `aes_inverse_scan` (as a
decryption routine stores it). They write a key to a private file under their
`out_dir`, and their answer gives the offset and the key file's name, no digest:
run them as `secret_output` jobs and record the offset and the key file's name,
never the key or a hash of it, in a post, the ledger or the report. `aeskeyfind`
is in the memory and full images; a host run has it only if the operator installed
it, and without it this check was not run, and the report says so.

**Sensitive output.** `aeskeyfind` prints the keys on stdout and the two library tools write them to a file: every run is a job with `secret_output: true`; the ledger and the report carry offsets and counts only (`credentials/material`).

**Does not show.** That a schedule is in use, which application used it, or that it opens anything; that a negative means no key was in memory.
