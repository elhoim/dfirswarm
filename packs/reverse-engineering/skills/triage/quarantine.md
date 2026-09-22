---
id: triage/quarantine
title: Working a sample without running it
when: Before you open anything the evidence produced.
needs: [evidence/verify]
tools: [file_type, entropy_map]
requires_host: []
---

Everything in this pack is static. Nothing from the evidence is executed, and
the harness enforces that rather than trusting it: under `--quarantine` the
extraction directory is held no-exec by the kernel, so a sample cannot run even
if something tries.

Work in this order and the order matters.

1. **Establish what the file is, from its bytes.** `file_type` reads the header.
   An extension is a claim by whoever named the file, and on a case that matters
   it is frequently a lie: a `.jpg` that is a ZIP, a `.doc` that is an RTF, a
   `.pdf` that is an HTML page with a script in it.
2. **Hash it and record the hash before anything else.** The hash is how the
   report ties every later statement to one object, and how a reviewer knows
   they have the same file.
3. **Measure entropy** before you reach for a disassembler. `entropy_map` shows
   where the file is compressed or encrypted. A section at 7.9 bits per byte is
   packed, and a disassembly of it is meaningless until it is unpacked.
4. **Then structure**: `pe/structure` or `elf/structure`.
5. **Then behaviour**: `capabilities/mapping`.

Two rules that keep this defensible.

**Do not submit the sample anywhere.** Uploading to a public service publishes
the evidence, tells whoever wrote it that they are being investigated, and in
some jurisdictions breaks the custody chain. Where a goal permits a hash lookup,
send the hash and never the file, and record that you did.

**Say what you did not do.** A static report that says "the sample was not
executed and no dynamic analysis was performed" is complete. One that implies
behaviour it did not observe is not — and "the malware connects to X" is a claim
about behaviour, where "the binary contains the string X, referenced from the
function at 0x4012a0" is a claim about the file.
