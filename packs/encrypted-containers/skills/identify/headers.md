---
id: identify/headers
title: Identifying encrypted evidence and its limits
when: A volume, archive or document may be encrypted.
needs: []
tools: [crypto_id, file_type]
requires_host: []
---

Use when a volume, archive or document may be encrypted and you must say what it is. Not for one format's detail or for opening it.

Identify the storage layer before interpreting encryption. Record the source
object, the acquisition type, the logical-stream path, the partition offset and the
sector size. `crypto_id` takes a byte offset into the file you give it: an offset
in a logical disk is not an offset in its E01 or virtual-disk wrapper (see
`evidence/imaging`).

Use `file_type` and `crypto_id` to triage, then check the proposed format with a
reader that supports the version you see. Record the reader and its version, the
fields it read, and any damaged, missing or unsupported structure.

`crypto_id` shows a recognised signature at the offset, the header fields at fixed
places (LUKS1 slot table; LUKS2 version, label, UUID), the basis of the call, the next
reader, and what is not determined.

**Does not show.** BitLocker protectors, LUKS2 keyslots, whether an APFS volume is
encrypted, document encryption, or whether any data is intact or openable. "No scheme
recognised" is not "not encrypted".

Only if you name a particular format's protection (BitLocker, LUKS, Apple, VeraCrypt and TrueCrypt, archives, Office, PDF, phone backups): `identify/by-format`.

**Sensitive output.** `crypto_id` prints no raw bytes unless `include_head_hex` is
true: leave it false when the input may itself be a key or credential file, and do
not copy those bytes into the report or the ledger. Run any job that may emit secret
material with `secret_output: true`, and record locations and sealed references,
never values or hashes.

Before opening anything, fix the question and the authority for examining it. Use
keys and passwords the case supplies, or that were found within that authority; a
clear-key path that needs no secret is still not authority. If the material is not
supplied, see `keys/where-they-hide` for how to look in the evidence, and ask before
trying anything further.

An unreadable volume is not necessarily encrypted. Rule out a volume manager, a
damaged partition table, a sparse or truncated image and a wrong offset first
(`evidence/imaging`): they are cheaper to fix and common. The base pack's
`filesystem/encrypted` separates encryption from the other causes of unreadability.

Report exactly one of: format and protection state confirmed (by which reader);
format suspected (on which observations); unsupported or damaged; not determinable.
A failed mount and a missing signature are not findings that encryption is absent.
