---
id: recovery/what-is-possible
title: What can actually be recovered
when: The organisation is deciding what to restore, and what is gone.
needs: [encryptor/destroyed-backups]
tools: [encrypted_survey]
requires_host: []
---

Be exact here. This is the part of the report people act on, and an optimistic
answer costs more than a pessimistic one.

**Files that were never encrypted.** Most campaigns skip by extension, by
directory and by size. `encrypted_survey` tells you the proportion actually
encrypted per tree, and the skipped set is often larger than anyone assumes.

**Files whose original survived elsewhere.** A copy in a shadow copy that the
deletion missed, in a cloud sync client's version history, in a mailbox, on a
laptop that was off, in a backup the operator did not reach. Check every one
before writing anything off.

**Partially encrypted files.** Speed matters to the operator, so many families
encrypt only the first few megabytes, or every other block, or a percentage.
A large database or disk image encrypted at the head may be substantially
recoverable by somebody who knows the format — that is a specialist job, but
whether it is *possible* is your finding, and `encrypted_survey` answers it by
measuring entropy across the file rather than at the front.

**Deleted originals.** A family that writes the encrypted output to a new file
and deletes the original leaves the original's clusters intact until they are
reused. That is ordinary carving, and it works. One that encrypts in place does
not.

**What is genuinely gone.** Properly encrypted with a key nobody has. Say it
plainly: "these files cannot be recovered without the key" is the finding, and
hedging it wastes weeks.

Two warnings for the report. **Do not promise recovery from a decryptor you
have not tested**, and test on a copy. And **note that paying does not
guarantee a working decryptor** — many are slow, many are buggy, and some lose
data — which is a factual statement the organisation is entitled to before it
decides.
