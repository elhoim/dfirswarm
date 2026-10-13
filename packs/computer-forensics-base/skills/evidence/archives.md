---
id: evidence/archives
title: Archives and extraction fidelity
when: A zip, tar, 7z or compressed file whose members you need as files.
tools: [archive_extract]
requires_host: [7z]
---

Use when a zip, tar, 7z or compressed file must become files. Not for an AD1 logical image (`evidence/ad1`) or a disk image.

An archive is hostile input and a container whose list is its own claim. List first, extract second.

**List.** The `archive-members` recipe writes `members.tsv` without extracting: `n` (the member's number in archive order, duplicates included), exact name bytes (`path_b64`), type, sizes, times, link target and `flags` (`escapes-root`, `encrypted`, `ratio>1000`, `name-not-utf8`). It runs `7z` for a 7z. Two members with one name are two rows.

**Extract** as a job with `archive_extract` (run it with `secret_output: true`: members are evidence content). It takes the archive, `out_dir` under `{OUT}`, budgets (`max_total_bytes`, `max_member_bytes`, `max_members`, `max_ratio`, `max_depth`, `max_seconds`) and `from_index` (the recipe's `n`):

    job_run tool=archive_extract args={"path": "inputs/collection.zip", "out_dir": "{OUT}/collection"} inputs=["input:collection.zip"]

It reads the format from the bytes, creates files only under `extracted/` and never recreates a link, device or FIFO (each is a `not_created` row with its target). `members.jsonl` has one row per member: `name_b64` (the exact name), `path` (where the bytes are, an ASCII-safe rendering), sizes, the archive's times with their zone said, `flags`, `status`. A member is `.partial` until its size and CRC match; a cut, CRC-failed or over-budget member stays `.partial` with the reason. `encrypted` and `unsupported` members are counted, not opened. A global budget stops the run with `stopped_by` and `next_index`; resume with `from_index` and `resume: true` on the same archive.

**Names.** A name shaped like a token or carrying user-info is withheld: `name_withheld` in every answer, the file under `extracted/_withheld/withheld-NNNNNN`, the real name only in `withheld-names.jsonl` (0600). Cite the member by `n`. There is no name filter. Do not paste a withheld name into the ledger.

**Nested archives** are named (`looks_like`), not opened: extract the inner one in a call of its own with its own budgets. zstd is read only where the image has a zstd reader; the answer says when it has none. A 7z with encrypted headers cannot be listed; no password is used or guessed.

**Does not show.** An extraction shows what the archive held and that each written member matches the archive's size and CRC. It does not show that the archive is authentic, complete as acquired, or that a member's stored times are real. A `.partial` or missing member is not an absent file.
