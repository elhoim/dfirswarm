# Mobile Forensics Pack

iOS and Android: what kind of extraction you were handed, what it cannot
contain, and where each answer actually lives.

Depends on the Computer Forensics Base Pack and on the macOS Forensics Pack —
iOS is macOS's sibling, and `plist_read` from that pack is needed for most of
what an iPhone stores.

## What it carries

**Seven skills**: `extractions/what-you-have`, `ios/artifacts`,
`ios/biome-segb`, `ios/unified-logs`, `android/artifacts`, `apps/databases`,
`location/sources`.

**Three tools.** `manifest_db` turns an iOS backup's flat directory of
hash-named files back into a file system, and reports the encryption flag first
— because an encrypted backup returns empty databases rather than failing, and
an examiner who misses that reports an empty phone. `sqlite_freespace` recovers
deleted rows from a database's freelist pages **and its per-page freeblock
chain**, which is where a deleted row's bytes actually sit. `protobuf_peek`
reads a protobuf blob without its schema, for the Android and iOS artefacts that
stopped being SQLite. All three return their complete matching result; the
harness retains oversized stdout rather than letting the tools cut it.

**Five recipes**, each saying what it prepares (`purpose` in its
`recipe.json`). Two inventories: `ios-filesystem` turns a full-file-system tar
into a structural mobile catalogue without extracting it (it parses no
artefact content), and `android-backup` reads an adb-backup header and
inventories every member of an unencrypted payload. Two broad extractions, run
by the kickoff: `ios-ileapp` hands a whole iOS full file-system acquisition (a
tar or a zip) to iLEAPP and keeps every report it writes, a TSV per artefact
with records, its timeline and the HTML, under `ileapp/`; `android-aleapp`
does the same for an Android full file-system acquisition with ALEAPP. Their
`exclusions` say what they do not hold (artefacts no module parses, deleted
records beyond what a module reads, protected data without its key), and a
run stopped before its end says partial. And one declared and never run:
`android-backup-apps`, the broad extraction an adb backup would need, which the
image cannot do (ALEAPP reads a file-system layout, an adb backup keeps each
app under `apps/<package>/`), so the harness records the preparation of every
adb backup declined with that reason instead of a parse that would find next
to nothing. Every recipe says exactly what it did not cover in
`coverage.json`. What the harness does with a broad extraction (its receipts,
the lead that offers one, the hold on a negative that claims absence while it
runs) is ADR 0013's "A source's broad extraction before a negative on it".

**One goal template**: `phone-examination.md`.

## The two things this pack will not let you skip

**A logical extraction cannot answer a question about deletion.** No unallocated
space, no slack, nothing outside what the backup protocol exposes. That belongs
in the report as a limit on the evidence.

**Copy the `-wal` with the database.** The newest messages are in the
write-ahead log, not in the `.db`, and on a phone that is never closed cleanly
the checkpointed state can be weeks old. Copying only the `.db` silently loses
exactly the period a case is about.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/macos-forensics
    scripts/pack.sh install packs/mobile-forensics
    scripts/swarm.sh start --pack computer-forensics-base,macos-forensics,mobile-forensics ...
