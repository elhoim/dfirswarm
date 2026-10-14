---
id: artifacts/knowledgec
title: KnowledgeC activity records and their limits
when: Interpret retained application and device-state activity.
needs: []
tools: [knowledgec_query, sqlite_query]
requires_host: []
---

Use when you read macOS application or device-state activity from `knowledgeC.db`. Not for a row's columns, values and dates (`artifacts/knowledgec-fields-time`, only if you read them).

macOS keeps application and device-state records for its own features in SQLite: what the machine's features saw, not a log of what a person did.

    ~/Library/Application Support/Knowledge/knowledgeC.db     per user
    /private/var/db/CoreDuet/Knowledge/knowledgeC.db          system-wide

Inventory the user and system stores separately; take each database with its `-wal`, `-shm` and `-journal` as one set. A write-ahead log holds committed rows the main file lacks: `knowledgec_query` applies one it finds in a private copy and counts the frames applied (`source_used`); a log left behind at collection is rows you do not have. A rollback journal holds the old pages of a transaction that did not commit and no rows the main file lacks: the tool rolls a hot one back in the copy and says so in `problems`, because the copy is then not the main file as acquired.

**Enumerate before you query.** The answer lists every stream in the file with its count and its first and last start. Candidates to look for, not a guaranteed set: `/app/inFocus`, `/app/usage`, `/display/isBacklit`, `/device/isLocked`, `/safari/history`, `/app/webUsage`. Streams, field types and retention vary by build. Check `status`, `problems` and `filters_unapplied`. For another table or a query the tool does not make, use `sqlite_query` on a copy, and read what it says about the write-ahead log before you rely on a negative.

**Whose activity.** The `source` columns can name a device other than this Mac. Decide whether the source identifies this device before you attribute a row to this machine.

**What foreground and display records support.** Shows: recorded application or device state (this application was in front, the screen was lit, the device was locked, for these seconds). Does not show: keyboard input, physical presence, attention, intent or who the human was, alone or in a row. Correlate authentication and session evidence (`logs/unified`, `accounts/users`) and weigh remote access and background activity before you say more.

**Biome.** Newer activity stores under `~/Library/Biome/` are another format: SEGB-framed records whose payloads belong to each stream. `knowledgec_query` does not read them and this pack has no decoder; if the mobile-forensics pack is loaded, its `ios/biome-segb` skill separates the framing from the payload, and iOS semantics do not carry over to macOS unchanged. A gap in KnowledgeC does not show that the activity did not happen elsewhere.

**Coverage.** Measure it per stream and source: first and last rows, gaps, decoding failures, sidecars present. Cite the database, table, `z_pk`, query and sealed output, and keep apart "not retained", "not acquired", "unsupported" and "searched, no match".

**Sensitive output.** `/safari/history` and web-usage values are URLs and can carry tokens and session identifiers in their query strings. Cite the row, and write a URL without its query string unless the question needs it.
