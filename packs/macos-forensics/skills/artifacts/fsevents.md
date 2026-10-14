---
id: artifacts/fsevents
title: FSEvents, retained filesystem change records
when: Assess filesystem changes and relative order without inventing timestamps.
needs: []
tools: [fsevents_parse]
requires_host: []
---

Use when you read `.fseventsd` records for what changed. Not for ordering or dating a record, flags or an external volume's log (`artifacts/fsevents-dating`, only if the question needs the order or a date).

Find `.fseventsd` in each acquired volume's own root, the Data volume included, and keep its record files and `fseventsd-uuid`. That file names this log; it is not the APFS volume UUID. A merged tree can hide which volume a directory came from.

    /.fseventsd/fseventsd-uuid    the log's identity
    /.fseventsd/<16 hex digits>   gzip record files, one or more members each

FSEvents is a change-notification history, not an audit of file operations. What survives depends on logging, retention, exclusions, coalescing, what was collected and whether the history was damaged, removed or restored. Do not assume a volume has a complete log, or that every operation made a record of its own.

**Check what the parser read before you rely on it.** `fsevents_parse` reads `1SLD` and `2SLD` pages. A page of another version (`3SLD`, say) is reported `unsupported` with the magic seen, and the rest of that file is not decoded; a file that is not an FSEvents record file is `unsupported` too. Read `status`, `files_by_state`, the `coverage` counts (gzip members complete, truncated and failed; pages parsed, invalid, truncated; records decoded and incomplete; bytes skipped) and `problems`. A zero count, an empty `problems` list or an exit of 0 is not a finished examination: for a format the tool does not read, use a parser validated for it or record the format as not examined.

For a record that matters keep the file, the format version, the event id, the raw and decoded flags, the path, the node id (version 2) and the member, page and record offsets the tool prints. A flag bit the tool has no name for is `flags_undecoded`. The flag names are the on-disk map, not the public FSEvents API constants; do not swap one for the other.

**Does not show.** When a change happened, who made it, what it contained, or that a path absent from the log was never touched. A negative reads: "no matching record was decoded from these files, by this parser and filter", with the formats supported, the failures counted and the retention limits stated.
