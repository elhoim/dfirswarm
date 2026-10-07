---
id: execution/amcache
title: Amcache and ShimCache inventory and interpretation
when: You need to identify a file or interpret compatibility and application-inventory records.
needs: [execution/overview, registry/overview]
tools: [amcache_apps, regkv]
requires_host: [RECmd, regripper]
---

Two inventories, one claim each: **an entry means the system's inventory or
compatibility cache recorded this file, not that the program ran**, and a missing
entry does not mean it did not. Which entries exist, and when they were written,
depends on the Windows build, the inventory task and the hive's state.

**Amcache** is `Windows/AppCompat/Programs/Amcache.hve`, a registry hive: work on a
copy, with the `.LOG1` and `.LOG2` beside it (`registry/overview` for hive state).
`amcache_apps` reads both layouts when both are present and names the layout in each
row: `File` (the older, numbered values) and `InventoryApplicationFile` (the Windows 10
and later layout, named values returned as the hive stores them). Read `layouts_found`
and `rows_by_layout` first. The older layout's numbered values are named by a
published mapping, research and not Microsoft documentation: record that when a field
name matters.

**Observation.** Per row: the path, publisher and version values the layout holds;
the hash as stored (`sha1_raw`) with the 40-digit form beside it (`sha1`;
`file_id_sha1` for the newer layout's `FileId`), stripped only where the stored value
has the shape of four zeros and 40 hex digits; the key's last-written time
(`key_last_modified`, UTC, seven fractional digits, raw FILETIME beside it) and, in the
older layout, the numbered FILETIME values. `linker_compile_time_utc` is the PE
header's 32-bit Unix-epoch value, converted as one, raw value kept: it is program
metadata set when the binary was linked and can be chosen by whoever built it. It is
not a run time and not a trustworthy build date.

**What it shows, and how to use the hash.** The inventory held an entry for that path
and file. The hash lets you test a file whose bytes are gone against a hash you hold
(a recovered copy, a case hash list). What range of the file the inventory hashed is
not established here and may depend on the build, so a mismatch with a whole-file hash
is not a different file until you have settled that, and a match is a match of that
range. Other sources, process-creation telemetry among them, may carry hashes too.
Keep the stored value in the record, not only the stripped one.

**State.** `hive_dirty` and `hive_sequence_numbers` say whether the base block's two
sequence numbers agree; `transaction_logs_beside_hive` names the logs, and
`transaction_logs_replayed` is false: the pack replays nothing. If the hive is dirty,
the newest entries may sit in the logs: say which state you read. If `RECmd` or
`regripper` is on the host, either can read the same hive as an independent reader
(optional; record the version, and whether it applied the logs). `status: partial`
(`rows_failed`, `problems`) is not the hive's whole inventory; "neither layout is
present" is an answer about this hive, not about the machine.

**ShimCache** (AppCompatCache) is a binary value in the SYSTEM hive, under
`ControlSet00n\Control\Session Manager\AppCompatCache`. `regkv` returns it as hex with its
type and length and nothing more: the pack has no ShimCache decoder. The layout varies
by Windows version, so decode it only with a parser validated for the build, `RECmd`
or `regripper` where the host has them, and say the tool, its version and the format
version; read the control set the question concerns (`registry/overview`), not a
hard-coded `ControlSet001`. Record path, cached file metadata and
order separately. A cached file time is the file's metadata, not an execution time, and
the order is not a complete sequence of runs. How and when the cache reaches the
registry, and what the flags mean, differ by implementation and build: a hive taken
from a running system can lag the in-memory state, so an absence near the end of a
timeline is not evidence.

**Sensitive output.** `regkv` withholds values whose name says password, secret, token
or credential, and no flag brings one back; record such a value as key, name, type and
length. A secret value, a fragment of one or a hash of one is never written to a note, a
report or a file. Inventory paths, versions and file hashes are not secrets.

**Absence is bounded.** "No Amcache entry for <name or hash> was found in <hive,
sequence state, layouts read>" and the same for ShimCache; say the build, whether the
logs were applied and what was not collected.

**Does not show.** That the program ran, who ran it or from which account, how often,
that it finished, that the file was present at any date the entry does not carry, or
(for a missing entry) that the file never existed there.
