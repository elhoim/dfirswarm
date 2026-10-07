---
id: registry/overview
title: Registry sources, recovery state and interpretation
when: You need to select, validate and query an offline hive while preserving state and timestamp meaning.
needs: [filesystem/extract]
tools: [regkv, icat_extract]
requires_host: [regfexport, RECmd, regripper]
---

Extract the hive, then read it. Never reason from a directory listing.

    Windows/System32/config/SYSTEM      hardware, services, mounted devices, USB
    Windows/System32/config/SOFTWARE    installed software, run keys, profile list
    Windows/System32/config/SAM         local account records
    Windows/System32/config/SECURITY    policy and LSA material
    Users/<user>/NTUSER.DAT             that user's settings and activity
    Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat   shell bags (artifacts/shell)
    Windows/AppCompat/Programs/Amcache.hve                      program inventory (execution/amcache)

**Acquire a hive as a set.** Take each hive with its `.LOG1` and `.LOG2` (and a
legacy `.LOG`) beside it, with `icat_extract` into a file whose digest you
record. A hive whose two sequence numbers differ is dirty: its newest state can
be only in those logs. `regkv` reports `hive_dirty`, the sequence numbers and
the logs it found beside the hive, and says `transaction_logs_replayed: false`:
it opens the hive as it is. This pack provides no replay. If a question turns on
the newest state, say the hive was dirty and not replayed, keep the original and
its logs, and treat any recovered copy made elsewhere as a derivative with its
inputs, method and tool version recorded. Earlier states (a shadow copy, a
backup copy of the hive) are separate sources: `filesystem/shadowcopies`.

**`regkv` reads; it does not decode.** It takes a hive and a key and returns the
values (each with its registry type and length, read whole) and the subkeys with
their last-write times, as ISO 8601 UTC with the raw FILETIME beside it.

- Give the path from the hive's root, with or without a leading backslash. The
  hive's file name (`SYSTEM`, `SOFTWARE`) is not part of it. A key that is not
  there is answered with `deepest_found`, the `missing` part and the
  `subkeys_there`, so ask again from those instead of guessing.
- A binary value is hex and nothing more. UserAssist, ShimCache, BAM, SAM and
  ShellBag values are not decoded by it; say which decoder you used, or that none
  was available.
- Read `status`, `problems`, `corrupted_values` and `stopped_branches`. A recursive
  listing stops at `depth`; the branches it did not enter are named, and the whole
  listing is kept in the file `all_nodes` names. A hive that did not parse to the
  end cannot support an absence finding.
- A value that can be a secret (a name that says password, secret, token or
  credential; SAM user `V` values; the LSA secrets and cached logons of a SECURITY
  hive) comes back as a marker holding only its length, and is listed under
  `sensitive_values_withheld`.

**The control set.** An offline SYSTEM hive has no `CurrentControlSet`. Read
`Select`, record `Current`, `Default`, `Failed` and `LastKnownGood`, and use the
numbered `ControlSet00n` the question concerns; keep the others as separately
identified states. If the key you expect is absent, do not substitute another
control set silently.

**Timestamps.** A key's last-write time is key-level: it dates a change to that
key, not to each value in it, and not the first time the key existed. Software
that restores or edits a hive can set it. Some artefacts keep their own times
inside a value, with a different meaning from the key's. Quote the hive, the full
key path, the value name and type, the raw data, the key's last-write time and the
tool version together; a value without them cannot be placed in a timeline.

**A second reader.** A finding two parsers agree on survives review better than one.
Where the image carries them (check its tool inventory, `/etc/dfirswarm/tools.md`),
`regfexport` (libregf) exports a hive with a parser that is not regipy, `RECmd`
runs batch files for artefact families and `regripper` runs one plugin per
question. Record the plugin or batch file and its version with every result, and
keep disagreements rather than choosing one silently. They are optional programs;
their presence does not mean they support the hive's build or its logs.

A value's presence is configuration, not execution: pair it with the execution
skills before you say a program ran. For the machine's own basics, see
`registry/system-profile`.

**Sensitive output.** `regkv` withholds those values on its own and no flag
brings one back, so a job needs no `secret_output` for it. Record such a value as
its key, name, type and length. A secret value, a fragment of one, or a hash of
one is never written to a note, a report or a file, whichever route produced it.

**Does not show.** From a registry value alone: who set it, that the program or
device it names was used, or that nothing else was there (a dirty or partly parsed
hive, a different control set, a user whose hive was not collected).
