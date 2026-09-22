---
id: registry/overview
title: The hives, where they live, and how to read one
when: Any question about configuration, accounts, devices, execution or persistence.
needs: [filesystem/extract]
tools: [regkv]
requires_host: [icat]
---

Extract the hive first, then parse it. Never reason from a listing.

    Windows/System32/config/SYSTEM      hardware, services, mounted devices, USB
    Windows/System32/config/SOFTWARE    installed software, run keys, profile list
    Windows/System32/config/SAM         local accounts and their RIDs
    Windows/System32/config/SECURITY    policy, and cached secrets
    Users/<user>/NTUSER.DAT             that user's own settings and activity
    Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat   shell bags (artifacts/shell)
    Windows/AppCompat/Programs/Amcache.hve                      program metadata

`regkv` takes a hive and a key and returns values plus subkeys with their
last-write times. The last-write time of a key is often the only timestamp you
get, and it is a real one: it is set by the kernel when the key changes.

`SYSTEM` carries a `Select` key naming the current control set. Read
`Select\Current` and use `ControlSet00<n>`, not a guess.

Two habits that keep answers honest:

- Quote the key path, the value name and the last-write time together. A value
  without its key's write time cannot be placed in a timeline.
- A value's presence is not execution. It is configuration. Pair it with
  something from the execution skills before you claim a program ran.

For the machine's own basics, see `registry/system-profile`.
