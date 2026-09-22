---
id: artifacts/plists
title: Property lists, which is to say most of macOS
when: Any question about configuration, an application's state, or what a user set.
needs: [triage/system-profile]
tools: [plist_read, timestamp_decode]
requires_host: []
---

A property list is a dictionary in one of three encodings, and two of them are
not text.

    XML        <?xml version …  readable, greppable, increasingly rare
    binary     bplist00 at offset 0, the normal case on a modern system
    JSON       a few newer components

`plist_read` reads all three and returns JSON. Reach for it before you reach for
`strings`: a binary plist searched with `strings` gives you keys without their
values and values without their keys, and an answer assembled from that is a
guess.

Where they live, and which matter:

    /Library/Preferences/                  machine-wide settings
    ~/Library/Preferences/                 per user, one file per bundle id
    ~/Library/Containers/<id>/Data/…       a sandboxed app's own copy
    /Library/LaunchDaemons, LaunchAgents   persistence, see persistence/mechanisms
    ~/Library/Preferences/com.apple.recentitems.plist   what was opened
    ~/Library/Preferences/com.apple.finder.plist        including recent folders
    /Library/Preferences/com.apple.loginwindow.plist    who logs in automatically

**Dates inside a plist are a real type, not a string.** A binary plist stores a
date as seconds since 2001-01-01 UTC — the Apple epoch — and a parser that
treats it as Unix time is off by thirty-one years. `plist_read` converts them;
when you meet a bare number in some other artefact, `timestamp_decode` will tell
you which epoch makes it plausible.

**A preference file is not a record of use.** It says what the setting is now,
and its own modification time says when it last changed. It does not say who
changed it or what it was before. For use, go to `artifacts/knowledgec` and the
unified log.

`cfprefsd` caches preferences in memory and writes them lazily, so a plist on a
disk imaged from a running machine can be minutes or hours behind what the user
saw. On a cleanly shut-down machine it will not be.
