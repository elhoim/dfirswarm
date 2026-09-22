---
id: ios/artifacts
title: iOS, and where each answer lives
when: The extraction came from an iPhone or an iPad.
needs: [extractions/what-you-have]
tools: [manifest_db, sqlite_freespace, plist_read]
requires_host: [ileapp]
---

Paths below are as they appear in a full file-system extraction; in a backup,
resolve them through `Manifest.db` first.

    private/var/mobile/Library/SMS/sms.db              messages and attachments
    .../Library/CallHistoryDB/CallHistory.storedata    calls
    .../Library/AddressBook/AddressBook.sqlitedb       contacts
    .../Library/Safari/History.db                      browsing
    .../Library/Caches/com.apple.routined/Cache.sqlite significant locations
    .../Library/BiomeStreams/, .../Library/Biome       newer activity streams
    .../Library/Preferences/*.plist                    per-app settings
    private/var/mobile/Containers/Data/Application/<uuid>/   one app's sandbox
    private/var/mobile/Containers/Shared/AppGroup/<uuid>/    shared between apps
    private/var/installd/Library/MobileInstallation/   what is installed, and when

**Two epochs and you will meet both.** Apple absolute is seconds since
2001-01-01 UTC and is what most iOS databases store. Unix seconds appear in
anything with a Unix heritage. `timestamp_decode` in the base pack settles a
bare number; getting it wrong is a thirty-one-year error that still looks
plausible.

**The application UUID directories are meaningless names.** Map each one to its
bundle identifier through the `.com.apple.mobile_container_manager.metadata.plist`
inside it, or through `MobileInstallation`. Reporting evidence from
"Application/4F2C…" without that mapping is unciteable.

**`sms.db` keeps deleted messages** in its own free pages until it is vacuumed,
which iOS does rarely. `sqlite_freespace` recovers text from those pages. A row
recovered that way has no reliable timestamp and no guaranteed thread — say
which parts you recovered and which you inferred.

**Knowledge and Biome are the activity record**, the same idea as the macOS
`knowledgeC` and increasingly protobuf rather than SQLite. `protobuf_peek`
opens a blob far enough to see what is in it before you decide it matters.
