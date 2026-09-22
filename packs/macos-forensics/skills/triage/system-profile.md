---
id: triage/system-profile
title: Build the system profile before anything else
when: The first ten minutes of any macOS case.
needs: [evidence/imaging]
tools: [plist_read]
requires_host: []
---

Almost everything on macOS is a property list, and the profile is six of them.

    /System/Library/CoreServices/SystemVersion.plist   ProductVersion, BuildVersion
    /Library/Preferences/SystemConfiguration/preferences.plist   hostname, network
    /Library/Preferences/com.apple.TimeMachine.plist   backup destinations
    /var/db/.AppleSetupDone                            the file's own ctime is the setup date
    /private/var/db/dslocal/nodes/Default/users/*.plist  every local account
    /Library/Preferences/.GlobalPreferences.plist      the machine's locale and timezone

`plist_read` handles both encodings. Most system plists on a modern macOS are
**binary**, not XML, and a grep over the raw file finds nothing while the value
sits there in plain sight — that is the single commonest wasted hour on this
platform.

The timezone is a symlink: `/etc/localtime` points into
`/usr/share/zoneinfo/<Region>/<City>`. Read the link target, not the file.
Convert from it and say so in the report.

The hardware identity lives in `preferences.plist` and in the IORegistry, which
a dead image does not have. The serial number is usually recoverable from
`/var/db/lockdown` on a machine that has paired an iOS device, and from a
Spotlight index otherwise.

**The system volume is read-only and sealed on macOS 11 and later.** The disk
is two volumes in one APFS container — a signed system volume and a writable
data volume — joined by firmlinks so that they look like one tree. When you
mount an image you may get one and not the other. Check both, and say which you
examined. See `filesystem/apfs`.
