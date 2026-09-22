---
id: registry/system-profile
title: Build the system profile before anything else
when: The first ten minutes of any Windows case.
needs: [registry/overview]
tools: [regkv]
requires_host: [icat, fsstat]
---

Everything later depends on these, and getting the timezone wrong invalidates
every timestamp you will write.

    SOFTWARE\Microsoft\Windows NT\CurrentVersion
        ProductName, CurrentBuild, DisplayVersion, InstallDate, RegisteredOwner
    SYSTEM\ControlSet00n\Control\ComputerName\ComputerName
    SYSTEM\ControlSet00n\Control\TimeZoneInformation
        TimeZoneKeyName, ActiveTimeBias
    SYSTEM\ControlSet00n\Control\FileSystem
    SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
        one subkey per SID, with ProfileImagePath and the profile load and
        unload times
    SYSTEM\ControlSet00n\Services\Tcpip\Parameters\Interfaces\<guid>
        addresses, DHCP lease times, the domain

`ActiveTimeBias` is minutes, and it is the offset in force when the hive was
written. `Bias` is the standard offset. Both are minutes west of UTC, so 480 is
UTC minus 8. State the conversion you used in the report.

Then the trap that has cost this project three separate runs: **`istat` prints
local time in the examiner's own timezone, not the evidence machine's.** An
analyst host set to UTC+3 renders every NTFS timestamp at UTC+3, and more than
one run wrote that into the timeline as though it were the guest's. Convert from
the raw value, not from what a tool rendered, and never inherit a timezone from
the previous case. A three-machine case is
worthless until every log is in one zone.

`ProfileList` load and unload times answer a question people usually try to
answer from event logs: which profile was actually loaded at a given moment.
That is how the wrong account gets named as the actor and how the right one is
found.

`fsstat` gives the volume serial, which ties link files and shortcuts to this
volume rather than to another one.
