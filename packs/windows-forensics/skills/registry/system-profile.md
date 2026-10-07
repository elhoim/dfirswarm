---
id: registry/system-profile
title: Windows build, volume, profile and clock context
when: You need to establish the system context required to interpret other Windows artefacts.
needs: [registry/overview]
tools: [regkv, mft_records, timestamp_decode, image_layout, lnk_parse]
requires_host: [istat, fsstat]
---

Record these before you interpret anything else: they decide how a build-specific
artefact is read, which zone a local-time value is in, and which account a path
belongs to. Each is a configuration state captured in a hive, not a history. Read
the hives by the rules of `registry/overview` (control set, dirty hive).

    SOFTWARE\Microsoft\Windows NT\CurrentVersion
        ProductName, CurrentBuild (or CurrentBuildNumber), UBR, DisplayVersion,
        EditionID, InstallationType, InstallDate, RegisteredOwner
    SYSTEM\ControlSet00n\Control\ComputerName\ComputerName
    SYSTEM\ControlSet00n\Control\ComputerName\ActiveComputerName
    SYSTEM\ControlSet00n\Control\TimeZoneInformation
        TimeZoneKeyName, Bias, ActiveTimeBias, StandardBias, DaylightBias
    SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
        one subkey per SID: ProfileImagePath, State, and the load and unload time words
    SYSTEM\ControlSet00n\Services\Tcpip\Parameters\Interfaces\<guid>
        addresses, DHCP lease times, the domain

**Build.** `ProductName` is a label and can name an earlier release than the
one installed. Decide the release from `CurrentBuild` with `UBR`, and corroborate
it with the version information of a system file in the image where a tool there
reads it; record each source and its value. Where a statement turns on a build,
cite the published build table you used with its date. `InstallDate` is a
Unix-epoch number (decode it with `timestamp_decode` and record the epoch you
chose): it can date the last upgrade or servicing rather than the first install.
`RegisteredOwner`
is text typed at setup, not proof of who owns or used the machine. `ActiveComputerName`
is the name in use since the last start and `ComputerName` the configured one;
where they differ, record both.

**Clock.** Before any conversion, state what each artefact's time is. NTFS
`$STANDARD_INFORMATION` and `$FILE_NAME` times, event log `SystemTime`, a registry
key's last-write time and a Prefetch run time are UTC FILETIMEs: they get no zone
conversion. FAT-family directory entries store the local clock as written, so the
zone comes from that volume's own evidence. Keep the raw value beside every
converted time (`mft_records` returns the raw FILETIMEs and ISO 8601 UTC) and
convert from the raw value, never from a rendering.

- Windows biases are minutes with `UTC = local time + bias`: 480 is UTC-8, and the
  daylight component is added on top of `Bias`. `ActiveTimeBias` is the offset in
  force when Windows last wrote it, so it can be a daylight offset and it says
  nothing about an earlier date.
- Never apply the zone you read today to a past date. Take the rule for the date
  in question (zone rules and their transition dates change over the years) from a
  named source: `TimeZoneKeyName`'s `Dynamic DST` rules in SOFTWARE where present,
  or the zone database of the tool, with its version. Where the date falls in a
  transition hour, say it is ambiguous and give both readings.
- `istat` prints a file's times in the examiner host's zone unless it is told
  otherwise. Run it with `istat -z UTC` (check the usage of each other Sleuth Kit
  program that prints times for the same option), and record the Sleuth Kit
  version and the exact invocation beside what you quote. A time an agent copied from a rendering without
  that record is a local-time claim: convert it again from the raw value.
- When two machines or two logs meet in one timeline, put every source in UTC first
  and state the zone you took for each local-time source and why.

**Profiles.** Each `ProfileList` subkey maps a SID to a profile path, which is how a
`Users\<name>` folder or a SID in an artefact is tied to an account. The load and
unload times are kept as a low and a high 32-bit word each that you combine into one
FILETIME yourself (record the words and the field names; availability and meaning
vary with the build). They are a profile-service record, not a complete
session history: a profile loaded is not an interactive logon, not a named person,
and a missing unload value does not mean the user was still there. For an
interval, corroborate with profile-service and authentication events
(`accounts/logons`, `logs/security`).

**Volume.** `fsstat` (or the `volume_serial` that `image_layout` returns per
partition) gives the filesystem serial. A shortcut or a jump list records a volume
serial of its own (`lnk_parse` prints eight hex digits), so compare like with
like and say which digits you compared. Equal serials support an association with
this volume; they do not prove it, because a clone or a copied image carries the
same serial. Keep a mismatch as a mismatch instead of forcing a path mapping, and
record the partition, filesystem type and acquisition source beside the serial.

**Network.** The interface keys hold the addresses and DHCP lease times that were
last written for each interface; lease times are numbers, so decode them with
`timestamp_decode` and record the epoch. They show a configuration, not a
connection history or the other machines on it.

**Sensitive output.** `regkv` withholds secret-bearing values and lists them under
`sensitive_values_withheld`; record any such value by key, name and length only
(`registry/overview`).

**Does not show.** This context does not show who used the machine, that the
current zone applied on an earlier date, the original installation date, or that a
profile was in use at a moment. Absence of a profile or interface key in one hive is
not absence of the profile or interface.
