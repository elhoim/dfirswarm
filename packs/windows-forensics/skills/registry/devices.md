---
id: registry/devices
title: Device identities, mount associations and connection records
when: You need to correlate removable-device observations without equating attachment with transfer.
needs: [registry/system-profile]
tools: [regkv, icat_extract, lnk_parse, jumplist, shellbags, timestamp_decode]
requires_host: []
---

Several records, kept apart, describe a storage device: the hardware identity, the
mount association, the connection dates and the account context. Read the hives by
the rules of `registry/overview` and set the clock by `registry/system-profile`.

    SYSTEM\ControlSet00n\Enum\USBSTOR     class, vendor, product, revision and instance ID per device
    SYSTEM\ControlSet00n\Enum\USB         the same devices by VID and PID, with ContainerID where present
    SYSTEM\ControlSet00n\Enum\SCSI        devices attached through UASP, which USBSTOR does not list
    SYSTEM\MountedDevices                 drive letter and volume GUID to device or disk
    SOFTWARE\Microsoft\Windows Portable Devices\Devices    friendly name per portable device
    NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
                                          volumes this profile's Explorer session saw
    Windows/INF/setupapi.dev.log          device installation, as text (extract it with `icat_extract`)

**Identity.** Keep the whole instance identifier of each device, its hardware IDs
and its `ContainerID`, and record the volume GUID and letter separately. Decide
whether the serial part is a value the device supplied or one Windows generated
from the complete identifier and the bus it was seen on, and say which; do not
decide it from one character. A device-supplied serial can still be missing,
duplicated across devices or altered, and a generated identifier can differ
between ports. Treat two sightings as one physical device only when the serial,
vendor and product, container identity and, where it was acquired, the volume's
own identifiers agree; say what agreed and what was not available.

**Dates.** Where present, the device subkey's `Properties` hold the documented
device properties `DEVPKEY_Device_InstallDate`, `FirstInstallDate`,
`LastArrivalDate` and `LastRemovalDate` under the property-set GUID
`{83da6326-97a6-4088-9453-a1923f573b29}` (property IDs `0064` to `0067`). They are
different events: an install is not an arrival, and an arrival is not a removal.
The value's layout differs between builds, so read it with `regkv` at the
property's own key, record the key path, value name, type and raw bytes, and decode
the 8-byte little-endian FILETIME with `timestamp_decode`. A key's last-write time
is key-level and is not a substitute for any of them. A device or hive without these
properties gives no first or last date: say so rather than estimating one.
`setupapi.dev.log` records installation in the machine's local clock; convert it by
the rules of `registry/system-profile` and treat an absent entry as a log that
rotated or was never written, not as a device never installed.

**Letters and mounts.** `MountedDevices` holds the latest assignment of a letter or
volume GUID: the next device to take a letter overwrites the earlier entry, so it
is not a history of every mapping. `regkv` returns its binary values as hex; the
entry for a removable device is the device's instance text in UTF-16LE, and an entry
for a fixed disk is a partition identifier, not text. `MountPoints2` keys are named by
volume GUID (network shares by path): they show that this profile's Explorer saw the
volume, an account context. They do not show that the person at the keyboard attached
or mounted the hardware. Not every portable device presents a file system, and not
every USB storage device follows the same registry path: when a device you expect is
missing from `USBSTOR`, check `SCSI`, the portable-devices key and `setupapi.dev.log`
before recording that it was absent.

**Correlating with files.** A shortcut, a jump-list entry or a ShellBag that names the
device's letter or volume serial (`lnk_parse`, `jumplist`, `shellbags`;
`artifacts/shell`) shows that a path on that volume was opened or browsed: it does
not show that content was copied to or from the device. To say that data was moved
you need file-level evidence: the device's own file system if it was acquired, file
system records on the host (`filesystem/journals`) that name the files at times that
fit the attachment window, or an application's own record. Say which of these you
looked for and did not find.

**Sensitive output.** `regkv` withholds secret-bearing values on its own and lists
them under `sensitive_values_withheld`; record such a value by key, name and length
only. Device serials and friendly names are identifiers, not secrets.

**Does not show.** Device records do not show what was copied, by whom, or that the
device was connected only at the dates found. A missing record in one hive or build
is not absence of the device: name the keys, hives and time range that were searched.
