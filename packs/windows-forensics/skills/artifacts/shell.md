---
id: artifacts/shell
title: Links, Jump Lists, ShellBags and recent-item records
when: You need to interpret shell references to files, directories, volumes or shares without overstating user activity.
needs: [registry/system-profile]
tools: [lnk_parse, jumplist, shellbags, regkv]
requires_host: [fsstat, lnkinfo, olecfexport]
---

These are references the Windows shell kept, not records that something was done.
A link holds a target and cached metadata about it, a Jump List an index of items an
application or the shell listed, a ShellBag a folder some shell component opened.
They outlive the file they name and none of them names the person. For each, say
what it holds, which clock its times are on, and what else would have to be true
for the claim you want to make.

**Collect the set per profile.** Links: `Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk`
and any link an application wrote elsewhere; keep a link's own filesystem times
apart from the times stored inside it. Jump Lists: the `AutomaticDestinations` and
`CustomDestinations` folders beside it (the file name is an application id; record
it, the pack does not map ids to programs). ShellBags: the `BagMRU` trees of
`UsrClass.dat` (`Local Settings\Software\Microsoft\Windows\Shell`) and of
`NTUSER.DAT` (`Software\Microsoft\Windows\Shell`, `ShellNoRoam` in older hives),
with the transaction logs beside each hive.

**Links (`lnk_parse`).** It reads the MS-SHLLINK layout: flags, the three target
FILETIMEs (raw decimal beside ISO 8601 UTC, seven fractional digits), LinkInfo
(VolumeID: `drive_type_name`, `serial_number` as eight hex digits, label; local base
path and common path suffix; CommonNetworkRelativeLink: `net_name`, device name,
provider), `linkinfo_target` with `linkinfo_target_kind` (local or network), the
string data (arguments among them) and the extra blocks it recognises. The shell
item list is not decoded: `idlist_ascii`, `idlist_paths`, `utf16_strings` and the
tracker block's `machine` are printable runs listed under `heuristic_fields`. ANSI
strings are shown as Latin-1 because the file records no code page. A read that
ends inside the structure says so under `problems` and `structure_complete`; read
more bytes (`size`) before citing a field of it. With `scan` it carves links from a
dump by the 20-byte header, and a hit is a candidate.

A link shows that a reference to the target was recorded, with the target's size and
times as they were when the link was last written. It does not show that the target
was opened (the shell writes links on opening, but an application or a user can
create one, and one can arrive in an archive or a message), where the content came
from, or who used it. A network target (`linkinfo_target_kind: network`) shows the
target was named by that share path when the link was written, not that the content
came from there. A removable drive type with a serial and a label says the volume
was recorded that way; tie it to a device only through the device records
(`registry/devices`), and not as proof of a copy.

**Volume identifiers.** A VolumeID serial is 32 bits; `fsstat` prints the file
system's own serial, which for NTFS is wider. Record the width, byte order and source
field of each, and check how the two relate on a volume whose serial you know. A
mismatch supports "a different recorded volume identifier" (another volume, a
re-formatted one, a link copied from another machine); a match says the identifiers
agree, not where the file is now.

**Jump Lists (`jumplist`).** An `automaticDestinations-ms` file is an OLE compound
file (read with olefile) holding a `DestList` index and one link stream per entry.
`jumplist` reads DestList versions 1, 3 and 4 by their own layouts and refuses any
other version with a problem and no entries; report that as a limitation, not as an
empty list. An entry gives its number, the NetBIOS host name, the last access (raw
FILETIME and ISO UTC), the pin state and the path. The counters between those fields
come back raw as `undecoded_*`: no access count is claimed, so do not read one from
the hex. Every embedded link is written to `out_dir`; the volume serial and the
target's own times are in those links, so run `lnk_parse` over them before citing
either. A `customDestinations-ms` file has no container: its links are carved by the
20-byte header and marked `carved`, they are candidates (header-shaped bytes inside
a link are cut as if they began another), and its categories, pins and tasks are not
parsed.

An entry shows that the application or the shell listed that item: recent use, a
pin (automatic destinations hold pins too), an application-supplied destination or a
task. It is not by itself an opening event, and its last access is the entry's own
record in the index, not the target's timestamp. Record the application id, source
file, DestList version, entry and stream.

**ShellBags (`shellbags`).** It walks every `BagMRU` root the hive has and names each
(the `Shell` and `ShellNoRoam` trees can both be populated). Per entry it returns the
rebuilt path, `key_last_written` (raw FILETIME and ISO UTC), the item's own created,
modified and accessed times, the MRU position and how the name was obtained. A
numbered value with no key under it is listed under `values_without_subkey`, keys
below `max_depth` under `not_walked_below_max_depth`, and `partial` means something
was not walked or read. Root folders, volumes and file or directory entries are read
by layout (`decoded: layout`), but a long name is read from its layout only for
extension version 3 or 7 (`long_name_from: layout`). For another version it is the
longest string in the block (`long_name_from: strings`, `extension_layout: not decoded
for this version`), and any other item class is `unrecognised` with the longest
readable string as its name (`decoded: strings`). Those are candidates found by
search, not decodes: do not report one as read until `pyfwsi` (libfwsi-python, a
library with no program) or another reader that follows the documented layout
agrees. `shellbags` does not look at the hive's transaction logs: run `regkv` on the
same hive for `hive_dirty` and the logs beside it, and say neither tool replays them,
so the newest bags of a dirty hive may be missing.

A bag has two clocks. `key_last_written` is UTC and moves when anything under that key
changes; it is not the first or last time the folder was viewed. The item's times are
DOS times in the machine's local time, to two seconds, with no zone stored. Converting
them needs the zone rules in force on that date (`registry/system-profile`); the
current offset is not enough for a date before a zone or daylight-saving change. Say
what you converted from, and never put an unconverted DOS time in a UTC timeline.

A bag shows that a shell component opened that folder on this account, including
folders on devices and shares that are gone. It does not show who, that a file in it
was opened, that the folder still exists, or when it was first or last viewed. Record
the root, full BagMRU path, value slot, MRU position, item type and whether the name
was decoded or found by strings.

**Recent documents (`regkv`).** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
(by extension) and `...\Explorer\ComDlg32\OpenSavePidlMRU`. `regkv` returns each value
as hex and decodes nothing; the pack has no decoder for either. `MRUListEx` is a list
of 32-bit little-endian slot numbers, most recent first, ended by `FFFFFFFF`: read the
order from it, since registry enumeration order is not recency. A name read by eye
from the hex is a candidate. The key's last-write time dates the latest change under
that key, not each item.

**A second reader for what a report rests on.** Where the host carries them (optional;
check the job image's `tools.md`): `lnkinfo` parses a link by another implementation
than `lnk_parse`; `olecfexport` takes the compound file apart, which confirms stream
extraction and not DestList semantics; `pyfwsi` reads shell items from their
documented layout. They are not interchangeable. For a target, serial, share or long
name that a report line depends on, keep both outputs and any disagreement; if no
second reader is available, say the field has one.

**Negatives.** "No link, Jump List entry or ShellBag for `<path>` was found in
`<profiles>`, `<hives and their state>`, acquired `<date>`" is bounded. These records
are written by components that can be disabled, limited or cleaned, a profile may not
have been collected, and the newest bags can sit in an unreplayed log. Absence of a
reference is not absence of the event.

**Sensitive output.** A link's arguments, working directory and strings, and the links
inside a Jump List, can hold a command line with a secret in it. Run `lnk_parse` and
`jumplist` as jobs with `secret_output: true` when they may. Describe a command line by
its shape (interpreter, script location, an encoded-argument form), never its text;
never write a password, token or key, a fragment of one or a hash of one. `regkv`
withholds values whose names say password, secret, token or credential and marks them.
An argument is read, never run or evaluated; decode it offline.

**Does not show.** That a person did it (these records are made by components acting
on an account); that a file was opened, read, copied or run; that content came from
the share or device a path names; when something was first or last used; that the item
still exists, or never existed; that the artefact set is complete.
