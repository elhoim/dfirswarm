---
id: artifacts/shell
title: Link files, jump lists, shell bags and recent documents
when: What a user opened, from where, and whether the source was removable or a share.
needs: [registry/system-profile]
tools: [lnk_parse, jumplist, shellbags, regkv]
requires_host: [icat]
---

These four say what a person touched, and they survive the file itself.

**Link files.** `Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk`.
`lnk_parse` returns the flags, three FILETIME timestamps of the *target*, the
local and common paths, the volume serial and, for network targets, the UNC
path. A link whose UNC names a share proves the document came from that share
and not from a local disk. Four of them agreeing was the answer to one published
case.

**Jump lists.**
`...\Recent\AutomaticDestinations\*.automaticDestinations-ms`, one per
application, keyed by an application id. They hold link structures for the files
that application opened, and they outlive the recent folder. `jumplist` reads
the DestList index — the path, the host the file was on, an access count and the
last access time — and writes each embedded link structure out for `lnk_parse`,
which is where the volume serial and the target's own timestamps come from. The
`customDestinations-ms` files are the pinned and task entries, in a different
format, and the same tool splits them.

**Shell bags.** `UsrClass.dat` under
`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`. They record folders a
user browsed in Explorer, including folders on devices and shares that are no
longer attached. This is the artefact that proves someone navigated to a
directory that no longer exists. `shellbags` walks the tree and rebuilds the
paths. Read its timestamps carefully: the key's last-write time is a kernel
FILETIME in UTC, and the shell item's own times are DOS timestamps in the
machine's local time, to two seconds.

**Recent documents.**
`NTUSER.DAT\...\Explorer\RecentDocs`, by extension, most recently used first.
`...\Explorer\ComDlg32\OpenSavePidlMRU` covers the open and save dialogues.

Cross-check the volume serial from a link against `fsstat` on the image. If they
differ, the file came from another volume, and that is usually the point.

Where the host carries them, `lnkinfo`, `olecfexport` and the `pyfwsi` module
(libfwsi-python, which has no program of its own) read the same three
artefacts with a different implementation. Use one of them on
anything you intend to put in the report: a shell bag name this pack had to
recover by searching, confirmed by a parser that read it from the documented
layout, is a much stronger line in a report than either alone.
