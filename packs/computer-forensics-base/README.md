# Computer Forensics Base Pack

The method and the tooling every examination needs, whatever the operating
system the evidence came from: work out what you were handed and where the
volume starts, verify the evidence, build a catalogue before spending a token,
extract and carve, tell an encrypted volume from an unreadable one, keep a
timeline that survives a second reader, and write a report whose every claim
cites something checkable.

Platform-specific artefact knowledge lives in the packs that depend on this one.

## What it carries

**Eleven skills**, fetched one at a time by the agents that need them:

| | |
| --- | --- |
| `evidence/verify` | prove the evidence is what you were handed, and stays that way |
| `evidence/imaging` | the container, the partition table, and the offset every command needs |
| `evidence/catalog` | read the catalogue before you spend a token |
| `evidence/collections` | the evidence is a zip or a directory tree, not a disk |
| `filesystem/extract` | get a file out of an image, and prove which file it was |
| `filesystem/carving` | find structure where there is no file system |
| `filesystem/encrypted` | a volume the toolkit cannot read, and which of three reasons it is |
| `timeline/build` | a timeline a second reader can trust |
| `timeline/super` | the window an incident happened in, from evidence too large to read |
| `reporting/citations` | every claim cites something a reviewer can re-run |
| `reporting/disagreement` | disagreeing, vetoing, and correcting after a sign-off |

**Thirteen tools**: `image_layout`, `check_inputs`, `catalog_search`,
`icat_extract`, `sig_carve`, `file_carver`, `ioc_scan`, `chunk_needles`,
`file_type`, `sqlite_query`, `feature_scan`, `timeline_super`,
`timestamp_decode`. The last four arrived with the packs that depend on this
one: a tool every pack would have carried belongs here once, not in each of
them.
Every one takes JSON on stdin and returns JSON, and every call lands on the
run's trace under the calling agent's name.

## Host requirements

The Sleuth Kit and libewf are invoked as executables and are not redistributed
here: their licences and this project's do not combine in one work. BitLocker,
LUKS and virtual-disk tooling is declared optional, needed for one kind of case
rather than for the pack to work. `requires/host.json` has the whole list with
install commands; `scripts/pack.sh show computer-forensics-base` says which of
them this host has.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/swarm.sh start --pack computer-forensics-base ...
