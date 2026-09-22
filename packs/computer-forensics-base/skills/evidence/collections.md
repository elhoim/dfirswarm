---
id: evidence/collections
title: A triage collection is not an image
when: The evidence is a zip or a directory tree of copied files rather than a disk.
needs: [evidence/imaging]
tools: [catalog_search, check_inputs, file_type]
requires_host: []
---

More cases arrive as a collection than as an image, and the difference decides
half of what you can say. A collector copied a list of files off a running
machine. There is no disk, no partition, no inode, no unallocated space and no
slack. Every command in the pack that takes `-o <offset>` is irrelevant here.

Recognise which collector made it, because the shape tells you what is in it:

    KAPE           a tree mirroring C:\, often with $MFT and $J at the root
    UAC            a .tar.gz with [bodyfile] [live_response] and per-artefact directories
    Velociraptor   a container zip, with an uploads/ tree and JSON result files
    CyLR           a zip mirroring the source paths, NTFS files pulled through the raw handle
    A hand-made copy   no manifest at all, and no way to know what was left out

**Work it as files.** Cite by path and hash instead of by inode. The parsers
still apply: a hive is a hive, an `.evtx` is an `.evtx`, and `$MFT` copied out
of a live volume parses exactly as it would from an image. `mft_records`,
`evtx_query`, `regkv` and the rest take a path and do not care where it came
from.

**Say what is missing, in the report, in one sentence.** The acquisition was
logical, so unallocated space, file slack, deleted records outside `$MFT`, and
anything the collector's target list did not name were never in your hands. A
reviewer must not have to work that out. "No carving was possible: the evidence
is a KAPE collection, not an image" is a complete answer to a question about
deleted files.

**Check the collector's own log.** Every collector above writes one, and it
names the files it could not read — usually the ones that were locked, which are
usually the ones that matter. A target that failed is a fact about the case.

**Do not trust the directory structure as a path.** Collectors rewrite paths to
be safe on the examiner's file system: a colon becomes something else, and a
named stream becomes a separate file with an invented name. Before you claim a
file lived at `C:\Users\x\y`, check the collector's manifest for the mapping.

Two host tools read these directly, if the host has them: `target-query` from
dissect, and mac_apt for a macOS or UAC collection. Neither is required, and
neither changes the rule above about what a logical acquisition cannot contain.
