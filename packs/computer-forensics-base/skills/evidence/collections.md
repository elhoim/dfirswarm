---
id: evidence/collections
title: A triage collection is not an image
when: The evidence is a zip, a directory tree of copied files or an AD1 logical image rather than a disk.
needs: [evidence/imaging]
tools: [catalog_search, check_inputs, file_type, ad1_extract]
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

**An AD1 image is a collection in a container.** FTK Imager's logical image
(`.ad1`, further segments `.ad2` and on) holds the files and folders the
examiner chose, with their times and the MD5 and SHA-1 the imager computed.
The catalogue lists every item (`members.tsv` of the `ad1-items`
generation: `n`, its `locator`, the path under the image's data source
name, size, the modified, accessed and created times, the recorded digests,
the SHA-256 of the content and `check`, whether that content still matches
them). Find what you need with `catalog_search which=members`, then write
it out as a job:

    job_run tool=ad1_extract args={"image": "inputs/case.ad1", "members": ["ad1:item=<address>"]} inputs=["input:case.ad1"]

`members` takes the locator or `n`; a folder takes its subtree; no
`members` takes everything. Use the locator when the listing was partial (a
segment missing, an item it could not read): after a break the numbers are
not a whole read's, the locators are. The files land in the store, cited as
`job:<id>/<path>`, and the derived catalogue takes an archive or a disk
image inside in turn. A segmented image needs every segment in the job's
`inputs`; the census lists each further segment as not catalogued, read
from its first. `check` mismatch means the content is not what the imager
hashed: say so before you rely on the file. An encrypted AD1 (`ADCRYPT`) is
read only once it is decrypted with its password or certificate. dissect's
`target-query`, in the job images that hold this pack, reads an AD1 too
(`target-query -f walkfs inputs/case.ad1`, as a job): a second reader to
hold the first to. Everything above about a logical acquisition holds for
it.

Two host tools read these directly, if the host has them: `target-query` from
dissect, and mac_apt for a macOS or UAC collection. Neither is required, and
neither changes the rule above about what a logical acquisition cannot contain.
