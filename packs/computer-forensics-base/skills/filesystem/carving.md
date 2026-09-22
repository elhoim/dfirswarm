---
id: filesystem/carving
title: Find structure where there is no file system
when: Unallocated space, a memory dump, slack, or a volume the toolkit cannot read.
needs: [filesystem/extract]
tools: [sig_carve, file_carver, ioc_scan, chunk_needles, feature_scan]
requires_host: []
---

Carve by signature, then prove the hit is real before you report it.

`sig_carve` scans for known headers and returns offsets with context.
`file_carver` cuts by header and footer once you know the type.
`ioc_scan` streams a large file for ASCII and UTF-16LE needles and returns
offsets, which is how you find a path, an address or a name in a blob.

Work in this order:

1. Scan for the structures that carry time: prefetch records, event log records,
   registry hives, browser databases, link files.
2. For each hit, cut a slice large enough to hold the record, parse it with the
   right tool, and only then report it.
3. Hash every carved artefact and record the offset it came from. The offset is
   its provenance; there is no path.

At scale, hand the whole image to `feature_scan`. It runs bulk_extractor, which
reads the bytes and ignores the file system entirely: addresses, URLs, card
numbers, EXIF and telephone numbers, each with the offset it was found at. Its
record scanners matter more than its string scanners — `ntfsmft`, `ntfsindx`,
`ntfsusn`, `ntfslogfile`, `winprefetch`, `winlnk` and `evtx` carve whole
structures out of unallocated space, which is the same job as `sig_carve` done
across a disk rather than a slice.

Large legitimate binaries carve out of unallocated space all the time. An
installer, a runtime, a signed driver. Classify them as noise explicitly rather
than leaving them out, so a reviewer can see you looked.

Text in a memory image is not proof a process did anything. A string can arrive
from an antivirus signature file as easily as from a sample. Say which process
and which region it came from.
