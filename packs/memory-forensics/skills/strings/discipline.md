---
id: strings/discipline
title: A string in memory is not an action
when: Any claim built on text found in a memory image.
needs: [triage/no-framework]
tools: [ioc_scan, chunk_needles]
requires_host: [strings]
---

This is the most common way a memory finding fails review, and it has happened
in the published runs.

The same bytes arrive in memory from at least five places that have nothing to
do with a process doing anything:

- an antivirus signature file, loaded into the scanner's own memory,
- a browser cache, or a page the user never clicked,
- a log line the logging service is holding,
- a file the indexer read,
- another examiner's tooling, running on the same machine during acquisition.

So: **name the process and the region**, or do not name the string. "The
address appears at offset 0x3f2a1000, inside a private committed region of
`chrome.exe` (pid 4120)" is a finding. "The address was found in memory" is a
sentence a reviewer will delete.

Three more rules that keep this honest:

1. **Search for UTF-16LE as well as ASCII.** Windows holds most of its strings
   wide, and a sweep that only looks at ASCII misses paths, command lines and
   URLs entirely. `ioc_scan` does both.
2. **Quote the context, not just the hit.** The bytes either side say whether
   you are looking at a command line, a log line or a list of signatures.
3. **A hit with no offset is not evidence.** The offset is the only provenance a
   memory finding has; without it nobody can go back and look.

When a string is all you have, say that. "The domain was present in memory, in a
region that could not be attributed to a process, and no artefact on disk
corroborates it" is a complete and defensible answer.
