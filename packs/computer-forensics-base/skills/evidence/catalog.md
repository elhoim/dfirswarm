---
id: evidence/catalog
title: Read the catalogue before you spend a token
when: At the start, and whenever you are about to run a broad listing yourself.
needs: [evidence/verify]
tools: [catalog_search]
requires_host: [fls, mmls, fsstat]
---

The kickoff can run the first pass over the evidence before any agent starts, so
seven agents do not each pay for the same `fls -r`. When it did, `catalog/`
holds, per image and partition: a file listing, a body file, a timeline, and for
memory images the output of the usual first plugins.

Search it before you image anything yourself. `catalog_search` takes a regex and
returns matching lines from the listing, the timeline and the body file.

Read `catalog-README.md` first. It says what was built and what was not. An
entry marked not built is a fact about the evidence, not an oversight: a volume
the toolkit could not read is usually the case's first real question. Take it to
`evidence/imaging`, and to `filesystem/encrypted` if the volume is there and
still refuses to open.

The listing shows named streams, so anything hidden in one is already in front
of you. Grep the listing for a colon before you go looking with anything
cleverer.

If the catalogue is missing or empty, say so on the board once, and build only
the part you need. Do not rebuild the whole thing in every pane.
