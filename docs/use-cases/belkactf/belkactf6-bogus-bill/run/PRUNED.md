# What this copy of the package leaves out

`swarm.sh package` now leaves the evidence-derived binaries in the sandbox
itself: seven of them here, over the 256 KB threshold, named with their
hashes in [`LEFT-BEHIND.txt`](LEFT-BEHIND.txt). That rule came out of this
very run — the first package it wrote was 37 MB, of which 35 MB was registry
hives, browser databases and a tar listing that agents had kept in their own
scratch directories.

Two files it kept are text, and the rule is deliberately about binaries: a
CSV timeline, a carved log and a JSON export belong in a handover whatever
their size. They are still derived from the evidence and still large, so this
repository does not carry them:

```
work/s821c05/tarfilelist.txt   17 MB   the full path listing of the iPhone tar
work/s821c05/postbox.strings  1.2 MB   strings pulled from the Telegram postbox
```

Both can be produced again from `inputs/` in one command, and both have a
sha256 in `artifacts.json` and `MANIFEST.txt` — which is the point: the
hashes stay, the bytes do not.
