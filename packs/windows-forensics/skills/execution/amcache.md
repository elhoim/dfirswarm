---
id: execution/amcache
title: Amcache and ShimCache, and what they do not prove
when: You need a hash for a binary that is gone, or a list of what was on the machine.
needs: [execution/overview]
tools: [amcache_apps, regkv]
requires_host: [icat]
---

**Amcache** (`Windows/AppCompat/Programs/Amcache.hve`) is the only common
artefact that carries a **SHA-1 of the binary itself**. That is what makes it
valuable: you can identify a file that no longer exists. It also carries the
publisher, the version, the PE link date and the path.

`amcache_apps` reads it and returns path, SHA-1, publisher and link date from
whichever of the key layouts this build uses. The layout changed across Windows
versions; do not hand-parse it.

The SHA-1 has a quirk: some builds store it with four leading zeros. Strip them
before comparing against a hash you computed.

**ShimCache** (`SYSTEM\ControlSet00n\Control\Session Manager\AppCompatCache`) is
the weakest execution artefact in common use. An entry means the file was seen
by the compatibility engine. On modern Windows that happens on execution, but
it can also happen from a directory listing in some paths, and the entries are
ordered but not individually timestamped in the way people assume.

It is also written to the registry **only at shutdown**. A machine imaged while
running, or one that crashed, has the most recent entries only in memory. So an
absence near the end of a timeline means nothing at all.

So: cite ShimCache for presence and for ordering. Do not cite it alone for
execution. Say which of the two you are claiming.
