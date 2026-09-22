---
id: memory/windows
title: A Windows memory image, with or without a framework
when: The evidence includes a .mem, .raw, .vmem, hiberfil.sys or a crash dump.
needs: [filesystem/carving]
tools: [mam_scan, evtx_carve, ioc_scan, sig_carve, yara_scan, utf16_urls]
requires_host: [strings]
---

Memory answers what disk cannot: what was running, what was injected, what was
decrypted, and what never touched a file. Work it in two passes, and do not
wait for a framework before you start.

**First, what is in the image whatever tooling you have.** These all work on raw
bytes and each one has closed a question in the published runs:

    mam_scan       prefetch records whose files were deleted
    evtx_carve     event records the log no longer holds
    sig_carve      registry hives (REGF), PE headers (MZ), archives, images
    ioc_scan       a path, an address, a name, in ASCII and UTF-16LE
    utf16_urls     the URLs a process had in memory
    yara_scan      a rule over the whole image, for a known family

Carve a hive out and hand it to `regkv`; carve a chunk out and hand it to
`evtx_carve`. A structure carved from memory is parsed by the same tool that
would parse it from disk.

**Then a framework, if the host has one.** Two exist and they differ in a way
that matters here. Volatility's licence and this project's do not combine, so it
is a host binary like the Sleuth Kit: use `vol` when it is on PATH, and record
the version and the plugin with every result, because plugin output changes
between versions and a reviewer needs to reproduce it. MemProcFS is AGPL-3.0,
the same licence as this harness, and it mounts the image as a file system —
processes, handles, registry and network state become files you can read with
the ordinary tools, and anything you extract from it can go straight to the
parsers in this pack. Where both are present, prefer whichever you can make a
reviewer repeat.

When the host has neither, say so in the report rather than implying the memory
was examined and found nothing.

Three things to keep straight, because memory findings are the easiest to
overstate:

- **A string in memory is not an action.** The same bytes arrive from an
  antivirus signature file, a browser cache, a log line and a sample. Name the
  process and the region, or do not name the string.
- **Page-level fragmentation.** A structure can be split across pages that are
  not adjacent in the file. A carved record that ends mid-field is truncated,
  not corrupt, and should be reported as partial.
- **`hiberfil.sys` is compressed and it is a *past* state**, not the state at
  acquisition. It is often the most valuable file on the disk for exactly that
  reason: it is the machine before the operator cleaned up. Say which moment you
  are quoting.

Pair anything you find here with a disk artefact before it becomes a
conclusion. Memory says a process existed; `execution/overview` says how to
prove it ran.
