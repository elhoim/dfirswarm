---
id: triage/volatility
title: Volatility with the right symbols, offline
when: You are about to run Volatility on Windows or Linux memory, or a plugin reports an unsatisfied symbol requirement.
needs: [triage/what-you-have]
tools: [mem_profile]
requires_host: [vol]
---

Run Volatility offline first. A result that required an unrecorded symbol
download is not reproducible on an isolated examiner workstation.

    vol --offline -vv -f IMAGE windows.info >work/<your id>/windows.info.txt \
      2>work/<your id>/windows.info.stderr

Record `Volatility 3 Framework`'s version line, the plugin, the image hash and
the symbol identity. The memory and `full` images hold the Volatility
Foundation's Windows symbol pack (`/etc/dfirswarm/tools.md` says where it is and
what it covers; a host run has no image, and holds no pack unless the operator
put one under `volatility3/symbols`):
3,014 tables for the Windows builds of 2019 and earlier, so a newer kernel is
usually not in it. `vol -q isfinfo` lists what is there. The kernel you need is
named by its PDB name and its GUID and age (`ntkrnlmp.pdb`, 32 hexadecimal digits,
a number); a table for it is in that listing as
`windows/<pdb>/<GUID>-<age>.json.xz` or it is not in the image.

If the error names a PDB plus GUID/age, the image does not hold that symbol.
Do not switch off `--offline` silently. Ask the operator to add a pinned ISF
pack through the image build, or make one controlled, allowlisted symbol-fetch
job whose downloaded PDB/ISF hash is retained. Say in the report that the
plugins which need the symbol were not run, and why, and which checks that
need no kernel symbols (strings, YARA, carving) were.

For Windows, establish the kernel once with `windows.info`, then compare views:

    windows.pslist     live linked process list
    windows.psscan     pool scan, including exited or unlinked remnants
    windows.pstree     parentage, checked against start times
    windows.cmdline    command lines where resident
    windows.netscan    live and carved network structures
    windows.malfind    suspicious executable private regions; dump and hash them
    windows.vadinfo    the region boundaries and protections behind a claim
    windows.handles    what a process could reach
    windows.modules / windows.dlllist   kernel and per-process modules
    windows.svcscan    registered and residual services

For Linux, there is no exhaustive public cache: the ISF must match the exact
kernel build. Start with `linux.pslist`, `linux.pstree`, `linux.lsof`,
`linux.sockstat`, `linux.envars`, `linux.bash` and `linux.malfind`. If the
matching ISF is absent, say that symbol-dependent Linux analysis was not
performed; a nearby distribution version is not a substitute.

Keep stdout and stderr whole. Empty output is an absence only after the plugin
completed successfully with the matching symbol table and its scope is stated.
