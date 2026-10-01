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
the symbol identity. The kernel you need is named by its PDB name and its GUID
and age (`ntkrnlmp.pdb`, 32 hexadecimal digits, a number); with `-vv` the
`Symbols` row of `windows.info` names the table Volatility read
(`windows/<pdb>/<GUID>-<age>.json.xz`), and without a table its log names the
symbol-server address it would have fetched, which carries the same identity.
The kickoff's catalogue does this for every memory input (the `kernel-symbols`
recipe: `kernel.json`, and `catalog/missing.json` when the image lacks the
table).

What the image holds is in `/etc/dfirswarm/tools.md`, under "Data the programs
read" (a host run has no image, and holds no table unless the operator put one
under `volatility3/symbols`): the exact tables the operator's build made for
the kernels its pack lists (`grep <GUID> /etc/dfirswarm/tools.md`), and the
Volatility Foundation's bundle of 2019, which covers the Windows builds of 2019
and earlier, so a newer kernel is usually not in it. `vol -q isfinfo --filter
<GUID>` says whether a table is there. An image built without its symbol sets
says so in the same file ("left out by the build").

If the error names a PDB plus GUID/age, the image does not hold that symbol.
Do not switch off `--offline`, and fetch nothing. Close a lead `needs_operator`
that names the PDB, the GUID and the age: the operator adds the kernel to the
pack's curated list, fetches its PDB on the host (`swarm.sh symbols fetch`) and
rebuilds the image, or makes the table and supplies it to the run
(`tool-supply`), and you point Volatility at a supplied table with `-s`. Say in
the report that the plugins which need the symbol were not run, and why, and
which checks that need no kernel symbols (strings, YARA, carving) were.

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
