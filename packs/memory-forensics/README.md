# Memory Forensics Pack

Method and tooling for a memory image, including what to do when no framework is
available — which is more often than the literature suggests.

Depends on the Computer Forensics Base Pack.

## What it carries

**Nine skills.**

| Family | Skills |
| --- | --- |
| Triage | `triage/what-you-have`, `triage/no-framework` |
| Frameworks | `triage/volatility` |
| Processes | `processes/injection` |
| Network | `network/state` |
| Credentials | `credentials/material` |
| Strings | `strings/discipline` |
| Pattern matching | `patterns/yara` |
| Acquisition | `acquire/images` |

**Three tools.** `mem_profile` names the container before anything is run
against it — and prints a crash dump's memory runs, because a dump is not
contiguous and a tool that assumes it is reads the wrong offset for everything
after the first gap. `mem_carve` finds the structures inside the image that the
other packs' parsers already read, and cuts them out with their offsets.
`mem_fs` drives MemProcFS.

**One goal template**: `memory-triage.md`.

## On Volatility

Volatility is declared as an optional host binary and is not imported or
vendored by this pack. The project keeps it at an executable boundary under
its own Volatility Software License 1.0; this is packaging policy, not a legal
conclusion about derivative works. The skills tell an agent to invoke `vol`
directly and to record the version and plugin with every result.

A production-ready memory image needs an offline Windows ISF symbol pack. The
image built from this pack pins one (`requires/host.json`, `install.data` of
`vol`): the Volatility Foundation's `windows.zip`, a snapshot of 2019-10-16 with
3,014 tables, downloaded at build time against its sha256 and indexed once so no
VM does it again. It covers the Windows builds of that time and no newer kernel,
which is why the skill still shows how to verify the cache and fail closed when
the matching symbol is absent; silently fetching a PDB during case work is not
an offline proof. The pack states no licence of its own: the Volatility Software
License 1.0 counts operating-system profiles as part of the software, and the
tables come from Microsoft's public symbol files, whose licence terms forbid
sharing them. The image is therefore for the machine that built it, never for a
public registry (`images/README.md`).

`aeskeyfind` finds AES key schedules in a memory image (BSD-3-Clause; Debian
packages it for amd64 and i386 only, so the image builds it from Debian's source
and patches on every architecture), and `gcc` and `make` are there for a
scanner a case needs that no library provides.

MemProcFS is AGPL-3.0, the same licence as this harness, which is why the one
wrapper here is for that and not for the other.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/memory-forensics
    scripts/swarm.sh start --pack computer-forensics-base,memory-forensics ...
