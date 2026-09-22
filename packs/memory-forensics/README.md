# Memory Forensics Pack

Method and tooling for a memory image, including what to do when no framework is
available — which is more often than the literature suggests.

Depends on the Computer Forensics Base Pack.

## What it carries

**Seven skills.**

| Family | Skills |
| --- | --- |
| Triage | `triage/what-you-have`, `triage/no-framework` |
| Processes | `processes/injection` |
| Network | `network/state` |
| Credentials | `credentials/material` |
| Strings | `strings/discipline` |
| Acquisition | `acquire/images` |

**Three tools.** `mem_profile` names the container before anything is run
against it — and prints a crash dump's memory runs, because a dump is not
contiguous and a tool that assumes it is reads the wrong offset for everything
after the first gap. `mem_carve` finds the structures inside the image that the
other packs' parsers already read, and cuts them out with their offsets.
`mem_fs` drives MemProcFS.

**One goal template**: `memory-triage.md`.

## On Volatility

Volatility is declared as an optional host binary and is never wrapped. Its
licence and this project's do not combine in one work, so a purpose-written
driver for it would be a derived work of Volatility rather than of this
repository. The skills tell an agent to invoke `vol` directly and to record the
version and the plugin with every result.

MemProcFS is AGPL-3.0, the same licence as this harness, which is why the one
wrapper here is for that and not for the other.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/memory-forensics
    scripts/swarm.sh start --pack computer-forensics-base,memory-forensics ...
