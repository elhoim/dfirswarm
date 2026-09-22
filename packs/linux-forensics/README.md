# Linux Forensics Pack

What a Linux examination needs: where each artefact lives, what it proves, what
parses it, and the traps that make an answer wrong.

Depends on the Computer Forensics Base Pack, which carries the method that is
true of any platform.

## What it carries

**Eight skills**, in seven families.

| Family | Skills |
| --- | --- |
| Triage | `triage/system-profile` |
| Logs | `logs/auth`, `logs/journal` |
| Accounts | `accounts/users` |
| Persistence | `persistence/mechanisms` |
| File system | `filesystem/ext` |
| Containers | `containers/docker` |
| Packages | `packages/integrity` |

**Five tools.** `auth_log` (auth.log and secure, through the rotated and gzipped
files, with the missing year worked out and said out loud), `utmp_parse` (wtmp,
btmp and utmp, the binary login records an operator who cleans the text logs
usually forgets), `shell_history` (every shell and client history under a tree,
with zsh and bash timestamps where the shell recorded them), `cron_dump`
(all six cron locations and systemd timers in one list), `journal_export`
(the systemd journal, read from the evidence path and never from this machine).

**Two goal templates**: `server-compromise.md`, `what-was-scheduled.md`.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/linux-forensics
    scripts/swarm.sh start --pack computer-forensics-base,linux-forensics ...

Host binaries are declared in `requires/host.json` and all of them are optional:
the pack's own tools use the standard library only, and each host tool widens
what can be read rather than being needed for the pack to work.
