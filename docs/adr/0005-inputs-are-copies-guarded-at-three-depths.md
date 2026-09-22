# 5. Inputs are copies, guarded at three depths

Date: 2026-09-18

## Status

Accepted

## Context

An operator wants to hand a swarm files to analyse — logs, a dataset, a
codebase snapshot — with one guarantee: the agents read them and nothing
they do changes them. The harness already keeps agents out of its own files
(`budget.json`, `locks/`, `done/`), but that guard has two limits. It sees
only the tool calls it can intercept (`edit`, `write`, `claim_file`); a
`bash` command is detected after the fact, not stopped (ADR 0001). And it
protects paths the harness owns, not a tree the operator brought.

Three choices had to be made: whether the agents work on the original
directory or a copy; whether "read-only" is a rule, a permission bit, or a
kernel decision; and what to do when a write gets through anyway.

## Decision

**The swarm gets a copy, never the original.** `--inputs DIR` copies the
directory into `<sandbox>/inputs/` with symlinks dereferenced, so the
original is out of reach whatever happens in the sandbox and nothing outside
the copy is reachable through it. A second, pristine clone sits next to it
(cheap on APFS and btrfs; a plain copy elsewhere) and a manifest records
every file's hash.

**Read-only is enforced at every depth the host allows, and each depth is
measured rather than assumed.**

1. The tool guard refuses `inputs/` the way it refuses harness files, with
   a reason that says what to do instead (copy into `work/`).
2. The bash watch covers `inputs/`; a write that gets through is healed from
   the pristine clone, logged as `inputs_violation`, and announced on the
   board. This is the layer that always exists.
3. Where the host can, the whole pane runs with `inputs/` read-only at the
   kernel: `sandbox-exec` on macOS, a mount namespace on Linux
   (`scripts/fsguard.sh`). The hook is the pane's shell (`ZDOTDIR`), because
   Herdr does not start `pi` through `PATH`. At session start each agent's
   harness probes a write under `inputs/` and records what stopped it.

`--inputs-enforce on` makes a missing kernel guard a refusal to start;
`auto` warns; `off` skips it.

**The console names sets, never paths.** A kickoff from the web form chooses
a directory under `SWARM_INPUTS_ROOT`; the server resolves it and refuses
anything that is not a plain directory right there.

## Consequences

- The original directory is safe by construction: no layer has to hold for
  it, only for the copy. The cost is disk (the copy plus the clone, which is
  free where the filesystem clones) and a size cap (`--inputs-max-mb`).
- Kernel enforcement depends on the pane being a zsh on macOS, or a zsh on a
  Linux host with unprivileged user namespaces. Elsewhere the run still
  starts, says so, and relies on layers 1–2; the trace shows which depth each
  pane actually got, so a claim of "read-only" is never stronger than the
  evidence.
- Layer 2 costs a stat per input file per `bash` call. A tree with thousands
  of files is watched only up to a cap; the size cap keeps that honest.
- Reading is not restricted. That is a different feature with a different
  threat model (exfiltration rather than corruption), and netguard already
  bounds where anything read could go.
- The hook rewrites `ZDOTDIR` for the pane; the user's own zsh configuration
  is loaded by the re-executed shell exactly as before. A bash pane ignores
  the hook and reports `enforced: none`.
