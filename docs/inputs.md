# Read-only inputs

Hand a swarm files to analyse that it can read and never change.

```
scripts/swarm.sh start --model deepseek/deepseek-v4-pro --n 3 --cap-usd 2 \
  --goal-file prompts/goals/analyse-logs.md --inputs ~/cases/2026-09-incident
```

The directory is copied into the sandbox as `inputs/`, the original is never
touched, and from then on the agents can `read`, `grep`, `ls` and `bash` over
it as much as they like, while every write, delete, rename or `chmod` under
it is refused or undone. Results go in `work/`, where the usual claims apply.

## What the kickoff does

| Step | What lands in the sandbox |
| --- | --- |
| Copy | `inputs/` — a dereferenced copy (`cp -RL`), so a symlink in the source becomes a plain file and nothing outside the copy is reachable through it. |
| Lock | Every file `r--r--r--`, every directory `r-xr-xr-x`. |
| Clone | `.inputs-pristine/` — the same bytes once more (an APFS clone or a reflink where the filesystem has them, a copy elsewhere). The harness heals from it. |
| Manifest | `inputs.json` — the source path, when it was copied, every file with its size and sha256, and which guard the panes got. |
| Contract | `SWARM.md` gains an **Inputs (read-only)** section: the rule, the file list, what happens on a write. |
| Registry | `inputs: {source, files, bytes, enforce, guard}` on the run, so the console can show it. |
| Pane hook | With a kernel guard available, `.zsh/.zshenv`, `.bash/.bashrc` + `.bash/.bash_profile` and `.fsguard/plan.txt`; the workspace gets `ZDOTDIR` and `HOME` pointing at them (below). |

Limits: `--inputs-max-mb` (default 512) refuses a larger directory before
anything is copied, and so does a directory with more than 5000 files: that
is how many the watch and the checks cover, and the promise is not made
where it cannot be kept.

## Three layers, from the tool call down to the kernel

1. **The tools refuse.** `edit`, `write` and `claim_file` return
   `read-only input: inputs/…` (with the advice to copy the file into
   `work/`), and so does `file_restore`. A symlink from `work/` into `inputs/`
   resolves to the input and is refused the same way. This is the same guard
   that keeps agents out of `budget.json` and `locks/`.
2. **A shell write is detected and healed.** `bash` cannot be intercepted
   mid-command, so the harness fingerprints what it watches before and after
   every call — and `inputs/` is on the watch. A forged tool gets exactly the
   same bracket under its own name: it is a subprocess with the reach of
   `bash`. The fingerprint is the file's sha256, its mode and its link count;
   the sha is re-read when size, mtime **or ctime** moved (an owner can put
   size and mtime back with `touch -t`; ctime needs root), a write bit given
   back counts as a change, and so does a second name for the inode (a hard
   link out of `inputs/`, which is how a path-based check would be walked
   around). A symlink planted inside is an addition: the kickoff dereferenced
   every one it copied, so none is legitimate. A changed, re-permissioned or
   deleted file is put back from `.inputs-pristine/` at a fresh inode, a
   planted file or link is removed, the trace gets an `inputs_violation` line
   naming the agent, the path and the tool it came through, and the board
   gets a `veto` post saying what was healed. A change nobody's tool call
   bracketed — a backgrounded process — is caught by the sweep that runs at
   turn ends (at most every 15 s per agent; a stat per file) and again inside
   `done`, which heals first and then records
   an `inputs_check` line: an `ok: false` there means a heal failed, not that
   nobody looked.
3. **The kernel says no** where the host can do it (`scripts/fsguard.sh`; the
   same wrapper takes `--noexec DIR` for `--quarantine`, a seatbelt
   `process-exec*` deny or a `noexec` bind mount over `work/extracted/` and
   `work/quarantine/`):

   | Host | Mechanism | What it denies |
   | --- | --- | --- |
   | macOS | `/usr/bin/sandbox-exec` with a profile that allows everything and denies `file-write*` and `file-link` under `inputs/` | write, create, unlink, rename, chmod, chflags, xattr, and a hard link whose source is under `inputs/` (verified on macOS 27: `ln inputs/a work/alias` is refused) — for the whole process tree: Pi's own tools, `bash`, python, node, a forged tool, headless Chromium |
   | Linux | `unshare -rm` (a user + mount namespace), `inputs/` bind-mounted over itself read-only, then back to the real uid | the same, for the whole process tree; a hard link out of the mount fails with `EXDEV` (verified in a privileged node:22 container); needs unprivileged user namespaces, like netguard's netns mode |
   | neither | — | nothing at the kernel; layers 1 and 2 stand, and the kickoff says `WARN: no kernel read-only mechanism on this host` |

   The guard has to be in front of the pane's shell, not of `pi`: Herdr
   starts `pi` from the pane however it likes and does not go through a
   `PATH` shim. A zsh reads `$ZDOTDIR/.zshenv` before anything else, so the
   workspace is created with `ZDOTDIR=<sandbox>/.zsh`, whose `.zshenv`
   re-runs the interactive shell under `fsguard.sh` and hands `ZDOTDIR` back
   to the user's own configuration. A bash has no such variable, so the
   workspace is also given `HOME=<sandbox>/.bash`: Herdr starts bash
   interactive and not as a login shell (measured with Herdr 0.9.1), and it
   reads `$HOME/.bashrc`; a login bash reads `.bash_profile`, which is the
   same file. Each hook puts `HOME` back first, re-runs the shell under
   `fsguard.sh`, and then reads the user's own configuration. Everything
   typed into that pane, `pi` included, then runs with `inputs/` read-only.
   A shell that is neither zsh nor bash ignores both hooks.

   Nothing is assumed: at session start every agent's harness tries to
   create a file under `inputs/` and records what stopped it as an
   `inputs_guard` trace line — `kernel` (EPERM), `mode` (EACCES, the
   permission bits alone) or `none`. The console shows this per pane.

`--inputs-bind` keeps the evidence where it is: `inputs/` becomes a link to
the source directory and the kernel guard holds the source itself read-only
in every pane — the same `--ro` rule, on the resolved path. There is no copy
and no pristine clone, so this needs a kernel guard (seatbelt, a Linux
namespace, or Landlock) and refuses without one; the write bits of the
source are left alone, since these are the operator's files. It is for the
evidence set that should not be copied to be guarded: 13.8 GB of images on
a Linux host, bound in a second.

`--inputs-enforce` chooses how much to insist:

| Value | Meaning |
| --- | --- |
| `auto` (default) | Kernel guard when the host has one; otherwise a `WARN` and layers 1–2. |
| `on` | Refuse to start (`BLOCKER`, exit 3) unless a kernel guard is available — and, once the panes are up, wait for every agent's own `inputs_guard` probe to say `kernel` before the first prompt is sent; a pane that measured anything else stops the swarm. An operator `--env SWARM_FSGUARD=…`, which would switch the hook off, is refused at kickoff. |
| `off` | Layers 1–2 only; no hook is written. |

## From the console

Name the evidence roots when starting the web app: `scripts/swarm.sh ui
--inputs-root /path/to/sets` (repeatable), or `SWARM_INPUTS_ROOT` with `:`
between several. Each directory directly under a root is a *set* the kickoff
form offers under **Read-only inputs**, with a file count, a size and a few
names, grouped by root when there is more than one; the form also has the
enforcement choice, and it shows every root the server is reading. A kickoff
names a set, never a path: the form sends `0:brief` (root 0, set `brief`; a
bare name still means root 0), the server resolves it under that root,
refuses a symlink or anything that resolves outside it, and passes the path
to `swarm.sh --inputs`. Without a root the form says so and prints the
command that names one.

The card also chooses how the evidence is attached: *copy* (the default, a
read-only copy under `inputs/`, with an optional size ceiling in MB), *bind
in place* (`--inputs-bind`, no copy, the source itself held read-only by the
kernel, refused on a host without one), or *disk image* (`--inputs-image`, a
dmg, iso or img inside the set, attached read-only; macOS). A **clean room**
picker names earlier runs whose directories every pane holds unreadable
(`--no-read`), the runs on the same evidence listed first. As with sets, the
form sends run ids and the server turns them into directories.

A root can also be added from the form, but only on a server started with
`--allow-inputs-root-from-ui`. Then `POST /api/inputs/roots {path}` with the
token adds an absolute, existing directory, kept in `inputs-roots.json`
under the runs directory so it survives a restart, and `DELETE
/api/inputs/roots/N` removes one that was added that way (a root named at
start cannot be removed from the form). The flag is off by default on
purpose: anyone on the LAN holding the token could otherwise expose any
directory on the machine, which is what the names-not-paths rule exists to
prevent. `GET /api/inputs` is open
like every other read on this app (the LAN can watch; the token gates what
starts, stops or changes a run), so set names and a few file names per set
are visible to the LAN: keep the root to what the LAN may know exists.

On a run, the header carries an **inputs read-only** chip with the guard
summary, and the **Files** tab opens with the inputs: source, every file with
its size, the guard measured in each pane, the writes that were caught and
healed, and the final check.

## What the agents see

- `SWARM.md` § Inputs (read-only): the rule and the file list.
- The system prompt: one line with the count, the size and what a write
  costs (`refused by the kernel` or `refused, or detected and undone`).
- The `inputs` tool: the manifest (path, size, short hash), where the copy
  came from, the guard requested, the guard the kickoff set up, and the guard
  measured in this pane. Present in every swarm; answers `inputs: false`
  when there are none.

## What this does not do

- It does not restrict **reading**. Agents can read anything the user can;
  `inputs/` is about not changing what they were given.
- A copy under `work/` is an ordinary work file: claimable, writable,
  restorable. That is the intended way to change an input.
- Layer 2 is a bracket around tool calls plus a sweep at turn ends (every
  15 s at most) and at
  `done`; between those moments a backgrounded process can have changed a
  file, and a peer reading it in that window reads the changed bytes. Layer
  3 closes the window where the host has it.
- Under a kernel guard the harness itself cannot heal (it shares the pane),
  and does not need to.

## Proof

`tests/inputs.test.sh` (kickoff behaviours and `fsguard.sh` on the host),
`tests/dry-run.test.ts` § read-only inputs (refusals, detection, healing),
`tests/ui-server.test.ts` (the library route, the kickoff, the view), and
the runs in [verified-runs.md](verified-runs.md).
