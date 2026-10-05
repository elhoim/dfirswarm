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
| Copy | `inputs/` — a copy with the evidence's links kept as the links they are, never followed: an extracted root's `etc/hosts -> /etc/hosts` stays a link to a path, and does not become this machine's own file. Only a link at the top of `--inputs` (the operator's, `ln -s /mnt/evidence/case.E01 ./`) is followed, to the file or directory it names. Links that lead out of the evidence are listed at kickoff. The copy is then checked against its source: first by name, kind and size (names merged on a case-insensitive volume, or a short read, stop the kickoff), then by content, each copied file's source read again and its SHA-256 compared with the manifest's (a progress line every 2 GiB on a large set). A mismatch, or a source that cannot be read again, stops the kickoff. `--no-verify-copy` keeps the first check only, and reads the evidence once instead of twice. `inputs.json` records which it was (`source_checked`: `{by: "content", files, mismatches, seconds}`, or the names-kinds-sizes form). |
| Lock | Every file `r--r--r--`, every directory `r-xr-xr-x`. |
| Clone | `.inputs-pristine/` — the same bytes once more (an APFS clone or a reflink where the filesystem has them, a copy elsewhere). The harness heals from it. |
| Manifest | `inputs.json` — the source path, when it was copied, every file with its size and its sha256, sha1 and md5 (from one read, to set beside an imager's acquisition hashes), every link with its target, every FIFO, socket or device by its kind, `source_checked`, and which guard the panes got. A name that is not UTF-8 (a Windows-1254 name from an archive, on ext4) is kept exactly as base64 in `path_b64` (`link_b64` for a link's target) beside a readable `path`, and every check compares names as those bytes. |
| Contract | `SWARM.md` gains an **Inputs (read-only)** section: the rule, the file list, what happens on a write. |
| Registry | `inputs: {source, files, bytes, enforce, guard}` on the run, so the console can show it (and `sets`, each with its own count, when there are several). |
| Pane hook | With a kernel guard available, `.zsh/.zshenv`, `.bash/.bashrc` + `.bash/.bash_profile` and `.fsguard/plan.txt`; the workspace gets `ZDOTDIR` pointing at the first, and `HOME` at `.bash/` when the account's login shell is bash (below). |

Limits: none by default, on size or on file count: evidence is as large as
the case is. `--inputs-max-mb N` and `--inputs-max-files N` (or
`SWARM_INPUTS_MAX_MB` and `SWARM_INPUTS_MAX_FILES` in the environment) are
opt-in limits an operator may set; a directory above either is refused
before anything is copied. What grows with the file count is the integrity
sweep, which fingerprints every input.

### Under `--isolation microvm`

No copy and no pristine clone: the evidence is used where it is, mounted
read-only and no-exec into every agent's VM, and the host refuses every
write through that mount whatever the guest does. The no-exec is a flag in
the guest's mount: each VM's probe reads it from the guest kernel's mount
table, and a VM whose evidence mount allows execution is refused. The
guest's root could remount it, so it guards against running evidence by
mistake, not against a root that means to. `inputs/` is a
link to it and `inputs.json` records `guard: "microvm"` and `held: "bind"`,
links inside the evidence recorded as links. A link that leads out of the
evidence is refused at kickoff, naming it, since no VM could follow it. When
the examiner's account can write the evidence (a file, or a directory whose
names can change, on a volume mounted read-write, by its permission bits as
they apply to this account; no ACL and no volume mounted inside the set is
read), the kickoff refuses it,
under every stop policy and at `start --check`: nothing on the host holds
evidence used in place, and a helper writing into a live run's evidence
folder is what the Breadcrumbs run's custody alert came from. Make it
read-only first (`chmod -R a-w`, or a read-only mount), or pass
`--inputs-copy`, the way to start a live run: the run gets its own
read-only copy (`held: "copy"`), held in each VM exactly like evidence in
place: `inputs/` and its pristine clone `.inputs-pristine/` are each their
own read-only, no-exec mount over the run's floor, and each VM's probe reads
both flags from the mount that holds the files (on the floor's share alone,
read-only but not no-exec, the probe refused every seat's VM; found by a
kickoff on 2026-10-05). The manifest's sha256 is anchored outside the
run at kickoff, and custody re-hashes the evidence in full at stop against it
(a custody that runs out of time says which files it did not re-read).
`--inputs-image` is macOS-only (`hdiutil`) in either mode: there is no Linux
path and no read-only virtio-blk attach to a VM yet.

## Several sets

A case can have more than one piece of evidence: a laptop and a phone, a
disk image and a memory image taken apart, the logs of three servers.
`--inputs` may be given once for each:

```
scripts/swarm.sh start … --inputs ~/cases/42/laptop --inputs ~/cases/42/phone
```

Each set lands at `inputs/<name>/`, `<name>` being its directory's name as
given (`inputs/laptop/`, `inputs/phone/`); a link names a set otherwise
(`ln -s /mnt/b/case case-b`, then `--inputs case-b` is `inputs/case-b/`).
One set is `inputs/` itself, exactly as before: the same paths, the same
manifest, nothing in it about sets.

Every other flag applies to every set: all are copied, or all held in place
(`--inputs-bind`, and a VM run's default), `--inputs-copy` copies all of
them, and `--no-verify-copy`, `--inputs-enforce` and `--inputs-hashes` hold
for all. The kickoff refuses, before anything is written: a directory given
twice, one set inside another (the same evidence twice), two sets that
would be one directory under `inputs/` (the same name, compared without
regard to case, as a case-insensitive volume compares it), and a name that
begins with a dot or is not UTF-8 on one line. `--inputs-image` stays one
image and is not combined with `--inputs`.

| | One set | Several sets |
| --- | --- | --- |
| Copied | `inputs/` is the copy; `.inputs-pristine/` its clone | `inputs/<name>/` each; `.inputs-pristine/<name>/` each; every set checked against its own source (a difference is named under its set) |
| Held in place | `inputs/` is a link to the source | `inputs/` is the run's own directory, read-only, holding a link per set at `inputs/<name>` |
| Ceilings | `--inputs-max-mb`, `--inputs-max-files` | the same ceilings, for the sets together |
| Kernel guard (host run) | one `--ro` rule on `inputs/` | the rule on `inputs/`, and one per set held in place; the guard recorded is the weakest any set got |
| Each VM | the source mounted read-only and no-exec where the link leads; a copy (`--inputs-copy`): `inputs/` and `.inputs-pristine/` each mounted so, over the run's floor | each set's source mounted so (a copy: `inputs/` and `.inputs-pristine/` whole, every set inside); a link from one set into another stays within the evidence |
| `inputs.json` | `source`, `files`, … | the same, with every set's files under `inputs/<name>/`, `source` naming every set's source (comma-separated, for a reader that shows one line), and `sets: [{name, path, source, files, bytes}]` in the order given |

A citation of an input names its set: `input:laptop/Users/…/NTUSER.DAT`
(the path under `inputs/`). An acquisition hash in `--inputs-hashes` is
matched by its path under `inputs/` (`laptop/disk.E01`) or by a name that is
unique across every set.

Every check of the evidence goes through a set's link only when the
manifest names that set: the agents' check and their bash watch, the pack's
`check_inputs`, each VM's probe (which counts every set's names and probes
each set's own mount), the job workers' mounts and host custody, which
re-hashes each file through its set's link. Any other link directly under
`inputs/` is a name of its own, found as an addition. The catalogue follows
links as it always did, so it reaches every set. A manifest written before
sets existed has no `sets`, and every one of these reads it as it always
did.

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
   around). A link planted inside is an addition: the manifest lists every
   link the evidence had, with its target, so any other is new. A changed, re-permissioned or
   deleted file is put back from `.inputs-pristine/` at a fresh inode, a
   planted file or link is removed, the trace gets an `inputs_violation` line
   naming the agent, the path and the tool it came through, and the board
   gets a `veto` post saying what was healed. A change nobody's tool call
   bracketed — a backgrounded process — is caught by the sweep that runs at
   turn ends (at most every 15 s per agent; a stat per file) and again inside
   `done`, which heals first and then records
   an `inputs_check` line: an `ok: false` there means a heal failed, not that
   nobody looked. A file the check reads again is held to the manifest's
   sha1 and md5 too; sha256 decides, and a file whose sha256 matches while
   another digest does not is listed as `digest_mismatch` in the `inputs`
   tool's answer, since the record around the bytes then disagrees with
   itself.
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
   to the user's own configuration. A bash has no such variable, so when the
   account's login shell is bash the workspace is also given
   `HOME=<sandbox>/.bash`: Herdr starts bash interactive and not as a login
   shell (measured with Herdr 0.9.1), and it reads `$HOME/.bashrc`; a login
   bash reads `.bash_profile`, which is the same file. Each hook puts the
   panes' `HOME` back first (an `--env HOME` if one was given, otherwise the
   kickoff's), re-runs the shell under `fsguard.sh`, and then reads the
   user's own configuration. Everything typed into that pane, `pi` included,
   then runs with `inputs/` read-only. `HOME` is moved for a bash account
   only: a shell that reads neither hook would keep it, and Pi would find no
   credentials there. Such a shell is refused at kickoff while the write
   guard is on or `--inputs-enforce on` is asked for, and warned about
   otherwise.

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

Several sets are chosen one at a time: the same picker adds a set, and each
chosen one is a chip beneath it that removes it again. A set whose name is
already chosen (the same name under another root) is not offered, since
both would be `inputs/<name>/`. The request's `inputs` is then a list of
set ids (`["0:laptop", "1:phone"]`, one `--inputs` each, in order); one set
is sent as it always was. A disk image is one set's, so it is offered only
while one set is chosen.

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
purpose: anyone who can reach the console and holds the token could
otherwise expose any directory on the machine, which is what the
names-not-paths rule exists to prevent. `GET /api/inputs` is open like
every other read on this app (whoever can reach it can watch; the token
gates what starts, stops or changes a run). The console binds `127.0.0.1`,
so by default that is this machine; started with `--host 0.0.0.0` it is the
LAN, and set names and a few file names per set are then visible to it:
keep the root to what the LAN may know exists.

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
`tests/inputs-copy.test.sh` (the copy and the manifest, one set and
several), `tests/microvm-flags.test.sh` (a VM run's evidence, sets
included), `tests/dry-run.test.ts` § read-only inputs (refusals, detection,
healing), `tests/custody.test.ts`, `tests/ui-server.test.ts` (the library
route, the kickoff, the view), and the runs in
[verified-runs.md](verified-runs.md).
