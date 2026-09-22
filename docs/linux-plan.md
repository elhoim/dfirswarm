# Linux: what the sandbox has there, what it lacks, and what to build

Status: **all five phases shipped, 2026-09-21** — what each one became, and
where it left the plan, is in §6 under "What shipped". Written the same day
against `main` at `fd4ff67`, the day after run `s83fd` showed an agent
walking out of the macOS network guard with `env -u HTTP_PROXY`
([the account](use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md)).
Sections 1–5 and 8 are left as the analysis that was made before the code,
so the measurements can be read against what was built.
The question this answers: *is the sandbox macOS-only, and what does it take to
run the swarm on Linux with at least the guarantees it has today — and the
ones it cannot have on macOS?*

Every claim below is a file:line in this repository or a measurement. The
measurements were taken on a Linux kernel from this machine — Docker Desktop's
VM, `7.0.12-linuxkit`, `ubuntu:24.04` userland, as an unprivileged user —
and each one says so with `MEASURED`. Two things a container cannot measure
are marked `UNVERIFIED` and named in §8 rather than assumed.

The short answer: **the harness already runs on Linux, and its network guard
is stronger there than on macOS. Its write guard, its clean-room isolation and
its terminal-socket seal do not exist on Linux at all.** They fall away
silently — the record says so, the panes do not notice — and two things the
macOS design relies on are false on Linux: a pane's environment is private,
and a network namespace keeps a Unix socket out. Both are measured below.

---

## 1. Today, guard by guard

As shipped (§6, "What shipped"), measured in two Docker tiers by
`tests/linux/run.sh`: a host with user namespaces (`write_guard: linux`) and
a container without them (`write_guard: landlock`). CI runs one job per tier
(`ci.yml:16`, `:62`), and the guard suites no longer skip on Linux.

| Guard | macOS (seatbelt) | Linux today | Where |
| --- | --- | --- | --- |
| Evidence read-only (`--inputs`, `--inputs-bind`) | kernel | **kernel** — bind + `remount,ro` inside the namespace, or a Landlock `--ro` rule on the resolved path; `--inputs-bind` holds the operator's directory itself read-only | `fsguard.sh:401`, `landlock.py`, `swarm.sh:816` |
| Quarantine `noexec` | kernel | **kernel** — bind + `remount,noexec` in the namespace; the execute right withheld under Landlock | `fsguard.sh:401`, `landlock.py:92` |
| Egress allowlist (netguard) | proxy variables, **advisory** | **kernel** — `unshare -rn`, no route but the proxy's Unix socket | `netguard.sh:121` |
| Write allowlist (`--rw`) | kernel | **kernel** — Landlock inside the user namespace (`linux`), Landlock alone where namespaces are off (`landlock`), bubblewrap's read-only root when present (`mountns`) | `fsguard.sh:214`, `:461`, `:401` |
| Clean room (`--no-read`) | kernel | **kernel** — a tmpfs over the directory in the namespace; Landlock denies the reads where there is no namespace (names stay visible, contents do not); `no_read_applied: true` | `fsguard.sh:401`, `landlock.py:92`, `swarm.sh:2093` |
| Terminal socket seal (`--no-socket*`) | kernel | **kernel in the namespace** — `/dev/null` bound over the socket, a tmpfs over its directory (`herdr_socket: masked`); Landlock alone cannot mask a socket, and the record says `unenforced` | `fsguard.sh:401`, `swarm.sh:2130`, `:2235` |
| Pi's `extensions/` | read-only inside the writable agent dir | **read-only** in the namespace modes; **writable** under Landlock alone, which cannot carve a read-only directory out of a writable one, and the record says so (`pi_extensions`) | `swarm.sh:2081` |
| Evidence on an image (`--inputs-image`) | `hdiutil -readonly` | **refused** — a loop mount needs root; `--inputs-bind` is the answer on Linux | `swarm.sh:706` |
| Trace attribution | token in the pane's environment, private on macOS (`attribution: token`) | **process ancestry** — a gate reads the sender's pid from `SO_PEERCRED`, walks `/proc` up to the pane, forwards with that pane's token and a key the collector requires (`attribution: ancestry`; `token-exposed` if the gate is down) | `trace-gate.py:82`, `:121`, `trace-collector.mjs:215`, `swarm.sh:2043` |

What a host could enforce is measured once at kickoff (`swarm.sh:623`) and
carried in the record as `host_caps`, `write_guard`, `no_read_applied`,
`herdr_socket`, `pi_extensions` and `attribution`; the report's custody
section and `SWARM.md`'s "This host" section print it, so a run on a
namespace-less host says what it lacked rather than claiming the seal. The
pane hook finds zsh with `command -v zsh` (`swarm.sh:942`) and the preflight
refuses a host without it.

### 1.1 Where this started

The table this plan was written against, kept as the baseline §2 to §6
argue from. The line numbers are the tree's at the time.

| Guard | macOS (seatbelt) | Linux today | Where |
| --- | --- | --- | --- |
| Evidence read-only (`--inputs`) | kernel | **kernel** — `unshare -rm`, bind + `remount,ro` | `fsguard.sh:306` |
| Quarantine `noexec` | kernel | **kernel** — bind + `remount,noexec` | `fsguard.sh:306` |
| Egress allowlist (netguard) | proxy variables, **advisory** | **kernel** — `unshare -rn`, no route but the proxy's Unix socket | `netguard.sh:119` |
| Write allowlist (`--rw`) | kernel | **none** — `write_guard_mode="none"` | `swarm.sh:1868` |
| Clean room (`--no-read`) | kernel | **none** — a `WARN`, then nothing | `swarm.sh:1895` |
| Terminal socket seal (`--no-socket*`) | kernel | **none** — `herdr_socket: unenforced` | `swarm.sh:1897` |
| Evidence on an image (`--inputs-image`) | `hdiutil -readonly` | **refused** — `BLOCKER`, needs root for a loop mount | `swarm.sh:658` |
| Trace attribution | token in the pane's environment, private on macOS | token in the environment, **readable by every pane** (§3.1) | `protocol.ts:2237` |

The fsguard `mountns` branch honours exactly two lists, `FSGUARD_RO_LIST` and
`FSGUARD_NOEXEC_LIST` (`fsguard.sh:312-313`); `--rw`, `--no-read`,
`--no-socket` and `--no-socket-tree` are parsed, canonicalised, and then not
used on that path. The header comments say "seatbelt only" and `swarm.sh` gates
on `write_guard_mode == "seatbelt"` before adding any of them, so nothing lies
— the run record on a Linux host reads `write_guard: none`,
`no_read_applied: false`, `herdr_socket: unenforced`. It just does not guard.

The rest of the harness is portable already. The shell scripts carry both
forms wherever the two userlands differ — `stat -c %s || stat -f %z`
(`evidence-catalog.sh:59`, `reap.sh:70`, `swarm.sh:3442`), `sha256sum ||
shasum -a 256` (`swarm.sh:3655`), a `timeout` fallback of its own
(`swarm.sh:364`). One hard dependency is wrong for Linux: the pane hook
`exec`s `/bin/zsh` by absolute path (`swarm.sh:837`); on most distributions
zsh is `/usr/bin/zsh` and not installed by default. CI already runs on
`ubuntu-latest` (`ci.yml:17`), which is why the three guard suites —
`write-guard`, `herdr-seal`, `evidence-image` — skip themselves there: on the
platform CI runs, those guards have no coverage because they have no
implementation.

## 2. What Linux gives that macOS cannot

All `MEASURED`, unprivileged user, `ubuntu:24.04` on kernel 7.0.

**Egress that holds.** `unshare -rn` gives the pane a network namespace with
only `lo`. Inside it, unsetting `HTTP_PROXY` changes nothing: there is no
route to fall back to. The only way out is the Unix socket to a proxy in the
host namespace, which is the allowlist. Under bubblewrap with
`--unshare-net`, a TCP connect to `1.1.1.1:443` returned `Network is
unreachable`. This is the guard that `s83fd` did not have.

**Read-only that survives a second namespace.** A bind mount remounted `ro` in
a user namespace is *locked*: from inside a nested `unshare -rm`, `mount -o
remount,bind,rw` on it → `DENIED`. `chmod 666` on the evidence → `DENIED`
(macOS reports success and changes nothing; Linux refuses). `write` → `DENIED`.
The evidence bytes afterwards: unchanged.

**A process tree of one.** `unshare -rmpf` plus a fresh `mount -t proc proc
/proc` leaves 12 pids visible — the pane's own — and a sibling pane's
`/proc/<pid>/environ` is `unreachable`. This closes §3.1 outright.

**An allowlist with no namespaces at all.** Landlock, ABI 8 on this kernel,
from Python's stdlib `ctypes` (no package). A ruleset granting read+execute
beneath `/` and everything beneath the sandbox, then `restrict_self`:

```
write outside the sandbox               DENIED
write inside the sandbox                ALLOWED
read the evidence                       ALLOWED
pip-style write under ~/.local          DENIED
```

It works under Docker's **default** seccomp profile, where `unshare` and
`bwrap` both fail with `Operation not permitted` — which is the case for
every run inside an ordinary container, and for an Ubuntu 24.04 host with
AppArmor's user-namespace restriction on (§3.6). Landlock also denies one
directory by granting its siblings: `~/secret/flags.md` → `DENIED`, `ls
~/secret` → `DENIED`, `~/ev/f` and `/etc/hostname` → `ALLOWED`. That is
`--no-read`, mechanically, with an enumeration. And it scopes TCP by port:
connect to the one allowed port → `ALLOWED`, to `1.1.1.1:443` → `DENIED`.

**Evidence without a 13.8 GB copy.** A bind mount of the source directory,
remounted `ro`, into `inputs/` is the same kernel guarantee `--inputs` gives
today with none of the copy. macOS has no equivalent short of `hdiutil`.

## 3. What Linux breaks that macOS had

### 3.1 The token is not a secret on Linux — `MEASURED`

`trace-collector.mjs:24` and `protocol.ts:2237` both rest on "on macOS no
other process can read a process's environment (measured)". On Linux:

```
grep SWARM_TRACE_TOKEN= /proc/<sibling pid>/environ   → READABLE (token leaks)
ps eww -p <sibling pid>                               → shows it
```

Same uid is enough. Every pane runs as the same uid. So on Linux any agent
can take a peer's token from `/proc` and write lines to the collector as that
peer — which `attribute()` would accept as verified. The claim is platform-
specific and the comment does not say so.

Two fixes, and they stack. A pid namespace per pane (§2) makes the other
panes' `/proc` entries not exist. And attribution can stop depending on a
secret at all: a Unix socket tells its server the connecting **pid** through
`SO_PEERCRED`, the kernel reports it, nothing in the pane chooses it. The
collector walks `/proc/<pid>/status` `PPid` upward until it reaches a pane's
root process, which the kickoff recorded from outside (Herdr knows the pid of
the shell it spawned). A process cannot re-parent itself into another pane's
tree. This is *stronger* than the token, and it is Linux-only; the run record
should say which one attributed the run (`attribution: token | ancestry`).

### 3.2 A network namespace does not keep a Unix socket out — `MEASURED`

```
python3 connect(~/sockdir/ctl.sock) inside unshare -rn   → REACHABLE
```

Filesystem sockets are files; a network namespace is about routes. Herdr's
socket, the collector's and the broker's are all reachable from inside
netguard's namespace. Good for the two of ours; bad for Herdr's, which is the
F7 escape (`sandbox-plan.md`). The seal on Linux is a mount: `tmpfs` over the
socket's directory in the pane's mount namespace →
`DENIED: No such file or directory`. Landlock does **not** do this
(`connect` to a Unix socket with no write grant on its directory → `ALLOWED`,
measured), so on a host without user namespaces the seal is unavailable and
the record must say so.

### 3.3 A pane can overlay what it sees — `MEASURED`

From a nested `unshare -rm`, `mount --bind /tmp/fake ~/ev` over the locked
read-only evidence succeeds: `cat ~/ev/f` inside prints `planted`. The bytes
on disk are untouched and `inputs_check` runs outside the pane, so this is the
same class as `hdiutil detach` on macOS: substitution of what the pane sees,
not of the evidence, caught by the sweep. bubblewrap closes it with
`--disable-userns` (sets `user.max_user_namespaces=1` inside the sandbox);
inside Docker that switch fails because `/proc/sys` is read-only there — on a
host it is not (`UNVERIFIED` here, documented by bubblewrap).

### 3.4 No `hdiutil`

`--inputs-image` refuses on Linux (`swarm.sh:658`). A loop mount needs root.
The unprivileged routes are FUSE — `ewfmount` for E01 sets, `squashfuse` /
`fuse2fs` for other images, all mountable inside a user+mount namespace on
kernels ≥ 4.18 — or the bind mount of §2, which gives the same kernel
read-only without a copy and covers the case the flag was built for.

### 3.5 `/bin/zsh`

`swarm.sh:837`. Not there on Debian, Ubuntu, Fedora, Arch by default. Resolve
with `command -v zsh` at kickoff and refuse with a `BLOCKER` that names the
package, the way `herdr`, `pi` and `jq` are checked (`swarm.sh:2159`).

### 3.6 Where user namespaces are switched off — partly `UNVERIFIED`

Everything in §2 that starts with `unshare` needs unprivileged user
namespaces. Three places turn them off:

- **Docker's default seccomp profile.** `MEASURED`: `unshare -rm` →
  `Operation not permitted`, `bwrap` → "No permissions to create new
  namespace". A run inside an ordinary container gets Landlock and nothing
  else. `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`
  restores them, and so does rootless podman with `--userns=keep-id`.
- **Ubuntu 24.04's AppArmor restriction**,
  `kernel.apparmor_restrict_unprivileged_userns=1` by default: an unconfined
  program calling `unshare` gets `EPERM`; bubblewrap ships an AppArmor profile
  that is allowed to. `UNVERIFIED` here — the container's kernel is not
  Ubuntu's — and the single most likely reason a fresh Ubuntu box "has no
  guard" on the first run.
- **`user.max_user_namespaces=0`** on hardened hosts.

The preflight has to test the capability, not the distribution: run
`unshare -rm true`, `unshare -rn true`, `unshare -rmpf true` and a Landlock
`create_ruleset` probe, and record the four answers.

### 3.7 bubblewrap inside a container

`bwrap --proc /proc` fails inside Docker (`Can't mount proc on /newroot/proc:
Operation not permitted`): the container's `/proc` has paths masked over it,
and the kernel refuses a fresh procfs in a less-privileged namespace that
would reveal them. On a host there is nothing masked. Without `--proc`, the
rest of the invocation works: `MEASURED`, `bwrap --ro-bind / / --bind
$sandbox $sandbox --dev /dev --tmpfs /tmp --tmpfs <masked dir> --unshare-user
--unshare-net --unshare-pid` → write outside `DENIED`, sandbox `OK`, `chmod`
on evidence `DENIED`, masked directory empty, nested user namespace `DENIED`,
network `unreachable`, Python with tempfile and sqlite3 `OK`.

## 4. Two mechanisms, one policy

Linux offers two ways to say what a process may touch, and they are not
rivals. The plan uses both, in layers, and records which layers applied.

| | **Namespaces** (bubblewrap / `unshare`) | **Landlock** (LSM, kernel ≥ 5.13; ≥ 6.7 for TCP) |
| --- | --- | --- |
| Needs unprivileged user namespaces | yes | **no** |
| Works under Docker's default seccomp | no | **yes** (`MEASURED`) |
| Works under Ubuntu's AppArmor restriction | only via bwrap's profile | **yes** |
| Write allowlist (`--rw`) | `--ro-bind / /` + `--bind` | grant beneath the sandbox only |
| Read-only evidence (`--ro`) | bind + `remount,ro`, locked | grant read, withhold write |
| `--noexec` | `remount,noexec` | withhold `EXECUTE` |
| Clean room (`--no-read`) | `--tmpfs` over the directory | withhold the directory, grant its siblings (enumeration) |
| Terminal socket seal (`--no-socket*`) | `--tmpfs` over the socket directory | **cannot** (`MEASURED`) |
| Egress | `--unshare-net` + proxy socket, fail-closed | TCP by **port**, not host — proxy port only, as a second fence |
| Environment privacy (§3.1) | `--unshare-pid` + fresh `/proc` | no |
| Undo from inside | no (locked mounts; `--disable-userns` for the rest) | no (inherited, irrevocable) |
| What it costs | bubblewrap ≥ 0.9, or `util-linux` alone for a subset | python3 stdlib, already a harness dependency |

The rule that falls out: **Landlock is the write guard on every Linux host,
because it is the one that is always there; namespaces are the masks, the
network and the pid tree, wherever user namespaces exist.** A host with both
gets the full macOS set plus a fail-closed network and a private `/proc`. A
host with Landlock alone gets the write guard, the clean room by enumeration,
and read-only evidence — and a record that says the socket seal and the
network guard were not enforced, in the same fields `s83fd` already fills.

## 5. What the record must say

`write_guard` gains two values beside `seatbelt` and `none`: `landlock`, and
`landlock+ns`. `herdr_socket` gains `masked` (namespace) beside `sealed`
(seatbelt). `no_read_applied` stays boolean but the report names the
mechanism. `netguard_mode` already distinguishes `netns` from `proxy-only`
(`swarm.sh:2016`); it stays. A new field, `attribution`, is `token` on macOS
and `ancestry` on Linux, and the custody section prints it — because on a
Linux host attributed by token, "who wrote this line" is a claim any pane
could have made.

## 6. The plan

Five phases, each with the test that fails without it and the record field it
sets. Phases L1 and L2 are independent of each other; L3–L5 build on them.

**L0 — Portability and honesty (a day).**
`/bin/zsh` → `command -v zsh`, with a `BLOCKER` naming the package.
`--inputs-image` on Linux: keep the refusal, point at `--inputs --bind` (L3).
`protocol.ts:2237` and `trace-collector.mjs:24`: say the privacy claim is
macOS-measured and false on Linux. The report's `writeGuardLine` and
`herdrSocketLine` learn the new values from §5. Preflight (§3.6): probe the
four capabilities, print them at kickoff, write them to the registry as
`host_caps`. CI: on `ubuntu-latest`, set `kernel.apparmor_restrict_unprivileged_userns=0`
in the job so the namespace suites can run at all, and stop the three guard
suites from skipping silently — a skip prints the capability it lacked.

**L1 — Landlock write guard (two to three days).**
`scripts/landlock.py`: stdlib `ctypes`, no package; takes the same argument
vocabulary as `fsguard.sh` (`--rw`, `--ro`, `--noexec`, `--no-read`), builds
one ruleset, `restrict_self`, `exec`s the command. `fsguard.sh --mode
landlock` calls it; `auto` prefers it on Linux whenever the ABI probe succeeds.
`--no-read` is implemented by enumeration: grant every ancestor's other
children read, withhold the denied subtree — the walk is a dozen lines and the
denied path is one directory. `--noexec` withholds `EXECUTE` beneath the
quarantine. Tests: the Linux half of `write-guard.test.sh` runs under
`--mode landlock` and asserts the same fifteen things, plus "a nested
`unshare` cannot lift it" and "`pip install --user` outside the sandbox is
refused". Record: `write_guard: landlock`.

**L2 — Namespace layer (two to three days).**
`fsguard.sh --mode mountns` gains `--rw` (bubblewrap when present: `--ro-bind
/ /`, `--bind` for the sandbox and Pi's agent dir, `--dev /dev`, `--tmpfs
/tmp`; `unshare` + `pivot_root` when it is not), `--no-read` (`--tmpfs` over
the directory), `--no-socket-tree` (`--tmpfs` over the socket directory —
this is the Linux seal), `--unshare-pid` with a fresh `/proc`, and
`--disable-userns`. netguard's `unshare -rn` folds into the same invocation
(`--unshare-net`), so one namespace set is created once, not two nested ones
with two uid maps. Tests: `herdr-seal.test.sh` runs its deny half under the
mask; a new `pidns.test.sh` asserts a sibling's `/proc/<pid>/environ` is
unreachable; `write-guard.test.sh` asserts the overlay of §3.3 is refused.
Record: `write_guard: landlock+ns`, `herdr_socket: masked`.

**L3 — Evidence without copying (a day).**
`--inputs DIR --bind`: on Linux, bind the source read-only into `inputs/`
instead of copying; the manifest records `guard: bind` and the source path;
`inputs_check` fingerprints the bind. `--inputs-image` via FUSE is a later
step and needs `ewfmount` on the host, which is a case tool and therefore the
agents' or the pro package's business, not the harness's.

**L4 — Attribution by ancestry (two days).**
The collector reads `SO_PEERCRED` on every connection; the kickoff records
each pane's root pid from Herdr (`pane.get`) into `team.json`; a line is
attributed to the pane whose root is an ancestor of the sender. Tokens stay
as the macOS path and as a second signal on Linux; a line whose token and
ancestry disagree is `disputed`. Record: `attribution: ancestry`. Test: a
process in pane A sending with pane B's token is written as A.

**L5 — Contract and docs (half a day).**
`SWARM.md` states which guards are enforced on this host and by what, from
`host_caps` — the `--no-pypi` lesson applied generally: the contract must not
promise a wall the host cannot build. `docs/safety.md` gets the Linux table
from §1 as it will then stand. `sandbox-plan.md` §9 closes "the write guard on
Linux".

Order of value: L0 is cheap and stops the silent fall-away; L1 is the one
that makes a Linux run *guarded*; L2 is what makes it *better than macOS*.
Together, L1+L2 on a Linux host close every finding `s83fd` produced.

### What shipped

Tested in Docker on the kernel above, in two tiers that both have to pass:
`--security-opt seccomp=unconfined` (user namespaces available: `write_guard:
linux`) and Docker's default profile (no namespaces: `write_guard:
landlock`). `tests/linux/run.sh` runs both; CI has one job per tier. macOS is
regression-free (seatbelt is still chosen there). Where the code differs from
the plan above, the plan was wrong and the difference is a measurement:

- **L0** as planned: `command -v zsh`, `python3` in the preflight,
  `host_caps` in the record and printed at kickoff (`swarm.sh host_caps()`),
  the report's `writeGuardLine` / `herdrSocketLine` / `piExtensionsLine`, CI
  with `kernel.apparmor_restrict_unprivileged_userns=0` and a second job with
  `user.max_user_namespaces=0`. `--inputs-image` still refuses on Linux and
  points at `--inputs-bind`.
- **L1** `scripts/landlock.py`, stdlib `ctypes`, ABI 8 measured. Two things
  the plan did not know: a rule on a *regular file* may carry only the
  file rights (`EXECUTE|WRITE_FILE|READ_FILE|TRUNCATE|IOCTL_DEV`) or the
  kernel answers `EINVAL`; and because Landlock only grants, a `--ro` inside
  a `--rw` is *carved* — every sibling along the path gets the region's
  rights, the ancestors get `READ_DIR` only, so nothing new can be created
  in a carved ancestor. The kickoff therefore creates every directory a run
  needs before the panes start, and on a Landlock-only host Pi's agent
  directory is left uncarved (`pi_extensions: writable`, said in the
  record) rather than made unable to take a token refresh.
- **L2** bubblewrap when present, `unshare` otherwise (`fsguard.sh
  ns_exec`): `--ro-bind / /`, the run and Pi's directory bound back, `--dev
  /dev`, `--tmpfs` over `--no-read` and `--no-socket-tree` paths, `/dev/null`
  bound over a `--no-socket` file. **No private `/tmp`** — the plan's `--tmpfs
  /tmp` let a pane "write outside the sandbox" into a tmpfs nobody could
  tell from a real escape; `/tmp` stays the host's, read-only under the
  read-only root. The pid namespace is conditional: bwrap's `--proc` and
  `--disable-userns` both fail inside Docker (masked `/proc`, read-only
  `/proc/sys`), so `bwrap_proc_supported()` probes and the record's
  `host_caps.pidns` says. The record value is `write_guard: linux` (both
  layers) or `landlock` (one), not `landlock+ns`; `herdr_socket: masked`
  where the mask could be applied, `unenforced` where it could not.
- **L3** `--inputs DIR --inputs-bind`: not a bind mount into `inputs/` but a
  symlink to the source and the same `--ro` rule on the *resolved* path —
  fsguard canonicalises, so seatbelt, the namespace and Landlock all hold
  the source itself read-only. The manifest hashes through the link and
  says `held: bind`; there is no pristine clone, the operator's write bits
  are left alone, and the flag refuses on a host with no kernel guard. Works
  on macOS too, which the plan had not asked for.
- **L4** the collector does not read `SO_PEERCRED` itself (Node has no
  `getsockopt`); `scripts/trace-gate.py` stands in front of it on Linux,
  reads the sender's pid from the kernel, walks `/proc/<pid>/status` up to
  the *topmost* process carrying a token this run minted — the pane — and
  forwards with that token. No pane root pids in `team.json`, no `disputed`:
  ancestry decides, the body's claim is kept as `claimed_agent` as before.
  Two things the plan missed. A pane with the collector's socket still in
  reach could bypass the gate with a token read from `/proc`, so the gate
  and the collector share a key on stdin (`{tokens, gate}`) that no pane
  can read, and the collector counts a token only beside it; the socket is
  masked as well where the host can. And an orphan — a grandchild whose
  parent exited — is reparented *above* the pane on a host without a pid
  namespace, so the walk would find only the token it chose to carry:
  `landlock.py --subreaper` makes the pane's root a child subreaper
  (`PR_SET_CHILD_SUBREAPER`) and the orphan stays inside the tree. Both are
  measured in `tests/trace-gate.test.sh`, including the control without a
  subreaper. Record: `attribution: ancestry` (gate up), `token` (macOS),
  `token-exposed` (Linux, gate down). The sidecars send through the gate.
- **L5** `SWARM.md` gains "## This host", rendered from `host_caps`, the
  write-guard mode and the attribution: what the kernel holds, what decides
  who wrote a line, and what this host cannot do (no user namespace, no pid
  namespace, advisory egress on macOS). `docs/safety.md` and
  `docs/inputs.md` say the same; `sandbox-plan.md` §9 closes the item.

### What a real server then added

The five phases above were built and tested in Docker. The first run on an
actual Ubuntu server — [run 4 of the Web Server
case](use-cases/dfir-web-server-case/run-4-linux.md) — found nine more
defects, two of them security defects, none of which a container could show:

- The pane's shell is the guard's only foothold, and **Herdr starts the login
  shell from the account database** (and passes its own `SHELL` to panes).
  With bash there the guard reached nothing while the record claimed it had.
  The preflight refuses it now, and the record carries
  `write_guard_measured` from the panes' own probes.
- **`nohup` is not enough on a headless host.** The kickoff's daemons kept
  their controlling terminal and died with the tmux window the kickoff ran
  in, taking the egress guard with them. `setsid`, via `detach_exec`, and the
  pid it records has to be the daemon's own — backgrounding a shell function
  forks a subshell, and for a while the pid files named that.
- **A carved path that is a symlink escaped the carve** (`--inputs-bind`),
  so the bound evidence was writable under Landlock. The sibling walk
  canonicalises now.
- **Landlock refuses with EACCES, not EPERM**, so the pane's own probe read a
  working guard as "permission bits only". It reads the mode it was started
  under now.
- **bubblewrap always forks**, so the terminal saw `bwrap` rather than a
  shell and Herdr refused to start an agent in the pane. `fsguard --in-place`
  uses `unshare` without `--fork` and keeps the pane one process; the pid
  namespace is what that costs.

[linux-server.md](linux-server.md) is the operator's side of all of it.

Still true from §8: the two `UNVERIFIED` items stand — a real Ubuntu with
AppArmor's restriction on, and a kernel older than 5.13 — CI covers the
first by sysctl on `ubuntu-latest`, nothing covers the second, and
`landlock.py` exits 3 there so the record says `none`.

## 7. Dependencies

The harness's own, and nothing else — the agents install what a case needs,
inside the sandbox, through the allowlist.

| Package | For | Optional? |
| --- | --- | --- |
| `util-linux` (`unshare`) | every namespace | needed for L2 |
| `bubblewrap` ≥ 0.9 | the namespace layer in one call, with `--disable-userns` | L2 falls back to `unshare` without it |
| `iproute2` (`ip`) | bringing `lo` up inside the network namespace | no — `netguard.sh:114` has a python3 fallback |
| `python3` | Landlock helper, contract rendering, catalog | already required |
| `zsh` | the pane hook | already required, now checked |
| `jq`, Node ≥ 22.6, Herdr, Pi | already required | — |

No forensic tooling. The `--toolbox` check reports what the host lacks; it is
not a requirement and must not become one.

## 8. Measured, and not

Every `MEASURED` above comes from two scripts run as an unprivileged user in
`ubuntu:24.04` on Docker Desktop's `7.0.12-linuxkit` kernel, once with
seccomp and AppArmor unconfined (user namespaces available) and once under the
default profile (not available). The raw lines:

```
unshare -rm / -rn / -rmpf as unprivileged              OK / OK / OK
ro bind: write / chmod / nested remount rw / overlay    DENIED / DENIED / DENIED / planted
/proc/<pid>/environ of a sibling, same uid              READABLE
inside unshare -rmpf + fresh /proc                      pids-visible:12  sibling-environ:unreachable
unix socket from inside unshare -rn                     REACHABLE
same, tmpfs masked over the socket dir                  DENIED: No such file or directory
bwrap ro-root + rw sandbox + masks + no net + pid ns    outside:DENIED sandbox:OK chmod-ev:DENIED
                                                        secret-entries:0 nested-userns:DENIED net:unreachable
Landlock ABI                                            8
  write outside / inside the sandbox                    DENIED / ALLOWED
  read one ungranted dir / list it / read a sibling     DENIED / DENIED / ALLOWED
  connect to a unix socket, no write grant on its dir   ALLOWED   (so: no socket seal from Landlock)
  TCP to the allowed port / to 1.1.1.1:443              ALLOWED / DENIED
under Docker's default seccomp: unshare / bwrap         EPERM / EPERM
under Docker's default seccomp: Landlock ABI            8
```

Not measured here, and named as such:

- **Ubuntu 24.04's AppArmor user-namespace restriction** on a real host
  (§3.6). The container's kernel is not Ubuntu's.
- **`bwrap --proc /proc` and `--disable-userns` on a host.** Both fail inside
  Docker for reasons that are Docker's (masked `/proc`, read-only
  `/proc/sys`); both are documented to work on a host.
- **Landlock TCP to the allowed port on another host.** The probe timed out;
  by design the rule is port-scoped, so the answer should be `ALLOWED`, and
  that is exactly why the port rule is a second fence and not the allowlist.
- **Herdr and Pi on Linux at all**, end to end. Herdr's source has a
  `platform/linux.rs` and its installer targets Linux; Pi is Node. A first
  full run on a Linux host is the real test, and L0 is what makes that run
  say the truth about itself.
