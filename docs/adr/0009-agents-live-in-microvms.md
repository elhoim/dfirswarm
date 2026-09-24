# Agents live in microVMs, and the board has one writer on the host

With `--isolation microvm`, every agent is a Pi process inside its own
microVM, created by the kickoff and put away by `stop`. The board's files are
written by one process on the host, the hub, which each VM reaches over its
own vsock port. Host mode (`--isolation host`) stays the default and keeps
its design: panes on the host, the board functions run locally, the host
guards. It did change where this work fixed things for both modes: the
console binds 127.0.0.1, the finish line is read from the registry only,
the trace masks the harness's tokens, `stop` takes custody, and more; the
CHANGELOG lists each under "Changed for host runs".

## Context

On the host, a pane is a process of the examiner's own uid. Everything that
holds it — the seatbelt or Landlock profile, the tool guard, netguard — is a
rule the process runs under, and `docs/sandbox-plan.md` §2 lists what that
leaves: the egress guard is advisory on macOS, an agent's token is readable by
its peers on Linux, the terminal's socket had to be denied by hand, and every
new capability is another rule to write for one OS and then the other.

A VM changes the question from "what may this process touch" to "what is in
this machine", and the answer is short: whatever the harness mounts, and the
hosts the harness allows. We measured microsandbox 0.7.2 (libkrun; macOS on
Apple silicon and Linux with KVM, the same CLI and SDK on both) before
building on it, on an M3 Max and on the DigitalOcean droplet with nested KVM:

- A read-only virtio-fs share is enforced on the host side. Guest root can
  flip its own kernel's mount flag (`mount -o remount,rw` succeeds), and every
  write after it is still refused, and the host's files do not change.
- A read-only share **inside** a writable one is not a boundary: guest root
  unmounted it and wrote through the parent (a forged trace line;
  `verifyEventChain` caught it, `broken_at 32, reason edited`).
- A writable share **between** VMs keeps none of the promises the board is
  built on (`spikes/microvm-smoke/shared-fs.sh`): an O_EXCL-guarded counter
  lost 494 of 600 increments, flock 377, O_APPEND lost 495 of 600 lines with 15
  torn, a reader missed a renamed file 999 times in 1,000, and inotify never
  fires for another VM's write. passthroughfs caches entries and attributes
  for five seconds (CachePolicy::Auto), not configurable in 0.7.2.
- Egress is open by default; `--no-net` plus domain rules is a real
  allowlist (a denied name gets a local NXDOMAIN, a hard-coded address has no
  route). A secret reaches the guest as a placeholder, and msb swaps in the
  value over TLS only to the hosts it is bound to.
- A VM boots in 0.3–1.3 s. virtio-fs reads at 2.5 GiB/s on the Mac (the host
  does 7) and 325 MiB/s on the droplet.

## Decision

- **One microVM per agent, Pi inside it.** The harness creates the VMs at
  kickoff (`scripts/vm.ts`, through the microsandbox SDK: structured mounts,
  rules and secrets, nothing on argv), runs each agent's Pi in its Herdr pane
  with `msb exec`, and at stop snapshots each disk with msb's integrity
  record, then removes the VM. Agents never make VMs.
- **A read-only floor with writable holes, each one seat's own.** The whole
  run is mounted read-only; the agent's own `work/<id>/`,
  `work/extracted/<id>/` and `work/quarantine/<id>/` (the last two no-exec),
  its own `tool-output/<id>/` and its own Pi session are mounted writable on
  top. Nothing writable is shared between VMs: the shared part of `work/`
  (`work/report.md`, `work/timeline.md`) is written by the hub through
  `publish_file`, from the agent's own directory, claimed and recorded. A
  writable `work/` shared by every VM kept none of the promises below and
  let any seat rewrite any other's findings without a record. The evidence
  is mounted read-only from where it is, with no copy: the host side of that
  read-only share is the one layer, and `--inputs-copy` adds a read-only copy
  in the run for evidence the examiner's own account can write. Everything is
  mounted at its host path, so no path is ever translated. The harness code
  (extensions, scripts, prompts, packs) is mounted read-only; the repository
  is not, because `runs/registry.json` and `docs/use-cases/` would come with
  it; a `--compact-prompt-file` is copied into the run rather than mounted
  with its directory. `--allow-install` installs into the VM's own disk,
  never a shared prefix.
- **The board has one writer: the hub** (`scripts/vm-hub.ts`). An agent's
  board calls go to it over one held connection (`extensions/board.ts`, the
  protocol's own function names), and it runs the same `protocol.ts` against
  the same files on the host. **Who is asking is the channel**: each VM's
  vsock port reaches exactly one socket, and every function that acts as
  someone is given that socket's agent. The trace goes through the hub to the
  same collector, with the channel's token, and the collector now stamps
  `recv_ts` by the host's clock.
- **A claim waits out the cache.** A claim on a file another agent wrote in
  the last six seconds is granted when that window has passed, so no VM
  appends at a size that is five seconds old. Reads of a peer's file are
  eventually current (five seconds), and the contract says so to the agents.
- **No credential enters a VM.** Pi on the host resolves each one (`pi auth
  print-api-key`, `pi auth print-bearer-token --min-expiry`, which refreshes
  a subscription for the length of the run) and msb holds it; the guest's Pi
  has a placeholder shaped the way Pi reads that credential, and so do a
  provider's env-block or header credentials and a pack's secrets. Each
  seat's VM holds only its own model's and the summary model's. A guest's
  token never refreshes, and the refresh endpoint is never bound. A
  subscription's placeholder is still the operator's account at the
  inference host, so a subscription provider needs `--allow-oauth-in-vm`.
  A credential is bound to its provider's hosts: msb terminates TLS on every
  port one travels on, no TLS bypass covers a secret's host, and a
  placeholder aimed anywhere else is stopped and logged (`block-and-log`),
  which custody reads. A provider whose host is not known is refused at
  kickoff (`--provider-host` names it); one that signs requests with its
  secret on the client (Bedrock, Vertex) cannot run in a VM at all.
- **The hub answers only an agent's business.** The stop clock and the
  harness stop are not on the agent channel; a `done` that would write the
  sentinel is refused unless the operator's finish line passes when the hub
  re-runs it on the host, with two exceptions: a reason that starts
  `ABANDONED: ` ends the run without the checks (the reason says so on the
  sentinel), and a seat leaving on its own cap (`agent_cap`) writes no
  sentinel and is not checked. A finish line the hub cannot run at all lets
  the `done` through unchecked, as it does on the host (`docs/protocol.md`).
  A seat's spend report may only grow; every path is resolved on the host
  without following a link the agent planted. Spend is still what the seat
  reports — the wall clock and each VM's `maxDuration` are the brakes the
  host enforces by itself.
- **The hub never opens a file under a seat's own directory.** Those are
  the only directories a running seat can rearrange, and a directory
  swapped for a link between the hub's checks and its open read a host file
  (measured: 140 of 39,385 racing reads before this rule; on Linux the open
  is also checked against `/proc/self/fd`, macOS has no such name). A seat
  sends the bytes of its own file with the call — a revision (kept whole up
  to 32 MiB, by its hash past that), a publish (up to 32 MiB), the disk side
  of a diff (up to 16 MiB) — and restores its own file in its own VM, checked
  against the hash the hub recorded. A peer's directory is refused for
  claims, writes, restores, records and publishes, compared without regard
  to case. A forged tool runs in a VM only as the bytes the hub says were
  sealed.
- **The hub bounds each seat.** At most 16 connections and 160 MB buffered
  per seat; 64 calls running and 192 queued; posts and claims at 40 in a
  burst and one every two seconds after, ledger records at 200 and five a
  second; a refusal repeated within a minute is counted, not written again.
  A call a seat sends again after a dropped link carries the same request id
  and gets the first run's answer. A seat's usage report carries only a
  budget row's fields; its model is the kickoff's.
- **The harness owns the stop.** The hub keeps the wall clock on its own
  clock, and applies the caps (the swarm's, each seat's, each model's) to the
  spend each seat reports about itself. It writes the sentinel when the
  agents do not stop, and once that has stood for the grace period it
  snapshots and stops the VMs. Each VM also has a hard `maxDuration` (the
  wall clock and half an hour).
- **Custody is taken on the host after the run** (`scripts/custody.ts`): the
  evidence re-hashed in full (a custody that runs out of time says which
  files it did not re-read), the sessions sealed, every kept output checked
  against the trace, every kept disk checked against its record.
- **Images come from the packs** (`images/recipe.py`), and a run records the
  digest it booted. Prebuilt images are published privately from the pro
  repository, never from this one: an image bundles separately licensed
  programs.

- **One image, by digest, fitted to the packs.** The kickoff resolves the
  image's tag once (pulling it before the run's clock when the host lacks
  it) and every VM must boot that digest. Each VM's probe looks for the
  programs the run's packs require; one missing stops the kickoff unless the
  agents may install. An image built from another version of a pack is said
  and recorded in `vm/<id>.json`, not refused. At stop each VM lists what it
  holds that its image did not; that list is measured inside the guest, by
  its root, and the kept disk is the authority.
- **The harness is frozen per run.** The extensions, scripts and prompts a VM
  sees are a copy taken at kickoff and mounted where the checkout is, so an
  edit or a `git pull` mid-run does not reach agents that have not loaded
  them yet. The hub runs from a second copy taken at the same time, and so
  do the VM finish and the custody it starts; the operator's own commands
  (`swarm.sh`, `stop`, the idle watchdog) run from the checkout.
- **A host run gets a stop from outside its panes too.** The idle watchdog,
  which runs for the length of every run outside the panes, claims the stop
  clock past a cap or the wall clock when no pane has, and writes the
  sentinel as the harness past the grace period: the hub's backstop, for
  runs that have no hub.

## Consequences

- Host mode keeps its design; the board functions run locally whenever
  `SWARM_BOARD_SOCKET` is unset. It did change where the work fixed things
  for both modes (the CHANGELOG lists them under "Changed for host runs"),
  and every host-mode suite runs.
- A VM run needs a host that can boot one, and says so before it writes
  anything (a `--no-start` prepared run boots nothing and is not probed);
  N VMs that would not fit the host's memory are refused. The
  droplet (2 vCPU, 4 GB) runs two agents at 1 vCPU / 1 GiB, which is the
  default on a host under 8 GiB.
- The five-second visibility window is real and bounded; the settle window
  covers writes, not reads.
- The guest kernel is the agent's; the boundary is the host side of every
  share and of the network. What that means, measured: guest root can flip a
  read-only share's flag, and the host still refuses the write; it can
  unmount its own holes and even the floor, and what is then under those
  paths is its own disk, never the host's (the host's trace and floor are
  unchanged). The no-exec on `work/extracted/` and `work/quarantine/` is a
  mount flag in the guest: both are mounted whole, read-only and no-exec,
  with the seat's own corner writable and no-exec on top, so neither its own
  carved material nor a peer's runs by mistake. It does not stop a root that
  means to run it. Nothing the harness decides is read inside a VM: the
  finish line, custody and the report run on the host.
- The hub is one process on the host. A keeper (`scripts/hub-supervise.sh`)
  brings it back from the state it keeps (`hub-input.json`, the stop clock)
  until the run's stop, and the idle watchdog does too while it runs. An
  agent whose hub stays unreachable for four minutes is stopped by its own
  extension.
- `tests/vm-integration.test.ts` holds all of this on every pull request, on
  a KVM runner, including one run end to end: Pi in its VM with the harness
  extension, a scripted model on the host, a post through the hub, and the
  evidence refused by the kernel. The test builds that run's VM itself; no
  test boots a run through `swarm.sh start`.

## Limits that stay

- A guest's terminal output reaches the host's terminal through Herdr, so an
  escape sequence an agent prints is interpreted there.
- msb's supervisor on the host holds every credential of the run in memory;
  a compromise of the host process is a compromise of the keys.
- msb also writes each VM's configuration, its secret values included, to
  its own SQLite database on the host (`~/.microsandbox/db`, measured on
  Linux with msb 0.7.2), and a removed VM's rows stay in the file's free
  pages and write-ahead log until SQLite reuses them. The kickoff makes
  `~/.microsandbox` its user's alone (0700), and a finish or reap that
  removed VMs rewrites the database from its live rows (`VACUUM` between
  two checkpoints, `scrubMsbDatabase`). While a VM lives its keys are on the
  host's disk in that file; a host with no `sqlite3` keeps the removed
  VMs' bytes, and `stop` says so. Blocks the filesystem freed are not
  overwritten.
- An allowed host is a channel out: anything an agent can send to its
  model's host, to a symbol server or to a blob store it may reach, leaves.
  The allowlist bounds where, not what.
- Spend in a VM run is what each seat reports; the wall clock and each VM's
  `maxDuration` are the brakes the host enforces by itself.
- Who is asking is the channel, not the process: every process inside a VM
  speaks to the hub as that seat. A forged tool, a parser running over
  hostile content, or a binary carved from the evidence and run by the
  guest's root can post, publish, record and call `done` as the seat.
- The extension inside a VM is the agent's own code under the guest's root.
  Its tool refusals, claim-before-write, the self-compaction lock and the
  per-seat cap steer are advisory there; what holds is what the hub, the
  mounts and msb enforce.
- The trace masks the harness's own tokens, and in a VM it never sees a
  provider's real key, only placeholders. A real key a provider echoes back
  in a response is not masked in the trace.
- `vm/<id>.json`, the record of each VM, is on the run's floor and readable
  from every VM. It names each secret and its hosts and holds no value.
- The hub runs on the host as the examiner, with no cage of its own: a path
  it resolves wrongly is a host path. Its own checks on each path (inside the
  run, no link an agent planted) are what stand there.
- A seat's writable holes are host directories with no quota: a seat can
  fill the host's disk.
- Liveness is the seat's own report: a VM that keeps its hub link and says
  "working" is never nudged or reaped. The wall clock bounds it.
- A local model's port, reached through msb's host gateway, is that
  server's whole API to every VM, not only inference: Ollama's `/api/pull`,
  `/api/create` and `/api/delete` included.
- msb's strict mode is not enabled: a host-name rule admits the addresses
  that name resolves to, and msb does not require the connection's own TLS
  server name or HTTP `Host` to be that name. Its DNS rebinding protection
  is left at the SDK's default (on).
- A client with its own trust store fails on a connection msb intercepts:
  Chromium's NSS store, Java's keystore.
- Deferred: `--inputs-image` attaches a disk image with macOS's `hdiutil`
  only; there is no Linux path and no read-only virtio-blk attach to a VM
  yet, and on Linux the kickoff refuses it (`--inputs DIR` instead).
- Deferred: image signatures and an SBOM. A run records and checks the
  digest it booted; nothing verifies who built that image.

## Open decisions

For the project owner; nothing in the code decides them yet.

- Whether `--isolation microvm` becomes the default, and on what evidence
  (for example the KVM job green over a number of pull requests and one real
  case run end to end in VMs).
- Whether host mode is frozen (labelled unisolated, fixes only) or removed
  once VM mode is the default, and what code goes with it: the host guards,
  the second spill location, the direct board path.
- A bare-metal Linux server with KVM for real cases. The droplet runs VMs
  through nested KVM and fits two agents.

## Alternatives considered

- **Pi on the host, tools in a VM.** Proposed first and rejected by the
  operator: the agent itself is the thing to contain, not only its commands.
- **One VM for the whole team.** Keeps the board's filesystem promises, but
  gives every agent every other agent's files and processes, which is the
  host-mode problem again inside a box.
- **Share the board over virtio-fs and hope.** Measured above; it loses
  posts.
- **exe.dev, E2B/Firecracker, containers.** exe.dev is closed and has no
  documented egress allowlist; Firecracker has no virtio-fs, so a triage
  folder would have to be repacked into a block image; a container's root
  remounts a `:ro` bind writable (`docs/sandbox-plan.md` §7).
