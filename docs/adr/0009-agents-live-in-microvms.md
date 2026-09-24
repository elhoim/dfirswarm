# Agents live in microVMs, and the board has one writer on the host

Every agent is a Pi process inside its own microVM, created by the kickoff
and put away by `stop`: `--isolation microvm`, the default since 2026-09-24.
The board's files are written by one process on the host, the hub, which
each VM reaches over its own vsock port. Host mode (`--isolation host`) is
kept as the opt-in, unisolated mode, with its design: panes on the host, the
board functions run locally, the host guards. It did change where this work
fixed things for both modes: the console binds 127.0.0.1, the finish line is
read from the registry only, the trace masks the harness's tokens, `stop`
takes custody, and more; the CHANGELOG lists each under "Changed for host
runs".

Status: accepted. The default was decided on 2026-09-24 (see "Decided"
below).

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
  which custody reads. msb swaps a placeholder for its value in request
  headers only (the SDK's default, which the harness keeps): a placeholder
  in a URL query or a request body goes out as the placeholder, to its own
  host too. A provider whose host is not known is refused at
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
- **The hub bounds each seat.** At most 16 connections per seat, and 160 MB
  held for it at once: the bytes of lines not yet whole, of lines waiting
  their turn and of calls queued or running (their arguments stay in memory
  until they answer); past it the seat's connections are paused until its
  calls drain. A line carries at most 64 MB (a file's bytes travel in the
  call), and a call that carries no file at most 8 MB. 64 calls running and
  192 queued; posts and claims at 40 in a burst and one every two seconds
  after, ledger records at 200 and five a second, `done` at three and one a
  minute after (each may run the operator's finish line on the host, and
  dones that arrive together share one run). How often `wait` polls is the
  hub's. A `state` report is one of four states with at most 200 characters
  of detail and no terminal control characters, and Herdr is told at most
  one report per seat every quarter second. A refusal repeated within a
  minute is counted, not written again. A call a seat sends again after a
  dropped link carries the same request id and gets the first run's answer.
  A seat's usage report carries only a budget row's fields; its model is the
  kickoff's.
- **The hubs live under the harness's home**, `~/.dfirswarm/hubs`
  (`SWARM_HUBS_DIR` moves it): one directory per user, 0700, refused when it
  is a link or not the user's own, not under the caller's `$TMPDIR` (a stop
  from another shell found no hub there) nor in a `/tmp` every user shares.
  A reboot does not clear it, so a `stop` after a crash finds the hub's
  state and its spill. A Unix socket path may be 103 bytes (104 on macOS
  with the NUL; msb also refuses a longer one): the kickoff measures the
  longest socket path the run's hub would bind and refuses the run past it,
  before anything starts.
- **The harness owns the stop.** The hub keeps the wall clock on its own
  clock, and applies the caps (the swarm's, each seat's, each model's) to the
  spend each seat reports about itself. It writes the sentinel when the
  agents do not stop, and once that has stood for the grace period it
  snapshots and stops the VMs. Each VM also has a hard `maxDuration` (the
  wall clock and half an hour).
- **Custody is taken on the host after the run** (`scripts/custody.ts`): the
  evidence re-hashed in full (a custody that runs out of time says which
  files it did not re-read), the sessions sealed, every kept output checked
  against the trace, every kept disk checked against its record. It reads
  and writes nothing through a link: the previous verdict is set aside
  before anything is checked, and every file it writes goes to a fresh file
  renamed into place. Ended by its deadline, a signal or an error, it writes
  what it found and names what it never reached, so `custody.json` is this
  custody's verdict, partial or whole, or none. Its sha256 is added to the
  anchor outside the run, and the report, the summary and the console say
  whether the `custody.json` they read matches it. The hub's own custody
  at a run's finish keeps the operator's bound (`--custody-timeout`).
- **Time is UTC by construction.** The agents and the run's own processes
  run with `TZ=UTC`, so a tool's local time and a zone-less time mean one
  instant on every host; the registry records the host's own zone and,
  where the host can say, whether its clock was synced (`host_clock`). A
  ledger event time must carry its zone (`Z` or an offset); one without is
  refused rather than read in the host's zone, and the text as written is
  kept (`ts_raw`) beside the UTC time.
- **The operator is on the record too.** Each command that starts, stops,
  reaps, speaks into, exports or reports on a run is a line in
  `runs/operator-audit.jsonl`, chained by hash, with the OS user and host;
  a `start`, `stop`, `reap` or `say` is on the live run's trace as well
  (`operator_action`). The run records what
  produced it (`provenance`: the harness commit and local changes, Node,
  Pi, msb, the image digest).
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
  do the VM finish and the custody it starts; that copy holds its own msb
  and SDK, so an `npm ci` mid-run does not change the binary that puts the
  VMs away (the rest of `node_modules` is linked from the checkout). The
  operator's own commands (`swarm.sh`, `stop`, the keeper, the idle
  watchdog) run from the checkout.
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
  until the run's stop, and the run's trace collector too, which in a VM run
  is the trace's only door (`collector_restarted`); it gives up after
  twenty crashes in a row and says so, and the idle watchdog restarts a hub
  only while no keeper is running and none has given up. An agent whose hub
  stays unreachable for four minutes is stopped by its own extension.
- `tests/vm-integration.test.ts` holds the parts of this that need a real
  VM on every pull request, on a KVM runner, including one run end to end:
  Pi in its VM with the harness extension, a scripted model on the host, a
  post through the hub, and the evidence refused by the kernel. The test builds that run's VM itself; no
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
  VMs' bytes, and `stop` says so from each removed VM's record, whoever
  removed it. Blocks the filesystem freed are not overwritten.
- An allowed host is a channel out: anything an agent can send to its
  model's host, to a symbol server or to a blob store it may reach, leaves.
  The allowlist bounds where, not what.
- Spend in a VM run is what each seat reports; the wall clock and each VM's
  `maxDuration` are the brakes the host enforces by itself.
- Who is asking is the channel, not the process: every process inside a VM
  speaks to the hub as that seat. A forged tool, a parser running over
  hostile content, or a binary carved from the evidence and run by the
  guest's root can post, publish, record and call `done` as the seat. The
  harness code in a VM is the guest's too: a harness post it sends reaches
  peers as `from: "system via <seat>"`, the seat's word and not the
  harness's.
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
- The examiner's browser is a way out the VM allowlist never sees. The
  console shows an agent's HTML artifact without scripts: with them, a page
  could navigate itself and carry what it holds to any host, from the
  examiner's machine. **Open with scripts** runs one file's scripts after a
  warning that says so, through a one-time grant bound to the file's hash,
  and the opening is on the run's trace (`artifact_scripts`); from then on
  that view is outside the allowlist. A file the examiner opens outside the
  console is outside that rule.
- The operator's record says who typed a command only as the OS says it:
  a line on the trace from a shell that is not the kickoff's carries no
  token and is marked unverified, and `runs/operator-audit.jsonl` is chained
  but not signed, so whoever can write it can rewrite it whole.
- `host_clock.synced` is `null` on macOS, which has no unprivileged way to
  say whether the clock is synced.
- The evidence copy is checked against its source by name, kind and size,
  not by content: the manifest hashes the copy, and a source that changed
  under the copy with its size unchanged is not caught there.
- A client with its own trust store fails on a connection msb intercepts:
  Chromium's NSS store, Java's keystore.
- Deferred: `--inputs-image` attaches a disk image with macOS's `hdiutil`
  only; there is no Linux path and no read-only virtio-blk attach to a VM
  yet, and on Linux the kickoff refuses it (`--inputs DIR` instead).
- Deferred: image signatures and an SBOM. A run records and checks the
  digest it booted; nothing verifies who built that image.

## Decided

- **The default is `--isolation microvm`** (2026-09-24). A run is in
  microVMs unless `--isolation host` or `SWARM_ISOLATION=host` says
  otherwise; the console's form defaults to it too and always names the
  isolation it chose in the command it runs. A host that cannot boot the
  VMs (an Intel Mac, Linux without KVM or glibc, no msb, an image that is
  not there and cannot be pulled, VMs that do not fit) is refused before
  anything is written, with what it lacks, how to fix it and `--isolation
  host` as the unisolated way on. The kickoff never falls back to host
  processes on its own. A host guard's flag (`--no-write-guard`,
  `--no-seal-herdr`, `--inputs-enforce`, `--key-from-env`,
  `--probe-violation`) without `--isolation` is refused with the hint to
  name host. A registry record with no isolation is a run from before the
  default changed, and is shown as a host run.
- **Host mode stays** (2026-09-24), neither frozen nor removed: supported as
  the opt-in, unisolated mode. What stays true of it: every agent is a Pi
  process on this machine, held by the write guard, the tool guard, netguard,
  the trace gate and the nudge broker where the host can enforce them, and
  by nothing else; reads are open by design; on macOS egress is advisory;
  the record and the report say which guard held. The kickoff and the
  console label it unisolated wherever it is chosen.

## Open decisions

For the project owner; nothing in the code decides them yet.

- A bare-metal Linux server with KVM for real cases. The droplet runs VMs
  through nested KVM and fits two agents.
- Whether a copied `--inputs` is also re-hashed from its source, which
  doubles the reads of a large case, or stays checked by name, kind and
  size.
- Whether a run started as root is refused rather than warned about.
- Whether the keeper and the idle watchdog run from the frozen copy as the
  hub does.

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
