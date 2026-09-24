# Agents live in microVMs, and the board has one writer on the host

With `--isolation microvm`, every agent is a Pi process inside its own
microVM, created by the kickoff and put away by `stop`. The board's files are
written by one process on the host, the hub, which each VM reaches over its
own vsock port. Host mode (`--isolation host`) stays the default and is
unchanged.

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
  is mounted read-only from where it is, with no copy. Everything is mounted
  at its host path, so no path is ever translated. The harness code
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
- **The hub answers only an agent's business.** The stop clock and the
  harness stop are not on the agent channel; a sentinel is written only when
  the operator's finish line passes on the host; a seat's spend report may
  only grow; every path is resolved on the host without following a link
  the agent planted. Spend is still what the seat reports — the wall clock
  and each VM's `maxDuration` are the brakes the host enforces by itself.
- **The harness owns the stop.** The hub enforces the wall clock and the caps
  from outside the VMs, writes the sentinel when the agents do not stop, and
  once it has stood for the grace period snapshots and stops the VMs. Each VM
  also has a hard `maxDuration`.
- **Custody is taken on the host after the run** (`scripts/custody.ts`): the
  evidence re-hashed in full, the sessions sealed, every kept output checked
  against the trace, every kept disk checked against its record.
- **Images come from the packs** (`images/recipe.py`), and a run records the
  digest it booted. Prebuilt images are published privately from the pro
  repository, never from this one: an image bundles separately licensed
  programs.

## Consequences

- Host mode is untouched: the board functions run locally whenever
  `SWARM_BOARD_SOCKET` is unset, and every host-mode suite runs as before.
- A VM run needs a host that can boot one, and says so before it writes
  anything. The droplet (2 vCPU, 4 GB) runs two agents at 1 vCPU / 1 GiB.
- The five-second visibility window is real and bounded; the settle window
  covers writes, not reads.
- The guest kernel is the agent's; the boundary is the host side of every
  share and of the network. A test (`tests/vm-integration.test.ts`) holds
  that on every pull request, on a KVM runner.

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
