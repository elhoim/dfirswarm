# No MCP, and no container by default

Two things a reader will look for and not find. Both are refused on the same
grounds: each one would take away a guard this project's claims rest on.

> **Amended by [ADR 0009](0009-agents-live-in-microvms.md) (2026-09-24).** An
> isolation now exists that is not a container, and it is the default:
> `--isolation microvm` runs each agent in a microVM whose guards are the host's (read-only mounts
> enforced on the host side, a deny-by-default network policy). Two claims
> below change for that mode: a refused connection is not on the run's log
> (msb enforces the policy and the report says so rather than counting), and
> the images do ship — built from the packs, published privately, recorded by
> digest. The condition this ADR sets, that the guard is measured in the
> pane, is kept for host mode; in VM mode the kickoff's probe measures it in
> each VM and a real-VM test holds it in CI.

## Context

The harness makes two enforcement claims that are not marketing. Every
outbound byte a swarm sends is on the log, because `netguard` puts the panes
behind an allowlisting proxy and refuses everything else. And the evidence
under `inputs/` is read-only at the kernel, because `fsguard` runs each pane
under a macOS seatbelt profile or a Linux mount namespace, and the kickoff
*measures* the result per pane rather than assuming it — `--inputs-enforce on`
stops the swarm before its first prompt if any pane failed to measure one.

Both are checkable. `docs/inputs.md` says how, and `swarm.sh netcheck` and the
`inputs_guard` trace event are how a run proves it.

## Decision

**No Model Context Protocol server, client or transport.**

[ADR 0004](0004-forged-tools-are-subprocesses-behind-a-flag.md) already decides
that agent-written code runs as a subprocess inside the sandbox and never in
the harness process. An MCP server is the same question with the network added:
a tool whose implementation lives somewhere this harness does not control and
cannot measure.

The specific breakage is the egress claim. `netguard` is opt-out but it is the
default, and its allowlist is per-host. A remote MCP endpoint is another host
the operator has to allow, and once allowed, every call through it is one
line in the proxy log and an opaque payload — the harness can say a connection
happened and cannot say what crossed it. For a tool whose output ends up in a
forensic report, "something went to a third party and we logged the hostname"
is not a chain of custody.

A local MCP server is no better: it is a process outside the seatbelt profile
reading files the panes are forbidden to write, with no manifest, no hash and
no line in the trace. Forged tools exist precisely so that agent-authored
capability arrives with a name, a schema, a script sealed by sha256 and an
entry in the trace naming its author.

**No Docker, and no container in the kickoff path.**

A naive `docker run` trades away *both* guards.

Docker's default seccomp profile blocks `unshare`, which is exactly the call
`fsguard.sh` needs to build the mount namespace that makes `inputs/` read-only
at the kernel on Linux. Under that profile the guard degrades to `detect +
heal`: the harness still notices a write and still restores the file from the
pristine copy, but the kernel is no longer refusing it. `netguard`'s network
namespace has the same problem from the same cause. So the two things a
container would be adopted for — isolation and repeatability — arrive by
removing the isolation this project actually enforces.

This is not a reason containers can never work. It is a reason they cannot be
adopted casually. If it is ever done, it needs a custom seccomp profile that
permits the two calls, and a CI test that starts a swarm inside the container
and asserts every pane measured `enforced: "kernel"` and that `netcheck`
refuses a host outside the allowlist. **Without that test it does not ship**,
because the failure is silent: everything still runs, and the guarantees are
quietly gone.

## Consequences

- A capability that needs a third-party service is written as a forged tool
  or a library tool, runs in the sandbox, and reaches the network through
  `netguard` with its host on the allowlist, or it is not added.
- The install is a git clone, Node, and whatever the toolbox preset asks for.
  `scripts/toolbox.sh` reports what is missing and how to install it, and a
  run can start without any of it.
- Reproducibility is addressed by the dossier — `inputs.json`, `toolbox.json`,
  `team.json`, `budget.json`, `netguard.allow` and `MANIFEST.txt` say exactly
  what was read, what was installed, who ran and what was allowed out — rather
  than by shipping an image.

Two related refusals, on the same grounds and not worth their own documents:
**no voice dictation**, which contradicts the egress claim the moment audio
leaves the machine; and **no share links**, which either do not work or push
an operator to expose a console with twenty-two open read routes to the
internet. The answer to "send this to somebody" is `swarm.sh package`: files,
with hashes.
