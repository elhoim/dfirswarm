# Security

DFIR Swarm runs model-written shell commands on your machine, on purpose.
Read this before you run it, and before you report something.

## Threat model, in one paragraph

A swarm is N Pi sessions with `bash`, `read`, `edit` and `write`, all with the
same isolated directory as their working directory. The harness enforces what
it can: `edit`/`write` outside the sandbox or without a lease are blocked;
harness-owned files (`SWARM.md`, `team.json`, `budget.json`, `names.json`,
`done/`, `locks/`, `threads/`, `traces/`, `history/`, `inbox/`, `tools/`,
`inputs/`, `ledger/`, `catalog/`) are refused as write targets;
egress goes through a per-swarm allowlisting proxy; every tool call is logged.
What it cannot enforce is `bash`: a shell command can read or write anything
the user running the swarm can, and no hook can stop it mid-command. The
harness *detects* shell writes to leased paths, snapshots them and announces
them on the board — after the fact. **Run swarms on a machine or account you
are willing to lose, with credentials you are willing to rotate.**

With `--isolation microvm` the model is different: each agent is root in its
own microVM, and the boundary is the host side of every mount, the VM's
network policy and the hub's socket — not the agent's shell. In that mode a
`bash` inside the VM is in scope wherever it reaches past those
([ADR 0009](docs/adr/0009-agents-live-in-microvms.md), `docs/safety.md`).

## In scope

Please report these privately (see below):

- A way for an agent to write outside its sandbox, or to a harness-owned file,
  through `edit` or `write` (the guard is supposed to block both).
- A way for an agent to rewrite `SWARM.md`, the checks, or `budget.json` so
  that the run certifies itself or raises its own cap.
- A way to create or delete `done/SWARM_DONE` that the harness does not record.
- Egress that bypasses the netguard proxy from inside a pane when netguard is
  on (other than by `--no-netguard`, which is the documented opt-out).
- A path-traversal or symlink escape in the web app (`/api/swarms/:id/work/…`,
  `/api/goals/:name`, history restore, the contract route).
- A way to call a token-gated route (start, stop, reap, restore, save goal)
  without the token.
- Secrets leaking into `traces/events.jsonl`, `budget.json`, the registry, or
  the web app's responses.
- Under `--isolation microvm`: anything an agent in its VM can do to the host
  or a peer — write outside its own directories (`work/<id>/`,
  `work/extracted/<id>/`, `work/quarantine/<id>/`, `tool-output/<id>/`, its
  session), read a host file or a credential, reach a host outside its
  allowlist, act through the hub as another seat or as the harness (the stop
  clock, the sentinel, a forge with forging off), make the hub follow a link,
  or hang or crash the hub or a custody check.
- With `--allow-tool-forging` on: a way to put a script under `tools/`
  without `make_tool`, to run a tool whose bytes differ from its manifest,
  to replace a live author's tool as a peer, or to register a forged tool
  when forging is off.

## Out of scope

- Anything an agent does through `bash` inside the sandbox it was given. That
  is the documented limit of the harness, not a bug. The same goes for what a
  forged tool's script does when it runs: it is a `bash` with a schema on it.
- The web app being reachable from your LAN when you ask for it. It binds to
  `127.0.0.1` by default; `--host 0.0.0.0` opens it to a second machine, and
  then watching is open and spending needs the token. Do not expose it to the
  internet. Read "open" literally: without the token, a request on the LAN can
  fetch the goal document, the board, the whole trace, every revision of every
  `work/` file, any artifact, and the `swarm.sh` output of each start, stop and
  reap on `/api/jobs`. If the goal or the evidence names something you would
  not put on a shared screen, keep the default.
- Under `--isolation microvm`, what the ADR and `docs/safety.md` list as the
  mode's stated limits: a spend report is the seat's own, an allowed host is
  reachable for anything, a bound placeholder is usable at its host, msb holds
  the credentials uncaged, and a guest's terminal output reaches the host's.
- The behaviour, cost or output of the model you point Pi at.
- Vulnerabilities in Herdr, Pi or a model provider. Report those upstream.

## Reporting

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or email the maintainer, Halil
Öztürkci, at **halil@halilozturkci.com**. Include the swarm id, the
`traces/events.jsonl` lines around the problem, and the Pi and Herdr versions.
You will get an acknowledgement within a week. There is no bounty.

## Hardening checklist for operators

- Run on a disposable machine or VM; keep provider credentials in Pi's own
  store (`pi auth login`), never in the sandbox or the goal.
- Keep netguard on. Add hosts with `NETGUARD_ALLOW`, do not switch it off.
- Keep the cap tight (`--cap-usd 1` for a first run) and the wall clock short.
- Treat the console token like a password; it is printed once at startup.
- Read the goal you are about to run. The harness refuses one without a
  definition of done, but it does not judge what the checks do.
