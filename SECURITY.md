# Security

DFIR Swarm runs model-written shell commands on your machine, on purpose.
Read this before you run it, and before you report something.

## Threat model, in one paragraph

A swarm is N Pi sessions with `bash`, `read`, `edit` and `write`, all with the
same isolated directory as their working directory. By default each agent is
root in its own microVM, and the boundary is the host side of every mount,
the VM's network policy and the hub's socket, not the agent's shell. What
that boundary protects: the host's files (a VM holds only what is mounted,
and the run is a read-only floor in it but for the seat's own directories),
the credentials (provider keys, subscription tokens and pack secrets never
enter a guest; msb swaps a placeholder for the value on the way to the
credential's own hosts), the evidence (read-only through a mount the host
enforces), and the harness's decisions (the finish line, the stop clock,
custody and the report are taken on the host). What it does not protect is
listed under Out of scope. In that mode a `bash` inside the VM is in scope
wherever it reaches past those
([ADR 0009](docs/adr/0009-agents-live-in-microvms.md), `docs/safety.md`).

With `--isolation host` the run is unisolated: every agent is a process on
this machine, and the harness enforces what it can. `edit`/`write` outside
the sandbox or without a lease are blocked; harness-owned files (`SWARM.md`,
`team.json`, `budget.json`, `names.json`, `done/`, `locks/`, `threads/`,
`traces/`, `history/`, `inbox/`, `tools/`, `inputs/`, `ledger/`, `catalog/`)
are refused as write targets; egress goes through a per-swarm allowlisting
proxy; every tool call is logged. What it cannot enforce is `bash`: a shell
command can read or write anything the user running the swarm can, and no
hook can stop it mid-command. The harness *detects* shell writes to leased
paths, snapshots them and announces them on the board, after the fact.

In either mode, **run swarms on a machine or account you are willing to
lose, with credentials you are willing to rotate.**

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
- A way to call a token-gated route (start, stop, reap, restore, save goal,
  the grant that opens an HTML artifact with its scripts) without the token,
  or a way for an agent's HTML artifact to run a script in the console
  without that grant.
- A way for a pane to make custody, the report or `stop` read or write
  through a link it planted, or to make custody's verdict say something
  other than what it checked.
- Secrets leaking into `traces/events.jsonl`, `budget.json`, the registry, or
  the web app's responses.
- Under `--isolation microvm`: anything an agent in its VM can do to the host
  or a peer — write outside its own directories (`work/<id>/`,
  `work/extracted/<id>/`, `work/quarantine/<id>/`, `tool-output/<id>/`, its
  session), read a host file or a credential, reach a host outside its
  allowlist, act through the hub as another seat or as the harness (the stop
  clock, the sentinel, a forge with forging off), make the hub follow a link,
  or hang or crash the hub or a custody check.
- Under `--isolation microvm`: a process outside a seat's VM that the hub
  serves as that seat without the seat's token, or a seat token that shows
  up in the trace, the registry, a VM record or a package.
- With `--model-gateway`: a VM that reaches a fronted provider without the
  gateway, a provider key that reaches a VM, a file or the trace, a seat
  whose token calls another seat's providers, a stopped seat's call that is
  forwarded, or a gateway route that reaches a host other than the
  provider's.
- The review, the package and purge: a way for an agent to write the
  examiner's review file (`runs/reviews/`), a package change that `verify`
  does not report, or a `purge` that deletes a held run or anything outside
  the run it names.
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
- Under `--isolation microvm`, what the ADR ("Limits that stay") and
  `docs/safety.md` list as the mode's stated limits, among them:
  - a spend report is the seat's own; the host enforces the wall clock by
    itself, and the caps only on what the seats report, except under
    `--model-gateway` for the providers it fronts, where the host measures
    the spend and refuses a call three minutes after a cap is crossed (so a
    run can overshoot a cap by what is spent in that grace);
  - every process in a VM speaks to the hub as that seat: a forged tool, a
    parser over hostile content, a binary extracted from the evidence and
    run by the guest's root; the seat token is in the guest's environment,
    and it keeps out only processes outside the VM;
  - the extension's checks inside a VM are advisory against the guest's
    root; only the hub, the mounts and msb enforce;
  - an allowed host is a way out: anything an agent can send to its model's
    host, a symbol server, or any host under an allowed suffix leaves, and a
    bound placeholder is usable at its host for whatever that credential may
    do there (an API key is not limited to inference; a pack's secret is
    usable by any process in the VM);
  - a local model's port, reached through the host gateway, is that server's
    whole API to every VM (Ollama's `/api/pull` and `/api/delete` included);
  - a real key that a provider echoes back in a response is not masked in
    the trace, and reaches the VM with or without the model gateway;
  - the model gateway, when on, holds the fronted providers' keys in its
    memory on the host;
  - `vm/<id>.json` is readable from every VM (it names secrets and hosts, no
    value);
  - msb's strict mode is off: a host-name rule admits what the name resolves
    to, whatever server name the connection then sends;
  - msb holds the credentials uncaged, and while a VM lives its secrets'
    values are in msb's own database on the host's disk
    (`~/.microsandbox/db`, made its user's alone at kickoff; a finish that
    removed VMs clears their leftover bytes when the host has `sqlite3`,
    and `stop` warns about any it could not clear);
  - msb swaps a placeholder for its value in request headers only: a
    placeholder in a URL query or a body goes out as the placeholder;
  - the hub runs as the examiner, and a guest's terminal output reaches the
    host's;
  - the examiner's browser is outside the VM allowlist: the console shows an
    agent's HTML artifact without scripts, but one the operator opens with
    **Open with scripts**, after its warning, or a file opened outside the
    console can reach the network;
  - the operator's record (`runs/operator-audit.jsonl`) and the examiner's
    review (`runs/reviews/`) are chained by hash, not signed: whoever can
    write them can rewrite them whole, and a trace line from a shell that is
    not the kickoff's is marked unverified;
  - a signed package proves which key signed its manifest, not whose key it
    is: that is the recipient's allowed-signers file;
  - `purge` deletes files the ordinary way, without overwriting the blocks
    the filesystem freed, and knows nothing of copies made elsewhere.
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
- Under `--isolation microvm`: use API keys and keep `--allow-oauth-in-vm`
  off; allow suffixes (`*.name`) only where the case needs one; keep the
  runs, with their `<sandbox>.vm-snapshots/`, out of synced folders and on an
  encrypted volume (the kickoff's `Disk:` line says which it is); and
  consider `--model-gateway`, which meters the fronted providers' spend on
  the host and refuses a stopped seat's calls there.
- Sign what you hand over (`swarm.sh package <id> --sign`), and give the
  recipient the allowed-signers line the command prints.
