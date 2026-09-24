# Data protection

Evidence usually holds personal data: names, messages, locations, health or
financial records of people who are not party to the case. This page says
where a run sends that data, where it keeps it, and what the harness leaves
to the operator. It describes the harness; what the law requires of a given
case (under the GDPR or any other law) is the operator's to
establish, and nothing here settles it.

## What leaves the machine, and to whom

- **The model provider of each seat.** An agent's model sees what the agent
  reads: the contract (`SWARM.md`, the goal and the catalog's index in it),
  the board, and the output of every tool it runs, file contents included.
  That is evidence content, sent to the provider's hosts over the provider's
  API. A long output is delivered in part, with the whole kept on disk and
  named, and the agent can read the rest.
- **The summary model.** Self-compaction (on unless `--no-self-compact`)
  hands an agent's context to a model to summarise: the agent's own, or the
  one `--compact-model` names. That provider receives the whole context.
- **Every other allowed host.** netguard's list (host runs) and each VM's
  allowlist (`--isolation microvm`) name where traffic may go: the model
  hosts, `--allow-host` entries such as a symbol server, and the package
  index under `--allow-install`. Anything an agent can send to an allowed
  host can leave, evidence included ([safety.md](safety.md)).
- **With `--model-gateway`,** a fronted provider's calls leave through one
  process on the host rather than from each VM; what the provider receives
  is the same. The gateway writes no request or response body: its log
  (`traces/model-gateway.jsonl`) holds seats, models, statuses, token
  counts, costs and byte counts.
- **The operator's `--notify` command** receives each event's details: the
  run id, states, counts, and on `evidence_changed` the names of the
  evidence files that changed, went missing or appeared. No evidence
  content. Where that command sends them is the operator's choice.
- **Nothing to the harness's authors.** The harness sends no telemetry. Pi's
  own startup calls to `pi.dev` are not on netguard's list or a VM's
  allowlist and are refused; on a host run with `--no-netguard` they go
  out. Pulling an image or installing a pack reaches its registry and
  carries no case data.

The report names each seat's model and the hosts it was served from, and
the summary model with them, so the record of a run says who received its
content. `--local-only` keeps every model on this machine or this network
and narrows netguard to those endpoints; the evidence then reaches no cloud
model. [Credentials and teams](credentials-and-teams.md) covers local
models.

## What stays on the machine, and where

- **The run directory** (under `runs/` in the checkout unless `SWARM_RUNS_DIR`
  or `--sandbox` says otherwise): a copied `--inputs` with its pristine
  clone, `work/` with `work/extracted/` and `work/quarantine/`,
  `tool-output/` (every tool's whole output), `.pi-sessions/` (every agent's
  whole conversation with its model), the trace, the board, the ledger and
  `catalog/`. All of it can hold evidence content.
- **Beside the run directory:** `<sandbox>.custody-anchor.json`, and under
  `--isolation microvm` each VM's kept disk and logs in
  `<sandbox>.vm-snapshots/` (a link to `--vm-snapshot-dir` when that is
  given). A kept disk holds whatever the agent left in its VM.
- **The package** (`swarm.sh package <id>` → `<sandbox>/package/`): the
  report, the summary, everything under `work/` except `work/extracted/` and
  `work/quarantine/`, the ledger, the trace and the board, `court-set.json`
  and this run's lines of the operator's record. It is what gets handed
  over, and it carries evidence content too. `--sign` adds the examiner's
  signature and public key.
- **Exports** (`swarm.sh export`, under `<sandbox>/exports/` by default):
  the ledger as CSV, values in full.
- **Who ran it.** `runs/operator-audit.jsonl`, beside the registry, has a
  line for each `start`, `stop`, `reap`, `say`, `package`, `report`,
  `tools`, `review`, `export`, `hold`, `release`, `purge` and `verify`: the
  time, the examiner's OS user name and host, and the arguments. The
  examiner's review (`runs/reviews/<id>.jsonl`) holds the examiner's name
  and notes on each entry. The trace carries the same for a live run (`operator_action`,
  and `artifact_scripts` with the console client's address), so the
  package carries it too. The registry records the host's time zone
  (`host_clock`) and what produced the run (`provenance`). These name the
  examiners, not the case's subjects, and are personal data all the same.
- **Credentials:** provider logins in Pi's own store (`~/.pi/agent/`), pack
  secrets in `~/.dfirswarm/secrets/<id>.env` (mode 0600). Under
  `--isolation microvm`, msb also keeps a live VM's configuration, the
  secrets' values included, in its database (`~/.microsandbox/db`); the
  kickoff makes `~/.microsandbox` its user's alone, a finish or reap that
  removed VMs clears their leftover bytes when the host has `sqlite3`, and
  `stop` warns about any it could not clear.
- **The console** binds `127.0.0.1`. Started with `--host 0.0.0.0`, anyone who
  can reach it can read the board, the trace and every `work/` file
  ([SECURITY.md](../SECURITY.md)).

The harness deletes none of this on its own. `swarm.sh purge <id> --yes`
deletes a finished run's directory, its kept VM disks and its hub
directory when the operator asks, keeps the anchor and the review (hashes,
verdicts and notes, not material), and leaves a destruction record on the
operator's record; a held run (`swarm.sh hold`) is refused. Purge removes
files the ordinary way and knows nothing of copies elsewhere: a package
handed on, a synced folder, a backup. The kickoff records whether the
volume that holds the runs is encrypted at rest (`disk_encryption`) and
warns when it is not. A run directory inside a synced folder
(Dropbox, iCloud Drive, OneDrive, Google Drive) is uploaded by that folder's
client. The kickoff refuses to put a copy of the evidence or the VMs' kept
disks in a folder it recognises as synced unless `--allow-synced-folder`
(or a `.dfirswarm-allow-synced` file the operator placed in that folder)
says they may go, and warns about a run directory there for what the agents
derive.

## What the operator decides

- **Whether the evidence may be processed this way at all**, and on what
  basis: who the controller is, and what the engagement or the law allows.
- **Which providers may receive it.** Each provider's terms for API data:
  whether prompts are retained or used for training, where they are
  processed, and whether a data processing agreement covers the case. A
  transfer to a provider abroad has its own conditions under the GDPR and
  similar laws. Where no cloud provider is acceptable, run `--local-only`.
- **How much evidence to hand the run.** `--inputs DIR` hands the run what
  is in `DIR`; give it what the question needs rather than the whole
  acquisition when the rest is not needed.
- **Who can read the runs:** the account on the host, anyone who can reach
  the console, anyone with the synced folder or the backup the runs land in.
- **How long each run, its snapshots and its packages are kept**, and when
  they are destroyed, under the case's retention rules and any legal hold
  ([safety.md](safety.md), "What a run leaves on disk"). Deleting a run
  means the run directory, `<sandbox>.vm-snapshots/` or the directory it
  points to, the anchor beside it, and every copy of the package that was
  handed on.
- **Protection at rest.** Deleting a file does not overwrite what it held,
  and on an SSD nothing the harness does could guarantee that it did.
  Full-disk encryption on the host (FileVault, LUKS) is what protects a run
  on a lost or retired disk.
- **A leak.** A run directory, a package or a provider key that reaches the
  wrong hands can be a personal data breach; notifying it, and to whom, is
  the controller's duty under the GDPR and similar laws.
