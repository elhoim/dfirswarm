# Troubleshooting FAQ

What goes wrong at kickoff, in a run and in the console, and what to do about it.


**`BLOCKER: this host cannot run the agents' VMs`.**
Every agent runs in its own microVM unless the run says `--isolation host`,
and this host cannot boot one: an Intel Mac, Linux without KVM (`/dev/kvm`
this user can open) or glibc, msb missing (`npm ci --omit=optional` leaves it
out), or `msb doctor` failing, whose whole output follows the refusal. Fix
what it names, or run unisolated with `--isolation host`: every agent is
then a process on this host, held by the host guards. The kickoff never
falls back to host processes on its own.

**`BLOCKER: dfirswarm-<profile>:dev-<arch> is not on this host and could not be pulled`.**
The VM image the run needs is not loaded into msb and no registry had it.
The refusal prints the three commands for the base (`docker build`,
`docker save`, `msb load`); a profile image is built the same way
([images/README.md](../images/README.md)). `--image REF` names one this host
has (`msb image list`), and `--isolation host` runs without VMs.

**`BLOCKER: msb could not list its VMs`.**
The kickoff checks a new run id against msb's VMs, even with `--no-start`,
and msb did not answer. Check `"$(node --experimental-strip-types scripts/vm.ts msb-path)" list`;
reinstall with `npm ci`; or run with `--isolation host`.

**`BLOCKER: --no-write-guard … set a guard of a host run, and a run is in microVMs unless it says otherwise`.**
A host guard's flag (`--no-write-guard`, `--no-seal-herdr`,
`--inputs-enforce`, `--key-from-env`, `--probe-violation`) means nothing in
a VM, where the VM is the guard. Add `--isolation host` if a host run is what
you meant, or drop the flag.

**`agent_name_taken` from Herdr.**
Each `start` allocates a fresh `s????` prefix and checks `herdr agent list` for `<prefix>00`, so two concurrent runs never collide. If you see this, a crashed run left agents registered under the same names: `herdr agent list`, then `scripts/swarm.sh stop <id>` (closes its workspaces) or `herdr workspace close <ws>`.

**`BLOCKER: this run's hub sockets would be N bytes long under …`.**
A microVM run's hub binds one Unix socket per agent under
`~/.dfirswarm/hubs/`, and a socket path may be 103 bytes. A long home
directory (or `DFIRSWARM_HOME`) can pass it. Set `SWARM_HUBS_DIR` to a
shorter directory of your own, for example `/tmp/dfh-$(id -u)`; the kickoff
makes it 0700 and refuses one that is a link or someone else's.

**`BLOCKER: these would go into a folder a sync client uploads`.**
The copy of the evidence (`inputs/`, `.inputs-pristine/`) or the VMs' kept
disks would land in Dropbox, iCloud Drive, OneDrive, Google Drive or
another folder under `~/Library/CloudStorage`. Put the run on a local disk
(`--sandbox`, `SWARM_RUNS_DIR`, `--vm-snapshot-dir`), or pass
`--allow-synced-folder` when the material may be uploaded.

**`BLOCKER: the copy of the evidence … does not match its source`.**
The copy lost names the source has: a case-insensitive volume (the default
APFS) merges names that differ only in case or Unicode form, and a short
read leaves a file short. Put the run on a volume that keeps the source's
names (a case-sensitive APFS volume, or the source's own file system), or
hold the evidence in place with `--inputs-bind`.

**`NOTE: nothing of run <id> was alive`.**
The host restarted, or the run crashed, while the registry still said
`running`. The `stop` that printed it puts the run away as usual: its VMs,
the hub's state and unsent trace lines (kept under `~/.dfirswarm/hubs/`,
which a reboot does not clear), custody. The note names the trace's last
time, which is when the run's record ends.

**`BLOCKER: Pi has no stored credential for <model>`.**
Run `pi /login` once. The spawner no longer passes keys to panes, so an
exported `DEEPSEEK_API_KEY` alone is not enough — add `--key-from-env` if that
is what you want (cloud, CI), and accept that `ps` can see it.

**`BLOCKER: Pi will not use <model> without a credential, and a local server has none`.**
Pi lists a `models.json` provider only when it has some `apiKey`, even one
the server ignores. Add a placeholder (`"apiKey": "local"`) to the provider —
the BLOCKER prints the whole snippet — and check with
`pi auth check --model <provider>/<id> --json`. Not `pi /login`, not
`--key-from-env`: there is no key. Details in
[credentials-and-teams.md](credentials-and-teams.md#local-models-ollama-lm-studio-vllm-llamacpp).

**`BLOCKER: no model on this team declares a cost … --cap-usd cannot stop it`.**
Every model on the team is a local server, or a `models.json` provider with
no `cost` block, so Pi reports an exact $0 and a USD cap would never fire.
Give the run `--cap-tokens N` instead (a few million for a small goal on two
agents; tens of millions for a seven-agent case). If the provider does bill,
put its rates in the `cost` block and the USD cap works again.

**`WARN: Ollama gives <model> a context of N tokens; models.json declares M`.**
Ollama's OpenAI endpoint uses its own `num_ctx` (4096 by default) and
truncates silently, while Pi budgets against the declared window. Set
`OLLAMA_CONTEXT_LENGTH=M` in Ollama's environment or `PARAMETER num_ctx M` in
a Modelfile, restart Ollama, and keep `contextWindow` equal to it.

**`BLOCKER: the goal has no "## Definition of done" section`.**
By design: a swarm with no finish line is the failure this harness is built
against. Copy `prompts/goals/hello.md`, change the artifact, keep the
`## Definition of done` and `## Checks` headings.

**`await-done.sh` says the checks do not pass, but the artifact looks right.**
Run them yourself: `cd <sandbox> && bash -c '<the check>'`. The usual causes are
a check that assumes a tool the sandbox does not have, and a check that passes
for the wrong reason (`for id in $(jq …)` succeeds when `jq` fails — use
`ids=$(jq -e …) && …`).

**A `claim_violation` with `via: "bash"`.**
An agent wrote a path through the shell that it did not hold. The write was not
blocked — it cannot be — but it was snapshotted and announced on the board. The
claim's owner can `file_restore` the previous revision. If it was your own
agent writing its own path, that is recorded as history, not a violation.

**The web app says 401 / asks for a token.**
Starting, stopping, reaping and restoring need the token the server printed in
its URL. Open that URL once, or paste the token when prompted. `SWARM_UI_TOKEN=`
(empty) disables the check.

**`BLOCKER: missing herdr` / `pi` / `jq`.**
They must be on the `PATH` of the process that runs `swarm.sh start`. With nvm-installed `pi`, start the UI server from a shell where `nvm use` has run. `GET /api/models` falls back to a static list (`source: "static"`) when `pi` is not found; set `SWARM_PI_BIN` to point at it.

**Web app shows "Web bundle not built" (503).**
`ui/dist` is gitignored. Run `npm install && npm run ui:build`, or let `swarm.sh ui` build it (it does when `node_modules/vite` exists and you did not pass `--no-build`). `/api/*` works without the bundle. For development use `npm run ui:dev` (Vite on 43174, `/api` proxied to 43173).

**Lots of `claim_file` conflicts.**
Normal. Agents all reach for the same file at boot; the harness returns
`conflict:true` with the holder's reason, and the tool text tells them to post
and do other work. Conflicts are not violations. Leases are short (120 s by
default), so a dead owner's claim clears on its own; `claims` shows who holds
what and why.

**`claim_violation` from my own agent.**
It called `edit`/`write` without a live lease on that exact path, or the lease
lapsed while it was thinking, or `AGENT_ID` was unset in its pane. Check the
Claims tab or `jq 'select(.tool=="claim_violation")' traces/events.jsonl` for
`reason` and `owner`.

**Pane limits / layout looks wrong.**
Herdr publishes no pane-count maximum; 30 panes on one tab worked. Splits are `right|down` only, laid out as a √N grid (max 5 columns). `SWARM_PANES_PER_TAB` (default 30) forces a new tab earlier; a failed split also opens a new tab, and a failed tab opens a new workspace. `layout.json` records `tabs`, `split_failures`, `extra_workspaces`. The CLI refuses N > 30.

**`netguard: WARNING unprivileged network namespace unavailable; falling back to proxy-only`.**
`unshare -rn` is blocked (Docker default seccomp, or no user namespaces). The filter is now advisory. Run on a host or a container with `--security-opt seccomp=unconfined`, or accept advisory mode, or `--no-netguard`.

**Agents cannot reach the provider under netguard (no `ALLOW` lines).**
Your `pi` is a Node build on Node < 22.21, so `fetch` ignores the proxy and, in netns mode, has no route. Options: use the Bun-compiled `pi.dev/install.sh` binary, run Node ≥ 22.21/24, or `--no-netguard`. Check `<sandbox>/traces/netguard.log` and `scripts/swarm.sh netcheck`.

**`playwright: package not installed` / browser missing.**
`npm install && npx playwright install chromium`, or set `BROWSER_CHECK_EXECUTABLE=/path/to/chrome` (kickoff sets it automatically when Google Chrome is at `/usr/local/bin` or `/usr/bin`) or `BROWSER_CHECK_CHANNEL=chrome`.

**The swarm stopped itself with `reason: cap` or `reason: wall_clock`.**
The harness wrote the sentinel because the agents were steered and did not stop
within the grace period. `budget.json` has `stop_steer_at` and `stop_reason`;
the board has the `system` post that announced it.

**`watch.sh` prints `watch(1) not found; polling`.**
Harmless; it loops with `sleep` instead.

**Restore in the UI returns 409.**
An agent holds a live lease on that path. Wait for it to be released or lapse (120 s by default, 600 s at most) or reap the holder.
