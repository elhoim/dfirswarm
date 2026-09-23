# Safety

> Forged tools (`--allow-tool-forging`, off by default) are agent-written scripts that run as subprocesses in the sandbox with exactly the containment described here for `bash` — no more. Their own rules are in [forged-tools.md](forged-tools.md).

The product requirements inverted from the incident write-up, and exactly what the harness enforces, detects, and cannot contain. Read with [SECURITY.md](../SECURITY.md).


These are product requirements, inverted from what OpenAI's [Hugging Face incident write-up](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) describes: a hidden channel, goals adopted from peers, no safe exit from impossible tasks, a grader to game, and no harness or monitor on the evaluation. The mapping is in [Why: the incident, inverted](why-the-incident-inverted.md); the mechanisms are below.

- **Isolated cwd, and a write allowlist.** Every agent's cwd is `runs/<id>/`.
  Claim keys, history and artifact serving all reject paths that escape it, and
  `edit` / `write` outside it are blocked. `bash` still cannot be stopped
  mid-command — but on macOS the pane's seatbelt profile now denies
  `file-write*` everywhere and allows it back only under the run and Pi's own
  agent directory (`--no-write-guard` turns that off). A shell command can no
  longer write the examiner's home, another case's sandbox, or
  `runs/registry.json` — the file `await-done.sh` reads the definition of done
  from and then `eval`s. `tests/write-guard.test.sh` asserts each of those. On
  a host without seatbelt the guard cannot apply, the kickoff says so on
  stderr, and the run record carries `write_guard`.
  **What is still writable outside the run**: Pi's own agent directory, because
  a provider token refresh has to land somewhere and a run that cannot refresh
  dies at the hour mark. Its `extensions/` is denied — that would be code
  loading in every later Pi run — but `models.json`, `settings.json`,
  `auth.json` and `sessions/` in that directory are not. Reads are not
  restricted at all: a pane can still read anything this user can. **This is
  still not a machine to run on casually; a spare box or a dedicated user
  account is still the right answer for a case that matters.**
- **What the bash detector covers.** Every shell call is bracketed by a hash of
  everything under `work/`, the four harness files an agent should never touch
  (`SWARM.md`, `team.json`, `layout.json`, the sentinel), every live claim, and
  the spend/time caps. It does **not** byte-watch `threads/`, `locks/`,
  `traces/`, `inbox/` or `history/`: those change constantly under normal
  operation, so comparing them would blame whoever happened to be running a
  shell at the time. Claims on them are refused and the write guard blocks
  them; a shell write to one is a known blind spot — except `traces/`, which a
  run with a trace collector gives the panes read-only while its lines go to a
  process outside the profile, each chained to the last. The watch also covers at
  most 500 files under `work/`; when a run outgrows that, the harness says so
  once to the agent whose shell call found it (`watch_truncated`), because a
  write it can no longer see is a promise it can no longer keep.
- **Peer mail is data.** The system prompt states that only the kickoff, the
  contract and the harness are authority. The harness enforces the parts that
  matter (claims, protected paths, done, both caps) rather than hoping the
  prompt holds — and when it does act, it says so on the board as `system`, so
  the enforcement is visible to every agent rather than buried in a log.
- **The harness owns its own files.** `done/`, `locks/`, `traces/`, `history/`,
  `inbox/`, `threads/`, `tools/`, `inputs/`, `ledger/`, `catalog/`, `SWARM.md`,
  `team.json`, `budget.json`, `names.json` and `layout.json`
  cannot be claimed or written by an agent; a shell write to one is detected and
  announced. The sentinel is written only by `done` or by the harness itself.
- **Inputs are copies, read-only at three depths.** `--inputs DIR` copies the
  directory into `inputs/` (the original is never touched, symlinks are
  dereferenced), strips the write bits, and keeps a pristine clone. The tool
  guard refuses it, a shell write is healed and announced, and on macOS
  (`sandbox-exec`) or Linux (a read-only bind in a mount namespace, Landlock
  beneath it, or Landlock alone where the host allows no namespaces) the pane
  runs with it read-only at the kernel; each pane records what it actually got
  as `inputs_guard`. `--inputs-bind` skips the copy on a host with a kernel
  guard: `inputs/` links to the source and the kernel holds the source itself
  read-only. Reading is not restricted. [inputs.md](inputs.md), ADR 0005.
- **The same guards on Linux, by a different mechanism.** The write guard is
  Landlock (kernel 5.13+) with a user namespace over it where the host allows
  one: a read-only root, this run and Pi's agent directory bound back writable,
  Herdr's socket and `--no-read` paths hidden under an empty tmpfs, the panes
  in their own pid namespace. Where namespaces are refused (Docker's default
  seccomp, Ubuntu's AppArmor restriction) Landlock alone holds the write
  allowlist and the record says what could not be masked. Attribution is by
  process ancestry there, not by token: `/proc/<pid>/environ` is readable
  across panes of one uid (measured), so a gate in front of the collector
  reads the sender's pid from the kernel (`SO_PEERCRED`) and walks up to the
  pane. What each host could enforce is probed at kickoff and recorded as
  `host_caps`; the custody section of the report reads it back.
  [linux-plan.md](linux-plan.md) has the measurements, and
  [linux-server.md](linux-server.md) is what an operator has to set up.
- **The record says what the panes measured, not what the host could give.**
  Every agent probes its own guard when its session starts, and the kickoff
  reads those probes back into the record as `write_guard_measured`
  (`kernel`, `partial`, `none`, `unmeasured`), with a WARN and a custody row
  when it is not `kernel`. A guard that never reached a pane — the pane's
  login shell was neither zsh nor bash, the multiplexer started the agent
  elsewhere — used to be invisible in a run that said it was guarded. On a
  Linux host the pane's shell must be zsh or bash for the hook to run at
  all, and the kickoff refuses to start otherwise.
- **The finish line is checked, not asserted.** `await-done.sh` runs the goal's
  own `## Checks` and reads them from the run registry, outside the sandbox — a
  swarm that could rewrite its contract could otherwise certify itself.
- **Netguard is on by default.** `herdr agent start --kind pi` cannot take a
  wrapper argv, so kickoff does two things: writes `<sandbox>/bin/pi` that execs
  `netguard.sh --allow <provider host> -- <real pi>` and prepends that directory
  to `PATH`, and starts a persistent proxy-only `netguard.sh` sidecar on
  its own `127.0.0.1:<port>` (the first free one from 43178 up, so two swarms
  never share a proxy) with `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` set on every
  pane so the filter holds even if Herdr launches `pi` by absolute path. The
  allowlist is netguard's default provider hosts plus the one the selected
  model needs — `--allow` adds, it does not replace; `--only` replaces. An
  entry with no port is port 443 alone; a local endpoint is allowlisted as
  `host:port`, because a bare `127.0.0.1` would admit a CONNECT to every
  port on the machine, this console and an SSH daemon included.
  Verified live: agent `bash curl https://example.com/` → `CONNECT tunnel
  failed, response 403`, provider `ALLOW`, swarm still reached `SWARM_DONE`.
  `--no-netguard` opts out. Caveats:
  - **Node-built clients.** Node's global `fetch` honours `HTTPS_PROXY` only with `NODE_USE_ENV_PROXY=1` on Node ≥ 22.21 / 24 (netguard exports it). On older Node the proxy is ignored; inside a network namespace that fails **closed** (no egress at all), never open. The `pi.dev/install.sh` binary is Bun-compiled and Bun's `fetch` honours the variables natively.
  - **Docker.** The default seccomp profile blocks `unshare` for unprivileged containers; `netguard.sh` prints a WARNING and falls back to `--mode proxy-only`, which is **advisory**: a process that ignores the proxy variables has full egress.
  - **macOS: UNKNOWN.** No `unshare`; only proxy-only runs. A `pf` ruleset would be the enforced equivalent and needs root.
  - The shim wraps `pi` in `netns` mode where available, so on Linux hosts outside Docker both layers apply.
- **The provider key stays in Pi's store.** `swarm.sh` passes no credential to
  the panes; `pi /login` once and Pi reads its own. `--key-from-env` restores
  the old env-var path for cloud and CI hosts with no persistent home, and says
  in `--help` that `ps` can see it. No file in the repo or sandbox ever contains
  a key; `.gitignore` excludes `runs/` anyway. See
  [ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md) and
  [Credentials](usage.md#credentials).
- **Cost and time caps.** `--cap-usd` is mandatory. Spend is measured from Pi's
  own session usage, not estimated. At either cap the agents are steered to
  `done cannot_complete`, and if the swarm is still over one grace period later
  the harness writes the sentinel itself. `--hard-kill` additionally shuts the
  steered session down. Kickoff allows N=1–30 and warns above 10.
- **No root, ever, and installing is not root.** The panes are ordinary
  processes owned by the examiner: the "sandbox" is a directory plus a kernel
  guard over `inputs/`, a no-exec rule over what is carved out of it, and an
  egress allowlist. There is no `sudo`, nothing mounts, and nothing asks for
  either — which is the guarantee that makes read-only evidence mean anything
  on this machine. A case that needs a library the host does not have gets
  `--allow-install` instead: `pypi.org` and `files.pythonhosted.org` join the
  allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox,
  and what a run installs goes when the run goes. It is off by default, the
  contract tells the agents the rule when it is on, and the ledger is where
  they record what they installed. Homebrew and the system package managers
  stay out: they write outside the sandbox, to a machine the next case also
  has to trust.

  What that leaves unreachable is anything that genuinely needs root —
  a FUSE mount, a loop device, attaching a volume. The place for that is not
  the examiner's machine but a container, where root is confined to something
  disposable and the evidence is bind-mounted read-only. Nothing here runs
  that way yet; it is B16 in the [improvement plan](improvement-plan.md). A
  run that needs to *read* an
  encrypted or virtual volume usually does not need root at all: libbde,
  libvhdi, libluksde and pytsk3 read them in place, and the `crypto` toolbox
  set now names them so a kickoff finds out before the run rather than at
  minute forty.

- **Playwright is off by default** and refuses remote http(s) targets unless `SWARM_BROWSER_REMOTE=1`; under netguard the browser has no egress anyway.
- **The web app gates what costs money, and keeps case data on this machine.**
  It binds `127.0.0.1`; reads need no token and show case data, so opening it
  to the LAN (`--host 0.0.0.0`) is the operator's explicit choice. Start, stop,
  reap and restore need the token the server prints in its URL (in the
  fragment, so it never reaches a proxy log). `SWARM_UI_TOKEN=` turns that off
  deliberately. Never port-forward it; use an SSH tunnel.

**Settled**: claims are short leases with a reason and a `seconds` argument,
renewed by re-claiming (120 s); the trace shows `thinking` rows and a duration
on every call; the agent view shows context-window occupancy; a
`claim violation` is a *bash* write announced on the board, not a blocked one;
`file_diff` addresses revisions by content hash; threads have a purpose and a
member list.

**Local choices** (marked in code): the stall timeout (ours: 960 s for the
reaper, above the catalog's own 900 s step, and 90 s for the console's `?`), the thread dim threshold (ours: 2 min), the grace period before a
harness stop (ours: 2 min), the hard-kill default (ours: off), the sentinel
filename and the board's directory tree, file-history storage (ours: numbered
copies), the Herdr pane-count ceiling (none hit at 30), and macOS network
enforcement.
