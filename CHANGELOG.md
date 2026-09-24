# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Changed for host runs

What the microVM work changed for host runs as well, so a host operator is
not surprised:

- Every trace line carries its process's id and count (`sid`, `seq`) and the
  collector's `recv_ts`; the idle watchdog and the console order by the
  latter. The watchdogs spill to `traces/system-spill.jsonl`, not `work/`.
- A kickoff that stops after registering puts away what it started and
  records the run as `failed`. The registry is written under a lock. The
  host is asked not to sleep for the run (`caffeinate`, `systemd-inhibit`;
  neither holds against a closed laptop lid). A sandbox a running run uses
  is refused.
- `stop` takes custody (see Added; `--no-custody` skips it,
  `--custody-timeout SEC` bounds it, 14400 by default) and says where it was
  if interrupted. Custody re-reads every evidence file, so a stop on a large
  case takes as long as hashing the evidence once more. `reap <id>` touches
  only that run.
- The console binds `127.0.0.1` by default. It bound `0.0.0.0`, so anyone on
  the LAN could read the board and the trace without a token; `--host
  0.0.0.0` opens it to the LAN on purpose.
- The finish line `done` runs is read from the registry only. It looked for
  the registry beside the sandbox and fell back to the agent-writable
  `SWARM.md` in silence; panes now get `SWARM_RUNS_DIR`, and a finish line
  that is met but was read from anywhere else cannot certify a run
  (abandoning still ends it).
- The trace token and the console's token are masked in every trace line. A
  shell's `env` in a tool output had put both into the trace.
- Pack and library tools are registered at session start with forging off,
  and named in `--tools`. They loaded only with `--allow-tool-forging`,
  although the contract listed them as ready. A `--tools-from` tool of the
  same name no longer replaces a pack's tool: the pack's copy is kept, and
  different bytes are said.
- Pack secrets are implemented (`docs/packs.md` §4): a pack tool gets its
  pack's secrets in its own child's environment, and the trace row and the
  output carry `[secret NAME]`. On the host that needs `--allow-pack-secrets`,
  since a pane can read what its extension can; a pack that requires a
  secret is refused without it. The secrets live in
  `$DFIRSWARM_HOME/secrets/<pack>.env` (`~/.dfirswarm` by default), not inside
  the pack; a reinstall moves an old one, and a pack that declares secrets
  and still has a `secrets.env` in its directory stops the kickoff in either
  mode. Shipped packs were resealed with corrected install lines
  (`pff-tools`, `libfwsi-python`, plaso from PyPI), pinned downloads, and
  after the review with names checked against Debian 12 and PyPI (zeek,
  suricata and radare2 are manual, `libfwsi-python` is a Python library, the
  encrypted-containers pack installs pybde, pyvhdi, pyluksde, pytsk3 and
  dfvfs, and `vss_stores` and `mem_fs` mount under the seat's own
  directory).
- `--allow-install` sets `PIP_BREAK_SYSTEM_PACKAGES=1` in every pane:
  `pip install --user` was refused on a PEP 668 system. The installs still
  go under `work/.toolchain/`, and the Python install paths now reach a
  forged or pack tool's child, which could not import what an agent had
  installed. The inventory also reads a venv an agent made under
  `work/.toolchain/`.
- The inputs integrity walk no longer stops at 5,000 files and 12 levels.
  Every manifest file past it read as missing, so a KAPE-style triage set
  failed the check on every sweep.
- `start --no-start` no longer leaves the collector, the gate and the broker
  running.
- The report says when refused connections are not observable, where it said
  "nothing was refused" with no log behind it, and names each model's
  provider hosts, recorded at kickoff.
- `tools --save` keeps only sealed tools, with `provenance.json` and without a
  `pack` field; `pack.sh adopt` takes a saved tool into a pack. The toolbox's
  use column read " head -1" for every tool; fixed.
- The netguard allowlist takes a provider's host from `models.json` for a
  built-in provider too, and from Pi's model list for the providers Pi ships;
  `--provider-host` adds one. `--local-only` refuses a cloud `--compact-model`.
- The console: a `failed` state, a packs field, `*.name` allowlist entries.
- `microsandbox` is an optional dependency (`npm ci --omit=optional` for a
  host-only install).
- The idle watchdog is a host run's stop from outside the panes: past a cap
  or the wall clock it claims the stop clock (and says so on the board) when
  no pane has, and past the grace period writes the sentinel as the harness.
- Custody opens nothing through a link and waits on no FIFO; every evidence
  file is re-hashed in full whatever its size, against one deadline checked
  inside the read, and an unfinished re-hash says so rather than
  "unchanged"; the trace is read a line at a time; the ledger is held to the
  trace (an entry deleted from its end, or written without the tool, is
  named); `artifacts.json` indexes `work/`; the verdict's hash is anchored
  outside the run. `stop` bounds it from outside too.
- The ledger's chain covers each entry's provenance (source, evidence,
  confidence); an unchained line after chained ones breaks it.
- Evidence FIFOs, sockets and device nodes are recorded by their kind and
  checked by kind; the evidence manifest and its anchor are read-only on
  disk, and the manifest's hash is in the run's record.
- A peer's own directory is refused for claims and writes; the report reads
  the swarm's own report only inside the run and never through a link; the
  package copies only regular files (a link left in place of a spill had
  put a host file into the handover).
- A trace line a pane could write nowhere is said on its next line and
  counted by custody; the host spill is watched as append-only.
- Pack secrets are refused on a suffix; two packs' tools of one name keep the
  first. `tools --save` copies a tool only as its sealed version, with what
  it ran with. A forged tool may name the programs it calls (`requires`).
- `list` has a `HELD` column; run ids are six hex digits; a pane helper that
  opened a workspace no longer loses it (they ran in a subshell); a kickoff
  that fails before its record is written clears what it started.
- Warnings: a run kept in a synced folder, a Mac on battery, a suffix in the
  allowlist, writable evidence directories, a host run whose panes cannot be
  kept from a live VM run's hub. An IPv6 allow entry is written `[v6]:port`,
  and netguard reads it. GitHub Copilot's token host is allowed.

### Added

- **Agents in microVMs (`--isolation microvm`).** Every agent runs Pi inside
  its own microVM (microsandbox 0.7.2; macOS on Apple silicon, Linux with
  KVM), created at kickoff through the SDK (`scripts/vm.ts`) and put away by
  `stop` with each disk kept as a snapshot msb can verify. ADR 0009.
  - The run is a read-only floor in each VM; the agent writes only its own
    `work/<id>/`, `work/extracted/<id>/` and `work/quarantine/<id>/` (both
    no-exec), `tool-output/<id>/` and Pi session. A shared file is written
    by the hub through `publish_file`, claimed and recorded. `--inputs` is
    used in place and mounted read-only; `--inputs-copy` gives the run its
    own read-only copy.
  - The board has one writer, the hub (`scripts/vm-hub.ts`); who is asking
    is the vsock port. The harness's own functions are not on the agents'
    channel, a sentinel is written only when the finish line passes on the
    host (a reason starting `ABANDONED: ` is let through unchecked, and a
    seat leaving on its own cap writes none), spend reports may only grow,
    and paths are resolved on the host without following a planted link.
    The hub keeps the wall clock itself; the caps apply to the spend each
    seat reports. A keeper (`scripts/hub-supervise.sh`) restarts a dead
    hub from its saved state until the run's stop.
  - No credential enters a VM: placeholders, swapped in by msb on the way
    to the credential's own hosts only, stopped and logged anywhere else.
    Subscriptions need `--allow-oauth-in-vm`. `--provider-host P=HOST` names
    a provider's host when the harness cannot (Pi's own model list names the
    hosts of the providers it ships); a provider with none is refused.
  - The image is the smallest profile that serves the packs, pulled before
    the run starts, booted by one digest; a program a pack requires that the
    image lacks stops the kickoff. Images carry a NOTICE, pinned downloads
    checked by sha256, and refuse to bake programs marked not redistributable
    without `--allow-nonredistributable` (`images/README.md`).
  - `netcheck --isolation microvm` asks msb what a run's VMs would reach.
    The report and the console's VM panel say what each VM was given, found
    and left: probe, image fit, clock, live state, installs outside the image.
  - The console starts a VM run (`isolation`, `image`, `vm_cpus`,
    `vm_memory`, `vm_disk`, `vm_snapshot`, `allow_oauth_in_vm`,
    `provider_hosts`); its default "copy" of the evidence is sent as
    `--inputs-copy` in a VM run, and a run whose hub could not put its VMs
    away shows as `finish_failed`.
- **Host custody at stop** (`scripts/custody.ts` → `custody.json`, printed by
  `stop` and carried by the report), both modes: the evidence re-hashed in
  full against a manifest anchored outside the run, every session file
  sealed, every kept output checked against the trace, the trace and the
  ledger chains, spilled and lost trace lines by their numbers, and every
  kept VM disk checked against its record and by msb.
- **VM integration tests** (`npm run test:vm`) on real VMs, one of them end to
  end with a scripted model, and a CI job that runs them on a KVM runner with
  the base and disk images built from this repository.
- **What the final review of the microVM work changed** (ADR 0009):
  - The hub never opens a file under a seat's own directory: a revision, a
    publish and the disk side of a diff come from the VM with the call (32,
    32 and 16 MiB), a seat restores its own file in its own VM, and a
    forged tool runs only as its sealed bytes. The host's own reads are
    checked again after the open (on Linux against `/proc/self/fd`).
  - The hub bounds each seat (connections, bytes buffered, calls, a rate for
    posts and records), answers a resent call once, keeps its lines
    numbered, refuses to run twice, resumes a finish it died in, clears up
    the run with `stop --after-hub`, and is kept by `scripts/hub-supervise.sh`;
    it runs from a frozen copy of the harness. A seat that is done has its
    VM put away a grace period later.
  - `stop` exits 3 and records `stop_incomplete` while a VM of the run is up,
    and waits for a hub that is finishing. Below 4 GiB free a VM is kept
    rather than snapshotted and removed; `--vm-snapshot-dir` puts the disks
    elsewhere.
  - `work/extracted/` and `work/quarantine/` are no-exec in every VM, a
    peer's corner as well as one's own. Each VM's probe checks that, that
    the evidence is no-exec, and that it can reach its model's hosts.
  - Pack secrets need `--allow-pack-secrets` in a VM too (the placeholder is
    in the whole VM's environment); `--local-only` withholds them; a local
    model's real key is refused; credential headers are swapped at every
    depth; a LAN model's name is resolved on the host; llama.cpp gets its
    environment; Pi's model catalog goes into the guest.
  - The catalog VM leaves only files and directories, is put away on `^C`
    and reaped if left; a VM that does not come up times out; `msb` other
    than 0.7.2 is warned about; a lock pinned by tag is refused.

- **Agents compact their own context.** On by default at kickoff
  (`--no-self-compact` turns it off): each agent watches its context against
  an effective ceiling the harness sets per model (`extensions/context-ceiling.ts`:
  272k for the GPT-5.4/5.5 family, 200k for grok-4.6, 300k for a million-token
  model, the declared window otherwise), receives a transient notice at 40%
  and a warning at 50%, and at the compact line (60%) every tool except
  `self_compact`, `budget` and `done` is refused until it hands off with
  `self_compact(note_to_self)`. The context is summarized with the harness's
  own prompt (`prompts/compaction-summary.md`, written for a forensic swarm)
  and the note comes back verbatim under a header of facts read from files:
  the agent's name, its live claims, its unread posts, the ledger, the
  sentinel, its spend. The three lines take token counts or percentages
  (`--compact-notice-at`, `--compact-warn-at`, `--compact-at`,
  `--compact-prompt-file`) from the CLI and the console's kickoff form; the
  registry records them as `self_compact`. Pi's own overflow compaction stays
  as the safety net, runs with our prompt, and is recorded as one. The
  kickoff pins Pi's `reserveTokens` and `keepRecentTokens` in the sandbox's
  `.pi/settings.json`. Every crossing, hold, note and compaction is on the
  trace, with one `context` row per turn; `budget.json` carries the ceiling,
  the level, the lock, the compaction count and cost and the hand-offs per
  agent; the `budget` tool returns the same numbers to the agent; the
  summary and the report gained a Context and a Compactions column; the
  console shows the lines on the context bar, the compaction ticks on the
  activity span, and a Context section with the agent's context over time
  and its compaction history. Decided in ADR 0008; the run data behind it
  is in `docs/self-compaction-plan.md`. Proven end to end through the real
  CLI with a scripted provider (`tests/self-compact-e2e.test.ts`).
- **The trace keeps everything whole.** Arguments, results and reasoning
  are no longer clipped at 20,000, 2,000 and 2,000 characters; the collector
  and the gate accept lines up to 64 MB. The `_truncated` marker is read
  from archived runs and never written again.
- **Nothing a tool produced is dropped: `tool-output/`.** When a result
  reaches the model as a prefix, the whole output is a file in the sandbox
  and the trace row names it (`full_output`: path, bytes, lines, sha256):
  Pi's `bash` spill past 50 KB is moved in from the host's temp directory and
  the model's trailer names the sandbox path; a forged tool's stdout and
  stderr stream to it past 64 KB; `browser_check` keeps the whole page text
  the same way (`full_text`). `read`, `grep`, `find` and `ls` slices are
  recorded as such (`view`). The console links each file from the trace row
  (`GET /api/swarms/:id/tool-output/<path>`), and the forged tool's own trace
  row now carries its output, whole, where it carried a byte count.
- **No silent cut remains in the harness.** An `inbox` or `wait` row lists
  every delivered post's sender and id (the lists stopped at twenty); a
  provider's error text, a forged tool's error and an agent's `doing` are
  whole; the ledger's `source` and `evidence` (1,000 and 4,000 characters), a
  forged tool's parameter descriptions and its example (400) are refused
  over their limits with the reason, where they were cut in silence.
- **`inbox` and `wait` page by whole posts.** One delivery carries at most
  `--inbox-page-chars` characters of post text (40,000 by default, 0 for no
  bound; the console form has the field, the registry records it): a post is
  never cut, the delivery stops before the post that would break the bound,
  what stayed behind is still unread, the result says `remaining` and why,
  and `wait` returns at once while anything is unread. The two `wait` results
  of 578 posts and 64k tokens each on the Linux run s3096 are what this is
  for.
- **Per-model compaction lines.** Each of `--compact-at`,
  `--compact-warn-at` and `--compact-notice-at` takes a seat value followed
  by per-model overrides (`60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`; a key
  with a slash is a `provider/id`, one without matches the model id under any
  provider). Resolved per seat against its own model; `compact_config`
  records which entry applied under `matched`. Same syntax in the console.
- **`--compact-model P/ID`: a summarizer for expensive seats.** Every
  summary call goes to that model; it is credential-checked and its provider's
  hosts join the netguard allowlist like a seat's model, and it is never a
  seat. Recorded as `self_compact.model`; `compact_config` says which model a
  seat will use and why, `compact_done` which one wrote each summary; a model
  Pi's registry does not know falls back to the agent's own with the reason
  on the trace. The console's form and goal panel carry it.
- **`swarm.sh context <id>`**, the context history of a run from its trace
  (`scripts/context-audit.ts`, Markdown or `--json`): per agent the model,
  the ceiling and the lines, the turns, the peak, the crossings, the holds,
  the hand-offs and Pi's own fallbacks with what each summary cost and which
  model wrote it, the largest climb in one turn, the outputs kept under
  `tool-output/`, the deliveries paged; then one sentence per thing the
  record says about the lines. What the defaults are revisited from.
- **The write guard reaches a pane whose login shell is bash.** The only
  hook was `$ZDOTDIR/.zshenv`, so a bash account was refused at kickoff (or,
  before that check, ran every pane unguarded). On such an account the panes
  are now given `HOME=<sandbox>/.bash`, whose `.bashrc` and `.bash_profile`
  put the panes' `HOME` back (an `--env HOME` if one was given), re-run the
  same bash under `fsguard.sh`, and then read the user's own configuration.
  `HOME` is moved for a bash account only, so a shell that reads neither
  hook keeps its own. The login-shell check now runs whenever a hook is
  written, `--no-write-guard` with `--inputs` or `--quarantine` included: a
  shell that is neither zsh nor bash is refused while the write guard or
  `--inputs-enforce on` depends on it, and warned about otherwise. A login
  shell the account database does not give is warned about rather than
  taken for zsh; before, a `getent` that exited non-zero (as it does for a
  user it does not know) ended the kickoff under `pipefail` with no message.
  Verified
  live on Ubuntu with Herdr 0.9.1 (`s5038` in `docs/verified-runs.md`).

### Changed

- The pinned `@earendil-works/pi-coding-agent` is **0.87.0** (was 0.85.1):
  npm `latest`, and what the Linux host already ran. The provider contract
  changed between the two (a transcript with system messages instead of
  `{systemPrompt, tools}`); the scripted provider behind the self-compaction
  e2e speaks both, and the suite passes on both.

### Fixed

- **The venv was 642 claims and seven violations, and the panes' temp
  files were more.** With `--allow-install` one agent's pip created
  `work/.toolchain/`; the shell-write watch took every file in it as that
  agent's implicit claim, the next agent's pip into the same venv as seven
  `CLAIM VIOLATION` posts, and the thousands of files pushed the watch past
  its budget so every agent was told `work/` was no longer covered (run 6,
  Linux, 2026-09-22). Pi's own bash spill files, written to the panes'
  `TMPDIR` under `work/.tmp/`, were claims and a violation too. The watch
  now leaves `work/.toolchain/` and `work/.tmp/` alone (`SHARED_WORK_DIRS`),
  and the spill file is removed once its whole copy is under `tool-output/`.
- **After a hand-off, agents answered the hand-off message with a status and
  ended their turns.** All four agents on run 6 did, a few tool calls after
  their notes came back ("they only asked for a compaction hand-off"), and
  three sat idle for ten minutes. The hand-off header and the system prompt
  now say the message is the harness, not a person, that it is not to be
  answered with a status, and that a turn that ends is not waiting.
- **The idle watchdog was found dead a minute after the kickoff started
  it, on runs 5 and 6 (Linux).** An empty log, no state file, nothing in
  the journal; a probe of the same detach from the same tmux session
  survives, so the cause is not established. The kickoff now looks two
  seconds after starting it, starts it once more with stdin closed when it
  is gone, and prints which happened; `swarm.sh status` reports every
  daemon's liveness from its pid file, so a dead watchdog is a line rather
  than a silence. On run 6 the watchdog, run by hand, woke all four agents.
- `swarm.sh context` no longer lists the watchdog's `system` rows as a seat.
- **A forged tool was killed at 64 KB of output and the rest was dropped
  unrecorded.** A parser that emits a large CSV, the normal case on a
  forensic run, ended with `SIGKILL` and a prefix. The tool now runs to its
  end; the model receives the first 64 KB with a trailer naming the whole
  stream under `tool-output/`, with its size and hash.
- **A shell loop writing to a peer's file flooded the board.** On the Linux
  run s3096 one agent's loop produced 566 `CLAIM VIOLATION` posts in
  fourteen minutes, and every peer's next `wait` delivered all of them: 240k
  characters, 64k tokens, a quarter of a working context spent reading one
  sentence. The board post now comes once per path per minute and says how
  many repeats the minute held; every write is still a `claim_violation` row
  on the trace.
- **A run account with no `~/.zshrc` never started an agent on Ubuntu.** zsh
  opened its new-user wizard in every pane and read the `pi` command line as
  the wizard's menu answer; `herdr agent start` then timed out "waiting for
  agent startup" with four idle panes, and the kickoff exited 1 after the
  sandbox, the daemons and the layout were all in place (measured on the
  Linux host, 2026-09-22). The pane hook now hands `ZDOTDIR` back to the home
  only when the home has a `.zshrc`; otherwise the pane keeps the sandbox's
  `.zsh/`, where an empty `.zshrc` stands in. `docs/linux-server.md` says to
  create the file anyway.
- **On Linux the trace gate was started without its key, so every line it
  forwarded was written unverified while the kickoff recorded
  `attribution: ancestry`.** The stdin line's shape was keyed off a variable
  `start_trace_gate` clears first. The gate and the collector now read one
  schema, `{tokens, gate}`, built once when the tokens are minted; the gate
  always gets the key and the collector gets it only once the gate is up.
  Both log what they were handed, and `tests/trace-gate.test.sh` asserts it
  after a real kickoff; `tests/trace-stdin.test.sh` asserts the shapes on
  any host.
- The kickoff line and the quarantine line named the `linux` and `landlock`
  guards as `none (detect + heal only)`; every mode fsguard has is labelled.
- The custody section said the trace anchor was writable by the panes on
  every host but macOS. It is out of a pane's reach under any write
  allowlist: seatbelt, Landlock with or without the namespace, and the
  namespace mode when bubblewrap makes the root read-only.
- The unenforced terminal-socket line explained the gap as "no seatbelt"; on
  a Landlock-only host the socket is reachable because Landlock cannot mask
  a socket, and the line now says so.

### Changed

- One walk writes the inputs manifest for the copy, the bind and the
  attached image (`write_inputs_manifest`), where there were three copies of
  it. `host_caps` runs once per kickoff and feeds both the contract and the
  registry. fsguard builds the Landlock argument list as an array and passes
  it without `eval`; `--subreaper` belongs to the pane's exec, not to the
  rule set.

- **Licensed under the GNU Affero General Public License v3 or later, with a
  commercial licence alongside it.** Nothing was ever released and the
  repository has never been public, so the licence is decided once here
  rather than inherited. The AGPL asks nothing of anyone running this
  software: on their own machines, on a client's case, whatever they bill for
  the work, modified or not, as long as the modified version stays inside one
  organisation. Section 13 attaches to a single use, offering a modified
  version to other people over a network without publishing those
  modifications, which is the one use that would hollow a project like this
  out. `LICENSE` is the FSF's text verbatim, `NOTICE` carries the copyright
  and the source link, and `package.json` is `AGPL-3.0-or-later`.
  `COMMERCIAL-LICENSE.md` states when a commercial licence is needed and,
  more usefully, the common cases where it is not. The trademark policy rests
  on the licence's sections 7(c) and 7(e). Herdr (Apache 2.0) and Pi (MIT)
  are both compatible and neither is bundled. The 0.3.0 entry below still
  records the MIT `LICENSE` that version shipped.
- **The console offers its own source, because it is a network service.**
  Section 13 asks a modified version reached over a network to offer its
  users that version's source. The page footer and the server's startup
  banner both carry the link, so an unmodified run complies by default and a
  fork changes one constant.
- **Renamed to DFIR Swarm, in a fresh repository.** The name now says both
  what this is and what it was built and proven for: an agent swarm for
  digital forensics and incident response. The repository is
  `halilozturkci/dfirswarm`, started from one root commit holding the tree
  as it stood on 2026-09-19; the package is `dfirswarm`, and the wordmark,
  the page title, the server's banner and every document follow. The
  previous repository, `halilozturkci/dfir-swarm`, is kept archived: its
  pull requests are the ones this changelog and the plans cite by number.
  The extension file keeps its name — `extensions/agent-swarm.ts` is a code
  path, not the product — and the published cases keep their screenshots as
  they were taken.
- **The harness assigns nothing.** `--seats`, the `dfir` seat preset and the
  Seats table in `SWARM.md` are gone, and nothing writes a seat into
  `team.json` or into an agent's system prompt. An agent reads the goal, reads
  the board, decides what it is taking on and says so with the new `name`
  tool; `names.json` records what each one said, every post carries its
  author's name, and the console and the summary show it beside the id. Two
  agents cannot answer to the same name, and an agent may rename itself
  whenever its work changes. The only boundaries the harness draws are the
  sandbox's own: read-only inputs, the no-exec quarantine, the network
  setting, the caps and the protocol.
- The console bundle is split into a vendor chunk (React, the router) and the
  app chunk, so a UI change no longer invalidates the vendor bytes in the
  browser cache and no chunk passes Vite's size warning.
- `@types/node` follows the runtime again (22.x, as `.nvmrc` and
  `engines.node`); Dependabot no longer proposes a newer major for it.
- CI runs with no warnings: git's `init.defaultBranch` hint under
  `actions/checkout` is silenced, and the netguard suite no longer echoes the
  proxy-only fallback it already reports as the detected mode.
- **The extension is type-checked against Pi's own types.** Pi's package
  (`@earendil-works/pi-coding-agent`, pinned) is a devDependency, the ambient
  stub and the separate server tsconfig are gone, and `npm run typecheck`
  covers `extensions/agent-swarm.ts` and every node test with the one
  config. The eight type errors this found were real, small and are fixed.
  A24's fault, two functions called and never imported, is now a compiler
  error. `npm ci` grows by Pi's package; a real run still needs `pi` on
  `PATH`.
- **The change bus drops what the console cannot show, and says what moved
  per swarm.** Pi appends to its session file on every message, the netguard
  proxy logs every connection, the idle watchdog writes its state every half
  minute and every post or claim takes and drops the lock-table mutex; none of
  it changes anything on screen, and together it was most of the events a
  running swarm produced. Those writes are classified (`sessions`, `logs`,
  `internal`) and dropped at the server, so neither the clients nor the
  finish line's change stamp see them. A `change` event now carries
  `by_swarm`, the kinds that moved under each swarm, and each panel keys its
  refetch on the kinds it reads: the board on `threads`, the trace on
  `events`, the files on `history`, the tool source on `tools`, the goal on
  `contract`. The view and the finish line still refetch on any kind, so a
  panel can never be more stale than the page around it. Two more things
  the bus does now, both measured on a post to a fixture swarm: a burst
  ends 200 ms after its last filesystem event rather than its first (one
  post used to arrive as three `change` events on macOS), flushing after a
  second at most under a steady stream; and a path reported again with the
  same size and mtime is not a change (the filesystem re-reports a write
  for a second or more, and a sync client touching attributes reports it
  once more). One post is one event, one appended trace line is one event.
- **The console refetches what changed, not everything.** A swarm's page is
  keyed on that swarm's changes plus the registry's, not on every change in
  the fleet; a burst of changes is one refetch after the request in flight
  lands, not one per change; the elapsed counters tick on the client instead
  of refetching every fifteen seconds. On the server, one swarm's view no
  longer rebuilds every swarm's row to find its own, the event log and a
  thread's posts are parsed once per change and shared, and the finish
  line's shell checks run again only when something under the sandbox moved
  (`/api/health` counts the runs). Same data on screen, a fraction of the
  requests and reads.
- **The shell-write watch caches hashes and says when it is full.** Every
  `bash` call hashes every file under `work/` before and after; a run whose
  extractions reached a gigabyte paid over a second per shell call for it. A
  file whose size, mtime and ctime have not moved is not read again, and the
  watch walks eight levels deep instead of four. When `work/` holds more than
  500 files the harness says so once, on the trace (`watch_truncated`) and on
  the board, instead of leaving the files it no longer covers unwatched in
  silence.
- `npm test` runs the Pi loader suite too (it skips where Pi is not
  installed), and `npm run test:bash` runs every shell suite and reports each
  one instead of stopping at the first failure (`scripts/test-bash.sh`).
- Dead code left the console: an unused messaging timeline, an unused tabs
  primitive and three Radix packages nothing imported; the grace-clock
  formatter and the post-tag colours are defined once.
- Docs brought back in line with the code: the roadmap no longer lists local
  models and the tool library as future work, `--tools-from` reads
  `manifest.json`, the usage page names every tool the agents get, the
  protocol page describes `name:` rather than `seat:` on a post, and the quick
  start cites the Pi version the runs used.

### Added

- **A second run on BelkaCTF #6, in a clean room, and an agent that walked out
  of the network guard.** `s83fd` worked the same evidence and the same goal
  as the first run with the first run's answers denied at the kernel
  (`--no-read`) and no tools carried forward. It reached 9 high-confidence
  answers to the first run's 6, for $68.89 against $77.32, while short-handed:
  four agents had been pointed at one Azure deployment and it rate-limited.
  The isolation was proved from inside a pane before the agents started — 17
  checks — and watched for the whole hour: zero reaches toward the previous
  run across 2,339 tool calls. The run also produced the finding that names
  the limit of this platform. Given `--allow-install --no-pypi`, an agent was
  refused by the proxy eight times and then ran `env -u HTTP_PROXY … pip
  install`, which worked, because netguard on macOS is environment variables
  rather than a network namespace. Four kernel-enforced guards held; the one
  advisory guard did not. `docs/use-cases/belkactf/belkactf6-bogus-bill/netguard-escape.md`
  is the whole account, and the contract now tells the truth under `--no-pypi`
  — it had promised the agents an allowlist entry the flag had removed, which
  is why they went looking in the first place.

- **A pane writes inside its run and nowhere else.** The seatbelt profile was
  `(allow default)` with a deny under `inputs/`: it protected the evidence
  from the agents and the machine from nobody. Measured inside a real guard, a
  pane could list the examiner's home, see `~/.ssh`, see every other case on
  the machine, and write outside its sandbox — including `runs/registry.json`,
  which is where `await-done.sh` reads the definition of done from before
  `eval`-ing it as the examiner. `fsguard.sh --rw DIR` now builds a write
  allowlist: `(deny file-write* (subpath "/"))` and the run's own tree allowed
  back, plus the devices a tool needs. Reads stay open on purpose — a
  deny-default profile cannot start `/bin/echo`. `TMPDIR` moves inside the
  run, which let the per-user temp area stay closed with python's
  `NamedTemporaryFile`, git, node, sqlite3 and tar all still working. On by
  default; `--no-write-guard` turns it off; macOS only, and `fsguard` says so
  rather than pretending on a host that cannot apply it.

- **The trace has a writer the agents cannot reach.** `traces/events.jsonl`
  lived in the directory the panes can write, and the only protection was a
  size-and-prefix comparison that announces a rewrite as `blocked: false`. On
  BelkaCTF #6 it fired once — "RECORD REWRITTEN … Nothing can restore it" —
  nobody answered it, and the file turns out to be intact: 2,287 of 2,287
  lines parse. The run's loudest integrity alarm was a false positive. Now a
  collector process outside the pane's profile holds the only writable handle,
  the panes reach it over a Unix socket and get `traces/` read-only, and every
  line carries the sha256 of the line before it — so a line edited or removed
  from the middle breaks something a reader can check, which "the file grew"
  never could. Without a collector a run behaves exactly as before and the
  report says "not chained" instead of claiming a chain it does not have.

- **A record the agents cannot forge, only fail to write.** The chain closed
  an edit in the middle and left two ways round it. A line appended after the
  last one still chained, so a trace could be *extended*: the head of the
  chain is now written to an anchor beside the registry, outside the sandbox
  and out of a pane's reach, and `verifyEventChain` reports `edited`,
  `appended`, `shortened` or `head` rather than a bare boolean. And the
  socket believed whoever wrote to it — any pane could send a line as any
  agent. Each pane now gets a token in its environment (which on macOS no
  other process can read, and which Herdr's API does not expose — both
  measured), the collector takes the token map on stdin where neither argv
  nor the filesystem leaks it, and a line's `agent` is decided from the
  token. A line claiming to be someone else is still written, with
  `claimed_agent` beside it: an attempt on the record is itself a finding.
  `idle-nudge.sh` and `reap.sh` append through `scripts/trace-emit.mjs`
  instead of writing the file directly — their unchained line used to break
  the *next* collector line, so a run with the watchdog on called its own
  record edited every three minutes.

- **The terminal multiplexer's control socket is out of the panes' reach.**
  Herdr puts `HERDR_SOCKET_PATH` into every pane, and that socket
  authenticates nobody: every method is dispatched to whoever connected, and
  the 0600 mode on the file is the whole boundary — which the panes are
  inside of. Measured from within the write guard: it answered. Through it,
  `layout.apply` starts a process with arbitrary argv and environment that
  the server owns, so it is not under the pane's profile and every write rule
  was optional; `pane.send_text` types into a peer's terminal;
  `pane.report_agent` forges another pane's lifecycle state; `server.stop`
  ends the run. `fsguard.sh --no-socket` denies it (a directory denies every
  socket under it, `literal` for a single path), on by default with the write
  guard and `--no-seal-herdr` to restore the hole. The one call the harness
  made from inside a pane — waking idle peers when a `done` finishes the
  swarm — goes through `scripts/nudge-broker.mjs`, where the pane names a
  `kind` and the broker owns the words: an agent can wake a peer and cannot
  tell it anything. The run record carries `herdr_socket` and the report
  prints "Terminal socket". Agent detection is unaffected — Herdr reads Pi's
  state off the screen, and the idle watchdog runs outside the panes.

- **What two review passes found in the two entries above, and what it cost
  to fix.** The anchor did not do what it was built to do: it checked two
  relations between the record and the length it remembered and let the rest
  through, so a line appended with a correctly computed `prev` — and the hash
  that needs is the previous line, which every pane can read — still verified
  as intact. So did a whole rewrite padded past the anchor's count. Stripping
  every `prev` skipped the anchor entirely and printed as "this run had no
  trace collector", the one sentence that tells a reader to stop worrying.
  The anchor also re-read its line count from the file, so truncating the
  trace and letting one more line through moved it *down* to the shorter
  count. Every relation is now decided, the count only ever grows, and the
  collector brackets each append with two anchor writes so that a reader in
  the window between them can tell it from a deleted last line.
  `attribute()` passed the sender's own `agent_unverified` and
  `claimed_agent` straight through, which let an agent stamp its own lines
  unattributable and repudiate them later. `trace-emit` and `sendToCollector`
  reported success when the bytes reached the kernel, so a line the collector
  refused vanished and the fallback built for that case never ran; both wait
  for the collector to say it wrote. The watchdogs' fallback appended to the
  trace itself, putting an unchained line in a chained record — the harness
  raising a corruption alarm against itself — and now spills instead, unless
  the record has no chain to protect. The watchdogs had no token, so every
  line they wrote came back unattributed. The socket deny was written with
  the path as given, and seatbelt matches the resolved one: on macOS
  `$TMPDIR` is `/var/...` for `/private/var/...`, so a rule could be present
  and deny nothing. It was also skipped entirely when the socket did not
  exist yet — the ordinary case — while the run record still said `sealed`.
  The broker checked its roster against a file inside the sandbox, which
  every pane may write, and sent "the swarm is finished, stop" on request
  without checking whether it was: a run-wide kill switch reachable by any
  agent. Neither daemon had a connection limit (300 senders took the
  collector to 821 MB; now bounded and it keeps serving) and neither noticed
  when its run was deleted — 307 orphaned daemons were found running on the
  development machine, and they now exit on their own.

- **An alarm about evidence that never changed.** The integrity check
  fingerprints bytes, mode and link count together, so a returning write bit
  read as "the evidence was modified". One archived run recorded 374 of those
  on two files whose sha256 still match the manifest exactly — 27% of its
  whole trace, every one of them `healed: failed`. Content drift and metadata
  drift are now different things, with `content_ok` answering the evidence
  question on its own, different board wording, and a metadata finding
  repeated at most once per path per ten minutes.

- **The record says which guard was achieved, not which was asked for.** The
  registry said `netguard: true` while the sidecar starts `--mode proxy-only`,
  which netguard's own header calls advisory — sitting beside `inputs.guard`,
  which is measured per pane. `netguard_mode` is recorded and printed, the
  report's custody section carries "Egress enforcement" and "Egress refused",
  and the harness's own `pi.dev` telemetry is dropped from the refusals: it is
  130 of the 172 on that run and it buries the one line that matters, an agent
  resolving a `bit.ly` link it had read inside the seized phone.

- **What a run installed is recorded, and what a tool returned.**
  `--allow-install` wrote nothing down: a report citing a finding produced by
  a library could not name the library's version. The harness now reads every
  `dist-info` under the run's own prefix — name, version, installer, the index
  URL pip recorded, and the sha256 of the package's own `RECORD` — into
  `toolchain.json`, the trace, the board, the report and the handover package.
  And a built-in tool's result carries the first 2,000 characters of its
  output beside `ok`, because `ok: true` is not correctness: 27 of 28
  `bde_unlock*` calls on that run returned `ok: true, exit_code: 0` with
  `InvalidTag` in the payload.

- **The evidence is the one input an adversary wrote, and nothing said so.** A
  search of the prompts, the docs and the code for "prompt injection",
  "untrusted" or "hostile input" returned nothing. The worker prompt and the
  generated contract now say that `inputs/`, `catalog/` and `work/extracted/`
  are material and never instruction, and name the refusal: no network
  request, no install, no execution because of something read in the evidence.
  A `confidence: high` claim wants a second independent artefact, and a
  sign-off by the agent that wrote the files is not a sign-off.

- **`--inputs-image`: evidence the host kernel holds.** A `:ro` bind mount is
  not a write block — `--cap-add SYS_ADMIN`, the capability that mounting a
  forensic image needs, remounts it read-write and edits the host's file
  (measured). So the obvious "give them root in a container" design destroys
  the guarantee the platform rests on. An image attached read-only on the host
  survives the same container, and `--inputs-image FILE` makes that a run
  mode: the manifest records `guard: "image"` with the mode and link count it
  found, the mount point is read-only to the panes (a pane can unmount the
  image — measured — and must not be able to write a replacement in its
  place), and `stop` detaches. The test
  asserts **both** halves, including that the bind mount is defeated, so
  nobody simplifies it back.

- **Every long list is paged.** An agent's trace is 229 calls, the artifact
  index 131 files, the ledger 57 entries — each of them one endless column
  where, past the first screenful, scrolling stops telling you where you are
  and there is no way back to a row you saw a minute ago. One control under
  every long list now: "51–100 of 229 calls", first and last always
  reachable, 25 / 50 / 100 / 250 per page, and a control that does not grow
  with the list. The page resets when a filter makes it a different list —
  page 5 of a list that no longer has five pages is an empty screen with no
  explanation — and a live trace's **Follow** moves to the last page instead
  of fighting it. The raw trace, an agent's trace, its reasoning, the
  ledger's timeline / indicators / findings, the artifact index and the files
  with history all use it.

- **An opened trace row reads like a record, not like JSON.** It was two
  bordered boxes of pretty-printed JSON: `{ "path": "SWARM.md" }` across
  three lines beside `{ "ok": true, "duration_ms": 10 }` in another — four
  lines of punctuation around six characters of fact. Now each argument and
  each result field is its own line, name beside value, wrapping; anything
  long or structured gets a block underneath; `ok` is coloured, because
  whether the call worked is what a reader looks for first; and RAW and COPY
  are there because this is an audit trail and somebody will want the bytes.
  One row is open at a time — two open rows pushed the list so far apart
  that the first was off the screen by the time you opened the second.

- **The trace kept 80 characters of an argument, and dropped every
  structure.** `summarizeArgs` cut each string at 80 characters and discarded
  objects and arrays without a word. So a shell line went into the audit
  trail as `ls -la catalog/ work/ 2>/dev/null; ls catalog/ | head; echo
  '---'; tar tf inp...`, losing the half that said which file it read; and a
  refused `make_tool` recorded `{name, runtime}`, leaving the trace holding
  the error `param "db" must match /^[a-z][a-z0-9_]{2,31}$/` about params the
  record did not contain. An audit trail that quietly shortens what it audits
  is worse than one that says it cannot. It now keeps 20,000 characters — a valve against one
  pathological argument, not a budget; on that run the longest argument, after
  the old clip, was 80 — keeps a structure as a structure while it fits, and when it does clip
  something records the true length under `_truncated` — so the console can
  say how much of how much it holds instead of leaving an ellipsis to be read
  as the whole thing. `make_tool`'s refusal path records the params
  it was asked for, the same as the path through.

- **A trace row opens where it sits, instead of covering the page.** Clicking
  a call used to throw a dialog over the trace: reading two calls meant
  opening and closing two of them, and the list you were reading vanished
  behind the thing you asked about. The row is now a disclosure — call and
  result unfold underneath it, inside the list, as many at once as you like.
  Both panes wrap, which the dialog's did not: a path that was stored whole
  was cut at the pane's edge, so the console looked like it was hiding
  something it was not.

- **What the board adds up to.** The Every-post tab rendered one row per
  thread — on most runs, one row — a pulse line, and then half a page of
  white space, under a run whose 104 posts are the only record of how ten
  strangers divided a case between them. Under the list now: six figures
  (posts and characters, who spoke of the team and who never did, the span,
  the median gap between posts, the longest silence and who broke it); the
  tag mix as one bar and again per speaker, so a team of reporters reads
  differently from a team that asks; a **who named whom** matrix built from
  the agent ids written in post bodies, where the empty rows say as much as
  the full ones; every **hold, veto and stop** on the board, with the
  harness's own marked as its own — on BelkaCTF #6 that is three claim
  violations and a record rewrite nobody would otherwise read; the **paths
  the posts cited**, counted and linked where the run kept the file; and the
  three longest silences with the line that ended each. Every figure is
  counted from `threads/` on disk by a pure module with its own tests —
  nothing here is a model's summary of what it thinks happened. A new
  `GET /api/swarms/:id/posts` returns every post across every thread, bodies
  included, because the swarm view ships only each post's clock, author and
  tag.

- **Every line of reasoning in every run rendered blank.** The harness writes
  a reasoning event as `logEvent(cwd, agent, "thinking", {}, { text, chars })`
  — empty args, the text in the **result** — and the console read `args.text`.
  It printed the empty string, in the raw trace, in an agent's own trace and
  in the "right now" strip, for every reasoning event since the tab existed.
  Two things hid it: the row also echoed `→ {"text":"…","chars":694}` on the
  right, so it read as a formatting quirk rather than a missing field; and on
  the BelkaCTF #6 run three of ten agents — every agent on
  `azure-foundry/grok-4.6` — genuinely emitted no reasoning at all, which made
  a reader's "the thinking blocks are empty" look like a fact about the
  models. The renderer now reads `result.text` and falls back to the old args
  shape so archived traces keep working, and the reasoning row no longer
  repeats its own text as a result.

- **THINKING is a document, not a list.** Reasoning is the one thing in a
  trace written in sentences, and it was clipped to whatever fitted between
  the clock and the duration on a single line. It is now one wrapped block per
  turn, the clock in the margin, the agent's colour down the side. Where the
  harness kept only an opening, a note under the block says how much of how
  much — measured from the text in hand, so a run recorded under the old
  240-character limit is described honestly rather than by today's constant.
  That limit itself is now 2,000 characters: 240 was barely the first
  sentence, so the reason an agent changed direction was never in the record,
  and at 2,000 a ten-agent run's whole trace is still under a megabyte.

- **An empty panel says which kind of empty it is.** "No trace lines —
  traces/events.jsonl is empty for this selection" was shown to an agent whose
  model returns no reasoning, to an agent with seven hundred lines and no
  failures, and to an agent that died before its first turn. The THINKING
  empty state now asks the harness for the per-agent reasoning census — one
  request, `limit=1`, using the new `matched_by_agent` on the traces API,
  which counts the *filtered* set per agent — and says which of three facts it
  found: this model returned none anywhere in the run (naming the models that
  did, with their line counts), this agent alone was quiet while its shipmates
  on the same model were not, or nobody in the run reasoned at all. The other
  lenses get their own sentences: nothing failed, it never posted or read the
  board, it left no trace at all.

- **"Right now" is not a thing a finished run has.** The Agents tab opened
  with five unlabelled rows of raw trace above the agents themselves — on a
  run that had ended, always the same five: `session end`, `session end`,
  `done`, `inputs check`. They were written to show a live team's newest
  lines and nobody had asked what they become once the team has gone home.
  A live run keeps them, with a heading that says what they are; a finished
  one opens on its agents.

- **The run's header is the run, and the page below it is the work.** Three
  things moved. The numbers and the team now sit side by side in the band
  instead of stacked, so neither the vitals nor a box of ten agents owns the
  full width and the right half is no longer empty at every size. The four
  setting chips — Herdr panes, hard-kill, tool forging, the inputs guard —
  left the band entirely: each was already stated where it is used, and all of
  them are now together under **the frame it ran under** in "How this run was
  started", beside the command, with the network allowlist, the toolbox sets,
  the catalog, the quarantine and the per-agent cap that were never shown at
  all. And the section tabs moved up into the band as one row, groups divided
  by a rule rather than by four labels that read as tabs nobody could click.
  The white page now opens on the work itself rather than on four rows of
  navigation.

- **A name is not permanent, and the console now says so.** `name()` can be
  called again whenever the work changes, and on a real run it is: one agent
  opened as "Laptop Triage" and four minutes later was "Dependency &
  Timeline"; another asked for "iPhone identity", was refused because a peer
  already answered to it, took it a second later anyway and renamed itself
  "Docs and money" half a minute on. `names.json` keeps only the last of
  those, so an agent's page showed one title for a decision it had made three
  times. The page now carries the whole sequence — when it named itself, when
  it renamed, when it kept the name and rewrote the job, and every refusal
  with the peer that caused it, which is how two agents worked out they were
  about to do the same work. It reads the trace route rather than the view's
  tail, because an agent names itself in its first minute and a fifty-minute
  run has long scrolled past it.

- **The team, where the model identifiers used to be.** A run's header
  carried a row of grey pills reading `azure-foundry/DeepSeek-V4-Pro`,
  `lmstudio/qwen3.8-27b-uncensored` — the one fact about a mixed team a reader
  cannot act on. It said nothing about who ran on what, what those agents
  called themselves, which of them finished, or where the money went. The
  strip is now one column per model: the agents on it under their own chosen
  names, a dot each for finished / working / quiet / reaped, the model's spend
  and its share of the bill, and every name a link to that agent. Ten agents
  across four providers and one local model is the most interesting thing on
  the page, and it is finally legible.

- **Seven things the console was getting wrong, found by reading it over a
  finished run.** The ledger's timeline wanted 1,645 px and got a horizontal
  scrollbar with its last column cut off, on a screen with room to spare: the
  tables are fixed-layout with shares of the width now, machine strings break
  inside their cell, and the shell is 1,680 px rather than 1,440. The agents
  vital said "6 done" where ten had started and four had ended a provider
  error away from a marker — it reads `6 of 10 · 4 never finished`. A
  `work/*.md` was shown as a monospace block, which is the source of a
  document rather than the document; the report's own renderer moved to
  `ui/src/lib/markdown.ts` and draws them in both places. "Open in new tab"
  downloaded the file, because every artifact was served as
  `application/octet-stream`: the route sends a real content type and
  `content-disposition: inline`, `?download=1` is the one that saves, and the
  panel has a **View** and a **Download** button instead of one that did the
  wrong one. The goal library was a native `<select>` — a full-screen grey
  system menu listing names and nothing else — and is now a control this
  application drew, with a filter, each goal's check count and a warning on
  the ones with no definition of done. The kickoff's field labels wrapped and
  pushed their inputs out of line, so they are shorter and their boxes reserve
  the same height. And the Goal tab opens with **how this run was started**:
  the `swarm.sh start` command, with `--env` values redacted, recorded in the
  registry at kickoff and copyable — the first thing anybody asks of a
  finished run, and the one thing the console could not answer.

- **The forensic report is a document now, not a dump.** The old one opened
  with a key-value list and a numbered list of forty-word sentences, and its
  five-column timeline pushed the page sideways on every long evidence string.
  The cover carries the case number, one sentence of verdict and six numbers —
  findings, indicators, dated events, evidence files, elapsed, spend — so a
  reader decides from the first page how much of the rest they need. The
  findings are verdict cards grouped by confidence, each with its exhibit
  number and the source it rests on, because what a run stands behind and what
  it is only offering are not the same claim. The timeline is a rail rather
  than a table: stamp, claim, source, evidence, nothing to scroll sideways
  for. Every table is `table-layout: fixed` with breaking inside the cell, the
  contents page carries a line about what each section is for, and the print
  stylesheet gives the cover and the contents a page of their own. Two bugs
  went with it: `swarm.sh stop` deleted `netguard.allow` along with the pid and
  the port, so every report written after a run finished said "netguard
  allowlist not recorded" about a run whose allowlist had been enforced all
  along — the record is kept now, and an older run that lost it has its
  allowlist read back from the proxy log and labelled as the weaker source it
  is.

- **A run can install what the case needs, without root.** BelkaCTF #6 found a
  BitLocker volume hidden in an alternate data stream, recovered its recovery
  key from a note inside an iTunes backup, and then spent half an hour failing
  to open it: no `dislocker`, no libbde, no libvhdi on the host. The agents
  never asked for root — they ran `brew install dislocker` and then
  `pip3 install dislocker`, and netguard denied `pypi.org` seventeen times.
  B14 had already found this half of the problem on challenge 9 and only the
  toolbox half was fixed. `--allow-install` fixes the other half: `pypi.org`
  and `files.pythonhosted.org` join the allowlist, `PYTHONUSERBASE` points at
  `work/.toolchain/` inside the sandbox, and what a run installs goes when the
  run goes. Off by default, stated in the contract, recorded in the ledger,
  and offered as a switch on the console's Case card. Root stays refused on
  the examiner's host — these panes are the examiner's own processes, and the
  read-only guard over `inputs/` is exactly what root would undo; a case that
  genuinely needs a mount wants a disposable container (B17), and most do not,
  because libbde, libvhdi, libluksde and pytsk3 read those volumes in place.

- **The crypto toolbox set names the class, not one tool of it.** It gains
  libbde (`bdeinfo`, `pybde`), libvhdi (`vhdiinfo`, `pyvhdi`), libluksde and
  `qemu-img`, all of which read a volume without mounting it. `--toolbox auto`
  now reads the goal document and adds the sets it asks for, and the evidence
  catalog warns when it has just seen a BitLocker or virtual-disk signature on
  a run with no crypto set. The BelkaCTF run was started with `--toolbox dfir`
  and nothing connected "the goal says encrypted container" to "you did not
  ask for crypto" until minute forty.

- **A segmented image is catalogued once.** libewf resolves a whole set from
  any one segment, so `--catalog` was producing an identical partition table,
  body file and timeline for `.E01` through `.E06` — six catalogues of one
  8.7 GB disk, and six times the minutes. The continuations are counted and
  named in `catalog/README.md` instead, so the gap does not read as a file
  that was skipped.

- **A provider failure is an event, not a silence.** Both `deepseek` agents on
  the BelkaCTF run died six seconds apart on `402 Insufficient Balance`. The
  console counted them among "10 working" for the rest of the hour, the board
  said nothing, and the idle watchdog spent all three of its nudges on each of
  them against retries that could only fail the same way. A turn that ends in
  a provider error now writes `agent_error` to the trace and posts the
  provider's own words to the board, and the watchdog leaves that agent alone
  until it works again.

- **A local model gets its first turn.** The LM Studio seat took about four
  minutes to read a 10 KB contract and was nudged twice before it had emitted
  a token; `--idle-sec` is tuned to cloud latency. A seat on a locally served
  model now has `--local-first-turn-sec` (600) before its first silence counts.

- **The package stops carrying the evidence it says it leaves behind.**
  `package` excludes `work/extracted/` and `work/quarantine/` and then wrote
  35 MB of registry hives and browser databases from the agents' own scratch
  directories. Provenance from the trace was tried and dropped — it identified
  0 of the 15 files it had to — so the rule is what a handover is for: binaries
  over `SWARM_PACKAGE_MAX_BINARY_KB` (256 by default) stay in the sandbox and
  are named with their hashes in `LEFT-BEHIND.txt`, next to the hash every one
  of them already has in `artifacts.json`.

- **The swarm page's tab strip stops pretending.** `THE RUN`, `EVIDENCE`,
  `THE FRAME` and `OUTPUT` were small-caps spans inline with the pills in one
  wrapping row: four things that looked like tabs, were not clickable, and
  could wrap away from the tabs they labelled. Each group now has its own row
  with the label in a column of its own. The Tools tab's empty state says
  which of three states it is in — forging off, forging on with N hints and
  nothing forged, or nothing seeded — because on this run an operator read it
  as "the agents are not forging" while the harness had asked five times.

- **The console can start a case, not just a task.** The kickoff form had the
  team, the caps and the read-only inputs, but none of the settings that turn
  a goal into an investigation, so every forensic run so far had to be typed
  at a terminal. `/new` now carries a **Case** card: the evidence catalog
  (the first pass over the inputs, refused without an input set, because a
  first pass over nothing is a kickoff that fails three minutes in),
  quarantine, the toolbox sets, a per-agent USD cap, the case id and the
  examiner. They reach `swarm.sh` as `--catalog`, `--quarantine`,
  `--toolbox`, `--cap-per-agent`, `--case-id` and `--examiner`, and the
  command preview shows them; a per-agent cap above the swarm's own cap, an
  unknown toolbox set and a case id or examiner that has no business on a
  command line are all refused in the browser rather than in a shell job
  somebody has to go and read. First used to start the BelkaCTF #6 run from
  the console.

- **A mark, drawn on the palette the console already had.** Two brackets
  holding five peers: the brackets are the harness, the part that is not
  negotiable, and inside them five agents of five specialisms, all the same
  size because none of them outranks another and nothing was handed out. The
  five colours are `brick`, `slate`, `saffron`, `kelp` and `moss` from
  `ui/src/index.css`, so the mark and the product it belongs to use one
  palette rather than two. `brand/` holds it for a dark ground, for a light
  one, and in `currentColor` for print and for anywhere colour is lost, with
  the usage rules beside them. The console header carries it, reading those
  tokens as CSS variables rather than repeating their hexes, so a retuned
  palette moves the mark with it; the tab icon, until now three dots on a
  teal square that matched nothing, is the same mark on the console's own
  band colour; and the README shows it above the title, switching with the
  reader's theme.

- **What a repository needs before it is public, and not a line more.** The
  Apache licence covers the code; two things it deliberately does not cover
  are now written down. `CLA.md` is the contributor agreement: it leaves the
  contributor's copyright with them and keeps a later decision about the
  project's own terms with the maintainer, which is a decision that stops
  being the maintainer's the moment one outside patch lands without it. It is
  referenced from the contributing guide and ticked in the pull-request
  template. `TRADEMARK.md` says what section 6 of the licence means in
  practice: fork freely, give the fork its own name, and use the name
  truthfully to refer to this project. A forensic tool has a reason to care
  which build a result came from.
- An issue chooser (`.github/ISSUE_TEMPLATE/config.yml`) that routes a
  vulnerability to the security policy rather than to a public issue.
- The upstream licences in the credits: Herdr is Apache 2.0 and Pi is MIT,
  both permissive, and neither is bundled here. Worth stating in a repository
  that cannot run without either of them.

- **Local models.** A team served from this machine or this network — a
  `models.json` provider on loopback, a private range or `.local`, or Pi's
  `llama.cpp` provider — is recognised at kickoff. It bills nothing and Pi
  reports its cost as an exact $0, so the USD cap could never stop it: such a
  team must be given `--cap-tokens N`, `budget.json` records `metered: false`
  and `cap_tokens`, the cap machinery brakes on tokens (`TOKEN_CAP_STEER`),
  and the summary speaks in tokens rather than "$0.00 spent". Before any
  pane opens the kickoff probes the server: that it answers, that it has the
  model, and, for Ollama, the context it will really give against what
  `models.json` declares; a missing `compat` block is warned about. A keyless
  local provider gets a BLOCKER with the placeholder `apiKey` to add rather
  than a pointer to `pi /login`, and `--key-from-env` is refused for it. The
  allowlist takes the literal host from `baseUrl` and its other spelling
  (`127.0.0.1` ↔ `localhost`); IPv6 literals no longer break `host_of_url`.
  `--local-only` turns the allowlist into the local endpoints alone
  (`netguard --only`) and sets `PI_OFFLINE=1` in the panes; the registry
  records `net: "local"`, `metered`, `cap_tokens` and `local_models`.
  `--cap-usd` is now checked to be a number. The console follows: the model
  picker lists every local provider from `models.json` even when Pi omits it
  for want of a key, readiness says "local · needs a placeholder apiKey"
  instead of "not logged in", the kickoff form has a token cap and a
  "Local only" network mode and refuses the wrong combination before
  `swarm.sh` has to, the budget tab speaks in tokens and says "free" when
  nothing was charged, and the fleet's spend line counts free runs
  separately rather than as "$0.00 of $0.00". Plan and evidence:
  `docs/local-models-plan.md`.
- **A forged tool can outlive its sandbox.** `--tools-from DIR` seeds `tools/`
  from a library of tools written in earlier runs — one directory per tool with
  its manifest and script — so they are in every agent's list from the first
  turn with their author and version kept. `swarm.sh tools <id>` lists what a
  run forged and `--save DIR` copies it into such a library. Six Windows cases
  rewrote an event-log filter and two rewrote a prefetch parser under different
  names, because tools died with the sandbox.
- **`make_tool` answers a near-duplicate.** Before anything is written it looks
  for a tool that already does this: the same runtime, overlapping parameter
  names and a description made of the same words. The refusal names the tool
  and its author, so the agent calls that instead of forging one capability
  under a second name — which two seats did six seconds apart on the Azure run,
  before either announcement reached the board.
- **Three network settings at kickoff instead of one switch.** The console's
  kickoff form asks what the panes may reach: *Guarded*, netguard's allowlist
  and nothing else, which stays the default; *Guarded + hosts*, the same
  allowlist plus the names you give, one `--allow-host` each; or *Open*, which
  takes the guard off and says so. Host names are validated before they reach a
  command line, at most twenty, and the old `netguard: false` body still means
  *Open*. The registry records the setting, so a run can be asked afterwards
  what network it had — which a forensic report has to be able to answer.
- **The seat travels with the post.** Every board post carries the author's
  seat in its front matter, and the console shows it under the agent id on the
  board and beside the author in the ledger. An agent id (`s864a06`) belongs to
  one run; the seat ("Key material and cryptography") is what a reader follows
  and the only part of the identity that means the same thing in the next run.
- **Forensic runs.** `--catalog` runs the standard first pass over the inputs
  once, before the agents start (partition tables, body files, MAC
  timelines, path lists; Volatility's process, command-line, network and
  injection lists for a memory image) into a read-only `catalog/` rendered
  into `SWARM.md`. `--toolbox dfir` checks the forensic tools on the host
  into `toolbox.json` and the contract, with install commands for what is
  missing (`--toolbox-required` makes that a blocker). `--quarantine` makes
  `work/extracted/` and `work/quarantine/` no-exec at the kernel
  (`fsguard.sh --noexec`) and strips execute bits there. `record` and
  `ledger` tools keep a shared ledger of dated events, indicators and
  findings with their evidence, deduped across authors, rendered by the
  harness into `ledger/ledger.md` after every record. `--seats dfir` (or a
  `## Seats` list in the goal) gives every agent a seat before the first
  post. `--cap-per-agent USD` stops one seat over its own budget without
  stopping the swarm. `--allow-host` adds a host to the netguard allowlist.
  `--case-id` and `--examiner` go into the contract, the registry and the
  summary. `swarm.sh summary` prints a run summary from the files;
  `swarm.sh package` writes the hand-over with a hashed manifest. See
  `docs/improvement-plan.md` for where each of these came from.
- **Azure OpenAI** as a team provider: `azure-openai-responses/<model>` in
  `--models`, the key variable and the resource host known to the kickoff
  (from the shell or Pi's credential store, with a warning and
  `--allow-host` when neither has it), the Azure settings forwarded to the
  panes. Any provider defined in Pi's own `models.json` — an Azure AI
  Foundry resource serving Grok or DeepSeek deployments, a gateway, a local
  server — now contributes the host of its `baseUrl` to the netguard
  allowlist, so a mixed team of third-party models on one Azure resource
  needs no `--allow-host`. See `docs/credentials-and-teams.md`.
- **Lessons from the first forensic run.** A shell write to an unclaimed
  `work/` file becomes the writer's claim instead of a notice; the agent
  whose `done` creates the sentinel prompts every idle peer once through
  Herdr (`await-done.sh --nudge` does the same from outside); the eighth
  `bash` call with the same command word earns a hint to forge a tool;
  `swarm.sh stop` records `done` when the sentinel exists; the Budget tab
  shows spend by model and marks agents over their own cap; the agents'
  prompt sends scratch files to `work/<id>/`; an idle watchdog
  (`scripts/idle-nudge.sh`, `--idle-nudge-sec`) prompts an agent that has
  made no tool call for three minutes to continue, and to hold `wait` open
  instead of ending its turn. The evidence catalog also reads a logical
  volume image with no partition table (the second challenge's raw NTFS
  volume was skipped at first). A change seen across a `bash` call is
  charged to it only when the command names the path or the file has
  stopped changing and is not a peer's scratch file: a peer's long shell job
  no longer gets every overlapping call blamed for it. The
  console's swarm page gains a Ledger tab: the events, indicators and
  findings the agents recorded, with authors, seats and evidence, live.

- **Read-only inputs** (`--inputs DIR`): hand the swarm a directory it can
  read and never change. The kickoff copies it into `inputs/` with no write
  bits, keeps a pristine clone and a hashed manifest; `edit`/`write`/
  `claim_file` refuse it, a shell write is detected and healed from the clone
  and announced, and where the host can (macOS `sandbox-exec`, Linux mount
  namespace) the whole pane runs with `inputs/` read-only at the kernel
  through `scripts/fsguard.sh` and a `ZDOTDIR` hook. Each agent records what
  guarded it (`inputs_guard`), an `inputs` tool lists the files, `done`
  records an `inputs_check`; a forged tool gets the same bracket as `bash`,
  and a sweep at every turn end heals what a background process changed. The console offers sets from
  `SWARM_INPUTS_ROOT` on the kickoff form and shows the inputs, the guard per
  pane and the healed writes on the Files tab. `--inputs-enforce on` refuses
  to start without a kernel guard. See `docs/inputs.md` and ADR 0005.
- **Forged tools** (`--allow-tool-forging`, off by default): an agent writes a
  tool with `make_tool` — python3, node or bash, JSON on stdin, stdout as the
  result — and every peer's harness registers it as a real tool on its next
  `inbox` / `wait`. `tools/` is harness-owned; names are exclusive; the author
  owns replacements while active; scripts must match their manifest's hash to
  run; timeouts kill the process group; output is capped. A Tools tab in the
  console shows each tool's script and calls; the trace marks forged calls.
  Proven with the real Pi loader and with two Pi agents on the scripted
  provider. See `docs/forged-tools.md` and ADR 0004.

- **A documented use case**: `docs/use-cases/dfir-web-server-case/` — seven
  agents on two providers investigating a 26 GB forensic case handed over
  as read-only inputs, with the board, the trace, the report, the forged
  tool, console and pane captures, and the bill.

### Added

- **`swarm.sh report <id>`: one self-contained document to hand over.** Cover,
  summary of findings, scope and evidence with a sha256 per file, the timeline
  and the exhibits, the method, the artifacts with their hashes, the
  limitations and the chain of custody — plus the swarm's own
  `work/report.md` reproduced verbatim with its headings demoted so the
  document keeps one outline. Exhibit numbers are the ledger's own `seq`, so
  the console, `ledger.jsonl` and the report all name the same row. It fetches
  no stylesheet, script, font or image: it is read in a room that may have no
  network, years after the run. There is no Markdown library either — none of
  the eighteen delivered reports contains an image, a link or raw HTML, so a
  hundred-line renderer covers the vocabulary and the repo keeps its one
  runtime dependency. `--pdf` prints it through Chrome, Chromium or Edge when
  one is installed; `--lint` checks the citations; `package` writes it too.
- **The print stylesheet, which is where "excellent PDF" actually lives.** A4
  page box, `break-inside: avoid` on every exhibit and row, `break-after:
  avoid` on headings, widow and orphan limits, `thead` set to repeat so a
  forty-row timeline carries its column headers onto every page, a 64-character
  hash that wraps instead of overflowing, and chips that keep their ground
  under the printer's "no background graphics" default. What it does *not* do
  is claim page numbers: `@page` margin boxes are unimplemented in Chrome and
  a `position: fixed` running head is anchored to the first page there, so the
  browser numbers the pages and the document asks to be cited by section. The
  document says so rather than being quietly different.
- **`artifacts.json`: every file under `work/`, hashed.** Walked to any depth
  and streamed, so the extracted tree does not have to fit in memory.
  `work/extracted/` and `work/quarantine/` are hashed and listed with
  `packaged: false` — the ledger cites those paths and sometimes their hashes,
  and a reader has to be able to check one without the package carrying live
  material. Symlinks are named and skipped, never followed.
- **The dossier as files, from the console.** `/api/swarms/:id/dossier/`
  serves `report.html`, `summary.md`, `artifacts.json`, `ledger.jsonl`,
  `ledger.md` and `trace.jsonl` with a filename. Nothing is newly exposed; the
  view routes already returned all of it without a token. What is new is that
  the trace arrives whole — `/traces` clamps to the last 5000 events, which on
  a long run drops the beginning of the case — and that the path says
  "dossier" rather than "download", which is a common content-blocker pattern.
- **A Report tab, and a tab strip in four groups.** The panel shows the report
  at A4 proportions beside every dossier file with its size and hash. The
  strip had grown to eleven tabs with no order to it and the evidence hashes
  were hidden inside `files`; it is now *the run*, *evidence*, *the frame* and
  *output*. `docs/improvement-plan.md` B8 claimed the console linked the
  package; after this it does.
- **`HashChip`, `EvidenceRow`, `DownloadRow`, `FileFacts`, `PrintSheet`.** The
  design system's new pieces, so an input, an artifact and a dossier file all
  say the same thing the same way. `HashChip` falls back to a hidden textarea
  when `navigator.clipboard` is missing, which is exactly the case over plain
  http to a LAN address.
- **The design system carries the evidence components.**
  `ui/src/design-system.ts` and `.design-sync/` are on the same branch as the
  components now, which is where they have to be: the barrel is
  hand-maintained, and a component added to `ui/src/components/` and not added
  there is invisible to every future sync with no warning. `HashChip`,
  `EvidenceRow`, `DownloadRow`, `FileFacts` and `PrintSheet` are in the barrel
  and the `componentSrcMap`, each with a preview, and the conventions header
  states the rule they exist for: anything that names a file names its sha256
  beside it. `cssEntry` is re-pointed at the rebuilt stylesheet — a stale hash
  there ships the old CSS and renders unstyled with no error.
- **The sixteen use-case goal documents are in the goal library**, each with a
  header naming the run it came from and the filenames to change. The library
  went from three, two of which draw a pelican, to nineteen.

- **Six tools for the gaps the corpus left.** `esedb_query` closes the one a
  delivered report recorded in its own words — *no `esedbexport`, so
  `WebCacheV01.dat` and `spartan.edb` could not be parsed as tables* — and the
  same wrapper opens SRUDB.dat and Edge's database. `browser_history` copies a
  database and any `-wal` beside it and opens the copy read-write so the
  write-ahead log is replayed rather than ignored, which is what made
  `sqlite_query` fail on those files in one case. `usn_journal` parses
  `$UsnJrnl:$J`, skipping the sparse front and saying where it started.
  `amcache_apps` reads whichever of the two Amcache layouts the hive has and
  names it. `recyclebin_i` parses `$I` metadata and refuses to decode a path
  from an unknown header version. `yara_scan` sweeps with rules the caller
  names — no rule set ships here, because a stale rule reads like a finding.
  `esedbexport` joins the `dfir` toolbox set.

### Changed

- **`record` requires `source` and `evidence`.** Across fifteen cases all 1501
  ledger entries already carried both, so this costs a working run nothing;
  what it stops is the entry that reads like a conclusion and cannot be
  checked.
- **The fixture is a forensic case.** A compromised web server with hashed
  evidence, an attack path, extracted material, a Prefetch timeline and a
  ledger whose entries cite their source; then a USB policy question, a
  ransomware triage, a single-hive triage and a carve stopped by its cap. The
  run ids and the shapes they exercise are unchanged, so the console coverage
  is the same. What changed is that somebody evaluating a forensic tool no
  longer opens it on `pelican-svg` and `raytracer-stopped`. Re-seeding the
  same directory works now, too: `seedInputs` leaves the tree read-only and
  `rm` could not clear it.
- **The corrected report-citation rule.** `docs/improvement-plan.md` B10
  proposed "every `## N.` section cites at least one path under `inputs/`,
  `catalog/` or `work/`". Measured against the eighteen delivered reports that
  rule rejects **60 of their 127 numbered sections**, because a forensic
  citation is usually not a path — it is an inode, a record id, an event id or
  a registry key. The rule that ships accepts any of those, and all 127 pass.
- **`--color-moss-ink` and `--color-slate-ink` are tokens.** `Chip` had been
  hard-coding `#2f5a1c` and `#2c4660` while every other tone used a token;
  two other call sites moved onto them.
- **Every library tool works on more than one case.** `icat_root`,
  `master_icat` and `hdfs_node_icat` hard-coded the image they were written
  for, so they were unusable anywhere else. Those filenames are defaults now
  and `image` and `offset` name any other. Measured over the eighteen traces
  under `docs/use-cases`: `catalog_grep` was called 152 times, `regkv` 84,
  `evtx_query` 64, and four tools never. That is in the library's README as a
  measurement, not a verdict — three of the four were written late, and one is
  the only AES Crypt implementation here. Nothing was deleted.
- **`split_failures` reaches the console.** A pane that fell back to its own
  tab is a pane the operator is not looking at, and the kickoff has always
  recorded it.

### Fixed

- **Who last wrote an artifact is the snapshot, not the trace.** The index
  treated `claim_file` as a write, so a lease looked like authorship. It now
  reads `history/`: a claim is a lease, the snapshot names the writer.
- **The Report tab's download rows had no hash.** They were a hardcoded list
  with no size and no sha256, while the component next to them exists to
  carry both. `GET /api/swarms/:id/dossier` now returns the handover as one
  product — the HTML, the artifact index, and every file with the hash of
  the bytes it is — so the number beside the button is the number of the
  file the button writes. `package` builds that set once instead of three
  node processes hashing `work/` twice.
- **Four icat writers could land under `inputs/`.** A prefix check on the
  path the caller typed misses `work/../inputs/x` and an absolute path.
  `icat_extract`, `icat_root`, `hdfs_node_icat` and `master_icat` now resolve
  the destination the way `aescrypt_v2_decrypt` already did, and refuse
  before `icat` runs.
- **`.jsonl`, `.yaml` and `.xml` were text in the artifact index and binary
  on the console's work/ list.** One table now answers both.

- **`package` shipped less than the run produced.** It globbed
  `work/*.md`, so a timeline CSV, a JSON export and anything in a
  subdirectory were left out of the handover without a word, and it never
  copied `tools/` although the improvement plan said it kept the run's tools.
  It now copies every regular file under `work/`, the run's `tools/` with
  their manifests, `layout.json` and `netguard.allow`, and hashes all of
  them. `work/extracted/` and `work/quarantine/` stay in the sandbox on
  purpose — that material came out of the evidence and may be live — and the
  command says how many files it left behind. Symlinks are not followed, so
  a link an agent dropped cannot pull an outside file into the package.
- **The ledger and the trace are watched for growth, not for equality.** A
  peer recording a finding while another agent's shell call was running
  changed `ledger/entries.jsonl`, and the watch, which compared hashes,
  reported that peer's `record` as this call's unattributed write to a
  protected path. The two append-only files are now marked by length and by
  the hash of that prefix: a file that only grew is the swarm working, and a
  file whose existing bytes changed is a rewrite, reported as
  `record_violation` on the board with the path named.
- **Three library tools answered confidently when they had failed.**
  `extract_stream` ran `icat … 2>&1 | base64`, so an error message came back
  base64-encoded as if it were file content and the pipe made every call exit
  0; failures are now JSON carrying icat's status and its stderr.
  `sigscan_e01` fell back to a hard-coded 42949672960 bytes whenever
  `img_stat` failed and reported that as the image's media size, so on any
  other image it walked a range that does not exist and called the result
  "no hits"; it now refuses unless the caller bounds the scan with `length`,
  says where the size came from, and lists ranges it could not read.
  `regkeys` decoded every `REG_BINARY` value as UTF-16LE with
  `errors="replace"`, turning a ShimCache or UserAssist blob into mojibake
  that reads like text — and because `"replace"` never raises, the hex
  fallback beneath it was unreachable; values are now rendered by their
  registry type, with binary as hex, matching what `regkv` and
  `reg_hive_query` already answered for the same value.
- **Two claims in `docs/improvement-plan.md` that were not true.** B8 said
  the console links the handover package and B12 said the console offers the
  tool library at kickoff; it does neither. Both rows now say what ships and
  what does not.

- **Three claims in the documents that were not true.** The security policy
  told a reporter to email the address on the maintainer's GitHub profile,
  and there is no public address there; it now names private vulnerability
  reporting first and the profile's own contact route as the fallback. Its
  out-of-scope entry said the console's reads are open to the LAN without
  saying what that returns: the goal document, the board, the whole trace,
  every revision of every `work/` file, any artifact, and the `swarm.sh`
  output of each start, stop and reap. The release checklist claimed no
  personal paths were in tracked files, while the maintainer's home path
  appears 2,594 times in the published pane captures and custody sections;
  the row now says what is there, that it is `~/DFIR/SampleCases` and
  nothing else, and why rewriting a verbatim terminal capture would cost it
  the thing it is published for.
- One broken relative link, out of every link in 259 Markdown files: the
  browser-policy case pointed at pane captures that were not kept for that
  run.

- **Six correctness bugs in the seeded tool library, and a test that keeps
  the library honest.** These are the tools agents wrote during the published
  cases and that every later run is handed, so a wrong answer from one of
  them is a wrong answer in a report.
  - **The BitLocker parser read four fields from the wrong offsets** and
    still printed well-formed JSON — the worst way for a forensic tool to
    fail. It took the metadata size from the block header's own size field,
    fell back to a `uint32` at the same offset when that looked too small
    (yielding the size and the version read as one number), took the
    encryption method 20 bytes past where it lives, took the VMK protection
    type 2 bytes short of it, and started entries at 64 rather than 48. Every
    offset now follows the layout libbde documents, the metadata size is read
    from the metadata header and checked against the copy the format keeps 12
    bytes later, and a disagreement is a refusal rather than a walk over
    arbitrary bytes. The fixture in the test was built to the parser's own
    layout, so it agreed with whatever the parser did; it is rebuilt from the
    documented layout, and the old parser cannot read it at all.
  - **The AES Crypt tool's `inputs/` guard was a string prefix**, which
    `work/../inputs/x` and any absolute path walked straight past. It
    resolves the destination and refuses anything landing in the read-only
    inputs or outside the run directory. A truncated file raised `IndexError`
    where the harness can only relay a traceback; lengths are checked and
    named instead. The manifest's example carried a real case password, which
    an agent would copy into a live call; it is a placeholder now.
  - **`icat_root` exited on `icat`'s code with nothing on either stream**, so
    a failure reached the agent as a bare non-zero with no way to tell a bad
    inode from a missing image. It reports the exit code and `icat`'s stderr.
  - **`grep_filelist` raised on an invalid pattern and on a missing catalog**;
    both are JSON refusals now, the pattern is compiled once, and a result set
    cut to the first 100 says so instead of reading as the whole answer.
  - **`master_icat` read stdin twice**, so the second reader got EOF and, under
    `set -e`, the script died before `icat` ran — the tool never worked. It
    reads its arguments once, validates the inode, refuses an output that
    escapes the run directory, and its refusals reach stdout instead of being
    swallowed by command substitution.
  - **Five manifests no longer matched their scripts** after these edits, and
    the harness refuses a tool whose bytes disagree with its manifest. All are
    rehashed and their versions bumped, the library README is regenerated from
    the manifests (its `fls_root` row had described a tool two versions old),
    and two new tests assert both: every manifest hashes the script beside it,
    and the table says what the manifests say. That drift was invisible until
    a run needed the tool.

- **Thirty-two findings from a second review, one commit each.** The ones
  that changed what the harness does:
  - **A per-agent cap stop wrote the swarm's sentinel**, so `--cap-per-agent`
    ended the whole run instead of one seat — the opposite of what the flag
    documents, and live from the moment the cap first armed. `done` treats
    `reason: agent_cap` as one seat leaving, and the harness stop passes the
    same. The 15-second cap timer now checks the per-agent cap too, so a seat
    inside a long shell call or a `wait` is steered when it passes its own
    ceiling rather than at the next turn end.
  - **A post's `to` field could forge board frontmatter.** A newline in it
    wrote further keys, and the last key won, so a peer's post could read as
    `from: system`. Values are flattened to one line, the first key wins, and
    a post's id comes from its filename rather than from the text.
  - **A forged tool inherited the pane's whole environment**, provider API
    keys included. It now gets PATH, proxy, locale and the run's own `SWARM_`
    context; the console's mutation token is denied by name, and the console
    no longer hands that token to the `swarm.sh` it spawns.
  - **A manifest's `sha256` could be empty or a stub**, which made the
    bytes-match check vacuous; it must be a 64-hex digest, a tool seeded by
    `--tools-from` is sealed into file history at kickoff so its hash is the
    harness's, a directory named after a reserved tool cannot load, and a
    rewritten tool no longer counts as a peer's forge.
  - **Allowlisting a host opened every port on it.** `127.0.0.1` for a local
    model admitted a CONNECT to SSH, to this console, to anything listening.
    An entry with no port is 443 alone; local endpoints carry `host:port`.
  - **The console's API answered any origin** (`access-control-allow-origin: *`
    on every route and the event stream), so a page the operator had open
    could read a run's board, trace, goal and spend. The header is gone, the
    token is a bearer header rather than a query parameter, and an artifact
    page is served under a CSP that cannot fetch.
  - **The reaper killed working agents**: a 300-second silence is normal for a
    `vol` or `fls` over an image, and `swarm.sh status` reaped as a side
    effect of looking. The threshold is 960 seconds, above the catalog's own
    step, a pane Herdr reports as `working` is never reaped, and `status`
    does not reap at all.
  - **Forged-tool output was capped after the child finished**, so a runaway
    script could fill memory first; it is capped as it is read.
  - **`done` could skip the late-correction check** by naming an output file
    that does not exist, or one outside the sandbox.
  - Claims follow the real path rather than a symlink alias; `names.json` is
    harness-owned; the bash watch fingerprints the token cap and the metered
    flag, so a shell cannot lift a local run's only brake; `--env
    SWARM_FSGUARD` is refused whether or not `--inputs` was passed; the
    inputs size and file caps follow the links `cp -RL` will copy; a leftover
    netguard sidecar or idle watchdog from an earlier run is stopped at
    kickoff; the goal library skips a symlink; the overview labels a harness
    stop from the sentinel's own frontmatter instead of inferring it from
    spend.
  - **The evidence catalog** keeps a filesystem whose start sector is 0,
    names its output after the path under `inputs/` rather than the basename
    (two images with the same name no longer overwrite each other), and runs
    Volatility only on files that look like memory.
  - **The tool library**: `icat` and `grep` tools parse JSON instead of
    calling `eval`, extract and catalog tools fail loudly when the image or
    the catalog is missing rather than printing nothing, AES Crypt writes
    plaintext only after both HMACs verify, and the BitLocker parser reads
    the FVE metadata from the volume header offsets.
  - `--toolbox crypto` recognises `pyAesCrypt` as the AES Crypt tool, and
    `SWARM.md` lists a seeded library tool as case-specific.

- **The console's artifact route followed a symlink out of the sandbox.**
  `GET /api/swarms/:id/work/<path>` checked the path lexically and then served
  whatever it pointed at, so a symlink an agent's shell planted under `work/`
  was readable by anyone on the LAN, no token needed. The route resolves the
  file and serves it only when it really lives under `work/`; a test plants
  the link.
- **A forged tool's manifest could name an entry outside its directory.** The
  runner refused that already; the console's read route did not, so a
  manifest a shell rewrote with `entry: ../../..` disclosed the file it
  pointed at. Both go through one check now, an entry is a plain file name,
  and a symlink out of the tool's directory is refused to read and to run.
- **`names.json` was not a harness-owned path.** An agent could claim it and
  rewrite what its peers called themselves through the guarded `write` tool.
  It is in the protected list now.
- **`swarm.sh say` posted without the lock-table mutex**, so an examiner's
  post and an agent's could take the same id. It takes the same mutex as the
  protocol and the reaper.
- Console: an undefined colour token left error notes uncoloured; the
  ledger's names went stale when only the names changed; two running swarms
  were never ordered against each other; a spend past the cap rounded to a
  whole multiple ("2×" at 150 %); the team panel keyed its fragments wrongly;
  and the kickoff form refuses a wall clock above 240 minutes and more than
  twenty extra hosts before the server has to.
- **The per-agent cap never fired.** `--cap-per-agent` was written into
  `budget.json` at kickoff and dropped by the first fold of session usage,
  because the record was rebuilt without the field; the cap then read as zero
  for the rest of the run. Nine forensic runs reported "0 cap steers" while one
  seat finished $1.26 over its cap. The field survives the rebuild now, and a
  test seeds a cap, folds usage, re-reads from disk and asserts the cap fires.
- The published run costs were wrong in both directions, and the case
  documents now carry the invoice rather than the harness's estimate. The
  Azure run was configured with a DeepSeek rate four times below Azure's, so
  it cost $37.03 and not the $24.68 it reported. The eight runs on DeepSeek's
  own API were billed at DeepSeek's peak rate, which is what Pi's catalogue
  carries, while all of them ran outside the peak window, where DeepSeek
  charges half; their DeepSeek seats cost half of what the console showed.
  A `cost` block holds one number, so the reported figure is an upper bound
  whenever a provider's rate depends on the hour.
- `herdr agent start` could hit `agent_pane_busy` on a pane whose shell was
  still starting (more likely with the fsguard hook) and abort the kickoff;
  the launch now waits for the pane to be at a prompt, up to 30 s.
- A large input (a 25 GB disk image) was read whole to hash it; hashing
  streams now, the manifest records mtime and ctime so an unchanged input
  is never re-read, and the inputs copy is an APFS clone where the
  filesystem allows it.
- `swarm.sh start` failed to write the registry on jq 1.6 (Debian 12,
  Ubuntu 22.04), where `label` is a keyword and can be neither a bare key nor
  a variable name; the key is quoted and the variable renamed.

## [0.3.0] — 2026-09-17

The open-source release. Renamed from "Simple Swarm" to **Agent Swarm**.

### Added

- Run a swarm on a Pi **subscription** (OpenAI Codex, Anthropic) with no API
  key, through Pi's own credential store; `pi auth check` gates every model
  before a cent is spent.
- **Mixed-model teams**: `--models "provider/id=count,…"` puts several models
  in one swarm; each agent's model is on the board and in `team.json`.
- A whole swarm end to end with **no provider at all** (`tests/mock-provider.mjs`,
  scripted turns), used for the cap-breach and runaway proofs.
- **Post-sentinel termination**: once `done/SWARM_DONE` exists every agent's
  session is ended at its next tool call, in-flight call included.
- The done sentinel is created with an exclusive `wx` write, so two agents
  finishing at once cannot both claim to have written it.
- **Goal library** (`prompts/goals/`, `/api/goals`), the live contract route,
  and `await-done.sh --checks-json` so the console and the CLI certify a run
  the same way.
- The console redesigned as a warm editorial control room: vitals band, the
  board as a story, the finish line, leases with expiry, team spend, the
  harness panel with a grace clock, the activity strip.
- The console, complete: per-agent colours, thread
  pulse lanes, agent chips with calls, thread overlays with compute budget and
  members, post sizes, the agents page with activity spans, failure ticks,
  token splits and context windows, trace filter chips, a CALL / RESULT modal,
  `/` to find, readiness-aware kickoff.
- One netguard sidecar **port per swarm**, so concurrent swarms never share a
  proxy.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, CI,
  issue and PR templates, Dependabot.

### Changed

- The goal document owns the definition of done; a goal without one is refused.
- Harness-owned paths cannot be written by agents; leases have expiries; threads
  have members and purposes; file history is content-addressed.
- Shell writes are detected, snapshotted and announced on the board rather than
  silently allowed.
- Threads are listed main first, then by most recent post.
- The README is a guide again; the protocol, usage, verified runs and
  troubleshooting moved to `docs/`.

### Fixed

- bash 3.2 empty-array expansions in `swarm.sh` and `netguard.sh`.
- A `pi auth check` failure exit that killed the preflight before it could
  print its blocker.
- The check-then-write race on the sentinel.

## [0.2.0] — 2026-09-16

- Web app: JSON API, SSE change bus, `swarm.sh` actions, fixture seed, API
  tests; Vite + React + Tailwind client; artifacts preview; model picker
  parsing `pi --list-models`.
- Stall reaping, the netguard egress allowlist (unprivileged netns or a local
  proxy), a real Playwright tool driving headless Chromium.
- Pane grid to N=30 across Herdr tabs and workspaces.

## [0.1.0] — 2026-09-16

- V1 N=2 local swarm: file mailbox, exclusive locks, done sentinel, event log,
  live Pi budget, `swarm.sh` kickoff, LAN debugger, file history and restore.

[Unreleased]: https://github.com/halilozturkci/dfirswarm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/halilozturkci/dfirswarm/releases/tag/v0.3.0
[0.2.0]: https://github.com/halilozturkci/dfirswarm/commit/d8e7e70
[0.1.0]: https://github.com/halilozturkci/dfirswarm/commit/04399a3
