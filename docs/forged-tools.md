# Forged tools

An agent writes a tool the goal needs and nobody has; the swarm gets it.
Off by default: `scripts/swarm.sh start … --allow-tool-forging`, or the
**Tool forging** switch on the kickoff form.

## What it looks like from an agent

```
tools()                       → { forged: [], hint: "Nothing forged yet…" }
make_tool({
  name: "count_lines",
  description: "Count the lines in a sandbox file",
  runtime: "python3",
  params: { path: { type: "string", required: true } },
  script: "import json, sys\nargs = json.load(sys.stdin)\n…print(json.dumps({…}))\n",
  example: 'count_lines(path="team.json")'
})                            → { ok: true, name: "count_lines", version: 1, sha256: "3f0a…" }
```

The harness posts on the author's behalf — *Forged tool `count_lines` v1
(python3): … It is in your tool list after your next inbox or wait.* — and
every other agent's harness registers it on its next `inbox`, `wait` or turn
end. The wake-up result says so:

```
wait() → { reason: "post", posts: […], new_tools: [{ name: "count_lines", by: "s99c600", … }] }
count_lines({ path: "team.json" }) → {"path": "team.json", "lines": 14}
```

## The contract for a script

- It is started as `<runtime> tools/<name>/run.<ext>` with the sandbox as its
  working directory. Runtimes: `python3`, `node`, `bash`.
- Its arguments arrive as **one JSON object on stdin**. Nothing on argv.
- Its result is **stdout**. Exit non-zero to fail; stderr is what the caller
  sees as the reason.
- `SWARM_SANDBOX`, `SWARM_TOOL` and `AGENT_ID` are set; colour is forced off.
- It is killed at `timeout_seconds` (default 30, max 120) — the whole process
  group, so a `sleep` it spawned dies with it. It is never killed for
  printing: the model receives the first 64 KiB of stdout (16 KiB of stderr)
  and, past that, a trailer naming the whole stream under `tool-output/`,
  with its size and sha256; the trace row names the same file
  (`full_output`, `full_stderr`). Read the rest with `read` and an offset,
  or `grep` it.
- The script is at most 64 KiB and the manifest lists at most 16 params of
  type `string` (with an optional `enum`), `number`, `integer`, `boolean`,
  `array` or `object`.

## What the harness enforces

| Rule | Why |
| --- | --- |
| `tools/` is a **protected path**: `edit` / `write` there are blocked, a shell write there is detected and announced, and the script's bytes must hash to what the manifest says or the tool refuses to run. | A tool is only what was announced. Rewriting one from a shell would put unreviewed code under a name every peer trusts. |
| The manifest's `entry` is a **plain file name inside `tools/<name>/`**. A manifest that names a path, or an entry that is a symlink out of the directory, is refused both by the runner and by the console's read route. | A shell can rewrite a manifest; that must not turn `tools/x` into a way to read or run a file anywhere else on the host. |
| Creating a name is an **exclusive `mkdir`**. | Two agents forging `count_lines` at once cannot both win; the loser is refused, not merged. |
| Replacing a tool is for its **author while active**, or anyone once the author is done or dead. Every version is a revision in file history. | A live author's work is not rewritten under them; a dead agent's tool is not a monument. |
| Names are `[a-z][a-z0-9_]{2,31}` and cannot shadow a harness or Pi tool (`read`, `bash`, `post`, `done`, `make_tool`, …). | The model has to spell the name back, and a forged `read` would be a trap. |
| No forging after `done/SWARM_DONE`. | The swarm is over. |
| Every forge, load and call is on `traces/events.jsonl` (`make_tool`, `tool_loaded`, and the tool's own name with `forged: true`, `by`, `version`, `exit_code`, `duration_ms`). | Agent-written code that peers run is the thing most worth watching. |

## What it does not do

A forged tool is a `bash` with a schema and a name. On the host it runs as the
user, in the sandbox, with the pane's environment — the same containment as
every other shell command, which is to say the netguard proxy and the write
guard and nothing else; in a VM it has the VM's containment (below). Read
[SECURITY.md](../SECURITY.md) before turning it on, and keep it off for goals
that do not need it.

A tool lives in its sandbox. Carrying a good one forward is an operator's act,
and there is a path for it: `swarm.sh tools <id> --save DIR` copies a run's
tools into a library, `--tools-from DIR` seeds the next run from one with the
author and version kept, and [`tool-library/`](../tool-library/README.md) in
this repository holds the thirty-two written during the forensic cases.
`make_tool` also answers a near-duplicate of a tool already on disk with that
tool's name and author rather than forging the same capability twice.

## Under `--isolation microvm`

The contract for a script is the same; where it is written and where it runs
are not.

- `make_tool` is a call to the hub, which forges on the host: it writes
  `tools/<name>/` and its history, as the seat whose channel asked. With
  forging off the hub refuses the call, whatever the extension in the VM
  believes.
- `tools/` is on the run's read-only floor in every VM, so no shell in a VM
  can rewrite a tool. The byte check still runs before every call.
- A tool runs inside the VM of the agent that calls it, as a process of that
  VM: the VM's network policy, the calling seat's writable directories, root
  in that VM. A peer's tool runs in your VM with your seat's reach, and its
  output goes to your `tool-output/<id>/`.
- A process in a VM speaks to the hub as that VM's seat, so a tool can post,
  publish or call `done` as the agent that ran it.
- A tool forged or re-forged a moment ago can read as its old bytes for about
  five seconds in another VM (virtio-fs caches what the host wrote). On a
  hash mismatch the runner waits six seconds and reads once more before it
  refuses the call.

## How it is wired

- `extensions/protocol.ts` — `validateToolSpec`, `forgeTool`, `listForgedTools`,
  `readForgedTool`, `runForgedTool`; `tools/` in `PROTECTED_PREFIXES`; tool
  files on the bash watch.
- `extensions/agent-swarm.ts` — `make_tool` and `tools`; `loadForgedTools` at
  `session_start`, `inbox`, `wait` and `turn_end`, registering each manifest
  with `pi.registerTool`; the base tool list applied with `pi.setActiveTools`
  because Pi's `--tools` filters by name and would drop a runtime tool.
- `scripts/swarm.sh` — `--allow-tool-forging` sets `SWARM_TOOL_FORGING=1` and
  `SWARM_TOOLS=<base list>` in every pane, drops `--tools`, records
  `tool_forging` in the registry, creates `tools/`.
- `scripts/ui/model.ts` — `SwarmView.tools` with calls, failures, users;
  `/api/swarms/:id/tools/:name` returns the manifest and the script, read-only.
- The console's **Tools** tab: one card per tool, the script as it is on disk,
  the last calls.

## Proof

- `tests/dry-run.test.ts` — the spec check, forge / list / read, the protected
  path, the author rule and the name race, the runner (JSON stdin, timeout,
  output cap, abort), and the shell-rewrite detection.
- `tests/pi-load.test.ts` — the real Pi loader: `make_tool` absent with forging
  off, present with it on, and a tool forged through it registered and run.
- `tests/ui-server.test.ts` — the view, the read route, the kickoff flag.
- `tests/model-teams.test.sh` — the flag reaches the registry and the sandbox.
- `tests/fixtures/mock-swarm-forge.mjs` — two real Pi agents on the scripted
  provider: one forges `count_lines`, the other wakes, sees `new_tools`, calls
  it by name; a reserved name and a takeover are refused; a failing tool is
  reported as a failure. See [verified-runs.md](verified-runs.md).

## What a manifest says about where a tool can run

`make_tool` takes an optional `requires`, the programs the script calls; the
manifest keeps it, and a VM run forged through the hub also records the
image the tool was forged against (`image_digest`). `tools --save` copies a
tool only as the version sealed into file history (a script and a manifest
rewritten together on disk are not that version) and writes, beside it, what
it ran with: the run, its image, its packs, and what the run installed.
In a VM a tool runs only as the bytes the hub says were sealed: the guest's
own view of `tools/` can lag five seconds behind a re-forge, and the bytes
are read again until they are the sealed ones or the tool is refused.
