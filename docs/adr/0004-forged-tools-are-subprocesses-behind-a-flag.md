# Forged tools are subprocesses, announced on the board, behind a flag

An agent can write a tool with `make_tool`; every peer's harness registers it
with Pi's runtime `registerTool` and runs it as a subprocess in the sandbox.
The feature is off unless the operator passes `--allow-tool-forging`.

## Context

A goal can need something no built-in tool does — a parser for one file type,
a checker for one invariant. Before this, an agent wrote a script under
`work/` and every peer had to know to call it through `bash`. That works but
it is not a tool: no schema, no name in the tool list, nothing in the trace
that says "this is agent-written code the team is running".

Pi supports registering a tool after the session has started, and activates
it automatically — but only when no `--tools` allowlist is in force, because
that list filters by name and a name chosen at runtime is never on it.

## Decision

- A forged tool is a **subprocess**: `<runtime> tools/<name>/run.<ext>`, JSON
  on stdin, stdout as the result, a timeout that kills the process group, an
  output cap. Not an in-process plugin: agent-written code never runs inside
  the harness's own process.
- **The allowlist moves into the extension** when forging is on: `swarm.sh`
  drops `--tools`, hands the base list over in `SWARM_TOOLS`, and the extension
  applies it with `setActiveTools` at session start. Forged tools then join
  it as they are registered.
- **The board is the registry.** `make_tool` posts the announcement itself;
  every harness loads manifests at its wake-up points (`inbox`, `wait`, turn
  end). There is no push channel and no daemon — the same files and the same
  polling the rest of the protocol already relies on.
- **`tools/` is harness-owned**, like `done/` and `locks/`: the only way to
  put a tool there is `make_tool`, which records the author, the version and
  the hash; a script whose bytes no longer match its manifest will not run.
- **Off by default**, because a forged tool is a `bash` with a schema on it.
  The operator who turns it on is accepting shell-level trust in what the
  agents write, and the console shows every script and every call.

## Alternatives considered

- One generic `run_tool(name, args)` dispatcher, always allowlisted. Simpler,
  no allowlist change — but the model never sees the forged tool's own schema
  in its tool list, which is the whole point of a tool over a script.
- Letting any agent replace any tool. Rejected: a peer who disagrees with a
  live author's tool should say so on the board or forge under another name;
  once the author has stopped, anyone may take it over.
- A cross-swarm tool library. Not now: a tool lives and dies with its run.
  Carrying one forward is a deliberate operator act.

## Consequences

- Concurrency: creating a name is an exclusive `mkdir`; the loser of a race
  is refused rather than merged.
- Observability: `make_tool`, `tool_loaded` and every forged call are on the
  event log; the console has a Tools tab.
- Containment is unchanged and documented as such in `SECURITY.md`.
