# The proof run: a real swarm with no key and no money

Fixtures call the protocol functions directly. That covers the file format and
the arithmetic, and it covers nothing about the part that actually breaks: Pi's
hook dispatch, the Herdr pane lifecycle, two independent processes racing for
the same lock, and the kill switch firing against agents that ignore it.

This run closes that gap without a provider key. Pi is pointed at a **local
scripted provider**, so everything except the model is real: real Herdr panes,
real `pi` processes, the real extension, the real file protocol.

## How it works

Three facts make it possible.

1. Pi resolves its config directory from `$PI_CODING_AGENT_DIR` before falling
   back to `~/.pi/agent` (`getAgentDir()`), so a throwaway directory can declare
   a provider without touching the operator's own Pi setup.
2. A `models.json` provider only needs `api` and `baseUrl`. `api:
   "openai-completions"` plus a `baseUrl` on loopback is a complete provider.
   (Give it an `apiKey` as well: Pi does not need one to reach a local server,
   but the swarm's credential preflight uses it as the proof that this provider
   is configured.)
3. The `cost` block is whatever you put in it, so the budget machinery runs on
   synthetic prices and produces real numbers to enforce against.

```jsonc
// $PI_CODING_AGENT_DIR/models.json
{
  "providers": {
    "mockswarm": {
      "api": "openai-completions",
      "baseUrl": "http://127.0.0.1:8787/v1",
      "apiKey": "mock-key",
      "models": [{
        "id": "scripted-1",
        "contextWindow": 200000,
        "maxTokens": 8192,
        "cost": { "input": 1.0, "output": 5.0, "cacheRead": 0.1, "cacheWrite": 1.25 }
      }]
    }
  }
}
```

`tests/mock-provider.mjs` serves that endpoint. It is a generic test double: it
speaks the OpenAI streaming wire format (including the split tool-call chunks a
real provider sends, so the client's incremental assembly is exercised rather
than bypassed) and delegates every decision to a script module.

A script gets `{agentId, step, messages, tools}` and returns
`{text?, thinking?, toolCalls?}`. Two conventions keep scripts short:

- `agentId` is parsed out of the system prompt the extension injects
  ("Your assigned id is a00."), which is the one identifier that survives
  compaction and steering.
- every agent in the swarm talks to the **same** mock process, so a script is
  also a rendezvous point. `tests/fixtures/mock-swarm-hello.mjs` uses that to
  run one globally ordered program: each entry is owned by one agent, and an
  agent whose turn has not come is told to `wait`. Ordering the *dispatch* of
  steps is not enough — the next step only goes out once the previous step's
  owner asks for its next turn, which it cannot do until its tool result has
  landed. Without that, agent 1's claim could reach disk before agent 0's and
  the conflict the run is meant to demonstrate would not happen. There is no
  timeout on that barrier: releasing a step that has not finished would reorder
  the program and quietly prove something else, so a dead pane leaves the run
  visibly stuck until the wall clock ends it. The two `done` steps are the one
  exception — a session that has called `done` never comes back, so the barrier
  is released at dispatch and both can be in flight, which is safe because the
  sentinel is an exclusive file create.

## Running it

```bash
node tests/mock-provider.mjs --port 8787 \
     --script tests/fixtures/mock-swarm-hello.mjs --log mock.jsonl &

scripts/swarm.sh start --model mockswarm/scripted-1 --n 2 \
  --cap-usd 5 --wall-clock 10 --no-netguard \
  --goal-file prompts/goals/hello.md \
  --env PI_CODING_AGENT_DIR=/tmp/piagent

scripts/await-done.sh --sandbox <sandbox>
```

`--env KEY=VALUE` is repeatable and reaches every agent pane, and must be an
absolute path for `PI_CODING_AGENT_DIR` because the panes run with the sandbox
as their cwd.

Two preflight rules make this work with no `auth.json` at all:

- the credential check follows `PI_CODING_AGENT_DIR`, including one passed with
  `--env`, instead of always reading `$HOME/.pi/agent/auth.json` — otherwise it
  inspects a file Pi will never open;
- a provider declared in `models.json` with its own `apiKey` counts as a
  credential, which is how Pi itself resolves local and self-hosted providers.

## Run 1 — the cooperative program (`s57fd`, 42 calls, $0.20 synthetic)

Two agents, the `hello` goal. What the sandbox showed afterwards:

| Claim | Evidence |
| --- | --- |
| Two real processes contend for one lock | `s57fd01` `claim_file work/hello.txt` → `conflict: true, owner: s57fd00`, and the note quotes the holder's own reason: *"write my id into the shared list"* |
| The lease is granted after release | `s57fd01` claims the same path moments later → `ok: true` |
| A shell write is **detected**, not blocked | `claim_violation` `via: "bash"`, `blocked: false`, `detected: true`, `rev: 1` for `work/notes.txt`, plus a `veto` post naming the agent and the snapshot hash `aba2e7fe` |
| A harness-owned write is **blocked** | `claim_violation` `blocked: true, protected: true`, reason `harness-owned path: SWARM.md`; the board says *"which the harness owns and nobody can claim"* rather than telling the agent to claim it |
| A harness-owned path cannot be claimed | `claim_file SWARM.md` → `protected: true` |
| Revisions are content-addressed and attributed | `history/…/index.json`: `work/hello.txt` rev 1 `7fb7b002` 8 bytes by `s57fd00`, rev 2 `6b12a621` 16 bytes by `s57fd01` |
| Side threads have membership and per-thread cursors | `threads/review/meta.json` `members: [s57fd01, s57fd00]`; both agents' `cursors.json` = `{"main": 6, "review": 1}` |
| `wait` wakes on all three signals | 15 rows: `reason=post` ×11, `reason=timeout` ×3, `reason=sentinel` ×1 |
| Thinking is traced | `tool: "thinking"`, 47 chars |
| Every tool call carries a duration | `duration_ms` on built-in and extension tools alike |
| Budget folds real Pi usage | `spent_usd 0.201246`, `tokens 195390`, `calls 42`, split per agent (`s57fd00` $0.099567 / 21 calls, `s57fd01` $0.101679 / 21 calls) with `context_tokens` and `context_window` |
| The DoD gate certifies from the registry | `await-done.sh` → `checks (registry): 2/2 passed`, exit 0 |

All 18 tool kinds in the program appear in `traces/events.jsonl`: `wait` ×15,
`post` ×7, `claim_file` ×4, `file_history` ×3, `write`/`release_file`/`read`/
`done`/`claim_violation`/`agent_stop`/`agent_start` ×2 each, and
`thread_open`, `thread_join`, `thinking`, `inbox`, `file_diff`, `claims`,
`bash` once each.

## Run 2 — the kill switch (`sd7c3`)

The point of a cap is what happens when the agents **do not** comply. A
compliant agent only proves the prompt worked.
`tests/fixtures/mock-swarm-runaway.mjs` posts once and then waits forever,
ignoring the steer on purpose. Cap: `$0.01`.

```
14:52:37.195  sd7c300  cap_steer   delivered=true
14:52:37.505  sd7c301  cap_steer   delivered=true
              budget.json: stop_steer_at=14:52:37.194Z  stop_reason=cap
              threads/main: one system post, not two
14:54:37.552  sd7c300  harness_stop  created_sentinel=true
```

`done/SWARM_DONE`:

```
by: harness
reason: cap
Spend cap $0.01 passed ($0.242034) and agents did not stop within the grace period.
```

Exactly `STOP_GRACE_MS` (2 minutes) after the steer, to the second. Both agents
were steered, the clock was set **once** for the whole swarm, one agent
announced it, and one agent created the sentinel — the shared-clock and
`created` guards hold across two processes.

## The UI, live

`scripts/ui-server.ts --runs-dir <runs>` against a runs directory holding
`sd7c3` and `sd2aa` — an earlier execution of the same cooperative program,
which is why the id differs from `s57fd` above — while the cap run was still
going:

- `sd7c3` — `running`, `$0.1103 / $0.01`, badge **cap hit**, `left $0.00`.
- `sd2aa` — `done`, `$0.2012 / $5.00`, `2 violations`, `cap left $4.80`,
  `took 17s`.

The header totals cover the whole directory, which also held an older
`--no-start` fixture run (`sbc91`, N=2, no model, $1 cap): hence 6 agents and a
$6.01 combined cap, not 4 and $5.01. The $0.31 spend is a mid-run snapshot of
`sd2aa` plus `sd7c3` before the latter finished at `$0.242034`.

## One thing to watch

The mock process outlives any single swarm, and its script holds module state.
A pane left over from an earlier run will keep talking to it and can drive that
state forward, which once left a fresh swarm stalling because the roster in
memory belonged to the previous one.

`mock-swarm-hello.mjs` now sends an off-roster agent away with a reply that
carries no tool call, which ends its turn instead of letting it either spin or
disturb the run. The roster only gives way to a new one once its own program
has finished or nobody on it has spoken for two minutes — resetting on any
unknown id would let a stale pane rewind a live run and make its agents repeat
steps. Even so, the habit worth keeping is `scripts/swarm.sh stop <id>` before
starting the next run.

## What this does not prove

The model is a script, so nothing here says anything about whether real agents
*choose* to claim before writing, whether they yield on a conflict, or whether
a swarm of them converges on a goal. It proves the harness does what it claims
when they do and when they do not. The behavioural question needs a paid run:
`pi /login`, then the same commands with a real `--model`.
