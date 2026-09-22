# Roadmap and non-goals

What is next and what this project will not become.


Roadmap (not started unless noted):

- Forged tools: a curated starter set. The tool library (`tool-library/`,
  `--tools-from`, `swarm.sh tools <id> --save`) already carries tools between
  runs; what is missing is a reviewed, documented set the way the shipped
  goals are, since the thirty-two in the library were written mid-case and
  never read line by line.
- Local models: one measured run so far (a 30B GLM on the hello goal, in
  [verified-runs.md](verified-runs.md)). A short table of which local models
  can drive the harness at all, measured one goal at a time, is the next
  step; a discovery extension that registers Ollama's models at runtime is
  set aside until then ([ADR 0006](adr/0006-a-local-model-is-braked-by-tokens.md)).
- The shell-write watch above 500 files under `work/`: the harness now says
  once when it has stopped covering everything (`watch_truncated`); covering
  everything, with a filesystem watcher rather than a hash bracket around
  each call, is the real fix.
- Optional rule: when every agent is `.done` or `.dead` and `SWARM_DONE` is
  absent, record `cannot_complete`.
- `stopped_at` in the registry; post timestamps in frontmatter instead of
  mtimes.
- macOS enforcement for netguard (`pf`); Node-version detection in `netcheck`.
- A per-thread `wait`, so an agent can block on one slice rather than all of
  its threads.
- Attribute a bash write to the command that made it, rather than to the agent
  whose shell call it happened during: when two agents run shells at the same
  time, one write can be reported by both.
- Watch `threads/`, `locks/`, `traces/` and `inbox/` for shell writes. They
  churn under normal operation, so this needs per-writer attribution first.

Non-goals:

- Reproducing any incident, evaluation, or third-party system. This repo implements the coordination pattern in the open, with locks, a stop signal and an observer.
- A planner/worker tree or sub-agent delegation. Peers on one goal only.
- Copying any other product's look. The console's design is its own.
- A hosted or multi-tenant service, user accounts, or a dark theme **in this
  repository**. The free harness runs on the examiner's own machine and has no
  identity system: the mutating routes carry a shared token, which is a guard
  against a stray LAN request. A managed deployment is scoped per engagement
  under Pro and is not built here.
