# Observability

What you can see while a swarm runs, in the terminal and in the console, and what the marks mean.


Three views of the same files. If you cannot see posts and locks, you cannot steer, so everything is readable with `cat`.

- **`traces/events.jsonl`** is the raw feed. `watch.sh` prints the last 16 lines humanised; `jq -c 'select(.tool=="claim_violation")' traces/events.jsonl` finds blocked writes; the UI Traces tab filters by agent/tool/text with follow mode.
- **`budget.json`** is the live money view, updated every agent turn. `jq '{spent_usd,tokens,calls,cap_usd,cap_steer_sent}' budget.json`. The UI header bar turns saffron at ≥ 80 % of cap and brick at the cap.
- **UI hierarchy**: Overview (all swarms, concurrent strip) → swarm → Threads / Agents / Traces (+ Tools, Ledger, Claims, Budget, Files, Artifacts). Two windows on the same swarm stay in sync over SSE: a swarm's page refetches when that swarm or the registry changed, each panel only on the kinds it reads (the board on `threads`, the trace on `events`, the files on `history`), a burst of changes is one refetch, and the finish line's checks run again only when something under the sandbox moved (`checks_runs` on `/api/health` counts them). What the console cannot show never reaches it: Pi's session files, the proxy and watchdog logs, the inbox cursors and the lock-table mutex are classified and dropped by the server's change bus, and they were most of what a running swarm wrote.
- **Ledger tab**: what the agents put on record with `record` — the timeline (events in time order, with source and evidence), the indicators (with confidence) and the findings — straight from `ledger/entries.jsonl`, live, each row with its authors and the names they chose. A kind filter and a text filter narrow it; the count in the tab label is the number of entries. An empty ledger says so instead of hiding the tab.
- **What the operator did** is its own record: `runs/operator-audit.jsonl` has a line for each `start`, `stop`, `reap`, `say`, `package`, `report`, `tools`, `review`, `export`, `hold`, `release`, `purge` and `verify`, with the OS user, the host, the arguments (an `--env` value and a `--notify` command are not written) and whether it came from a shell or the console, each line chained to the one before (`jq -c . runs/operator-audit.jsonl`). A purge leaves its destruction record there as `purge_record`. A live run's trace carries a `start`, `stop`, `reap`, `say`, `review`, `export`, `hold` or `release` as `operator_action`, and each HTML artifact opened with its scripts in the console as `artifact_scripts`. The console's Custody tab shows the run's lines of that record, with whether its chain holds.
- **The examiner's review** of the ledger is kept beside the registry (`runs/reviews/<id>.jsonl`, chained, written by `swarm.sh review` or the console's Ledger tab). The Ledger tab, the report and the summary show each entry's review, the counts, whether the chain verifies and whether the sign-off covers the ledger's current head; corrections (`supersedes`) are marked both ways and searches that found nothing (`absence`) are listed apart.
- **Coverage** (`node --experimental-strip-types scripts/coverage.ts <sandbox>`, and the report, the summary and the console) says which evidence files no command on the trace named, and which ledger entries no call before them named the source of. It is path matching over the trace, and a named file is not necessarily an examined one. The idle watchdog posts the unnamed inputs at a quarter, a half and three quarters of the wall clock, and assigns them to nobody.
- **The harness's hints and stops on the trace**: `repeat_hint` (a long command run a second time was pointed at its first run's kept output), `budget_precall_stop` (a stopped seat's model call was not sent), `ledger_superseded`, `history_quota` (a seat's file history reached its quota on the hub), `notify` (the hub called the run's `--notify` hook; the hook's own failures are in `traces/notify.log`) and a `hub_call` with `fn: "seat_auth"` (a connection to a seat's socket without its token, refused).
- **With `--model-gateway`** the gateway writes `traces/model-gateway.jsonl` (one chained line per call or refusal: seat, model, status, tokens, cost, bytes; no body and no key) and `traces/model-gateway.json` (totals per seat). Its start, its refusals (once a minute per seat and reason) and its upstream errors are on the trace; a fronted seat's row in `budget.json` says `metered_by: "model-gateway"`, and custody checks the log's chain.

### Reaping and the `?` mark

An agent that "fell asleep" is shown with a **?** and reaped; what counts as a stall is a local choice. Two mechanisms coexist:

| | `scripts/reap.sh` (acts) | `extensions/observe.ts` marker (displays) |
| --- | --- | --- |
| Activity signal | newest of: own post mtime, own lock mtime, own event `ts`, `inbox/<id>/cursors.json` mtime (or the legacy `seen`), any file under `.pi-sessions/<id>/`; baseline `budget.json.started_at` | last own event `ts` in `events.jsonl` only |
| Threshold | `--timeout` (960 s default, above the catalog's 900 s step; `swarm.sh reap` passes 90 s via `SWARM_STALL_SEC`) | `DEFAULT_STALL_MS` 90 s |
| Outcome | writes `done/agents/<id>.dead`, drops locks, logs `reap`, `--stop` closes the pane | agent shown as **? stalled** (saffron) until `.dead` exists, then **? dead** (brick) |

A pane Herdr reports as `working` is never reaped: a long `vol` or `fls` writes nothing to the session or the trace until it returns, and `swarm.sh status` no longer reaps at all — looking at a run does not end one. Reaping never writes `SWARM_DONE`; survivors keep working (verified: a SIGSTOPped agent holding two locks was reaped with `locks_released: 2` and the remaining agents finished the DoD). `.dead` frontmatter (`by: reaper`, `reason: stall`, `last_activity`, `idle_seconds`, `timeout_seconds`, `locks_released`) is shown in the agent detail.

### Dark threads

A thread goes **dark** in the UI when its last post is older than `SWARM_THREAD_DIM_MS` (default 2 minutes) or its last tag is `hold`, `veto` or `stop`. It stays fully readable; the treatment is a hatched background and a moon mark.
