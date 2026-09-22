# Verified results

Live runs that proved a feature, with the swarm id, the cost and what the evidence was. Fixture coverage without a model is listed at the end.


All live runs on 2026-09-16, Linux container, `deepseek/deepseek-v4-pro`,
Herdr 0.9.0. Spend figures are `budget.json.spent_usd` from Pi session usage.

**These runs predate the current harness.** They were made when the definition
of done was fixed (`work/hello.txt`), `bash` writes were invisible, the wall
clock was advisory and the web app had no token. What they still prove is the
part that did not change: the board, the claims, the budget fold, the reaper,
netguard, and that the thing runs at N=30. The numbers are kept because they
are real; a run against the current harness is the one thing on the roadmap
that no fixture can stand in for.

## A local model, braked by tokens (2026-09-19)

| Run | N | Model | Spent | Calls | What it proved |
| --- | --- | --- | --- | --- | --- |
| `s7f9d` | 2 | `ollama/glm-4.7-flash-64k:latest` (Ollama 0.34.1 on the same Mac; a placeholder `apiKey`, a `compat` block and `contextWindow` 65536 in a throwaway `models.json`) | $0 — `metered: false`, 157,803 tokens of a 3,000,000-token cap | 16 | The hello goal on Pi 0.85.1 with `--cap-tokens 3000000 --local-only`. The kickoff's probe found the server, the model and a matching `num_ctx`, and passed silently; `pi auth check` answered `ready / api_key` on the placeholder. Both agents named themselves, one claimed `work/hello.txt`, wrote both ids, released it and posted; the other verified the checks and wrote the sentinel: **2/2 checks, 8m 50s**. `budget.json` records `metered: false`, `cap_usd: 0`, `spent_usd: 0` and the tokens; the summary says "free" and "No metered cost … 157,803 tokens of a 3,000,000-token cap" rather than "$0.00 spent". netguard ran with `--only 127.0.0.1,localhost` and logged three `ALLOW connect 127.0.0.1:11434` and **no DENY**: the model traffic went through the proxy as CONNECT tunnels, and with `PI_OFFLINE=1` nothing else was attempted. `~/.pi/agent` was not touched. |

## A forensic case on real evidence (2026-09-18)

| Run | N | Model | Spent | Calls | What it proved |
| --- | --- | --- | --- | --- | --- |
| `s2cb9` | 7 | 4× `openai/gpt-5.4` (API key) + 3× `deepseek/deepseek-v4-pro` | $7.98 | 420 | A 26 GB forensic case (25 GB raw NTFS disk image + 1 GB memory image) handed over with `--inputs`, read-only at the kernel in all seven panes (`enforced=kernel`); the swarm split seven seats on the board, extracted hives, event logs, web logs and web shells with The Sleuth Kit, ran Volatility 3, forged an `evtx_filter` tool that every session loaded within a minute, found a sqlmap phase, two added accounts and a PHP reverse shell, and delivered a cited report and a 61-row timeline in **14.5 minutes**; 40 shell writes detected and snapshotted, 0 writes to `inputs/`, 9/9 checks. Everything is in [`docs/use-cases/dfir-web-server-case/`](use-cases/dfir-web-server-case/README.md). |

## Read-only inputs (2026-09-18)

| Run | N | Model | Spent | Calls | What it proved |
| --- | --- | --- | --- | --- | --- |
| `s559a` | 2 | `mockswarm/scripted-1` (no key; `tests/fixtures/mock-swarm-inputs.mjs`) | $0.21 synthetic | 40 | Real Herdr panes, real Pi, `--inputs` with two files, `--inputs-enforce auto` on macOS. Both panes logged `inputs_guard mode=seatbelt enforced=kernel`: the `ZDOTDIR` hook put the pane's zsh, and so Pi, under `sandbox-exec`. `write inputs/readings.csv` refused (`read-only input: …`), `claim_file` refused with the same reason, then three shell attempts — append, `rm`, a planted file — left **no trace on disk and no violation to heal**; the report went to `work/report.md`; both agents' `inputs_check ok`; sentinel; **5/5 checks** including a sha256 sweep of every input against `inputs.json`. Wall 0:40. |
| `s971d` | 2 | `mockswarm/scripted-1` | $0.21 synthetic | 40 | `--inputs-enforce on`: after the panes started, the kickoff waited for both agents' `inputs_guard` probes to say `kernel` and printed `Guard: kernel guard measured in every pane (2)` before the first prompt; the refused `write` is on the trace as `inputs_violation {blocked:true, via:"write"}`; both `inputs_check ok`; **5/5 checks**. |
| `s4df3` | 2 | `mockswarm/scripted-1` (`MOCK_INPUTS_CHMOD=1`) | $0.22 synthetic | 40 | The same program with `--inputs-enforce off`, so only the tool guard and detect + heal stand, and the script `chmod -R u+w inputs` before each shell attempt. Both panes logged `enforced=mode`; the three shell writes went through and the harness healed each within the same call: `inputs_violation healed=restored` (append), `restored` (delete), `removed` (planted file), with a `veto` post on the board for each; the readings were byte-for-byte intact when the peer counted them; `inputs_check ok` from both; **5/5 checks**. Wall 0:40. |

Linux, in a privileged `node:22` container (`unshare -rm` available): `fsguard.sh` picks `mountns`; under it a write is `Read-only file system`, `rm` and `chmod` are refused, a hard link out of the mount fails with `Invalid cross-device link`, and `tests/inputs.test.sh` takes its kernel branch and passes. On macOS 27 the seatbelt profile refuses the hard link too (`ln inputs/a work/alias`: denied; the same command succeeds outside the profile).

## Forged tools (2026-09-18)

| Run | N | Model | Spent | Calls | What it proved |
| --- | --- | --- | --- | --- | --- |
| `s19d0` | 2 | `mockswarm/scripted-1` (no key; `tests/fixtures/mock-swarm-forge.mjs`) | $0.23 synthetic | 44 | Real Pi panes, real extension. `tools` empty → `make_tool read` refused (reserved) → `make_tool count_lines` ok and `tool_loaded` in the author's session; **0.3 s later `tool_loaded` in the peer's session** off its `wait`; the peer called `count_lines` by name twice; the peer's `make_tool count_lines` refused (author active); `always_fails` forged by the peer, loaded by both, its failure reported as `ok:false "boom"`; sentinel by the author; 2/2 checks. |

| `sfb60` | 2 | `openai-codex/gpt-6-astra` (subscription) | $0.67 | 36 | A real model, unscripted, on a goal that needs a tool nobody has: sfb6000 checked `tools` (empty), wrote `work/readings.csv`, forged `csv_stats` (760 bytes of python) — `tool_loaded` in its own session at once and **in sfb6001's session 0.4 s later**; sfb6001 called `csv_stats(path="work/readings.csv")` by name, wrote `work/stats.json` from its output; sentinel by sfb6001; **4/4 checks** including `test -f tools/csv_stats/manifest.json` and a `csv_stats` line in the trace. Wall 1:40. |

## Earlier runs

| Run | N | Cap | Spent | Tokens | Calls | Wall | What it proved | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `s9091` | 2 | — | $0.061 | 243,160 | 34 | ~110 s | Netguard default: provider `ALLOW`, `example.com` `DENY` 403 from agent `bash`; `playwright` on `work/index.html` with screenshot; `file_history` → `file_restore` rev 1 under a claim; `SWARM_DONE`. | [`docs/feature-evidence.md`](feature-evidence.md) §2–4 |
| `sfd9e` | 2 + probe | — | — | — | — | — | `--probe-violation`: the guard blocked `write work/hello.txt` from `sfd9epv`, logged `claim_violation`, file unchanged. | store `internal/n-scale-probe-budget.md` §3 |
| `s7e50` | 10 | $3 | $0.191 | 523,871 | 87 | 73 s | `SWARM_DONE` + `hello.txt` + `summary.md` with all 10 ids; 14 posts, 13 claim conflicts, 0 dead; 10 panes on one Herdr tab (4 columns). | store `internal/n-scale-probe-budget.md` §1 |
| `s8218` | 2 | $1 | $0.019 | — | — | — | Started while `s7e50` ran; `swarm.sh list` showed both `running`; DoD met. | store `internal/n-scale-probe-budget.md` §2 |
| `sbeef` | 30 | $3 | $0.725 | 1,989,624 | 244 | 128 s | `SWARM_DONE`; 30 posts, 40 conflicts, 0 dead; **30 panes on one tab** (`tabs=1`, `split_failures=0`), so the tab/workspace spill path was not exercised. | [`docs/feature-evidence.md`](feature-evidence.md) §1 |
| `sd169` | 3 | $1 | $0.053 | 185,768 | 32 | ~170 s | Live reap: `SIGSTOP` on `sd16901` holding two locks → `swarm.sh reap --stall-sec 20` → `.dead`, `locks_released: 2`, UI **?**; survivors finished the DoD. | [`docs/feature-evidence.md`](feature-evidence.md) §6 |
| `sbf00` / `s34b1` | 2 | $0.005 | ~$0.012 | — | — | — | Cap steer → `done cannot_complete` → `SWARM_DONE`; with `--hard-kill` the steered session also left `herdr agent list`. | store `internal/n-scale-probe-budget.md` §4–5 |
| `sc60f` | 6 | $1 | $0.171 | 429,472 | 59 | — | Kicked off **from the web form**; `work/index.html` + `summary.md`; 2× `playwright` ok; 5 claim conflicts; operator **Restore** of `hello.txt` rev 1 via the UI. | [`docs/ui-coverage.md` § Live run](ui-coverage.md#live-run) |
| `s4081`, `scff0`, `s0938`, `sfdc8`, `s94a3` | 1–2 | $0.2–1 | $0.009–0.023 | — | — | — | UI **Stop** closed the Herdr workspace; UI **Reap stalled** `--stall-sec 12 --stop` closed panes; three swarms running at once on the Overview; `inbox` events carry senders. | [`docs/ui-coverage.md` § Live run](ui-coverage.md#live-run) |

Fixture coverage without a model: `npm test` (the protocol suite + the web API suite, 50 tests), `npm run test:bash` (certification, reaper, netguard), `scripts/test-slice2.sh` (those plus the Playwright tool and the real Pi loader). Live-run evidence is in [`docs/feature-evidence.md`](feature-evidence.md) (per-feature runs) and [`docs/ui-coverage.md`](ui-coverage.md) § Live run (web app).
