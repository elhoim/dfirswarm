# Local models: what Pi supports, what the harness does today, and what changes

Status: implemented in three stacked pull requests, the same day (in the archived `halilozturkci/dfir-swarm` repository, whose history this one replaced) — phase 1
(CLI, extension, summary; PR #40, proven on a real Ollama run recorded in
`docs/verified-runs.md`), phase 2 (the console; PR #41), phase 3 (ADR 0006,
the quick start, the README; PR #42). Item 31's Linux proof turned out to
exist already in `tests/netguard.test.sh` under netns mode, so no CI job was
added. Of the open questions in §7, only the per-model measurement (4) is
partly done: one model. Written 2026-09-19 against this repository
at `4ec1767` and the Pi coding agent installed on the development machine,
`@earendil-works/pi-coding-agent` **0.85.1**, which is npm `latest`. Every
claim below was either read in that package's own `docs/` and `dist/`, read in
this repository, or measured on the machine; where something is inferred it
says so.

"Local model" here means a model served on the same machine or the LAN by
Ollama, LM Studio, vLLM, llama.cpp's server, or any other OpenAI-compatible
endpoint, with no API key and no metered cost.

## 1. The verdict

The harness is one configuration line away from running a local model, and
several design decisions away from doing it honestly.

- **It nearly works today.** Give the provider a dummy `apiKey` in Pi's
  `models.json` and the credential gate passes, the netguard allowlist already
  picks the loopback host out of the provider's `baseUrl`, and the pane's
  proxy settings carry the model traffic to the local server through netguard.
  All three were measured, not assumed.
- **Two things break.** Without that dummy key nothing starts, and the BLOCKER
  text sends the operator to `pi /login`, which is the wrong place. And because
  a local model's cost is a real, computed zero, the whole budget machine goes
  quiet: no cap ever fires, and the CLI, the console and the summary report
  "$0.00 spent" as if nothing had happened.
- **One principle is violated.** A fully local run still has eight cloud hosts
  open in netguard, because the allowlist only ever grows.
- **Two server-side traps.** Ollama's OpenAI-compatible endpoint truncates at
  4096 tokens by default while Pi budgets against whatever `contextWindow` the
  operator declared; and Pi's compatibility autodetection has no branch for a
  local URL, so it sends `developer` roles and `reasoning_effort` that local
  servers reject.
- **One live defect in the current configuration**, unrelated to local models
  but found on the way: in `~/.pi/agent/models.json` the `DeepSeek-V4-Pro`
  entry sets `maxTokensField` at model level, where Pi silently ignores it. It
  belongs inside `compat`. See §9.

## 2. What Pi 0.85.1 does

Read in the installed package unless marked otherwise.

| Fact | Source |
| --- | --- |
| Custom providers live only in `models.json` under `PI_CODING_AGENT_DIR` (default `~/.pi/agent`). No XDG paths, no project-local `models.json`, no `--base-url` flag. A sandbox's `.pi/` directory cannot carry a provider definition. | `dist/config.js:403-438`, `docs/settings.md:7-22`, `pi --help` |
| Provider fields: `baseUrl`, `api`, `apiKey`, `headers`, `authHeader`, `compat`, `models[]`, `modelOverrides`, `name`. Model fields: only `id` is required; defaults are `contextWindow` 128000, `maxTokens` 16384, `cost` all zero. `api` for a local server is `openai-completions`. | `docs/models.md:132-145`, builder in `dist/bundle/chunks/chunk-JVUZSMYM.js:1066` |
| **A keyless provider fails the credential gate.** `pi auth check --model p/id --json` returns `{"status":"not_ready","reason":"credentials_not_configured"}` exit 1, and the provider is absent from `pi --list-models`. A dummy `"apiKey": "ollama"` makes it `ready` with `authType: "api_key"` and exit 0. The run path accepts `--api-key` but the gate does not. | measured; `docs/models.md:37,145` |
| `cost` per million tokens; when absent it is `{0,0,0,0}` and `Usage.cost.total` is computed as exactly `0` — never undefined, never NaN. The footer shows `$0.00`. | `pi-ai/dist/models.js:530-548`, `docs/session-format.md:104-117` |
| Usage fields: `input`, `output`, `cacheRead`, `cacheWrite`, `totalTokens`, `cost.{input,output,cacheRead,cacheWrite,total}`; cache fields stay 0 for local servers, which is correct. | `docs/session-format.md:104-117` |
| **`detectCompat` has no local branch.** An unknown local URL gets strict-OpenAI defaults: `developer` role, `reasoning_effort`, `store`, `max_completion_tokens`, `stream_options.include_usage`. Pi's docs say to set `compat.supportsDeveloperRole: false` and `supportsReasoningEffort: false` for Ollama, vLLM, SGLang. Provider-level `compat` applies to all its models; only the keys you name are overridden. | `pi-ai/dist/api/openai-completions.js:1236-1317`, `docs/models.md:39-41` |
| No tool-capability field exists; Pi always sends tool definitions and cannot degrade if the model lacks tool use. llama.cpp needs `--jinja` for tools. | `pi-ai/dist/types.d.ts:716-737`, `docs/llama-cpp.md:26` |
| **Pi installs its own env-reading proxy agent** (`undici.EnvHttpProxyAgent`, `proxyTunnel: true`) at startup. `HTTP_PROXY`/`HTTPS_PROXY` and lowercase forms are honoured; **`ALL_PROXY` is not read**; `NODE_USE_ENV_PROXY` is irrelevant. `NO_PROXY` matches the literal hostname in the URL with no DNS, so `127.0.0.1` does not cover `localhost`. Even a plain `http://` origin goes out as `CONNECT host:port`. | `dist/core/http-dispatcher.js:73-85`, `undici/lib/dispatcher/env-http-proxy-agent.js:26-38`; measured against the running Ollama |
| Two more places a proxy can come from: `settings.json.httpProxy` (global, `??=`, does not override env) and a provider-scoped `env` block in `auth.json` that **takes precedence over the process environment** for that provider. | `docs/settings.md:92`, `docs/providers.md:141` |
| Ollama's OpenAI endpoint ignores `num_ctx` in the request and defaults to **4096**; fix on the server with `OLLAMA_CONTEXT_LENGTH` or a Modelfile `PARAMETER num_ctx`, then declare a matching `contextWindow`. Pi's auto-compaction recognises Ollama's "prompt too long" error. | [earendil-works/pi discussion #5983](https://github.com/earendil-works/pi/discussions/5983), changelog #2626 |
| llama.cpp has a first-class path: `llama-server` in router mode with `--jinja`, provider id `llama.cpp`, base URL from `LLAMA_BASE_URL` (default `http://127.0.0.1:8080`) or `/login llama.cpp`; it is not a `models.json` provider. | `docs/llama-cpp.md`, `docs/providers.md:300` |
| Extensions see every model's `baseUrl` and `cost` through `ctx.modelRegistry.getAll()` / `getAvailable()`; both are required fields on `Model`. `hasConfiguredAuth` is `false` for a keyless provider, so `getAll()` lists its models and `getAvailable()` does not — the same split as `--list-models`. `model_select` fires on change and on restore; an async extension factory can `registerProvider` dynamically and the result reaches `pi --list-models`. | `dist/core/model-registry.d.ts:20-44`, `pi-ai/dist/types.d.ts:716-737`, `docs/extensions.md:738-759,1015-1017` |
| Default HTTP idle timeout 300 s, configurable; `PI_OFFLINE=1` / `--offline` stops all startup network calls; `pi auth check --no-refresh` makes the gate side-effect-free. | `pi --help`, `docs/environment-variables.md` |
| `apiKey: "!cmd"` in `models.json` runs on **every request** with no caching (auth.json's `!cmd` is cached for the process). | `docs/models.md:172-176`, `docs/providers.md:163` |

On this machine: Ollama 0.34.1 is installed and answering on `127.0.0.1:11434`
with 17 models (`qwen3-coder-next:latest`, `gpt-oss:120b`, `gpt-oss:20b`,
`glm-4.7-flash:q8_0`, `deepseek-r1:70b`, `qwen3:32b` …); LM Studio's CLI is
installed but nothing answers on `:1234`; no `llama-server` or vLLM.

## 3. What the harness does today, flow by flow

File and line references are against `4ec1767`.

| Flow | Today, with a local provider | Where | Verdict |
| --- | --- | --- | --- |
| `--model` / `--models` parsing | `ollama/llama3.1:8b` and `llama.cpp/x` both pass the reference regex | `scripts/swarm.sh:1815-1817`, `scripts/ui/actions.ts:95` | works |
| Credential preflight | Single gate is `pi auth check`; a keyless provider is `not_ready` → BLOCKER, nothing starts. The text suggests `pi /login` and `--key-from-env`; never mentions `models.json` | `scripts/swarm.sh:1562-1608` | **broken, wrong diagnosis** |
| `--key-from-env` | `provider_key_var("ollama")` → `OLLAMA_API_KEY`; if unset, `detect_provider_key` scans known variables and can hand **another provider's key** to the panes | `scripts/swarm.sh:477-520` | silently wrong |
| netguard allowlist | Unknown provider → host from `models.json.baseUrl`: `http://127.0.0.1:11434/v1` → `127.0.0.1` | `scripts/swarm.sh:1912-1926` | works |
| `host_of_url` on IPv6 | `http://[::1]:11434/v1` yields `[` | `scripts/swarm.sh:1928-1930` | broken |
| Host matching in the proxy | Literal string compare, no DNS: `localhost` allowed ≠ `127.0.0.1` requested | `scripts/netguard-proxy.mjs:67-73` | trap |
| netguard default list | `--allow` **adds** to eight cloud hosts; `--only` is never used by `swarm.sh` | `scripts/netguard.sh:49,75`, `scripts/swarm.sh:1998-2001` | principle violated |
| Per-pane proxy env | `HTTP(S)_PROXY`, `ALL_PROXY`, `NODE_USE_ENV_PROXY=1`, empty `NO_PROXY`; loopback traffic is proxied and, in `proxy-only` mode, reaches the local server | `scripts/swarm.sh:1644-1646` | works on macOS; **untested on Linux netns** |
| Budget accounting | `Usage.cost.total` summed → `spent_usd` is 0; tokens and calls are counted correctly but drive nothing | `extensions/protocol.ts:1658-1707` | zero by definition |
| Swarm cap | `over_budget = cap_usd > 0 && spent_usd >= cap_usd` → never fires; the wall clock is the only brake, and nothing says so | `extensions/protocol.ts:2096-2109`, `:1780` | **silently wrong** |
| Per-agent cap | Same guard; `--cap-per-agent` is inert | `extensions/protocol.ts:2112-2117`, `extensions/agent-swarm.ts:320-345` | silently inert |
| `--cap-usd` validation | Required but not numeric-checked; `--cap-usd 0` is accepted and means "unbounded" | `scripts/swarm.sh:1258-1261` | undocumented |
| `budget.json` | No field says whether cost was measured | `scripts/swarm.sh:917-935`, `extensions/protocol.ts:153-172` | missing field |
| Console model list | Parsed from `pi --list-models`, where a keyless provider never appears; fallback `STATIC_MODELS` is cloud only | `scripts/ui/actions.ts:77-88,339-396` | **broken** |
| Console readiness | `not_ready` → "not logged in", tooltip `pi auth login ollama` | `scripts/ui/actions.ts:401-468`, `ui/src/components/model-team.tsx:22-43` | misleading |
| Console kickoff default | First model whose provider is `ready`; a local one never is; typing it in `__custom` hits the server-side BLOCKER | `ui/src/screens/kickoff.tsx:180-191,373-401` | broken |
| Console `validateStart` | `cap_usd <= 0` rejected → a free run cannot be expressed; pinned by `tests/ui-server.test.ts:441` | `scripts/ui/actions.ts:136` | blocks |
| Console `allow_hosts` | `isHostName` needs a dot: `localhost`, `::1`, `127.0.0.1:11434` rejected | `scripts/ui/actions.ts:69-71` | partly broken |
| Console budget tab | `$0.0000`, "remaining of $N", by-model cards all zero, footnote "Zero means the agent has not reported a turn yet" — false for a local run | `ui/src/screens/detail/budget-panel.tsx:68-79,112-145,202-205` | silently wrong |
| Console network modes | `guarded` / `hosts` / `open`; no "local only" | `scripts/ui/actions.ts:62-66` | missing mode |
| `summary.ts` / `package` | "$0.00 of a $N cap … 0 provider calls", by-model shares "—" | `scripts/summary.ts:282-305` | misleading, ships in the package |
| idle-nudge, await-done, reap, toolbox, catalog, kickoff prompt, `team.json`, `run.json` | No model or cost dependency; model strings pass through | — | unaffected |
| Docs | `docs/proof-run.md:19-28` already shows the loopback + dummy-key + synthetic-cost pattern for the mock provider; `docs/credentials-and-teams.md:68-133` covers Foundry and warns that a missing `cost` block means $0 and a cap that never fires. No document names Ollama, LM Studio, vLLM or llama.cpp, says the dummy key is mandatory, or explains the literal-host trap | — | missing |
| Tests | Preflight tests cover only providers **with** a key; model-team tests cover `baseUrl` → allowlist only with an https host; netguard tests use loopback only as a **denied** host; `cap_usd: 0` is pinned as invalid | `tests/swarm-preflight.test.sh:124-228`, `tests/model-teams.test.sh:116-136`, `tests/netguard.test.sh:76-82`, `tests/ui-server.test.ts:441` | gaps |

## 4. Design decisions

**D1 — "Local" is a property of the endpoint, decided once.** A provider is
local when the host of its `baseUrl` is loopback (`127.0.0.0/8`, `::1`,
`localhost`), a private range (`10/8`, `172.16/12`, `192.168/16`), or ends in
`.local`; the built-in `llama.cpp` provider is local by definition, with its
host taken from `LLAMA_BASE_URL` or the default `127.0.0.1:8080`. One function
in `swarm.sh` decides this at kickoff and writes the answer into `run.json`
and `budget.json`; the extension and the console read it from there rather
than re-deriving it. Everything else in this plan hangs off that one bit.

**D2 — Local traffic stays inside netguard.** The alternative — `NO_PROXY`
for loopback — would take the model calls out of the one place the harness
sees every request. Pi tunnels even `http://` origins as `CONNECT`, the tunnel
is a raw socket pipe so keep-alive survives, and the sidecar runs on the host
and reaches loopback in both `proxy-only` and `netns` modes. So: keep
`NO_PROXY` empty, keep the proxy, and make the allowlist carry the literal
host from `baseUrl` **plus its twin** (`localhost` ↔ `127.0.0.1`), because
neither Pi's `NO_PROXY` matcher nor the proxy's `isAllowed` resolves names.

**D3 — Metering is declared, not inferred.** `Usage.cost.total` is a true
zero for a local model, so session data cannot distinguish "free" from
"unmeasured". `metered` is therefore derived at kickoff from `models.json`:
a model whose `cost` block is absent or all zero is unmetered; every built-in
cloud provider is metered; `llama.cpp` is unmetered. A team is `metered` if
any of its models is. `budget.json` carries `metered` and, new, `cap_tokens`.

**D4 — The brake for an unmetered run is tokens, and it is mandatory.** When
the team is unmetered, `--cap-usd` is not required and `--cap-tokens N` is;
`over_budget` becomes `tokens >= cap_tokens`. When the team is mixed,
`--cap-usd` stays required and `--cap-tokens` is an optional second brake.
The wall clock stays as it is. Nothing should ever be "unbounded by accident":
that is the state the harness is in today for local models, and it is the one
thing this plan exists to end. Tokens here are Pi's `totalTokens` summed over
turns — the context is re-sent every turn, so the number grows fast; the
seven-agent forensic runs used 20–75M. The docs must say that.

**D5 — The harness never writes `models.json`.** It is Pi's own configuration
and the operator's; the harness reads it and, when something is missing,
prints the exact snippet to add (dummy `apiKey`, `compat`, `contextWindow`).
A discovery extension that registers Ollama's models at runtime through
`registerProvider` was considered and set aside for now: it would hide
exactly the settings (`compat`, `contextWindow`) that a local server gets
wrong when they are hidden. It remains the right next step once the static
path is solid.

**D6 — Preflight probes the server, not just the credential.** For a local
provider, before any pane opens: `GET <baseUrl>/models` with a two-second
timeout (BLOCKER if it does not answer: "Ollama is not running"); the model
id must be in that list (BLOCKER if not, with the ids that are); and for
Ollama, `POST /api/show` to read the effective `num_ctx`, compared with the
declared `contextWindow` — a WARNING when the server's window is smaller,
because Pi will budget against the wrong number and the model will truncate
silently. The `compat` block is checked for presence and warned about when
absent.

**D7 — Local-only is a network mode.** A team that is entirely local gets
`netguard --only <local hosts>`: the cloud defaults drop out. `--local-only`
asks for it explicitly and refuses a team with a cloud model; the console
gets a fourth network mode with the same meaning. Panes in this mode also get
`PI_OFFLINE=1`, so Pi makes no catalog refresh calls at startup.

**D8 — The console mirrors the CLI, from the same source.** `listModels`
reads `models.json` in addition to `pi --list-models`, so a configured but
keyless provider appears with status `local` and the hint that fixes it;
readiness maps `not_ready` + `credentials_not_configured` + local `baseUrl`
to `local`; the budget tab switches its unit from dollars to tokens when
`metered` is false.

## 5. The change list, in three phases

Line numbers are against `4ec1767`. "R" is required for local models to be
usable and honest; "N" is worth doing once R is in.

### Phase 1 — start correctly, account honestly (CLI + extension)

| # | File · function | Change | Why | |
| --- | --- | --- | --- | --- |
| 1 | `scripts/swarm.sh` — new `provider_is_local`, between `provider_hosts_for_model` (`:1882`) and `host_of_url` (`:1928`) | Classify the `baseUrl` host per D1; special-case `llama.cpp` (`LLAMA_BASE_URL`, default `127.0.0.1:8080`). Record `local` per model in `run.json` and `metered` in `budget.json` | The single source of truth for everything below; the word "local" does not exist in the code today | R |
| 2 | `scripts/swarm.sh:1928-1930` `host_of_url` | Handle `[::1]` bracket form | Produces `[` today; garbage reaches the allowlist | R |
| 3 | `scripts/swarm.sh:1935` `provider_hosts_for_models` | When the literal is `localhost` add `127.0.0.1` too, and vice versa; for `llama.cpp` add its host | Neither the proxy nor Pi resolves names (D2) | R |
| 4 | `scripts/swarm.sh:1586-1607` BLOCKER text | If the provider is local: print the `models.json` snippet (dummy `apiKey`, `compat`, `contextWindow`), the `pi auth check` line that will then pass, and no `pi /login` / `--key-from-env` advice. Add `--no-refresh` to the gate call | Measured: the keyless provider fails with `credentials_not_configured` and today's text sends the operator to the wrong place | R |
| 5 | `scripts/swarm.sh` preflight loop, before `pi_auth_report` (`~:1565`) | D6 probes: `/models` reachability, model id present, Ollama `num_ctx` vs `contextWindow`, `compat` present | Otherwise N panes open and die with connection errors, or truncate silently at 4096 | R |
| 6 | `scripts/swarm.sh:477-520` `provider_key_var` / `detect_provider_key` | Refuse `--key-from-env` for a local provider ("a local provider has no key") instead of scanning for someone else's | Silently ships another provider's key into every pane | R |
| 7 | `scripts/swarm.sh:1071-1130` args, `:1258-1261` cap check, `:890-935` `write_team_budget` | Add `--cap-tokens N`; validate `--cap-usd` numerically like `--cap-per-agent` does at `:1215`; unmetered team → `--cap-tokens` required, `--cap-usd` optional; write `metered`, `cap_tokens` | D3/D4; also ends the undocumented `--cap-usd 0` = unbounded | R |
| 8 | `scripts/swarm.sh:1497-1500`, `:1608-1612` kickoff summary | Local model: `Model: ollama/… → local http://127.0.0.1:11434 · no metered cost · cap 40M tokens` instead of the `Key:` line | The operator must see which brake is armed | R |
| 9 | `extensions/protocol.ts:153-172` `BudgetRecord`, `:2096` `budgetPressure`, `:2112` `agentPressure`, `:1780` `applySessionUsage` | Add `metered`, `cap_tokens`; when `metered === false`, `over_budget = cap_tokens > 0 && tokens >= cap_tokens`; per-agent pressure likewise on a token share when `cap_per_agent_tokens` is set (N) | Today the cap machine is silent for a free run | R |
| 10 | `extensions/agent-swarm.ts:320-345` `enforceAgentCap`, `:460-490` steer texts, `:1202-1220` `budget` tool | Phrase steers and the `budget` tool's answer in tokens when unmetered; return `metered: false` so an agent does not reason from "$ left" | The agents read these numbers | R |
| 11 | `scripts/swarm.sh:1634-1642`, `scripts/netguard.sh:75` | `--local-only`: all-local team → `netguard --only <local hosts>`; refuse with a cloud model; set `PI_OFFLINE=1` in panes | D7; today eight cloud hosts stay open in a local run | R |
| 12 | `scripts/summary.ts:282-305` | `metered === false` → agent table shows tokens/calls instead of `Spent`; by-model share by tokens; headline "no metered cost (local models); N tokens of a M-token cap" | The summary is what `package` hands over | R |
| 13 | `scripts/swarm.sh:2052-2088` `cmd_netcheck` | `--local` variant: ALLOW to the configured local endpoint, DENY to a cloud host | Today it always tries `api.deepseek.com` | N |
| 14 | `scripts/netguard-proxy.mjs:113-119` | Keep-alive on the absolute-URI path | Only matters if a client ever uses it; Pi uses CONNECT (D2). Measure first | N |
| 15 | `scripts/swarm.sh` preflight | Warn when `auth.json` carries a provider-scoped `env` with `HTTP_PROXY`/`HTTPS_PROXY`, since it overrides the pane's proxy and would bypass netguard | Found in Pi's docs; a quiet escape hatch | N |

### Phase 2 — the console

| # | File · function | Change | Why | |
| --- | --- | --- | --- | --- |
| 16 | `scripts/ui/actions.ts:364-396` `listModels`, `:77-88` `STATIC_MODELS`, `ModelList` type | Also read `models.json` (respecting `PI_CODING_AGENT_DIR`); providers configured there but absent from `pi --list-models` are returned with `local: true` and `needs: "dummy apiKey"`. This is the console's equivalent of Pi's own `getAll()` minus `getAvailable()`: configured, not credentialed | A keyless provider is invisible to the picker today (measured) | R |
| 17 | `scripts/ui/actions.ts:401-468` `checkOneProvider` / `ProviderReadiness` | New status `local`: `not_ready` + `credentials_not_configured` + local `baseUrl`; hint text names `models.json`, not `pi auth login` | "not logged in" is the wrong diagnosis | R |
| 18 | `scripts/ui/actions.ts:136` `validateStart`, `StartParams`, `:227-247` `startArgv` | Unmetered team → `cap_usd` may be 0/absent, `cap_tokens` required; pass `--cap-tokens`; new `net: "local"` → `--local-only` | A free run cannot be started from the console today | R |
| 19 | `scripts/ui/actions.ts:69-71` `isHostName` | Accept `localhost`, `host:port`, `[::1]` | `localhost` and `127.0.0.1:11434` are rejected; the proxy grammar already takes `host:port` | R |
| 20 | `scripts/ui/actions.ts:62-66` `NetMode` / `NET_MODES` | Fourth mode `local` — "nothing leaves the machine" | D7 in the form | R |
| 21 | `ui/src/components/model-team.tsx:22-43` `modelOptionLabel`, `ReadyDot` | `local` → "local · free" label and its own colour; tooltip with the `models.json` hint | Visible half of #17 | R |
| 22 | `ui/src/screens/kickoff.tsx:180-191` | Default model = first that is `ready` **or** `local`; cap field switches to tokens for an unmetered team; network picker shows `local` | A local provider can never be the default today | R |
| 23 | `ui/src/screens/detail/budget-panel.tsx:68-79,112-145,202-205` | `metered === false` → headline in tokens against `cap_tokens`, by-model cards by token share, footnote corrected ("no metered cost: this run's brake is N tokens and the wall clock") | The panel says "no turn reported yet" about a run that worked | R |
| 24 | `ui/src/screens/overview.tsx` fleet header / row | Spend cell reads "free · 12M tok" for an unmetered run; the fleet total excludes it from "$ of caps" and says how many runs were local | The overview is the README's first image; it must not lie about a local run | N |

### Phase 3 — the environment and the docs of record

| # | Item | |
| --- | --- | --- |
| 25 | `docs/credentials-and-teams.md` after `:68`: **"Local models (Ollama, LM Studio, vLLM, llama.cpp)"** — the `models.json` examples from §9, why the dummy key, why `compat`, the Ollama `OLLAMA_CONTEXT_LENGTH` rule, the literal-host rule, `--cap-tokens`, `--local-only`, and llama.cpp's own path | R |
| 26 | `docs/usage.md:47-49,75`: `--key-from-env` is meaningless for a local provider; the pane's proxy env and why loopback goes through it; `--cap-tokens`; `--cap-usd` numeric | R |
| 27 | `docs/troubleshooting.md`: "`credentials_not_configured` for a local provider" and "my local model is not in the picker" — one root cause, one fix | R |
| 28 | `docs/quick-start.md:55-72`: a real Ollama run next to the mock-provider proof run, on a model that is installed here | R |
| 29 | `README.md` quick start: one line — a full run on a local model is possible and costs nothing; link | N |
| 30 | `docs/adr/0006-a-local-model-is-braked-by-tokens.md`: why `metered` is declared from `models.json`, why the brake is mandatory, why local traffic stays inside netguard (D2–D4). Hard to reverse, surprising without context, a real trade-off | R |
| 31 | CI: a Linux job that runs a fake OpenAI-compatible server on loopback under `netguard --mode netns` and proves a pane reaches it — the one path nobody could measure on macOS | R |

## 6. Tests to add

| Suite | Case |
| --- | --- |
| `tests/swarm-preflight.test.sh` (next to `:124-170`) | Keyless loopback provider → `pi_auth_report` `not_ready`; add a dummy `apiKey` → `ready`, `authType api_key`. BLOCKER text for a local provider contains `models.json` and `apiKey`, and does **not** contain `pi /login`. `--key-from-env` with a local provider is refused. `--cap-usd abc` refused; unmetered team without `--cap-tokens` refused; with it, `budget.json` has `metered: false` and `cap_tokens` |
| `tests/swarm-preflight.test.sh` | The D6 probes against a fake server on a loopback port: unreachable → BLOCKER; model id absent → BLOCKER naming the ids present; Ollama-shaped `/api/show` with `num_ctx` 4096 vs declared 131072 → WARNING |
| `tests/model-teams.test.sh` (next to `:116-136`) | `http://127.0.0.1:11434/v1` → allowlist `127.0.0.1`; `http://localhost:1234/v1` → `localhost,127.0.0.1`; `http://[::1]:11434/v1` → `::1`; `llama.cpp/x` → `127.0.0.1:8080` or `LLAMA_BASE_URL`'s host; an all-local team → `--only`, a mixed team → `--allow` |
| `tests/netguard.test.sh` (counterpart of `:76-82`) | The **allowed** side of loopback: `--only 127.0.0.1` lets `CONNECT 127.0.0.1:PORT` through and denies `api.openai.com` |
| `tests/plan.test.ts` / `tests/dry-run.test.ts` | A session entry with an all-zero `cost` → `spent_usd === 0`, `tokens > 0`, `calls > 0`; `budgetPressure` with `metered: false` and `cap_tokens` → `over_budget` at the token line; `cap_per_agent_usd` inert when unmetered |
| `tests/ui-server.test.ts` (updating `:441`) | `validateStart({cap_usd: 0, cap_tokens: N})` valid for a local team, still invalid for a cloud team; `isHostName("localhost")`, `isHostName("127.0.0.1:11434")`, `isHostName("[::1]")` true; `listModels` with an injected `models.json` returns the keyless provider as `local`; `net: "local"` → `--local-only` in argv |
| `tests/summary.test.ts` | A `budget.json` with `metered: false` → the summary speaks in tokens, never "$0.00 of a $N cap" |
| CI (Linux) | The netns loopback proof from #31 |

## 7. Open questions, to settle during implementation

1. **Does Ollama's OpenAI endpoint report cache fields?** Almost certainly
   not (`cacheRead`/`cacheWrite` stay 0, which Pi treats as correct), so a
   local run's `tokens` are not comparable with a cloud run's, and the
   suggested `--cap-tokens` values in the docs must come from measured local
   runs, not from the forensic series.
2. **Linux `netns` reachability** of a loopback server from a pane — the
   proxy sits in the host namespace so it should work; only CI can say (#31).
3. **`pi auth check` and `!command` keys** — availability is judged by
   configuration presence, not by running the command; a failing command
   surfaces at request time. Irrelevant for a dummy key; worth one line in
   the docs.
4. **Which local models can actually drive this harness.** Pi cannot detect
   missing tool support; a model that ignores tool definitions will post
   nothing and claim nothing. The plan should end with one measured run per
   candidate on the `hello` goal (`qwen3-coder-next`, `gpt-oss:20b`,
   `glm-4.7-flash`) and a short table of what each did, the way every other
   feature in this repository was proven.
5. **Discovery extension** (D5): once the static path is solid, an async
   extension factory that reads Ollama's `/api/tags` and registers the
   provider with the right `compat` would remove the hand-written
   `models.json` step. Not before.

## 8. Order of work

Phase 1 first and alone: it is where the two real breaks are, it touches
only `swarm.sh`, the extension and `summary.ts`, and it can be proven with a
real Ollama run on this machine. Phase 2 makes the console tell the same
story. Phase 3 writes it down and closes the Linux gap. Each phase is one PR
with its tests; nothing in Phase 2 or 3 is blocked on the other.

## 9. Appendix

### 9.1 A defect in the current `~/.pi/agent/models.json`

The `azure-foundry` → `DeepSeek-V4-Pro` entry has `"maxTokensField":
"max_tokens"` at the model's top level. Pi's custom-model builder copies
known fields one by one and drops the rest, and `maxTokensField` is a
`compat` key, so it is ignored and Pi sends `max_completion_tokens`. It
belongs here:

```json
"compat": { "maxTokensField": "max_tokens" }
```

Worth checking whether `grok-4.6` needs the same. The harness does not edit
this file (D5); the operator does.

### 9.2 `models.json` for Ollama, on the model installed here

```json
{
  "providers": {
    "ollama": {
      "name": "Ollama (local)",
      "baseUrl": "http://127.0.0.1:11434/v1",
      "api": "openai-completions",
      "apiKey": "ollama",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        { "id": "qwen3-coder-next:latest", "name": "Qwen3 Coder Next (Ollama)",
          "contextWindow": 131072, "maxTokens": 32768 },
        { "id": "gpt-oss:20b", "name": "GPT-OSS 20B (Ollama)",
          "reasoning": true, "contextWindow": 131072, "maxTokens": 32768 }
      ]
    }
  }
}
```

The three load-bearing lines: `apiKey` (any value; without it the gate fails
and the models vanish from `--list-models`), `compat` (autodetection has no
local branch), and `contextWindow` matching `OLLAMA_CONTEXT_LENGTH` on the
server (otherwise Ollama truncates at 4096 while Pi believes 131072). The
`cost` block is omitted on purpose: absent means all zero, which is the truth.

LM Studio is the same shape on `http://127.0.0.1:1234/v1` (the `/v1` is
required; model ids may contain `/`). vLLM is the same on `:8000/v1`, plus
`"thinkingTokenBudgetField": "thinking_token_budget"` in `compat` and
`samplingParams` per model if wanted. llama.cpp is better served by its own
path: `llama-server --models-dir … --jinja --host 127.0.0.1 --port 8080 -c
32768` in router mode, then `LLAMA_BASE_URL=http://127.0.0.1:8080` and
`--model llama.cpp/<loaded id>`; only loaded models appear.

### 9.3 What the preflight will run, for the record

```bash
curl -sf -m 2 http://127.0.0.1:11434/v1/models | jq -r '.data[].id'   # reachable, and which ids
curl -sf -m 2 http://127.0.0.1:11434/api/show -d '{"name":"qwen3-coder-next:latest"}' \
  | jq -r '.parameters' | grep -i num_ctx                              # Ollama's effective window
pi auth check --model ollama/qwen3-coder-next:latest --json --no-refresh # the gate, side-effect free
```

### 9.4 Sources

- Installed package: `~/.nvm/versions/node/v24.13.1/lib/node_modules/@earendil-works/pi-coding-agent/` — `docs/models.md`, `docs/providers.md`, `docs/llama-cpp.md`, `docs/extensions.md`, `docs/session-format.md`, `docs/settings.md`, `CHANGELOG.md`, `dist/config.js`, `dist/core/http-dispatcher.js`, `dist/core/model-registry.d.ts`, `dist/cli/auth-check.d.ts`, and the bundled `@earendil-works/pi-ai` and `undici`.
- [models.md on `main`](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md), byte-equivalent to the installed copy.
- [Discussion #5983 — Ollama context length](https://github.com/earendil-works/pi/discussions/5983); [Issue #2626 — Ollama context overflow](https://github.com/earendil-works/pi/issues/2626).
- Note: `@mariozechner/pi-coding-agent` is deprecated at 0.73.1 in favour of `@earendil-works/pi-coding-agent`, and the source moved from `badlogic/pi-mono` to `earendil-works/pi`. This repository names neither package; it links to pi.dev, which still resolves.
