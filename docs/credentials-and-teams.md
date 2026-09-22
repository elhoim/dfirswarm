# Credentials, subscriptions, and mixed-model teams

## Credentials: ask Pi, do not guess

A swarm can authenticate four different ways, and the harness does not try to
tell them apart:

| How | Set up with | What the preflight prints |
| --- | --- | --- |
| A Claude or ChatGPT/Codex **subscription** (OAuth) | `pi /login` | `anthropic subscription (OAuth, refreshed by Pi)` |
| A stored **API key** | `pi /login` | `deepseek api_key via Pi's own store` |
| A provider configured in **models.json** (self-hosted, local, a gateway) | edit `models.json` | `mockswarm api_key via Pi's own store` |
| A key exported into the shell | `--key-from-env` | `$DEEPSEEK_API_KEY passed to each pane` |

The gate is one call to `pi auth check --model <provider/id> --json`, run once
per distinct model before any pane opens. Pi is the thing that will actually do
the authenticating; every hand-rolled version of this check grew a bug that
either waved through a run with no usable credential or refused one that was
perfectly fine. The check also refreshes an expired OAuth token as a side
effect, which is what you want *before* the panes go behind netguard.

A subscription needs no API key and no `--key-from-env`. It does need its token
endpoint on the netguard allowlist, because an access token expires mid-run and
a refresh that cannot reach the endpoint fails the swarm rather than the
request:

| Provider | API host | OAuth token endpoint |
| --- | --- | --- |
| `anthropic` | `api.anthropic.com` | `platform.claude.com` |
| `openai-codex` | `chatgpt.com` | `auth.openai.com` |

Both are in `provider_hosts_for_model` and in netguard's own default list.

### Azure OpenAI

Pi's `azure-openai-responses` provider serves the same model ids as OpenAI
(`azure-openai-responses/gpt-5.4`, `gpt-5.4-mini`, `gpt-5.5`, …) against the
customer's own resource. Four settings: the key (`AZURE_OPENAI_API_KEY`), the
endpoint (`AZURE_OPENAI_BASE_URL`, `https://<resource>.openai.azure.com` or
the `.cognitiveservices.azure.com` / `.ai.azure.com` forms; or
`AZURE_OPENAI_RESOURCE_NAME`), and optionally the API version
(`AZURE_OPENAI_API_VERSION`) and the deployment map
(`AZURE_OPENAI_DEPLOYMENT_NAME_MAP=gpt-5.4=<deployment>`). The clean way is
Pi's own store, where the key never touches the shell or `ps`:

```json
{
  "azure-openai-responses": {
    "type": "api_key",
    "key": "<the key>",
    "env": {
      "AZURE_OPENAI_BASE_URL": "https://<resource>.openai.azure.com",
      "AZURE_OPENAI_API_VERSION": "<api version>",
      "AZURE_OPENAI_DEPLOYMENT_NAME_MAP": "gpt-5.4=<deployment>"
    }
  }
}
```

in `~/.pi/agent/auth.json` (mode 0600). `pi auth check --model azure-openai-responses/gpt-5.4 --json`
is the gate, as for every provider. The netguard allowlist needs the
resource's host: `provider_hosts_for_model` reads it from the shell or from
that store entry, and the kickoff warns when it finds neither, in which case
`--allow-host <resource>.openai.azure.com` does it. Azure settings exported in
the kickoff shell are forwarded to the panes; the key itself only with
`--key-from-env`.

### Azure AI Foundry, and any other provider from `models.json`

An Azure AI **Foundry** resource is not the same thing as an Azure OpenAI
resource: it serves third-party models (Grok, DeepSeek, Llama, Mistral) from
your own deployments, on an OpenAI-compatible route
`https://<resource>.services.ai.azure.com/openai/v1`, where the model name is
the **deployment** name. `azure-openai-responses` does not carry those model
ids, so define the provider in Pi's own `~/.pi/agent/models.json` instead:

```json
{
  "providers": {
    "azure-foundry": {
      "name": "Azure AI Foundry",
      "baseUrl": "https://<resource>.services.ai.azure.com/openai/v1",
      "api": "openai-completions",
      "models": [
        { "id": "grok-4.6", "reasoning": true, "input": ["text", "image"],
          "contextWindow": 500000, "maxTokens": 128000,
          "cost": { "input": 2, "output": 6, "cacheRead": 0.5, "cacheWrite": 0,
                    "tiers": [{ "inputTokensAbove": 200000, "input": 4, "output": 12, "cacheRead": 1, "cacheWrite": 0 }] } },
        { "id": "DeepSeek-V4-Pro", "reasoning": true, "input": ["text"],
          "contextWindow": 1000000, "maxTokens": 384000, "maxTokensField": "max_tokens",
          "cost": { "input": 1.74, "output": 3.48, "cacheRead": 0.145, "cacheWrite": 0 } }
      ]
    }
  }
}
```

with the key in `auth.json` under the same provider id. Then
`--models "azure-foundry/grok-4.6=4,azure-foundry/DeepSeek-V4-Pro=3"`.

Two things worth knowing:

- **The costs are yours to state.** Pi bills the swarm from the `cost` block,
  so a provider defined here reports spend at whatever rates you write, and a
  missing block means a run that reports $0 and a spend cap that never fires.
  Take the numbers from the provider, not from the model's own vendor: the
  rates above are Azure's own (retail prices API, Global deployments,
  commercial regions), and DeepSeek V4 Pro costs $1.74 per 1M input tokens
  there against $1.32 at DeepSeek itself. The first run here was configured
  from neither, and under-reported its bill by a third —
  [the case README](use-cases/dfir-c07-sysinternals-azure/README.md) shows
  the arithmetic. Azure's current figures for any model:

  ```bash
  curl -s "https://prices.azure.com/api/retail/prices?\$filter=productName%20eq%20'Azure%20Grok%20Models'" \
    | jq -r '.Items[] | "\(.meterName) \(.retailPrice * 1000) USD/1M \(.armRegionName)"' | sort -u
  ```
- **A rate can depend on the hour.** DeepSeek's own API charges half its list
  price outside 01:00–04:00 and 06:00–10:00 UTC on weekdays
  ([its pricing page](https://api-docs.deepseek.com/quick_start/pricing/):
  V4 Pro at $1.32 input, $3.96 output, $0.044 cached input per 1M at peak).
  A `cost` block holds one number, so Pi bills the peak rate around the
  clock; an off-peak run really costs half of what the console showed. That
  is the safe direction for a cap, and it means the reported figure is an
  upper bound rather than the invoice — the DFIR cases recompute it.
- **The host comes from `baseUrl`.** `provider_hosts_for_model` falls through
  to `models.json` for any provider it does not know, so a Foundry resource, a
  gateway or a local server reaches netguard's allowlist without
  `--allow-host`. Check it with
  `pi auth check --model azure-foundry/<deployment> --json` before the run;
  the kickoff refuses to start on anything but `ready`.

### Local models (Ollama, LM Studio, vLLM, llama.cpp)

A model served from this machine or this network is a `models.json`
provider like any other, with three things Pi's own documentation is explicit
about and the harness now checks for you.

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
        { "id": "qwen3-coder-next:latest", "contextWindow": 131072, "maxTokens": 32768 },
        { "id": "gpt-oss:20b", "reasoning": true, "contextWindow": 131072, "maxTokens": 32768 }
      ]
    }
  }
}
```

- **The `apiKey` is a placeholder, and it is mandatory.** Pi lists a provider
  only when it has *some* credential, even one the server ignores; without it
  `pi auth check` answers `not_ready / credentials_not_configured` and the
  models are absent from `pi --list-models`. Any value will do. There is no
  `pi /login` for this and nothing for `--key-from-env` to forward; the
  kickoff says so, with the snippet to add, when it meets a keyless local
  provider.
- **The `compat` block is required.** Pi autodetects compatibility from the
  URL and has no rule for a local server, so without it Pi sends the
  `developer` role, `reasoning_effort`, `store` and `max_completion_tokens`,
  which Ollama, vLLM and SGLang reject. The kickoff warns when the block is
  missing.
- **`contextWindow` must match the server.** Ollama's OpenAI-compatible
  endpoint ignores `num_ctx` in a request and uses its own default — 4096 on
  current builds — while Pi budgets against whatever you declared, and the
  truncation is silent. Set `OLLAMA_CONTEXT_LENGTH=131072` in Ollama's
  environment (or `PARAMETER num_ctx` in a Modelfile), restart it, and
  declare the same number here. The kickoff reads the effective value back
  from Ollama and warns when the two disagree.

No `cost` block: absent means all zero, which is the truth, and it is how the
harness knows the team is not metered. Pi reports the run's cost as an exact
$0, so **a USD cap cannot stop it**; the kickoff requires `--cap-tokens N`
for such a team and records `metered: false` in `budget.json`. The summary
and the console then speak in tokens rather than saying "$0.00 spent".

```bash
scripts/swarm.sh start --model ollama/qwen3-coder-next:latest --n 3 \
  --cap-tokens 20000000 --wall-clock 30 --local-only \
  --goal-file prompts/goals/hello.md
```

Before any pane opens the kickoff asks the server itself: that it answers on
`baseUrl`, that the model id is in its `/models` list (a BLOCKER naming what
it does serve when not), and, for Ollama, what context it will really give.
The traffic then goes through netguard like every other model call — Pi
tunnels even a plain-HTTP origin as `CONNECT`, and the sidecar runs on the
host, so loopback is reachable — with the literal host from `baseUrl` on the
allowlist, and its other spelling too (`127.0.0.1` ↔ `localhost`), because
neither Pi's proxy matcher nor the proxy resolves names. `--local-only` turns
the allowlist into those endpoints alone.

LM Studio is the same shape on `http://127.0.0.1:1234/v1` (the `/v1` is
required; its model ids may contain `/`). vLLM is the same on `:8000/v1`,
with `"thinkingTokenBudgetField": "thinking_token_budget"` in `compat` if
you want thinking budgets. llama.cpp is better served by Pi's own provider:
run `llama-server` in router mode with `--jinja` (which is what enables tool
calling), export `LLAMA_BASE_URL=http://127.0.0.1:8080` and
`LLAMA_API_KEY=local`, and name the model `llama.cpp/<loaded id>`; only loaded
models are listed, and the harness takes the host from `LLAMA_BASE_URL`.

Two things a local model cannot promise: Pi has no way to tell whether a
model supports tool calls, so one that ignores tool definitions will post
nothing and claim nothing rather than fail loudly; and prompt-cache fields
stay zero, so a local run's token total is not comparable with a cloud run's.
Measure a candidate on `prompts/goals/hello.md` before trusting it with a case.

### What a subscription will not do

A login is not the same as an entitlement. Anthropic answered a third-party
request on a Claude plan with:

> Third-party apps now draw from your extra usage, not your plan limits.

That is a billing decision at the provider, not a harness problem: OAuth worked,
the request reached the API, and the API declined it. On the ChatGPT side only
some models are offered to a ChatGPT account — `gpt-6-astra` ran, `gpt-5.4` and
`gpt-5.3-codex-spark` came back "not supported when using Codex with a ChatGPT
account". The preflight cannot see any of this, because `pi auth check` asks
whether Pi *has a credential*, not whether the account may use a given model.
The first agent turn is where you find out.

## What a run may install

A case can turn on a reader this host does not have. `--allow-install` is the
narrow answer: `pypi.org` and `files.pythonhosted.org` join netguard's
allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox,
and `python3 -m pip install --user <package>` therefore installs into the run
and nowhere else. It is off by default; the contract says the rule when it is
on, and asks the agents to record what they installed in the ledger.

Two things it deliberately does not do. It does not open Homebrew or a system
package manager: those write to `/opt/homebrew` and `/usr`, outside the
sandbox, on a machine the next case also has to trust. And it does not grant
root — there is none here, nothing mounts, and that is the guarantee that
makes `inputs/` read-only mean anything. For reading an encrypted or virtual
volume this costs nothing: libbde, libvhdi, libluksde and pytsk3 all read in
place, and the `crypto` toolbox set names them so a kickoff finds out before
the run instead of at minute forty. For a case that genuinely needs a mount,
the answer is a container, not `sudo`; see [safety](safety.md).

## Mixed teams

One swarm does not have to be one model:

```bash
scripts/swarm.sh start \
  --models "openai-codex/gpt-6-astra=2,deepseek/deepseek-v4-pro=2" \
  --cap-usd 10 --goal-file prompts/goals/hello.md
```

N is the sum of the counts. Pass `--n` as well and it is checked against that
sum rather than silently winning. `--model` and `--models` are mutually
exclusive: one is "everybody runs this", the other is "here is the team".

What the harness does with it:

- **Every distinct model is credential-checked** before a pane opens, so a team
  that can only authenticate half of itself fails at kickoff rather than three
  agents in.
- **The allowlist is the union** of every provider's hosts. Allowing only the
  first model's provider leaves the other agents unable to reach theirs, which
  looks exactly like a hung swarm.
- **Each agent's model is in `team.json` and named on the board.** Who is
  running what is the one thing an agent cannot work out for itself, and the
  only basis on which it could sensibly hand a slice to a peer.
- Agents are assigned in spec order: the first model named gets agent `00`.

A four-agent run of the `hello` goal, two Codex agents and two DeepSeek:

```
s85a500 -> openai-codex/gpt-6-astra    $0.332720
s85a501 -> openai-codex/gpt-6-astra    $0.289682
s85a502 -> deepseek/deepseek-v4-pro    $0.028674
s85a503 -> deepseek/deepseek-v4-pro    $0.034981
```

All four ids landed in the artifact, both checks passed, and the sentinel was
written by a DeepSeek agent. The order-of-magnitude difference in the per-agent
column is the argument for mixing in the first place — and a reminder that the
Codex figures are Pi's price-table estimate against a subscription, not money
charged.

## Editing the goal from the web app

`/new` has the goal document as a first-class editor, backed by a library:

- **Goal library** — the markdown files in `prompts/goals/`. Load one into the
  form, or save what you have written back under a name. The CLI launches from
  the same files with `--goal-file`, so there is one copy, not two.
- **Goal tab** on a swarm — the goal document this run was given, and below it
  the rendered `SWARM.md` the agents actually read.

The live contract is **read-only**, deliberately. `SWARM.md` is a protected
path: an `edit`/`write` is blocked and a claim on it refused, because an agent
that could edit its own definition of done could certify itself. A *shell*
write is the gap the harness cannot close — no hook can stop a command
mid-flight — so that one is detected afterwards and announced on the board,
and `await-done.sh` reads the checks from the registry rather than from the
sandbox for exactly this reason. Changing a contract
under a running team would also leave half of them working to a goal the other
half never saw. So the Goal tab offers "edit a copy and relaunch", which opens
the kickoff form prefilled, and "save to library" to keep a contract that
worked.

Saving a goal needs the server token, the same as starting a swarm, and a goal
with no `## Definition of done` is refused on the way in — the same rule the CLI
applies.
