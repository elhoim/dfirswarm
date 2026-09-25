# A local model is braked by tokens, declared at kickoff, inside netguard

A model served from this machine or this network — Ollama, LM Studio, vLLM,
llama.cpp, any OpenAI-compatible server on loopback, a private range or a
`.local` name — bills nothing, and Pi reports its cost as an exact zero: the
`cost` block of a `models.json` provider defaults to all zeros and
`calculateCost` multiplies them through. A swarm on such a team therefore
could never reach `spent_usd >= cap_usd`, and before this decision it ran
with the wall clock as its only brake, by accident, while every surface
reported "$0.00 spent" about a run that had worked.

Three things were decided together, because each one is only safe with the
other two.

**Metering is declared, not inferred.** A session cannot tell a free run from
an unmeasured one: both sum to zero. So the kickoff decides `metered` once,
from `models.json` — a model whose `cost` block is absent or all zero is
unmetered, a cloud provider Pi knows on its own is metered, an unknown one is
assumed to bill because that is the cheap mistake — and writes the answer to
`budget.json` and the registry. Everything downstream reads it; nothing
re-derives it from spend. The same rule treats a cloud gateway defined in
`models.json` without a `cost` block as unmetered, which is not a mistake:
Pi would report $0 for it too, and the USD cap would never fire. The
operator either states the rates or takes the token cap.

**An unmetered team must have a token cap.** `--cap-tokens N` is required
when nothing on the team bills and optional as a second brake otherwise;
`over_budget` becomes `tokens >= cap_tokens`; the steer and the harness stop
say tokens when tokens were the reason. Tokens here are Pi's own totals over
every turn, so the number grows fast and is not comparable with a cloud
run's — the context is re-sent each turn and a local server reports no cache
fields — which is why the docs give a scale rather than a formula. The
alternative, letting a free team run with no cap because it costs nothing,
is the state this project exists to prevent: a run unbounded by accident.

**Local traffic stays inside netguard.** Pi installs an environment-reading
proxy agent at startup and tunnels even a plain-HTTP origin as `CONNECT`, so
a `http://127.0.0.1:11434` base URL goes through the sidecar like any cloud
call; the sidecar runs on the host and reaches loopback in both `proxy-only`
and `netns` modes. Bypassing it with `NO_PROXY` would take the model calls
out of the one place the harness sees every request, for no gain: the
tunnel is a raw socket pipe, so keep-alive survives and the overhead is one
hop. What the allowlist needs is the literal host from the base URL and its
other spelling, `127.0.0.1` and `localhost`, because neither Pi's `NO_PROXY`
matcher nor the proxy's rules resolve names. `--local-only` then turns the
allowlist into those endpoints alone and tells Pi to make no startup calls.

Two consequences the harness accepts rather than papers over. Pi cannot tell
whether a model supports tool calls, so a local model that ignores tool
definitions posts nothing and claims nothing instead of failing loudly; the
only defence is to measure a candidate on the hello goal first, which the
docs say. And Ollama's OpenAI endpoint uses its own context window — 4096
by default — whatever `contextWindow` declares, and truncates silently; the
kickoff reads the effective value back and warns, but the fix is on the
server, in `OLLAMA_CONTEXT_LENGTH`, not in the harness.

The harness never writes `models.json`. It is Pi's configuration and the
operator's; when something is missing — the placeholder `apiKey` Pi wants
before it will list a provider, the `compat` block Pi's autodetection cannot
supply for a local URL — the kickoff prints the exact lines to add and
refuses to start. A discovery extension that registers Ollama's models at
runtime was considered and set aside: it would hide precisely the settings a
local server gets wrong when they are hidden.

## Later: a subscription is braked the same way

On 2026-09-25 the same reasoning was extended to a team on a subscription (an
OAuth login in Pi's store, such as `openai-codex`). Its dollars are not zero,
which is worse: they are an estimate from a price list for a model Pi runs as
a custom id, charged to no one, and not comparable across models. On the
BelkaCTF #6 mixed run a GPT-6-Luna seat that used ten million tokens read
$0.13 while a Daybreak Blue seat with a similar count read $14, so a dollar
cap stopped one model's seats early and let another's run on. A seat on a
subscription does not make a team metered; a team with no metered seat needs
`--cap-tokens`, and `--cap-per-agent-tokens` is its per-seat brake. Every cap
can be changed while the run goes on (`swarm.sh cap`).
