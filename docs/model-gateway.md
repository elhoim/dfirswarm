# The model gateway

With `--model-gateway`, every model call an agent's VM makes goes through
one process on the host. That process holds the provider's key, reads each
call's usage off the provider's own answer, and refuses a call that would go
past a cap. It is off unless the flag is given, and it applies to
`--isolation microvm` runs.

Without it, a VM run has two limits ([ADR 0009](adr/0009-agents-live-in-microvms.md)):

- Spend is what each seat reports. Pi inside the VM counts its own usage and
  the hub adds up the reports. A seat that under-reports is not caught.
- The budget check before a call runs inside the VM, under the guest's root.
  It is advisory there.

The gateway moves both to the host. The usage it counts is what the
provider sent back, and a call refused on the host never reaches the
provider.

## What the agents see

Each VM's Pi is pointed at the gateway through its own `models.json`. Pi
lets a built-in provider's base URL and key be overridden there without
redefining its models. The base URL keeps the provider's host in its path,
for example:

```
http://host.microsandbox.internal:<port>/p/openai/api.openai.com/v1
```

Pi decides some request fields from the text of the base URL: OpenAI's
prompt-cache key, OpenRouter's dialect, and others. Keeping the host there
keeps those decisions as they would be without the gateway.

The key a VM holds is its seat's gateway token. It works only against this
gateway, only for that seat, and only for the providers that seat's models
use. It is not a provider key, and no provider key is in the VM.

## What the gateway does with a call

1. It takes the seat from the token. No header, path or body the guest
   writes can name another seat.
2. It checks the route: `/p/<provider>/<host><base path>/<endpoint>`. The
   host must be the provider's own, and the endpoint one a model client
   calls. For chat completions, responses and messages the method must be
   POST; for the model list it must be GET. Anything else is refused and
   never leaves the host. The gateway is not a general proxy.
3. It checks the stops and the caps (below).
4. It forwards the call with the host's key in the header the provider
   reads, and drops the seat's token, cookies and any organisation or
   project header the guest set.
5. It streams the answer back as the provider sent it, byte for byte, and
   reads the usage from it on the way. That is the usage chunk of an OpenAI
   chat stream, the finished response of an OpenAI responses stream, or
   Anthropic's `message_start` and `message_delta`. The cost is priced from
   Pi's own model catalogue, the way Pi prices it.

## Stops and caps

The gateway reads the run's `budget.json` on every call and applies the
caps the harness already has: the run's cap, `--cap-per-agent`, the
per-model caps and the token cap. It applies them to the spend it measured
itself.

- **The harness's own stop is refused at once.** That is a seat's done or
  dead marker, or the run's sentinel. In a VM run without the gateway, a
  seat the hub has stopped can still reach its model. With the gateway it
  cannot.
- **A cap or the wall clock is refused three minutes after it is first
  crossed.** When a seat goes over a cap, the harness tells it to post its
  findings and gives it a two-minute grace to do so, which takes model
  calls. The gateway allows that grace and one minute more, then refuses.
  A run can therefore go past a cap by what its seats spend in those three
  minutes.

A refusal comes back in the provider's own error shape, so the agent sees
the reason as the provider's message. It is also written to the gateway's
log and, once a minute per seat and reason, to the trace.

## Limits on a seat

Per seat, by default:

- 4 calls in flight at once;
- 20 calls at once, refilled at 60 a minute;
- request bodies up to 32 MiB;
- a call cut after 10 minutes with nothing from the provider.

These are in the gateway's config (`limits`).

## What is written, and where

- `traces/model-gateway.jsonl` has one line per call: the seat, the model,
  the status, the tokens, the cost, the time and the byte counts. Refusals
  get a line too, and a knocking loop is collapsed to a count. Each line is
  chained to the one before by its hash. No request or response body is
  written, and no key.
- `traces/model-gateway.json` holds the totals per seat. A restarted
  gateway reads them back.

Both are under `traces/`, which no VM can write.

The gateway's config holds each seat's token and each provider's upstream,
and never a key. It is written at kickoff into the run's hub directory
(0600), where no VM reaches. The keys are resolved by the gateway itself at
start, with Pi's `pi auth print-api-key`, and are held in its memory only.

## What it does not front

A provider the gateway cannot front keeps the placeholder path: msb swaps
the placeholder for the key on the way out, as in a run without the
gateway. The kickoff names each one, and the report says that provider's
spend is what its seats reported. These are:

- **Subscriptions** (Claude Pro/Max, ChatGPT through Codex): the guest's Pi
  shapes the request from the token itself.
- **Providers that sign each request** (Bedrock, Vertex).
- **APIs whose usage the gateway does not read** (Google's, Mistral's).
- **Providers whose models do not share one API and one base URL**
  (OpenRouter and Fireworks, which serve both OpenAI-style and
  Anthropic-style models).
- **A base URL only the operator can complete** (Azure's resource name,
  a Cloudflare account).
- **Local models**: nothing is billed and there is no key to hold. They are
  reached as before, through msb's host gateway.

A call whose provider sent no usage is counted with its cost unknown, and
the count of such calls is kept per seat. So is a call to a model Pi's
catalogue does not price. Neither is counted as free.

## In the run's record

- **Budget.** The hub folds each fronted seat's measured totals into
  `budget.json` on every tick and marks the seat's row
  `metered_by: "model-gateway"`. Every cap, steer and stop then reads the
  host's figure. A seat's own report can only raise it, never lower it.
- **Keeper and stop.** The keeper (`scripts/hub-supervise.sh`) brings a
  gateway that died back on the same port with the same config, since the
  VMs were given that port, and puts `model_gateway_restarted` on the
  trace. `stop` ends it after the VMs are put away. Its config goes with the
  hub directory.
- **Custody and the package.** Custody checks the chain of
  `traces/model-gateway.jsonl`, puts the result in its verdict and anchors
  the log's hash outside the run. The package carries the log. A host run
  has no gateway, and custody does not read a file of that name there.
- **Report.** The report and the summary say that the spend of the fronted
  providers was metered on the host, and name each declined provider, whose
  spend is what its seats reported. They also give the gateway's refusals
  and any calls it could not price.
