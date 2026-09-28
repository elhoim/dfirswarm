# A dynamic network: lookups decided by rules, made on the host, sealed as external material

An agent that needs something the evidence cannot give and a reference
service can (a domain's registration, a certificate log, a CVE, a hash's
reputation, a place) asks for **one bounded lookup**. The hub decides the
request by **rules alone**, in a fixed order, under the run's **case
policy**, and records the decision before it answers. A granted request is a
**capability**: one exact method and URL, for one principal, for a few
minutes and a counted number of uses. A **fetch service** on the host, a
process of its own with no evidence, makes exactly that request and nothing
else, and seals the answer as a **capture**, which enters the ledger as
**external material**. Where a client needs a socket, a **socket grant** says
plainly what it cannot control.

Status: accepted, 2026-09-28, as Plan 3's fourth phase (work package 6).
Designed by Claude, Fable and Astra over three rounds (Plan 3's joint
documents, section C and phase 4) and approved by the owner with the other
defaults of the plan: `standard` is the default preset, and no model sits in
the decision.

## Context

- In the ctf12 round every lookup went through the operator: an agent closed a
  lead `needs_operator`, the operator allowed a host with `swarm.sh lead note
  --allow-host`, and a job fetched it. Nothing recorded what was fetched, and
  the host stayed allowed for every later job of the run.
- A host allowlist cannot say "HEAD only" or "this URL only". The host proxy
  (`scripts/netguard-proxy.mjs`) forwards an opaque CONNECT once the host and
  port are allowed, and a VM's msb policy keeps a host that carries no secret
  on end-to-end TLS (`scripts/vm.ts`): neither sees a method or a path.
- A seat's msb policy is fixed when its VM boots. Widening it means a new VM.
- A lookup discloses. A hash sent to a reputation service, a coordinate sent
  to a geocoder, a domain sent to a registry all tell a third party what the
  case is interested in, and in a published case a search engine or a
  write-up site ends the examination's independence.

## Decision

1. **Two controls, kept apart.** The run's network mode is `closed` (the
   default, today's behaviour: the models' hosts, the package index with
   `--allow-install`, `--allow-host`, and what the operator allows later),
   `dynamic` (this ADR) or `open` (every public host: `--no-netguard`). The
   **case policy** says what the examination permits whatever the mode:
   `lookups` (none, reference, evidence_linked, any), `contact` (passive or
   active), which **disclosure classes** may leave (hash, public_indicator,
   coordinate, internal_name, personal, file_upload), the legal text the
   operator fills in, provider retention, whether more evidence may come,
   what material may be used for. Four **presets** set every field:
   `standard` (hashes and public indicators to approved passive adapters;
   active contact is the operator's), `live_adversary` (stricter: nothing the
   evidence names is ever contacted, no socket grant), `internal` (nothing
   leaves) and `ctf` (a published case: no search, no write-up site, only
   reference or evidence-linked adapters, and what is sent must be in the
   evidence). The goal's metadata block and the kickoff's flags override one
   field at a time (`--network`, `--policy`, `--lookups`, `--contact`,
   `--disclosure`); a combination that contradicts its preset is refused at
   kickoff, never resolved by guessing. So is a run whose **effective direct
   egress** does not fit it: under `ctf`, `internal` and `live_adversary` no
   host is reached without a grant, so `--allow-host`, the package index that
   `--allow-install` would open (unless `--no-pypi`) and a pack's secret hosts
   are each refused, naming where they came from. The policy is recorded in
   `network/policy.json` (read on every decision, read-only to every VM),
   SWARM.md and the registry. An agent can weaken neither control.
   `scripts/case-policy.ts` holds it, as the seed of Plan 3's case contract.

2. **Rules decide, in order.** `scripts/net-policy.ts` evaluates a request in
   eight steps: who asks (the channel, never a field), the request's shape (a
   strict schema, an adapter's typed params, an open lead the asker holds),
   the case policy, the hard denials (search engines, write-up and CTF sites,
   paste sites, social platforms, proxies and caches, logins, uploads:
   `network/deny.json`), credential patterns and the run's sensitive values in
   what would leave (each URL component, as sent and percent-decoded; a
   sensitive value anywhere inside one, not only a component equal to it),
   the evidence link (what leaves must be found, as sent, in the source bytes
   the request cites, read on the host: the evidence, the catalogue, a
   capture, or the output of a job that declared the sources it read and
   whose own command does not hold the value; an agent's sealed file, a bare
   digest and a ledger entry's own words are not evidence, and an entry counts
   only through the objects it cites), enforceability, quotas (counted again
   under the lock that issues the grant, so a burst cannot pass them
   together). The
   first step that refuses decides, with machine-readable reasons (step,
   rule, code, detail, whether the operator may override it). A request no
   rule can place, one with no adapter, is **uncertain and refused**: nothing
   guesses what an arbitrary URL is. A refusal stops that avenue and never
   touches the lead. The same request (by its digest, which is everything the
   rules read) gets the same answer. Free text, the purpose, is stored and
   shown and read by no rule, so no words in a request or in a response can
   change a decision. There is no model in the decision; if a steward is ever
   added it may only narrow, and it stays off under `ctf`.

3. **One operator item per host and lead.** A refusal the operator may
   override opens an item (`NI-<m>`) for its host and lead, or joins the one
   that is open, and the refusal says so; the item is a line in
   `operator-requests.jsonl` and a board post. The operator grants a request
   (`swarm.sh net <run> grant NR-<n> --why TEXT`): the same engine runs with
   the overridable reasons waived and recorded; a login, an upload, a
   credential, a sensitive value, a malformed request or an internal case
   stay refused whoever asks. A refusal that a later step would make
   unoverridable is not overridable at all, so no item is opened for a
   request nobody may grant.

4. **The adapter catalogue** (`network/adapters.json`) is the positive list:
   RDAP (domain, IP, AS number, through rdap.org, following its referral
   only to the registries the adapter names), crt.sh, the NVD CVE API, CISA's
   KEV feed, CIRCL hashlookup, RIPEstat (prefix and AS overview), Nominatim
   (reverse and search), Overpass (a structured query built from a
   coordinate, a radius and a tag, never free Overpass QL), YouTube oEmbed
   (the title and nothing else) and an evidence-linked HEAD of one exact URL,
   its redirect never followed (active contact). VirusTotal by hash is there
   too, off unless the operator configures a key on the host
   (`DFIRSWARM_VT_API_KEY`), which only the fetch service reads and no VM is
   given. An agent gives typed values (a domain, a hash, a coordinate); the
   adapter's template places each one, percent-encoded; none can become a
   host, a path segment or a query key.

5. **Grants are capabilities** (`N-<k>`), chained with the lead register's
   code in `network/grants.jsonl` with every request (`NR-<n>`), decision,
   binding to a job, revocation, item and contamination. A grant names its
   principal (`seat:<id>`, or a job of a seat's once bound: `job:<id>`), its
   lead, its exact method and URL, its lifetime (five minutes for a single
   lookup), its uses (one) and its byte limit. Its state is derived, never
   stored: `granted`, `active`, then `exhausted`, `expired` or `revoked`
   (by the operator, when its lead closes, when its job ends).

6. **The fetch service makes the request** (`scripts/net-fetch.ts`): a host
   process like the model gateway, started from the run's frozen harness,
   kept by the hub's keeper on the same loopback port, reading only the
   network records and writing only its log and the captures. Each
   principal's token is an HMAC of its name under a secret kept in the hub's
   directory. A seat's `net_fetch` goes through the hub, which asks as that
   seat; a job's worker is booted with the fetch service's port allowed and
   its own job's token in its environment, and calls it itself (`python3
   /job/net_fetch.py N-<k>`). The service refuses anything but the grant's
   method and exact URL, sends no body and only its own headers (a user
   agent, an accept, and a host-managed key where the adapter has one), so no
   provider key, seat token or cookie can leave with it. It resolves the name
   once, refuses it when any address is loopback, private, link-local (the
   metadata address with it), carrier-grade NAT, multicast, reserved or an
   IPv6 form of those (an IPv6 address is classified by its parsed bytes: only
   global unicast outside the special and embedding ranges is public, however
   it is written), connects to the address it checked with TLS verified
   against the name, and never asks DNS again for that hop: a changed answer
   is never used. It is no proxy: CONNECT and absolute-form requests are
   refused. The use is written to `network/fetches.jsonl` and fsynced before
   a byte leaves; a log that cannot be written stops the fetch. The grant is
   held to again at every point where time has passed: under the log's lock
   before the attempt is written (after any wait for the adapter's rate, whose
   per-host slot is reserved at once so two fetches cannot share it), after
   each DNS answer, during the transfer and before anything is published. A
   body over the limit is refused whole and its size recorded, never kept in
   part; a revocation or expiry during a transfer stops it, and what came is
   kept as incomplete and delivered to nobody. An oversize, broken or stopped
   answer ends the fetch where it is: only a whole, in-limit redirect is
   followed. The result line is written, durably, **before** a capture is
   published: a capture no seat can read until the log says what it is, and
   one whose line cannot be written is not published at all. Every attempt
   gets an outcome: an attempt with no result (the service stopped
   mid-fetch) is given one when the service starts again and then
   periodically, saying nothing of it was published, and custody reports any
   attempt still without one as incomplete.

7. **Captures are sealed store objects, and external material.**
   `store/net/<k>/<n>/` holds the request (the line, the headers sent, a key
   named and not recorded, the address, TLS identity and each hop), the
   response (status and headers), the body, a summary and a manifest, every
   file hashed and read-only. `net:<k>/<n>` resolves like `job:` and a job
   may declare it as an input. Each capture is recorded on the ledger as an
   entry of the new kind `external` (`source_class: external_capture`) with
   its provenance in the chained core; the harness writes it, never an agent.
   A capture's hash proves its bytes, not their truth or their fit to the
   time of the events: an examiner records what it establishes. What is
   derived from a capture stays external (a job that read it or fetched it,
   an entry citing that job, an answer resting on that entry), and
   `check-answers` names every answer that rests on it. The lineage is read
   from what a job resolved, never from how it spelled it: its scope manifest's
   paths and digests (`store/net/1/1/body` is `net:1/1`, a copy of a
   capture's bytes is that capture), and a job whose scope was broad could
   read every capture sealed before it started. An adapter that
   delivers only some fields (the title) delivers those; whatever was
   received and not delivered (the whole response and its headers, a partial
   body, an answer withheld because its grant ended) is kept beside the run,
   outside every VM (`<run>.netraw/<k>/<n>/`), recorded in the capture by
   size and hash, verified by custody and packaged under `network/raw/`. A
   response that exposed what the policy prohibits (a redirect to a denied
   host, a grant the operator made over a category denial) is recorded as
   contamination: revoking access cannot make a seat forget it.

8. **A socket grant is its own type (tier 2)**: a host and a port for a job's
   own client, through the worker's msb policy, with no method or path
   control and no content capture; its connection log is the worker's policy,
   not a capture. It is the operator's alone, needs a case policy that
   permits it (`standard`), and is refused under `ctf`, `internal` and
   `live_adversary`. The grants chain is its authority: a host is written
   one canonical way (lower case, the default port dropped), and an operator
   host that a socket grant covers is in force only while the grant is,
   however it was spelled. `swarm.sh lead note --allow-host` now makes one
   and says so; the kickoff's `--allow-host` says it is a static socket
   allowance for the whole run.

9. **The operator sees and acts**: `swarm.sh net <run> list|grant|deny|revoke`
   and the console's **Network** tab (the policy, what waits on the operator,
   every grant with its time left and a revoke, every request with its
   reasons, every capture and what the fetch service refused). Every act
   needs a reason, writes the grants chain, lands on the trace and the
   operator's record, and is posted to whoever asked. Custody seals both
   chains, re-hashes every capture and every file kept beside the run, and
   names every attempt with no recorded outcome; a package carries them.
   `swarm.sh purge` removes `<run>.netraw/` with the run.

## Consequences and limits

- Nothing changes for a run that does not ask: `closed` is the default, and
  the case policy of such a run is recorded as `standard`, network closed.
- A host run has no hub and no fetch service: `network: dynamic` needs a
  microVM run and is refused otherwise.
- The evidence link is a literal match (case-insensitive for ASCII, UTF-8 and
  UTF-16LE), bounded at 256 MiB of each cited object. A value the agent
  converted (a coordinate from EXIF rationals) is cited from the job output
  that holds it as sent; a refusal says so.
- Domain categories cannot enforce a published case's integrity alone (a
  write-up can sit on any personal site); `ctf` therefore also requires that
  every value sent is in the evidence, so the question's own words can never
  be what is looked up.
- The harness does not see a model provider's own retrieval (a provider-side
  browsing tool); where one exists it is outside this mediation, and a run
  that must exclude it must use a model that has none.
- A socket grant's limits are real: host and port, the connection allowed
  and nothing more. A worker already running keeps the network it booted
  with until it ends; revocation reaches the next one.
- A job's capture reaches the ledger on the hub's next round (fifteen
  seconds), a seat's at once.
- Operator items are operator requests with their own ids since the case
  contract ([ADR 0014](0014-the-case-contract-says-what-comes-in-and-what-is-asked.md)):
  the grants chain's `item` event is the commit, the request is derived from
  it, and the hub notifies it by its ids; `check-answers`, the report and
  `release.json` name every answer resting on external material with its
  classes. The report's per-question weighing comes with work package 5.
- Not built: a model steward (off by rule), amending the case policy while
  the run goes on (a new run, or the operator's grant), live DNS lookups as an
  adapter.
