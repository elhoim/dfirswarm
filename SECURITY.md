# Security

DFIR Swarm runs model-written shell commands on your machine, on purpose.
Read this before you run it, and before you report something.

## Threat model, in one paragraph

A swarm is N Pi sessions with `bash`, `read`, `edit` and `write`, all with the
same isolated directory as their working directory. By default each agent is
root in its own microVM, and the boundary is the host side of every mount,
the VM's network policy and the hub's socket, not the agent's shell. What
that boundary protects: the host's files (a VM holds only what is mounted,
and the run is a read-only floor in it but for the seat's own directories),
the credentials (provider keys, subscription tokens and pack secrets never
enter a guest; msb swaps a placeholder for the value on the way to the
credential's own hosts), the evidence (read-only through a mount the host
enforces), and the harness's decisions (the finish line, the stop clock,
custody and the report are taken on the host). What it does not protect is
listed under Out of scope. In that mode a `bash` inside the VM is in scope
wherever it reaches past those
([ADR 0009](docs/adr/0009-agents-live-in-microvms.md), `docs/safety.md`).

With `--isolation host` the run is unisolated: every agent is a process on
this machine, and the harness enforces what it can. `edit`/`write` outside
the sandbox or without a lease are blocked; harness-owned files (`SWARM.md`,
`team.json`, `budget.json`, `names.json`, `done/`, `locks/`, `threads/`,
`traces/`, `history/`, `inbox/`, `tools/`, `inputs/`, `ledger/`, `catalog/`)
are refused as write targets; egress goes through a per-swarm allowlisting
proxy; every tool call is logged. What it cannot enforce is `bash`: a shell
command can read or write anything the user running the swarm can, and no
hook can stop it mid-command. The harness *detects* shell writes to leased
paths, snapshots them and announces them on the board, after the fact.

**What host mode hides from the agents, and what it cannot.** Reads are open
in host mode except what the kernel guard denies, so the kickoff denies the
things an agent must never hold or simply find: where this install's
signing keys are kept (each home's `machine/` and `examiners/`, made 0700
first; `SWARM_SIGNERS_HOME`; each enrolled examiner's key file as its record
names it; the custody key), the ssh-agent (`SSH_AUTH_SOCK` is dropped from
the panes and its socket denied, launchd's on macOS by its directory),
every earlier run's sandbox in the registry, and the examiners' reviews.
Where the guard cannot deny a signing key's path or the agent's socket
(Landlock alone cannot refuse a socket) the run is refused; with no guard at
all (`--no-write-guard`, or a host without one) it is refused while a
signing key exists, unless `--accept-signer-exposure`, and then the run's
record says `signer_keys_hidden: false` with what was exposed, and the
operator is told to rotate (`swarm.sh machine rotate`; an examiner's new key
is a new enrolment). It cannot hide: whatever else the account can read
(other ssh keys, a browser's stores, the credentials a pane is handed), an
agent socket `SSH_AUTH_SOCK` does not name at kickoff (a gpg-agent's, one
another shell started), a key or a run made after the kickoff where a mount
namespace is the guard (it masks what exists then; seatbelt and Landlock
refuse by path), and earlier runs under Landlock alone (a carve beneath
`runs/` would freeze it for the panes, the registry included), which the
record says. Hidden from the agents is not protected from the account: the
operator holds every one of these keys.

In either mode, **run swarms on a machine or account you are willing to
lose, with credentials you are willing to rotate.**

## In scope

Please report these privately (see below):

- A way for an agent to write outside its sandbox, or to a harness-owned file,
  through `edit` or `write` (the guard is supposed to block both).
- A way for an agent to rewrite `SWARM.md`, the checks, or `budget.json` so
  that the run certifies itself or raises its own cap.
- A way to create or delete `done/SWARM_DONE` that the harness does not record.
- Egress that bypasses the netguard proxy from inside a pane when netguard is
  on (other than by `--no-netguard`, which is the documented opt-out).
- A host-mode pane that reads a signing key of the install (the machine key,
  an enrolled examiner's key file, the custody key), reaches the ssh-agent,
  or reads an earlier run's sandbox or the reviews, in a run whose record
  says they were hidden (`signer_keys_hidden: true`, `earlier_runs_hidden`);
  or a run that starts unguarded while a signing key exists without
  `--accept-signer-exposure`.
- A path-traversal or symlink escape in the web app (`/api/swarms/:id/work/…`,
  `/api/goals/:name`, history restore, the contract route).
- A way to call a token-gated route (start, stop, reap, restore, save goal,
  the grant that opens an HTML artifact with its scripts) without the token,
  or a way for an agent's HTML artifact to run a script in the console
  without that grant.
- A way for a pane to make custody, the report or `stop` read or write
  through a link it planted, or to make custody's verdict say something
  other than what it checked.
- Secrets leaking into `traces/events.jsonl`, `budget.json`, the registry, or
  the web app's responses.
- Under `--isolation microvm`: anything an agent in its VM can do to the host
  or a peer — write outside its own directories (`work/<id>/`,
  `work/extracted/<id>/`, `work/quarantine/<id>/`, `tool-output/<id>/`, its
  session), read a host file or a credential, reach a host outside its
  allowlist, act through the hub as another seat or as the harness (the stop
  clock, the sentinel, a forge with forging off), make the hub follow a link,
  or hang or crash the hub or a custody check.
- Under `--isolation microvm`: a process outside a seat's VM that the hub
  serves as that seat without the seat's token, or a seat token that shows
  up in the trace, the registry, a VM record or a package.
- With `--model-gateway`: a VM that reaches a fronted provider without the
  gateway, a provider key that reaches a VM, a file or the trace, a seat
  whose token calls another seat's providers, a stopped seat's call that is
  forwarded, or a gateway route that reaches a host other than the
  provider's.
- The review, the package and purge: a way for an agent to write the
  examiner's review file (`runs/reviews/`), a package change that `verify`
  does not report, a part taken out of a package (the verdict, an anchor, a
  chain, the sealed index, the review) that it does not report, a work file
  changed after the stop that `custody-verify` or `verify` passes, a
  sign-off the report calls current when the ledger or the report moved
  after it, or a `purge` that deletes a held run or anything outside the run
  it names.
- Releases, examiners and redaction: a release written over, or one whose
  changed bytes, record, signature, place in the chain or line in the
  anchor `releases --verify` or `verify` passes; a machine's draft shown or
  verified as an examiner's adoption; the registry's `examiner` string shown
  as the examiner; an answer with defective support adopted or qualified,
  or a release signed while one has no withdrawal or inconclusive
  disposition; an evidence link moved (even to identical bytes) that
  custody passes; a rerun that writes into the run's store, runs in an image
  whose digest is not the recorded one, or reports a normalised equivalence
  as a reproduction; a redaction that leaves a sensitive entry's words in a
  package without the scan naming them, or a record of it that prints the
  words.
- With `--allow-tool-forging` on: a way to put a script under `tools/`
  without `make_tool`, to run a tool whose bytes differ from its manifest,
  to replace a live author's tool as a peer, or to register a forged tool
  when forging is off.

## Out of scope

- Anything an agent does through `bash` inside the sandbox it was given. That
  is the documented limit of the harness, not a bug. The same goes for what a
  forged tool's script does when it runs: it is a `bash` with a schema on it.
- The web app being reachable from your LAN when you ask for it. It binds to
  `127.0.0.1` by default; `--host 0.0.0.0` opens it to a second machine, and
  then watching is open and spending needs the token. Do not expose it to the
  internet. Read "open" literally: without the token, a request on the LAN can
  fetch the goal document, the board, the whole trace, every revision of every
  `work/` file, any artifact, and the `swarm.sh` output of each start, stop and
  reap on `/api/jobs`. If the goal or the evidence names something you would
  not put on a shared screen, keep the default.
- Under `--isolation microvm`, what the ADR ("Limits that stay") and
  `docs/safety.md` list as the mode's stated limits, among them:
  - a spend report is the seat's own; the host enforces the wall clock by
    itself, and the caps only on what the seats report, except under
    `--model-gateway` for the providers it fronts, where the host measures
    the spend and refuses a call three minutes after a cap is crossed (so a
    run can overshoot a cap by what is spent in that grace);
  - every process in a VM speaks to the hub as that seat: a forged tool, a
    parser over hostile content, a binary extracted from the evidence and
    run by the guest's root; the seat token is in the guest's environment,
    and it keeps out only processes outside the VM;
  - the extension's checks inside a VM are advisory against the guest's
    root; only the hub, the mounts and msb enforce;
  - an allowed host is a way out: anything an agent can send to its model's
    host, a symbol server, or any host under an allowed suffix leaves, and a
    bound placeholder is usable at its host for whatever that credential may
    do there (an API key is not limited to inference; a pack's secret is
    usable by any process in the VM);
  - a local model's port, reached through the host gateway, is that server's
    whole API to every VM (Ollama's `/api/pull` and `/api/delete` included);
  - a real key that a provider echoes back in a response is not masked in
    the trace, and reaches the VM with or without the model gateway;
  - the model gateway, when on, holds the fronted providers' keys in its
    memory on the host;
  - `vm/<id>.json` is readable from every VM (it names secrets and hosts, no
    value);
  - msb's strict mode is off: a host-name rule admits what the name resolves
    to, whatever server name the connection then sends;
  - msb holds the credentials uncaged, and while a VM lives its secrets'
    values are in msb's own database on the host's disk
    (`~/.microsandbox/db`, made its user's alone at kickoff; a finish that
    removed VMs clears their leftover bytes when the host has `sqlite3`,
    and `stop` warns about any it could not clear);
  - msb swaps a placeholder for its value in request headers only: a
    placeholder in a URL query or a body goes out as the placeholder;
  - the hub runs as the examiner, and a guest's terminal output reaches the
    host's;
  - the examiner's browser is outside the VM allowlist: the console shows an
    agent's HTML artifact without scripts, but one the operator opens with
    **Open with scripts**, after its warning, or a file opened outside the
    console can reach the network;
  - the operator's record (`runs/operator-audit.jsonl`) and the examiner's
    review (`runs/reviews/`) are chained by hash, not signed: whoever can
    write them can rewrite them whole, and a trace line from a shell that is
    not the kickoff's is marked unverified;
  - a signed package proves which key signed its manifest (and, since
    2026-09-27, `SIGNER.txt` with it), not whose key it is: that is the
    recipient's allowed-signers file;
  - an RFC 3161 token is held to the authority's CA only when the operator
    names one (`--custody-timestamp-ca`, `SWARM_CUSTODY_TSA_CA`,
    `custody-verify --tsa-ca`); without it the token is checked for the
    verdict's digest alone, which anyone can put in a token, and custody
    says "imprint only";
  - the anchors, the verdict, `artifacts.json` and the review are files of
    the operator's own account: `custody-verify` and `verify` hold the run
    and a package to them, which catches a change made after the stop to
    one part (a report edited, an entry appended), not a rewrite of all of
    them together by that account;
  - `purge` deletes files the ordinary way, without overwriting the blocks
    the filesystem freed, and knows nothing of copies made elsewhere;
  - what each part of the record proves, and does not, is below.

## What the record proves, and what it does not

- **The custody verdict and its anchor.** That the evidence, the chains
  and `work/` were as the host read them after the run, and that nothing
  sealed changed since, as far as `custody-verify` can see: the anchor is a
  file of the operator's own account, so a coherent rewrite of every part by
  that account is not caught. Custody checks the links the evidence is read
  through (`inputs/`, `inputs/<set>`) against the source recorded; it does
  not know what the source was before the kickoff, unless acquisition hashes
  were given.
- **A machine's draft release (v0).** That the harness held these bytes at
  stop, sealed by the install's machine key, which lives on the same host,
  unprotected by a passphrase so that a stop can use it: it is the
  machine's statement, not anyone's opinion, and anyone with the account can
  sign with it. It adopts nothing.
- **An examiner's release (v1 and after).** That the holder of an enrolled
  examiner's key signed these exact bytes (the rendering, the PDF's sha256,
  each disposition, every chain's head). Who holds the key is what the
  organisation's signer register says, checked in person at enrolment;
  without a register the tie is the fingerprint alone, and every check says
  "not checked". A key with no passphrase can be used by anyone who can read
  the account's files. An adoption is the examiner's opinion; it does not
  make a conclusion true, and an unsupported one cannot be adopted.
- **A technical reviewer's record.** That the examiner recorded who checked
  the methods and what; it carries the examiner's signature through the
  release, not the reviewer's own.
- **An RFC 3161 token.** That the signed release existed by the authority's
  time, when the token verifies against the authority's CA; without a CA,
  only that a token names its digest, which anyone can make. A token
  obtained later (`swarm.sh timestamp`) dates the proof from then, and says
  so.
- **An anchor mirror, an OpenTimestamps proof, a transparency log.** A copy
  of a release's digest line held where this account cannot rewrite it,
  when the target is such a place: an object-locked bucket or a records
  custodian's separately administered archive is; a folder of the same
  account is not; a signed git remote is a witness of when a line was
  pushed, not a write-once store. An OpenTimestamps proof is pending until a
  Bitcoin block commits it. A receipt is what the log's client printed; what
  the log itself guarantees is the log's.
- **A rerun.** That the job's spec, in the image of the recorded digest,
  made the same bytes again, or which files it did not. It does not measure
  which bytes the job read, re-fetch what it fetched, or reproduce the
  reasoning that asked for it; an equivalence under a normalisation is not
  a reproduction.
- **A redaction's record and its leak scan.** What each redaction replaced,
  by the sha256 of the original, and that no sensitive entry's words, as
  the scan normalises them, are left in the package's text or bytes. It
  does not find what is said in other words, a value no entry was marked
  sensitive for, or text inside a compressed stream (a release's PDF is
  withheld for that reason).
- **The certification template.** Nothing, until a qualified person who
  can attest to it completes and signs it. It is not legal advice.
- **The agents' attestations and disputes.** Agents re-deriving agents'
  work: never an independent review.
- The behaviour, cost or output of the model you point Pi at.
- Vulnerabilities in Herdr, Pi or a model provider. Report those upstream.

## Reporting

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or email the maintainer, Halil
Öztürkci, at **halil@halilozturkci.com**. Include the swarm id, the
`traces/events.jsonl` lines around the problem, and the Pi and Herdr versions.
You will get an acknowledgement within a week. There is no bounty.

## Hardening checklist for operators

- Run on a disposable machine or VM; keep provider credentials in Pi's own
  store (`pi auth login`), never in the sandbox or the goal.
- Keep netguard on. Add hosts with `NETGUARD_ALLOW`, do not switch it off.
- Keep the cap tight (`--cap-usd 1` for a first run) and the wall clock short.
- Treat the console token like a password; it is printed once at startup.
- Read the goal you are about to run. The harness refuses one without a
  definition of done, but it does not judge what the checks do.
- Under `--isolation microvm`: use API keys and keep `--allow-oauth-in-vm`
  off; allow suffixes (`*.name`) only where the case needs one; keep the
  runs, with their `<sandbox>.vm-snapshots/`, out of synced folders and on an
  encrypted volume (the kickoff's `Disk:` line says which it is); and
  consider `--model-gateway`, which meters the fronted providers' spend on
  the host and refuses a stopped seat's calls there.
- Sign what you hand over (`swarm.sh package <id> --sign`), and give the
  recipient the allowed-signers line the command prints.
- Enrol each examiner with a passphrase or a hardware key
  (`swarm.sh examiner enroll`), put the line it prints in the organisation's
  signer register after checking the fingerprint in person, and hand the
  register to recipients apart from the package.
- Name a timestamp authority and its CA at enrolment (`--tsa-url`,
  `--tsa-ca`), or run `swarm.sh timestamp` once the lab is online; and set
  `--anchor-mirror` to a place this account cannot rewrite.
