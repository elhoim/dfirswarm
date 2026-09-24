# Packs: skills, tools and method, in one importable directory

A pack is a directory the operator installs once and then names at kickoff. It
carries four things the harness already knows how to consume, plus the record of
where they came from:

| What | How the harness consumes it |
| --- | --- |
| Skills | method notes an agent fetches by name with the `skill` tool |
| Tools | `tools/<name>/{manifest.json,run.py}`, the shape `make_tool` already writes |
| Host requirements | binaries a case needs, checked at kickoff like `--toolbox` |
| Goal templates | a `--goal-file` with its own definition of done and checks |

Packs are optional. A swarm runs with no pack, with one, or with several.
Nothing in a pack can weaken a guard: a pack ships data and scripts, and both
run inside the same sandbox, under the same write allowlist, with the evidence
held read-only exactly as before.

---

## 1. Why skills are a tree of files

The obvious design is to append a pack's method to every agent's system prompt.
It is also the wrong one. A Windows pack's method runs to tens of thousands of
tokens. Pasting it into every agent spends the context window on material most
of them never need, and spends it again on every turn for the whole run.

So a pack's skills are small files, and an agent fetches one when it needs it:

- The index is small and goes in front of the agent once: skill ids, each with a
  title and one line saying when to reach for it.
- A body arrives only when an agent calls `skill("<id>")`.
- A body may name other skills. The agent fetches those the same way, so one
  skill builds on another without either repeating it.
- Every fetch is an event on the trace. Which method a swarm consulted, and
  when, becomes part of the record the report can cite.

A skill is written for an agent in the middle of a case: what to look at, in
what order, what the answer looks like, what would disprove it, which tool to
use. It does not explain what a registry is.

### Skill file format

Front matter, then a short imperative body.

    ---
    id: windows/execution/prefetch
    title: Prefetch, and what it proves
    when: An executable's run count, its first and last run, or the files it touched.
    needs: [windows/execution/overview]
    tools: [prefetch_mam, mam_scan]
    requires_host: []
    ---

`needs` names skills this one assumes. `tools` names tools that should already
be loaded. `requires_host` names binaries the body's commands call. Install
validates all three against the pack and warns about anything it does not carry:
a warning rather than a refusal, because a Windows skill is expected to call the
base pack's `icat_extract` and the set is resolved across the dependency chain
at kickoff. A reference that no pack in the resolved set carries is a bug, and
`tests/pack-tools.test.sh` fails the build on one.

### Tool help stays out of the context window

A skill does not paste a tool's full option list. It gives the one or two
invocations that matter in a case, and names the command that prints the rest.
The agent runs that command when it needs the detail, and pays for it once, in
its own turn, instead of in every agent's prompt on every turn.

---

## 2. Directory layout

Every pack has the same shape. Later packs follow it without deviation.

    <pack-id>/
      pack.json                 identity, dependencies, secrets, checksums
      README.md                 what this pack is, for a human
      LICENCE                   the pack's own licence
      NOTICE                    third-party attribution, one block per vendored project
      skills/
        INDEX.md                generated from the front matter of every skill
        <namespace>/<name>.md
      tools/
        <name>/manifest.json
        <name>/run.py
      vendor/                   third-party code that may be redistributed
        <project>/LICENCE
      requires/
        host.json               binaries the operator installs, with why and how
        python.txt              pip requirements, pinned
      goals/
        <template>.md
      tests/
        pack.test.sh            the pack's own suite
        cases.json              published cases this pack is verified against

Nothing outside these paths is installed. A zip whose top level is not a single
directory named for the pack id is refused.

---

## 3. pack.json

    {
      "id": "windows-forensics",
      "name": "Windows Forensics Pack",
      "version": "1.0.0",
      "description": "Artefact-by-artefact method and tooling for a Windows examination.",
      "licence": "AGPL-3.0-or-later",
      "depends": ["computer-forensics-base>=1.0.0"],
      "tools": ["evtx_query", "regkv", "prefetch_mam"],
      "vendor": [
        { "name": "python-evtx", "version": "0.8.0", "licence": "Apache-2.0",
          "url": "https://github.com/williballenthin/python-evtx",
          "path": "vendor/python-evtx" }
      ],
      "requires": { "host": "requires/host.json", "python": "requires/python.txt" },
      "secrets": [
        { "name": "VT_API_KEY", "title": "VirusTotal API key", "required": false,
          "why": "Reputation lookups on hashes the case finds.",
          "url": "https://www.virustotal.com/gui/my-apikey" }
      ],
      "checksums": { "sha256": { "skills/INDEX.md": "..." } }
    }

`depends` is resolved at install. A pack whose dependency is missing is refused,
named, with the version it wanted.

---

## 4. Secrets

A pack may declare secrets. The rule the harness holds for a provider key is
that no credential is handed to an agent's pane. A pack's secret keeps that
rule in a microVM, where only a placeholder enters. On the host it keeps it
only by withholding the secret, and hands it to the pack's tools only when
the operator accepts that the agents can reach it too.

- At install, `pack install` asks for each declared secret and writes it to
  `~/.dfirswarm/secrets/<id>.env`, mode 0600, owned by the operator — beside
  the packs, never inside one: a pack's directory is mounted read-only into
  every agent's VM, and `verify` checks it against the pack's own checksums. A
  secret that is not required may be skipped; the tools that need it say so when
  they run.
- At kickoff the secret is not exported into the pane environment and is not
  written into the sandbox. (A VM's environment gets a placeholder; below.)
- When an agent calls a pack tool on the host, the secret is passed in the
  environment of that tool's own child process. The tool reads it there. It
  is never in the pane's own environment, so `env` in an agent's shell shows
  nothing. (In a VM the environment holds a placeholder instead; below.)
- The design also put the file itself out of the agent's reach, with the
  mechanism that keeps a previous run's findings unreadable (a tmpfs over the
  directory inside the namespace, or a Landlock rule denying the read). That
  denial is not built. The extension runs inside the pane, so on the host an
  agent can read the secrets file with its own shell, and that is why a pack
  tool gets a secret there only when the operator accepts it (below).
- The trace records the call and its parameters. It does not record the secret.

A pack that requires a secret is refused on the host unless the operator
passes `--allow-pack-secrets`, and the record's `pack_secrets` says what each pack's secrets were given.

How this is implemented:

- A secret entry may name the `hosts` its value is for:
  `{"name": "VT_API_KEY", "title": "…", "why": "…", "hosts": ["www.virustotal.com"]}`.
  Each is a host name, not a suffix: a VM whose secret is bound to `*.name`
  is refused, since msb would swap the value in for any host under it.
- On the host the extension cannot be kept from what its own pane can read, so
  a pack tool gets its pack's secrets only when the operator passes
  `--allow-pack-secrets`, and a pack that requires one is refused without it.
  The run record's `pack_secrets` says, per pack, `exposed`, `withheld` or
  `not-set`.
- Under `--isolation microvm` the value never enters the VM. Each secret is
  given to the VM as a placeholder bound to the pack's `hosts`; the host swaps
  the real value in on the way to those hosts only, and a placeholder sent
  anywhere else is refused. The record says `injected`. A secret with no
  `hosts` cannot be bound, and is withheld.
- On the host, only the pack's own tools get the secret, in their child
  process's environment; a tool forged during the run gets none. In a VM the
  placeholder is in the environment of the whole VM, under the secret's own
  name, so any process in that VM, an agent's shell included, can use the
  secret at the pack's `hosts` (look up a hash, or upload a file there). The
  value itself never enters the VM, and the placeholder is refused anywhere
  but those hosts.
- The trace row of the call, and the output handed back to the model, carry
  `[secret NAME]` where the value would have been.

---

## 5. Third-party tools and licences

A pack carries third-party code only where the licence allows redistribution,
and says so in `NOTICE`, with the licence text beside the code in
`vendor/<project>/LICENCE`.

Anything that may not be redistributed is declared in `requires/host.json`
instead, with the reason and the install line per platform. What the kickoff
does with it depends on the mode:

- **Host runs** do not read it. The agents install what they need
  (`--allow-install`) or work without it, and the pack's tools say what is
  missing when they run.
- **Under `--isolation microvm`** each VM's probe looks for every program a
  pack marks as required (not `optional`). One missing from the image stops
  the kickoff, unless the agents may install (`--allow-install`), in which
  case it is a warning they are told about. An image built from another
  version of a pack is a warning, recorded in `vm/<id>.json`, not a refusal.
  `--toolbox` in a VM run also lists every program the packs name, required
  or optional, in `toolbox.json`.

    {
      "binaries": [
        { "name": "fls", "package": "sleuthkit",
          "why": "List files and streams in an image.",
          "install": { "brew": "brew install sleuthkit", "apt": "apt install sleuthkit" },
          "licence": "IPL-1.0 and GPL-2.0", "redistributable": false }
      ]
    }

---

## 6. Installing, and running with a pack

    scripts/pack.sh install windows-forensics-1.0.0.zip
    scripts/pack.sh list
    scripts/pack.sh show windows-forensics
    scripts/pack.sh verify windows-forensics
    scripts/pack.sh remove windows-forensics

Install refuses a pack whose checksums do not match, whose dependency is
missing, whose skill front matter names a tool or a skill it does not carry, or
whose zip holds anything above the pack directory.

At kickoff:

    swarm.sh start --pack windows-forensics ...
    swarm.sh start --pack computer-forensics-base,windows-forensics ...
    swarm.sh start ...

The last one is a run with no pack at all, exactly as before.

`--pack` seeds the pack's tools into the run the way `--tools-from` does, puts
the skill index in front of every agent, and lets `skill` fetch any body.
Under `--isolation microvm` it also picks the image and adds the pack's host
requirements to the VM's probe and to the toolbox check (§5). The run record names every pack,
its version and its checksum, so a reader knows which method produced the
result.

---

## 7. The packs in this repository

Twelve, all under the same AGPL-3.0-or-later as the harness, in `packs/`:
99 skills, 64 tools and 14 goal templates. Every one of them is sealed,
checksummed, and installs and verifies in the test suite.

| Pack | Skills | Tools | Goals | What it is for |
| --- | --- | --- | --- | --- |
| `computer-forensics-base` | 11 | 13 | — | the method true of any platform; everything else depends on it |
| `windows-forensics` | 24 | 20 | 3 | ten artefact families, from `$MFT` to what anti-forensics leaves behind |
| `linux-forensics` | 8 | 5 | 2 | auth logs, the journal, accounts, systemd and cron, ext4, containers |
| `macos-forensics` | 8 | 4 | 1 | property lists, the unified log, FSEvents, KnowledgeC, APFS |
| `mobile-forensics` | 5 | 3 | 1 | iOS and Android extractions, app databases, protobuf |
| `memory-forensics` | 7 | 3 | 1 | containers, what works with no framework, injection, credentials |
| `network-forensics` | 6 | 3 | 1 | captures, sessions, DNS and TLS metadata, beacons, exfiltration |
| `reverse-engineering` | 7 | 3 | 1 | static triage of a binary or a document, under quarantine |
| `encrypted-containers` | 5 | 3 | 1 | which scheme, which protectors, and where the key already is |
| `cloud-forensics` | 6 | 3 | 1 | Microsoft 365, Entra, AWS, Workspace, and the tokens behind them |
| `ransomware-response` | 7 | 2 | 1 | the order the case has to be worked in |
| `triage-collection` | 5 | 2 | 1 | a collector's output, which is how most cases arrive |

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/windows-forensics
    scripts/swarm.sh start --pack computer-forensics-base,windows-forensics ...

### Two rules the set holds to

**No pack carries a tool name another pack carries.** A run that loaded both
would collide, so the generic tools — `file_type`, `sqlite_query`,
`timestamp_decode`, `image_layout` — live in the base pack and nowhere else.
`tests/pack-tools.test.sh` fails the build on a duplicate.

**Every reference resolves inside its own pack's dependency closure**, not
merely somewhere in the repository. A Windows skill may name a base pack tool
because Windows depends on base; it may not name a network pack tool. The same
test checks that for all twelve.

### Third-party tools

Nothing third-party is redistributed in any pack. Host binaries are declared in
`requires/host.json` with their licence and their install command, and are
invoked as executables — which is why the Sleuth Kit (CPL-1.0), Suricata
(GPL-2.0-only) and Volatility can all be used by an AGPL-3.0 project without a
licence question arising. Python packages are declared in `requires/python.txt`
and fetched from PyPI.

Two consequences worth stating. The memory pack wraps **MemProcFS** and not
Volatility, because MemProcFS is AGPL-3.0 and a purpose-written driver for
Volatility would be a derived work of Volatility rather than of this
repository. And almost every host binary is marked **optional**: the packs'
own tools use the standard library, so a host with none of them still works,
and each host tool widens what can be established rather than being required.
