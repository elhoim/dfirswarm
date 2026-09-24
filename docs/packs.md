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

## 4. Secrets never reach a pane

A pack may declare secrets. The rule the harness already holds is that no
credential is handed to an agent's pane, and a pack gets no exception.

- At install, `pack install` asks for each declared secret and writes it to
  `~/.dfirswarm/packs/<id>/secrets.env`, mode 0600, owned by the operator. A
  secret that is not required may be skipped; the tools that need it say so when
  they run.
- At kickoff the secret is not exported into the pane environment and is not
  written into the sandbox.
- When an agent calls a pack tool, the secret is passed in the environment of
  that tool's own child process. The tool reads it there. It is never in the
  pane's own environment, so `env` in an agent's shell shows nothing.
- The file itself is put out of the agent's reach by the same mechanism that
  keeps a previous run's findings unreadable: a tmpfs over the directory inside
  the namespace, or a Landlock rule denying the read. This is the honest part:
  the extension runs inside the pane, so without that denial an agent could read
  `secrets.env` with its own shell. Where the host cannot enforce the denial the
  kickoff says so and the run record carries it, exactly as it does for every
  other guard.
- The trace records the call and its parameters. It does not record the secret.

A pack that declares a required secret on a host that cannot deny the read is
refused at kickoff unless the operator says to go ahead, and the record names
the gap.

**Status.** Only the first two points exist today. `pack install` writes
`secrets.env` (mode 0600), and nothing exports it into a pane or copies it into
the sandbox. The rest is still to be built:

- No pack tool is handed its secret yet. Nothing in the harness reads
  `secrets.env` after install.
- The kickoff does not deny the read. `~/.dfirswarm/packs/` stays readable to
  the panes because their skills and tools live there, so an agent's own shell
  can `cat` the file under every write-guard mode.
- The kickoff does not refuse a pack whose required secret it cannot protect,
  and the run record does not name the gap.

Until then, treat a pack secret as readable by the agents of any run that loads
the pack, and install one only when that is acceptable.

---

## 5. Third-party tools and licences

A pack carries third-party code only where the licence allows redistribution,
and says so in `NOTICE`, with the licence text beside the code in
`vendor/<project>/LICENCE`.

Anything that may not be redistributed is declared in `requires/host.json`
instead, with the reason and the install line per platform. The kickoff checks
for it and records what the host had. A missing binary is named in the record
and the run goes ahead rather than refusing to start.

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

`--pack` seeds the pack's tools into the run the way `--tools-from` does, adds
its host requirements to the toolbox check, puts the skill index in front of
every agent, and lets `skill` fetch any body. The run record names every pack,
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
