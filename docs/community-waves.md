# The Community waves

Three waves of work, ordered so that each one ends with something an examiner
can hand to somebody else. Every line names the file it touches and what it
costs. Nothing here is speculative: the effort figures come from reading the
code that already exists and the delivered cases under
[docs/use-cases](use-cases/README.md).

> **Status: all three waves have shipped.** What follows is the plan as it was
> written, kept because the reasoning is the part worth keeping — why each item
> was chosen, and what was measured to choose it. Where the implementation
> departed from the plan, a **Shipped** note says so and why. The CHANGELOG
> records what landed.

**Where the plan was wrong, and what happened instead.**

- **Page numbers in the PDF.** The plan proposed `@page` margin boxes for a
  running header and a page counter. Chrome implements neither, and the usual
  workaround — a `position: fixed` element — is anchored to the first page
  there and prints on top of the content of every page after it. Both were
  tried and both failed visibly. What ships lets the browser draw the page
  numbers and the document asks to be cited by section; the limitation is
  stated in the document.
- **Embedded fonts.** The plan said the report would embed its fonts as
  `data:` URIs. That is megabytes of base64 in every report, for type that
  reads correctly in Georgia and Menlo anyway. The report uses system stacks
  and says so.
- **The download routes.** `/api/swarms/:id/dossier/<name>`, not
  `/download/<name>`: "download" in a URL path is a common content-blocker
  pattern, and a blocked request leaves an operator looking at nothing with no
  error. The report preview goes further and uses `srcdoc`, so no request can
  be refused at all.
- **Pruning the library.** The plan proposed deleting the four tools the
  corpus never called. Measured, three of those four were written late in the
  corpus and one is the only AES Crypt implementation in the repo, so "never
  called" says nothing about whether they work. Nothing was deleted. What was
  wrong — and is fixed — is that three tools hard-coded the image they were
  written for and could not be used on any other case.
- **The tab grouping.** Planned as a cosmetic tidy; it turned out to be what
  makes the evidence hashes findable, because `InputsPanel` was buried inside
  the `files` tab where nobody looks for them.
- **Who wrote an artifact.** The plan put `last_written_by` on the index and
  the first cut read it from the trace, so a `claim_file` looked like a
  write. The snapshot in `history/` is what names the writer.
- **The Report tab's hashes.** The download rows were a hardcoded list. The
  tab now loads `GET /dossier` once, and the generated files are offered as
  the bytes of that response, so the hash beside the button is the hash of
  the file it writes.
- **icat writers and `inputs/`.** A string prefix is not a directory check.
  The four extractors now resolve the destination the way
  `aescrypt_v2_decrypt` already did.

## The frame

The licence is [AGPL-3.0-or-later](../LICENSE) with a
[commercial licence](../COMMERCIAL-LICENSE.md) beside it. The paid thing is a
*licence*, not a feature set, and the commercial document says plainly that
running this software and working client cases with it costs nothing. So the
question "what goes in Community" is really "what ships first", and this plan
answers that one.

### The spine: one run, one dossier

Everything below converges on a single shape. A finished run produces a
**dossier**: one directory that somebody who was not in the room can read.

```
package/
  report.html          the report, one file, no external references
  report.pdf           the same report, paginated              (Wave 2)
  summary.md           the run summary scripts/summary.ts renders
  artifacts.json       every file under work/, with sha256     (Wave 1)
  ledger.jsonl         the timeline, indicators and findings
  ledger.md            the rendered ledger
  trace/events.jsonl   every tool call the swarm made
  inputs.json          the evidence, with sha256 per file
  toolbox.json         what was installed on the host
  team.json            who ran, on which model
  budget.json          what it cost
  layout.json          how the panes were laid out
  netguard.allow       what the run was allowed to reach
  tools/               the tools the run used, with manifests
  work/                everything the run wrote
  board/               one file per thread
  SWARM.md             the contract the agents were under
  MANIFEST.txt         one sha256 per file above
```

`scripts/swarm.sh package` already writes most of that. Wave 1 adds
`artifacts.json`, Wave 2 adds `report.html` and `report.pdf`. The console
reads the same directory, so there is one shape and not two.

### What a reader is entitled to ask

Four questions decide whether a forensic tool's output is usable, and the
plan is arranged around them:

1. **What did you look at?** — `inputs.json`, with a hash per file, shown as
   a hash and not as a tooltip.
2. **What did you produce?** — `artifacts.json`, every file under `work/`
   hashed, including the 3.3 GB of extracted material that never leaves the
   sandbox.
3. **How did you get there?** — the ledger with exhibit numbers, and the
   trace, both downloadable as files.
4. **Can I hand this to somebody else?** — one report, one PDF, one manifest.

---

## Wave 1 — everything already computed, made visible

About a week. Nothing in this wave requires a new idea; every item is a value
the harness already has and does not show, or a mechanism that is already
written and not used. That is why it is first.

### W1.1 `artifacts.json`: hash everything under `work/`

**Where.** New `scripts/artifacts.ts`, exporting
`hashArtifacts(sandbox): Promise<ArtifactIndex>`, called from
`scripts/swarm.sh cmd_package`, from `scripts/summary.ts`, and from a new
console route.

**What it holds**, per file: `path`, `bytes`, `mtime`, `sha256`, `kind`
(reusing `WorkFile["kind"]`), `revisions` (from `history/`, which already
keeps numbered copies), and `first_seen` / `last_written_by` taken from the
trace's write attribution.

**The part that matters.** `work/extracted/` and `work/quarantine/` hold
3.3 GB across 694 files in the measured corpus. Wave 0 deliberately keeps
them out of the package — they came out of the evidence and may be live — but
207 ledger entries cite those paths and 46 cite their hashes. So they are
**hashed and listed** in `artifacts.json` with `packaged: false`, and their
bytes stay in the sandbox. A reader can verify a quoted hash without the
package carrying malware.

**Effort** half a day. **Test** `tests/artifacts.test.ts`: a nested tree, a
symlink that must not be followed, an excluded directory that is still
hashed, and a file that changes between two calls.

### W1.2 The evidence hash, out of the tooltip

`ui/src/screens/detail/inputs-panel.tsx:73` renders the sha256 as
`title={f.sha256}` and nothing else. The hash is computed, stored, shipped to
the client, and drawn as a hover. This is the single thing that says
"forensics" and it is invisible.

Client-only change, plus two new design-system components (see
[The UI work](#the-ui-work-against-the-design-system)). **Effort** 3 hours.

### W1.3 Download routes

**Where.** `scripts/ui/app.ts`, in the per-swarm `switch (sub)`.

| Route | Body |
| --- | --- |
| `GET /api/swarms/:id/dossier/summary.md` | `summarize()` — already an exported pure function |
| `GET /api/swarms/:id/dossier/ledger.jsonl` | `ledger/entries.jsonl`, streamed |
| `GET /api/swarms/:id/dossier/trace.jsonl` | `traces/events.jsonl`, streamed |
| `GET /api/swarms/:id/dossier/artifacts.json` | W1.1's index |

All four send `content-disposition: attachment` with a filename carrying the
swarm id, and all four **stream** rather than buffer. The security delta is
exactly zero: `/api/swarms/:id/traces` already returns the same content
without a token, and `docs/safety.md` already says so. Streaming also fixes
the silent truncation at `scripts/ui/model.ts:728`, which is the more serious
problem — a trace that drops its first 14,000 events without saying so is a
worse artifact than no trace.

**Effort** 3 hours. **Test** `tests/ui-server.test.ts`: the header, the
filename, and a trace longer than the old cap arriving whole.

### W1.4 `record` requires its provenance

`extensions/agent-swarm.ts:1873-1874` has `source` and `evidence` as
`Type.Optional`. In 1501 ledger entries across fifteen cases, **1501 carry
both**. The corpus has already decided; the schema has not caught up.

Making them required turns an observation about the corpus into a guarantee
the harness enforces, and it cannot break a run that was going to produce a
usable ledger anyway. The contract text and the prompt guidelines change with
it.

**Effort** half a day, most of it in the contract wording and the dry-run
fixtures. **Test** `tests/dry-run.test.ts`: a `record` without `evidence` is
refused with a message that says what to supply.

### W1.5 Fifteen goals into the library

`scripts/ui/goals.ts` and `/api/goals` are complete: list, read, save,
delete, and a refusal for a goal with no finish line. The library at
`prompts/goals/` currently holds three — `analyse-inputs`, `hello` and
`pelican`, two of which are not forensic at all. `docs/use-cases` holds
sixteen case directories, fifteen of them the measured runs.

The work is editorial, not structural: of 23 check lines across the fifteen,
only 4 are case-specific (they name an image by filename). Those four become
a parameter or are dropped. The kickoff's goal picker goes from 3 to 18 with
no code change, and two of the three it shows today stop being the first
thing an evaluator sees.

**Effort** 1–1.5 days.

### W1.6 The fixture becomes a case

`scripts/seed-fixture.ts` seeds five demo runs labelled `pelican-svg`,
`hello-n2`, `canvas-n10`, `hello-world` and `raytracer-stopped`, none of
which carries a single check. Somebody evaluating a forensic tool opens the
console and sees the wrong product in the window.

The mechanism stays — `tests/ui-server.test.ts:16` imports `seedFixtureRuns`
and calls it at `:71`. The *content* is replaced with one shape: a
compromised web server, with inputs that have hashes, a ledger with a
timeline and two indicators, a finish line with checks that pass and one that
does not, and a stopped run that was stopped by a cap.

**Effort** half a day.

### W1.7 The numbers the server computes and throws away

`/api/health` serves `checks_runs` without a type for it;
`scripts/swarm.sh` computes `split_failures` and writes it to `layout.json`
where nothing reads it; the model readiness pass knows which providers are
local and drops that. Each is one field.

**Effort** 4 hours, including the artifact download button that belongs with
them.

### W1.8 The refusals, in writing

Four things this project will not do, written down in
[ADR 0007](adr/0007-no-mcp-and-no-container-by-default.md) so that "missing
feature" becomes "stated position":

- **No MCP.** [ADR 0007](adr/0007-no-mcp-and-no-container-by-default.md), which
  builds on [ADR 0004](adr/0004-forged-tools-are-subprocesses-behind-a-flag.md):
  agent-written code runs as a subprocess in the sandbox and never inside the
  harness process. A remote MCP server also breaks the claim that every
  outbound byte is in the log, because netguard is off by default and an MCP
  transport would sit outside it.
- **No Docker.** A naive `docker run` trades away *both* enforcing guards:
  Docker's default seccomp profile blocks `unshare`, so the Linux mount
  namespace that makes `inputs/` read-only at the kernel cannot be created,
  and the egress guard loses its netns. The two things containerisation
  breaks are the two things this product advertises. If it is ever done, it
  needs a custom seccomp profile and a CI test proving both guards still
  measure as `kernel` inside the container — and it does not ship without
  that test.
- **No voice dictation.** It contradicts the egress claim directly.
- **No share links.** Either they do not work, or they push an operator to
  put a console with 22 open read routes on the internet. Our answer is a
  hashed file you send.

**Effort** 2 hours.

**Wave 1 exits** when a run produces a dossier whose every evidence file and
every artifact has a visible, copyable, verifiable hash, and when the ledger,
the trace and the summary all come out as files.

---

## Wave 2 — the report

About a week and a half. This is the flagship, and it is the thing a
competitor meters by the unit.

### W2.1 `swarm.sh report <id>` → `report.html`

**One file, no dependencies, no network.** The critical finding from reading
the fifteen delivered reports: **none of them contains an image, a link or
raw HTML**. A 115-line dependency-free Markdown renderer reproduced all
fifteen correctly. There is no reason to take a Markdown library, and the
repo's one-runtime-dependency rule stands.

**Where.** New `scripts/report.ts`, exporting
`renderReport(sandbox, options): Promise<string>`, and a `cmd_report` in
`scripts/swarm.sh` beside `cmd_package`. `package` calls it, so the dossier
always contains the report.

**The sections**, in the order a reader needs them:

| § | Section | Source |
| --- | --- | --- |
| 1 | Cover: case id, examiner, tool and version, run id, start and end, the mark | registry, `package.json`, `brand/mark-mono.svg` |
| 2 | Summary of findings | ledger `kind=finding`, newest first |
| 3 | Scope and evidence | `inputs.json`, every file with its sha256 and the guard each pane measured |
| 4 | Method | `team.json`, `budget.json`, `SWARM.md`, the caps and what enforced them |
| 5 | Timeline | ledger `kind=event`, sorted by `ts`, exhibit-numbered |
| 6 | Indicators | ledger `kind=ioc`, grouped by type |
| 7 | Findings, in full | ledger `kind=finding` with source, evidence and confidence |
| 8 | Artifacts produced | `artifacts.json`, with hashes and whether packaged |
| 9 | Chain of custody | input hashes at copy and at finish, the inputs check, the toolbox, the catalog, the netguard allowlist |
| 10 | Limitations | what was capped, what was not read, `unread_ranges` from any scan, tools that refused |
| A | Manifest | `MANIFEST.txt` in full |

**Exhibit numbering.** Six lines in the ledger renderer. Every ledger entry
already has a stable `seq`; an exhibit number is `E-<seq>` and every citation
in sections 5–8 carries one. The data is 100 % ready.

**Branding is free and belongs in Community**: the operator's own logo, firm
name and case metadata are three fields in `SWARM.md`'s front matter, read
straight into section 1. Charging for a logo on a report would be a bad
trade.

**Effort** 3 days. **Test** `tests/report.test.ts`: the fifteen delivered
reports as fixtures, each rendering without loss; a run with an empty ledger
producing a report that says so rather than an empty section; and a check
that the output has no `src=`, no `href=http`, and no `<script>` except the
one the pagination pass adds.

### W2.2 The PDF, done properly

The user's requirement is that the PDF comes out *excellent*, so this needs
to be specific rather than "print to PDF".

**Three routes, and the honest comparison:**

| | Cost | Metadata | Page control | Always works |
| --- | --- | --- | --- | --- |
| (a) `@media print` + the operator's browser | zero | none | CSS only | yes |
| (b) headless Chrome | an optional dependency | full `/Info`, outline, attachments | full | only where a browser exists |
| (c) an in-repo PDF writer | weeks | full | full | yes |

**(c) is out.** Re-implementing text layout, line breaking and font embedding
is not a week's work and would be the second-largest thing in the repo.

**Ship (a) as the default and (b) behind a flag.** `swarm.sh report <id>`
writes `report.html`; `swarm.sh report <id> --pdf` writes `report.pdf` when a
browser is available and says clearly what to do when it is not. Playwright
is already an optional kickoff flag (`--playwright`), so the dependency
question is already answered in this repo's favour: optional, not required.

**The print stylesheet**, which is where "excellent" actually lives, and all
of it is inside `report.html`:

```css
@page {
  size: A4;
  margin: 20mm 18mm 18mm 18mm;
  @top-left    { content: "DFIR Swarm · " attr(data-case); }
  @bottom-right{ content: counter(page) " / " counter(pages); }
}
@page :first { margin-top: 0; }           /* the cover bleeds to the edge */
```

- **Page breaks that respect the content.** `break-inside: avoid` on every
  exhibit block, every table row group and every finding; `break-after:
  avoid` on headings so a section title never ends a page; `orphans: 3;
  widows: 3` on body text.
- **Tables that survive a break.** `thead { display: table-header-group }`
  so the column headers repeat on every page of a long timeline, and
  `tfoot { display: table-footer-group }` for the continued-overleaf line.
- **Hashes that wrap.** A sha256 is 64 characters of monospace and will
  overflow an A4 column. `overflow-wrap: anywhere; font-variant-numeric:
  tabular-nums` on every hash cell, and a `<wbr>`-free rendering so a copied
  hash is still one string.
- **Links printed.** `a[href^="http"]::after { content: " (" attr(href) ")" }`
  — but section 1 says the report has no external links, so this catches the
  case where an operator adds one.
- **Colour that survives monochrome.** `brand/README.md` already states the
  rule: below 24 px and in print, the mark is `mark-mono.svg`. The five
  accents stay, but every coloured chip also carries a shape or a word, so a
  black-and-white fax still reads. `print-color-adjust: exact` on the chips
  that must keep their ground.
- **A table of contents.** In the (b) path a small script numbers it after
  layout, because Chrome does not support `target-counter`. In the (a) path
  the ToC carries section numbers, not page numbers, and says so rather than
  printing wrong ones. **This limitation is stated in the document, not
  hidden.**
- **Fonts embedded**, the three families the console already uses, from
  `.design-sync/fonts/`, as `@font-face` with `data:` URIs so the single file
  stays single.

**PDF metadata in the (b) path**: `/Title` the case id, `/Author` the
examiner, `/Creator` `DFIR Swarm <version>`, `/CreationDate` the run's end,
and the dossier's `MANIFEST.txt` attached as an embedded file so the PDF
carries its own hashes.

**Effort** 3 days. **Test**: the print CSS is exercised by rendering with
`--pdf` in CI where a browser is present and asserting the page count, the
absence of a split exhibit, and the `/Info` fields; where no browser is
present the test asserts the refusal message names the missing piece.

### W2.3 The report lint, corrected

`docs/improvement-plan.md` B10 states a citation rule. **As written it is
wrong**: applied to the fifteen delivered reports it rejects 57 of 103
sections, because a forensic citation is usually not a path — it is an inode,
a record id or a registry key.

The corrected rule: a section cites its evidence if it contains a code span
**or** a ledger `seq` **or** an inode / record id. All fifteen pass. The rule
ships as a `swarm.sh report --lint` that warns and does not fail, because a
report linter that blocks delivery is a linter operators disable.

**Effort** half a day, including fixing B10's row.

### W2.4 The console's Report tab

New tab in `ui/src/screens/swarm-detail.tsx:35`, between `artifacts` and
`goal`. It shows the rendered report in the same sandboxed iframe the
artifacts panel already uses (`sandbox="allow-scripts"`, no same-origin, no
network), a `PrintSheet` preview at paper proportions, and one download row
per dossier file with its size and its hash.

This is also where B8's correction lands: the improvement plan said the
console links the package and it does not. After this it does.

**Effort** 2 days, most of it the new components below.

**Wave 2 exits** when `swarm.sh report <id> --pdf` produces a document an
examiner would attach to a case file without editing it, and the console
offers the whole dossier for download.

---

## Wave 3 — capability, ranked by measured use

About two weeks. Ordered by what the corpus proves was missing, not by what
sounds impressive.

| Tool | Effort | The measured reason |
| --- | --- | --- |
| `esedb_query` | 1 day | A delivered report recorded the gap in its own words: *no `esedbexport`, so `WebCacheV01.dat` and `spartan.edb` could not be parsed as tables*. That file appears in 4 of 15 runs across 144 events and was never read as tables. The same wrapper opens SRUM and Edge's database for nothing extra. One line in `scripts/toolbox.sh` plus ~120 lines of wrapper. |
| `amcache_apps` | 0.5 day | Program execution; currently done by hand through `regkv`. |
| `recyclebin_i` | 0.5 day | `$I` file parsing; three cases did it with `xxd` and arithmetic. |
| `browser_history` | 1–1.5 days | The direct cause of `sqlite_query`'s 93 % error rate in one case: locked WAL databases need a copy-and-checkpoint the generic tool does not do. |
| `yara_scan` | 0.5 day | Without a rule set. A curated rule set is maintenance and belongs to a paid tier. |
| `usn_journal` | 1–1.5 days | `$UsnJrnl:$J` parsing; requested in two cases and forged badly in one. |

**And a pruning.** Across fifteen runs, 4 of the 32 library tools were never
called once, and 5 carry an embedded case-specific path (an image filename,
a sandbox directory) that makes them useless outside the run that wrote them.
Generalise or delete: 32 tools become 14–15 real capabilities, which is a
better number to state honestly than 32.

**Effort** half a day for the audit, then per tool.

---

## The UI work, against the design system

The design system is **DFIR Swarm** on Claude Design —
<https://claude.ai/artifact/PEcXRvqdakJYeiTs31qSg9> — synced from this repo
by the `design-sync` skill. Thirty-six components mount from
`window.DfirSwarm`; the tokens are real CSS custom properties defined in
`ui/src/index.css` under `@theme`; `.design-sync/conventions.md` is the
README header and states the rules.

**Three rules that are not negotiable**, all of them already learned the hard
way and recorded in `.design-sync/NOTES.md`:

1. **Never a Tailwind utility that the app does not already use.** The
   synced stylesheet is the application's *compiled* CSS, so `grid-cols-4`
   silently does nothing. New layout is inline styles reading the tokens.
2. **`npm run ui:build` before every re-sync**, and update `cssEntry`'s
   hashed filename in `.design-sync/config.json`. A stale hash ships the old
   stylesheet and renders unstyled with no error.
3. **`ui/src/design-system.ts` is hand-maintained.** A component added to
   `ui/src/components/` and not added to the barrel is invisible to every
   future sync, with no warning.

**One meaning per accent, everywhere**: `kelp` is running and the primary
action, `saffron` is budget and stall, `brick` is violation and danger,
`slate` is locks and files, `moss` is done. Everything new below obeys it.

### New components

Each is added to `ui/src/components/`, exported from
`ui/src/design-system.ts`, given a `componentSrcMap` entry, and re-synced.

| Component | What it is | Tokens | Wave |
| --- | --- | --- | --- |
| `HashChip` | A truncated sha256 in mono, click to copy, full value in a `Tooltip`. The atom this whole plan rests on. | `slate`, `--font-mono`, `--radius-sm` | 1 |
| `EvidenceRow` | One evidence file or artifact: kind icon, path, size, `HashChip`, a state chip. Replaces three hand-rolled list rows. | `--color-card`, `--color-line` | 1 |
| `DownloadRow` | A dossier file: name, size, `HashChip`, `Button`. Used in the report tab and, later, wherever the package is offered. | `kelp` action | 1 |
| `FileFacts` | What a binary artifact gets instead of a preview: type, size, hash, first bytes. Today it gets `EmptyState`, which is wrong — the file is not empty. | neutral | 1 |
| `ExhibitCard` | A numbered ledger entry: `E-<seq>`, the value, source, evidence, a confidence chip. | tone by kind | 2 |
| `TimelineRail` | The ledger timeline, using the dark band's serif figures for the dates. | `--color-band`, `--font-serif` | 2 |
| `ChainTable` | The custody table, with `thead` set to repeat in print. | `--color-line-2` | 2 |
| `StepList` | Numbered method steps for section 4 of the report. | `--font-serif` numerals | 2 |
| `PrintSheet` | A paper-proportioned frame so the console shows what the PDF will be. Not a component the app needs; a component the *report* needs. | `--color-paper`, a 1px `--color-line` edge | 2 |

`HashChip`, `EvidenceRow` and `DownloadRow` are the whole of Wave 1's UI.
The rest arrive with the report.

### Components that need reworking

These are existing parts that the design system already holds, which this
plan finds are not carrying their weight.

- **`InputsPanel`** (`inputs-panel.tsx`) — the hash comes out of
  `title={f.sha256}` and into `EvidenceRow`. The per-pane guard chips stay as
  they are; they are the best thing in the console.
- **`ArtifactsPanel`** (`artifacts-panel.tsx`) — every file in the left list
  becomes an `EvidenceRow` with its hash; the header row gains a download
  button; the `binary` branch swaps `EmptyState` for `FileFacts`. The
  sandboxed-iframe note stays exactly as written — it is correct and it
  explains a real control.
- **`LedgerPanel`** (`ledger-panel.tsx`) — entries become `ExhibitCard`s and
  gain their `E-<seq>` number, so the console and the report cite the same
  thing.
- **`TracesPanel`** (`traces-panel.tsx`) — a download button, and the
  truncation named in the interface instead of happening silently.
  `scripts/ui/model.ts:728` clamps the query to 5000 and then takes the
  *last* 5000, so on a 19,000-event run the early calls are gone and nothing
  says so. A trace view that quietly drops the beginning of an investigation
  is the console telling a small lie.
- **`EmptyState`** (`states.tsx`) — currently doing duty for "binary file",
  which is not an empty state. Once `FileFacts` exists, `EmptyState` goes
  back to meaning nothing is there.
- **`Chip`** (`console.tsx`) — the `Tone` union gains nothing, but the
  `moss` and `slate` entries hard-code hex values (`#2f5a1c`, `#2c4660`)
  where every other tone uses a token. Those two need `--color-moss-ink` and
  `--color-slate-ink` in `@theme`, or the design system documents a colour
  the tokens do not contain.
- **`Vital`** (`console.tsx`) — the report's cover wants the band's big
  serif figures on paper. It needs an `onPaper` variant rather than a second
  copy of the component.
- **`swarm-detail.tsx`** — the tab strip is eleven tabs (`swarm-detail.tsx:35`)
  and about to be twelve, and `InputsPanel` is already hidden inside the
  `files` tab where nobody looks for the evidence hashes. At twelve it needs
  grouping: *the run* (story, threads, traces, agents), *the evidence* (files
  — which is where inputs live — artifacts, ledger), *the frame* (goal, tools,
  claims, budget), *the output* (report). This is a layout change, not a new
  component, and it is what makes W1.2 findable.

### Sequencing the design-system work

1. Build `HashChip`, `EvidenceRow`, `DownloadRow`, `FileFacts` in the repo.
2. Add them to `ui/src/design-system.ts` and `componentSrcMap`.
3. `npm run ui:build`, update `cssEntry`, re-sync with `design-sync`.
4. Rework `InputsPanel`, `ArtifactsPanel`, `TracesPanel` against them.
5. Repeat for the Wave 2 set once the report renderer exists, because a
   component built without the thing it displays is a guess.

---

## Deliberately not doing

Stated here so that "we don't have it" reads as a decision:

- **MCP** — see W1.8. Also: the user has ruled it out.
- **Docker** — see W1.8. Also: the user has ruled it out.
- **Voice dictation** — contradicts the egress claim.
- **Share links** — the answer is a hashed file, not an exposed console.
- **Plaso** — does not fit the 120-second tool timeout.
- **Linux and macOS memory analysis** — needs network at run time, which the
  netguard default forbids.
- **Hypothesis tracking as `finding` + `confidence: low`** — the corpus
  refutes it: one entry in 1501. Done properly it needs its own `kind` plus
  `about` and `stance` fields, 2–3 days, and it is whole or nothing.

## What genuinely belongs to a paid tier

Not in these waves, and not because they are hard to build:

- A keyed HMAC ledger chain and a `swarm verify` report.
- A multi-template report library and digital signature.
- A curated YARA rule set — the cost is maintenance, forever.
- `$LogFile` and VSS parsing.
- Identity, multi-tenancy and an audit trail.

## The gate

Every wave's work passes the same four commands before it is pushed, and the
pull request says so:

```
npm run typecheck
npm run ui:build
npm test
bash scripts/test-bash.sh
```
