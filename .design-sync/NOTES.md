# design-sync notes

- **This repo has no publishable component library.** `ui/` is a Vite application:
  no Storybook, no story files, no library entry points in `package.json`. The
  design system's entry is `ui/src/design-system.ts`, a barrel written for this
  sync that re-exports exactly the presentational components. Adding a component
  to the system means adding it there. `cfg.entry` pins it, so the driver needs
  no `--entry` flag. Do not drop that key: `package.json` declares no `main`,
  `module` or `exports`, so without it the converter falls into synth-entry mode
  and bundles every `.tsx` under `ui/src` — screens included — instead of the
  barrel, and it exits 0 either way.
- **The stylesheet is compiled Tailwind, not source.** `ui/src/index.css` is a
  Tailwind v4 entry (`@import "tailwindcss"` plus an `@theme` block); the class
  names the components use only exist after a build. `cssEntry` therefore points
  at `ui/dist/assets/index-*.css`, which means **`npm run ui:build` must run
  before the converter**, and the hashed filename in `cssEntry` changes whenever
  the CSS does. Check it on every re-sync.
- **The evidence components** (`HashChip`, `EvidenceRow`, `DownloadRow`,
  `FileFacts`, `PrintSheet`) came in with the report. They are presentational
  and take no context; `HashChip` touches `navigator.clipboard` only inside a
  click handler, with a textarea fallback, so it renders anywhere.
- **Excluded on purpose** (`componentSrcMap` nulls): `AppShell` needs a router
  context, and `JobsDrawer`, `JobCard`, `JobStatusIcon`, `GoalLibrary` and
  `ModelTeamEditor` read the live event stream or the HTTP API. They are screens,
  not design-system parts.
- `lucide-react` supplies the icons and `class-variance-authority` the button
  variants; both resolve from the repo root `node_modules`.

## Re-sync risks

- The `cssEntry` hash goes stale on any UI change. A sync that silently ships the
  old stylesheet looks fine locally and renders unstyled in Claude Design.
- `ui/src/design-system.ts` is hand-maintained. A component added to
  `ui/src/components/` and not added to the barrel is invisible to every future
  sync, with no warning.
- The token values live in `ui/src/index.css` under `@theme`. `docs/ui-design.md`
  documents a different, older set (Inter, JetBrains Mono, `#F7F5F0`); the CSS is
  authoritative and the docs are stale.
- Every component ships an empty prop contract. This is the largest open gap in
  the uploaded system and it is invisible from the render check, which passes
  clean regardless. See "The empty prop contracts" below before assuming a sync
  that exits 0 shipped a usable API.

## Fixed during the first sync

- **`docsDir` must not be `docs/`.** The default bound `docs/inputs.md` — the
  read-only *evidence* document — to the `Input` component, so the design agent
  would have read harness guidance as text-field usage. Pointed at
  `.design-sync/component-docs/` instead, which is empty: every component's
  `.prompt.md` is synthesized from its `.d.ts` and its source JSDoc, which is
  accurate. Put real per-component docs there when they exist.
- **`guidelinesGlob` must not be the default.** It swept all 24 files of
  `docs/*.md` — safety, protocol, netguard, inputs — into `guidelines/` as
  design guidance. Narrowed to the two documents that actually describe the
  console's design.
- **Previews must not use Tailwind utility classes for layout.** `cssEntry` is
  the app's *compiled* stylesheet, so it contains only the classes the app
  itself uses. `grid-cols-4` is not among them and silently collapsed the
  vitals band to one column — it looked like a design choice, not a missing
  class. Use inline `style={{...}}` for preview layout; the components' own
  classes come from the bundle and are fine.
- `VitalsBand` is a full-width bar, so it carries
  `overrides.VitalsBand.cardMode = "column"`.

## Folded from the first fan-out (batches forms, console, states)

### Which classes a preview may use

`cssEntry` is the app's **compiled** stylesheet, so a class exists only if the
app already writes it. Check the shipped bundle, never `ui/src/index.css`:

    grep -cF '.text-ink-2' ds-bundle/_ds_bundle.css

Safe to pass as `className`: `serif`, `label-caps`, `card`, `tabular`,
`font-mono`, `font-medium`, `truncate`, `w-fit`, the `text-ink*` /
`text-band-ink-2` / `text-kelp-ink` / `text-brick-ink` / `text-moss` /
`text-saffron` family, `console-row`, `console-cell`, and the arbitrary sizes
`text-[11px] [12px] [13px] [14px] [20px] [22px] [30px]`.

**Absent, do not reach for**: `text-[11.5px]`, `text-[12.5px]`,
`leading-[1.1]`. They appear in `ui/src` but inside `cn()` the scanner emits a
different escape. All layout stays inline `style={{...}}` regardless; the token
custom properties (`var(--color-ink-3)`, `var(--font-mono)`) are in the bundle
even where the utility that consumes them is not.

### Preview mechanics

- **`defaultValue`, never `value`.** A preview has no `onChange`; a controlled
  input without one logs a React warning into `pageErrs` and the capture
  reports the cell as an error.
- **The per-story capture is a 900x700 viewport shot, not `fullPage`.** Content
  past 700px is silently cut; give tall stories an explicit height.
- **Components that render a Radix `Tooltip` must wrap themselves in
  `TooltipProvider` inside the preview.** There is no `cfg.provider`, stories
  mount bare, and the Radix context has no default, so `Root` throws.
  `AgentMark` and `DarkThreadMark` both need this.
- `label-caps` already carries `text-ink-3`; on the dark band write
  `label-caps text-band-ink-2` or the caption vanishes into the ground.
- `Vital` and `Meter onDark` are band-coloured and invisible on paper: wrap
  them in `VitalsBand`.

### Content source

`docs/use-cases/dfir-web-server-case/` is a real run end to end (`s2cb9`, 7
agents, $7.98 of $60, 14.5 min, 420 calls, 9/9 checks, a forged `evtx_filter`,
a `CLAIM VIOLATION` post, agent ids `s2cb900`–`s2cb906`). Phase titles come
from `TITLES` in `ui/src/lib/story.ts`. Mine those rather than inventing.

### Component behaviour found while previewing — not preview bugs

- **`NativeSelect` draws no chevron, in the shipped app as well.**
  `ui/src/components/ui/input.tsx` sets
  `bg-[url("data:image/svg+xml,%3Csvg ... width='12' ...")]`; the literal has
  unescaped spaces, so Tailwind v4 discards that candidate and the two beside
  it. Verified: `appearance-none`, `pr-8` and `bg-no-repeat` compiled into
  `ui/dist/assets/index-sh_94sOY.css`; `%3Csvg` and `bg-[length` did not. The
  result is a text-input-shaped box with 32px of dead right padding. **Fix it
  in the component** (escape the data URI, move the rule into `index.css`, or
  draw a `lucide-react` ChevronDown), then re-capture — the grades clear
  themselves.
- `Input` and `Textarea` have **no invalid state**: the shared field class
  carries only `focus-visible:` and `disabled:`. No error story exists because
  there is nothing to show; that is a component change first.
- `StatusDot` maps `prepared` and `unknown` to the same dashed ring. Label both
  cells or the sheet reads as a duplicate.
- `TagChip`'s `from` beats its `tag`: `from="system"` forces the band tone.
- `BudgetBar` calls `money(spent)` with no digit count, so a figure under $10
  prints three decimals (`$7.980 / $60.00`).
- `ThreadPulse` positions dots against `from`/`to`, not the last post, so a
  thread whose window far outruns its posts bunches every dot at the left edge.

### Sequencing

`viewport` is keyed into a component's grade stamp; `cardMode` and
`primaryStory` are not. Adding a `viewport` override after a full build makes
`preview-rebuild` refuse with `[CONFIG_STALE]` for exactly those components.
Set every `viewport` override **before** the full build, or run
`package-build.mjs` again after.

## Folded from the overlays batch

- **Portals are fine in a card.** `DialogContent` and `TooltipContent` portal to
  `document.body`, outside the `.ds-single` wrapper, so its `translateZ(0)`
  never becomes their containing block. They position against the viewport and
  the per-story capture *is* a viewport shot at the card's declared size, so an
  open overlay lands centred. No workaround needed.
- **Radix's scroll lock zeroes `body` padding when a dialog opens.** The emitted
  card relies on `body{padding:24px}` for its gutter, so anything left in normal
  flow *beside* an open dialog is clipped against the top and right edges. Give
  that content its own padding in its own wrapper.
- **Id convention, corrected while porting:** the swarm is `s2cb9`; `s2cb900`
  through `s2cb906` are its agents. `swarm.sh stop s2cb903` would address an
  agent, not the run. Use the short id for run-level copy.

## Known render warns

Checked on every re-sync. A warn line that is not on this list is new: look at
it, then fix it or add it here.

- `! docsDir: .design-sync/component-docs not found — skipped`. The directory is
  deliberately empty, and git does not track empty directories, so it never
  exists on a fresh clone. Every `.prompt.md` is synthesized instead, which is
  the intent — see the `docsDir` bullet under "Fixed during the first sync".
- `tokens: N defined, M referenced (1 missing, below threshold)`. Non-blocking
  and stable across runs.

## The empty prop contracts

**All 41 `<Name>.d.ts` files ship `export interface <Name>Props { [key: string]:
unknown; }`.** The design agent gets no prop names, no types and no enums for
any component in the system. Confirmed 2026-09-20; it has been true since the
first sync, so the uploaded project carries the same contracts. The render check
passes clean either way, so nothing in the pipeline flags it — which is why it
survived a whole campaign unnoticed.

- **Cause.** `lib/dts.mjs` resolves a component's props through
  `project.getSourceFile(entry)`, where `entry` is
  `pkgJson.types || pkgJson.typings || 'index.d.ts'` under the repo root. This
  `package.json` has no `types` field and `<repo>/index.d.ts` does not exist, so
  the lookup returns no declarations and every props body falls back to the
  index signature. The tell in the build log is `[DTS] parsed 0 .d.ts files`.
- **What still works.** `<Name>.prompt.md` is synthesized from the source JSDoc
  plus the authored preview, so it carries the real props in real JSX
  (`tone="kelp"`, `chars={8}`, `sha={...}`). The agent has a working example for
  every component; what it lacks is the formal contract.
- **Fix path, validated as far as it goes.**
  `./node_modules/.bin/tsc -p ui/tsconfig.json --noEmit false --declaration
  --emitDeclarationOnly --outDir ui/dist/types` emits 48 declaration files
  carrying real prop types with per-prop JSDoc. With that tree on disk the
  parser picks it up (`[DTS] parsed 48 .d.ts files`) and `Badge` and `Button`
  fill in. The other 39 stay empty because the lookup still goes through the
  missing types entry.
  - Finishing it takes two things: a types entry pointing at the emitted barrel
    (`ui/dist/types/src/design-system.d.ts`), and the `@/*` path alias taught to
    the extractor. The emitted barrel re-exports `@/components/...`, and the
    extractor builds its ts-morph project without `compilerOptions.paths`, so
    those specifiers do not resolve. The documented lever for the second half is
    a `.design-sync/overrides/dts.mjs` fork declared in `cfg.libOverrides`.
  - Emit **after** `npm run ui:build`, never before: vite owns `ui/dist/` and
    clears it.
  - Do not emit into a dot directory. The parser globs `<root>/**/*.d.ts`
    through fast-glob, whose default skips dot directories, so
    `.design-sync/.cache/types` is invisible to it. `ui/dist/types` works and is
    already gitignored.
  - `cfg.entry` exists as a config field (`flag('entry', cfg.entry)` in
    `package-build.mjs`) even though the skill's config table omits it. It pins
    the *bundle* entry, not the types entry, so it does not help here.
- **Deliberately not applied in the 2026-09-20 re-sync.** It needs either a
  manifest change or a lib fork, both wider than a sync, and a half-applied
  version (2 of 41) is worse than the consistent one. The bundle shipped with
  all 41 on the index signature, which is what a fresh clone reproduces.

## The report vocabulary (added 2026-09-20)

`ui/src/components/report.tsx` holds 23 components for showing a recorded fact:
the `Claim` atom and `FindingCard`, the `TimelineTable` / `IndicatorTable` /
`Timeline` collections, `Exhibit` + `Excerpt`, `MethodList` + `MethodStep`,
`ArtifactTable`, `CustodyRecord`, `Limitation`, `NotRecorded`, and the
`ReportCover` / `ReportContents` / `ReportSection` / `Verdict` / `ReportCounts`
frame. `LedgerPanel` and `ReportPanel` were moved onto it, which deleted the
bespoke table and card markup those screens used to carry.

- **The uncited mark is the point, not a bug.** `Claim`, the tables and
  `Provenance` all render a brick mark when `source` or `evidence` is missing.
  A future change that "cleans up the empty column" removes the only place the
  harness's own rule is visible.
- **`ExhibitNo` closed a real gap.** `LedgerPanel` used to print `#<seq>` while
  the ledger and the report both cite `E-<seq>`. Three names for one number.
- **Confidence diverges from the printed report on purpose, and that is worth
  revisiting.** `ConfidenceMark` draws three pips in ink;
  `scripts/report.ts:567` colours the same value (high → moss, medium →
  saffron, low → *no chip at all*). Two reasons the console does not copy it:
  one meaning per accent is the stated rule and moss already means done, and
  the report's mapping leaves a low-confidence claim with no mark, so it cannot
  be told from one whose confidence nobody stated. The right end state is
  probably `scripts/report.ts` adopting the pip mark; until somebody decides,
  the two documents show confidence differently and a reader moving between
  them will notice.
- **`cssEntry` moved twice while this was built**, ending at
  `ui/dist/assets/index-DLXRDMcg.css`. Every class a new component introduces
  changes the hash, so on a branch that touches `ui/src` expect to update it
  more than once, and check it after the *last* `npm run ui:build`, not the
  first.
- `ArtifactTable` is the file list (report section 6). `CustodyRecord` is the
  fixed-row who-held-what table (section 8). They are different sections and
  were briefly conflated while this was built.

## Still open on the report surface

Found while building the components; none of it is wired:

- `lintReport()` has no UI caller. `swarm.sh report <id> --lint` checks that
  every numbered section of the swarm's own `work/report.md` cites something
  checkable, and nothing in the console ever shows the result.
- `ReportOptions.caseId` / `examiner` / `organisation` are only ever set from
  `registry.json`; `organisation` has no caller at all. `ReportCover` takes all
  three, so the component is ready before the data path is.
- The dossier `DownloadRow`s still pass no `bytes` and no `sha`, though the
  props exist. That is the hash-on-the-row rule going unmet on the one screen
  whose whole subject is the handover. It needs a server route that reports
  per-file size and hash for `package/`.

## Preview content drift

- The five evidence previews use their own fictional run: `s7a1c`, agent
  `s7a1c00`. Every other preview mines `s2cb9` from
  `docs/use-cases/dfir-web-server-case/`. Both are internally consistent, but a
  reader browsing the pane sees two run ids. Harmonize on `s2cb9` if you touch
  those five.

## Fixed during the 2026-09-20 re-sync

- `conventions.md` pointed the design agent at
  `components/<Name>/<Name>.prompt.md`. The emitted layout carries a group
  segment, so the true path is `components/general/<Name>/<Name>.prompt.md`.
  Corrected. Everything else the header names — 34 tokens, 14 components, the
  three radius values, the absence of a `Card` component, and
  `guidelines/docs/ui-design.md` — was re-verified against the fresh build and
  still holds.
