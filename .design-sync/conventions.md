# Building with DFIR Swarm

The console of a tool you watch a forensic investigation happen in. Its visual
language is **field notebook**: warm paper, ink, and a few coloured pens. Not a
dark terminal, not a dashboard.

## Setup

No global provider. Mount any component directly from `window.DfirSwarm`.

One exception: anything using `Tooltip` must sit inside `TooltipProvider`, or
the tooltip never opens. Wrap the screen once, not each tooltip.

```jsx
const { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } = window.DfirSwarm;
<TooltipProvider><App /></TooltipProvider>
```

`Dialog` and `Tooltip` render through a portal and position `fixed`, so they
escape any clipping parent. That is intended; do not wrap them in `overflow:
hidden`.

## Styling: use the custom properties, never a utility class

The shipped stylesheet is the application's **compiled** CSS. It contains the
utility classes that application already uses and no others, so
`className="grid-cols-4"` or `className="p-8"` will silently do nothing in a
design that did not come from this repo. This is the single most common way to
produce a page that looks broken.

Style your own layout with **inline styles reading the tokens**, which are real
CSS custom properties and always resolve:

| Group | Names |
| --- | --- |
| Surfaces | `--color-paper` `--color-paper-2` `--color-paper-3` `--color-card` |
| Ink | `--color-ink` `--color-ink-2` `--color-ink-3` |
| Lines | `--color-line` `--color-line-2` |
| The dark band | `--color-band` `--color-band-2` `--color-band-line` `--color-band-ink` `--color-band-ink-2` `--color-band-brick` |
| Accents | `--color-kelp` `--color-saffron` `--color-brick` `--color-slate` `--color-moss`, each with a `-soft` ground; `kelp`, `saffron` and `brick` also have `-ink` for text on that ground |
| Type | `--font-sans` `--font-serif` `--font-mono` |
| Radius | `--radius-sm` (4px badges) `--radius-md` (6px controls) `--radius-lg` (10px cards) |

**One meaning per accent, everywhere.** `kelp` is running and the primary
action. `saffron` is budget and stall. `brick` is violation and danger. `slate`
is locks and files. `moss` is done. A colour that means one thing in a chip
means the same thing in a bar and in a chart. Nothing else is coloured.

Mono is for identifiers only: a swarm id, a path, a tool name, a shell line.
Mono never carries prose. Serif is italic, used only for the wordmark and the
big figures in the dark band.

Borders separate, not shadows. Pills are for status only; everything else takes
`--radius-md`.

## Evidence: the hash goes on the row

Anything that names a file names its sha256 beside it. `HashChip` is the
atom — twelve characters, the whole value on hover, click to copy — and
`EvidenceRow` is the line an input or an artifact takes. `DownloadRow` is the
same line for a file of the handover, with the button beside the hash on
purpose: what makes it a handover rather than a download is that the number
travels with it. A file with no preview gets `FileFacts`, never `EmptyState`
— for a carved executable the size and the hash *are* the content.

`PrintSheet` frames anything at A4 proportions. Use it for what will be
printed, and for nothing else.

## Reporting: the citation goes on the claim

Evidence puts a sha256 beside a file. The report vocabulary puts a **source**
and a **way to check it** beside every assertion, which is the same rule one
level up: the harness requires both when a fact is recorded, because an entry
nobody can check is not a record.

`Claim` is the atom — an exhibit number, the statement, and the provenance
under it. `FindingCard` is the same thing with the room a conclusion needs.
`TimelineTable` and `IndicatorTable` are the collections; `Timeline` is the
narrative form for a column too narrow to carry six. **When `source` or
`evidence` is missing they mark the claim in brick rather than dropping the
empty field.** Do not tidy that away: the mark is the feature.

`ExhibitNo` renders `E-<seq>`, the one identifier the console, the ledger and
the printed report share. Use it wherever a claim is shown and never invent a
second numbering beside it.

**Confidence is not a colour.** `ConfidenceMark` draws three pips and the word,
in ink. The accents are spent on state and stay that way, a pip count survives
the greyscale print these documents are usually read in, and `low` and "nobody
said" are different answers that look different.

The document frame is `ReportCover`, `ReportContents`, `ReportSection`,
`Verdict` and `ReportCounts`. Sections are numbered and anchored (`#s-3`)
because the report asks to be cited by section, not by page. `ReportCounts`
carries a fourth number, `uncited`, and that one says whether the other three
are worth anything.

The rest, in the order a report uses them: `Exhibit` and `Excerpt` for quoted
evidence with line numbers, `MethodList` with `MethodStep` for what was run,
`ArtifactTable` for the files and their hashes, `CustodyRecord` for who held
what and whether it was intact at the end, `Limitation` for what the run could
not establish, and `NotRecorded` for an absence that has to be stated rather
than left blank.

## Where the truth is

- `styles.css` and its `@import` closure: the tokens, the fonts, the component
  CSS. Read it before inventing a value.
- `components/general/<Name>/<Name>.prompt.md` for a component's props and
  usage, and `guidelines/docs/ui-design.md` for the design's own reasoning.

## An idiomatic screen

```jsx
const { Chip, Meter, Button } = window.DfirSwarm;
// there is no Card component: a surface is a div with the tokens on it

<div style={{ background: "var(--color-paper)", padding: 24, fontFamily: "var(--font-sans)" }}>
  <div style={{ background: "var(--color-card)", border: "1px solid var(--color-line)",
                borderRadius: "var(--radius-lg)", padding: 16, display: "flex",
                flexDirection: "column", gap: 12 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <Chip tone="kelp">running</Chip>
      <span style={{ fontSize: 14, color: "var(--color-ink)" }}>compromised web server</span>
      <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5,
                     color: "var(--color-ink-3)" }}>s2cb9</span>
    </div>
    <Meter pct={13} label="Spend against the cap" />
    <Button variant="secondary">Open the trace</Button>
  </div>
</div>
```
