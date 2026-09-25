# DFIR Swarm web app — design

The local web app for `runs/`: it binds `127.0.0.1`, and `--host 0.0.0.0` opens it to the LAN. Hierarchy stays **swarms → threads → agents → traces**; the look is ours. Not a dark terminal. Working name for the visual language: **field notebook** — warm paper, ink, a few coloured pens.

Stack: Vite + React 19 + TypeScript + Tailwind v4, shadcn-style primitives on Radix (`ui/src/components/ui/*`). Server: `scripts/ui-server.ts` → `scripts/ui/app.ts` on `node:http` (no runtime deps), JSON API + SSE, static `ui/dist`.

## 1. Tokens

Defined once in `ui/src/index.css` under `@theme`; every component uses the Tailwind utilities generated from them (`bg-paper`, `text-ink-2`, `border-line`, `bg-kelp`…).

### Colour

| Token | Hex | Role |
| --- | --- | --- |
| `paper` | `#F7F5F0` | page background |
| `paper-2` | `#EFECE4` | subtle fills, table heads, dark-thread base |
| `paper-3` | `#E6E1D6` | track of progress bars, skeletons |
| `card` | `#FFFFFF` | cards, inputs |
| `ink` | `#1C1B1A` | primary text, dark surfaces (trace JSON) |
| `ink-2` | `#55524C` | secondary text |
| `ink-3` | `#8A867E` | captions, labels, placeholders |
| `line` / `line-2` | `#DDD8CC` / `#CCC6B8` | hairlines, stronger borders |
| `kelp` / `kelp-ink` / `kelp-soft` | `#0E7C7B` / `#0A5D5C` / `#DCEFEE` | **primary**: actions, running state, spend bar, live indicator |
| `saffron` / `saffron-ink` / `saffron-soft` | `#E09F3E` / `#9A5F0C` / `#FBEBD3` | **budget & stall**: ≥80 % of cap, past wall clock, stalled `?`, reap |
| `brick` / `brick-ink` / `brick-soft` | `#B23A48` / `#8B2532` / `#F5DADE` | **violations & danger**: claim violation, dead `?`, stop, cap hit |
| `slate` / `slate-soft` | `#3E5C76` / `#DCE4EC` | **locks & files**: claims, write/edit, critic role, prepared |
| `moss` / `moss-soft` | `#4C7A34` / `#E1EDD8` | **done**: ✓, released, SWARM_DONE |

One meaning per colour. Nothing else is coloured. Charts (spend bars, timeline) reuse the same five hues so a red bar and a red badge say the same thing.

### Type

- Sans: `Inter, ui-sans-serif, system-ui` for all UI text. Body 14 px / 1.45. Headings 22 px (page), 18 px (card), 15 px (section). Numbers always `tabular-nums`.
- Mono: `JetBrains Mono, ui-monospace` **only** for identifiers (`s7a1c00`), paths (`work/hello.txt`), tool names, shell lines, JSON. Mono never carries prose.
- Labels: 11 px, semibold, uppercase, 0.08 em tracking, `ink-3` (`.label-caps`).

### Spacing & shape

- 4 px grid. Card padding 16 px (12 px in dense lists). Gaps 8 / 12 / 16.
- Radii: 4 px badges, 6 px controls, 10 px cards. Pills for status only.
- Borders instead of shadows; one 1 px `line` hairline and a barely-there `shadow-card`. No elevation stacks.
- Max content width 1680 px — wide enough that the ledger and trace tables fit without a scrollbar of their own on the monitors this is operated from; the header is sticky and translucent over paper.

### Density

Operator tool, so dense but not cramped: 13 px in tables and trace rows, 28–32 px control height, single-line rows with a second 11 px caption line. Long text (goal, posts) is clamped with a mask and a **Show all** toggle.

## 2. Layout

| Screen | Route | Shape |
| --- | --- | --- |
| Overview | `/` | Title + filter row → **concurrent strip** (6 stats across all swarms) → status chips → card grid (1 / 2 / 3 columns) or table. |
| Kickoff | `/new` | Single centred form, 720 px. Two-column fields on ≥640 px. Live `swarm.sh start …` preview badge. Job output card below. |
| Swarm detail | `/swarms/:id/:tab/:sub` | Breadcrumb → **header card** (title, phase, identity line, actions, spend bar + 4 stats, state badges) → **goal card** → tabs. Tab + selection live in the URL, so two windows can show a thread and a trace of the same swarm. |
| Threads | `…/threads/:thread` | 280 px thread rail (dark threads hatched) + posts column with the messaging timeline on top. |
| Agents | `…/agents/:agent` | Search + legend → 1/2/3-column agent cards → agent detail (header + that agent's calls). |
| Traces | `…/traces` | Filter bar (agent, tool, text, order, show-all, follow) → one-line-per-event list; click a row for raw JSON. |
| Claims | `…/claims` | Two columns: live locks / violations / reaped; claim → work → release sequences. |
| Budget | `…/budget` | Spend-vs-cap card, wall-clock card, per-agent table. |
| Files | `…/files/:path` | Files-with-history rail + revisions → revision viewer + Restore. |
| Artifacts | `…/artifacts/:path` | `work/` rail → sandboxed iframe (HTML), `<img>` (SVG/PNG), inline text. |

Narrow (< 1024 px): rails stack above content; header nav collapses to the logo, live dot, Actions and **New swarm**; the tab strip scrolls horizontally; stats reflow to 2 columns; the swarm table falls back to cards.

## 3. Components

`ui/src/components/ui/`: `Button` (default / secondary / ghost / danger / outlineDanger / warn / link), `Badge` (neutral / kelp / saffron / brick / slate / moss / outline), `Input`, `Textarea`, `Select`, `Label`, `Switch`, `Dialog`, `Tooltip`.

`ui/src/components/`: `AppShell` (header, live indicator, footer, jobs drawer), `JobsDrawer` + `JobCard` (shell action console), the console vocabulary in `console.tsx` (`Chip`, `TagChip` and the one tag-colour table, `Meter`, `FinishMeter`, `VitalsBand`, `Vital`, `StatusDot`, `SerifH`), `AgentMark` (● working · ✓ done · ? stalled · ? dead), `BudgetBar`, `DarkThreadMark`, `ActivityStrip` + `ThreadPulse` (messages against tool calls over the run; a lane per agent per thread), `EmptyState` / `LoadingState` / `ErrorState` / `InlineNote`.

Screens in `ui/src/screens/`, detail panels in `ui/src/screens/detail/`. Data: `lib/api.ts` (typed fetch), `lib/live.tsx` (one `EventSource`, per-swarm versions, `useResource` stale-while-revalidate), `lib/types.ts` (wire types mirrored from `scripts/ui/model.ts`).

### The dropdown

One control for every list an operator picks from: a model, an evidence set,
a guard mode, a trace filter. It is `Select` in `ui/src/components/ui/select.tsx`
and there is no native `<select>` left in the console, because on macOS a native
one hands the list to the operating system: a grey system menu in the system
font, with no room under an option for what the choice means.

- **Trigger.** Field-shaped, the same border, height and focus ring as `Input`,
  in two sizes: `md` (40px, the kickoff form) and `sm` (32px, a filter bar).
  It shows the chosen option's label, its mark if it has one, and a chevron
  that turns when the panel is open. Strings the operator reads as identifiers
  (a model id, a set name, a tool name) are set in mono with `mono`.
- **Panel.** Portalled and positioned against the trigger, so it escapes the
  scrolling panels and `overflow-hidden` cards the screens are built from, and
  flips above the trigger when there is no room below. Paper surface, hairline
  border, the one deep shadow the console uses for anything that floats.
- **Options.** A label, and under it a `hint` in ink-3 for what the choice
  means or costs; a `meta` on the right for a count or a size; a `mark` in
  front (the readiness dot, for a model); a `group` heading that sticks while
  its options scroll. The chosen one carries a kelp check. Disabled options
  stay in the list at 45% so the operator can see what is missing.
- **Filter.** Appears on its own once a list is longer than eight, or with
  `searchable`. It matches the label, the hint and any `keywords` an option
  carries (a set's file names, say). The row under the list names the keys.
- **Keyboard.** ↑ ↓ move, Home and End jump, Enter chooses, Escape closes and
  returns focus to the trigger. With no filter field a typed prefix jumps to
  the option that starts with it, which is the one thing a native select did
  well.
- **A11y.** The trigger is a `combobox` with `aria-expanded` and
  `aria-controls`; the list is a `listbox` of `option`s with `aria-selected`.

What it is not: a multi-select, a menu of actions (that is a `Button` group or
a `Dialog`), or a free-text combobox. A choice that needs a typed value the
list lacks gets an "Other…" option and an `Input` that appears beside it, as
the model picker does.

## 4. States

| State | Treatment |
| --- | --- |
| Loading (first) | `LoadingState`: spinner caption + 3–6 skeleton bars. Never a blank panel. |
| Refreshing (SSE) | Old data stays; header shows a quiet “syncing…”; no flashing. |
| Empty | `EmptyState`: dashed card, icon, one-line title, one sentence that names the file that is missing (`threads/main`, `traces/events.jsonl`, `history/`), and the action that creates it. |
| Empty, where nothing is missing | Naming the file is wrong when the file is fine and the world is simply like that: an agent with no failures, a model that returns no reasoning. The panel says the fact instead — “nothing failed”, “this model returns no reasoning”, with the evidence for it (which models did reason, and how many lines). Where a panel cannot tell the two apart on its own, it asks the harness before it answers rather than guessing. |
| Error | `ErrorState`: brick card with the server message in mono and a Retry. Refresh failures while data is present show as a one-line note next to the filters. |
| 404 swarm | Dedicated empty state explaining `SWARM_RUNS_DIR`. |
| Offline | Header pill turns brick “offline”; the client retries the stream every 3 s. “live · polling” when the fs watcher is unavailable. |
| Bundle missing | Server answers `/` with a 503 page pointing at `npm run ui:build`; `/api/*` keeps working. |
| Prepared (`--no-start`) | Agents shown as “waiting for kickoff”, not stalled. |
| Dark thread | Hatched `paper-2` background, `ink-2` text, moon “dark” mark. Still fully readable. |
| Cap hit / past wall clock | Spend bar and “Remaining” go brick; elapsed goes saffron; badges in the header. |

## 5. Motion

Only functional: pulsing dot on running / live, spinner on running jobs, 150 ms dialog fade, smooth follow-scroll on new trace lines. No page transitions.

## 6. What is deliberately not there

No dark theme, no auth screen, no drag-and-drop, no chat box for humans to post (the protocol has no operator author), no per-token cost estimates beyond what `budget.json` holds. Stop / Reap / Restore / Kickoff exist in the UI as **our additions** and are labelled as such.
