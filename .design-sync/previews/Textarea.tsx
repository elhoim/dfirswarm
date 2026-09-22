import { Textarea, Label } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS, so it only holds classes the app itself uses.
const field = { display: "flex", flexDirection: "column", gap: 6, maxWidth: 560 } as const;
const hint = { margin: 0, fontSize: 12, lineHeight: 1.5, color: "var(--color-ink-3)" } as const;

// Hard-wrapped at the width the field is previewed at, the way a goal file on
// disk is wrapped: no soft-wrap orphans, so the document reads as a document.
const GOAL = `## Goal

Read every file under \`inputs/\` and write
\`work/report.md\`: what each one contains, the
numbers that matter, and anything that looks
wrong. Claim the report before you write it.

## Definition of done

\`work/report.md\` names every file under
\`inputs/\`, and a peer has posted that it
matches. \`inputs/\` is byte-for-byte unchanged.`;

/** The resting composer: the goal is the one long-form field a kickoff has. */
export const Resting = () => (
  <div style={field}>
    <Label htmlFor="goal-empty">Goal</Label>
    <Textarea id="goal-empty" spellCheck={false} placeholder="What the swarm is for, how it is done, and how you will know." />
    <p style={hint}>Markdown. It becomes <code>goal.md</code> in the sandbox, unchanged.</p>
  </div>
);

/**
 * Filled with a real goal document, in mono at the console's reading size —
 * the way the kickoff screen sets it, because the agents read it as a file.
 */
export const Filled = () => (
  <div style={field}>
    <Label htmlFor="goal-filled">Goal</Label>
    <Textarea
      id="goal-filled"
      spellCheck={false}
      className="font-mono"
      style={{ minHeight: 264, fontSize: 12.5, lineHeight: 1.6 }}
      defaultValue={GOAL}
    />
    <p style={hint}>338 / 32,000 chars</p>
  </div>
);

/** Disabled: a goal loaded from the library is read until it is taken off the shelf. */
export const Disabled = () => (
  <div style={field}>
    <Label htmlFor="goal-locked">Goal · from the library</Label>
    <Textarea
      id="goal-locked"
      spellCheck={false}
      className="font-mono"
      style={{ minHeight: 110, fontSize: 12.5, lineHeight: 1.6 }}
      defaultValue={"## Goal\n\nEach of you introduces yourself on `threads/main`, then the team\nwrites one file containing every assigned agent id."}
      disabled
    />
    <p style={hint}>Saved goals are locked until you edit a copy.</p>
  </div>
);
