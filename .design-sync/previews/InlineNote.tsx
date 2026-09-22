import { InlineNote } from "dfirswarm";

const stack = { display: "grid", gap: 8 } as const;

/** Four tones, one meaning each: a remark, a warning, a violation, a pass. */
export const Tones = () => (
  <div style={stack}>
    <InlineNote>The cap is per run, not per agent. Every agent on the team spends against the same $60.</InlineNote>
    <InlineNote tone="warn">Two agents have been idle for 11 minutes. Reaping them releases the four files they claim.</InlineNote>
    <InlineNote tone="danger">done/SWARM_DONE was written while 2 of 9 checks were still failing. The run is not certified.</InlineNote>
    <InlineNote tone="ok">All 9 checks passed in the sandbox. work/report.md carries the sentinel.</InlineNote>
  </div>
);

const label = { fontFamily: "var(--font-sans)", fontSize: 12.5, fontWeight: 500, color: "var(--color-ink-2)" } as const;
const spec = { fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-ink)" } as const;

/** Where a note actually sits: under the control it qualifies, at its width. */
export const UnderTheFieldItQualifies = () => (
  <div style={{ display: "grid", gap: 6, maxWidth: 460 }}>
    <span style={label}>Model team</span>
    <span style={spec}>ollama/qwen3-coder=4,anthropic/claude-opus-4=1</span>
    <InlineNote>A team of local models bills nothing: spend stays an exact $0.00, and the token cap is the only brake on the run.</InlineNote>
  </div>
);
