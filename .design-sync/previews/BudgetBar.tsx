import { BudgetBar } from "dfirswarm";

// Full-width stories (cardMode: column). Layout is inline style, never a
// Tailwind utility.
const stack = { display: "grid", gap: 6 } as const;
const caption = { fontFamily: "var(--font-sans)", fontSize: 11.5, color: "var(--color-ink-3)" } as const;

/** Room left: kelp, and the percentage beside the two figures. */
export const WithRoom = () => (
  <div style={stack}>
    <span style={caption}>s2cb903 · 7 agents · 14.5 min in</span>
    <BudgetBar spent={7.98} cap={60} />
  </div>
);

/** At 80% the bar turns saffron — the threshold the harness itself watches. */
export const Hot = () => (
  <div style={stack}>
    <span style={caption}>s2cb903 · 9 agents · 92.9 min in</span>
    <BudgetBar spent={49.1} cap={60} />
  </div>
);

/** Past the cap the figures go brick and the percentage becomes “cap hit”. */
export const OverTheCap = () => (
  <div style={stack}>
    <span style={caption}>s4f11ae · stopped on the cap · 7 agents reaped</span>
    <BudgetBar spent={61.4} cap={60} />
  </div>
);

/** A team of local models bills nothing, so tokens are the brake instead. */
export const BrakedByTokens = () => (
  <div style={stack}>
    <span style={caption}>s9d27c0 · ollama/qwen3-coder=4 · nothing metered</span>
    <BudgetBar spent={1840000} cap={4000000} unit="tokens" />
  </div>
);
