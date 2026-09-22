import { SerifH, Chip } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const stack = { display: "flex", flexDirection: "column", gap: 20 } as const;
const cardHead = { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12 } as const;

/**
 * `size` is the axis, and the console uses four of them: 40 for the one
 * promise a screen makes, 28 for a panel, 22 for a card, 20 for a card that
 * has to sit quietly beside another.
 */
export const Sizes = () => (
  <div style={stack}>
    <SerifH as="h1" size={40}>
      The goal is the contract.
    </SerifH>
    <SerifH as="h2" size={28}>
      The board, as a story
    </SerifH>
    <SerifH as="h3" size={22}>
      Finish line
    </SerifH>
    <SerifH as="h3" size={20}>
      Harness
    </SerifH>
  </div>
);

/**
 * A forged tool is named in the heading, so the heading is mono: the serif
 * face is for prose, and `evtx_filter` is an identifier, not a word.
 */
export const AsAToolName = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
    <SerifH as="h3" size={26} className="font-mono">
      evtx_filter
    </SerifH>
    <span className="text-[13px] text-ink-2">
      forged by s2cb903 in minute 6, loaded into all seven sessions within a minute · 31 calls in this run
    </span>
  </div>
);

/** In a card header, with the chip that carries the card's state. */
export const InACardHeader = () => (
  <section className="card" style={{ display: "flex", flexDirection: "column", gap: 10, padding: "18px 20px" }}>
    <div style={cardHead}>
      <SerifH as="h3" size={22}>
        Finish line
      </SerifH>
      <Chip tone="moss">9 of 9 · certified</Chip>
    </div>
    <p className="text-[13px] text-ink-2" style={{ margin: 0, maxWidth: 560 }}>
      <span className="font-mono">work/report.md</span> carries headings <span className="font-mono">## 1.</span> through{" "}
      <span className="font-mono">## Bonus</span>, the words <em>shellcode</em> and <em>hypothesis</em>, a timeline of at least
      40 rows, and <span className="font-mono">inputs/</span> byte-for-byte as handed over.
    </p>
  </section>
);
