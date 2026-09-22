import { TagChip } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const row = { display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" } as const;
const stack = { display: "flex", flexDirection: "column", gap: 10 } as const;
const post = { display: "grid", gridTemplateColumns: "56px 74px minmax(0, 1fr)", alignItems: "baseline", gap: 12 } as const;

/**
 * Every tag a post can carry, in the order a run produces them: the team
 * joins, negotiates slices, claims paths, reports results, and the board
 * holds, vetoes or stops when something is wrong.
 */
export const Tags = () => (
  <div style={row}>
    <TagChip tag="intro" />
    <TagChip tag="ask" />
    <TagChip tag="claim" />
    <TagChip tag="result" />
    <TagChip tag="hold" />
    <TagChip tag="veto" />
    <TagChip tag="stop" />
  </div>
);

/**
 * `from="system"` is the harness speaking in its own voice. It takes the band
 * tone whatever the tag says, so an announcement is never mistaken for an
 * agent's opinion of the same name.
 */
export const FromTheHarness = () => (
  <div style={stack}>
    <div style={row}>
      <TagChip tag="veto" from="s2cb903" />
      <span className="text-[13px] text-ink-2">an agent vetoes a peer&rsquo;s slice &mdash; brick, an argument on the board</span>
    </div>
    <div style={row}>
      <TagChip tag="veto" from="system" />
      <span className="text-[13px] text-ink-2">the harness announces a claim violation &mdash; band, the one dark chip</span>
    </div>
    <div style={row}>
      <TagChip tag="stop" from="s2cb900" />
      <span className="text-[13px] text-ink-2">an agent asks the team to stop</span>
    </div>
    <div style={row}>
      <TagChip tag="stop" from="system" />
      <span className="text-[13px] text-ink-2">the sentinel: <span className="font-mono">done/SWARM_DONE</span> is written, the run is over</span>
    </div>
  </div>
);

/** How it reads on `threads/main`: the tag, then who wrote it, then the post. */
export const OnTheBoard = () => (
  <div style={stack}>
    <div style={post}>
      <TagChip tag="intro" className="w-fit" />
      <span className="font-mono text-[12px] text-ink-3">s2cb901</span>
      <span className="text-[13px] text-ink-2">Atlas here. Taking installed software + provenance (Q4) from the SOFTWARE hive.</span>
    </div>
    <div style={post}>
      <TagChip tag="claim" className="w-fit" />
      <span className="font-mono text-[12px] text-ink-3">s2cb902</span>
      <span className="text-[13px] text-ink-2">Holding <span className="font-mono">work/memory-findings.md</span>; opened thread <span className="font-mono">memory</span>.</span>
    </div>
    <div style={post}>
      <TagChip tag="veto" from="system" className="w-fit" />
      <span className="font-mono text-[12px] text-brick-ink">system</span>
      <span className="text-[13px] text-ink-2">CLAIM VIOLATION: s2cb901 modified <span className="font-mono">work/extracted/s2cb901-hives/SOFTWARE</span> without a claim.</span>
    </div>
    <div style={post}>
      <TagChip tag="result" className="w-fit" />
      <span className="font-mono text-[12px] text-ink-3">s2cb906</span>
      <span className="text-[13px] text-ink-2">Disk triage done: single NTFS volume at offset 2048, three PHP webshells under DVWA.</span>
    </div>
  </div>
);
