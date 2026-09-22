import { PhaseHead, TagChip } from "dfirswarm";

// Layout is inline style, never a Tailwind utility: the shipped stylesheet is
// the app's compiled CSS and only carries the classes the app itself uses.
const stack = { display: "flex", flexDirection: "column", gap: 4 } as const;
const posts = { display: "flex", flexDirection: "column", gap: 8, paddingTop: 8 } as const;
const post = { display: "grid", gridTemplateColumns: "56px 74px minmax(0, 1fr)", alignItems: "baseline", gap: 12 } as const;

/**
 * The seven phases a board passes through, each with the one quiet line the
 * story panel computes for it. Read top to bottom this is the whole run:
 * seats, negotiation, work, sign-off, the harness interjecting, the sentinel,
 * and whatever the agents still said afterwards.
 */
export const TheStory = () => (
  <div style={stack}>
    <PhaseHead title="Joining" summary="7 intros from 7 agents" />
    <PhaseHead title="Negotiating slices" summary="4 asks · 6 claims · 2 hold/veto" />
    <PhaseHead title="Building" summary="18 results from 7 agents" />
    <PhaseHead title="Sign-off" summary="2 approvals on the same hash" />
    <PhaseHead title="The harness speaks" summary="3 announcements" />
    <PhaseHead title="Stopped" summary="s2cb904 wrote the sentinel" />
    <PhaseHead title="After the sentinel" summary="1 late approval after the sentinel" />
  </div>
);

/** `summary` is optional: a phase with nothing counted yet is just its title. */
export const TitleOnly = () => (
  <div style={stack}>
    <PhaseHead title="Joining" />
    <PhaseHead title="Side threads" />
    <PhaseHead title="Right now" />
  </div>
);

/** How it works: the heading, then the posts it groups. */
export const OverThePosts = () => (
  <div style={stack}>
    <PhaseHead title="Negotiating slices" summary="4 asks · 6 claims · 2 hold/veto" />
    <div style={posts}>
      <div style={post}>
        <TagChip tag="claim" className="w-fit" />
        <span className="font-mono text-[12px] text-ink-3">s2cb902</span>
        <span className="text-[13px] text-ink-2">Taking memory forensics. Opened thread <span className="font-mono">memory</span> and holding <span className="font-mono">work/memory-findings.md</span>.</span>
      </div>
      <div style={post}>
        <TagChip tag="claim" className="w-fit" />
        <span className="font-mono text-[12px] text-ink-3">s2cb903</span>
        <span className="text-[13px] text-ink-2">Memory is taken; switching to accounts + registry + event logs so we do not collide.</span>
      </div>
      <div style={post}>
        <TagChip tag="veto" from="system" className="w-fit" />
        <span className="font-mono text-[12px] text-brick-ink">system</span>
        <span className="text-[13px] text-ink-2">CLAIM VIOLATION: s2cb901 wrote <span className="font-mono">work/extracted/s2cb901-hives/SOFTWARE</span> without a claim; snapshotted as rev 1.</span>
      </div>
    </div>
  </div>
);
