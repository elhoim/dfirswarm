import { Exhibit, Excerpt } from "dfirswarm";

const LOG = `2026-02-11 03:14:19 10.4.2.31 GET /default.aspx - 443 - 91.219.236.8 200 0 0 62
2026-02-11 03:14:22 10.4.2.31 POST /upload.aspx - 443 - 91.219.236.8 200 0 0 411
2026-02-11 03:14:24 10.4.2.31 GET /uploads/upload.aspx cmd=whoami 443 - 91.219.236.8 200 0 0 51`;

/** The evidence itself, framed, numbered, and carrying the line that says where it came from. */
export const WithAnExcerpt = () => (
  <div style={{ maxWidth: 660 }}>
    <Exhibit
      seq={9}
      caption="The upload that became the shell"
      source="inputs/logs/u_ex260211.log"
      evidence="lines 8809–8811, sha256 86abc66f0e8a…"
    >
      <Excerpt text={LOG} startLine={8809} highlight={[8810]} />
    </Exhibit>
  </div>
);

/** An exhibit can hold anything a reader needs to see, not only text. */
export const WithFacts = () => (
  <div style={{ maxWidth: 660 }}>
    <Exhibit seq={12} caption="Persistence, as written" source="work/extracted/SOFTWARE" evidence="inode 33194-128-4">
      <dl style={{ margin: 0, display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 16px", fontSize: 12.5 }}>
        <dt className="label-caps">Key</dt>
        <dd style={{ margin: 0, fontFamily: "var(--font-mono)", color: "var(--color-ink)" }}>{"…\\CurrentVersion\\Run\\IISUpdate"}</dd>
        <dt className="label-caps">Value</dt>
        <dd style={{ margin: 0, fontFamily: "var(--font-mono)", color: "var(--color-ink)" }}>{"C:\\Windows\\Temp\\svchost.exe"}</dd>
        <dt className="label-caps">Written</dt>
        <dd style={{ margin: 0, fontFamily: "var(--font-mono)", color: "var(--color-ink)" }}>2026-02-11 03:15:03Z</dd>
      </dl>
    </Exhibit>
  </div>
);

/** An exhibit whose provenance is incomplete still says so, in the caption where a reader looks first. */
export const Uncited = () => (
  <div style={{ maxWidth: 660 }}>
    <Exhibit seq={31} caption="Screenshot supplied by the site team" source="inputs/handover/screen.png">
      <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: "var(--color-ink-2)" }}>
        No hash was recorded at handover, so this exhibit shows what was received and not that it is what was captured.
      </p>
    </Exhibit>
  </div>
);
