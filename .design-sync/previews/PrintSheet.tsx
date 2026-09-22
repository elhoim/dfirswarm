import { PrintSheet, SerifH } from "dfirswarm";

/**
 * A frame at A4 proportions, so the console can show what the PDF will be
 * before anyone commits to printing it. It is sized by height, because a page
 * is read top to bottom.
 */
export const Sheet = () => (
  <PrintSheet height="420px">
    <div style={{ padding: 28, fontFamily: "var(--font-sans)", color: "var(--color-ink)" }}>
      <SerifH as="h2" size={26}>Forensic report</SerifH>
      <p style={{ fontSize: 13, color: "var(--color-ink-2)", marginTop: 4 }}>CASE-2026-004 · run s7a1c</p>
      <hr style={{ border: 0, borderTop: "1px solid var(--color-line)", margin: "18px 0" }} />
      <p style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--color-ink-2)" }}>
        Entry was an unauthenticated upload to /upload.aspx, not a stolen credential.
      </p>
    </div>
  </PrintSheet>
);
