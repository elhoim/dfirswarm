import { Excerpt } from "dfirswarm";

const LOG = `2026-02-11 03:14:19 10.4.2.31 GET /default.aspx - 443 - 91.219.236.8 200 0 0 62
2026-02-11 03:14:22 10.4.2.31 POST /upload.aspx - 443 - 91.219.236.8 200 0 0 411
2026-02-11 03:14:24 10.4.2.31 GET /uploads/upload.aspx cmd=whoami 443 - 91.219.236.8 200 0 0 51
2026-02-11 03:15:03 10.4.2.31 GET /uploads/upload.aspx cmd=reg+add 443 - 91.219.236.8 200 0 0 48`;

/** A quoted piece of evidence, numbered so a reader can cite a line rather than the block. */
export const Numbered = () => (
  <div style={{ maxWidth: 640 }}>
    <Excerpt text={LOG} startLine={8809} />
  </div>
);

/** The line the finding rests on, marked. Saffron because it is a pointer, not a verdict. */
export const Highlighted = () => (
  <div style={{ maxWidth: 640 }}>
    <Excerpt text={LOG} startLine={8809} highlight={[8810]} />
  </div>
);

/** A long line wraps instead of scrolling: a report is printed, and a scrollbar prints as a truncation. */
export const LongLines = () => (
  <div style={{ maxWidth: 420 }}>
    <Excerpt
      text={'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v IISUpdate /t REG_SZ /d "C:\\Windows\\Temp\\svchost.exe" /f'}
      startLine={1}
    />
  </div>
);
