import { CustodyRecord } from "dfirswarm";

/** Who held what, when, and whether it was still intact at the end. */
export const Intact = () => (
  <div style={{ maxWidth: 620 }}>
    <CustodyRecord
      rows={[
        { label: "Case", value: "CASE-2026-004", mono: true },
        { label: "Examiner", value: "H. Ozturkci" },
        { label: "Tool", value: "DFIR Swarm 0.3.0", mono: true },
        { label: "Run", value: "s2cb9", mono: true },
        { label: "Started", value: "2026-02-11 08:57:14Z", mono: true },
        { label: "Ended", value: "2026-02-11 09:11:44Z", mono: true },
        { label: "Evidence", value: "14 files, 2.1 GB, read-only under fsguard", mono: false },
        { label: "Evidence intact at the end", value: "yes, 14 checked by s2cb900 at 09:11:38Z", tone: "ok" },
        { label: "Network", value: "egress denied except api.anthropic.com" },
        { label: "Ledger", value: "ledger/entries.jsonl, 31 entries", mono: true },
      ]}
    />
  </div>
);

/**
 * The answer that changes how the whole document is read. "Not checked" and
 * "intact" are different answers, and a blank cell reads as the second.
 */
export const EvidenceMoved = () => (
  <div style={{ maxWidth: 620 }}>
    <CustodyRecord
      rows={[
        { label: "Case", value: "CASE-2026-004", mono: true },
        { label: "Run", value: "s2cb9", mono: true },
        { label: "Evidence intact at the end", value: "NO — 1 modified, 0 missing, 0 added", tone: "danger" },
        { label: "Network", value: "egress denied except api.anthropic.com" },
      ]}
    />
  </div>
);

/** A fact nobody recorded is named as missing, in the place the value would have been. */
export const NotRecordedRows = () => (
  <div style={{ maxWidth: 620 }}>
    <CustodyRecord
      rows={[
        { label: "Case", value: "CASE-2026-004", mono: true },
        { label: "Examiner" },
        { label: "Evidence intact at the end", value: "not checked", tone: "warn" },
      ]}
    />
  </div>
);
