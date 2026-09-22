import { Verdict } from "dfirswarm";

/** The answer before the evidence for it: a reader who stops here still leaves with the finding and how sure it is. */
export const TheAnswer = () => (
  <div style={{ maxWidth: 660 }}>
    <Verdict
      statement="A web shell was uploaded to the public IIS server on 11 February at 03:14 UTC and used to establish persistence 41 seconds later."
      confidence="high"
    >
      Entry needed no credential. The upload endpoint accepted an unauthenticated POST, which is the defect to fix before the host
      returns to service.
    </Verdict>
  </div>
);

/** Hedged, and readably so, without the palette shouting danger about a careful sentence. */
export const Hedged = () => (
  <div style={{ maxWidth: 660 }}>
    <Verdict
      statement="Data was probably staged for exfiltration, but the window that would prove it was rotated out of the proxy log before collection."
      confidence="low"
    >
      Treat this as unresolved rather than negative. Section 7 says what was not covered.
    </Verdict>
  </div>
);

/** Confidence nobody stated is shown as unstated, not quietly rendered as if it were low. */
export const NoConfidenceStated = () => (
  <div style={{ maxWidth: 660 }}>
    <Verdict statement="The host was compromised through its upload endpoint." />
  </div>
);
