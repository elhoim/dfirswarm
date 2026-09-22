import { Limitation } from "dfirswarm";

const list: React.CSSProperties = { margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 10, maxWidth: 640 };

/**
 * What the run could not establish. A report without these is not a shorter
 * report, it is a report that overclaims.
 */
export const WhatWasNotEstablished = () => (
  <ul style={list}>
    <Limitation>
      The proxy log covering 03:10–03:40 was rotated before collection, so outbound volume in that window is unknown.
    </Limitation>
    <Limitation>
      Work stopped because of the budget: the run spent $7.98 of its $60 cap but hit the 15-minute wall with two agents still
      reading.
    </Limitation>
    <Limitation>
      Three tool calls failed or were refused. Their absence is recorded in the trace but their results are not in this document.
    </Limitation>
  </ul>
);

/** The closing line every report of this kind carries. */
export const TheStandingCaveat = () => (
  <ul style={list}>
    <Limitation>
      This document reports what the swarm recorded. An artefact nobody opened is not evidence of absence, and a question nobody
      asked is not a question with no answer.
    </Limitation>
  </ul>
);
