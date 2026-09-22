import { ErrorState } from "dfirswarm";

const retry = () => {};

/** A swarm that would not fetch. The message is verbatim, in mono. */
export const TheFetchFailed = () => (
  <ErrorState error="GET /api/swarms/s2cb903 — 502 Bad Gateway" onRetry={retry} />
);

/** `error` takes an Error as readily as a string, and `title` names the panel. */
export const WithItsOwnTitle = () => (
  <ErrorState
    title="The trace stopped short"
    error={new Error("trace/events.jsonl: unexpected end of JSON input at line 4813")}
    onRetry={retry}
  />
);

/** Without `onRetry` there is no button: nothing here is fixed by asking again. */
export const NothingToRetry = () => (
  <ErrorState
    title="Sandbox unreachable"
    error="docker: cannot connect to the daemon at unix:///var/run/docker.sock"
  />
);
