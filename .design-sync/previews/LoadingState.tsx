import { LoadingState } from "dfirswarm";

/** The trace panel while the run's events are being fetched. */
export const LoadingTheTrace = () => <LoadingState label="Loading the trace" />;

/** `rows` is the shape of what is coming: one row for a single card. */
export const OneRow = () => <LoadingState label="Fetching s2cb903" rows={1} />;

/** A whole panel of rows, for the trace's own long list. */
export const AFullPanel = () => <LoadingState label="Replaying 4,812 events" rows={6} />;
