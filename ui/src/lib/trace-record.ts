/**
 * The marker an *archived* trace line carries when the harness of the day
 * clipped an argument.
 *
 * Nothing writes it any more: the trace keeps every argument and every
 * result whole (extensions/protocol.ts `summarizeArgs`). Runs recorded under
 * the old limits (80, 2,000, then 20,000 characters) still carry it, and the
 * console still says "the record holds an opening" for those. It mirrors
 * `ARG_TRUNCATED_KEY` in the protocol; the console cannot import the
 * extension (it runs in a browser), so the constant is stated here and
 * checked against the harness's in tests/trace-record.test.ts.
 */
export const ARG_TRUNCATED_KEY = "_truncated";
