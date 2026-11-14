/**
 * A value read from the hub before every model call, served within a deadline.
 *
 * The seat's `context` hook reads the budget twice and the sentinel once
 * before each model call. With a hub that is busy those three round trips
 * were the longest wait of the run: 136, 158 and 181 seat-minutes in the runs
 * s01a4f4, s17fdfe and s5d814f, against 2.4 in a run whose hub was free,
 * while the model's own latency did not move. A read that does not answer
 * within the deadline gives the last value it did answer with, and goes on
 * in the background so the next call has a newer one. Only a first read,
 * with nothing known yet, is waited for whole.
 *
 * The reads before one call share one deadline: the caller starts them
 * together and gives each what is left of it (`read(fn, waitMs)`), so a held
 * hub costs a call the deadline once, not once a read (three reads one after
 * another, each with its own 1.5 s, held a call 4.5 s). And a read that has
 * already outlived a deadline is not waited on again while it is still in
 * flight: the hub is known to be slow, and every call until it answers goes
 * out at once on the last value.
 */
export type LastKnown<T> = { read(fn: () => Promise<T>, waitMs?: number): Promise<T>; age(): number | null; stale(): number };

export function lastKnown<T>(deadlineMs: number, now: () => number = Date.now): LastKnown<T> {
  let known: { value: T; at: number } | null = null;
  let flying: Promise<void> | null = null;
  /** The read in flight has outlived a deadline already. */
  let late = false;
  let failed: unknown = null;
  let staleServed = 0;
  return {
    async read(fn, waitMs = deadlineMs) {
      if (!flying) {
        failed = null;
        late = false;
        flying = fn()
          .then((value) => {
            known = { value, at: now() };
          })
          .catch((err) => {
            failed = err ?? new Error("read failed");
          })
          .finally(() => {
            flying = null;
          });
      }
      const mine = flying;
      if (!known) {
        await mine;
        if (known) return (known as { value: T }).value;
        throw failed ?? new Error("read failed");
      }
      if (late || waitMs <= 0) {
        staleServed += 1;
        return known.value;
      }
      let timer: ReturnType<typeof setTimeout> | undefined;
      const inTime = await Promise.race([mine.then(() => true), new Promise<boolean>((r) => (timer = setTimeout(() => r(false), waitMs)))]);
      if (timer) clearTimeout(timer);
      if (!inTime) {
        staleServed += 1;
        if (flying === mine) late = true;
      }
      return known.value;
    },
    age: () => (known ? now() - known.at : null),
    stale: () => staleServed,
  };
}
