/**
 * Offers: first claim on a piece of work for one seat, for a short while.
 *
 * On ctf12 a wake told three parties to claim the same lead at the same
 * moment (the woken seat, the lead's previous holder, and every seat the
 * board announcement reached), and the one with context won by seconds:
 * Belka's woken seat took 16 of its 30 wakes, c09's 4 of 19, and 27 of
 * Belka's 32 refused claims were "held by X, worked N s ago" within 15 s of a
 * wake or a reopen. Here a wake is an offer: the seat it names has first
 * claim for OFFER_TTL (60 s, three times the slowest accept measured on
 * ctf12) counted from when the offer reached it, never longer than the
 * offer's whole age bound from when it was made. It is accepted (the seat
 * claims the lead, or takes up the question), declined (it passes on at
 * once), invalidated by any change to what it offers (the lead's or the
 * question's revision), or it lapses. Everything is derived from events on
 * the registers' chains and their times, so a hub that restarts in the
 * middle of an offer finds it where it was.
 *
 * One mechanism for both registers: a lead's offers are events of the lead
 * register (a wake, a hand-off, a parked lead, a reopen after the operator's
 * note, a closure to confirm), a question's are events of the question
 * register (the asker's suggested seat first, then the most suited idle
 * seat). This module holds the timings and the state machine; each register
 * keeps its own events. Nothing here knows a case.
 */

/** Whole seconds from the environment, in milliseconds, or the default. */
function envMs(name: string, dfltSec: number): number {
  const raw = process.env[name]?.trim();
  const n = raw && /^\d+$/.test(raw) ? Number(raw) : dfltSec;
  return n * 1000;
}

/** How long an offer's first claim lasts once it reached its seat (SWARM_OFFER_SEC, 60). */
export function offerTtlMs(): number {
  return envMs("SWARM_OFFER_SEC", 60);
}

/** The most an offer may live from when it was made, delivered or not (SWARM_OFFER_MAX_SEC, 300). */
export function offerMaxAgeMs(): number {
  return Math.max(offerTtlMs(), envMs("SWARM_OFFER_MAX_SEC", 300));
}

/**
 * How long a review's offer stays its seat's once the seat took it (offer
 * accept): a review takes minutes, not the first claim's seconds
 * (SWARM_REVIEW_HOLD_SEC, 600). The c10 pilot's review offers ran out
 * sixty seconds after delivery while the seat that took them worked, and
 * went to the next seat, which did the same review again or declined it.
 */
export function reviewHoldMs(): number {
  return Math.max(offerTtlMs(), envMs("SWARM_REVIEW_HOLD_SEC", 600));
}

/** What an offer is for: work nobody holds (wake), a hand-off, a parked lead, a reopen after the operator's note, a closure to confirm, a question, a limiting route's review, a material negative's review. */
export const OFFER_REASONS = ["wake", "handoff", "parked", "reopen", "confirm", "question", "route_review", "negative_review"] as const;
export type OfferReason = (typeof OFFER_REASONS)[number];

/** An offer as a register folds it from its events. */
export type Offer = {
  /** The seq of the event that made it (its id within its register). */
  seq: number;
  at: string;
  to: string;
  /** The revision of what it offers when it was made: any change since invalidates it. */
  rev: number;
  reason: OfferReason;
  /** When it reached its seat (the seat's wait or header delivered it). */
  seen_at: string | null;
  declined: { at: string; why: string } | null;
  accepted: { at: string } | null;
  /** A lapse the register wrote down (the state is derived from the times; this is the record). */
  lapsed_at: string | null;
  /** An older offer's own bound (a question offer made before offers were counted from delivery). */
  until?: string | null;
  /** The seat that held the work when it was offered (a parked lead, a hand-off). */
  from?: string;
  /** A review's offer: the answers its item was offered for (a route review is bound to them). */
  basis?: string;
  /** A confirmation's batch: the correction chain's head it follows (one offer per seat and batch, confirmed at once). */
  batch?: string;
  /** A review's offer its seat took (offer accept): its first claim holds until then, for the review itself (reviewHoldMs). */
  held_until?: string | null;
  /** Withdrawn by the register: what it offered needs nothing any more (reviewed by another route, superseded), and why. */
  withdrawn?: { at: string; why: string } | null;
};

export type OfferState = "pending" | "live" | "accepted" | "declined" | "withdrawn" | "lapsed" | "invalidated";

/**
 * Where an offer stands at `now`, against the revision of what it offers:
 * pending (made, not yet delivered: first claim is the seat's, until its age
 * bound), live (delivered: first claim until OFFER_TTL after delivery, and
 * never past the age bound; a review's offer its seat took holds until
 * its hold ends), accepted, declined, withdrawn (what it offered needs
 * nothing any more), lapsed, or invalidated (what it offers changed
 * since). `until` is when its first claim ends.
 */
export function offerStatus(o: Offer, now: number, rev: number): { state: OfferState; until: number } {
  const made = Date.parse(o.at);
  const bound = o.until && !o.seen_at ? Math.min(Date.parse(o.until), made + offerMaxAgeMs()) : made + offerMaxAgeMs();
  const first = o.seen_at ? Math.min(Date.parse(o.seen_at) + offerTtlMs(), bound) : bound;
  const until = o.held_until ? Math.max(first, Date.parse(o.held_until)) : first;
  if (o.accepted) return { state: "accepted", until };
  if (o.declined) return { state: "declined", until };
  if (o.withdrawn) return { state: "withdrawn", until };
  if (o.rev !== rev) return { state: "invalidated", until };
  if (o.lapsed_at || now >= until) return { state: "lapsed", until };
  return { state: o.seen_at ? "live" : "pending", until };
}

/** Whether an offer holds its work for its seat now: made or delivered, not yet ended. */
export function reserving(o: Offer, now: number, rev: number): boolean {
  const s = offerStatus(o, now, rev).state;
  return s === "pending" || s === "live";
}

/** The offer that holds the work now, if any (the newest that still reserves it). */
export function reservingOffer(offers: Offer[], now: number, rev: number): Offer | null {
  for (let i = offers.length - 1; i >= 0; i--) if (reserving(offers[i], now, rev)) return offers[i];
  return null;
}

/** When an offer's first claim ends, in words. */
export function untilWords(o: Offer, now: number, rev: number): string {
  const { state, until } = offerStatus(o, now, rev);
  const secs = Math.max(0, Math.round((until - now) / 1000));
  if (o.held_until && state === "live") return `yours for ${secs} s more (until ${new Date(until).toISOString()})`;
  return state === "pending" ? `until it reaches ${o.to} and ${Math.round(offerTtlMs() / 1000)} s after, at most until ${new Date(until).toISOString()}` : `for ${secs} s more (until ${new Date(until).toISOString()})`;
}
