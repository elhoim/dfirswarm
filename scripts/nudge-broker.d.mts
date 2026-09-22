/**
 * Types for the broker's two decisions, so a `.ts` test can import them.
 *
 * The broker itself stays plain ESM: `swarm.sh` runs it with `node` directly,
 * with no build step between the file on disk and the process that answers
 * the panes.
 */
export declare const NUDGE_SOCKET_REL: string;
export declare const MESSAGES: Record<string, string>;
export declare function resolvePeer(
  roster: string[],
  peer: string,
  sender?: string,
): { ok: true } | { ok: false; error: string };
export declare function claimHolds(sandbox: string, kind: string): boolean;
export declare function messageFor(kind: string): string;
