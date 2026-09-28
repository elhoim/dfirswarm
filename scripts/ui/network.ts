/**
 * The Network tab (docs/adr/0011): the run's case policy, what waits on the
 * operator (one item per host and lead), every request with its decision
 * and reasons, every grant with its state and time left, every capture and
 * what the fetch service refused, contamination. Read from the run's own
 * files (network/grants.jsonl, network/fetches.jsonl, the sealed captures);
 * the operator's acts run as swarm.sh net, like the CLI's.
 */
import { netListing, type NetListing } from "../net-broker.ts";
import { netLogsExist } from "../net-grants.ts";
import { policyLines, readCasePolicy } from "../case-policy.ts";

export type NetworkPanelView = NetListing & { lines: string[]; now: string };

/** The header's view: the mode, and what waits on the operator. Null for a run whose network is closed and made no request. */
export type NetworkBrief = { mode: string; policy: string; waiting: number; grants_in_force: number; requests: number; chain_ok: boolean; contamination: number };

export async function readNetwork(sandbox: string): Promise<NetworkPanelView> {
  const l = await netListing(sandbox);
  return { ...l, lines: policyLines(l.policy), now: new Date().toISOString() };
}

export async function networkBrief(sandbox: string): Promise<NetworkBrief | null> {
  const policy = readCasePolicy(sandbox);
  if (policy.network === "closed" && !netLogsExist(sandbox)) return null;
  const l = await netListing(sandbox).catch(() => null);
  if (!l) return null;
  return {
    mode: policy.network,
    policy: policy.policy,
    waiting: l.items.filter((it) => !it.closed).length,
    grants_in_force: l.grants.filter((g) => g.status === "granted" || g.status === "active").length,
    requests: l.requests.length,
    chain_ok: l.chain.ok && l.fetch_chain.ok,
    contamination: l.contamination.length,
  };
}
