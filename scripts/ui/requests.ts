/**
 * The console's Requests tab (extensions/requests.ts, docs/adr/0014):
 * everything the run asked of a person, each with its durable id and how it
 * stands, the open ones first; the case policy's word on more evidence; the
 * evidence and material added. Read from the run's own files. The
 * operator's acts run as `swarm.sh requests`, so they land on the trace and
 * the operator's record like the CLI's; the server checks their shape only.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import * as R from "../../extensions/requests.ts";
import { readCasePolicy } from "../case-policy.ts";
import { listMaterial } from "../material.ts";

export type RequestsPanelView = {
  brief: R.RequestsBrief;
  chain: R.RequestsState["chain"];
  requests: R.OperatorRequest[];
  more_evidence: string;
  material: Array<Record<string, unknown>>;
  now: string;
};

export async function readRequests(sandbox: string): Promise<RequestsPanelView> {
  const s = await R.requestsSnapshot(sandbox);
  return {
    brief: R.requestsBrief(s),
    chain: s.chain,
    requests: R.requestList(s),
    more_evidence: readCasePolicy(sandbox).more_evidence,
    material: await listMaterial(sandbox).catch(() => []),
    now: new Date().toISOString(),
  };
}

/** The header's badge: open requests by kind; null for a run that asked nothing of the operator. */
export async function requestsBrief(sandbox: string): Promise<R.RequestsBrief | null> {
  if (!existsSync(join(sandbox, R.REQUESTS_LOG))) return null;
  const s = await R.requestsSnapshot(sandbox).catch(() => null);
  return s ? R.requestsBrief(s) : null;
}

export class RequestActionError extends Error {}

export const REQUEST_ACTIONS = ["ack", "answer", "decline", "withdraw", "authorise", "collecting", "unavailable"] as const;
const PERSON = /^[a-z0-9][a-z0-9-]{0,47}$/;

/** A Requests tab act as `swarm.sh requests <id> <sub> …` arguments; the CLI does the real checking. */
export function requestArgv(body: Record<string, unknown>): { sub: string; argv: string[] } {
  const action = String(body.action ?? "");
  if (!(REQUEST_ACTIONS as readonly string[]).includes(action)) throw new RequestActionError(`action is one of ${REQUEST_ACTIONS.join(", ")}`);
  const rid = String(body.request ?? "").trim().toUpperCase();
  if (!R.REQUEST_ID.test(rid)) throw new RequestActionError("request is R-<n>");
  const text = typeof body.text === "string" ? body.text.trim() : "";
  const why = typeof body.why === "string" ? body.why.trim() : "";
  if (text.length > 4000 || why.length > 4000) throw new RequestActionError("an answer or a reason is at most 4000 characters: nothing is cut, so a longer one is refused");
  const as = typeof body.as === "string" ? body.as.trim() : "";
  if (as && !PERSON.test(as)) throw new RequestActionError("as is an enrolled person's id");
  const argv: string[] = [rid];
  if (action === "answer") {
    if (!text) throw new RequestActionError("an answer needs its text");
    argv.push(text);
  } else {
    if ((action === "decline" || action === "withdraw" || action === "unavailable") && !why) throw new RequestActionError(`${action} needs its reason`);
    if (why) argv.push("--why", why);
  }
  if (as) argv.push("--as", as);
  return { sub: action, argv };
}
