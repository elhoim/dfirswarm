#!/usr/bin/env node
/**
 * The dynamic network from the operator's side (docs/adr/0011): what was
 * asked and decided, and the operator's acts on it. swarm.sh net <run> calls
 * this with the run's sandbox, puts each act on the trace and the operator's
 * record, and posts its text to whoever asked.
 *
 *   net-cli.ts list <sandbox> [--json]
 *   net-cli.ts grant <sandbox> NR-<n> --why TEXT [--no-jobs]
 *   net-cli.ts grant <sandbox> --socket HOST[:PORT] [--lead L-<n>] --why TEXT [--no-jobs]
 *   net-cli.ts deny <sandbox> NI-<m>|NR-<n> --why TEXT
 *   net-cli.ts revoke <sandbox> N-<k> --why TEXT
 *
 * An act prints one JSON line: {ok, text, grant?, to?} or {ok: false, reason},
 * and exits 0 or 2.
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { policyLines } from "./case-policy.ts";
import { netListing, operatorDeny, operatorGrant, operatorRevoke, operatorSocket, type NetListing } from "./net-broker.ts";

/** The listing as a reader in a terminal takes it: what waits on the operator first. */
export function listText(l: NetListing): string {
  const out: string[] = [];
  out.push(...policyLines(l.policy));
  out.push(`Fetch service: ${l.service.port ? `port ${l.service.port}` : "none"}${l.service.keyed.length ? `; keyed adapters: ${l.service.keyed.join(", ")}` : ""}.`);
  out.push(`Chains: grants ${l.chain.ok ? `intact, ${l.chain.events} events` : `BROKEN at line ${l.chain.broken_at} (${l.chain.reason})`}; fetches ${l.fetch_chain.ok ? `intact, ${l.fetch_chain.events} events` : `BROKEN at line ${l.fetch_chain.broken_at} (${l.fetch_chain.reason})`}.`);
  const open = l.items.filter((it) => !it.closed);
  if (open.length) {
    out.push("", "WAITING ON THE OPERATOR:");
    for (const it of open) {
      out.push(`  ${it.id} ${it.host}${it.lead ? ` for ${it.lead}` : ""}: ${it.requests.join(", ")} (opened by ${it.opened_by} at ${it.opened_at})`);
      out.push(`    refused: ${it.reasons.map((r) => `${r.code}: ${r.detail}`).join("; ")}`);
      out.push(`    answer: swarm.sh net <run> grant ${it.requests.at(-1)} --why TEXT | swarm.sh net <run> deny ${it.id} --why TEXT`);
    }
  }
  if (l.grants.length) {
    out.push("", "GRANTS:");
    for (const g of l.grants) {
      out.push(`  ${g.id} [${g.status}${g.status_why ? `: ${g.status_why}` : ""}] ${g.type === "socket" ? `socket ${g.host}:${g.port} (tier 2: host and port only, no content capture)` : `${g.method} ${g.url}`} for ${g.bound ? `job ${g.bound}` : g.principal}${g.lead ? ` on ${g.lead}` : ""}; by ${g.granted_by}${g.why ? ` (${g.why})` : ""}${g.waived.length ? `, waiving ${g.waived.join(", ")}` : ""}; ${g.max_requests === null ? "no count" : `${g.uses} of ${g.max_requests} used`}${g.expires_at ? `, until ${g.expires_at}` : ", for the run"}`);
    }
  }
  if (l.requests.length) {
    out.push("", "REQUESTS:");
    for (const r of l.requests) {
      out.push(`  ${r.id} ${r.at} ${r.principal}${r.lead ? ` ${r.lead}` : ""} ${r.type === "socket" ? `socket ${r.host}` : r.adapter ? `${r.adapter} (${r.url ?? r.host})` : r.url ?? r.host ?? ""}: ${r.decision ?? "undecided"}${r.decided_by ? ` by ${r.decided_by}` : ""}${r.grant ? ` as ${r.grant}` : ""}${r.item ? ` (item ${r.item})` : ""}${r.why ? ` — ${r.why}` : ""}`);
      if (r.reasons.length) out.push(`    reasons: ${r.reasons.map((x) => `${x.code} [${x.rule}${x.overridable ? "" : ", not overridable"}]: ${x.detail}`).join("; ")}`);
      out.push(`    purpose: ${r.purpose}${r.evidence.length ? `; evidence: ${r.evidence.join(", ")}` : ""}`);
    }
  }
  if (l.captures.length) {
    out.push("", "CAPTURES:");
    for (const c of l.captures) out.push(`  ${c.capture} ${c.at} ${c.method} ${c.url} for ${c.principal}: ${c.refused ? `refused (${c.refused})` : c.error ? `failed (${c.error})` : `${c.status}, ${c.bytes} bytes${c.sha256 ? `, sha256 ${c.sha256}` : ""}`}${c.complete ? "" : ", incomplete"}${c.delivered ? "" : ", not delivered"}`);
  }
  if (l.refusals.length) {
    out.push("", `USES THE FETCH SERVICE REFUSED (${l.refusals.length}):`);
    for (const r of l.refusals) out.push(`  ${r.at} ${r.principal} ${r.grant ?? ""}: ${r.code}: ${r.detail}`);
  }
  if (l.contamination.length) {
    out.push("", "CONTAMINATION:");
    for (const c of l.contamination) out.push(`  ${c.at} ${c.capture ?? c.grant ?? ""}: ${c.what} (${c.category ?? "recorded"}): ${c.why}`);
  }
  if (!l.requests.length && !l.grants.length) out.push("", "No request yet.");
  return `${out.join("\n")}\n`;
}

async function main(argv: string[]): Promise<void> {
  const [cmd, sandbox, ...rest] = argv;
  const opt = (name: string) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const say = (r: { ok: boolean }) => {
    process.stdout.write(`${JSON.stringify(r)}\n`);
    process.exit(r.ok ? 0 : 2);
  };
  if (!cmd || !sandbox) {
    process.stderr.write("net-cli: usage: net-cli.ts list|grant|deny|revoke <sandbox> …\n");
    process.exit(2);
  }
  const S = resolve(sandbox);
  const jobs = !rest.includes("--no-jobs");
  const why = opt("--why") ?? "";
  const positional = rest.find((a, i) => !a.startsWith("--") && !(i > 0 && rest[i - 1].startsWith("--") && !["--no-jobs", "--json"].includes(rest[i - 1])));
  switch (cmd) {
    case "list": {
      const l = await netListing(S);
      process.stdout.write(rest.includes("--json") ? `${JSON.stringify(l, null, 2)}\n` : listText(l));
      return;
    }
    case "grant": {
      const socket = opt("--socket");
      if (socket) return say(await operatorSocket(S, { host: socket, ...(opt("--lead") ? { lead: opt("--lead") } : {}), why }, { jobs }));
      if (!positional) return say({ ok: false, reason: "grant names a request (NR-<n>), or --socket HOST[:PORT]" } as { ok: boolean });
      return say(await operatorGrant(S, positional, why, { jobs }));
    }
    case "deny":
      if (!positional) return say({ ok: false, reason: "deny names an item (NI-<m>) or a request (NR-<n>)" } as { ok: boolean });
      return say(await operatorDeny(S, positional, why));
    case "revoke":
      if (!positional) return say({ ok: false, reason: "revoke names a grant (N-<k>)" } as { ok: boolean });
      return say(await operatorRevoke(S, positional, why));
    default:
      process.stderr.write(`net-cli: unknown command ${cmd}\n`);
      process.exit(2);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: err instanceof Error ? err.message : String(err) })}\n`);
    process.exit(2);
  });
}
