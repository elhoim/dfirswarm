#!/usr/bin/env node
/**
 * The lead register from outside the panes: the operator's side of it and
 * the watchdog's (extensions/leads.ts).
 *
 *   leads-cli.ts list <sandbox> [--json]            every lead, the operator's requests first
 *   leads-cli.ts note <sandbox> <L-n> <text> [--allow-host HOST]
 *                                                   the operator's answer: recorded on the lead,
 *                                                   the lead reopened, a host allowed for jobs
 *   leads-cli.ts reopen <sandbox> <L-n> [why]       the operator reopens a closed lead
 *   leads-cli.ts nudge-line <sandbox> <agent>       one line for the idle watchdog's nudge
 *
 * swarm.sh lead <run> list|note|reopen calls this with the run's sandbox,
 * puts the operator's act on the trace and the operator's record, and posts
 * the note to the board as the examiner.
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";

function words(v: L.LeadView): string {
  const needs = v.needs.length ? ` needs ${v.needs.map((n) => `${n.need}${n.met ? " (met)" : ` (unmet: ${n.why})`}`).join(", ")}` : "";
  const held = v.holder ? ` held by ${v.holder} (generation ${v.generation})` : "";
  const ended = v.disposition ? ` closed ${v.disposition} by ${v.closed_by}: ${v.ref}` : "";
  const notes = v.notes.length ? ` operator notes: ${v.notes.map((n) => n.text).join(" | ")}` : "";
  return `${v.id} [${v.status}${v.material ? "" : ", not material"}] ${v.title}${held}${needs}${ended}${v.stale ? ` STALE since ${v.stale.at}` : ""}${notes}\n    why: ${v.why}`;
}

/** Every lead, the ones waiting on the operator first, as a reader in a terminal takes them. */
export async function listText(sandbox: string): Promise<string> {
  const snap = await L.leadsSnapshot(sandbox);
  const ranked = L.rankedLeads(snap);
  const lines: string[] = [];
  lines.push(`${ranked.length} lead(s); chain ${snap.state.chain.ok ? `intact, ${snap.state.events.length} events` : `BROKEN at line ${snap.state.chain.broken_at} (${snap.state.chain.reason})`}.`);
  const waiting = ranked.filter((v) => v.disposition === "needs_operator");
  if (waiting.length) {
    lines.push("", "WAITING ON THE OPERATOR:");
    for (const v of waiting) {
      lines.push(`  ${v.id} ${v.title} (closed by ${v.closed_by} at ${v.closed_at})`, `    asks: ${v.ref}`);
      lines.push(`    answer: swarm.sh lead <run> note ${v.id} "<your answer>" [--allow-host HOST]`);
    }
  }
  for (const [name, st] of [["ACTIVE", "active"], ["BLOCKED", "blocked"], ["OPEN", "open"], ["CLOSED", "closed"]] as const) {
    const list = ranked.filter((v) => v.status === st && v.disposition !== "needs_operator");
    if (!list.length) continue;
    lines.push("", `${name}:`);
    for (const v of list) lines.push(`  ${words(v)}`);
  }
  const cov = L.questionCoverage(snap);
  if (snap.goal.questions.length) lines.push("", `Questions: ${snap.goal.questions.length}; without an answer: ${cov.unanswered.map((q) => `question:${q}`).join(", ") || "none"}; of those, held by no lead: ${cov.uncovered.map((q) => `question:${q}`).join(", ") || "none"}.`);
  return `${lines.join("\n")}\n`;
}

/**
 * The idle watchdog's line for an agent it nudges: the top question nobody
 * covers, or the ready lead the register ranks first, and the jobs awaiting
 * the agent's interpretation. Empty when there is nothing to name.
 */
export async function nudgeLine(sandbox: string, agent: string): Promise<string> {
  const snap = await L.leadsSnapshot(sandbox);
  const ranked = L.rankedLeads(snap);
  const cov = L.questionCoverage(snap);
  const parts: string[] = [];
  const mine = ranked.filter((v) => v.holder === agent && v.status !== "closed");
  if (mine.length) parts.push(`You hold ${mine.map((v) => `${v.id} (${v.status})`).join(", ")}: go on with it, or lead_release it with why.`);
  const ready = ranked.find((v) => v.status === "open");
  if (ready) parts.push(`The ready lead the register ranks first is ${ready.id} "${ready.title}"${ready.priority ? ` (${ready.priority} waiting on it)` : ""}: lead_claim ${ready.id}.`);
  if (cov.uncovered.length) parts.push(`Question${cov.uncovered.length === 1 ? "" : "s"} nobody holds a lead for: ${cov.uncovered.map((q) => `question:${q}${cov.open_leads_for[q] ? ` (open: ${cov.open_leads_for[q].join(", ")})` : ""}`).join(", ")}.`);
  const awaiting = (await L.awaitingInterpretation(sandbox, snap.state, snap.jobs)).filter((a) => a.agent === agent);
  if (awaiting.length) parts.push(`Jobs of yours awaiting interpretation: ${awaiting.map((a) => `${a.job}${a.unread_bytes ? ` (${a.unread_bytes} bytes unread)` : ""}`).join(", ")}: record what each shows with interprets.`);
  return parts.join(" ");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, sandboxArg, ...rest] = process.argv.slice(2);
  const usage = () => {
    process.stderr.write("usage: leads-cli.ts list|note|reopen|nudge-line <sandbox> ...\n");
    process.exit(2);
  };
  if (!cmd || !sandboxArg) usage();
  const sandbox = resolve(sandboxArg);
  const opt = (name: string) => {
    const i = rest.indexOf(name);
    if (i < 0) return undefined;
    const v = rest[i + 1];
    rest.splice(i, 2);
    return v;
  };
  switch (cmd) {
    case "list": {
      if (rest.includes("--json")) {
        const snap = await L.leadsSnapshot(sandbox);
        process.stdout.write(`${JSON.stringify({ leads: L.rankedLeads(snap), chain: snap.state.chain, coverage: L.questionCoverage(snap) }, null, 2)}\n`);
      } else process.stdout.write(await listText(sandbox));
      break;
    }
    case "note": {
      const host = opt("--allow-host");
      const [lead, ...text] = rest;
      if (!lead || !text.length) usage();
      // Who had the lead last, for the board post: the holder, or the agent that closed it.
      const before = (await L.leadsSnapshot(sandbox)).state.leads.get(String(lead).toUpperCase());
      const to = before?.holder ?? before?.closed?.by ?? "all";
      const r = await L.noteLead(sandbox, lead, text.join(" "), { ...(host ? { allowHost: host } : {}) });
      process.stdout.write(`${JSON.stringify({ ...r, to })}\n`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case "reopen": {
      const [lead, ...why] = rest;
      if (!lead) usage();
      const r = await L.reopenLead(sandbox, lead, "operator", why.join(" ") || "the operator reopened it", "operator");
      process.stdout.write(`${JSON.stringify(r)}\n`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case "nudge-line": {
      const [agent] = rest;
      if (!agent) usage();
      process.stdout.write(`${await nudgeLine(sandbox, agent).catch(() => "")}\n`);
      break;
    }
    default:
      usage();
  }
}
