#!/usr/bin/env node
/**
 * The operator requests from the operator's side (extensions/requests.ts,
 * docs/adr/0014): what the run asked of a person, each with its durable id,
 * and the acts on it. `swarm.sh requests` runs it, and the console's
 * Requests tab through it.
 *
 *   requests-cli.ts list <sandbox> [--json] [--open]
 *   requests-cli.ts show <sandbox> R-n [--json]
 *   requests-cli.ts route <sandbox> R-n            how its answer is given (swarm.sh reads it)
 *   requests-cli.ts ack <sandbox> R-n [--why W] [--as ID]
 *   requests-cli.ts answer <sandbox> R-n TEXT [--as ID]   a decision's answer (a lead's and a
 *                                                   clarification's are given on the lead and the question)
 *   requests-cli.ts decline <sandbox> R-n --why W [--as ID]
 *   requests-cli.ts withdraw <sandbox> R-n --why W [--as ID]
 *   requests-cli.ts authorise|collecting|unavailable <sandbox> R-n [--why W] [--as ID]
 *                                                   an acquisition's stages (evidence add makes it received and validated)
 *   requests-cli.ts fire <sandbox> [--runs DIR]     reconcile and deliver: the watchdog's fallback where no hub runs
 *
 * An act takes `--hub-admin SOCKET` when the run's hub runs: the hub admits
 * it (it writes the chain while it runs), as it admits the question
 * register's acts; with no hub it is made here. Either way the act is its
 * event on the chain, and what it says on the board is derived from that
 * event, once (publishRequestActs), so a post that fails after the commit is
 * made at the next round. An act prints one JSON line once the chain holds
 * it.
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";

function parse(rest: string[]): { pos: string[]; opts: Map<string, string>; flags: Set<string> } {
  const valued = new Set(["--why", "--as", "--runs", "--via", "--hub-admin"]);
  const pos: string[] = [];
  const opts = new Map<string, string>();
  const flags = new Set<string>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valued.has(a)) {
      opts.set(a, rest[i + 1] ?? "");
      i += 1;
    } else if (a.startsWith("--")) flags.add(a);
    else pos.push(a);
  }
  return { pos, opts, flags };
}

function emit(r: Record<string, unknown>): never {
  process.stdout.write(`${JSON.stringify(r)}\n`);
  process.exit(r.ok === false ? 1 : 0);
}

/** One request in words: its id, kind, state, who asked and what, and how it is answered. */
export function requestText(r: R.OperatorRequest): string {
  const l = r.line;
  const out: string[] = [];
  out.push(`${r.rid} [${r.kind}, ${r.state}${r.stage ? `, stage ${r.stage}` : ""}] from ${r.by} at ${r.at}${r.lead ? ` on ${r.lead}` : ""}${typeof l.q === "string" ? ` on ${l.q}` : ""}${r.questions.length ? `; questions ${r.questions.join(", ")}` : ""}`);
  if (l.title) out.push(`    ${String(l.title)}`);
  if (l.request) out.push(`    asks: ${String(l.request)}`);
  if (r.ask) {
    out.push(`    source: ${r.ask.source}`, `    where: ${r.ask.where}`, `    would establish: ${r.ask.expected_value}`, `    urgency: ${r.ask.urgency}${r.ask.owner ? `; held by ${r.ask.owner}` : ""}${r.ask.authority_needed ? `; authority needed: ${r.ask.authority_needed}` : ""}`);
  }
  if (r.closed) out.push(`    ${r.closed.ev} by ${r.closed.by} at ${r.closed.at}: ${r.closed.text}`);
  else if (l.answer) out.push(`    answer: ${String(l.answer)}`);
  for (const h of r.history.slice(1)) if (h.ev !== "answered" && h.ev !== "declined" && h.ev !== "withdrawn") out.push(`    ${h.at} ${h.ev}${h.stage ? ` ${h.stage}` : ""} by ${h.by}${h.targets ? ` (${h.targets.join(", ")})` : ""}${h.why ? `: ${h.why}` : ""}`);
  return out.join("\n");
}

/** Every request, open ones first. */
export function listText(s: R.RequestsState, openOnly = false): string {
  const list = R.requestList(s).filter((r) => !openOnly || R.isOpen(r));
  const b = R.requestsBrief(s);
  const head = `${b.total} request(s), ${b.open} open${b.open ? ` (${Object.entries(b.by_kind).map(([k, n]) => `${n} ${k}`).join(", ")})` : ""}; chain ${s.chain.ok ? "intact" : `BROKEN at line ${s.chain.broken_at} (${s.chain.reason})`}.`;
  if (!list.length) return `${head}\nNothing ${openOnly ? "open " : ""}was asked of the operator.\n`;
  const open = list.filter(R.isOpen);
  const closed = list.filter((r) => !R.isOpen(r));
  return `${head}\n${open.length ? `\nWAITING ON THE OPERATOR:\n${open.map(requestText).join("\n")}\n` : ""}${closed.length ? `\nCLOSED:\n${closed.map(requestText).join("\n")}\n` : ""}`;
}

/**
 * An operator's act on a request, where the chain is written (the hub while
 * it runs, else here): the act committed, then said on the board from its
 * event; a post that fails is named, and made at the next round.
 */
export async function admitRequestAct(sandbox: string, rid: unknown, a: Parameters<typeof R.requestAct>[2]): Promise<Record<string, unknown>> {
  const r = await R.requestAct(sandbox, rid, a);
  if (!r.ok) return r;
  const posted = await R.publishRequestActs(sandbox).catch((err: Error) => ({ error: err.message }));
  const mine = Array.isArray(posted) ? posted.find((p) => r.events.includes(p.seq)) : undefined;
  return { ...r, ...(mine ? { post: mine.post } : { post_pending: Array.isArray(posted) ? "said on the board already" : `the board post failed (${(posted as { error: string }).error}); it is made at the next round` }) };
}

async function main(argv: string[]): Promise<void> {
  const [cmd, sandboxArg, ...rest] = argv;
  if (!cmd || !sandboxArg) {
    process.stderr.write("usage: requests-cli.ts list|show|route|ack|answer|decline|withdraw|authorise|collecting|unavailable|fire <sandbox> ...\n");
    process.exit(2);
  }
  const S = resolve(sandboxArg);
  const { pos, opts, flags } = parse(rest);
  const who = async (): Promise<string> => {
    const QC = await import("./questions-cli.ts");
    const a = QC.actorFor({ ...(opts.get("--as") ? { as: opts.get("--as") } : {}), via: opts.get("--via") === "console" ? "console" : "cli" });
    if ("why" in a) emit({ ok: false, reason: a.why });
    return Q.originWords(Q.originOf((a as { actor: Q.Actor }).actor));
  };
  // Every read reconciles first: what is committed elsewhere and not written yet is written now.
  if (cmd !== "fire") await R.reconcileRequests(S).catch(() => undefined);
  // An act: admitted by the hub when it runs, else here; its board post derived from its event.
  const act = async (rid: string | undefined, a: Parameters<typeof R.requestAct>[2]): Promise<never> => {
    const QC = await import("./questions-cli.ts");
    emit(await QC.admit(S, opts.get("--hub-admin"), { op: "request_act", rid, act: { ...a, announce: true } }, () => admitRequestAct(S, rid, { ...a, announce: true })));
  };
  switch (cmd) {
    case "list": {
      const s = await R.requestsSnapshot(S);
      if (flags.has("--json")) emit({ ok: true, brief: R.requestsBrief(s), chain: s.chain, requests: R.requestList(s).filter((r) => !flags.has("--open") || R.isOpen(r)) });
      process.stdout.write(listText(s, flags.has("--open")));
      return;
    }
    case "show":
    case "route": {
      const id = pos[0];
      if (!id) emit({ ok: false, reason: `${cmd} needs R-<n>` });
      const s = await R.requestsSnapshot(S);
      const m = /^R-?([1-9]\d{0,6})$/i.exec(String(id).trim());
      const r = m ? s.requests.get(`R-${Number(m[1])}`) : undefined;
      if (!r) emit({ ok: false, reason: `${id} is not a request of this run` });
      const req = r as R.OperatorRequest;
      if (cmd === "route") emit({ ok: true, rid: req.rid, kind: req.kind, state: req.state, stage: req.stage, lead: req.lead, q: req.line.q ?? null, id: req.line.id ?? null, item: req.line.item ?? null, by: req.by });
      if (flags.has("--json")) emit({ ok: true, request: req });
      process.stdout.write(`${requestText(req)}\n`);
      return;
    }
    case "ack":
      await act(pos[0], { ev: "acknowledged", by: await who(), ...(opts.get("--why") ? { why: opts.get("--why") } : {}) });
      return;
    case "answer": {
      const text = pos.slice(1).join(" ");
      const s = await R.requestsSnapshot(S);
      const m = /^R-?([1-9]\d{0,6})$/i.exec(String(pos[0] ?? "").trim());
      const r = m ? s.requests.get(`R-${Number(m[1])}`) : undefined;
      if (r && r.kind !== "decision") emit({ ok: false, reason: `${r.rid} is a ${r.kind} request: ${r.kind === "lead" ? `answer it on its lead (swarm.sh lead <run> note ${r.lead} TEXT), which reopens the lead` : r.kind === "clarification" ? `answer it on its question (swarm.sh question <run> clarify-reply ${String(r.line.q)} ${String(r.line.id)} TEXT)` : r.kind === "network" ? `grant or deny it (swarm.sh net <run> grant|deny)` : "supply the evidence (swarm.sh evidence <run> add PATH --for " + r.rid + " --why TEXT), or say it is unavailable or declined"}` });
      await act(pos[0], { ev: "answered", by: await who(), text });
      return;
    }
    case "decline":
    case "withdraw":
      await act(pos[0], { ev: cmd === "decline" ? "declined" : "withdrawn", by: await who(), why: opts.get("--why") ?? "" });
      return;
    case "authorise":
    case "authorize":
    case "collecting":
    case "unavailable":
    {
      const stage: R.AcquisitionStage = cmd === "collecting" ? "collecting" : cmd === "unavailable" ? "unavailable" : "authorised";
      await act(pos[0], { ev: "stage", by: await who(), stage, why: opts.get("--why") ?? "" });
      return;
    }
    case "fire": {
      const r = await R.fireRequests(S, opts.get("--runs") ? { runsDir: opts.get("--runs") } : {});
      emit({ ok: true, ...r });
      return;
    }
    default:
      process.stderr.write(`requests-cli: unknown command ${cmd}\n`);
      process.exit(2);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: err instanceof Error ? err.message : String(err) })}\n`);
    process.exit(1);
  });
}
