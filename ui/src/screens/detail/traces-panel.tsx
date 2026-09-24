/**
 * The raw event trace: one line per
 * tool call — clock, agent in its colour, tool, the call's own words, how long
 * it took — with a chip per agent carrying its line count and spend, and a
 * CALL / RESULT modal for any row.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowDownToLine, ChevronDown, ChevronRight, Download, ListTree } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Chip } from "@/components/console";
import { Pager, usePager } from "@/components/pager";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { api } from "@/lib/api";
import { clock, compact, eventSkew, eventTime, money, shortJson } from "@/lib/format";
import { isNoise, toolLabel, toolTone, useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import { ARG_TRUNCATED_KEY } from "@/lib/trace-record";
import type { AgentRow, SwarmEvent, SwarmView } from "@/lib/types";
import { thinkingText } from "@/lib/thinking";
import { cn } from "@/lib/utils";

/** A sender whose clock is this far from the host's gets its time shown in red; custody names it too. */
const SKEW_FLAG_SEC = 120;

function humanResult(e: SwarmEvent): string {
  const r = e.result as Record<string, unknown> | null;
  if (!r || typeof r !== "object") return shortJson(e.result);
  switch (e.tool) {
    case "claim_violation":
      return `${r.via === "bash" ? "detected" : "blocked"}${typeof r.owner === "string" ? ` — held by ${r.owner}` : ""}${typeof r.reason === "string" ? ` · ${r.reason}` : ""}`;
    case "inbox":
      return inboxResultText(r);
    case "claim_file":
      return r.ok === false ? `conflict — held by ${String(r.owner ?? "?")}` : r.refreshed ? "refreshed" : "claimed";
    case "release_file":
      return r.released === false ? "nothing to release" : "released";
    case "done":
      return r.created_sentinel ? "wrote SWARM_DONE" : "joined existing SWARM_DONE";
    case "agent_stop":
      return typeof r.via === "string" ? `via ${r.via}` : "";
    case "reap":
    case "reaped": {
      const released = (r.locks_released as number | undefined) ?? (Array.isArray(r.released) ? r.released.length : 0);
      return `${typeof r.idle_seconds === "number" ? `idle ${r.idle_seconds}s · ` : ""}${released} lock(s) released`;
    }
    case "budget":
      return `remaining ${String(r.remaining_usd ?? "?")}${r.over_budget ? " · OVER CAP" : ""}`;
    case "wait":
      return typeof r.reason === "string" ? `${r.reason}${typeof r.n === "number" ? ` · ${r.n} new` : ""}` : shortJson(r);
    default:
      return shortJson(r);
  }
}

function inboxSenders(r: Record<string, unknown>): string[] {
  const raw = r.from;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item === "string" && item && !out.includes(item)) out.push(item);
  }
  return out;
}

function inboxResultText(r: Record<string, unknown>): string {
  if (typeof r.n !== "number") return shortJson(r);
  if (r.n === 0) return "no new messages";
  const senders = inboxSenders(r);
  if (!senders.length) return `${r.n} new message${r.n === 1 ? "" : "s"}`;
  const shown = senders.slice(0, 20);
  const extra = senders.length > shown.length || (Array.isArray(r.from) && (r.from as unknown[]).length < r.n);
  return `${r.n} new from ${shown.join(", ")}${extra ? "…" : ""}`;
}

function InboxResult({ e, names, swarmId }: { e: SwarmEvent; names: (id: string) => string; swarmId?: string }) {
  const r = e.result as Record<string, unknown> | null;
  if (!r || typeof r !== "object" || typeof r.n !== "number") return <>{humanResult(e)}</>;
  if (r.n === 0) return <>no new messages</>;
  const senders = inboxSenders(r);
  if (!senders.length) return <>{r.n} new message{r.n === 1 ? "" : "s"}</>;
  const shown = senders.slice(0, 20);
  const extra = senders.length > shown.length || (Array.isArray(r.from) && r.from.length < r.n);
  return (
    <>
      {r.n} new from{" "}
      {shown.map((id, i) => (
        <span key={id}>
          {i > 0 ? ", " : null}
          {swarmId ? (
            <Link
              to={`/swarms/${swarmId}/agents/${encodeURIComponent(id)}`}
              className="font-medium text-kelp-ink hover:underline"
              onClick={(ev) => ev.stopPropagation()}
            >
              {names(id)}
            </Link>
          ) : (
            <span className="font-medium text-ink">{names(id)}</span>
          )}
        </span>
      ))}
      {extra ? "…" : null}
    </>
  );
}

function humanArgs(e: SwarmEvent): string {
  const a = e.args ?? {};
  switch (e.tool) {
    case "post":
      return [a.thread ? `#${String(a.thread)}` : "", a.tag ? `[${String(a.tag)}]` : "", a.body ? `“${String(a.body)}”` : ""].filter(Boolean).join(" ");
    case "done":
      return `reason=${String(a.reason ?? "?")} output_file=${String(a.output_file ?? "?")}`;
    case "claim_violation":
      return `${String(a.tool ?? "write")} → ${String(a.path ?? "?")}`;
    default: {
      const parts = Object.entries(a).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
      return parts.join("  ");
    }
  }
}

/** The right-hand figure: how long the call took, or for a session end what it cost. */
function Tail({ e }: { e: SwarmEvent }) {
  const r = (e.result ?? {}) as Record<string, unknown>;
  if (e.tool === "agent_stop" && (typeof r.tokens === "number" || typeof r.spent_usd === "number")) {
    return (
      <span className="whitespace-nowrap font-mono text-[11px] tabular text-saffron-ink">
        {compact(Number(r.tokens) || 0)} tok | {money(Number(r.spent_usd) || 0)}
      </span>
    );
  }
  const took = r.duration_ms;
  const ms = typeof took === "number" && Number.isFinite(took) ? took : null;
  if (ms === null) return null;
  return <span className="whitespace-nowrap font-mono text-[11px] tabular text-ink-3">{ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`}</span>;
}

/** One event's identity: the clock plus who and what, which is unique in a trace. */
function eventKey(e: SwarmEvent): string {
  return `${e.ts}|${e.agent}|${e.tool}`;
}

export function TraceRow({
  e,
  names,
  colour,
  showAgent,
  swarmId,
  open = false,
  onToggle,
}: {
  e: SwarmEvent;
  names: (id: string) => string;
  colour: (id: string) => string;
  showAgent: boolean;
  swarmId?: string;
  /** Whether this row's call and result are unfolded underneath it. */
  open?: boolean;
  onToggle?: (e: SwarmEvent) => void;
}) {
  const tone = toolTone(e.tool);
  const violation = e.tool === "claim_violation";
  const thinking = e.tool === "thinking";
  const result = e.tool === "inbox" ? <InboxResult e={e} names={names} swarmId={swarmId} /> : humanResult(e);
  return (
    <li
      className={cn(
        "border-b border-line/70 last:border-b-0",
        violation ? "bg-brick-soft/60" : e.tool === "reap" || e.tool === "reaped" ? "bg-saffron-soft/50" : e.tool === "agent_stop" || e.tool === "harness_stop" ? "bg-paper-2/70" : "",
      )}
    >
      <div
        role="button"
        tabIndex={0}
        className={cn(
          "grid w-full cursor-pointer items-baseline gap-x-2.5 px-2 py-1 text-left hover:bg-paper-2/70",
          showAgent ? "grid-cols-[84px_minmax(0,1fr)] sm:grid-cols-[84px_104px_104px_minmax(0,1fr)_auto]" : "grid-cols-[84px_minmax(0,1fr)] sm:grid-cols-[84px_104px_minmax(0,1fr)_auto]",
        )}
        aria-expanded={open}
        onClick={() => onToggle?.(e)}
        onKeyDown={(ev) => {
          if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            onToggle?.(e);
          }
        }}
      >
        <span
          className={cn("flex items-baseline gap-1 whitespace-nowrap font-mono text-[11px] tabular", Math.abs(eventSkew(e) ?? 0) > SKEW_FLAG_SEC ? "text-brick-ink" : "text-ink-3")}
          title={e.recv_ts ? `received ${e.recv_ts} (host) · sent ${e.ts} (sender's clock${Math.abs(eventSkew(e) ?? 0) > SKEW_FLAG_SEC ? `, ${eventSkew(e)} s off the host's` : ""})` : e.ts}
        >
          <ChevronRight className={cn("size-3 shrink-0 self-center text-ink-3 transition-transform", open && "rotate-90")} aria-hidden />
          {clock(eventTime(e))}
        </span>
        {showAgent ? (
          <span className="truncate font-mono text-[12px] font-medium" style={{ color: colour(e.agent) }} title={e.agent}>
            {names(e.agent)}
          </span>
        ) : null}
        <Badge variant={(e.result as { forged?: boolean } | null)?.forged ? "slate" : tone} className="justify-self-start font-mono" title={(e.result as { forged?: boolean } | null)?.forged ? "a tool an agent forged" : undefined}>
          {(e.result as { forged?: boolean } | null)?.forged && e.tool !== "make_tool" && e.tool !== "tool_loaded" ? "⚒ " : ""}
          {toolLabel(e.tool)}
        </Badge>
        <span className={cn("col-span-2 min-w-0 truncate font-mono text-[12px] text-ink-2 sm:col-span-1")}>
          {e.tool === "post" && typeof e.args.thread === "string" ? <span className="mr-1.5 font-semibold text-brick-ink">→ #{e.args.thread}</span> : null}
          <span className={cn(thinking ? "italic text-[#6b3d7a]" : "text-ink")}>{thinking ? thinkingText(e) : humanArgs(e)}</span>
          {result && !thinking ? <span className="text-ink-3"> → {result}</span> : null}
        </span>
        <span className="hidden justify-self-end sm:block">
          <Tail e={e} />
        </span>
      </div>
      {open ? <TraceDetail e={e} names={names} swarmId={swarmId} /> : null}
    </li>
  );
}

/** The record's own bookkeeping is described underneath, not shown as an argument. */
function argsWithoutMeta(e: SwarmEvent): Record<string, unknown> {
  const args = (e.args ?? {}) as Record<string, unknown>;
  if (!(ARG_TRUNCATED_KEY in args)) return args;
  const { [ARG_TRUNCATED_KEY]: _meta, ...rest } = args;
  return rest;
}

function pretty(value: unknown): string {
  try {
    return JSON.stringify(value ?? null, null, 2);
  } catch {
    return String(value);
  }
}

/**
 * One call, opened where it sits.
 *
 * It used to be a modal: the row was a button that covered the page with a
 * dialog, so reading two calls meant opening and closing two of them, and
 * the trace you were reading disappeared behind the thing you asked about.
 * A trace is a list, and a list row that has more to say should say it in
 * place.
 *
 * Both panes wrap. The dialog's `<pre>` scrolled sideways, so a path or a
 * command that ran past the pane's edge was cut on screen while being whole
 * in the file — the panel looked like it was hiding something it was not.
 * Where the *record* is an opening rather than the whole argument, the
 * harness says so under `_truncated`, and that is stated rather than left as
 * an ellipsis to be misread.
 */
function isLong(value: unknown): boolean {
  return typeof value === "string" && (value.length > 120 || value.includes("\n"));
}

/** One field: the name on the left, the value beside it, wrapping. */
function Field({ name, value, tone }: { name: string; value: unknown; tone?: "ok" | "bad" }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, typeof value === "object" && value !== null ? 2 : 0);
  if (isLong(value) || (typeof value === "object" && value !== null)) {
    return (
      <div className="min-w-0">
        <div className="label-caps mb-0.5 text-ink-3">{name}</div>
        <pre className="m-0 max-h-[22rem] overflow-y-auto whitespace-pre-wrap break-all rounded-md border border-line bg-paper px-2.5 py-1.5 font-mono text-[11.5px] leading-[1.55] text-ink">
          {text}
        </pre>
      </div>
    );
  }
  return (
    <div className="grid min-w-0 grid-cols-[minmax(4.5rem,auto)_minmax(0,1fr)] items-baseline gap-x-2.5 py-[3px]">
      <span className="truncate text-right font-mono text-[11px] uppercase tracking-[0.03em] text-ink-3" title={name}>
        {name}
      </span>
      <span
        className={cn(
          "min-w-0 break-all font-mono text-[12.5px] leading-[1.5]",
          tone === "bad" ? "text-brick-ink" : tone === "ok" ? "text-moss" : "text-ink",
        )}
      >
        {text}
      </span>
    </div>
  );
}

/** A group of fields under one heading, or nothing when there are none. */
function FieldGroup({ title, entries, tones }: { title: string; entries: Array<[string, unknown]>; tones?: Record<string, "ok" | "bad"> }) {
  const short = entries.filter(([, v]) => !isLong(v) && !(typeof v === "object" && v !== null));
  const long = entries.filter(([, v]) => isLong(v) || (typeof v === "object" && v !== null));
  return (
    <div className="min-w-0">
      <div className="mb-1 border-b border-line pb-1 font-mono text-[10.5px] font-semibold uppercase tracking-[0.08em] text-ink-3">{title}</div>
      {entries.length === 0 ? <p className="m-0 font-mono text-[12px] italic text-ink-3">no fields</p> : null}
      {short.map(([k, v]) => (
        <Field key={k} name={k} value={v} tone={tones?.[k]} />
      ))}
      {long.length ? (
        <div className={cn("flex flex-col gap-1.5", short.length && "mt-1.5")}>
          {long.map(([k, v]) => (
            <Field key={k} name={k} value={v} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

/**
 * One call, opened where it sits.
 *
 * It was a modal, then it was two boxes of pretty-printed JSON — which is
 * the record's shape, not a reading of it. `{ "path": "SWARM.md" }` across
 * three lines in a bordered box, beside `{ "ok": true, "duration_ms": 10 }`
 * in another, is four lines of punctuation around six characters of fact.
 *
 * So: fields, not documents. Each argument and each result field on its own
 * line, name beside value, wrapping; anything long or structured gets a
 * block of its own underneath. `ok` is coloured, because whether the call
 * worked is the first thing anybody looks for. The exact record is one
 * click away under RAW, and copyable, because this is an audit trail and
 * somebody will want the bytes.
 */
/** A whole output kept under tool-output/, as a trace row names it. */
type FullOutputRef = { path: string; bytes: number; lines?: number; sha256: string; write_error?: string };

function isFullOutputRef(v: unknown): v is FullOutputRef {
  return Boolean(v && typeof v === "object" && typeof (v as FullOutputRef).path === "string" && typeof (v as FullOutputRef).bytes === "number" && typeof (v as FullOutputRef).sha256 === "string");
}

/**
 * The files a row's result points at: the whole output of a call the model
 * saw a prefix of. Shown as links to the console's tool-output route, with
 * the size and the hash, so the operator reads the bytes the agent did not.
 */
function FullOutputs({ e, swarmId }: { e: SwarmEvent; swarmId?: string }) {
  const result = e.result && typeof e.result === "object" ? (e.result as Record<string, unknown>) : null;
  if (!result) return null;
  const refs: Array<[string, FullOutputRef]> = [];
  for (const key of ["full_output", "full_stderr", "full_text"]) {
    const value = result[key];
    if (isFullOutputRef(value)) refs.push([key, value]);
  }
  if (!refs.length) return null;
  return (
    <div className="mt-2 flex flex-col gap-1 pl-1 font-mono text-[10.5px] leading-[1.5] text-ink-2">
      {refs.map(([key, ref]) => (
        <span key={key}>
          <span className="uppercase tracking-[0.05em] text-ink-3">{key === "full_stderr" ? "whole stderr" : key === "full_text" ? "whole text" : "whole output"}</span>{" "}
          {swarmId ? (
            <a href={api.workUrl(swarmId, ref.path)} target="_blank" rel="noreferrer" className="text-ink underline">
              {ref.path}
            </a>
          ) : (
            <span className="text-ink">{ref.path}</span>
          )}{" "}
          · {ref.bytes.toLocaleString()} bytes{typeof ref.lines === "number" ? ` · ${ref.lines.toLocaleString()} lines` : ""} · sha256 {ref.sha256.slice(0, 12)}…
          {ref.write_error ? <span className="text-brick-ink"> · could not be written: {ref.write_error}</span> : null}
        </span>
      ))}
    </div>
  );
}

function TraceDetail({ e, names, swarmId }: { e: SwarmEvent; names: (id: string) => string; swarmId?: string }) {
  const [raw, setRaw] = useState(false);
  const [copied, setCopied] = useState(false);
  const clipped = (e.args as Record<string, unknown> | null)?.[ARG_TRUNCATED_KEY];
  const lengths = clipped && typeof clipped === "object" ? (clipped as Record<string, number>) : null;
  const args = Object.entries(argsWithoutMeta(e));
  const result = e.result && typeof e.result === "object" ? Object.entries(e.result as Record<string, unknown>).filter(([k]) => k !== "duration_ms") : [];
  const ok = (e.result as { ok?: unknown } | null)?.ok;
  const record = { ts: e.ts, agent: e.agent, tool: e.tool, args: e.args, result: e.result };

  const copy = () => {
    void navigator.clipboard?.writeText(pretty(record)).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      },
      () => undefined,
    );
  };

  return (
    <div className="border-t border-line/70 bg-paper-2/50 px-2 py-2.5" style={{ boxShadow: "inset 3px 0 0 var(--line-2)" }}>
      <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 pl-1 font-mono text-[11px] text-ink-3">
        <span className="tabular">{e.ts}</span>
        <span aria-hidden>·</span>
        <span>{names(e.agent)}</span>
        <span aria-hidden>·</span>
        <span>{toolLabel(e.tool)}</span>
        {typeof ok === "boolean" ? (
          <span className={cn("rounded-[3px] px-1.5 text-[10px] font-semibold uppercase", ok ? "bg-moss-soft text-moss-ink" : "bg-brick-soft text-brick-ink")}>
            {ok ? "ok" : "failed"}
          </span>
        ) : null}
        <span className="ml-auto flex items-center gap-2">
          <Tail e={e} />
          <button type="button" onClick={() => setRaw((r) => !r)} aria-pressed={raw} className={cn("rounded-[4px] border px-1.5 py-px text-[10px] uppercase tracking-[0.05em]", raw ? "border-ink text-ink" : "border-line text-ink-3 hover:text-ink")}>
            raw
          </button>
          <button type="button" onClick={copy} className="rounded-[4px] border border-line px-1.5 py-px text-[10px] uppercase tracking-[0.05em] text-ink-3 hover:text-ink">
            {copied ? "copied" : "copy"}
          </button>
        </span>
      </div>

      {raw ? (
        <pre className="m-0 max-h-[26rem] overflow-y-auto whitespace-pre-wrap break-all rounded-md border border-line bg-paper px-2.5 py-2 font-mono text-[11.5px] leading-[1.5] text-ink">
          {pretty(record)}
        </pre>
      ) : (
        <div className="grid gap-x-6 gap-y-3 pl-1 md:grid-cols-2">
          <FieldGroup title="Call" entries={args} />
          <FieldGroup title="Result" entries={result} tones={{ ok: ok === false ? "bad" : "ok", error: "bad", reason: "bad" }} />
        </div>
      )}

      <FullOutputs e={e} swarmId={swarmId} />

      {lengths ? (
        <p className="m-0 mt-2 pl-1 font-mono text-[10.5px] leading-[1.4] text-saffron-ink">
          {Object.entries(lengths)
            .map(([key, n]) => `${key}: the harness of the day kept an opening of a ${n.toLocaleString()}-character argument (the trace keeps everything whole now)`)
            .join(" · ")}
        </p>
      ) : null}
    </div>
  );
}

export function TraceList({
  events,
  agents,
  showAgent = true,
  className,
  swarmId,
  empty,
  pageKey,
  follow = false,
}: {
  events: SwarmEvent[];
  agents: AgentRow[];
  showAgent?: boolean;
  className?: string;
  swarmId?: string;
  /** What "nothing here" means for this list, when the caller knows better. */
  empty?: { title: string; hint: string };
  /** Whatever makes this a different list — a lens, a filter — so paging restarts. */
  pageKey?: unknown;
  /** A running trace keeps the newest line in view: paging follows it to the last page. */
  follow?: boolean;
}) {
  const names = useAgentNames(agents);
  const colour = useAgentColours(agents);
  // One at a time. Several open at once pushed the rows around it so far
  // apart that the list stopped being a list — and the row you opened first
  // was off the screen by the time you opened the second.
  const [open, setOpen] = useState<string | null>(null);
  const toggle = useCallback((e: SwarmEvent) => {
    const key = eventKey(e);
    setOpen((was) => (was === key ? null : key));
  }, []);
  const pager = usePager(events, pageKey);
  const { set } = pager;
  const lastPage = pager.page.pages;
  useEffect(() => {
    // Following a live trace means the newest call, which is on the last page.
    if (follow) set(lastPage);
  }, [follow, lastPage, events.length, set]);
  if (!events.length)
    return (
      <EmptyState
        icon={<ListTree />}
        title={empty?.title ?? "No trace lines"}
        hint={empty?.hint ?? "traces/events.jsonl holds nothing for this selection."}
      />
    );
  return (
    <div className={cn("min-w-0", className)}>
      <ol className="card overflow-hidden rounded-lg p-0" aria-label="Trace events">
        {pager.rows.map((e, i) => (
          <TraceRow
            key={`${e.ts}-${e.agent}-${e.tool}-${i}`}
            e={e}
            names={names}
            colour={colour}
            showAgent={showAgent}
            swarmId={swarmId}
            open={open === eventKey(e)}
            onToggle={toggle}
          />
        ))}
      </ol>
      <Pager page={pager.page} onPage={pager.set} onSize={pager.setSize} unit="calls" />
    </div>
  );
}

export function TracesPanel({ view, version, initialAgent }: { view: SwarmView; version: number; initialAgent?: string }) {
  const id = view.summary.id;
  const [agent, setAgent] = useState(initialAgent ?? "");
  const [tool, setTool] = useState("");
  const [q, setQ] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [showAll, setShowAll] = useState(false);
  const [follow, setFollow] = useState(true);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const prevCount = useRef(0);
  const loader = useCallback(() => api.traces(id, { agent: agent || undefined, tool: tool || undefined, q: q || undefined, limit: 1000, order }), [id, agent, tool, q, order]);
  const page = useResource(loader, version, [id, agent, tool, q, order]);
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);

  const events = useMemo(() => {
    const all = page.data?.events ?? [];
    return showAll || tool ? all : all.filter((e) => !isNoise(e));
  }, [page.data, showAll, tool]);
  const hidden = (page.data?.events.length ?? 0) - events.length;

  useEffect(() => {
    if (follow && order === "asc" && prevCount.current > 0 && events.length > prevCount.current) bottomRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    prevCount.current = events.length;
  }, [events.length, follow, order]);

  const toolOptions = page.data?.tools ?? [...new Set(view.traces.map((e) => e.tool))].sort();
  // Team seats first, in team order; anything else that left a line after.
  const byAgent = page.data?.by_agent ?? {};
  const chipAgents = [...view.agents.map((a) => a.id), ...Object.keys(byAgent).filter((a) => !view.agents.some((t) => t.id === a))];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="flex items-baseline gap-2">
          <span className="text-[14px] font-semibold uppercase tracking-[0.04em] text-ink">Raw event trace</span>
          <span className="font-mono text-[12px] tabular text-ink-3">{page.data ? `${page.data.total.toLocaleString()} events` : "…"}</span>
        </span>
        <span className="hidden items-center gap-1.5 sm:flex">
          <Badge variant="brick">claim_violation</Badge>
          <Badge variant="saffron">reap</Badge>
          <Badge variant="moss">done · session end</Badge>
          <Badge variant="kelp">post · inbox</Badge>
          <Badge variant="slate">claim · release · write</Badge>
        </span>
      </div>

      {/* one chip per agent: lines and spend, in the agent's own colour */}
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by agent">
        <button
          type="button"
          onClick={() => setAgent("")}
          aria-pressed={agent === ""}
          className={cn("h-7 rounded-md border px-2.5 font-mono text-[11.5px] font-semibold uppercase", agent === "" ? "border-ink bg-ink text-paper" : "border-line bg-card text-ink-2 hover:text-ink")}
        >
          All
        </button>
        {chipAgents.map((a) => {
          const stat = byAgent[a];
          const inTeam = view.agents.some((t) => t.id === a);
          const row = view.agents.find((t) => t.id === a);
          const mark = row?.done ? "✓" : row?.dead || row?.stalled ? "?" : "●";
          const active = agent === a;
          return (
            <button
              key={a}
              type="button"
              onClick={() => setAgent(active ? "" : a)}
              aria-pressed={active}
              title={inTeam ? `${a} · ${stat?.events ?? 0} lines · ${money(stat?.spent_usd ?? 0)}` : `${a} (not in team)`}
              className={cn("inline-flex h-7 items-center gap-1.5 rounded-md border px-2 font-mono text-[11.5px] tabular", !inTeam && "border-dashed", active ? "bg-paper-2 text-ink" : "bg-card text-ink-2 hover:text-ink")}
              style={{ borderColor: active ? colour(a) : undefined }}
            >
              <span style={{ color: colour(a) }}>{mark}</span>
              <span className="font-medium" style={{ color: active ? colour(a) : undefined }}>
                {names(a)}
              </span>
              <span className="text-ink-3">{stat?.events ?? 0}</span>
              {stat ? <span className="text-ink-3">| {money(stat.spent_usd)}</span> : null}
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          size="sm"
          mono
          value={tool}
          onChange={setTool}
          className="w-[190px]"
          aria-label="Filter by tool"
          searchPlaceholder="Filter tools…"
          options={[{ value: "", label: "All tools" }, ...toolOptions.map((t) => ({ value: t, label: toolLabel(t), keywords: t }))]}
        />
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="find a signal…  ( / )" className="h-8 min-w-[180px] flex-1 rounded-lg font-mono text-[12.5px]" aria-label="Search traces" data-find />
        <Button variant="secondary" size="sm" onClick={() => setOrder((o) => (o === "asc" ? "desc" : "asc"))} title="Toggle order">
          {order === "asc" ? <ChevronDown /> : <ChevronRight className="rotate-[-90deg]" />} {order === "asc" ? "oldest first" : "newest first"}
        </Button>
        <Button variant={showAll ? "secondary" : "ghost"} size="sm" onClick={() => setShowAll((s) => !s)} title="Reveal inbox / budget / read / bash / wait chatter">
          {showAll ? "Hide chatter" : `Show all${hidden ? ` (+${hidden})` : ""}`}
        </Button>
        <Button variant={follow ? "secondary" : "ghost"} size="sm" onClick={() => setFollow((f) => !f)} title="Auto-scroll to newest">
          <ArrowDownToLine /> {follow ? "Following" : "Follow"}
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[12px] text-ink-3 tabular">
        {page.data ? (
          <span>
            {events.length} shown · {page.data.matched} matched · {page.data.total} total
            {page.data.matched > page.data.events.length ? ` (last ${page.data.events.length})` : ""}
          </span>
        ) : null}
        {/*
          The query keeps the LAST N events, so on a long run the view drops
          the beginning of the investigation — the opening moves, which are
          usually the ones a reader wants. Saying so, and offering the file
          that has all of them, is the least this panel can do.
        */}
        {page.data && page.data.matched > page.data.events.length ? (
          <span className="text-saffron-ink">
            The earliest {(page.data.matched - page.data.events.length).toLocaleString()} are not on this page.
          </span>
        ) : null}
        <a
          href={api.dossierUrl(id, "trace.jsonl")}
          download
          className="ml-auto inline-flex items-center gap-1 text-kelp-ink hover:underline"
        >
          <Download className="size-3.5" /> trace.jsonl · all {page.data ? page.data.total.toLocaleString() : ""} events
        </a>
        {(agent || tool || q) && (
          <button
            type="button"
            className="text-kelp-ink hover:underline"
            onClick={() => {
              setAgent("");
              setTool("");
              setQ("");
            }}
          >
            clear filters
          </button>
        )}
        {agent ? (
          <Chip tone="neutral" className="font-mono">
            {names(agent)}
          </Chip>
        ) : null}
      </div>

      {page.error && !page.data ? <ErrorState error={page.error} onRetry={page.reload} /> : null}
      {page.loading && !page.data ? <LoadingState label="Reading events.jsonl" rows={6} /> : null}
      {page.data ? (
        events.length ? (
          <>
            <TraceList
              events={events}
              agents={view.agents}
              swarmId={id}
              pageKey={`${agent}|${tool}|${q}|${order}|${showAll}`}
              follow={follow && order === "asc"}
            />
            <div ref={bottomRef} />
          </>
        ) : page.data.total === 0 && page.data.unreadable ? (
          // There, and not readable: not the same as a run with no trace yet.
          <EmptyState
            icon={<ListTree />}
            title="The trace could not be read"
            hint={`traces/events.jsonl is there and was not read: ${page.data.unreadable}. The host's custody check says what it found.`}
          />
        ) : page.data.total === 0 ? (
          <EmptyState icon={<ListTree />} title="No traces yet" hint="traces/events.jsonl is empty. Lines appear on the first tool call (agent_start, post, inbox…)." />
        ) : (
          <EmptyState title="Nothing matches these filters" hint={hidden ? `${hidden} chatter lines are hidden — try “Show all”.` : "Clear a filter to widen the view."} />
        )
      ) : null}
    </div>
  );
}
