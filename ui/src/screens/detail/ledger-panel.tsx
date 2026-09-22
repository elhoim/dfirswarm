/**
 * The ledger: what the agents put on record with `record`, straight from
 * ledger/entries.jsonl. The timeline is the events in time order; the
 * indicators and the findings follow.
 *
 * The rendering is the report vocabulary rather than markup local to this
 * screen, so a claim looks the same here as it does on the handover and in
 * `report.html`. That matters for one reason in particular: an entry missing
 * its source or its evidence is marked in both places, because the harness's
 * rule is that an entry nobody can check is not a record, and a panel that
 * quietly dropped the empty column would hide exactly the thing worth seeing.
 */
import { useCallback, useMemo, useState } from "react";
import { BookOpenText } from "lucide-react";
import { Pager, usePager } from "@/components/pager";
import { EmptyState, InlineNote } from "@/components/states";
import {
  FindingCard,
  IndicatorTable,
  NotRecorded,
  ReportCounts,
  TimelineTable,
  isCited,
  type Author,
  type ClaimRecord,
} from "@/components/report";
import { useAgentColours } from "@/lib/agent-colour";
import { useAgentNames } from "@/lib/hooks";
import type { LedgerEntry, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

type Kind = "all" | LedgerEntry["kind"];
const KINDS: Array<{ key: Kind; label: string }> = [
  { key: "all", label: "All" },
  { key: "event", label: "Events" },
  { key: "ioc", label: "Indicators" },
  { key: "finding", label: "Findings" },
];

export function LedgerPanel({ view }: { view: SwarmView }) {
  const entries = view.ledger?.entries ?? [];
  const names = useAgentNames(view.agents);
  const colour = useAgentColours(view.agents);
  const chosenOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const n of view.names ?? []) map.set(n.id, n.name);
    return (id: string) => map.get(id);
  }, [view.names]);
  const [kind, setKind] = useState<Kind>("all");
  const [query, setQuery] = useState("");

  const authorsFor = useCallback(
    (c: ClaimRecord): Author[] => (c.authors ?? []).map((id) => ({ id, name: names(id), chosen: chosenOf(id), colour: colour(id) })),
    [names, chosenOf, colour],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => (kind === "all" || e.kind === kind) && (!q || [e.value, e.source, e.evidence, ...e.authors].some((t) => (t ?? "").toLowerCase().includes(q))));
  }, [entries, kind, query]);
  const events = filtered.filter((e) => e.kind === "event");
  const iocs = filtered.filter((e) => e.kind === "ioc");
  const findings = filtered.filter((e) => e.kind === "finding");
  const timelinePage = usePager(events, `${kind}|${query}`, 50);
  const iocPage = usePager(iocs, `${kind}|${query}`, 50);
  const findingPage = usePager(findings, `${kind}|${query}`, 25);
  const counts = {
    event: entries.filter((e) => e.kind === "event").length,
    ioc: entries.filter((e) => e.kind === "ioc").length,
    finding: entries.filter((e) => e.kind === "finding").length,
  };
  const uncited = entries.filter((e) => !isCited(e)).length;

  if (!entries.length) {
    return (
      <EmptyState
        icon={<BookOpenText className="size-5" />}
        title="Nothing recorded yet"
        hint={
          <>
            Agents put dated events, indicators and findings here with <code>record</code>; the harness renders them into <code>ledger/ledger.md</code> after every call.
          </>
        }
      />
    );
  }

  return (
    <div className="space-y-4">
      <ReportCounts events={counts.event} indicators={counts.ioc} findings={counts.finding} uncited={uncited} />

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Ledger kinds">
          {KINDS.map((k) => (
            <button
              key={k.key}
              type="button"
              role="tab"
              aria-selected={kind === k.key}
              onClick={() => setKind(k.key)}
              className={cn(
                "h-[26px] rounded-full border px-2.5 text-[12px] font-medium transition-colors",
                kind === k.key ? "border-ink bg-ink text-paper" : "border-line bg-transparent text-ink-2 hover:text-ink",
              )}
            >
              {k.label}
              {k.key === "all" ? ` · ${entries.length}` : ` · ${counts[k.key]}`}
            </button>
          ))}
        </div>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter by text, source, evidence or agent"
          aria-label="Filter ledger entries"
          className="h-[26px] min-w-[220px] flex-1 rounded-[6px] border border-line bg-paper px-2 text-[12.5px] text-ink outline-none placeholder:text-ink-3"
        />
        <span className="text-[12px] text-ink-3">
          {view.ledger?.rendered ? (
            <>
              rendered as <code>ledger/ledger.md</code>
            </>
          ) : (
            "not rendered yet"
          )}
        </span>
      </div>

      {kind === "all" || kind === "event" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Timeline</h3>
            <span className="text-[12px] text-ink-3">
              {events.length} event{events.length === 1 ? "" : "s"}, in time order (UTC)
            </span>
          </div>
          <TimelineTable entries={timelinePage.rows} authorsFor={authorsFor} />
          <Pager page={timelinePage.page} onPage={timelinePage.set} onSize={timelinePage.setSize} unit="events" />
        </section>
      ) : null}

      {kind === "all" || kind === "ioc" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Indicators</h3>
            <span className="text-[12px] text-ink-3">
              {iocs.length} indicator{iocs.length === 1 ? "" : "s"}
            </span>
          </div>
          <IndicatorTable entries={iocPage.rows} authorsFor={authorsFor} />
          <Pager page={iocPage.page} onPage={iocPage.set} onSize={iocPage.setSize} unit="indicators" />
        </section>
      ) : null}

      {kind === "all" || kind === "finding" ? (
        <section className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <h3 className="label-caps">Findings</h3>
            <span className="text-[12px] text-ink-3">
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </span>
          </div>
          {findings.length ? (
            <ol className="m-0 list-none space-y-2 p-0">
              {findingPage.rows.map((e) => (
                <li key={e.seq}>
                  <FindingCard claim={e} authors={authorsFor(e)} />
                </li>
              ))}
            </ol>
          ) : null}
          {findings.length ? (
            <Pager page={findingPage.page} onPage={findingPage.set} onSize={findingPage.setSize} unit="findings" />
          ) : (
            <NotRecorded what="No finding matches" why="Clear the filter, or nothing was recorded with kind `finding`." />
          )}
        </section>
      ) : null}

      <InlineNote>
        Rows come from <code>ledger/entries.jsonl</code>, one line per <code>record</code> call; an entry equal in kind, value and time to an earlier one is merged and both authors are named. The same content is rendered into <code>ledger/ledger.md</code> for the report to cite.
      </InlineNote>
    </div>
  );
}
