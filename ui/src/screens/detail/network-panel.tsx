/**
 * The dynamic network (docs/adr/0011): the case policy in force, what waits
 * on the operator (one item per host and lead) with the form that answers
 * it, every grant with its state, uses and time left and a revoke, every
 * request with its decision and machine-readable reasons, every capture as
 * sealed, what the fetch service turned away, and contamination. The
 * operator's acts run as `swarm.sh net`, with a reason, so they land on the
 * trace and the operator's record like the CLI's. Nothing is cut: every
 * reason, purpose and hash is shown whole.
 */
import { useCallback, useState } from "react";
import { AlertTriangle, Globe, KeyRound, ListChecks, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Chip } from "@/components/console";
import { JobCard } from "@/components/jobs-drawer";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { clock } from "@/lib/format";
import { useNow } from "@/lib/hooks";
import { useLive, useResource } from "@/lib/live";
import type { NetReason, NetworkPanelView, SwarmView } from "@/lib/types";

type Grant = NetworkPanelView["grants"][number];
type Item = NetworkPanelView["items"][number];
type Req = NetworkPanelView["requests"][number];

const STATUS_TONE: Record<string, "kelp" | "saffron" | "slate" | "moss" | "brick"> = { granted: "kelp", active: "kelp", exhausted: "moss", expired: "slate", revoked: "brick" };

function left(expires: string | null, now: number): string {
  if (!expires) return "for the run";
  const ms = Date.parse(expires) - now;
  if (ms <= 0) return `ended ${clock(expires)}`;
  const s = Math.ceil(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s left` : `${s} s left`;
}

function Reasons({ reasons }: { reasons: NetReason[] }) {
  if (!reasons.length) return null;
  return (
    <ul className="m-0 list-none space-y-0.5 p-0">
      {reasons.map((r, i) => (
        <li key={`${r.code}${i}`} className="text-ink-2">
          <code className="font-mono text-[11.5px] text-ink">{r.code}</code> <span className="text-ink-3">(step {r.step}, {r.rule}{r.overridable ? "" : ", not overridable"})</span>: {r.detail}
        </li>
      ))}
    </ul>
  );
}

/** The operator's act, with its reason: run as swarm.sh net. */
function useAct(runId: string, onJob: (id: string) => void) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const act = async (payload: Parameters<typeof api.netAct>[1]) => {
    setError(null);
    setBusy(true);
    try {
      const job = await api.netAct(runId, payload);
      onJob(job.id);
      return true;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { act, error, busy };
}

function ItemCard({ item, requests, runId, onJob }: { item: Item; requests: Req[]; runId: string; onJob: (id: string) => void }) {
  const [why, setWhy] = useState("");
  const { act, error, busy } = useAct(runId, onJob);
  const last = item.requests.at(-1) ?? "";
  const reqs = requests.filter((r) => item.requests.includes(r.id));
  return (
    <li className="rounded-md border-2 border-brick bg-brick-soft/40 px-3 py-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <AlertTriangle className="size-4 text-brick-ink" aria-hidden="true" />
        <code className="font-mono font-semibold text-ink">{item.id}</code>
        <span className="font-medium text-ink">{item.host}</span>
        {item.lead ? <Chip tone="slate">{item.lead}</Chip> : null}
        <span className="text-ink-3">opened by {item.opened_by} at {clock(item.opened_at)}</span>
      </div>
      <div className="mt-1 space-y-1">
        <Reasons reasons={item.reasons} />
        {reqs.map((r) => (
          <p key={r.id} className="m-0 text-ink-2">
            <code className="font-mono text-[11.5px]">{r.id}</code> {r.adapter ? `${r.adapter}: ` : ""}
            <span className="break-all font-mono text-[11.5px] text-ink">{r.url ?? r.host}</span> — {r.purpose}
            {r.evidence.length ? <span className="text-ink-3"> (evidence: {r.evidence.join(", ")})</span> : null}
          </p>
        ))}
      </div>
      <div className="mt-2 grid gap-2">
        <Label htmlFor={`why-${item.id}`} className="text-[12px] text-ink-2">
          Your reason (recorded with the decision, posted to the board to whoever asked)
        </Label>
        <Input id={`why-${item.id}`} value={why} onChange={(e) => setWhy(e.target.value)} placeholder="why you grant or decline it" className="h-8" />
        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={busy || !why.trim() || !last} onClick={() => void act({ action: "grant", target: last, why: why.trim() }).then((ok) => ok && setWhy(""))}>
            Grant {last}
          </Button>
          <Button size="sm" variant="secondary" disabled={busy || !why.trim()} onClick={() => void act({ action: "deny", target: item.id, why: why.trim() }).then((ok) => ok && setWhy(""))}>
            Decline {item.id}
          </Button>
        </div>
        <p className="m-0 text-[12px] text-ink-3">A grant runs the same rules with the overridable reasons waived and recorded; a login, an upload, a credential or a sensitive value stays refused. A decline closes this avenue, never the lead.</p>
        {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      </div>
    </li>
  );
}

function GrantRow({ g, now, runId, onJob }: { g: Grant; now: number; runId: string; onJob: (id: string) => void }) {
  const [why, setWhy] = useState("");
  const { act, error, busy } = useAct(runId, onJob);
  const live = g.status === "granted" || g.status === "active";
  return (
    <li className="card space-y-1 px-3 py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <code className="font-mono text-[12px] font-semibold text-ink">{g.id}</code>
        <Chip tone={STATUS_TONE[g.status] ?? "slate"}>{g.status}</Chip>
        {g.type === "socket" ? <Chip tone="saffron">socket (tier 2)</Chip> : null}
        <Chip tone={g.granted_by === "operator" ? "saffron" : "slate"}>by {g.granted_by}</Chip>
        {live ? <span className="text-ink-3">{left(g.expires_at, now)}</span> : null}
        {g.max_requests !== null ? <span className="text-ink-3">{g.uses} of {g.max_requests} used</span> : null}
      </div>
      <p className="m-0 break-all font-mono text-[11.5px] text-ink">{g.type === "socket" ? `${g.host}:${g.port} — host and port only, no method or path control, no content capture` : `${g.method} ${g.url}`}</p>
      <p className="m-0 text-ink-2">
        for {g.bound ? `job ${g.bound}` : g.principal}
        {g.lead ? ` on ${g.lead}` : ""}
        {g.adapter ? `, adapter ${g.adapter}` : ""}
        {g.request ? `, request ${g.request}` : ""}
        {g.why ? ` — ${g.why}` : ""}
        {g.waived.length ? ` (waived: ${g.waived.join(", ")})` : ""}
        {g.status_why ? ` — ${g.status_why}` : ""}
      </p>
      {live ? (
        <div className="flex flex-wrap items-center gap-2">
          <Input aria-label={`Reason to revoke ${g.id}`} value={why} onChange={(e) => setWhy(e.target.value)} placeholder="reason to revoke" className="h-7 max-w-[320px]" />
          <Button size="sm" variant="outlineDanger" disabled={busy || !why.trim()} onClick={() => void act({ action: "revoke", target: g.id, why: why.trim() }).then((ok) => ok && setWhy(""))}>
            Revoke
          </Button>
        </div>
      ) : null}
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
    </li>
  );
}

function SocketForm({ runId, onJob, permitted }: { runId: string; onJob: (id: string) => void; permitted: boolean }) {
  const [host, setHost] = useState("");
  const [lead, setLead] = useState("");
  const [why, setWhy] = useState("");
  const { act, error, busy } = useAct(runId, onJob);
  if (!permitted) return <p className="m-0 text-[12px] text-ink-3">This case policy permits no socket grant: every request here is mediated by the fetch service.</p>;
  return (
    <div className="grid gap-2">
      <p className="m-0 text-[12px] text-ink-2">
        A socket grant (tier 2) gives the run's jobs run with network=allowlist a host and a port, from their next worker on: host and port only, no method or path control, no content capture. Prefer granting an agent's request, which is mediated and captured.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Input aria-label="Host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="api.example.org[:port]" className="h-8 max-w-[240px]" />
        <Input aria-label="Lead" value={lead} onChange={(e) => setLead(e.target.value)} placeholder="L-n (optional)" className="h-8 max-w-[120px]" />
        <Input aria-label="Reason" value={why} onChange={(e) => setWhy(e.target.value)} placeholder="reason" className="h-8 max-w-[320px]" />
        <Button size="sm" variant="secondary" disabled={busy || !host.trim() || !why.trim()} onClick={() => void act({ action: "socket", host: host.trim(), ...(lead.trim() ? { lead: lead.trim() } : {}), why: why.trim() }).then((ok) => ok && (setHost(""), setWhy("")))}>
          Make a socket grant
        </Button>
      </div>
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
    </div>
  );
}

export function NetworkPanel({ view, version }: { view: SwarmView; version: number }) {
  const id = view.summary.id;
  const live = useLive();
  const now = useNow(1000);
  const loader = useCallback(() => api.network(id), [id]);
  const res = useResource(loader, version, [id]);
  const [jobId, setJobId] = useState<string | null>(null);
  const job = jobId ? (live.jobs[jobId] ?? null) : null;
  if (res.error && !res.data) return <ErrorState error={res.error} onRetry={res.reload} title="Could not read the network records" />;
  if (!res.data) return <LoadingState label="Reading the network records" rows={4} />;
  const d = res.data;
  const open = d.items.filter((it) => !it.closed);
  const closed = d.items.filter((it) => it.closed);
  const requests = [...d.requests].reverse();
  return (
    <div className="space-y-5">
      <section className="space-y-1">
        <h3 className="label-caps flex items-center gap-1.5">
          <Globe className="size-3.5" /> Case policy
        </h3>
        <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-ink-2">
          {d.lines.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="m-0 text-[12px] text-ink-3">
          Fetch service: {d.service.port ? `port ${d.service.port}` : "none"}
          {d.service.keyed.length ? `; keyed adapters: ${d.service.keyed.join(", ")}` : ""}. Records: grants {d.chain.ok ? `intact, ${d.chain.events} events` : <span className="text-brick-ink">BROKEN at line {d.chain.broken_at} ({d.chain.reason})</span>}; fetches{" "}
          {d.fetch_chain.ok ? `intact, ${d.fetch_chain.events} lines` : <span className="text-brick-ink">BROKEN at line {d.fetch_chain.broken_at} ({d.fetch_chain.reason})</span>}. The CLI is <code>swarm.sh net {id} list</code>.
        </p>
      </section>

      {d.contamination.length ? (
        <section className="space-y-1" aria-label="Contamination">
          <h3 className="label-caps flex items-center gap-1.5 text-brick-ink">
            <ShieldAlert className="size-3.5" /> Contamination ({d.contamination.length})
          </h3>
          <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-brick-ink">
            {d.contamination.map((c, i) => (
              <li key={`${c.at}${i}`}>
                {clock(c.at)} {c.capture ?? c.grant ?? ""}: {c.what}
                {c.category ? ` (${c.category})` : ""} — {c.why}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="space-y-2" aria-label="Waiting on the operator">
        <h3 className="label-caps flex items-center gap-1.5 text-brick-ink">
          <AlertTriangle className="size-3.5" /> Waiting on you ({open.length})
        </h3>
        {open.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {open.map((it) => (
              <ItemCard key={it.id} item={it} requests={d.requests} runId={id} onJob={setJobId} />
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-3">Nothing: no refused request waits for your decision.</p>
        )}
        {job ? <JobCard job={job} /> : null}
      </section>

      <section className="space-y-2">
        <h3 className="label-caps flex items-center gap-1.5">
          <KeyRound className="size-3.5" /> Grants ({d.grants.length})
        </h3>
        {d.grants.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {[...d.grants].reverse().map((g) => (
              <GrantRow key={g.id} g={g} now={now} runId={id} onJob={setJobId} />
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-3">No grant yet.</p>
        )}
        <SocketForm runId={id} onJob={setJobId} permitted={d.policy.sockets === "operator"} />
      </section>

      <section className="space-y-2">
        <h3 className="label-caps flex items-center gap-1.5">
          <ListChecks className="size-3.5" /> Requests ({d.requests.length})
        </h3>
        {requests.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {requests.map((r) => (
              <li key={r.id} className="card space-y-1 px-3 py-2 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="font-mono text-[12px] font-semibold text-ink">{r.id}</code>
                  <Chip tone={r.decision === "granted" ? "kelp" : r.decision === "denied" ? "saffron" : "slate"}>{r.decision ?? "undecided"}</Chip>
                  {r.decided_by ? <span className="text-ink-3">by {r.decided_by}</span> : null}
                  <span className="text-ink-3">
                    {clock(r.at)} · {r.principal}
                    {r.lead ? ` · ${r.lead}` : ""}
                  </span>
                  {r.grant ? <Chip tone="kelp">{r.grant}</Chip> : null}
                  {r.item ? <Chip tone="brick">{r.item}</Chip> : null}
                </div>
                <p className="m-0 break-all font-mono text-[11.5px] text-ink">
                  {r.type === "socket" ? `socket ${r.host}` : `${r.adapter ? `${r.adapter} ` : ""}${r.url ?? r.host ?? ""}`}
                </p>
                <p className="m-0 text-ink-2">
                  {r.purpose}
                  {r.evidence.length ? <span className="text-ink-3"> (evidence: {r.evidence.join(", ")})</span> : null}
                  {r.why ? <span> — {r.why}</span> : null}
                </p>
                <Reasons reasons={r.reasons} />
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="No request yet" hint="An agent asks for one bounded lookup with net_request; the hub decides it by the case policy and records the decision here." />
        )}
      </section>

      {d.captures.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Captures ({d.captures.length})</h3>
          <p className="m-0 text-[12px] text-ink-3">Sealed in store/net/&lt;k&gt;/&lt;n&gt;/ and recorded on the ledger as external material: a hash proves the bytes, not their truth.</p>
          <ul className="m-0 list-none space-y-1 p-0 text-[12.5px] text-ink-2">
            {[...d.captures].reverse().map((c) => (
              <li key={c.capture} className="break-all">
                <code className="font-mono text-[12px] text-ink">{c.capture}</code> {clock(c.at)} {c.method} <span className="font-mono text-[11.5px]">{c.url}</span> for {c.principal}:{" "}
                {c.refused ? `refused (${c.refused})` : c.error ? `failed (${c.error})` : `${c.status}, ${c.bytes ?? 0} bytes`}
                {c.sha256 ? <span className="font-mono text-[11px] text-ink-3"> sha256 {c.sha256}</span> : null}
                {c.complete ? "" : " · incomplete"}
                {c.delivered ? "" : " · not delivered"}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {d.refusals.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Uses the fetch service refused ({d.refusals.length})</h3>
          <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-ink-2">
            {[...d.refusals].reverse().map((r, i) => (
              <li key={`${r.at}${i}`}>
                {clock(r.at)} {r.principal} {r.grant ?? ""}: <code className="font-mono text-[11.5px]">{r.code}</code> — {r.detail}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {closed.length ? (
        <section className="space-y-1">
          <h3 className="label-caps m-0">Items decided ({closed.length})</h3>
          <ul className="m-0 list-none space-y-0.5 p-0 text-[12.5px] text-ink-2">
            {closed.map((it) => (
              <li key={it.id}>
                <code className="font-mono text-[12px]">{it.id}</code> {it.host}
                {it.lead ? ` for ${it.lead}` : ""}: {it.closed?.how} by {it.closed?.by} at {clock(it.closed?.at ?? "")} — {it.closed?.why}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
