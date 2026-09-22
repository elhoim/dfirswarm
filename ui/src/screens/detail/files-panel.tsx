import { useCallback, useState } from "react";
import { History, Lock, RotateCcw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Pager, usePager } from "@/components/pager";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { bytes, clock, dateTime } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { useResource } from "@/lib/live";
import type { FileVersion, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

export function FilesPanel({
  view,
  selected,
  onSelect,
  version,
}: {
  view: SwarmView;
  selected: string | null;
  onSelect: (path: string) => void;
  version: number;
}) {
  const id = view.summary.id;
  const names = useAgentNames(view.agents);
  const paths = Object.keys(view.history).sort();
  const pager = usePager<string>(paths, paths.length, 25);
  const current = selected && view.history[selected] ? selected : paths[0] ?? null;
  const versions: FileVersion[] = current ? view.history[current] : [];
  const [rev, setRev] = useState<number | null>(null);
  const activeRev = rev !== null && versions.some((v) => v.rev === rev) ? rev : versions.at(-1)?.rev ?? null;
  const loader = useCallback(() => (current && activeRev !== null ? api.revision(id, current, activeRev) : Promise.reject(new Error("no revision"))), [id, current, activeRev]);
  const content = useResource(current && activeRev !== null ? loader : null, version, [id, current, activeRev]);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const lock = current ? view.locks.find((l) => l.path === current) : null;

  async function restore() {
    if (!current || activeRev === null) return;
    setBusy(true);
    setResult(null);
    try {
      const r = await api.restore(id, current, activeRev);
      setResult({ ok: r.ok, message: r.ok ? `Restored ${current} to rev ${activeRev}. A new revision was recorded first, so nothing is lost.` : r.reason ?? "Restore refused." });
    } catch (err) {
      setResult({ ok: false, message: err instanceof ApiError ? err.message : (err as Error).message });
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  }

  if (!paths.length) {
    return (
      <EmptyState
        icon={<History />}
        title="No file history yet"
        hint={
          <>
            Every legal <code>edit</code>/<code>write</code> copies the previous bytes into <code>history/&lt;sha256&gt;/NNNNNN.bin</code>. The first write to a <code>work/</code> file creates the first revision.
          </>
        }
      />
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
      <aside className="space-y-3">
        <div>
          <div className="label-caps px-1">Files with history</div>
          <ul className="mt-1.5 space-y-1">
            {pager.rows.map((p) => (
              <li key={p}>
                <button
                  type="button"
                  onClick={() => {
                    setRev(null);
                    setResult(null);
                    onSelect(p);
                  }}
                  className={cn("flex w-full items-center justify-between gap-2 rounded-md border px-3 py-2 text-left", p === current ? "border-kelp/50 bg-card shadow-card" : "border-line bg-card hover:bg-paper-2/60")}
                >
                  <code className="truncate text-[12.5px] text-ink">{p}</code>
                  <span className="text-[11px] tabular text-ink-3">{view.history[p].length} rev</span>
                </button>
              </li>
            ))}
          </ul>
          <Pager page={pager.page} onPage={pager.set} unit="files" />
        </div>
        {current ? (
          <div>
            <div className="label-caps px-1">Revisions</div>
            <ol className="mt-1.5 space-y-1">
              {[...versions].reverse().map((v) => (
                <li key={v.rev}>
                  <button
                    type="button"
                    onClick={() => {
                      setRev(v.rev);
                      setResult(null);
                    }}
                    className={cn("flex w-full items-center gap-2 rounded-md border px-3 py-1.5 text-left text-[12.5px]", v.rev === activeRev ? "border-kelp/50 bg-kelp-soft/50" : "border-line bg-card hover:bg-paper-2/60")}
                  >
                    <Badge variant={v.rev === versions.at(-1)?.rev ? "kelp" : "outline"} className="font-mono">
                      r{v.rev}
                    </Badge>
                    <span className="truncate text-ink">{names(v.agent)}</span>
                    <span className="ml-auto whitespace-nowrap tabular text-ink-3">
                      {bytes(v.bytes)} · {clock(v.ts)}
                    </span>
                  </button>
                </li>
              ))}
            </ol>
          </div>
        ) : null}
      </aside>

      <section className="min-w-0 space-y-3">
        {current && activeRev !== null ? (
          <>
            <div className="card flex flex-wrap items-center gap-2 p-3">
              <code className="text-[13px] font-medium text-ink">{current}</code>
              <Badge variant="outline" className="font-mono">
                rev {activeRev} of {versions.length}
              </Badge>
              {lock ? (
                <Badge variant="slate">
                  <Lock /> held by {names(lock.owner)}
                </Badge>
              ) : null}
              <div className="ml-auto flex items-center gap-2">
                <Button variant="secondary" size="sm" onClick={() => setConfirm(true)} disabled={busy || activeRev === versions.at(-1)?.rev} title={activeRev === versions.at(-1)?.rev ? "This is already the newest revision" : "Restore this revision"}>
                  <RotateCcw /> Restore this revision
                </Button>
              </div>
            </div>
            {result ? <InlineNote tone={result.ok ? "ok" : "danger"}>{result.message}</InlineNote> : null}
            {content.error && !content.data ? <ErrorState error={content.error} onRetry={content.reload} /> : null}
            {content.loading && !content.data ? <LoadingState label="Reading revision" rows={5} /> : null}
            {content.data ? (
              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-line bg-paper-2/60 px-3 py-1.5 text-[11px] text-ink-3">
                  <span>
                    written by {names(versions.find((v) => v.rev === activeRev)?.agent ?? "?")} · {dateTime(versions.find((v) => v.rev === activeRev)?.ts)}
                  </span>
                  <span className="tabular">{content.data.text.length.toLocaleString()} chars</span>
                </div>
                <pre className="max-h-[60vh] overflow-auto px-3 py-2 text-[12px] leading-[1.55] text-ink">{content.data.text || <span className="italic text-ink-3">(empty file)</span>}</pre>
              </div>
            ) : null}
            <p className="text-[11.5px] text-ink-3">
              Restore is an operator addition. The server claims the file as <code>operator</code>, restores through the same guarded path agents use, releases the claim and logs <code>file_restore</code> in the trace. If an agent holds the lock, restore is refused.
            </p>
          </>
        ) : null}
      </section>

      <Dialog open={confirm} onOpenChange={setConfirm}>
        <DialogContent>
          <DialogTitle>Restore {current} to rev {activeRev}?</DialogTitle>
          <DialogDescription>
            The current bytes are saved as a new revision first, then rev {activeRev} is copied back into <code>{current}</code>. Agents will see the change on their next read.
            {lock ? (
              <span className="mt-2 block text-brick-ink">
                {names(lock.owner)} holds this file's lock right now; the restore will be refused until it is released.
              </span>
            ) : null}
          </DialogDescription>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button onClick={() => void restore()} disabled={busy}>
              <RotateCcw /> {busy ? "Restoring…" : "Restore"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
