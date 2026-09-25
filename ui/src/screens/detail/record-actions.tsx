/**
 * What an examiner does with a run's record once it exists: hold it
 * (legal hold: purge and reap refuse it), export the ledger (CSV, or a
 * Timesketch import), package it (signed with the operator's SSH key when
 * asked), verify a package, or purge the run. Every one of them is a
 * `swarm.sh` command run by the console's job runner, so each lands in the
 * operator's own record (runs/operator-audit.jsonl) as the console's.
 * Purge deletes the sandbox, the kept disks and the hub directory; it asks
 * for the run id typed out, and swarm.sh itself refuses a running or held run.
 */
import { useCallback, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { InlineNote } from "@/components/states";
import { api, ApiError } from "@/lib/api";
import { useLive, useResource } from "@/lib/live";
import { clock } from "@/lib/format";
import type { SwarmView } from "@/lib/types";

export function RecordActions({ view, open, onOpenChange, onJob }: { view: SwarmView; open: boolean; onOpenChange: (open: boolean) => void; onJob: (jobId: string) => void }) {
  const live = useLive();
  const id = view.summary.id;
  const held = view.summary.hold ?? null;
  const running = view.summary.phase === "running";
  const [reason, setReason] = useState("");
  const [sign, setSign] = useState(true);
  const [pkg, setPkg] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [exportJob, setExportJob] = useState<string | null>(null);
  const exported = exportJob ? (live.jobs[exportJob] ?? null) : null;
  // What swarm.sh package left, read again whenever a package job of this run ends.
  const packageJobsDone = Object.values(live.jobs).filter((j) => j.swarm_id === id && j.kind === "package" && j.status !== "running").length;
  const packageLoader = useCallback(() => api.packageInfo(id), [id]);
  const pkgInfo = useResource(open ? packageLoader : null, packageJobsDone, [id, open]);

  async function run(fn: () => Promise<{ id: string }>, keepOpen = false): Promise<string | null> {
    setError(null);
    try {
      const j = await fn();
      onJob(j.id);
      if (!keepOpen) onOpenChange(false);
      return j.id;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
      return null;
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogTitle>The record of {view.summary.label}</DialogTitle>
        <DialogDescription>
          Each action is a <code>swarm.sh</code> command, and each goes on the operator's own record (<code>runs/operator-audit.jsonl</code>) as run from the console.
        </DialogDescription>
        <div className="mt-3 grid gap-4 text-[13px]">
          <section className="space-y-1.5">
            <h3 className="label-caps m-0">Legal hold</h3>
            {held ? (
              <>
                <p className="m-0 text-ink-2">On hold{held.reason ? `: ${held.reason}` : ""}{held.at ? ` (since ${held.at})` : ""}. Purge and reap refuse the run until it is released.</p>
                <Button size="sm" variant="secondary" onClick={() => void run(() => api.release(id))}>
                  Release the hold
                </Button>
              </>
            ) : (
              <div className="flex flex-wrap items-center gap-2">
                <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (a case, a request, an order)" aria-label="Hold reason" className="h-8 min-w-[220px] flex-1" />
                <Button size="sm" variant="secondary" onClick={() => void run(() => api.hold(id, reason.trim()))}>
                  Hold
                </Button>
              </div>
            )}
          </section>

          <section className="space-y-1.5">
            <h3 className="label-caps m-0">Export the ledger</h3>
            <p className="m-0 text-ink-2">Every entry with its hash, what corrects it and its review. Timesketch gets the event time as its datetime; an entry with none carries the time it was recorded.</p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" onClick={async () => setExportJob(await run(() => api.exportLedger(id, "csv"), true))}>
                CSV
              </Button>
              <Button size="sm" variant="secondary" onClick={async () => setExportJob(await run(() => api.exportLedger(id, "timesketch"), true))}>
                Timesketch
              </Button>
              {exported ? (
                exported.status === "ok" ? (
                  <Button asChild size="sm">
                    <a href={api.exportUrl(exported.id)} download>
                      Download the export
                    </a>
                  </Button>
                ) : (
                  <span className="self-center text-[12px] text-ink-3">{exported.status === "running" ? "exporting…" : "the export failed; its output is below the actions"}</span>
                )
              ) : null}
            </div>
          </section>

          <section className="space-y-1.5">
            <h3 className="label-caps m-0">Package</h3>
            <p className="m-0 text-ink-2">
              <code>swarm.sh package {id}</code>: the report, the ledger, the trace, custody, the VM records and every output, with a <code>MANIFEST</code> of their hashes.
            </p>
            <label className="flex items-center justify-between gap-3">
              <span>Sign the manifest with this user's SSH key (<code>--sign</code>)</span>
              <Switch checked={sign} onCheckedChange={setSign} aria-label="Sign the package" />
            </label>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="secondary" onClick={() => void run(() => api.packageRun(id, sign), true)}>
                {pkgInfo.data?.present ? "Package again" : "Package"}
              </Button>
              {pkgInfo.data?.present ? (
                <Button asChild size="sm">
                  <a href={api.packageZipUrl(id)} download>
                    Download the package (zip)
                  </a>
                </Button>
              ) : null}
              {pkgInfo.data?.present ? (
                <Button size="sm" variant="secondary" onClick={() => void run(() => api.verifyPackage(id, pkgInfo.data!.dir), true)}>
                  Verify it
                </Button>
              ) : null}
            </div>
            {pkgInfo.data?.present ? (
              <p className="m-0 text-[12px] text-ink-2 [overflow-wrap:anywhere]">
                Packaged {pkgInfo.data.made_at ? clock(pkgInfo.data.made_at) : ""}: {pkgInfo.data.files} files in <code>MANIFEST.txt</code> (sha256 <span className="font-mono">{pkgInfo.data.manifest_sha256}</span>),{" "}
                {pkgInfo.data.signed ? `signed${pkgInfo.data.signer.length ? ` (${pkgInfo.data.signer.join(" · ")})` : ""}` : "not signed"}. The zip is the directory as it is, made when you download it; <code>swarm.sh verify</code> takes either.
              </p>
            ) : pkgInfo.data?.error ? (
              <InlineNote tone="danger">{pkgInfo.data.error}</InlineNote>
            ) : pkgInfo.data ? (
              <p className="m-0 text-[12px] text-ink-3">Not packaged yet.</p>
            ) : null}
          </section>

          <section className="space-y-1.5">
            <h3 className="label-caps m-0">Verify a package</h3>
            <div className="flex flex-wrap items-center gap-2">
              <Input value={pkg} onChange={(e) => setPkg(e.target.value)} placeholder="/absolute/path/to/the/package (directory or zip)" aria-label="Package path" className="h-8 min-w-[220px] flex-1 font-mono text-[12px]" />
              <Button size="sm" variant="secondary" disabled={!pkg.trim().startsWith("/")} onClick={() => void run(() => api.verifyPackage(id, pkg.trim()))}>
                Verify
              </Button>
            </div>
          </section>

          <section className="space-y-1.5">
            <h3 className="label-caps m-0">Purge</h3>
            <p className="m-0 text-ink-2">Deletes the sandbox, each VM's kept disk and the hub's directory. The registry keeps the run as purged, with a destruction record of what went and its hashes. It cannot be undone.</p>
            {running || held ? (
              <InlineNote tone="warn">{running ? "A running run cannot be purged; stop it first." : "The run is on hold; release it first."}</InlineNote>
            ) : (
              <div className="space-y-1.5">
                <Label htmlFor="purge-confirm">Type the run id ({id}) to purge it</Label>
                <div className="flex flex-wrap items-center gap-2">
                  <Input id="purge-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-8 w-48 font-mono" autoComplete="off" />
                  <Button size="sm" variant="danger" disabled={confirm !== id} onClick={() => void run(() => api.purge(id, confirm))}>
                    Purge
                  </Button>
                </div>
              </div>
            )}
          </section>
          {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
