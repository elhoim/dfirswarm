import { useEffect } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, LoaderCircle, TerminalSquare, XCircle } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/states";
import { api } from "@/lib/api";
import { relTime } from "@/lib/format";
import { useLive } from "@/lib/live";
import type { Job } from "@/lib/types";
import { cn } from "@/lib/utils";

export function JobStatusIcon({ job, className }: { job: Job; className?: string }) {
  if (job.status === "running") return <LoaderCircle className={cn("size-4 animate-spin text-saffron-ink", className)} />;
  if (job.status === "ok") return <CheckCircle2 className={cn("size-4 text-moss", className)} />;
  return <XCircle className={cn("size-4 text-brick", className)} />;
}

export function JobCard({ job, compact = false }: { job: Job; compact?: boolean }) {
  const out = [job.stdout, job.stderr ? `\n[stderr]\n${job.stderr}` : ""].join("").trim();
  return (
    <div className="card p-3">
      <div className="flex flex-wrap items-center gap-2">
        <JobStatusIcon job={job} />
        <code className="text-[12px] text-ink">swarm.sh {job.argv.map((a) => (a.includes(" ") ? `"${a.replace(/"/g, '\\"').slice(0, 40)}${a.length > 40 ? "…" : ""}"` : a)).join(" ")}</code>
        <span className="ml-auto text-[11px] text-ink-3 tabular">{relTime(job.started_at)}</span>
        {job.exit_code !== null ? <Badge variant={job.exit_code === 0 ? "moss" : "brick"}>exit {job.exit_code}</Badge> : <Badge variant="saffron">running</Badge>}
        {job.swarm_id ? (
          <Link to={`/swarms/${job.swarm_id}`} className="text-[12px] font-medium text-kelp-ink hover:underline">
            open {job.swarm_id} →
          </Link>
        ) : null}
      </div>
      {out && !compact ? (
        <pre className="mt-2 max-h-56 overflow-auto rounded-md bg-ink px-3 py-2 text-[11.5px] leading-[1.5] text-paper/90 whitespace-pre-wrap break-words">{out}</pre>
      ) : null}
    </div>
  );
}

/** Every start / stop / reap is a shell job; this is their console. */
export function JobsDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const live = useLive();
  const jobs = Object.values(live.jobs).sort((a, b) => (a.started_at < b.started_at ? 1 : -1));

  // The SSE stream only carries jobs since this tab connected; fetch history once.
  const mergeJobs = live.mergeJobs;
  useEffect(() => {
    if (!open) return;
    api.jobs().then(mergeJobs).catch(() => undefined);
  }, [open, mergeJobs]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogTitle className="flex items-center gap-2">
          <TerminalSquare className="size-4 text-ink-2" /> Shell actions
        </DialogTitle>
        <DialogDescription>Kickoff, stop and reap run <code>scripts/swarm.sh</code> on the server. Output is captured here; the sandbox itself is the source of truth.</DialogDescription>
        <div className="mt-4 max-h-[60vh] space-y-2 overflow-auto pr-1">
          {jobs.length ? jobs.map((job) => <JobCard key={job.id} job={job} />) : <EmptyState title="No actions yet" hint="Start, stop or reap a swarm and its shell output will show up here." icon={<TerminalSquare />} />}
        </div>
      </DialogContent>
    </Dialog>
  );
}
