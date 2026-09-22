import type { ReactNode } from "react";
import { AlertTriangle, Inbox, LoaderCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function EmptyState({
  title,
  hint,
  action,
  icon,
  className,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line-2 bg-paper-2/60 px-6 py-10 text-center", className)}>
      <div className="text-ink-3 [&_svg]:size-6">{icon ?? <Inbox />}</div>
      <p className="text-[14px] font-medium text-ink">{title}</p>
      {hint ? <p className="max-w-md text-[13px] text-ink-2">{hint}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading", rows = 3, className }: { label?: string; rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} role="status" aria-live="polite">
      <div className="flex items-center gap-2 text-[12px] text-ink-3">
        <LoaderCircle className="size-3.5 animate-spin" />
        {label}…
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-9 animate-pulse rounded-md bg-paper-3/70" style={{ width: `${92 - i * 9}%` }} />
      ))}
    </div>
  );
}

export function ErrorState({ error, onRetry, className, title = "Could not load" }: { error: Error | string; onRetry?: () => void; className?: string; title?: string }) {
  const message = typeof error === "string" ? error : error.message;
  return (
    <div className={cn("flex items-start gap-3 rounded-lg border border-brick/30 bg-brick-soft/60 px-4 py-3 text-[13px] text-brick-ink", className)} role="alert">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <p className="font-medium">{title}</p>
        <p className="mt-0.5 break-words font-mono text-[12px] opacity-90">{message}</p>
      </div>
      {onRetry ? (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          <RefreshCw /> Retry
        </Button>
      ) : null}
    </div>
  );
}

export function InlineNote({ children, tone = "neutral", className }: { children: ReactNode; tone?: "neutral" | "warn" | "danger" | "ok"; className?: string }) {
  const tones = {
    neutral: "border-line bg-paper-2 text-ink-2",
    warn: "border-saffron/40 bg-saffron-soft text-saffron-ink",
    danger: "border-brick/30 bg-brick-soft text-brick-ink",
    ok: "border-moss/30 bg-moss-soft text-moss",
  };
  return <div className={cn("rounded-md border px-3 py-2 text-[12.5px] leading-[1.5]", tones[tone], className)}>{children}</div>;
}
