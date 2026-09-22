/**
 * The console design's shared pieces: the dark vitals band with its big serif
 * numbers, the segmented finish-line meter, chips and thin meters. Everything
 * the screens compose is here so the three screens stay visually one thing.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { PostTag } from "@/lib/types";

export type Tone = "kelp" | "moss" | "saffron" | "brick" | "slate" | "neutral" | "band";

const CHIP: Record<Tone, string> = {
  kelp: "bg-kelp-soft text-kelp-ink",
  moss: "bg-moss-soft text-moss-ink",
  saffron: "bg-saffron-soft text-saffron-ink",
  brick: "bg-brick-soft text-brick-ink",
  slate: "bg-slate-soft text-slate-ink",
  neutral: "bg-paper-2 text-ink-2",
  band: "bg-band-2 text-[#e6e1d6]",
};

export function Chip({ tone = "neutral", mono, className, children }: { tone?: Tone; mono?: boolean; className?: string; children: ReactNode }) {
  return (
    <span className={cn("inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-[12px] font-medium", mono && "font-mono text-[11.5px]", CHIP[tone], className)}>
      {children}
    </span>
  );
}

const TAG_TONE: Record<PostTag | "system", Tone> = {
  intro: "slate",
  ask: "saffron",
  claim: "kelp",
  result: "moss",
  hold: "saffron",
  veto: "brick",
  stop: "brick",
  system: "brick",
};

export function tagTone(tag: string, from?: string): Tone {
  if (from === "system") return "band";
  return TAG_TONE[tag as PostTag] ?? "neutral";
}

export function TagChip({ tag, from, className }: { tag: string; from?: string; className?: string }) {
  return (
    <Chip tone={tagTone(tag, from)} className={cn("h-[22px] px-2 text-[11.5px]", className)}>
      {tag}
    </Chip>
  );
}

const FILL: Record<Tone, string> = {
  kelp: "bg-kelp",
  moss: "bg-moss",
  saffron: "bg-saffron",
  brick: "bg-brick",
  slate: "bg-slate",
  neutral: "bg-line-2",
  band: "bg-band-ink-2",
};

/** A thin bar. `pct` is clamped; `onDark` picks the band's track colour. */
export function Meter({ pct, tone = "kelp", onDark, className, label }: { pct: number; tone?: Tone; onDark?: boolean; className?: string; label?: string }) {
  const p = Math.min(100, Math.max(0, pct));
  return (
    <div
      className={cn("h-1.5 w-full overflow-hidden rounded-full", onDark ? "bg-band-line" : "bg-paper-3", className)}
      role="progressbar"
      aria-valuenow={Math.round(p)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <span className={cn("block h-full rounded-full transition-[width] duration-500", FILL[tone])} style={{ width: `${p > 0 ? Math.max(2, p) : 0}%` }} />
    </div>
  );
}

/** The finish line: one cell per check. Pending cells are dashed so "not yet" never reads as "failed". */
export function FinishMeter({ passed, total, failed = 0, pendingTone = "saffron", className }: { passed: number; total: number; failed?: number; pendingTone?: Tone; className?: string }) {
  if (total <= 0) {
    return <div className={cn("h-2 rounded-[3px] bg-paper-3", className)} aria-label="no checks defined" />;
  }
  const cells = Array.from({ length: total }, (_, i) => (i < passed ? "pass" : i < passed + failed ? "fail" : "pending"));
  return (
    <div className={cn("flex gap-1", className)} aria-label={`${passed} of ${total} checks passed`}>
      {cells.map((c, i) => (
        <span
          key={i}
          className={cn(
            "h-2 flex-1 rounded-[3px]",
            c === "pass" && "bg-moss",
            c === "fail" && "bg-brick",
            c === "pending" && cn("box-border border-2 border-dashed bg-transparent", pendingTone === "saffron" ? "border-saffron" : "border-line-2"),
          )}
        />
      ))}
    </div>
  );
}

/** The dark band at the top of a screen. */
export function VitalsBand({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn("bg-band text-band-ink", className)}>{children}</section>;
}

/** One number in the band: caption, big serif figure, optional tail and meter. */
export function Vital({
  label,
  value,
  tail,
  sub,
  meter,
  tone,
  className,
}: {
  label: string;
  value: ReactNode;
  tail?: ReactNode;
  sub?: ReactNode;
  meter?: ReactNode;
  tone?: "brick" | "saffron";
  className?: string;
}) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      <span className="label-caps text-band-ink-2">{label}</span>
      <span className={cn("serif text-[30px] leading-none tabular", tone === "brick" && "text-band-brick", tone === "saffron" && "text-saffron")}>
        {value}
        {tail ? <span className="ml-1.5 text-[16px] text-band-ink-2">{tail}</span> : null}
      </span>
      {meter}
      {sub ? <span className="text-[12px] text-band-ink-2">{sub}</span> : null}
    </div>
  );
}

export function SerifH({ as: Tag = "h2", size = 28, className, children }: { as?: "h1" | "h2" | "h3"; size?: number; className?: string; children: ReactNode }) {
  return (
    <Tag className={cn("serif m-0 text-ink", className)} style={{ fontSize: size, lineHeight: 1.1 }}>
      {children}
    </Tag>
  );
}

/** A phase heading on the story: serif title plus a quiet one-line summary. */
export function PhaseHead({ title, summary }: { title: string; summary?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-3 pt-2.5">
      <span className="serif text-[20px] text-ink">{title}</span>
      {summary ? <span className="text-[12.5px] text-ink-3">{summary}</span> : null}
    </div>
  );
}

export function StatusDot({ phase }: { phase: "running" | "done" | "stopped" | "prepared" | "unknown" }) {
  if (phase === "running") return <span className="ml-[7px] box-border block size-3.5 rounded-full border-[3px] border-kelp" aria-label="running" />;
  if (phase === "done") {
    return (
      <span className="ml-[7px] grid size-3.5 place-items-center rounded-full bg-moss" aria-label="done">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M5 13l4 4L19 7" />
        </svg>
      </span>
    );
  }
  if (phase === "stopped") {
    return (
      <span className="ml-[7px] grid size-3.5 place-items-center rounded-full bg-brick" aria-label="stopped">
        <svg width="8" height="8" viewBox="0 0 24 24" fill="#fff" aria-hidden>
          <rect x="5" y="5" width="14" height="14" rx="2" />
        </svg>
      </span>
    );
  }
  return <span className="ml-[7px] box-border block size-3.5 rounded-full border-2 border-dashed border-line-2" aria-label={phase} />;
}
