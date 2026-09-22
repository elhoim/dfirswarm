/**
 * The control under a long list.
 *
 * One bar, the same everywhere: where you are ("51–100 of 229"), the pages
 * you can reach, and how many rows you want at a time. It appears only when
 * there is more than one page, so a short list still reads as a short list.
 */
import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { paginate, pageWindow, type Page } from "@/lib/pager";
import { cn } from "@/lib/utils";

export const PAGE_SIZES = [25, 50, 100, 250] as const;

/**
 * Paging state for one list.
 *
 * `resetKey` is whatever makes the list a different list — a filter, a lens,
 * a search. When it changes the page goes back to the first, because page 5
 * of a list that no longer has five pages is an empty screen with no
 * explanation.
 */
export function usePager<T>(rows: T[], resetKey: unknown, initialSize = 50): { page: Page; rows: T[]; set: (page: number) => void; setSize: (size: number) => void } {
  const [size, setSize] = useState(initialSize);
  const [wanted, setWanted] = useState(1);
  useEffect(() => {
    setWanted(1);
  }, [resetKey, size]);
  const page = useMemo(() => paginate(rows.length, size, wanted), [rows.length, size, wanted]);
  const slice = useMemo(() => (rows.length > page.size ? rows.slice(page.start, page.end) : rows), [rows, page.start, page.end, page.size]);
  return { page, rows: slice, set: setWanted, setSize };
}

function Step({ children, label, disabled, onClick }: { children: React.ReactNode; label: string; disabled: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        "inline-flex size-7 items-center justify-center rounded-md border border-line bg-card text-ink-2 transition-colors",
        disabled ? "cursor-not-allowed opacity-40" : "hover:border-line-2 hover:text-ink",
        "[&_svg]:size-3.5",
      )}
    >
      {children}
    </button>
  );
}

export function Pager({
  page,
  onPage,
  onSize,
  unit = "rows",
  className,
}: {
  page: Page;
  onPage: (page: number) => void;
  onSize?: (size: number) => void;
  /** What the list holds, for the count: "calls", "entries", "files". */
  unit?: string;
  className?: string;
}) {
  if (page.total <= page.size && page.page === 1) {
    return (
      <p className={cn("m-0 px-1 pt-1.5 font-mono text-[11px] tabular text-ink-3", className)}>
        {page.total.toLocaleString()} {unit}
      </p>
    );
  }
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-2 pt-2", className)}>
      <span className="font-mono text-[11.5px] tabular text-ink-3">
        <span className="text-ink-2">
          {page.from.toLocaleString()}–{page.to.toLocaleString()}
        </span>{" "}
        of {page.total.toLocaleString()} {unit}
      </span>
      <nav className="flex items-center gap-1" aria-label="Pages">
        <Step label="Previous page" disabled={page.page <= 1} onClick={() => onPage(page.page - 1)}>
          <ChevronLeft />
        </Step>
        {pageWindow(page.page, page.pages).map((n, i) =>
          n === "gap" ? (
            <span key={`gap${i}`} className="px-0.5 font-mono text-[11px] text-ink-3">
              ·
            </span>
          ) : (
            <button
              key={n}
              type="button"
              aria-current={n === page.page ? "page" : undefined}
              onClick={() => onPage(n)}
              className={cn(
                "h-7 min-w-7 rounded-md border px-1.5 font-mono text-[11.5px] tabular transition-colors",
                n === page.page ? "border-ink bg-ink text-paper" : "border-line bg-card text-ink-2 hover:border-line-2 hover:text-ink",
              )}
            >
              {n}
            </button>
          ),
        )}
        <Step label="Next page" disabled={page.page >= page.pages} onClick={() => onPage(page.page + 1)}>
          <ChevronRight />
        </Step>
      </nav>
      {onSize ? (
        <span className="flex items-center gap-1" role="group" aria-label="Rows per page">
          <span className="font-mono text-[11px] uppercase tracking-[0.03em] text-ink-3">per page</span>
          {PAGE_SIZES.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={s === page.size}
              onClick={() => onSize(s)}
              className={cn(
                "h-7 rounded-md border px-1.5 font-mono text-[11px] tabular transition-colors",
                s === page.size ? "border-ink text-ink" : "border-line text-ink-3 hover:text-ink",
              )}
            >
              {s}
            </button>
          ))}
        </span>
      ) : null}
    </div>
  );
}
