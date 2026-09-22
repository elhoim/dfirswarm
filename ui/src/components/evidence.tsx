/**
 * The pieces that put a hash in front of a reader.
 *
 * Every evidence file has arrived with a sha256 since the inputs manifest
 * existed, and the console drew it as a `title=` tooltip — computed, stored,
 * shipped to the browser, and invisible. A forensic tool's one distinguishing
 * claim cannot live in a hover. These four components are where it lives
 * instead, and they are shared so that an input, an artifact and a file in
 * the handover package all say the same thing the same way.
 */
import { useCallback, useState, type ReactNode } from "react";
import { Check, Copy, Download, FileLock2 } from "lucide-react";
import { Chip } from "@/components/console";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { bytes as formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

/** How much of a sha256 the eye can actually compare at a glance. */
const SHORT = 12;

export function shortHash(sha: string, chars = SHORT): string {
  return sha.length > chars ? sha.slice(0, chars) : sha;
}

/**
 * A sha256, truncated to what a reader can compare, click to copy the whole
 * thing. `slate` because the palette's slate means locks and files, and a
 * hash is the strongest statement this console makes about a file.
 */
export function HashChip({
  sha,
  label = "sha256",
  chars = SHORT,
  className,
}: {
  sha: string;
  /** What the tooltip calls it: sha256 here, "sha256 at kickoff" for inputs. */
  label?: string;
  chars?: number;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    // navigator.clipboard is undefined over plain http to a LAN address in
    // some browsers, which is exactly how this console is usually reached.
    // Falling back keeps the one action on this component working there.
    const done = () => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(sha).then(done, () => undefined);
      return;
    }
    const area = document.createElement("textarea");
    area.value = sha;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
      done();
    } finally {
      area.remove();
    }
  }, [sha]);

  if (!sha) {
    return (
      <Chip tone="neutral" mono className={cn("opacity-70", className)}>
        no hash
      </Chip>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy the ${label} of this file`}
          className={cn(
            "inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full bg-slate-soft px-2.5 font-mono text-[11.5px] font-medium text-slate-ink",
            "hover:bg-slate/20 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-slate",
            className,
          )}
        >
          {copied ? <Check className="size-3" /> : <Copy className="size-3 opacity-60" />}
          {shortHash(sha, chars)}
        </button>
      </TooltipTrigger>
      <TooltipContent>
        <span className="font-mono text-[11px] break-all">{sha}</span>
        <span className="mt-1 block opacity-70">{copied ? "Copied" : `${label} · click to copy`}</span>
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * One file in a list of files that matter: what it is, how big, its hash,
 * and whatever the caller needs to say about its state. Used for the
 * read-only inputs and for the artifacts a run produced, because those two
 * lists answer the same two questions and used to look nothing alike.
 */
export function EvidenceRow({
  path,
  bytes,
  sha,
  icon,
  meta,
  tail,
  selected,
  onSelect,
  className,
}: {
  path: string;
  bytes?: number;
  sha?: string | null;
  icon?: ReactNode;
  /** A line under the path: when it was written, who wrote it. */
  meta?: ReactNode;
  /** Chips or buttons at the end of the row. */
  tail?: ReactNode;
  selected?: boolean;
  onSelect?: () => void;
  className?: string;
}) {
  const body = (
    <>
      <span className="text-ink-3 [&_svg]:size-4">{icon ?? <FileLock2 />}</span>
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-[12.5px] text-ink">{path}</span>
        <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] tabular text-ink-3">
          {bytes === undefined ? null : <span>{formatBytes(bytes)}</span>}
          {meta}
        </span>
      </span>
      {sha ? <HashChip sha={sha} /> : null}
      {tail}
    </>
  );
  const shell = cn(
    "flex w-full items-center gap-2.5 rounded-md border px-3 py-2 text-left",
    selected ? "border-kelp/50 bg-card shadow-card" : "border-line bg-card",
    onSelect && !selected && "hover:bg-paper-2/60",
    className,
  );
  if (!onSelect) return <div className={shell}>{body}</div>;
  return (
    <button type="button" onClick={onSelect} aria-current={selected ? "true" : undefined} className={shell}>
      {body}
    </button>
  );
}

/**
 * A file in the handover package: its name, its size, its hash and the link
 * that fetches it. The hash sits beside the button on purpose — what makes
 * this a handover rather than a download is that the number travels with it.
 */
export function DownloadRow({
  name,
  href,
  description,
  bytes,
  sha,
  disabled,
  disabledReason,
  className,
}: {
  name: string;
  href: string;
  description?: ReactNode;
  bytes?: number;
  sha?: string | null;
  /** True when this run never produced the file; the row says so instead of 404ing. */
  disabled?: boolean;
  disabledReason?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-line bg-card px-3 py-2.5",
        disabled && "opacity-60",
        className,
      )}
    >
      <span className="min-w-0 flex-1">
        <span className="block font-mono text-[12.5px] text-ink">{name}</span>
        {description ? <span className="mt-0.5 block text-[11.5px] text-ink-2">{description}</span> : null}
      </span>
      {bytes === undefined ? null : <span className="tabular text-[11.5px] text-ink-3">{formatBytes(bytes)}</span>}
      {sha ? <HashChip sha={sha} /> : null}
      {disabled ? (
        <Chip tone="neutral">{disabledReason ?? "not produced"}</Chip>
      ) : (
        <Button asChild variant="secondary" size="sm">
          <a href={href} download={name}>
            <Download /> Download
          </a>
        </Button>
      )}
    </div>
  );
}

/**
 * What a file with no preview gets. It used to get `EmptyState`, which says
 * "nothing is here" about a file that is very much here — and for a carved
 * executable or a hive, the facts below are the whole point of it.
 */
export function FileFacts({
  path,
  bytes,
  sha,
  kind,
  note,
  actions,
  className,
}: {
  path: string;
  bytes: number;
  sha?: string | null;
  kind: string;
  note?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-3 px-6 py-8", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <FileLock2 className="size-4 text-slate" />
        <code className="text-[13px] text-ink">{path}</code>
        <Chip tone="neutral">{kind}</Chip>
      </div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-[12.5px]">
        <dt className="label-caps text-ink-3">Size</dt>
        <dd className="tabular text-ink">{formatBytes(bytes)}</dd>
        <dt className="label-caps text-ink-3">sha256</dt>
        <dd className="break-all font-mono text-[11.5px] text-ink">{sha || "not hashed yet"}</dd>
      </dl>
      {note ? <p className="max-w-prose text-[12.5px] leading-[1.5] text-ink-2">{note}</p> : null}
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/**
 * A frame at paper proportions, so the console can show what the PDF will be
 * before the operator commits to printing it. A4 is 1:√2; the sheet keeps
 * that ratio at whatever width it is given, sits on the paper ground with a
 * hairline edge, and does nothing else.
 */
export function PrintSheet({
  children,
  height = "70vh",
  className,
}: {
  children: ReactNode;
  /** The sheet is sized by height, because a page is read top to bottom. */
  height?: string;
  className?: string;
}) {
  return (
    <div
      className={cn("mx-auto overflow-hidden rounded-lg border border-line bg-white shadow-card", className)}
      style={{ height, aspectRatio: "1 / 1.414", maxWidth: "100%" }}
    >
      {children}
    </div>
  );
}
