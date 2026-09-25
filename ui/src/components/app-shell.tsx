import { type ReactNode, useEffect, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import { Activity, Plus, TerminalSquare, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/console";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useLive } from "@/lib/live";
import { cn } from "@/lib/utils";
import { JobsDrawer } from "@/components/jobs-drawer";

/**
 * Where this console's own source lives. Change it in a fork: the AGPL asks a
 * modified version to offer its users *its* source, not the original's.
 */
const SOURCE_URL = "https://github.com/halilozturkci/dfirswarm";

/**
 * The mark: two brackets holding five peers. The dots read from the palette in
 * index.css rather than repeating its hexes, so a retuned token moves the logo
 * with it. Decorative here — the link beside it already carries the name.
 */
function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true" focusable="false">
      <path d="M 21 11 H 11 V 53 H 21" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M 43 11 H 53 V 53 H 43" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="27" cy="21" r="3.6" fill="var(--color-brick)" />
      <circle cx="39" cy="20" r="3.6" fill="var(--color-slate)" />
      <circle cx="32" cy="32" r="3.6" fill="var(--color-saffron)" />
      <circle cx="41" cy="37" r="3.6" fill="var(--color-kelp)" />
      <circle cx="27" cy="44" r="3.6" fill="var(--color-moss)" />
    </svg>
  );
}

function LiveChip() {
  const live = useLive();
  const label = live.status === "live" ? (live.watching ? "live" : "live · polling") : live.status === "connecting" ? "connecting" : "offline";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>
          <Chip tone={live.status === "live" ? "kelp" : live.status === "connecting" ? "neutral" : "brick"} className="h-7 px-2.5">
            {live.status === "offline" ? <WifiOff className="size-3" /> : <span className={cn("size-[7px] rounded-full", live.status === "live" ? "bg-kelp" : "bg-ink-3")} />}
            <span className="hidden sm:inline">{label}</span>
          </Chip>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {live.status === "live"
          ? `Server-sent events connected. ${live.watching ? "Filesystem watcher active." : "Watcher unavailable; polling every 3 s."}`
          : live.status === "connecting"
            ? "Opening the event stream."
            : "Event stream lost. Retrying every 3 s; data may be stale."}
      </TooltipContent>
    </Tooltip>
  );
}

const navClass = ({ isActive }: { isActive: boolean }) =>
  cn("border-b-2 pb-0.5 text-[13.5px] font-medium transition-colors", isActive ? "border-kelp text-ink" : "border-transparent text-ink-2 hover:text-ink");

export function AppShell({ children }: { children: ReactNode }) {
  const live = useLive();
  const [jobsOpen, setJobsOpen] = useState(false);
  const running = Object.values(live.jobs).filter((j) => j.status === "running").length;
  const total = Object.keys(live.jobs).length;

  // `/` finds the signal on whatever screen is open: the first search box on
  // the page takes focus.
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key !== "/" || ev.metaKey || ev.ctrlKey || ev.altKey) return;
      const target = ev.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT" || target.isContentEditable)) return;
      const box = document.querySelector<HTMLElement>("[data-find]");
      if (!box) return;
      ev.preventDefault();
      box.focus();
      if (box instanceof HTMLInputElement) box.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex min-h-dvh flex-col bg-paper">
      <header className="sticky top-0 z-40 border-b border-line bg-paper/92 backdrop-blur supports-[backdrop-filter]:bg-paper/80">
        <div className="mx-auto flex h-[60px] w-full max-w-[1680px] items-center justify-between gap-3 px-4 sm:px-10">
          <div className="flex items-center gap-7">
            <Link to="/" className="flex items-center gap-2.5 text-ink" title="DFIR Swarm — an agent swarm for digital forensics and incident response">
              <Mark className="size-[26px] shrink-0" />
              <span className="serif text-[24px] italic" style={{ letterSpacing: "-0.01em" }}>
                DFIR Swarm
              </span>
            </Link>
            <nav className="hidden items-center gap-[18px] sm:flex">
              <NavLink to="/" end className={navClass}>
                Swarms
              </NavLink>
              <NavLink to="/new" className={navClass}>
                Kickoff
              </NavLink>
            </nav>
          </div>
          <div className="flex items-center gap-2.5">
            <LiveChip />
            <Button variant="ghost" size="sm" onClick={() => setJobsOpen(true)} className="hidden sm:inline-flex" aria-label="Show shell actions">
              <TerminalSquare />
              Actions
              {total ? (
                <Chip tone={running ? "saffron" : "neutral"} className="ml-0.5 h-5 px-1.5 text-[11px]">
                  {running ? <Activity className="size-3 animate-pulse" /> : null}
                  {running ? `${running} running` : total}
                </Chip>
              ) : null}
            </Button>
            <Button asChild size="sm" className="h-[38px] rounded-lg px-4 text-[13.5px]">
              <Link to="/new">
                <Plus /> New swarm
              </Link>
            </Button>
          </div>
        </div>
      </header>
      <main className="flex w-full flex-1 flex-col">{children}</main>
      <footer className="border-t border-line">
        <div className="mx-auto flex min-h-10 w-full max-w-[1680px] flex-wrap items-center justify-between gap-2 px-4 py-1.5 text-[12px] text-ink-3 sm:px-10">
          <span>Reads runs/ · every action goes through scripts/swarm.sh · watching is open to whoever reaches this address (this machine only unless started with --host 0.0.0.0), spending needs the token</span>
          {/* AGPL s13: whoever reaches this console over the network is offered
              the source of the version serving it. An unmodified run is already
              covered by this link; a modified one points it at its own source. */}
          <a
            className="underline-offset-2 hover:underline"
            href={SOURCE_URL}
            target="_blank"
            rel="noreferrer"
          >
            AGPL v3 · source
          </a>
          <button type="button" className="underline-offset-2 hover:underline sm:hidden" onClick={() => setJobsOpen(true)}>
            Shell actions {total ? `(${total})` : ""}
          </button>
        </div>
      </footer>
      <JobsDrawer open={jobsOpen} onOpenChange={setJobsOpen} />
    </div>
  );
}
