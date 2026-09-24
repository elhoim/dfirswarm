export function money(n: number | undefined | null, digits?: number): string {
  const v = Number(n) || 0;
  const d = digits ?? (v >= 10 ? 2 : v >= 1 ? 3 : 4);
  return `$${v.toFixed(d)}`;
}

export function compact(n: number | undefined | null): string {
  const v = Number(n) || 0;
  if (v >= 1_000_000_000) return `${(v / 1_000_000_000).toFixed(1)}B`;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(v >= 10_000_000 ? 0 : 1)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}k`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return String(v);
}

export function duration(ms: number | undefined | null): string {
  const v = Math.max(0, Number(ms) || 0);
  const s = Math.floor(v / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function shortDuration(ms: number | undefined | null): string {
  const v = Math.max(0, Number(ms) || 0);
  const m = Math.round(v / 60_000);
  if (m < 1) return `${Math.floor(v / 1000)}s`;
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function relTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const diff = now - t;
  if (diff < 0) return "just now";
  if (diff < 45_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 90 * 60_000) return `${Math.round(diff / 60_000)} min ago`;
  if (diff < 36 * 3_600_000) return `${Math.round(diff / 3_600_000)} h ago`;
  return `${Math.round(diff / 86_400_000)} d ago`;
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/**
 * When a trace line happened, by the host's clock: the collector's receive
 * time when it stamped one, the sender's own otherwise. Lines from a VM carry
 * the guest's clock in `ts`, and ordering them against the host's posts by
 * that clock puts a skewed guest's lines in the wrong place.
 */
export function eventTime(e: { ts: string; recv_ts?: string }): string {
  return e.recv_ts || e.ts;
}

/** Seconds between the sender's clock and the host's for one line; null when either is missing. */
export function eventSkew(e: { ts: string; recv_ts?: string }): number | null {
  if (!e.recv_ts) return null;
  const a = Date.parse(e.ts);
  const b = Date.parse(e.recv_ts);
  return Number.isFinite(a) && Number.isFinite(b) ? Math.round((a - b) / 1000) : null;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function pct(part: number, whole: number): number {
  if (!whole || whole <= 0) return 0;
  return Math.min(100, Math.max(0, (part / whole) * 100));
}

export function shortJson(value: unknown, max = 160): string {
  let text: string;
  try {
    text = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === undefined || text === "{}" || text === "null") return "";
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * How long a swarm has run, ticking while it runs. The server's `elapsed_ms`
 * is a snapshot taken when the row was built; a running swarm counts on from
 * its start on the client, so the figure moves without another request.
 */
export function liveElapsed(row: { phase: string; elapsed_ms: number; started_at: string; finished_at: string | null }, now: number): number {
  if (row.finished_at || row.phase !== "running") return row.elapsed_ms;
  const start = Date.parse(row.started_at);
  return Number.isFinite(start) ? Math.max(0, now - start) : row.elapsed_ms;
}

/** m:ss, for the grace clock and the lease countdowns. */
export function mmss(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** A one-glyph mark for the provider in front of a model id. */
export function providerGlyph(model: string): string {
  const provider = model.split("/")[0] ?? "";
  switch (provider) {
    case "anthropic":
      return "✳";
    case "openai":
    case "openai-codex":
      return "◎";
    case "deepseek":
      return "◇";
    case "google":
    case "gemini":
      return "✦";
    case "zai":
    case "glm":
      return "⧉";
    case "openrouter":
      return "⇄";
    case "mockswarm":
      return "⌂";
    default:
      return "●";
  }
}

/** "1,931 chars" — the size of a post. */
export function chars(text: string): string {
  return `${text.length.toLocaleString()} chars`;
}

