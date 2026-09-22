/**
 * Choosing what the swarm is made of.
 *
 * One model everywhere is the common case and stays one control. A mixed team
 * is the interesting one: a couple of strong agents to design, cheaper ones to
 * grind, a different vendor to review so the whole swarm does not share one
 * blind spot. N follows from the counts, so the two can never disagree.
 */
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, type SelectOption } from "@/components/ui/select";
import type { ProviderReadiness } from "@/lib/types";
import { cn } from "@/lib/utils";

/** One line of a mixed team: the model, how many agents run it, and what those agents may spend together (USD, as typed; "" is no ceiling). */
export type TeamRow = { model: string; count: number; cap: string };

/** The per-model cap as a number, or undefined when blank or not a number. */
export function rowCap(row: TeamRow): number | undefined {
  const n = Number(row.cap);
  return row.cap.trim() && Number.isFinite(n) && n > 0 ? n : undefined;
}

export function providerOf(model: string): string {
  const slash = model.indexOf("/");
  return slash === -1 ? model : model.slice(0, slash);
}

/** One line under a model in the picker: whether its provider can be used right now, and how. */
export function readinessHint(model: string, readiness?: Record<string, ProviderReadiness>): string | undefined {
  const r = readiness?.[providerOf(model)];
  if (!r) return undefined;
  if (r.status === "ready") return r.local ? "ready · local, free" : r.auth_type === "oauth" ? "ready · subscription" : r.auth_type === "api_key" ? "ready · api key" : "ready";
  if (r.status === "local") return "local · needs a placeholder apiKey";
  if (r.status === "not_ready") return "not logged in";
  if (r.status === "invalid") return "credentials invalid";
  return undefined;
}

export const CUSTOM_MODEL = "__custom";

/**
 * The options a model picker shows: grouped by provider, readiness under each
 * one, the dot in front, and a way out at the end for a model the list lacks.
 */
export function modelOptions(known: string[], readiness?: Record<string, ProviderReadiness>): SelectOption[] {
  const out: SelectOption[] = known.map((m) => ({
    value: m,
    label: m,
    group: providerOf(m),
    hint: readinessHint(m, readiness),
    mark: <ReadyDot model={m} readiness={readiness} />,
  }));
  out.push({ value: CUSTOM_MODEL, label: "Other…", hint: "type a provider/id the list does not have", group: "not listed" });
  return out;
}

/** A small dot: kelp when the provider is ready, brick when its credentials are bad, hollow when unknown. */
export function ReadyDot({ model, readiness, className }: { model: string; readiness?: Record<string, ProviderReadiness>; className?: string }) {
  const r = readiness?.[providerOf(model)];
  const title = !r
    ? "readiness unknown"
    : r.status === "ready"
      ? `${r.provider}: ready${r.local ? ` — local server at ${r.base_url ?? "this machine"}, no metered cost` : r.auth_type ? ` via ${r.auth_type}` : ""}`
      : r.status === "local"
        ? `${r.provider}: a local server at ${r.base_url ?? "this machine"} — give it a placeholder apiKey in models.json; there is no login`
        : r.status === "not_ready"
          ? `${r.provider}: not logged in — pi auth login ${r.provider}`
          : r.status === "invalid"
            ? `${r.provider}: credentials invalid`
            : `${r.provider}: ${r.reason ?? "unknown"}`;
  return (
    <span
      className={cn("inline-block size-2.5 shrink-0 rounded-full", !r || r.status === "unknown" ? "border border-line-2" : r.status === "ready" ? "bg-kelp" : r.status === "invalid" ? "bg-brick" : "bg-saffron", className)}
      title={title}
      aria-label={title}
    />
  );
}

export const MODEL_REF = /^[a-z0-9_.-]+\/[A-Za-z0-9_.:/-]+$/;

/** The `--models` spec swarm.sh parses, or "" when the team is unusable. */
export function teamSpec(rows: TeamRow[]): string {
  return rows
    .filter((row) => MODEL_REF.test(row.model.trim()) && row.count >= 1)
    .map((row) => `${row.model.trim()}=${Math.floor(row.count)}${rowCap(row) !== undefined ? `@${rowCap(row)}` : ""}`)
    .join(",");
}

export function teamTotal(rows: TeamRow[]): number {
  return rows.reduce((sum, row) => sum + (row.count >= 1 ? Math.floor(row.count) : 0), 0);
}

export function teamProblems(rows: TeamRow[]): string[] {
  const out: string[] = [];
  if (rows.length === 0) out.push("A mixed team needs at least one model.");
  for (const row of rows) {
    if (!MODEL_REF.test(row.model.trim())) out.push(`“${row.model || "(empty)"}” must look like provider/id.`);
    if (!Number.isInteger(row.count) || row.count < 1) out.push(`“${row.model}” needs a whole count of at least 1.`);
    if (row.cap.trim() && rowCap(row) === undefined) out.push(`“${row.model}” needs a cap in USD above zero, or none.`);
  }
  const total = teamTotal(rows);
  if (total > 30) out.push(`A team of ${total} is over the limit of 30.`);
  return out;
}

export function ModelTeamEditor({
  rows,
  onChange,
  known,
  disabled,
  readiness,
}: {
  rows: TeamRow[];
  onChange: (rows: TeamRow[]) => void;
  known: string[];
  disabled?: boolean;
  readiness?: Record<string, ProviderReadiness>;
}) {
  const total = teamTotal(rows);
  const update = (index: number, patch: Partial<TeamRow>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));

  return (
    <div className="space-y-2">
      {rows.map((row, index) => (
        <div key={index} className="flex items-center gap-2">
          <Select
            mono
            size="sm"
            value={known.includes(row.model) ? row.model : CUSTOM_MODEL}
            disabled={disabled}
            onChange={(v) => update(index, { model: v === CUSTOM_MODEL ? "" : v })}
            options={modelOptions(known, readiness)}
            searchPlaceholder="Filter models…"
            className="min-w-0 flex-1"
            aria-label={`Model ${index + 1}`}
          />
          {known.includes(row.model) ? null : (
            <ReadyDot model={row.model} readiness={readiness} />
          )}
          {known.includes(row.model) ? null : (
            <Input
              value={row.model}
              disabled={disabled}
              onChange={(e) => update(index, { model: e.target.value })}
              placeholder="provider/model-id"
              className="flex-1 font-mono"
              aria-label={`Model ${index + 1} id`}
            />
          )}
          <Input
            type="number"
            min={1}
            max={30}
            value={row.count}
            disabled={disabled}
            onChange={(e) => update(index, { count: Number(e.target.value) })}
            className="w-20 tabular"
            aria-label={`How many agents on model ${index + 1}`}
          />
          <div className={cn("flex h-8 w-28 items-center gap-1 rounded-md border border-line bg-card px-2", disabled && "opacity-50")} title="What every agent on this model may spend together, in USD. Blank means no ceiling of its own; the swarm's cap still binds.">
            <span className="text-[12px] text-ink-3">$</span>
            <input
              inputMode="decimal"
              value={row.cap}
              disabled={disabled}
              onChange={(e) => update(index, { cap: e.target.value })}
              placeholder="no cap"
              className="w-full border-0 bg-transparent font-mono text-[12.5px] text-ink outline-none placeholder:text-ink-3"
              aria-label={`USD cap for every agent on model ${index + 1}`}
            />
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            disabled={disabled || rows.length <= 1}
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
            aria-label={`Remove model ${index + 1}`}
          >
            <Trash2 className="size-4" />
          </Button>
        </div>
      ))}
      <div className="flex items-center justify-between">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={disabled}
          onClick={() => onChange([...rows, { model: known[0] ?? "", count: 1, cap: "" }])}
        >
          <Plus className="size-3.5" /> Add a model
        </Button>
        <span className={cn("text-[12px] tabular", total > 30 ? "text-brick-ink" : "text-ink-3")}>
          N = {total}
          {rows.some((r) => rowCap(r) !== undefined) ? (
            <span className="ml-3 text-ink-3">model caps Σ ${rows.reduce((sum, r) => sum + (rowCap(r) ?? 0), 0)}</span>
          ) : null}
        </span>
      </div>
    </div>
  );
}
