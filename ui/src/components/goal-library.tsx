/**
 * Two shelves of goal documents, one picker.
 *
 * The investigation library is the repo's: one document per kind of case
 * under `library/<category>/`, generic over the evidence, read from disk on
 * every request so an edit to a file is what the picker offers next. The
 * saved goals are the operator's: `prompts/goals/` on the server, what they
 * wrote and launched before, savable and deletable from here. The CLI can
 * launch either file as it is.
 *
 * Picking one used to replace the editor with no warning, and the goal is the
 * one input actually worth iterating on between runs: edits you have not
 * saved are asked about first. A library entry may also suggest a team size,
 * a cap and a wall clock; those are offered, not applied.
 */
import { useCallback, useMemo, useState } from "react";
import { AlertTriangle, BookOpen, Check, Save, Trash2 } from "lucide-react";
import { Select, type SelectOption } from "@/components/ui/select";
import { api, ApiError } from "@/lib/api";
import type { GoalSummary, LibraryEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export type GoalSuggestion = { seats?: number; cap_usd?: number; wall_clock?: number };

const CATEGORY_LABEL: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  memory: "Memory",
  logs: "Logs",
  network: "Network",
  malware: "Malware",
  cloud: "Cloud",
  mobile: "Mobile",
  general: "General",
};
const SAVED_GROUP = "Saved goals · prompts/goals/";

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

export function GoalLibrary({
  goals,
  loading,
  library,
  libraryLoading,
  current,
  defaultText,
  onLoad,
  onSuggest,
  onSaved,
}: {
  goals: GoalSummary[];
  loading: boolean;
  library: LibraryEntry[];
  libraryLoading: boolean;
  /** The text in the editor right now, so "save as" keeps what you see. */
  current: string;
  /** The editor's starting text: not an edit worth protecting. */
  defaultText: string;
  onLoad: (text: string, name: string) => void;
  onSuggest: (suggestion: GoalSuggestion) => void;
  onSaved: () => void;
}) {
  const [selected, setSelected] = useState("");
  const [saveName, setSaveName] = useState("");
  /** What the editor last received from here; the editor differing from it is an edit. */
  const [loaded, setLoaded] = useState<string | null>(null);
  const [pending, setPending] = useState<{ value: string; title: string } | null>(null);
  const [suggestion, setSuggestion] = useState<(GoalSuggestion & { title: string }) | null>(null);
  const [busy, setBusy] = useState<"load" | "save" | "delete" | null>(null);
  const [note, setNote] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  const run = useCallback(async (kind: "load" | "save" | "delete", work: () => Promise<string>) => {
    setBusy(kind);
    setNote(null);
    try {
      setNote({ tone: "ok", text: await work() });
    } catch (err) {
      setNote({ tone: "bad", text: err instanceof ApiError ? err.message : (err as Error).message });
    } finally {
      setBusy(null);
    }
  }, []);

  const options = useMemo<SelectOption[]>(
    () => [
      ...library.map((e) => ({
        value: `lib:${e.id}`,
        label: e.title,
        hint: e.summary || e.inputs,
        meta: plural(e.checks, "check"),
        group: CATEGORY_LABEL[e.category] ?? e.category,
        keywords: [e.id, e.os, ...e.evidence, ...e.tags].join(" "),
      })),
      ...goals.map((g) => ({
        value: `goal:${g.name}`,
        label: g.name,
        hint: g.has_definition_of_done ? g.title : "no definition of done — the harness would refuse it",
        meta: plural(g.checks, "check"),
        group: SAVED_GROUP,
        mark: g.has_definition_of_done ? undefined : <AlertTriangle className="size-3 text-brick-ink" aria-label="no definition of done" />,
        keywords: "saved",
      })),
    ],
    [library, goals],
  );

  const dirty = current.trim() !== "" && current !== defaultText && current !== loaded;
  const labelOf = (value: string) => options.find((o) => o.value === value)?.label ?? value;

  const load = useCallback(
    async (value: string) => {
      if (value.startsWith("lib:")) {
        const doc = await api.libraryEntry(value.slice(4));
        onLoad(doc.text, doc.slug);
        setLoaded(doc.text);
        setSaveName(doc.slug);
        const has = doc.seats !== undefined || doc.cap_usd !== undefined || doc.wall_clock !== undefined;
        setSuggestion(has ? { title: doc.title, seats: doc.seats, cap_usd: doc.cap_usd, wall_clock: doc.wall_clock } : null);
        return `Loaded ${doc.title} — ${plural(doc.checks, "check")}.`;
      }
      const doc = await api.goal(value.slice(5));
      onLoad(doc.text, doc.name);
      setLoaded(doc.text);
      setSaveName(doc.name);
      setSuggestion(null);
      return `Loaded ${doc.name} — ${plural(doc.checks, "check")}.`;
    },
    [onLoad],
  );

  const pick = (value: string) => {
    setSelected(value);
    setPending(null);
    if (!value) return;
    if (dirty) {
      setPending({ value, title: labelOf(value) });
      return;
    }
    void run("load", () => load(value));
  };

  const isSaved = selected.startsWith("goal:");
  const empty = !library.length && !goals.length;

  return (
    <div className="rounded-md border border-line bg-paper-2/40 p-3 space-y-2">
      <div className="flex items-center gap-1.5 text-[12px] font-medium text-ink-2">
        <BookOpen className="size-3.5" /> Goal library
        <span className="font-normal text-ink-3">· investigations from library/, your own goals from prompts/goals/</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          options={options}
          value={selected}
          onChange={pick}
          searchable
          searchPlaceholder="Search by title, evidence, OS or tag…"
          placeholder={empty ? (loading || libraryLoading ? "Loading…" : "No goals on the server") : "Pick an investigation or a saved goal…"}
          emptyText="Nothing matches."
          className="min-w-[22rem] flex-1"
          panelClassName="w-[min(36rem,calc(100vw-2rem))]"
          aria-label="Goal library"
          disabled={busy !== null}
        />
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={!isSaved || busy !== null}
          onClick={() =>
            run("delete", async () => {
              const name = selected.slice(5);
              await api.deleteGoal(name);
              setSelected("");
              onSaved();
              return `Deleted ${name}.`;
            })
          }
          aria-label="Delete the selected saved goal"
          title={isSaved ? "Delete this saved goal" : "Only a saved goal can be deleted here; the library is edited in the repo"}
        >
          <Trash2 className="size-3.5" />
        </Button>
      </div>

      {pending ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-paper px-2.5 py-1.5 text-[12px] text-ink-2">
          <span>
            The editor holds edits you have not saved. Replace them with <strong className="text-ink">{pending.title}</strong>?
          </span>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => {
              const { value } = pending;
              setPending(null);
              void run("load", () => load(value));
            }}
          >
            Replace
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              setPending(null);
              setSelected("");
            }}
          >
            Keep mine
          </Button>
        </div>
      ) : null}

      {suggestion ? (
        <p className="flex flex-wrap items-center gap-x-2 text-[11.5px] text-ink-2">
          <span>
            {suggestion.title} suggests
            {suggestion.seats !== undefined ? ` ${plural(suggestion.seats, "seat")}` : ""}
            {suggestion.cap_usd !== undefined ? `${suggestion.seats !== undefined ? "," : ""} a $${suggestion.cap_usd} cap` : ""}
            {suggestion.wall_clock !== undefined ? `${suggestion.seats !== undefined || suggestion.cap_usd !== undefined ? "," : ""} ${suggestion.wall_clock} min` : ""}
            . Yours to take or leave.
          </span>
          <button
            type="button"
            className="text-ink underline decoration-line underline-offset-2 hover:decoration-ink"
            onClick={() => {
              onSuggest({ seats: suggestion.seats, cap_usd: suggestion.cap_usd, wall_clock: suggestion.wall_clock });
              setSuggestion(null);
              setNote({ tone: "ok", text: "Applied the suggested team size, cap and wall clock to the form." });
            }}
          >
            Apply to the form
          </button>
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={saveName}
          onChange={(e) => setSaveName(e.target.value)}
          placeholder="name-for-this-goal"
          className="min-w-[13rem] flex-1 font-mono"
          aria-label="Name to save the goal under"
        />
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={!saveName.trim() || busy !== null}
          onClick={() =>
            run("save", async () => {
              const doc = await api.saveGoal(saveName.trim().toLowerCase(), current);
              onSaved();
              setLoaded(current);
              setSelected(`goal:${doc.name}`);
              return `Saved ${doc.name} — ${plural(doc.checks, "check")}.`;
            })
          }
        >
          <Save className="size-3.5" /> Save
        </Button>
      </div>

      {note ? (
        <p className={note.tone === "ok" ? "flex items-center gap-1 text-[11.5px] text-kelp-ink" : "text-[11.5px] text-brick-ink"}>
          {note.tone === "ok" ? <Check className="size-3.5" /> : null}
          {note.text}
        </p>
      ) : (
        <p className="text-[11.5px] text-ink-3">
          A library entry is a starting point: load it, name the evidence it should read, and save it as yours. Saving needs the server token, the same as starting a swarm; a goal without a
          <code className="mx-1">## Definition of done</code>
          is refused here as well as at kickoff.
        </p>
      )}
    </div>
  );
}
