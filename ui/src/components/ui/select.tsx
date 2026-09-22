/**
 * The console's dropdown: one control for every list an operator picks from.
 *
 * A native `<select>` hands the list to the operating system. On macOS that is
 * a grey system menu floating over the page in the system font: no tokens, no
 * hint under an option, no group headings, no filter, and fifty models in one
 * column. The goal picker already stopped doing that; this is the same control
 * generalised, so a model, an evidence set, a guard mode and a trace filter are
 * all the same object with the same keyboard.
 *
 * The panel is portalled and positioned against the trigger, so it escapes the
 * scrolling panels and `overflow-hidden` cards the console is built from, and
 * flips above the trigger when the space below runs out.
 *
 * Keyboard: ↑ ↓ move, Home / End jump, Enter chooses, Escape closes, and with
 * no filter field a typed prefix jumps to the option that starts with it.
 * A filter appears on its own once a list is longer than `SEARCH_AT`.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown, Search } from "lucide-react";
import { cn } from "@/lib/utils";

export type SelectOption = {
  value: string;
  /** What the closed control shows, and the first line of the option. */
  label: string;
  /** The second line: what this choice means, or what it costs. */
  hint?: string;
  /** Right-aligned, for a count or a size. */
  meta?: string;
  /** A heading this option sits under. Options keep the order they are given. */
  group?: string;
  /** A dot, an icon: anything that belongs before the label. */
  mark?: React.ReactNode;
  disabled?: boolean;
  /** Extra words the filter should match, such as a path the label shortens. */
  keywords?: string;
};

/** Longer than this and the panel grows a filter of its own. */
const SEARCH_AT = 8;
const PANEL_MAX = 320;

type Size = "sm" | "md";

export function Select({
  options,
  value,
  onChange,
  placeholder = "Choose…",
  disabled,
  size = "md",
  mono,
  searchable,
  searchPlaceholder,
  emptyText = "Nothing to choose from.",
  className,
  panelClassName,
  "aria-label": ariaLabel,
  id,
}: {
  options: SelectOption[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  size?: Size;
  /** Model ids, set names and tool names are read as strings, so they set in mono. */
  mono?: boolean;
  searchable?: boolean;
  searchPlaceholder?: string;
  emptyText?: string;
  className?: string;
  panelClassName?: string;
  "aria-label"?: string;
  id?: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const typed = useRef<{ text: string; at: number }>({ text: "", at: 0 });
  const [box, setBox] = useState<{ top: number; left: number; width: number; flip: boolean } | null>(null);
  const listId = useId();

  const withFilter = searchable ?? options.length > SEARCH_AT;

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter((o) =>
      `${o.label} ${o.hint ?? ""} ${o.keywords ?? ""}`.toLowerCase().includes(q),
    );
  }, [options, query]);

  const current = options.find((o) => o.value === value);

  /** Anchor the panel to the trigger in viewport coordinates, flipping when it would not fit. */
  const place = useCallback(() => {
    const t = trigger.current;
    if (!t) return;
    const r = t.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const flip = below < Math.min(PANEL_MAX, 240) && r.top > below;
    setBox({ top: flip ? r.top - 4 : r.bottom + 4, left: r.left, width: r.width, flip });
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const onScroll = () => place();
    // `true` so a scroll inside any ancestor panel moves the popup with it.
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (trigger.current?.contains(target) || panel.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    const at = options.findIndex((o) => o.value === value);
    setCursor(at >= 0 ? at : 0);
    if (withFilter) requestAnimationFrame(() => field.current?.focus());
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the moving cursor in view without scrolling the page behind the panel.
  useEffect(() => {
    if (!open) return;
    panel.current?.querySelector<HTMLElement>(`[data-cursor="true"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor, open, shown.length]);

  const close = (focus = true) => {
    setOpen(false);
    if (focus) trigger.current?.focus();
  };

  const choose = (option: SelectOption) => {
    if (option.disabled) return;
    onChange(option.value);
    close();
  };

  /** One step, skipping the options that cannot be chosen. */
  const move = (from: number, step: number) => {
    for (let i = from + step; i >= 0 && i < shown.length; i += step) {
      if (!shown[i].disabled) return i;
    }
    return from;
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!open) return setOpen(true);
      setCursor((c) => move(c, 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) return setOpen(true);
      setCursor((c) => move(c, -1));
    } else if (e.key === "Home" && open) {
      e.preventDefault();
      setCursor(move(-1, 1));
    } else if (e.key === "End" && open) {
      e.preventDefault();
      setCursor(move(shown.length, -1));
    } else if (e.key === "Enter" || (e.key === " " && !withFilter)) {
      if (!open) {
        e.preventDefault();
        return setOpen(true);
      }
      e.preventDefault();
      const pick = shown[cursor];
      if (pick) choose(pick);
    } else if (e.key === "Escape") {
      if (!open) return;
      e.preventDefault();
      close();
    } else if (e.key === "Tab" && open) {
      close(false);
    } else if (!withFilter && open && e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
      // Type-ahead, the one thing a native select does well.
      const now = Date.now();
      typed.current = { text: now - typed.current.at > 900 ? e.key : typed.current.text + e.key, at: now };
      const prefix = typed.current.text.toLowerCase();
      const at = shown.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(prefix));
      if (at >= 0) setCursor(at);
    }
  };

  let lastGroup: string | undefined;

  return (
    <>
      <button
        ref={trigger}
        id={id}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={onKeyDown}
        className={cn(
          "flex w-full items-center gap-2 rounded-lg border border-line bg-card text-left text-ink transition-colors",
          "hover:border-line-2 disabled:cursor-not-allowed disabled:opacity-50",
          "focus-visible:border-kelp focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kelp/25",
          size === "sm" ? "h-8 px-2.5 text-[12.5px]" : "h-10 px-3 text-[13px]",
          open && "border-kelp ring-2 ring-kelp/15",
          className,
        )}
      >
        {current?.mark ? <span className="flex shrink-0 items-center">{current.mark}</span> : null}
        <span className={cn("truncate", mono && "font-mono", current ? "text-ink" : "text-ink-3")}>
          {current ? current.label : placeholder}
        </span>
        {current?.meta ? <span className="ml-auto shrink-0 tabular text-[11px] text-ink-3">{current.meta}</span> : null}
        <ChevronDown
          className={cn("size-4 shrink-0 text-ink-3 transition-transform", current?.meta ? "" : "ml-auto", open && "rotate-180")}
        />
      </button>

      {open && box
        ? createPortal(
            <div
              ref={panel}
              style={{
                position: "fixed",
                left: box.left,
                top: box.flip ? undefined : box.top,
                bottom: box.flip ? window.innerHeight - box.top : undefined,
                minWidth: box.width,
                maxWidth: Math.max(box.width, 420),
              }}
              className={cn(
                "z-50 overflow-hidden rounded-xl border border-line bg-paper shadow-[0_12px_32px_rgba(23,22,21,.16)]",
                panelClassName,
              )}
            >
              {withFilter ? (
                <div className="flex items-center gap-2 border-b border-line px-3 py-2">
                  <Search className="size-3.5 shrink-0 text-ink-3" />
                  <input
                    ref={field}
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setCursor(0);
                    }}
                    onKeyDown={onKeyDown}
                    placeholder={searchPlaceholder ?? `Filter ${options.length}…`}
                    className="h-6 w-full border-0 bg-transparent p-0 text-[13px] text-ink outline-none placeholder:text-ink-3"
                    aria-label="Filter the list"
                    aria-controls={listId}
                  />
                </div>
              ) : null}
              <ul
                id={listId}
                role="listbox"
                aria-label={ariaLabel}
                className="m-0 list-none overflow-y-auto p-1"
                style={{ maxHeight: PANEL_MAX }}
              >
                {shown.length === 0 ? (
                  <li className="px-3 py-4 text-center text-[12.5px] text-ink-3">
                    {query ? `Nothing matches “${query}”.` : emptyText}
                  </li>
                ) : (
                  shown.map((option, i) => {
                    const selected = option.value === value;
                    const head = option.group && option.group !== lastGroup ? option.group : null;
                    lastGroup = option.group;
                    return (
                      <li key={option.value}>
                        {head ? (
                          <div className="label-caps sticky top-0 bg-paper px-2.5 pb-1 pt-2 text-ink-3">{head}</div>
                        ) : null}
                        <button
                          type="button"
                          role="option"
                          aria-selected={selected}
                          aria-disabled={option.disabled || undefined}
                          data-cursor={i === cursor ? "true" : undefined}
                          onMouseEnter={() => !option.disabled && setCursor(i)}
                          onClick={() => choose(option)}
                          className={cn(
                            "flex w-full items-start gap-2.5 rounded-lg px-2.5 py-1.5 text-left transition-colors",
                            i === cursor && !option.disabled ? "bg-paper-2" : "bg-transparent",
                            option.disabled && "cursor-not-allowed opacity-45",
                          )}
                        >
                          <Check className={cn("mt-0.5 size-3.5 shrink-0", selected ? "text-kelp" : "opacity-0")} />
                          {option.mark ? <span className="mt-0.5 flex shrink-0 items-center">{option.mark}</span> : null}
                          <span className="min-w-0 flex-1">
                            <span className={cn("block truncate text-[12.5px] text-ink", mono && "font-mono")}>
                              {option.label}
                            </span>
                            {option.hint ? (
                              <span className="mt-0.5 block text-[11px] leading-[1.4] text-ink-3">{option.hint}</span>
                            ) : null}
                          </span>
                          {option.meta ? (
                            <span className="mt-0.5 shrink-0 tabular text-[11px] text-ink-3">{option.meta}</span>
                          ) : null}
                        </button>
                      </li>
                    );
                  })
                )}
              </ul>
              {withFilter ? (
                <p className="m-0 border-t border-line bg-paper-2/60 px-3 py-1.5 text-[11px] text-ink-3">
                  ↑ ↓ to move · Enter chooses · Esc closes
                </p>
              ) : null}
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
