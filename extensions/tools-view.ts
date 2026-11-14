/**
 * What the `tools` tool answers.
 *
 * With no name: one line a tool, the packs' tools grouped by pack and the
 * ones this run forged apart. With a name: that tool whole (its description,
 * parameters, example and how to call it). The whole library in one answer
 * was 472,000 characters in a run with five packs (the runs s571aaa and
 * s68ce47): a compaction followed within three turns after each of 65 calls,
 * and a seat's first one came in minute 2.
 *
 * The list is about 8,500 characters for the 153 tools of every pack: a
 * pack's tools are one string, a line a tool (the answer is pretty-printed
 * JSON, and an array put each line on its own indented, quoted row), and a
 * line is the tool's name and what its description says first, in a few
 * words. It was 18,367 characters with a first sentence of up to 140.
 */

export type ToolRow = { name: string; description?: string; by?: string; version?: number | string; pack?: string | null; runtime?: string; example?: string; params?: unknown; call?: string };

/** How long a tool's line may say what it does, in characters, past its name. */
export const ABOUT_MAX = 38;

/**
 * What a tool does, in a few words: its description's first clause, with the
 * asides in parentheses left out, cut at a word to `max` characters. A
 * description that opens with a label in capitals ("SENSITIVE: decrypt ...")
 * keeps the label, in lower case, before the clause it labels.
 */
export function aboutLine(description: string | undefined, max = ABOUT_MAX): string {
  let text = String(description ?? "").replace(/\s+/g, " ").trim();
  for (let i = 0; i < 3; i += 1) text = text.replace(/\s*\([^()]*\)/g, "");
  let label = "";
  const caps = /^([A-Z][A-Z-]{2,15}):\s+(.*)$/.exec(text);
  if (caps) {
    label = `${caps[1]!.toLowerCase()}: `;
    text = caps[2]!;
  }
  let first = (text.split(/(?<=[.:;])\s/)[0] ?? "").replace(/[.:;,]$/, "");
  const room = Math.max(8, max - label.length);
  if (first.length > room) {
    const cut = first.slice(0, room);
    const space = cut.lastIndexOf(" ");
    first = `${cut.slice(0, space > room / 2 ? space : room - 1).replace(/[,;:]$/, "")}…`;
  }
  return `${label}${first}`;
}

export type ToolsListing =
  | { ok: true; count: number; hint: string; packs: Record<string, string>; forged: string }
  | { ok: true; tool: ToolRow }
  | { ok: false; reason: string; nearest?: string[] };

/** The listing (no name), or one tool whole (a name; a name nobody has gets the nearest ones). */
export function toolsListing(all: readonly ToolRow[], name?: string): ToolsListing {
  if (name !== undefined && name !== "") {
    const hit = all.find((t) => t.name === name) ?? all.find((t) => t.name.toLowerCase() === name.toLowerCase());
    if (hit) return { ok: true, tool: hit };
    const want = name.toLowerCase();
    const nearest = all.map((t) => t.name).filter((n) => n.toLowerCase().includes(want) || want.includes(n.toLowerCase())).slice(0, 8);
    return { ok: false, reason: `no tool named ${name}: tools() lists every name`, ...(nearest.length ? { nearest } : {}) };
  }
  const packs: Record<string, string[]> = {};
  const forged: string[] = [];
  for (const t of [...all].sort((a, b) => a.name.localeCompare(b.name))) {
    const line = `${t.name}: ${aboutLine(t.description)}`;
    if (t.pack) (packs[t.pack] ??= []).push(line);
    else forged.push(`${line}${t.by ? ` (by ${t.by})` : ""}`);
  }
  return {
    ok: true,
    count: all.length,
    hint: all.length
      ? "A line a tool. tools(name: \"<tool>\") gives one whole: what it does, its parameters, an example, how to call it. Pack tools are tested in their pack; forged ones were written in this run."
      : "Nothing forged yet. make_tool writes one and shares it.",
    packs: Object.fromEntries(Object.keys(packs).sort().map((pack) => [pack, packs[pack]!.join("\n")])),
    forged: forged.join("\n"),
  };
}
