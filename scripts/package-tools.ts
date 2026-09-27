#!/usr/bin/env node
/**
 * A package's two checks beyond its MANIFEST.txt (swarm.sh package, verify):
 *
 * redact <sandbox> <package dir>
 *   What a sensitive ledger entry says, and the objects it cites, are taken
 *   out of a package before it is handed over (GDPR or similar laws ask for
 *   no more than the purpose needs). A chained file keeps its chain: a
 *   redacted line is replaced by `{"redacted": true, "line_sha256": <the
 *   line's own hash>}` (a ledger entry keeps its seq, kind, prev and hash),
 *   so a recipient re-walks every chain and sees which lines it cannot read.
 *   Any other text file of the package with a sensitive entry's words in it
 *   has them replaced; a file a sensitive entry cites is replaced whole.
 *   REDACTIONS.txt lists every change with the file's sha256 before and
 *   after, so the owner of the original can match it.
 *
 * components <sandbox> <package dir>
 *   COMPONENTS.json: each part a recipient holds the record to (the verdict,
 *   its anchor, its signature and token, the index of work/ custody sealed,
 *   the trace, the ledger, its attestations, the store's journal, the
 *   examiner's review), present or absent with why. Written before the
 *   manifest, so it is under the manifest's hash and its signature: a part
 *   taken out of a package, and out of the list, breaks the signature.
 *
 * verify <package dir>
 *   Every part the package should carry is there or declared absent; the
 *   chains it carries, re-walked (every ledger entry's core recomputed, a
 *   redacted one's hash taken as it stands): the trace, the ledger, its
 *   attestations, the store's journal and the examiner's review, each held
 *   to the custody verdict's seal (its lines and heads), the verdict to its
 *   anchor; every packaged work/ file held to the index custody sealed, and
 *   that index to the anchor.
 *
 * Nothing here knows a tool or an evidence format.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, lstatSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ledgerHash, readLedger, verifyAttestationChain, verifyDisputeChain, type LedgerEntry } from "../extensions/protocol.ts";

const sha256 = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");
const REDACTED = "[redacted: marked sensitive]";

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const d of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, d.name);
    if (d.isDirectory()) out.push(...walk(p));
    else if (d.isFile()) out.push(p);
  }
  return out;
}

/** The words a sensitive standing entry says, long enough to be told from ordinary text. */
function sensitiveWords(entries: LedgerEntry[]): string[] {
  const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
  const words = new Set<string>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    // A corrected sensitive entry is still sensitive: both say the secret.
    void replaced;
    for (const w of [e.value, e.evidence ?? "", e.attribution?.subject ?? "", ...(e.locators ?? []).map((l) => l.at)]) {
      if (w && w.trim().length >= 6) words.add(w.trim());
      // A key, a token or a password is said in other words elsewhere: each
      // long run with a digit in it is taken on its own too.
      for (const t of (w ?? "").match(/[^\s"'`,;()]{12,}/g) ?? []) if (/\d/.test(t)) words.add(t);
    }
  }
  return [...words].sort((a, b) => b.length - a.length);
}

/** Package paths a sensitive entry's refs name, as the package lays them out. */
function citedPaths(entries: LedgerEntry[]): string[] {
  const out = new Set<string>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    for (const r of e.refs ?? []) {
      const m = /^job:(j\d{6})\/(.+)$/.exec(r);
      if (!m) continue;
      if (/^(stdout\.log|stderr\.log)$/.test(m[2])) out.add(`store/jobs/${m[1]}/${m[2]}`);
      else out.add(`store/jobs/${m[1]}/out/${m[2].replace(/^out\//, "")}`);
    }
  }
  return [...out];
}

export async function redactPackage(sandbox: string, dir: string): Promise<{ entries: number; files: number; lines: number }> {
  const entries = await readLedger(sandbox);
  const words = sensitiveWords(entries);
  const sensitiveSeqs = new Set(entries.filter((e) => e.sensitive).map((e) => e.seq));
  const log: string[] = [];
  let lines = 0;
  const change = (rel: string, before: Buffer, after: Buffer | string, why: string) => {
    writeFileSync(join(dir, rel), after);
    log.push(`${sha256(before)}  ${sha256(after)}  ${rel}  ${why}`);
  };
  // The ledger: a sensitive entry's line keeps what chains it.
  const ledgerRel = "ledger.jsonl";
  if (existsSync(join(dir, ledgerRel))) {
    const before = readFileSync(join(dir, ledgerRel));
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim()) return l;
        try {
          const e = JSON.parse(l) as LedgerEntry;
          if (!sensitiveSeqs.has(e.seq)) return l;
          lines += 1;
          return JSON.stringify({ v: e.v, seq: e.seq, kind: e.kind, redacted: true, line_sha256: sha256(l), ...(e.prev ? { prev: e.prev } : {}), ...(e.hash ? { hash: e.hash } : {}), ...(e.refs ? { refs: e.refs } : {}) });
        } catch {
          return l;
        }
      })
      .join("\n");
    if (out !== before.toString("utf8")) change(ledgerRel, before, out, `${sensitiveSeqs.size} sensitive entr${sensitiveSeqs.size === 1 ? "y" : "ies"} replaced by their seq, kind, chain hashes and line hash`);
  }
  // The trace: a line with a sensitive entry's words is replaced by its own hash, which the next line's prev names.
  for (const rel of ["trace/events.jsonl"]) {
    if (!existsSync(join(dir, rel)) || !words.length) continue;
    const before = readFileSync(join(dir, rel));
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim() || !words.some((w) => l.includes(w) || l.includes(JSON.stringify(w).slice(1, -1)))) return l;
        n += 1;
        return JSON.stringify({ redacted: true, line_sha256: sha256(l) });
      })
      .join("\n");
    lines += n;
    if (n) change(rel, before, out, `${n} line(s) holding a sensitive entry's words replaced by their own sha256`);
  }
  // The store's journal: a job's command can carry a secret too; a line is replaced keeping its seq, its prev and its own hash.
  for (const rel of ["store/journal.jsonl"]) {
    if (!existsSync(join(dir, rel)) || !words.length) continue;
    const before = readFileSync(join(dir, rel));
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim() || !words.some((w) => l.includes(w) || l.includes(JSON.stringify(w).slice(1, -1)))) return l;
        n += 1;
        const o = JSON.parse(l) as { v?: number; seq?: number; prev?: string | null; type?: string; job?: string };
        return JSON.stringify({ v: o.v, seq: o.seq, type: o.type, ...(o.job ? { job: o.job } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev ?? null });
      })
      .join("\n");
    lines += n;
    if (n) change(rel, before, out, `${n} journal line(s) holding a sensitive entry's words replaced, keeping seq, prev and their own sha256`);
  }
  // The examiner's review: a note can say what an entry said; a line is replaced keeping its seq, action and prev, and its own hash.
  for (const rel of ["review.jsonl"]) {
    if (!existsSync(join(dir, rel)) || !words.length) continue;
    const before = readFileSync(join(dir, rel));
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim() || !words.some((w) => l.includes(w) || l.includes(JSON.stringify(w).slice(1, -1)))) return l;
        n += 1;
        const o = JSON.parse(l) as { v?: number; seq?: number; action?: string; prev?: string | null };
        return JSON.stringify({ v: o.v, seq: o.seq, action: o.action, redacted: true, line_sha256: sha256(l), prev: o.prev ?? null });
      })
      .join("\n");
    lines += n;
    if (n) change(rel, before, out, `${n} review line(s) holding a sensitive entry's words replaced, keeping seq, action, prev and their own sha256`);
  }
  // A file a sensitive entry cites, whole.
  for (const rel of citedPaths(entries)) {
    if (!existsSync(join(dir, rel))) continue;
    const before = readFileSync(join(dir, rel));
    change(rel, before, `${REDACTED}: cited by a sensitive ledger entry; its sha256 before redaction is ${sha256(before)}\n`, "cited by a sensitive entry, replaced whole");
  }
  // Every other text file: the words replaced where they appear.
  const skip = new Set(["MANIFEST.txt", "MANIFEST.txt.sig", "SIGNER.txt", "signer.pub", "REDACTIONS.txt", "COMPONENTS.json", ledgerRel, "trace/events.jsonl", "store/journal.jsonl", "ledger-attestations.jsonl", "review.jsonl"]);
  let files = 0;
  if (words.length) {
    for (const abs of walk(dir)) {
      const rel = relative(dir, abs);
      if (skip.has(rel) || lstatSync(abs).size > 64 * 1024 * 1024) continue;
      const before = readFileSync(abs);
      if (before.subarray(0, 8192).includes(0)) continue;
      let text = before.toString("utf8");
      let hit = false;
      for (const w of words) {
        for (const form of [w, JSON.stringify(w).slice(1, -1)]) {
          if (form && text.includes(form)) {
            text = text.split(form).join(REDACTED);
            hit = true;
          }
        }
      }
      if (hit) {
        files += 1;
        change(rel, before, text, "a sensitive entry's words replaced");
      }
    }
  }
  writeFileSync(
    join(dir, "REDACTIONS.txt"),
    [
      "Redactions",
      "==========",
      "",
      `This package was made with --redact. ${sensitiveSeqs.size} ledger entr${sensitiveSeqs.size === 1 ? "y was" : "ies were"} marked sensitive (seq ${[...sensitiveSeqs].join(", ") || "none"}).`,
      "What they say, and the objects they cite, are not in it. A chained file keeps its chain: a redacted",
      "line carries the sha256 of the line it replaces, which the next line's prev names. Each change below",
      "is the file's sha256 before and after, so the owner of the original can match it.",
      "",
      "sha256 before                                                    sha256 after                                                     path  why",
      ...log,
      "",
    ].join("\n"),
  );
  return { entries: sensitiveSeqs.size, files, lines };
}

// --- verify ------------------------------------------------------------------------------

/** The trace chain, a redacted line counting as the line it replaced. */
function traceChain(text: string): { ok: boolean; lines: number; redacted: number; detail: string; lineHashes: string[] } {
  let previous = "";
  let started = false;
  let n = 0;
  let redacted = 0;
  const hashes: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    n += 1;
    let o: { prev?: unknown; redacted?: unknown; line_sha256?: unknown };
    try {
      o = JSON.parse(line);
    } catch {
      return { ok: false, lines: n, redacted, detail: `line ${n} is not JSON`, lineHashes: hashes };
    }
    let own = sha256(line);
    if (o.redacted === true && typeof o.line_sha256 === "string") {
      redacted += 1;
      own = o.line_sha256;
      previous = own;
      hashes.push(own);
      started = true;
      continue;
    }
    if (typeof o.prev === "string") {
      started = true;
      if (o.prev !== previous) return { ok: false, lines: n, redacted, detail: `line ${n}'s prev does not name the line before it`, lineHashes: hashes };
    } else if (started) return { ok: false, lines: n, redacted, detail: `line ${n} has no prev after chained lines`, lineHashes: hashes };
    previous = own;
    hashes.push(own);
  }
  return { ok: true, lines: n, redacted, detail: `${n} lines, chain intact${redacted ? `, ${redacted} redacted (their hashes kept)` : ""}`, lineHashes: hashes };
}

/**
 * The ledger chain, walked as verifyLedgerChain walks it, a redacted entry's
 * hash taken as it stands (its core is not in the package): every other
 * entry's core is recomputed and must give its hash, whatever came before
 * it. A walk that recomputed only the first core let a rewritten entry
 * after a redaction pass on its prev alone.
 */
export function ledgerChain(text: string): { ok: boolean; entries: number; redacted: number; head: string | null; detail: string } {
  const lines = text.split("\n").filter((l) => l.trim());
  let last = "genesis";
  let chained = 0;
  let redacted = 0;
  let newest = 1;
  let n = 0;
  const broken = (why: string) => ({ ok: false, entries: n, redacted, head: null, detail: `broken at entry ${n} (${why})` });
  for (const l of lines) {
    n += 1;
    let e: LedgerEntry & { redacted?: boolean };
    try {
      e = JSON.parse(l) as LedgerEntry & { redacted?: boolean };
    } catch {
      return broken("not json");
    }
    // Versions only go up along the chain, as verifyLedgerChain holds them (ledgerHash dispatches on each).
    const version = typeof e.v === "number" ? e.v : 1;
    if (version < newest) return broken(`a version ${version} entry after version ${newest} ones`);
    newest = version;
    if (e.redacted === true) {
      // Its core is not here: its hash is taken, and it must name the entry before it.
      if (e.prev !== last) return broken(`redacted entry ${e.seq}'s prev does not name the entry before it`);
      if (typeof e.hash !== "string") return broken(`redacted entry ${e.seq} carries no hash`);
      redacted += 1;
      chained += 1;
      last = e.hash;
      continue;
    }
    if (!e.prev && !e.hash) {
      if (chained > 0) return broken("an entry without the chain after chained ones");
      last = ledgerHash(e, "genesis");
      continue;
    }
    if (e.prev !== last) return broken("prev does not name the entry before it");
    if (e.hash !== ledgerHash(e, e.prev)) return broken("the entry's core was rewritten");
    chained += 1;
    last = e.hash;
  }
  const head = chained ? last : null;
  return { ok: true, entries: n, redacted, head, detail: `${n} entries, chain intact${redacted ? `, ${redacted} redacted (their hashes kept, their cores not in the package)` : ""}` };
}

/** The journal's chain, a redacted line counting as the line it replaced; each line's hash and type, to hold it to a sealed head. */
function journalChain(text: string): { ok: boolean; lines: number; redacted: number; head: string | null; detail: string; hashes: string[]; types: string[] } {
  let prev: string | null = null;
  let n = 0;
  let redacted = 0;
  const hashes: string[] = [];
  const types: string[] = [];
  for (const raw of text.split("\n")) {
    if (!raw) continue;
    let o: { seq?: number; prev?: string | null; redacted?: boolean; line_sha256?: string; type?: string };
    try {
      o = JSON.parse(raw);
    } catch {
      return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} is not JSON)`, hashes, types };
    }
    if ((o.prev ?? null) !== prev) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} does not chain to the line before)`, hashes, types };
    if (o.seq !== n) return { ok: false, lines: n, redacted, head: null, detail: `CHAIN BROKEN (line ${n + 1} has seq ${o.seq})`, hashes, types };
    prev = o.redacted && o.line_sha256 ? o.line_sha256 : sha256(raw);
    hashes.push(prev);
    types.push(String(o.type ?? ""));
    if (o.redacted) redacted += 1;
    n += 1;
  }
  return { ok: true, lines: n, redacted, head: prev, detail: `${n} lines, chain intact${redacted ? `, ${redacted} redacted (their hashes kept)` : ""}`, hashes, types };
}

/** The examiner's review chain (scripts/review.ts), a redacted line counting as the line it replaced. */
function reviewChain(text: string): { ok: boolean; lines: number; redacted: number; detail: string; signed: { ledger_head?: string; ledger_entries?: number; report_path?: string; report_sha256?: string | null; examiner?: string; at?: string } | null } {
  let prev: string | null = null;
  let n = 0;
  let redacted = 0;
  let signed: ReturnType<typeof reviewChain>["signed"] = null;
  for (const raw of text.split("\n")) {
    if (!raw) continue;
    n += 1;
    let o: { seq?: number; prev?: string | null; action?: string; redacted?: boolean; line_sha256?: string };
    try {
      o = JSON.parse(raw);
    } catch {
      return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} is not JSON)`, signed };
    }
    if (o.seq !== n) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} says seq ${o.seq})`, signed };
    if ((o.prev ?? null) !== prev) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} does not follow the line before it)`, signed };
    if (!["accept", "reject", "amend", "sign"].includes(String(o.action))) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} has no known action)`, signed };
    if (o.redacted) redacted += 1;
    else if (o.action === "sign") signed = o as NonNullable<typeof signed>;
    prev = o.redacted && o.line_sha256 ? o.line_sha256 : sha256(raw);
  }
  return { ok: true, lines: n, redacted, detail: `${n} act(s), chain intact${redacted ? `, ${redacted} redacted` : ""}`, signed };
}

/**
 * Every part a recipient holds the record to, by its path in the package:
 * what it is and why it would be absent. `core` parts must be there or be
 * declared absent; `sealed` parts must be there when the verdict sealed any
 * of them; `since` parts were first packaged then, so a package from before
 * it carries none and says so.
 */
export const PACKAGE_COMPONENTS: ReadonlyArray<{ path: string; source: string; what: string; absent: string; core?: true; sealed?: "trace" | "ledger" | "attestations" | "disputes" | "journal" | "artifacts"; since?: string }> = [
  { path: "custody.json", source: "custody.json", what: "the custody verdict", absent: "no custody was taken for this run (swarm.sh stop takes it)", core: true },
  { path: "trace/custody-anchor.json", source: "<sandbox>.custody-anchor.json", what: "the verdict's anchor, kept outside the run", absent: "the kickoff wrote no custody anchor for this run", core: true },
  { path: "custody.json.sig", source: "custody.json.sig", what: "the verdict's signature", absent: "custody.json was not signed (--custody-sign-key)" },
  { path: "custody.json.tsr", source: "custody.json.tsr", what: "the verdict's RFC 3161 timestamp token", absent: "custody.json was not timestamped (--custody-timestamp-url)" },
  { path: "artifacts.sealed.json", source: "artifacts.json", what: "the index of work/ custody sealed at stop", absent: "no custody verdict indexed work/", sealed: "artifacts", since: "2026-09-27" },
  { path: "trace/events.jsonl", source: "traces/events.jsonl", what: "the trace", absent: "the run has no trace", sealed: "trace" },
  { path: "trace/trace-anchor.json", source: "<sandbox>.trace-anchor.json", what: "the trace's anchor", absent: "no collector anchored the trace" },
  { path: "ledger.jsonl", source: "ledger/entries.jsonl", what: "the ledger", absent: "nothing was recorded", sealed: "ledger" },
  { path: "ledger-attestations.jsonl", source: "ledger/attestations.jsonl", what: "the ledger's attestations", absent: "no entry has a second author", sealed: "attestations" },
  { path: "ledger-disputes.jsonl", source: "ledger/disputes.jsonl", what: "the agents' disputes of entries", absent: "no agent disputed an entry", sealed: "disputes", since: "2026-09-27" },
  { path: "store/journal.jsonl", source: "store/journal.jsonl", what: "the store's journal", absent: "the run had no job service", sealed: "journal" },
  { path: "trace/journal-anchor.json", source: "<sandbox>.journal-anchor.json", what: "the journal's anchor", absent: "the run had no job service" },
  { path: "review.jsonl", source: "<runs>/reviews/<run>.jsonl", what: "the examiner's review", absent: "no examiner has reviewed this run", since: "2026-09-27" },
];

/** COMPONENTS.json for a package: each part present, or absent with why. */
export function writeComponents(sandbox: string, dir: string): { present: number; absent: number } {
  const custodyText = existsSync(join(sandbox, "custody.json")) ? readFileSync(join(sandbox, "custody.json"), "utf8") : null;
  let custody: { artifacts?: unknown } | null = null;
  try {
    custody = custodyText ? (JSON.parse(custodyText) as { artifacts?: unknown }) : null;
  } catch {
    custody = null;
  }
  const out = PACKAGE_COMPONENTS.map((c) => {
    if (existsSync(join(dir, c.path))) return { path: c.path, what: c.what, present: true };
    let reason = c.absent;
    if (c.sealed === "artifacts") reason = !custodyText ? "no custody was taken, so nothing sealed work/" : !custody?.artifacts ? "the verdict indexed no work files (a custody from before the index was sealed, or one that did not reach it)" : "artifacts.json, the index the verdict sealed, is not in the run (or is not a regular file there)";
    else if (!c.source.startsWith("<") && existsSync(join(sandbox, c.source))) reason = `in the run, and not copied: it is not a regular file there, or it is empty`;
    return { path: c.path, what: c.what, present: false, reason };
  });
  writeFileSync(
    join(dir, "COMPONENTS.json"),
    `${JSON.stringify({ v: 1, note: "Each part a recipient holds this record to: present, or absent with why. It is under MANIFEST.txt, and its signature: a part taken out of the package, and out of this list, breaks it. swarm.sh verify fails on a part that is missing and not declared absent.", components: out }, null, 2)}\n`,
  );
  return { present: out.filter((c) => c.present).length, absent: out.filter((c) => !c.present).length };
}

/** LEFT-BEHIND.txt's rows: each binary left in the sandbox, by path, with its sha256. */
function leftBehind(text: string | null): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of (text ?? "").split("\n")) {
    const m = /^([0-9a-f]{64})\s+\d+\s+(work\/.+)$/.exec(line);
    if (m) out.set(m[2], m[1]);
  }
  return out;
}

/** REDACTIONS.txt's rows: each file changed by redaction, with its sha256 before and after. */
function redactions(text: string | null): Map<string, { before: string; after: string }> {
  const out = new Map<string, { before: string; after: string }>();
  for (const line of (text ?? "").split("\n")) {
    const m = /^([0-9a-f]{64})  ([0-9a-f]{64})  (.+?)  \S.*$/.exec(line);
    if (m) out.set(m[3], { before: m[1], after: m[2] });
  }
  return out;
}

function packagedFiles(dir: string, under: string): string[] {
  const root = join(dir, under);
  if (!existsSync(root)) return [];
  return walk(root).map((abs) => relative(dir, abs).split("\\").join("/")).sort();
}

type SealShape = { trace?: { lines?: number; last_line_sha256?: string | null }; ledger?: { entries?: number; head?: string | null }; attestations?: { lines?: number; head?: string | null }; disputes?: { lines?: number; head?: string | null }; journal?: { lines?: number; head?: string | null } | null };

export function verifyPackage(dir: string): { ok: boolean; lines: string[] } {
  const out: string[] = [];
  let ok = true;
  const fail = (line: string) => {
    out.push(line);
    ok = false;
  };
  const read = (rel: string) => (existsSync(join(dir, rel)) ? readFileSync(join(dir, rel), "utf8") : null);
  const redacted = redactions(read("REDACTIONS.txt"));
  const custodyText = read("custody.json");
  type Verdict = { seal?: SealShape; artifacts?: { index_sha256?: string } | null };
  let custody: Verdict | null = null;
  try {
    custody = custodyText ? (JSON.parse(custodyText) as Verdict) : null;
  } catch {
    fail("Verdict:      custody.json is not JSON");
  }
  const seal = custody?.seal;
  const anchorText = read("trace/custody-anchor.json");
  let lastAnchored: { sha256?: string; artifacts_sha256?: string | null; signature?: { file?: string; error?: string }; timestamp?: { file?: string; error?: string } } | undefined;
  try {
    lastAnchored = anchorText ? ((JSON.parse(anchorText) as { custody?: Array<NonNullable<typeof lastAnchored>> }).custody ?? []).at(-1) : undefined;
  } catch {
    fail("Anchor:       trace/custody-anchor.json is not JSON");
  }
  // A file whose sha256 is anchored: the same bytes, or redacted from those bytes (REDACTIONS.txt names its sha256 before).
  const heldTo = (rel: string, text: string, want: string | null | undefined): "matches" | "redacted" | "differs" => {
    const have = sha256(text);
    if (have === want) return "matches";
    const r = redacted.get(rel);
    return r && r.before === want && r.after === have ? "redacted" : "differs";
  };

  // Every part: there, or declared absent.
  const componentsText = read("COMPONENTS.json");
  let declared: Map<string, { present: boolean; reason?: string }> | null = null;
  try {
    declared = componentsText ? new Map(((JSON.parse(componentsText) as { components?: Array<{ path: string; present: boolean; reason?: string }> }).components ?? []).map((c) => [c.path, c])) : null;
  } catch {
    fail("Components:   COMPONENTS.json is not JSON");
  }
  const expected = (c: (typeof PACKAGE_COMPONENTS)[number]): string | null => {
    if (!seal && !custody) return null;
    switch (c.sealed) {
      case "trace":
        return (seal?.trace?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.trace?.lines} trace lines` : null;
      case "ledger":
        return (seal?.ledger?.entries ?? 0) > 0 ? `the verdict sealed ${seal?.ledger?.entries} ledger entries` : null;
      case "attestations":
        return (seal?.attestations?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.attestations?.lines} attestation lines` : null;
      case "disputes":
        return (seal?.disputes?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.disputes?.lines} dispute lines` : null;
      case "journal":
        return seal?.journal ? `the verdict sealed a journal of ${seal.journal.lines} lines` : null;
      case "artifacts":
        return custody?.artifacts?.index_sha256 ? "the verdict sealed an index of work/" : null;
      default:
        if (c.path === "custody.json.sig" && lastAnchored?.signature?.file) return "the anchor says the verdict was signed";
        if (c.path === "custody.json.tsr" && lastAnchored?.timestamp?.file) return "the anchor says the verdict was timestamped";
        return null;
    }
  };
  const missing: string[] = [];
  const absent: string[] = [];
  const notCarried: string[] = [];
  for (const c of PACKAGE_COMPONENTS) {
    if (existsSync(join(dir, c.path))) {
      if (declared && declared.get(c.path)?.present === false) missing.push(`${c.path} (declared absent, and there)`);
      continue;
    }
    const d = declared?.get(c.path);
    const want = expected(c);
    if (d?.present === true) missing.push(`${c.path} (declared present)`);
    else if (want) missing.push(`${c.path} (${want}${d ? `; declared absent: ${d.reason ?? "no reason"}` : ""})`);
    else if (d) absent.push(`${c.path}: ${d.reason ?? "no reason given"}`);
    else if (!declared && c.since) notCarried.push(c.path);
    else if (c.core) missing.push(`${c.path} (not declared absent)`);
    else absent.push(`${c.path}: not there (not declared)`);
  }
  if (missing.length) fail(`Components:   MISSING, AND NOT DECLARED ABSENT OR AGAINST THE SEAL: ${missing.join("; ")}`);
  else out.push(`Components:   ${declared ? "every part is there or declared absent (COMPONENTS.json)" : "NO COMPONENTS.json (a package made before 2026-09-27): each part held to the verdict's seal only"}`);
  if (absent.length) out.push(`Absent:       ${absent.join("; ")}`);
  if (notCarried.length) out.push(`Not carried:  ${notCarried.join(", ")} (packaged since 2026-09-27; this package is older)`);

  // The verdict against the anchor it was written with.
  if (custodyText && lastAnchored) {
    const held = heldTo("custody.json", custodyText, lastAnchored.sha256);
    if (held === "differs") fail("Verdict:      custody.json DOES NOT MATCH the last verdict its anchor names");
    else out.push(`Verdict:      custody.json ${held === "matches" ? "matches the last verdict its anchor names" : "was redacted (REDACTIONS.txt names its sha256 before redaction, the one its anchor names)"}`);
  } else out.push(`Verdict:      ${custodyText ? "no anchor in the package to hold it to" : "no custody.json in the package"}`);
  // The trace.
  const trace = read("trace/events.jsonl");
  if (trace !== null) {
    const t = traceChain(trace);
    let sealNote = "";
    if (seal?.trace?.lines) {
      const at = t.lineHashes[seal.trace.lines - 1];
      const same = at === seal.trace.last_line_sha256;
      sealNote = same ? `; the ${seal.trace.lines} lines the verdict sealed are there, ${t.lines - seal.trace.lines} after` : "; THE SEALED LINE IS NOT THE ONE THE VERDICT NAMES";
      ok &&= same;
    }
    out.push(`Trace:        ${t.detail}${sealNote}`);
    ok &&= t.ok;
  }
  // The ledger and its attestations.
  const ledger = read("ledger.jsonl");
  let ledgerHead: string | null = null;
  if (ledger !== null) {
    const l = ledgerChain(ledger);
    ledgerHead = l.head;
    const sealed = !seal?.ledger || (seal.ledger.head ?? null) === l.head && (seal.ledger.entries === undefined || seal.ledger.entries === l.entries);
    out.push(`Ledger:       ${l.detail}${seal?.ledger ? (sealed ? "; its head and length are the ones the verdict sealed" : `; NOT THE LEDGER THE VERDICT SEALED (sealed ${seal.ledger.entries ?? "?"} entries, head ${seal.ledger.head ?? "none"}; here ${l.entries}, head ${l.head ?? "none"})`) : ""}`);
    ok &&= l.ok && sealed;
  }
  const att = read("ledger-attestations.jsonl");
  if (att !== null) {
    const a = verifyAttestationChain(att);
    const sealed = !seal?.attestations || ((seal.attestations.head ?? null) === a.head && (seal.attestations.lines === undefined || seal.attestations.lines === a.total));
    out.push(`Attestations: ${a.ok ? `${a.total} lines, chain intact` : `CHAIN BROKEN at line ${a.broken_at} (${a.reason})`}${seal?.attestations ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : ""}`);
    ok &&= a.ok && sealed;
  }
  // The agents' disputes: their own chain, held to the seal when the verdict sealed them.
  const disp = read("ledger-disputes.jsonl");
  if (disp !== null) {
    const d = verifyDisputeChain(disp);
    const sealed = !seal?.disputes || ((seal.disputes.head ?? null) === d.head && (seal.disputes.lines === undefined || seal.disputes.lines === d.total));
    out.push(`Disputes:     ${d.ok ? `${d.total} lines, chain intact` : `CHAIN BROKEN at line ${d.broken_at} (${d.reason})`}${seal?.disputes ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before disputes were sealed)"}`);
    ok &&= d.ok && sealed;
  } else if ((seal?.disputes?.lines ?? 0) > 0) {
    // Named by the components check above; said here too, beside the other chains.
    out.push(`Disputes:     NOT IN THE PACKAGE, and the verdict sealed ${seal?.disputes?.lines} lines`);
  }
  // The store's journal: the sealed line where the seal says, and only examiner notes after it.
  const journal = read("store/journal.jsonl");
  if (journal !== null) {
    const j = journalChain(journal);
    let note = "";
    let sealed = true;
    if (seal?.journal) {
      const at = seal.journal.lines ? j.hashes[(seal.journal.lines ?? 0) - 1] : null;
      const rest = j.types.slice(seal.journal.lines ?? 0);
      sealed = (at ?? null) === (seal.journal.head ?? null) && rest.every((t) => t === "note");
      note = sealed ? `; head sealed${rest.length ? `, ${rest.length} examiner note(s) after it` : ""}` : "; HEAD NOT THE ONE SEALED, or lines after it that are not an examiner's notes";
    }
    out.push(`Journal:      ${j.detail}${note}`);
    ok &&= j.ok && sealed;
  }
  // work/ against the index custody sealed, and that index against the anchor and the verdict.
  const sealedText = read("artifacts.sealed.json");
  if (sealedText !== null) {
    const want = custody?.artifacts?.index_sha256;
    const byVerdict = heldTo("artifacts.sealed.json", sealedText, want);
    const byAnchor = lastAnchored?.artifacts_sha256 === undefined ? null : heldTo("artifacts.sealed.json", sealedText, lastAnchored.artifacts_sha256);
    if (byVerdict === "differs" || byAnchor === "differs") fail(`Sealed index: artifacts.sealed.json IS NOT THE INDEX ${byVerdict === "differs" ? "THE VERDICT" : "THE ANCHOR"} NAMES (${sha256(sealedText)}, sealed ${(byVerdict === "differs" ? want : lastAnchored?.artifacts_sha256) ?? "none"})`);
    else {
      let index: { files?: Array<{ path: string; sha256: string; packaged?: boolean }>; skipped?: Array<{ path: string }> } = {};
      try {
        index = JSON.parse(sealedText);
      } catch {
        fail("Sealed index: artifacts.sealed.json is not JSON");
      }
      const left = leftBehind(read("LEFT-BEHIND.txt"));
      // What today's indexer covers, from the index generated with this package: a file it leaves out is not one custody could have sealed.
      let fresh: Set<string> | null = null;
      try {
        const f = read("artifacts.json");
        fresh = f ? new Set(((JSON.parse(f) as { files?: Array<{ path: string }> }).files ?? []).map((x) => x.path)) : null;
      } catch {
        fresh = null;
      }
      const sealedFiles = new Map((index.files ?? []).map((f) => [f.path, f]));
      const sealedSkipped = new Set((index.skipped ?? []).map((f) => f.path));
      const changed: string[] = [];
      const gone: string[] = [];
      let same = 0;
      let redactedFiles = 0;
      let behind = 0;
      for (const f of sealedFiles.values()) {
        if (f.packaged === false) continue;
        if (!f.path.startsWith("work/") || f.path.split("/").includes("..")) {
          changed.push(`${f.path} (not a path under work/)`);
          continue;
        }
        if (existsSync(join(dir, f.path))) {
          const have = sha256(readFileSync(join(dir, f.path)));
          const r = redacted.get(f.path);
          if (have === f.sha256) same += 1;
          else if (r && r.before === f.sha256 && r.after === have) redactedFiles += 1;
          else changed.push(f.path);
        } else if (left.get(f.path) === f.sha256) behind += 1;
        else gone.push(f.path);
      }
      const added: string[] = [];
      const outside: string[] = [];
      for (const rel of packagedFiles(dir, "work")) {
        if (sealedFiles.has(rel) || rel.endsWith("/.gitkeep")) continue;
        if (sealedSkipped.has(rel)) added.push(`${rel} (not hashed at custody)`);
        else if (fresh && !fresh.has(rel)) outside.push(rel);
        else added.push(rel);
      }
      const bad = [
        ...(changed.length ? [`${changed.length} CHANGED (${changed.join(", ")})`] : []),
        ...(gone.length ? [`${gone.length} MISSING (${gone.join(", ")})`] : []),
        ...(added.length ? [`${added.length} NOT IN THE SEALED INDEX (${added.join(", ")})`] : []),
      ];
      const held = byVerdict === "redacted" ? "redacted (REDACTIONS.txt names its sha256 before, the sealed one)" : `the one the verdict${byAnchor ? " and the anchor" : ""} name${byAnchor ? "" : "s"}`;
      const counts = `${same} as sealed${redactedFiles ? `, ${redactedFiles} redacted from the sealed bytes (REDACTIONS.txt)` : ""}${behind ? `, ${behind} left in the sandbox with the sealed sha256 (LEFT-BEHIND.txt)` : ""}`;
      if (bad.length) fail(`Work files:   NOT AS SEALED: ${bad.join("; ")}; ${counts}; the index is ${held}`);
      else out.push(`Work files:   every packaged work/ file is the one custody sealed: ${counts}; the index is ${held}`);
      if (outside.length) out.push(`Unindexed:    ${outside.length} work/ file(s) outside what the index covers, neither sealed nor indexed: ${outside.join(", ")}`);
    }
  } else if (existsSync(join(dir, "work"))) out.push(`Work files:   not held to a sealed index (${declared?.get("artifacts.sealed.json")?.reason ?? "the package carries none"}): only MANIFEST.txt holds them`);
  // The examiner's review, and what its sign-off is over.
  const review = read("review.jsonl");
  if (review !== null) {
    const r = reviewChain(review);
    if (!r.ok) fail(`Review:       CHAIN ${r.detail}`);
    else if (!r.signed) out.push(`Review:       ${r.detail}; not signed`);
    else {
      const reportPath = r.signed.report_path && !r.signed.report_path.startsWith("/") && !r.signed.report_path.split("/").includes("..") ? r.signed.report_path : null;
      const reportHere = reportPath && existsSync(join(dir, reportPath)) ? sha256(readFileSync(join(dir, reportPath))) : null;
      const overLedger = ledgerHead === null ? "the ledger is not in the package" : r.signed.ledger_head === ledgerHead ? "this ledger" : `AN EARLIER LEDGER (head ${r.signed.ledger_head}; this one's ${ledgerHead})`;
      const overReport = !r.signed.report_sha256 ? "NO REPORT" : !reportPath ? "a report path that is not under the run" : reportHere === null ? `${reportPath} as it was (sha256 ${r.signed.report_sha256}), which is not in the package` : reportHere === r.signed.report_sha256 ? `this ${reportPath}` : `${reportPath} AS IT WAS (sha256 ${r.signed.report_sha256}), NOT THE ONE IN THE PACKAGE (${reportHere})`;
      out.push(`Review:       ${r.detail}; signed by ${r.signed.examiner ?? "?"} at ${r.signed.at ?? "?"} over ${overLedger} and ${overReport}`);
    }
  }
  if (existsSync(join(dir, "REDACTIONS.txt"))) out.push("Redacted:     this package was made with --redact (REDACTIONS.txt)");
  return { ok, lines: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "redact" && a && b) {
    const r = await redactPackage(a, b);
    console.log(JSON.stringify(r));
  } else if (cmd === "components" && a && b) {
    console.log(JSON.stringify(writeComponents(a, b)));
  } else if (cmd === "verify" && a) {
    const r = verifyPackage(a);
    console.log(r.lines.join("\n"));
    process.exit(r.ok ? 0 : 1);
  } else {
    console.error("usage: package-tools.ts redact <sandbox> <package dir> | components <sandbox> <package dir> | verify <package dir>");
    process.exit(2);
  }
}
