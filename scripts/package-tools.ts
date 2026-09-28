#!/usr/bin/env node
/**
 * A package's two checks beyond its MANIFEST.txt (swarm.sh package, verify):
 *
 * redact <sandbox> <package dir> [--leaks fail|list]
 *   What a sensitive ledger entry says, and the objects it cites, are taken
 *   out of a package before it is handed over (GDPR or similar laws ask for
 *   no more than the purpose needs). A chained file keeps its chain: a
 *   redacted line is replaced by `{"redacted": true, "line_sha256": <the
 *   line's own hash>}` (a ledger entry keeps its seq, kind, prev and hash;
 *   an attestation or a dispute its act, target, prev and hash), so a
 *   recipient re-walks every chain and sees which lines it cannot read. A
 *   JSON file is redacted field by field, keeping its shape; any other text
 *   file word by word; a file a sensitive entry cites is replaced whole; a
 *   PDF a release printed is withheld. REDACTIONS.txt lists every change
 *   with the file's sha256 before and after, so the owner of the original
 *   can match it, and REDACTIONS.json what each replaced (the sha256 of the
 *   original, why, which entry). Then every file is scanned for each
 *   sensitive entry's words, normalised: a hit refuses the package (exit 5),
 *   or with --leaks list is recorded and said.
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
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { attestationHash, disputeHash, ledgerHash, readLedger, sensitiveTokens, type LedgerAttestation, type LedgerDispute, type LedgerEntry, type SensitiveToken } from "../extensions/protocol.ts";
import { leadEventHash, type LeadEvent } from "../extensions/leads.ts";
import { REVIEW_ACTIONS } from "./review.ts";
import { packageLayout, verifyReleases } from "./release-record.ts";

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

// What a sensitive entry says, as the words redaction looks for (protocol.ts, where the question register reads them too).
export { sensitiveTokens, type SensitiveToken };

/** Package paths a sensitive entry's refs name, as the package lays them out, with the entry. */
function citedPaths(entries: LedgerEntry[]): Array<{ path: string; seq: number }> {
  const out = new Map<string, number>();
  for (const e of entries) {
    if (!e.sensitive) continue;
    for (const r of e.refs ?? []) {
      const m = /^job:(j\d{6})\/(.+)$/.exec(r);
      if (!m) continue;
      const p = /^(stdout\.log|stderr\.log)$/.test(m[2]) ? `store/jobs/${m[1]}/${m[2]}` : `store/jobs/${m[1]}/out/${m[2].replace(/^out\//, "")}`;
      if (!out.has(p)) out.set(p, e.seq);
    }
  }
  return [...out].map(([path, seq]) => ({ path, seq }));
}

/** What one redaction replaced: the sha256 of the original (never the original), why, and which entry's words it held. */
export type Replaced = { what: "entry" | "line" | "file" | "field" | "text"; entry: number | null; sha256_of_original: string; line?: number; pointer?: string; count?: number; why: string };
export type RedactionChange = { path: string; before_sha256: string; after_sha256: string; why: string; replaced: Replaced[] };
export type LeakHit = { path: string; entry: number; token_sha256: string; as: string };

/** A sensitive entry's words as they may stand in a file: as written, JSON-escaped. */
const forms = (t: string) => [...new Set([t, JSON.stringify(t).slice(1, -1)])];

/** The files a package seals as they are: signatures, tokens, a release's record and its sidecars. Scanned, never rewritten. */
function sealedAsIs(rel: string): boolean {
  if (["MANIFEST.txt", "MANIFEST.txt.sig", "SIGNER.txt", "signer.pub", "REDACTIONS.txt", "REDACTIONS.json", "COMPONENTS.json", "custody.json.sig", "custody.json.tsr"].includes(rel)) return true;
  return /^release\/v\d+\/(release\.json(\.sig(\.tsr|\.ots)?)?|timestamp\.json|mirror-\d+\.json|print-\d+\.json|transparency-\d+\.json|case-file\.txt)$/.test(rel);
}

/** A JSON value with every string that holds a sensitive entry's words replaced whole; each replacement recorded by its pointer. */
function redactJsonValue(v: unknown, pointer: string, tokens: SensitiveToken[], replaced: Replaced[]): unknown {
  if (typeof v === "string") {
    const hit = tokens.find((t) => v.includes(t.token));
    if (!hit) return v;
    replaced.push({ what: "field", entry: hit.seq, sha256_of_original: sha256(v), pointer, why: "a field holding a sensitive entry's words, replaced whole" });
    return REDACTED;
  }
  if (Array.isArray(v)) return v.map((x, i) => redactJsonValue(x, `${pointer}/${i}`, tokens, replaced));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, redactJsonValue(x, `${pointer}/${k.replace(/~/g, "~0").replace(/\//g, "~1")}`, tokens, replaced)]));
  return v;
}

/**
 * Every packaged file searched for what redaction should have taken out:
 * each sensitive entry's words, normalised (lower case, one kind of path
 * separator, JSON escapes read), in a text file's text, and as UTF-8 and
 * UTF-16 bytes in any file (a PDF's compressed text is not read). A hit is
 * named by the file, the entry and the sha256 of the word, never the word.
 */
export function leakScan(dir: string, tokens: SensitiveToken[]): { files: number; hits: LeakHit[] } {
  const hits: LeakHit[] = [];
  let files = 0;
  const norm = (s: string) => s.replace(/\\"/g, '"').replace(/\\\//g, "/").replace(/\\\\/g, "\\").toLowerCase().replace(/\\/g, "/");
  const wanted = tokens.map((t) => ({ ...t, n: norm(t.token), raw: [Buffer.from(t.token, "utf8"), Buffer.from(t.token, "utf16le"), Buffer.from(t.token.toLowerCase(), "utf8")] }));
  const maxLen = Math.max(0, ...wanted.map((w) => w.raw[1].length));
  for (const abs of walk(dir)) {
    const rel = relative(dir, abs).split("\\").join("/");
    if (rel === "REDACTIONS.txt" || rel === "REDACTIONS.json" || rel.startsWith("MANIFEST.txt")) continue;
    files += 1;
    const size = lstatSync(abs).size;
    const seen = new Set<string>();
    const note = (w: (typeof wanted)[number], as: string) => {
      if (seen.has(`${w.token}\u0000${as}`)) return;
      seen.add(`${w.token}\u0000${as}`);
      hits.push({ path: rel, entry: w.seq, token_sha256: sha256(w.token), as });
    };
    // Whole, when it can be held; in overlapping chunks when it cannot: nothing is left unread.
    const chunk = 32 * 1024 * 1024;
    const fd = openSync(abs, "r");
    try {
      for (let off = 0; off < Math.max(size, 1); off += chunk) {
        const len = Math.min(chunk + maxLen, size - off);
        if (len <= 0) break;
        const buf = Buffer.alloc(len);
        readSync(fd, buf, 0, len, off);
        // Text when no NUL stands in its first 8 KiB; any file's bytes are searched either way.
        const text = !buf.subarray(0, 8192).includes(0) ? norm(buf.toString("utf8")) : null;
        for (const w of wanted) {
          if (text !== null && text.includes(w.n)) note(w, "text");
          else if (w.raw.some((b) => buf.includes(b))) note(w, "bytes");
        }
      }
    } finally {
      closeSync(fd);
    }
  }
  return { files, hits };
}

/**
 * Redact a package in place: what every sensitive entry says, and what it
 * cites, taken out before the manifest is written, and each change
 * recorded with what it replaced (the sha256 of the original, why, which
 * entry). The chained files keep their chains: a redacted line carries the
 * hash the next line names (the ledger, its attestations and disputes keep
 * seq, kind or act, target, prev and hash; the trace, the journal and the
 * review, the line's own sha256). A JSON file is redacted field by field,
 * keeping its shape; any other text file word by word; a PDF a release
 * printed, which words cannot be taken out of, is withheld. The signed
 * records (a release, a token, a signature) are sealed as they are. Then
 * every file is scanned for what should have been taken out: `leaks: fail`
 * (the default) refuses the package on a hit, `list` records the hits.
 */
export async function redactPackage(sandbox: string, dir: string, opts: { leaks?: "fail" | "list" } = {}): Promise<{ entries: number; files: number; lines: number; leaks: LeakHit[]; scanned: number }> {
  const entries = await readLedger(sandbox, { raw: true });
  const tokens = sensitiveTokens(entries);
  const sensitiveSeqs = new Set(entries.filter((e) => e.sensitive).map((e) => e.seq));
  const sensitiveHashes = new Set(entries.filter((e) => e.sensitive && e.hash).map((e) => e.hash as string));
  const changes: RedactionChange[] = [];
  let lines = 0;
  const change = (rel: string, before: Buffer, after: Buffer | string, why: string, replaced: Replaced[]) => {
    writeFileSync(join(dir, rel), after);
    changes.push({ path: rel, before_sha256: sha256(before), after_sha256: sha256(after), why, replaced });
  };
  const holds = (l: string) => tokens.find((t) => forms(t.token).some((f) => l.includes(f)));
  const handled = new Set<string>();
  // A chained file, line by line: `keep` says what a redacted line keeps of the one it replaces.
  const chained = (rel: string, judge: (o: Record<string, unknown>, raw: string) => { seq: number | null; why: string } | null, keep: (o: Record<string, unknown>, raw: string) => Record<string, unknown>, what: Replaced["what"], why: string) => {
    handled.add(rel);
    if (!existsSync(join(dir, rel))) return;
    const before = readFileSync(join(dir, rel));
    const replaced: Replaced[] = [];
    let n = 0;
    const out = before
      .toString("utf8")
      .split("\n")
      .map((l) => {
        if (!l.trim()) return l;
        n += 1;
        let o: Record<string, unknown>;
        try {
          o = JSON.parse(l) as Record<string, unknown>;
        } catch {
          return l;
        }
        const j = judge(o, l);
        if (!j) return l;
        replaced.push({ what, entry: j.seq, sha256_of_original: sha256(l), line: n, why: j.why });
        return JSON.stringify(keep(o, l));
      })
      .join("\n");
    if (replaced.length) {
      lines += replaced.length;
      change(rel, before, out, `${replaced.length} ${why}`, replaced);
    }
  };
  const byWords = (l: string) => {
    const t = holds(l);
    return t ? { seq: t.seq, why: "holds a sensitive entry's words" } : null;
  };
  // The ledger: a sensitive entry, and any entry that repeats one's words, keeps what chains it.
  chained(
    "ledger.jsonl",
    (o, l) => (sensitiveSeqs.has(Number(o.seq)) ? { seq: Number(o.seq), why: "marked sensitive" } : byWords(l)),
    (o, l) => ({ v: o.v, seq: o.seq, kind: o.kind, redacted: true, line_sha256: sha256(l), ...(o.prev ? { prev: o.prev } : {}), ...(o.hash ? { hash: o.hash } : {}), ...(o.refs ? { refs: o.refs } : {}) }),
    "entry",
    "entr(y|ies) sensitive, or holding a sensitive entry's words, replaced by their seq, kind, chain hashes and line hash",
  );
  // An agent's act on a sensitive entry, or one that says its words: the act, the target and the chain kept.
  for (const rel of ["ledger-attestations.jsonl", "ledger-disputes.jsonl"]) {
    chained(
      rel,
      (o, l) => (typeof o.target === "string" && sensitiveHashes.has(o.target) ? { seq: Number(o.seq), why: "an act on a sensitive entry" } : byWords(l)),
      (o, l) => ({ ...(o.v !== undefined ? { v: o.v } : {}), ...(o.act ? { act: o.act } : {}), seq: o.seq, ...(o.target ? { target: o.target } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }),
      "line",
      "act(s) on or holding a sensitive entry, replaced keeping act, target, prev and hash",
    );
  }
  if (tokens.length) {
    // A lead that repeats a sensitive entry's words: its event kept by what chains it.
    chained("leads.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, ev: o.ev, ...(o.lead ? { lead: o.lead } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }), "line", "lead event(s) holding a sensitive entry's words replaced, keeping seq, ev, lead, prev and hash");
    // A question that repeats a sensitive entry's words, the same way.
    chained("questions.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, ev: o.ev, ...(o.q ? { q: o.q } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev, hash: o.hash }), "line", "question event(s) holding a sensitive entry's words replaced, keeping seq, ev, q, prev and hash");
    if (existsSync(join(dir, "questions.md"))) {
      const before = readFileSync(join(dir, "questions.md"));
      const hit = holds(before.toString("utf8"));
      handled.add("questions.md");
      if (hit) change("questions.md", before, `${REDACTED}: the rendered question register repeats a sensitive entry's words; questions.jsonl carries every event (those redacted by their hashes); its sha256 before redaction is ${sha256(before)}\n`, "the rendered register holds a sensitive entry's words, replaced whole", [{ what: "file", entry: hit.seq, sha256_of_original: sha256(before), why: "repeats a sensitive entry's words" }]);
    }
    if (existsSync(join(dir, "leads.md"))) {
      const before = readFileSync(join(dir, "leads.md"));
      const hit = holds(before.toString("utf8"));
      handled.add("leads.md");
      if (hit) change("leads.md", before, `${REDACTED}: the rendered lead register repeats a sensitive entry's words; leads.jsonl carries every event (those redacted by their hashes); its sha256 before redaction is ${sha256(before)}\n`, "the rendered register holds a sensitive entry's words, replaced whole", [{ what: "file", entry: hit.seq, sha256_of_original: sha256(before), why: "repeats a sensitive entry's words" }]);
    }
    chained("trace/events.jsonl", (_o, l) => byWords(l), (_o, l) => ({ redacted: true, line_sha256: sha256(l) }), "line", "line(s) holding a sensitive entry's words replaced by their own sha256");
    chained("store/journal.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, type: o.type, ...(o.job ? { job: o.job } : {}), redacted: true, line_sha256: sha256(l), prev: o.prev ?? null }), "line", "journal line(s) holding a sensitive entry's words replaced, keeping seq, prev and their own sha256");
    chained("review.jsonl", (_o, l) => byWords(l), (o, l) => ({ v: o.v, seq: o.seq, action: o.action, redacted: true, line_sha256: sha256(l), prev: o.prev ?? null }), "line", "review line(s) holding a sensitive entry's words replaced, keeping seq, action, prev and their own sha256");
  }
  // A file a sensitive entry cites, whole.
  for (const c of citedPaths(entries)) {
    if (!existsSync(join(dir, c.path))) continue;
    const before = readFileSync(join(dir, c.path));
    handled.add(c.path);
    change(c.path, before, `${REDACTED}: cited by a sensitive ledger entry; its sha256 before redaction is ${sha256(before)}\n`, "cited by a sensitive entry, replaced whole", [{ what: "file", entry: c.seq, sha256_of_original: sha256(before), why: "cited by a sensitive entry" }]);
  }
  let files = 0;
  if (sensitiveSeqs.size) {
    for (const abs of walk(dir)) {
      const rel = relative(dir, abs).split("\\").join("/");
      if (handled.has(rel) || sealedAsIs(rel)) continue;
      const before = readFileSync(abs);
      // A PDF a release printed: words cannot be taken out of it, so it is withheld.
      if (/^release\/v\d+\/.+\.pdf$/.test(rel)) {
        change(rel, before, `[withheld: a PDF cannot be redacted by replacing words; the release names it by its sha256 before redaction, ${sha256(before)}]\n`, "a release's PDF, withheld", [{ what: "file", entry: null, sha256_of_original: sha256(before), why: "a PDF cannot be redacted word by word" }]);
        files += 1;
        continue;
      }
      if (!tokens.length || before.subarray(0, 8192).includes(0)) continue;
      const text = before.toString("utf8");
      if (!holds(text)) continue;
      const replaced: Replaced[] = [];
      let after: string | null = null;
      // JSON, field by field, keeping its shape.
      if (/\.json$/.test(rel)) {
        try {
          const v = redactJsonValue(JSON.parse(text), "", tokens, replaced);
          after = `${JSON.stringify(v, null, /\n\s+"/.test(text) ? 2 : undefined)}${text.endsWith("\n") ? "\n" : ""}`;
        } catch {
          after = null;
        }
      } else if (/\.jsonl$/.test(rel)) {
        const out: string[] = [];
        let ok = true;
        text.split("\n").forEach((l, i) => {
          if (!l.trim() || !holds(l)) return out.push(l);
          try {
            out.push(JSON.stringify(redactJsonValue(JSON.parse(l), `${i + 1}`, tokens, replaced)));
          } catch {
            ok = false;
            out.push(l);
          }
        });
        after = ok ? out.join("\n") : null;
      }
      if (after === null) {
        // Any other text: the words replaced where they stand.
        replaced.length = 0;
        let t = text;
        for (const tok of tokens) {
          for (const f of forms(tok.token)) {
            const count = t.split(f).length - 1;
            if (!count) continue;
            t = t.split(f).join(REDACTED);
            replaced.push({ what: "text", entry: tok.seq, sha256_of_original: sha256(tok.token), count, why: "a sensitive entry's words" });
          }
        }
        after = t;
      }
      if (replaced.length) {
        files += 1;
        change(rel, before, after, /\.jsonl?$/.test(rel) && replaced.every((r) => r.what === "field") ? "fields holding a sensitive entry's words replaced whole" : "a sensitive entry's words replaced", replaced);
      }
    }
  }
  // What should have been taken out, looked for everywhere now.
  const scan = leakScan(dir, tokens);
  const mode = opts.leaks ?? "fail";
  writeFileSync(
    join(dir, "REDACTIONS.txt"),
    [
      "Redactions",
      "==========",
      "",
      `This package was made with --redact. ${sensitiveSeqs.size} ledger entr${sensitiveSeqs.size === 1 ? "y was" : "ies were"} marked sensitive (seq ${[...sensitiveSeqs].join(", ") || "none"}).`,
      "What they say, and the objects they cite, are not in it. A chained file keeps its chain: a redacted",
      "line carries the sha256 of the line it replaces, which the next line's prev names. Each change below",
      "is the file's sha256 before and after, so the owner of the original can match it; REDACTIONS.json",
      "records what each replaced (the sha256 of the original, why, which entry) and the leak scan.",
      `Leak scan: ${scan.hits.length ? `${scan.hits.length} HIT(S) over ${scan.files} file(s), LISTED in REDACTIONS.json (made with --redact-leaks list)` : `nothing found over ${scan.files} file(s)`}.`,
      "",
      "sha256 before                                                    sha256 after                                                     path  why",
      ...changes.map((c) => `${c.before_sha256}  ${c.after_sha256}  ${c.path}  ${c.why}`),
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(dir, "REDACTIONS.json"),
    `${JSON.stringify(
      {
        v: 1,
        note: "What this package's redaction replaced: each change with the sha256 of what it replaced (never the words), why, and which sensitive entry's words it held; then every file scanned for what should have been taken out. Under MANIFEST.txt and its signature.",
        entries: entries.filter((e) => e.sensitive).map((e) => ({ seq: e.seq, kind: e.kind, hash: e.hash ?? null })),
        words: tokens.length,
        changes,
        leak_scan: { mode, files: scan.files, hits: scan.hits },
      },
      null,
      2,
    )}\n`,
  );
  return { entries: sensitiveSeqs.size, files, lines, leaks: scan.hits, scanned: scan.files };
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

/**
 * An act chain (the attestations, the disputes: each line's hash over its
 * core and the line before), a redacted line's hash taken as it stands (its
 * core is not in the package) once it names the line before it: every other
 * line's hash is recomputed. The same as verifyAttestationChain and
 * verifyDisputeChain on an unredacted chain.
 */
export /**
 * The lead register's chain as a package holds it: each line chains to the
 * one before by its hash; a redacted line keeps its hash, and only its link
 * is checked, as the ledger's are.
 */
function leadChain(text: string): { ok: boolean; total: number; head: string | null; broken_at: number | null; reason: string | null; redacted: number } {
  let prev = "genesis";
  let total = 0;
  let redacted = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return { ok: false, total, head: null, broken_at: total, reason: "the line is not JSON", redacted };
    }
    if (o.prev !== prev) return { ok: false, total, head: null, broken_at: total, reason: "the line does not chain to the one before", redacted };
    if (o.redacted === true) redacted += 1;
    else if (o.hash !== leadEventHash(o as unknown as LeadEvent, prev)) return { ok: false, total, head: null, broken_at: total, reason: "the line was rewritten", redacted };
    prev = String(o.hash);
  }
  return { ok: true, total, head: total ? prev : null, broken_at: null, reason: null, redacted };
}

function actChain(text: string, hash: (line: Record<string, unknown>, prev: string) => string): { ok: boolean; total: number; redacted: number; head: string | null; broken_at: number | null; reason: string | null } {
  let last = "genesis";
  let total = 0;
  let redacted = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    total += 1;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return { ok: false, total, redacted, head: null, broken_at: total, reason: "not json" };
    }
    if (o.prev !== last) return { ok: false, total, redacted, head: null, broken_at: total, reason: "prev does not name the line before it" };
    if (o.redacted === true) {
      if (typeof o.hash !== "string") return { ok: false, total, redacted, head: null, broken_at: total, reason: "a redacted line carries no hash" };
      redacted += 1;
      last = o.hash;
      continue;
    }
    if (o.hash !== hash(o, last)) return { ok: false, total, redacted, head: null, broken_at: total, reason: "the line was rewritten" };
    last = String(o.hash);
  }
  return { ok: true, total, redacted, head: total ? last : null, broken_at: null, reason: null };
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
    if (!(REVIEW_ACTIONS as readonly string[]).includes(String(o.action))) return { ok: false, lines: n, redacted, detail: `BROKEN (line ${n} has no known action)`, signed };
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
export const PACKAGE_COMPONENTS: ReadonlyArray<{ path: string; source: string; what: string; absent: string; core?: true; sealed?: "trace" | "ledger" | "attestations" | "disputes" | "leads" | "questions" | "requests" | "journal" | "artifacts"; since?: string }> = [
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
  { path: "leads.jsonl", source: "leads/leads.jsonl", what: "the lead register: how the investigation proceeded (unsigned, sealed by custody)", absent: "no lead was opened", sealed: "leads", since: "2026-09-28" },
  { path: "leads.md", source: "leads/leads.md", what: "the lead register, rendered", absent: "no lead was opened", since: "2026-09-28" },
  { path: "questions.jsonl", source: "questions/questions.jsonl", what: "the question register: what the examination was asked, by whom (the goal, an agent, a person, claimed or signed), and how each question stood (unsigned as a whole, sealed by custody)", absent: "the run wrote no question event", sealed: "questions", since: "2026-09-28" },
  { path: "questions.md", source: "questions/questions.md", what: "the question register, rendered", absent: "the run wrote no question event", since: "2026-09-28" },
  { path: "operator-requests.jsonl", source: "operator-requests.jsonl", what: "what the run asked of the operator, one line per request as it stood", absent: "nothing was asked of the operator", since: "2026-09-28" },
  { path: "requests.jsonl", source: "requests/requests.jsonl", what: "the operator requests' chain: every request (a lead's needs, an acquisition, a clarification, a network item, a stop proposed) with its id and lifecycle (unsigned, sealed by custody)", absent: "nothing was asked of the operator, or the run is from before the chain", sealed: "requests", since: "2026-09-28" },
  { path: "requests.md", source: "requests/requests.md", what: "the operator requests, rendered", absent: "nothing was asked of the operator", since: "2026-09-28" },
  { path: "material", source: "store/imports/", what: "what entered the run after its kickoff (evidence add, material add): each addition's provenance record and manifest; the bytes stay with the evidence", absent: "no evidence or material was added after the kickoff", since: "2026-09-28" },
  { path: "operator-hosts.jsonl", source: "operator-hosts.jsonl", what: "the hosts the operator allowed while the run went on", absent: "the operator allowed no host during the run", since: "2026-09-28" },
  { path: "store/journal.jsonl", source: "store/journal.jsonl", what: "the store's journal", absent: "the run had no job service", sealed: "journal" },
  { path: "trace/journal-anchor.json", source: "<sandbox>.journal-anchor.json", what: "the journal's anchor", absent: "the run had no job service" },
  { path: "review.jsonl", source: "<runs>/reviews/<run>.jsonl", what: "the examiner's review", absent: "no examiner has reviewed this run", since: "2026-09-27" },
  { path: "release", source: "release/", what: "the report's releases: the machine's drafts and the examiner's adoptions, each signed", absent: "no release was sealed for this run (no custody taken, or a run from before releases)", since: "2026-09-27" },
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

type SealShape = { trace?: { lines?: number; last_line_sha256?: string | null }; ledger?: { entries?: number; head?: string | null }; attestations?: { lines?: number; head?: string | null }; disputes?: { lines?: number; head?: string | null }; leads?: { lines?: number; head?: string | null }; questions?: { lines?: number; head?: string | null }; requests?: { lines?: number; head?: string | null }; journal?: { lines?: number; head?: string | null } | null };

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
  let anchoredReleases = 0;
  try {
    const rs = anchorText ? (JSON.parse(anchorText) as { releases?: unknown }).releases : undefined;
    anchoredReleases = Array.isArray(rs) ? rs.length : 0;
  } catch {
    anchoredReleases = 0;
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
      case "leads":
        return (seal?.leads?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.leads?.lines} lead events` : null;
      case "questions":
        return (seal?.questions?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.questions?.lines} question events` : null;
      case "requests":
        return (seal?.requests?.lines ?? 0) > 0 ? `the verdict sealed ${seal?.requests?.lines} operator request events` : null;
      case "journal":
        return seal?.journal ? `the verdict sealed a journal of ${seal.journal.lines} lines` : null;
      case "artifacts":
        return custody?.artifacts?.index_sha256 ? "the verdict sealed an index of work/" : null;
      default:
        if (c.path === "release" && anchoredReleases > 0) return `the anchor names ${anchoredReleases} release(s)`;
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
    const a = actChain(att, (o, prev) => attestationHash(o as unknown as LedgerAttestation, prev));
    const sealed = !seal?.attestations || ((seal.attestations.head ?? null) === a.head && (seal.attestations.lines === undefined || seal.attestations.lines === a.total));
    out.push(`Attestations: ${a.ok ? `${a.total} lines, chain intact${a.redacted ? `, ${a.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${a.broken_at} (${a.reason})`}${seal?.attestations ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : ""}`);
    ok &&= a.ok && sealed;
  }
  // The agents' disputes: their own chain, held to the seal when the verdict sealed them.
  const disp = read("ledger-disputes.jsonl");
  if (disp !== null) {
    const d = actChain(disp, (o, prev) => disputeHash(o as unknown as LedgerDispute, prev));
    const sealed = !seal?.disputes || ((seal.disputes.head ?? null) === d.head && (seal.disputes.lines === undefined || seal.disputes.lines === d.total));
    out.push(`Disputes:     ${d.ok ? `${d.total} lines, chain intact${d.redacted ? `, ${d.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${d.broken_at} (${d.reason})`}${seal?.disputes ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before disputes were sealed)"}`);
    ok &&= d.ok && sealed;
  } else if ((seal?.disputes?.lines ?? 0) > 0) {
    // Named by the components check above; said here too, beside the other chains.
    out.push(`Disputes:     NOT IN THE PACKAGE, and the verdict sealed ${seal?.disputes?.lines} lines`);
  }
  // The lead register: its own chain, sealed unsigned, held to the seal when the verdict sealed it.
  const leadsText = read("leads.jsonl");
  if (leadsText !== null) {
    const l = leadChain(leadsText);
    const sealed = !seal?.leads || ((seal.leads.head ?? null) === l.head && (seal.leads.lines === undefined || seal.leads.lines === l.total));
    out.push(`Leads:        ${l.ok ? `${l.total} events, chain intact${l.redacted ? `, ${l.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${l.broken_at} (${l.reason})`}${seal?.leads ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before the lead register was sealed)"}`);
    ok &&= l.ok && sealed;
  } else if ((seal?.leads?.lines ?? 0) > 0) {
    out.push(`Leads:        NOT IN THE PACKAGE, and the verdict sealed ${seal?.leads?.lines} events`);
  }
  // The question register: the same chain code, held to the seal the same way.
  const questionsText = read("questions.jsonl");
  if (questionsText !== null) {
    const q = leadChain(questionsText);
    const sealed = !seal?.questions || ((seal.questions.head ?? null) === q.head && (seal.questions.lines === undefined || seal.questions.lines === q.total));
    out.push(`Questions:    ${q.ok ? `${q.total} events, chain intact${q.redacted ? `, ${q.redacted} redacted (their hashes kept)` : ""}` : `CHAIN BROKEN at line ${q.broken_at} (${q.reason})`}${seal?.questions ? (sealed ? "; head sealed" : "; HEAD NOT THE ONE SEALED") : "; not sealed by this verdict (a custody from before the question register was sealed)"}`);
    ok &&= q.ok && sealed;
  } else if ((seal?.questions?.lines ?? 0) > 0) {
    out.push(`Questions:    NOT IN THE PACKAGE, and the verdict sealed ${seal?.questions?.lines} events`);
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
  if (existsSync(join(dir, "REDACTIONS.txt"))) {
    // What each redaction replaced, and what the scan after it found.
    let lineage = "";
    try {
      const r = JSON.parse(read("REDACTIONS.json") ?? "") as { changes?: Array<{ path: string; replaced?: unknown[] }>; leak_scan?: { mode?: string; files?: number; hits?: Array<{ path: string; entry: number }> } };
      const rows = redactions(read("REDACTIONS.txt"));
      const listed = new Set((r.changes ?? []).map((c) => c.path));
      const unrecorded = [...rows.keys()].filter((p) => !listed.has(p));
      const hits = r.leak_scan?.hits ?? [];
      lineage = `; REDACTIONS.json records what ${(r.changes ?? []).reduce((n, c) => n + (c.replaced?.length ?? 0), 0)} redaction(s) replaced (the sha256 of each original, why, which entry)${unrecorded.length ? `, and NOT ${unrecorded.join(", ")}` : ""}; the leak scan after it ${hits.length ? `FOUND ${hits.length} HIT(S), LISTED: ${hits.map((h) => `${h.path} (entry ${h.entry})`).join(", ")}` : `found nothing over ${r.leak_scan?.files ?? "?"} file(s)`}`;
      if (unrecorded.length) ok = false;
    } catch {
      lineage = "; no REDACTIONS.json (a package made before redactions were recorded): what each replaced is not said";
    }
    out.push(`Redacted:     this package was made with --redact (REDACTIONS.txt)${lineage}`);
  }
  return { ok, lines: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "redact" && a && b) {
    const leaks = process.argv.includes("--leaks") ? process.argv[process.argv.indexOf("--leaks") + 1] : "fail";
    if (leaks !== "fail" && leaks !== "list") {
      console.error("redact: --leaks fail|list");
      process.exit(2);
    }
    const r = await redactPackage(a, b, { leaks });
    console.log(JSON.stringify({ entries: r.entries, files: r.files, lines: r.lines, scanned: r.scanned, leaks: r.leaks.length }));
    // A word that should have been taken out and is still there: named by file, entry and the word's sha256, never the word.
    for (const h of r.leaks) console.error(`  ${h.path}: entry ${h.entry}'s words (sha256 ${h.token_sha256.slice(0, 16)}…, as ${h.as})`);
    if (r.leaks.length && leaks === "fail") process.exit(5);
  } else if (cmd === "components" && a && b) {
    console.log(JSON.stringify(writeComponents(a, b)));
  } else if (cmd === "verify" && a) {
    const rest = process.argv.slice(4);
    const opt = (name: string) => (rest.indexOf(name) >= 0 ? rest[rest.indexOf(name) + 1] : undefined);
    const r = verifyPackage(a);
    console.log(r.lines.join("\n"));
    // The report's releases: every signature, the bytes each binds, the chain between them.
    const rel = await verifyReleases(packageLayout(a), { allowedSigners: opt("--allowed-signers"), tsaCa: opt("--tsa-ca"), ca: opt("--ca"), caIntermediate: opt("--ca-intermediate") });
    console.log(rel.lines.join("\n"));
    const unchecked = rel.signatures.some((s) => s.adopted && s.state !== "verified");
    process.exit(!r.ok || !rel.ok ? 1 : unchecked && opt("--allowed-signers") ? 3 : 0);
  } else {
    console.error("usage: package-tools.ts redact <sandbox> <package dir> | components <sandbox> <package dir> | verify <package dir>");
    process.exit(2);
  }
}
