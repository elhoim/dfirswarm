/**
 * Lines of any chained register a run writes, chained with its own code
 * (scripts/chained-registers.ts ChainCode): for the tests that hold every
 * register to custody, the release and the package.
 */
import { createHash } from "node:crypto";
import { attestationHash, disputeHash, ledgerHash, type LedgerAttestation, type LedgerDispute, type LedgerEntry } from "../extensions/protocol.ts";
import { leadEventHash, type LeadEvent } from "../extensions/leads.ts";
import { sweepHash, type SweepRecord } from "../extensions/store-sweep.ts";
import type { ChainCode } from "../scripts/chained-registers.ts";

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/** `n` more lines of a register, chained with its own code after the lines it has. */
export function chainLines(code: ChainCode, n: number, have: string[] = []): string[] {
  const out = [...have];
  const lastObj = () => (out.length ? (JSON.parse(out.at(-1)!) as Record<string, unknown>) : null);
  for (let i = 0; i < n; i++) {
    const seq = out.length + 1;
    const at = new Date(Date.UTC(2026, 8, 29, 10, 0, seq)).toISOString();
    const hashPrev = (lastObj()?.hash as string | undefined) ?? "genesis";
    const rawPrev = out.length ? sha(out.at(-1)!) : null;
    let line: Record<string, unknown>;
    switch (code) {
      case "trace":
        line = { ts: at, agent: "a0", tool: "bash", args: { n: seq }, result: { ok: true }, prev: rawPrev ?? "" };
        break;
      case "gateway":
        line = { at, seat: "a0", model: "m", tokens: seq, prev: rawPrev };
        break;
      case "journal":
        line = { v: 1, seq: out.length, at, type: "note", note: `note ${seq}`, prev: rawPrev };
        break;
      case "ledger": {
        const e = { v: 2, seq, kind: "event", value: `event ${seq}`, source: "a log", evidence: `line ${seq}`, by: "a0", authors: ["a0"], at, prev: hashPrev } as unknown as LedgerEntry;
        line = { ...e, hash: ledgerHash(e, hashPrev) };
        break;
      }
      case "attestation": {
        const a = { v: 2, act: "attest", seq, target: "t".repeat(64), by: "a1", at, how: `re-derived ${seq}`, prev: hashPrev } as unknown as LedgerAttestation;
        line = { ...a, hash: attestationHash(a, hashPrev) };
        break;
      }
      case "dispute": {
        const d = { v: 1, act: "dispute", seq, target: "t".repeat(64), by: "a1", at, why: `does not hold ${seq}`, prev: hashPrev } as unknown as LedgerDispute;
        line = { ...d, hash: disputeHash(d, hashPrev) };
        break;
      }
      case "sweep": {
        const s = { v: 1, seq, target: "t".repeat(64), state: "clean", terms: ["alpha"], searched: { objects: 1, bytes: 1 }, hits: [], named_hits: [], unsearched: [], started_at: at, at, prev: hashPrev } as unknown as SweepRecord;
        line = { ...s, hash: sweepHash(s, hashPrev) };
        break;
      }
      case "lead": {
        const e = { v: 1, seq, at, by: "a0", ev: "note", note: `note ${seq}`, prev: hashPrev } as unknown as LeadEvent;
        line = { ...e, hash: leadEventHash(e, hashPrev) };
        break;
      }
    }
    out.push(JSON.stringify(line));
  }
  return out;
}

