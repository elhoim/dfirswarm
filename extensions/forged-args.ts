/**
 * The arguments of a forged tool, brought to the types its manifest declares.
 *
 * A seat's tool declares `candidates: array` and is called with
 * "[1, 2, 3]" or "1,2,3"; it declares `offset: integer` and gets "4096".
 * The script then adds a string to a number and dies: all seven calls of two
 * forged tools in the run sf4406b, all seven of one in s5d814f, across three
 * seats, none repaired. What a value plainly is under its declared type is
 * taken as that; anything else is left as it came, and what was changed is
 * said, so the caller learns the form (coercedWords), on a direct call and
 * on job_run alike.
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdir, rm, rmdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

export type ParamDecl = { type?: string };

export function coerceArgs(params: Record<string, ParamDecl> | undefined, args: Record<string, unknown>): { args: Record<string, unknown>; coerced: string[] } {
  const out: Record<string, unknown> = { ...args };
  const coerced: string[] = [];
  for (const [key, decl] of Object.entries(params ?? {})) {
    const v = out[key];
    if (typeof v !== "string") continue;
    const t = v.trim();
    const took = (value: unknown, as: string) => {
      out[key] = value;
      coerced.push(`${key} (a string) was taken as ${as}`);
    };
    switch (decl?.type) {
      case "integer":
      case "number": {
        if (t !== "" && /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t) && Number.isFinite(Number(t)) && (decl.type === "number" || Number.isInteger(Number(t)))) took(Number(t), `the ${decl.type} ${Number(t)}`);
        else if (decl.type === "integer" && /^0x[0-9a-f]+$/i.test(t)) took(Number.parseInt(t, 16), `the integer ${Number.parseInt(t, 16)}`);
        break;
      }
      case "boolean":
        if (/^(true|false)$/i.test(t)) took(t.toLowerCase() === "true", `the boolean ${t.toLowerCase()}`);
        break;
      case "array": {
        let parsed: unknown;
        try { parsed = JSON.parse(t); } catch { parsed = undefined; }
        if (Array.isArray(parsed)) took(parsed, `an array of ${parsed.length}`);
        else if (t !== "" && !/^[[{]/.test(t)) {
          const items = t.split(/\s*,\s*/).filter((x) => x !== "").map((x) => (/^[+-]?\d+(\.\d+)?$/.test(x) ? Number(x) : x));
          took(items, `an array of ${items.length} (split at the commas)`);
        }
        break;
      }
      case "object": {
        let parsed: unknown;
        try { parsed = JSON.parse(t); } catch { parsed = undefined; }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) took(parsed, "an object");
        break;
      }
      default:
        break;
    }
  }
  return { args: out, coerced };
}

/** What a coercion did, in one sentence for the caller; "" when nothing was changed. */
export function coercedWords(coerced: readonly string[]): string {
  return coerced.length ? `Arguments taken as their declared types: ${coerced.join("; ")}.` : "";
}

/** A tool's known-answer test, as make_tool takes it: the arguments of one call and text its output holds. */
export type SelfTest = { args?: unknown; expect?: unknown };

/** What is wrong with a self-test as given, or null. */
export function selfTestProblem(st: unknown): string | null {
  if (!st || typeof st !== "object" || Array.isArray(st)) return 'selftest is required: {args: {...}, expect: "<text its output holds>"}, one call whose answer you know';
  const { args, expect } = st as SelfTest;
  if (args !== undefined && (!args || typeof args !== "object" || Array.isArray(args))) return "selftest.args is the object of arguments of that call";
  if (typeof expect !== "string" || !expect.trim()) return "selftest.expect is text the output of that call holds (not empty)";
  return null;
}

/** A tool not yet written: what make_tool was given. */
export type CandidateTool = { name: string; description?: string; runtime: "python3" | "node" | "bash"; script: string; params?: Record<string, ParamDecl>; timeout_seconds?: number };
type CandidateRunResult = { ok: boolean; exit_code: number | null; stdout: string; stderr: string; timed_out: boolean };
/** How a staged tool is run: protocol-core.ts runForgedTool, given its manifest and the sha256 its script must have. */
export type CandidateRun = (root: string, manifest: Record<string, unknown> & { name: string; entry: string; runtime: string; sha256: string }, args: Record<string, unknown>, o: { agentId?: string; sealed?: string }) => Promise<CandidateRunResult>;

const RUNTIME_EXT: Record<CandidateTool["runtime"], string> = { python3: "py", node: "mjs", bash: "sh" };
export const SELFTEST_DIR = ".make_tool";

/**
 * A tool's self-test, run before it is written or shared (IMPROVEMENT-PLAN-2
 * D6). Its script is staged in its author's own directory
 * (work/<id>/.make_tool/<name>-<random>/), run from the run's directory as
 * a tool is run, with the self-test's arguments brought to the declared
 * types, and removed. The test passes when the call ends 0 and its output
 * holds the expected text. A tool that fails it is never in tools/, so no
 * peer loads it; the tool used to be written and shared first and tested
 * after, and a failing one stayed in every seat's list.
 */
export async function selfTestCandidate(root: string, agentId: string, tool: CandidateTool, st: SelfTest, run: CandidateRun): Promise<{ passed: boolean; said: string; coerced: string[]; exit: number | null; timed_out: boolean }> {
  const typed = coerceArgs(tool.params, (st.args ?? {}) as Record<string, unknown>);
  const expect = String(st.expect ?? "");
  const where = join(root, "work", agentId, SELFTEST_DIR, `${tool.name}-${randomBytes(4).toString("hex")}`);
  const entry = `run.${RUNTIME_EXT[tool.runtime]}`;
  try {
    await mkdir(where, { recursive: true });
    await writeFile(join(where, entry), tool.script, { encoding: "utf8", mode: 0o644 });
    const sha256 = createHash("sha256").update(tool.script).digest("hex");
    // Its name leads from tools/ to where it is staged: the runner finds the entry as it finds any tool's.
    const manifest = { name: relative(join(root, "tools"), where), description: tool.description ?? "", params: tool.params ?? {}, runtime: tool.runtime, entry, timeout_seconds: tool.timeout_seconds ?? 60, by: agentId, at: new Date().toISOString(), version: 0, sha256 };
    const r = await run(root, manifest, typed.args, { agentId, sealed: sha256 }).catch((err: Error): CandidateRunResult => ({ ok: false, exit_code: null, stdout: "", stderr: err.message, timed_out: false }));
    const passed = r.ok && r.stdout.includes(expect);
    const last = (r.stderr || r.stdout).trim().split("\n").slice(-1)[0]?.slice(0, 200) ?? "";
    const said = passed
      ? "its self-test passed (a call whose answer its author knew gave that answer)"
      : `its self-test failed (${r.timed_out ? "timed out" : r.ok ? `the output did not hold ${JSON.stringify(expect.slice(0, 80))}` : `exit ${r.exit_code ?? "?"}${last ? `: ${last}` : ""}`})`;
    return { passed, said, coerced: typed.coerced, exit: r.exit_code, timed_out: r.timed_out };
  } finally {
    await rm(where, { recursive: true, force: true }).catch(() => undefined);
    await rmdir(join(root, "work", agentId, SELFTEST_DIR)).catch(() => undefined);
  }
}
