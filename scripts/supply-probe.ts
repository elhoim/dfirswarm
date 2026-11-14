/**
 * A known-answer test of a program the operator supplied, run where the
 * seats will run it: as a job in a worker VM of the run, with the supplied
 * import named in `programs`.
 *
 *   supply-probe.ts <sandbox> <import id> --provides CAP[,CAP] --hub-admin SOCKET [--timeout SECONDS]
 *   supply-probe.ts <sandbox> <import id> --untested WHY [--provides CAP[,CAP]] [--hub-admin SOCKET]
 *
 * Prints one JSON object: { ok, import, probes: [{ capability, ok, job, said }], requires },
 * writes the same under the import's id in <sandbox>/supplied-capabilities.json,
 * takes it into what the kickoff recorded as wanted (toolbox.json `requires`):
 * a capability whose known-answer test passed is met, by the import, and
 * `requires` in the answer says how many are met now. It tells the seats on
 * the board. Exit 0 when every probe passed, 3 when one did not, 2 on a usage
 * error.
 *
 * --untested: a program that is sealed and was not tested (nothing said what
 * it is for, or the run has no job service to test it in) is recorded so,
 * and the seats are told it is untested: its silence says nothing about the
 * evidence. Exit 0; the caller says what that means to the operator.
 *
 * Why: a QR decoder supplied to eight runs could read no image (its
 * ImageMagick had no coders). It had been tried with `--version` only; two
 * runs wrote the fault on their ledgers, three read its silence as "no QR".
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

export const PROBE_PAYLOAD = "dfirswarm-probe";

export type Probe = { capability: string; command: string; expect: RegExp; what: string };

/** The PNG of a QR symbol whose payload is known (scripts/lib/qrgen.py), as base64. */
export function probeQrBase64(): string {
  const dir = mkdtempSync(join(tmpdir(), "qrprobe-"));
  try {
    execFileSync("python3", ["-I", join(HERE, "lib", "qrgen.py"), PROBE_PAYLOAD, join(dir, "p.png")]);
    return readFileSync(join(dir, "p.png")).toString("base64");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The capabilities this file can test, each with the command a job runs and what its output must hold. */
export function probeFor(capability: string, qrPngBase64: string): Probe | null {
  const png = `printf %s '${qrPngBase64}' | base64 -d > "$OUT/probe.png"`;
  switch (capability) {
    case "qr-decode":
      return {
        capability,
        command: `${png} && zbarimg -q --raw "$OUT/probe.png"`,
        expect: new RegExp(`^${PROBE_PAYLOAD}$`, "m"),
        what: `zbarimg decodes a QR symbol whose payload is "${PROBE_PAYLOAD}" from a PNG`,
      };
    case "image-convert":
      return {
        capability,
        command: `${png} && { magick "$OUT/probe.png" "$OUT/probe.pnm" 2>/dev/null || convert "$OUT/probe.png" "$OUT/probe.pnm"; } && head -c 2 "$OUT/probe.pnm" && echo " converted"`,
        expect: /^P[1-6] converted$/m,
        what: "ImageMagick reads a PNG and writes it as PNM",
      };
    case "video-decode":
      return {
        capability,
        command:
          'ffmpeg -v error -f lavfi -i testsrc=duration=1:size=64x64:rate=5 -c:v mpeg4 "$OUT/probe.mp4" && ' +
          'echo "frames=$(ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 "$OUT/probe.mp4")"',
        expect: /^frames=5$/m,
        what: "ffmpeg writes a five-frame clip and ffprobe decodes and counts its five frames",
      };
    default:
      return null;
  }
}

export type ProbeResult = { capability: string; ok: boolean; job: string | null; said: string };

/** What a finished probe job shows: passed only when it ended ok and its output holds the known answer. */
export function decide(p: Probe, job: { id?: string; state?: string; status?: string; reason?: string } | null, stdout: string, stderrTail: string): ProbeResult {
  const id = job?.id ?? null;
  if (!job || job.state !== "committed") return { capability: p.capability, ok: false, job: id, said: `the test job did not finish (${job?.state ?? "no job"}${job?.reason ? `: ${job.reason}` : ""})` };
  if (p.expect.test(stdout)) return { capability: p.capability, ok: true, job: id, said: `known-answer test passed: ${p.what}` };
  const err = (stderrTail || stdout).trim().split("\n").slice(-2).join(" | ").slice(0, 300);
  return { capability: p.capability, ok: false, job: id, said: `known-answer test FAILED: ${p.what} was expected${job.reason ? `; the job says ${job.reason}` : ""}${err ? `; it printed: ${err}` : "; it printed nothing"}` };
}

export type HubCall = (fn: string, arg: Record<string, unknown>) => Promise<Record<string, unknown>>;

/** Run each capability's test as a job and decide it. `call` is the hub's admin "call" (as system). */
export async function runProbes(call: HubCall, importId: string, capabilities: string[], o: { qr?: string; timeoutS?: number; sleep?: (ms: number) => Promise<void> } = {}): Promise<{ ok: boolean; import: string; probes: ProbeResult[] }> {
  const qr = o.qr ?? probeQrBase64();
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const probes: ProbeResult[] = [];
  for (const cap of capabilities) {
    const p = probeFor(cap, qr);
    if (!p) {
      probes.push({ capability: cap, ok: false, job: null, said: `no known-answer test exists for ${cap} (tested: qr-decode, image-convert, video-decode): it is not verified` });
      continue;
    }
    const sub = await call("jobSubmit", { command: p.command, inputs: [], programs: [`import:${importId}`], timeout_seconds: 120, note: `known-answer test of ${cap} for ${importId}` });
    const id = String((sub.job as { job?: string } | undefined)?.job ?? "");
    if (sub.ok !== true || !id) {
      probes.push({ capability: cap, ok: false, job: null, said: `the test job was not accepted: ${String(sub.reason ?? "no reason given")}` });
      continue;
    }
    const until = Date.now() + (o.timeoutS ?? 600) * 1000;
    let st: Record<string, unknown> = {};
    for (;;) {
      st = await call("jobStatus", { job_id: id });
      const state = String((st.job as { state?: string } | undefined)?.state ?? "");
      if (state === "committed" || state === "cancelled" || Date.now() > until) break;
      await sleep(2000);
    }
    const job = (st.job ?? null) as { job?: string; state?: string; status?: string; reason?: string; stderr?: { tail?: string } } | null;
    const stdout = String((st.stdout as { text?: string } | undefined)?.text ?? "");
    probes.push(decide(p, job ? { id, state: job.state, status: job.status, reason: job.reason } : null, stdout, String(job?.stderr?.tail ?? "")));
  }
  return { ok: probes.every((x) => x.ok), import: importId, probes };
}

/** A row of toolbox.json's `requires`, as toolbox.sh writes it. */
export type RequireRow = Record<string, unknown>;

/**
 * A supplied program's probes taken into what the kickoff recorded as wanted: a capability whose known-answer test
 * passed is met, and the import is among what meets it; one that failed stays as it was, with the failure beside it.
 * Returns how many of the wanted capabilities are met now, and which this supply made met.
 */
export function applySupply(requires: RequireRow[], importId: string, probes: ProbeResult[]): RequiresCount {
  const newly: string[] = [];
  for (const r of requires) {
    const p = probes.find((x) => x.capability === r.capability);
    if (!p) continue;
    r.supplied = { import: importId, ok: p.ok, job: p.job, said: p.said };
    if (!p.ok) continue;
    if (r.met_at_kickoff === undefined) r.met_at_kickoff = r.met === true;
    if (r.met !== true) newly.push(String(r.capability));
    r.met = true;
    const by = Array.isArray(r.by) ? (r.by as unknown[]).map(String) : [];
    const ref = `import:${importId}`;
    r.by = by.includes(ref) ? by : [...by, ref];
  }
  return countRequires(requires, newly);
}

/** A supply that was not tested, beside each capability it was said to be for: met is left as the kickoff found it. */
export function applyUntested(requires: RequireRow[], importId: string, capabilities: string[], why: string): RequiresCount {
  for (const r of requires) if (capabilities.includes(String(r.capability))) r.supplied = { import: importId, ok: null, untested: why };
  return countRequires(requires, []);
}

export type RequiresCount = { met: number; of: number; newly_met: string[]; unmet: string[] };

function countRequires(requires: RequireRow[], newly: string[]): RequiresCount {
  return { met: requires.filter((r) => r.met === true).length, of: requires.length, newly_met: newly, unmet: requires.filter((r) => r.met !== true).map((r) => String(r.capability)) };
}

/** The words the seats are told of a program sealed and not tested. */
export function untestedPost(importId: string, why: string, capabilities: string[]): string {
  return (
    `SUPPLIED PROGRAM NOT TESTED: import:${importId} was not run against a known answer (${why})` +
    (capabilities.length ? `; it was supplied for ${capabilities.join(", ")}, which is therefore not shown to work` : "") +
    `. Whether it works where you run it is not known: a program that starts and prints its version can still read no file. ` +
    `Before you rely on it, run it in a job on an input whose answer you know (job_run programs ["import:${importId}"]). Until then its silence or an empty answer says nothing about the evidence, and what rests on it says it was untested.`
  );
}

/** The words the seats are told. */
export function probePost(importId: string, probes: ProbeResult[]): string {
  const lines = probes.map((x) => `${x.capability}: ${x.ok ? "WORKS" : "DOES NOT WORK"} (${x.said}${x.job ? `; job ${x.job}` : ""})`);
  const bad = probes.some((x) => !x.ok);
  return `SUPPLIED PROGRAM TESTED: import:${importId} was run in a worker VM against a known answer. ${lines.join(". ")}.${bad ? " A capability that does not work must not be read as a negative: its silence says nothing about the evidence. Say so on the ledger if you relied on it, and use another way." : ""}`;
}

async function readToolbox(sandbox: string): Promise<{ requires?: RequireRow[] } | null> {
  return readFile(join(sandbox, "toolbox.json"), "utf8").then((t) => JSON.parse(t) as { requires?: RequireRow[] }).catch(() => null);
}

async function recordSupply(sandbox: string, importId: string, rec: Record<string, unknown>): Promise<void> {
  const file = join(sandbox, "supplied-capabilities.json");
  const had = await readFile(file, "utf8").then((t) => JSON.parse(t) as Record<string, unknown>).catch(() => ({}) as Record<string, unknown>);
  await writeFile(file, `${JSON.stringify({ ...had, [importId]: { at: new Date().toISOString(), ...rec } }, null, 2)}\n`);
}

async function main(argv: string[]): Promise<number> {
  const [sandbox, importId, ...rest] = argv;
  const opt = (name: string) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
  const provides = (opt("--provides") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const admin = opt("--hub-admin");
  const untested = opt("--untested");
  if (!sandbox || !importId || (untested === undefined && (!provides.length || !admin)) || untested === "") {
    console.error("usage: supply-probe.ts <sandbox> <import id> --provides CAP[,CAP] --hub-admin SOCKET [--timeout SECONDS]\n       supply-probe.ts <sandbox> <import id> --untested WHY [--provides CAP[,CAP]] [--hub-admin SOCKET]");
    return 2;
  }
  // The hub's board functions take the run root first: the admin socket's "call" is given it here.
  const call: HubCall = (fn, arg) =>
    new Promise((resolve, reject) => {
      let answer = "";
      if (!admin) return reject(new Error("no hub admin socket"));
      const socket = connect(admin);
      socket.setTimeout(60_000, () => { socket.destroy(); reject(new Error("the hub did not answer")); });
      socket.setEncoding("utf8");
      socket.on("error", reject);
      socket.on("data", (c) => (answer += c));
      socket.on("close", () => {
        try { resolve(JSON.parse(answer.trim().split("\n")[0] ?? "{}") as Record<string, unknown>); } catch (err) { reject(err as Error); }
      });
      socket.on("connect", () => socket.write(`${JSON.stringify({ op: "call", fn, args: [sandbox, arg] })}\n`));
    });
  const tb = join(sandbox, "toolbox.json");
  if (untested !== undefined) {
    // Sealed and not tested: said so in the run's records and to the seats, never left to read as working.
    await recordSupply(sandbox, importId, { untested, ...(provides.length ? { provides } : {}) });
    const toolbox = await readToolbox(sandbox);
    const requires = toolbox?.requires ? applyUntested(toolbox.requires, importId, provides, untested) : null;
    if (toolbox?.requires) await writeFile(tb, `${JSON.stringify(toolbox, null, 2)}\n`).catch(() => undefined);
    const post = { tag: "hold", to: "all", key: `supply-probe:${importId}`, body: untestedPost(importId, untested, provides) };
    const posted = admin
      ? await call("systemPost", post).then(() => true, () => false)
      : await import("../extensions/protocol.ts").then((P) => P.systemPost(sandbox, post)).then(() => true, () => false);
    console.log(JSON.stringify({ ok: false, untested: true, import: importId, why: untested, provides, posted, ...(requires ? { requires } : {}) }));
    return 0;
  }
  const result = await runProbes(call, importId, provides, { timeoutS: Number(opt("--timeout") ?? 600) });
  await recordSupply(sandbox, importId, { probes: result.probes });
  // What the kickoff recorded as wanted is now met by the supply where its known-answer test passed, or shown not to be.
  const toolbox = await readToolbox(sandbox);
  let requires: RequiresCount | null = null;
  if (toolbox?.requires) {
    requires = applySupply(toolbox.requires, importId, result.probes);
    await writeFile(tb, `${JSON.stringify(toolbox, null, 2)}\n`).catch(() => undefined);
  }
  await call("systemPost", { tag: result.ok ? "result" : "hold", to: "all", key: `supply-probe:${importId}`, body: probePost(importId, result.probes) }).catch(() => undefined);
  console.log(JSON.stringify({ ...result, ...(requires ? { requires } : {}) }));
  return result.ok ? 0 : 3;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => { console.error(`supply-probe: ${(err as Error).message}`); process.exit(1); });
}
