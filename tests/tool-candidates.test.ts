/**
 * Tool harvesting (B19, docs/adr/0016): the code the agents wrote into
 * command jobs, taken out whole (heredocs, inline scripts, the command
 * itself, a script of their own a job ran), counted once per text, ranked by
 * lines times the jobs that ran it, each with its jobs, seats, profiles and
 * lines and the library tools that may already cover it, and written for the
 * maintainer; the CLI and swarm.sh tools --candidates, on a synthetic run.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { harvest, normaliseScript, piecesOf, writeHarvest } from "../scripts/tool-candidates.ts";

const ROOT = join(import.meta.dirname, "..");

/** A python script of n lines, the same text for the same seed. */
const py = (seed: string, n: number) => ["import json, sys", ...Array.from({ length: n - 2 }, (_, i) => `rows_${seed}_${i} = ${i}`), `print(json.dumps({"seed": "${seed}"}))`].join("\n");

function synthetic() {
  const base = mkdtempSync(join(tmpdir(), "candidates-"));
  const S = join(base, "run");
  const lib = join(base, "library");
  mkdirSync(join(S, "store", "jobs"), { recursive: true });
  mkdirSync(join(S, "work", "a2"), { recursive: true });
  const shared = py("parse", 30);
  const big = py("carve", 55);
  const workScript = py("own", 24);
  writeFileSync(join(S, "work", "a2", "own.py"), `${workScript}\n`);
  const jobs: Array<[string, string, string, Record<string, unknown>]> = [
    ["j000001", "a1", `python3 - <<'PY' > "$OUT/out.json"\n${shared}\nPY`, { inputs: ["input:logs/Security.evtx"] }],
    ["j000002", "a2", `set -e\npython3 - <<'PY'\n${shared}\nPY\necho done`, {}],
    ["j000003", "a3", `python3 - <<'PY'\n${shared}\n\nPY`, { profile: "disk" }],
    ["j000004", "a1", `cat > "$OUT/list.txt" <<'EOF'\n${Array.from({ length: 40 }, (_, i) => `line ${i}`).join("\n")}\nEOF\npython3 - <<'PY'\n${big}\nPY`, {}],
    ["j000005", "a2", "python3 -c 'print(1)'", {}],
    ["j000006", "a2", "python3 work/a2/own.py > \"$OUT/own.json\"", { scope: { manifest: "store/jobs/j000006/scope.1.json" } }],
    ["j000007", "system", `python3 - <<'PY'\n${py("kickoff", 40)}\nPY`, {}],
  ];
  for (const [id, agent, command, extra] of jobs) {
    mkdirSync(join(S, "store", "jobs", id), { recursive: true });
    const { scope, profile, inputs } = extra as { scope?: unknown; profile?: string; inputs?: string[] };
    writeFileSync(join(S, "store", "jobs", id, "job.json"), JSON.stringify({ id, spec: { kind: "command", command, inputs: inputs ?? [], ...(profile ? { profile } : {}) }, requester: { agent }, status: "ok", state: "committed", accepted_at: `2026-09-28T10:00:0${id.slice(-1)}Z`, ...(scope ? { scope } : {}) }));
  }
  // A job's declared scope, with the snapshot of the agent's own script it read, and one whose objects are an event log.
  writeFileSync(join(S, "store", "jobs", "j000006", "scope.1.json"), JSON.stringify({ accessible: [{ path: "work/a2/own.py", sha256: "0".repeat(64), hashed: "at the job's start" }], expanded: [] }));
  writeFileSync(join(S, "store", "jobs", "j000001", "scope.1.json"), JSON.stringify({ accessible: [], expanded: [{ ref: "input:logs/Security.evtx", path: "inputs/logs/Security.evtx", shape: "file" }] }));
  const j1 = JSON.parse(readFileSync(join(S, "store", "jobs", "j000001", "job.json"), "utf8"));
  writeFileSync(join(S, "store", "jobs", "j000001", "job.json"), JSON.stringify({ ...j1, scope: { manifest: "store/jobs/j000001/scope.1.json" } }));
  writeFileSync(join(S, "store", "journal.jsonl"), `${JSON.stringify({ type: "job_started", job: "j000002", profile: "mobile" })}\n`);
  // The maintainer's library: one tool that reads event logs, one whose name the big script uses.
  for (const [name, m] of [["evtx_reader", { description: "d", use: { extensions: [".evtx"] } }], ["rows_carve_3", { description: "d" }]] as const) {
    mkdirSync(join(lib, name), { recursive: true });
    writeFileSync(join(lib, name, "manifest.json"), JSON.stringify({ name, ...m }));
  }
  return { S, lib, base, shared, big, workScript };
}

test("the code in a command: each heredoc with its language, each inline script, the command itself", () => {
  const cmd = ["set -e", "cat > \"$OUT/list.txt\" <<'EOF'", "a", "b", "EOF", "python3 - <<'PY' > \"$OUT/x.json\"", "import json", "print(1)", "PY", "grep x <<< \"$y\"", "perl -e 'print 2'"].join("\n");
  const pieces = piecesOf(cmd);
  assert.deepEqual(pieces.map((p) => `${p.kind}:${p.lang}`), ["heredoc:text", "heredoc:python", "inline:perl", "command:shell"]);
  assert.equal(pieces[1].text, "import json\nprint(1)");
  assert.doesNotMatch(pieces[3].text, /import json/, "the command without its heredoc bodies");
  assert.match(pieces[3].text, /grep x <<< "\$y"/, "a here-string is not a heredoc");
  assert.equal(normaliseScript("\n\n  a  \n b\t\n\n"), "  a\n b");
});

test("candidates: one per text, ranked by lines times jobs, with jobs, seats, profiles, lines, reuse and library matches, written whole", () => {
  const { S, lib, base, shared, big, workScript } = synthetic();
  return (async () => {
    const h = await harvest(S, { libraries: [lib] });
    assert.equal(h.command_jobs, 6, "the kickoff's own job is not an agent's code");
    const [first, second, third] = h.candidates;
    assert.equal(h.candidates.length, 3, JSON.stringify(h.candidates.map((c) => [c.kind, c.lines])));
    // 30 lines × 3 jobs = 90 beats 55 × 1 and 24 × 1.
    assert.equal(first.text, normaliseScript(shared));
    assert.deepEqual([first.lines, first.jobs.length, first.reuse, first.score], [30, 3, 2, 90]);
    assert.deepEqual(first.jobs.map((j) => [j.job, j.seat, j.profile]), [["j000001", "a1", "the run's worker image"], ["j000002", "a2", "mobile"], ["j000003", "a3", "disk"]]);
    assert.deepEqual(first.library.map((l) => l.tool), ["evtx_reader"]);
    assert.match(first.library[0].why, /reads what the jobs declared \(extension \.evtx\)/);
    assert.deepEqual([second.text, second.lines, second.jobs.map((j) => j.job)], [normaliseScript(big), 55, ["j000004"]]);
    assert.deepEqual(second.library.map((l) => `${l.tool}: ${l.why}`), ["rows_carve_3: the script names it"]);
    assert.deepEqual([third.kind, third.source, third.lines], ["work file", "work/a2/own.py", 24]);
    assert.match(String(third.note), /changed since job j000006 read it/);
    assert.ok(!h.candidates.some((c) => c.lang === "text"), "a heredoc of data is not code");
    // Written whole for the maintainer, with where each came from.
    const out = join(base, "out");
    await writeHarvest(h, out, "srun");
    assert.equal(readFileSync(join(out, first.file), "utf8"), `${normaliseScript(shared)}\n`);
    assert.equal(readFileSync(join(out, third.file), "utf8"), `${normaliseScript(workScript)}\n`);
    const json = JSON.parse(readFileSync(join(out, "candidates.json"), "utf8"));
    assert.equal(json.run, "srun");
    assert.deepEqual(json.candidates.map((c: { file: string }) => c.file), h.candidates.map((c) => c.file));
    assert.equal(json.candidates[0].text, undefined, "the text is in its file, not repeated");
    assert.match(readFileSync(join(out, "README.txt"), "utf8"), /To fold one into the tool library/);
    // --min-lines moves the bar.
    assert.equal((await harvest(S, { libraries: [lib], minLines: 50 })).candidates.length, 1);
  })();
});

test("the CLI and swarm.sh tools --candidates list and write them", () => {
  const { S, lib, base } = synthetic();
  const cli = spawnSync("node", ["--experimental-strip-types", "--no-warnings", join(ROOT, "scripts", "tool-candidates.ts"), S, "--library", lib, "--out", join(base, "cli")], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.match(cli.stdout, /3 candidate\(s\): scripts of 20 lines or more in 6 command job\(s\)/);
  assert.match(cli.stdout, /1\. python heredoc, 30 lines, 3 job\(s\) \(reused 2×\), score 90: j000001 \(a1, the run's worker image, ok\), j000002 \(a2, mobile, ok\), j000003 \(a3, disk, ok\)/);
  assert.match(cli.stdout, /library: evtx_reader in .*: it reads what the jobs declared/);
  const runs = join(base, "runs");
  mkdirSync(runs, { recursive: true });
  writeFileSync(join(runs, "registry.json"), JSON.stringify({ runs: [{ id: "scand", sandbox: S, state: "done" }] }));
  const sh = spawnSync("bash", [join(ROOT, "scripts", "swarm.sh"), "tools", "scand", "--candidates", "--library", lib, "--min-lines", "25"], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: runs } });
  assert.equal(sh.status, 0, sh.stderr + sh.stdout);
  assert.match(sh.stdout, /2 candidate\(s\): scripts of 25 lines or more/);
  assert.ok(JSON.parse(readFileSync(`${S}.tool-candidates/candidates.json`, "utf8")).candidates.length === 2, "written beside the run by default");
  const bad = spawnSync("bash", [join(ROOT, "scripts", "swarm.sh"), "tools", "scand", "--min-lines", "25"], { encoding: "utf8", env: { ...process.env, SWARM_RUNS_DIR: runs } });
  assert.notEqual(bad.status, 0, "--min-lines goes with --candidates");
});
