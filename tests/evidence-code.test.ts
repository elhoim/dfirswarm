/**
 * Code from the evidence, run (the limits spec, item 3; c10 run sd9645b).
 * A seat's password-test jobs read a crypto library recovered from a browser
 * cache blob (an earlier job's output under store/) and evaluated it with
 * Node's vm module: no-exec stops a file executing, not an interpreter
 * reading one, and a job's output is not no-exec at all. The harness flags,
 * from a command's words, a command that runs or evaluates code from an
 * evidence-derived place: in the seat's reply, on the trace, and in the
 * report's job record. It never refuses, and a command that only reads such
 * a place (grep, strings, a hash, a parser of the seat's own) is not
 * flagged. The commands here are shaped as the run's were; none of its
 * values is in them.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { evidenceCodeNote, evidenceCodeRun, evidencePaths } from "../extensions/evidence-code.ts";
import { renderReportBodyMarkdown } from "../scripts/report-body.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

// The shapes of sd9645b's jobs: a script written by a heredoc, then run with node.
const BOUND = [
  "cat > /tmp/crack.js <<'EOF'",
  "const fs = require('fs'); const vm = require('vm');",
  "const sj = fs.readFileSync('store/jobs/j000010/out/cache-0001.decoded', 'utf8');",
  "const paste = fs.readFileSync('store/jobs/j000011/out/paste.txt', 'utf8');",
  "let ctx = {}; vm.createContext(ctx); vm.runInContext(sj, ctx);",
  "for (const w of fs.readFileSync('store/jobs/j000012/out/words.txt', 'utf8').split('\\n')) { try { ctx.decrypt(w, paste); } catch (e) {} }",
  "EOF",
  "node /tmp/crack.js",
].join("\n");
const INLINE = "cat > /tmp/t.js <<'EOF'\nconst fs = require('fs'), vm = require('vm');\nvm.runInThisContext(fs.readFileSync('/run/sandbox/store/jobs/j000010/out/cache-0001.decoded', 'utf8'));\nEOF\nnode /tmp/t.js";
const INDIRECT = "cat > /tmp/u.js <<'EOF'\nconst p = 'store/jobs/j000010/out/lib.js';\nconst src = require('fs').readFileSync(p, 'utf8');\nnew Function(src)();\nEOF\nnode /tmp/u.js";

test("the run's shape is flagged: recovered code evaluated with vm.runInContext or runInThisContext, directly or through a name bound to what was read", () => {
  assert.deepEqual(evidenceCodeRun(BOUND, ["job:j000010/cache-0001.decoded", "job:j000011/paste.txt", "job:j000012/words.txt"]), {
    how: "evaluates",
    what: "vm.runIn…",
    paths: ["store/jobs/j000010/out/cache-0001.decoded", "store/jobs/j000011/out/paste.txt", "store/jobs/j000012/out/words.txt", "job:j000010/cache-0001.decoded", "job:j000011/paste.txt", "job:j000012/words.txt"],
  });
  assert.equal(evidenceCodeRun(INLINE)?.what, "vm.runIn…");
  assert.equal(evidenceCodeRun(INDIRECT)?.what, "new Function", "a path bound to a name, read into another, evaluated");
  for (const [cmd, what] of [
    ["python3 -c \"exec(open('work/extracted/a1/s.py').read())\"", "exec"],
    ["python3 - <<'EOF'\nwith open('work/quarantine/a1/s.py') as f:\n    code = f.read()\nexec(compile(code, 's', 'exec'))\nEOF", "exec"],
    ["node -e \"require('./work/extracted/a1/lib.js')\"", "require"],
    ["python3 -c \"import runpy; runpy.run_path('store/jobs/j1/out/tool.py')\"", "runpy"],
  ] as const) assert.equal(evidenceCodeRun(cmd)?.what, what, cmd);
});

test("an interpreter, a shell or a browser given an evidence-derived file as its script, on its stdin or through a pipe, runs it", () => {
  for (const [cmd, what, path] of [
    ["python3 work/extracted/a1/payload.py", "python", "work/extracted/a1/payload.py"],
    ["/usr/bin/python3 -u /run/sandbox/work/extracted/a1/p.py --flag", "python", "work/extracted/a1/p.py"],
    ["node inputs/site/app.js", "node", "inputs/site/app.js"],
    ["cd $OUT && bash work/quarantine/a1/dropper.sh arg", "bash", "work/quarantine/a1/dropper.sh"],
    [". store/jobs/j1/out/env.sh", ".", "store/jobs/j1/out/env.sh"],
    ["sh < work/extracted/a1/x.sh", "sh", "work/extracted/a1/x.sh"],
    ["java -jar store/jobs/j1/out/tool.jar", "java", "store/jobs/j1/out/tool.jar"],
    ["chromium --headless --dump-dom store/imports/i1/page.html", "chromium", "store/imports/i1/page.html"],
  ] as const) assert.deepEqual(evidenceCodeRun(cmd), { how: "runs", what, paths: [path] }, cmd);
  assert.deepEqual(evidenceCodeRun("cat store/jobs/j1/out/x.sh | sh"), { how: "runs", what: "sh", paths: ["store/jobs/j1/out/x.sh"] });
});

test("reading an evidence-derived place is not running it: patterns, hashes, strings, a seat's own parser, a module import, a method named exec or compile", () => {
  for (const cmd of [
    "python3 work/a1/parse.py inputs/disk.E01",
    "strings -a work/extracted/a1/x.bin | grep -Ei 'http|bash|sudo|python3 inputs/x'",
    "grep -Ei 'foo|chrome inputs/Case.E01' store/jobs/j1/out/tree.tsv > \"$OUT/c.tsv\" || true",
    "sha256sum store/jobs/j1/out/*",
    "python3 -c \"import re; print(re.compile('x').findall(open('store/jobs/j1/out/a.txt').read()))\"",
    "node -e \"const m = /x/.exec(require('fs').readFileSync('store/jobs/j1/out/a.txt', 'utf8'))\"",
    "python3 - <<'EOF'\nsrc = open('work/a1/helper.py').read(); exec(src, ns)\nd = open('store/jobs/j1/out/runs.json').read()\nEOF",
    "python3 -c \"p = __import__('os').environ['OUT']; print(open('store/jobs/j1/out/a').read())\"",
    "node /tmp/t.js",
    "python3 work/me/inputs/tool.py",
    "file work/quarantine/a1/dropper.sh; xxd work/quarantine/a1/dropper.sh | head",
  ]) assert.equal(evidenceCodeRun(cmd), null, cmd);
  assert.deepEqual(evidencePaths("icat -o 2048 inputs/Case.E01 1234 > work/extracted/a1/f.bin; ls /run/s/store/jobs/j2/out/"), ["inputs/Case.E01", "work/extracted/a1/f.bin", "store/jobs/j2/out/"]);
});

test("the seat is told the rule, why the mount did not stop it and what to do instead, never refused", () => {
  const note = evidenceCodeNote(evidenceCodeRun(BOUND)!, "job");
  for (const must of ["this job's command evaluates code (vm.runIn…) it read from store/jobs/j000010/out/cache-0001.decoded", "may have been executed", "no-exec stops the kernel running a file, not an interpreter reading it", "a job's output under store/ is not no-exec", "Reimplement what the recovered code does", "say so in the ledger", "lead_close needs_operator", "flagged on the trace and in the report"]) {
    assert.ok(note.includes(must), `the note does not say: ${must}`);
  }
  assert.match(evidenceCodeNote(evidenceCodeRun("python3 work/extracted/a1/p.py")!, "shell"), /^Note from the harness: this command runs work\/extracted\/a1\/p\.py with python:/);
});

test("the report's job record says a job may have executed evidence code, and lists every such job; one that only read is not marked", async () => {
  const base = await mkdtemp(join(tmpdir(), "evidence-code-report-"));
  dirs.push(base);
  const S = join(base, "run");
  const job = (command: string, inputs: string[]) => ({ state: "committed", status: "ok", exit: 0, requester: { agent: "a1" }, image: "img:dev", image_digest: "sha256:0", spec: { kind: "command", command, inputs, network: "off" } });
  const files: Record<string, string> = {
    "ledger/entries.jsonl": "",
    "store/jobs/j000001/job.json": JSON.stringify({ id: "j000001", ...job(BOUND, ["job:j000010/cache-0001.decoded"]) }),
    "store/jobs/j000002/job.json": JSON.stringify({ id: "j000002", ...job("sha256sum store/jobs/j000010/out/cache-0001.decoded", ["job:j000010/cache-0001.decoded"]) }),
  };
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(dirname(join(S, rel)), { recursive: true });
    await writeFile(join(S, rel), text);
  }
  const md = await renderReportBodyMarkdown(S);
  assert.match(md, /1 job may have executed code recovered from the evidence \(.*\): j000001\./);
  const one = md.slice(md.indexOf("Job j000001"), md.indexOf("Job j000002") > 0 ? md.indexOf("Job j000002") : undefined);
  assert.match(one, /evidence code executed/);
  assert.match(one, /Evidence code.*may have been executed: the command evaluates code \(vm\.runIn…\) it read from store\/jobs\/j000010\/out\/cache-0001\.decoded/);
  const two = md.slice(md.indexOf("Job j000002"));
  assert.doesNotMatch(two.slice(0, two.indexOf("Cited by")), /evidence code/i);
  // The worker prompt says the rule where the seats read it.
  const prompt = (await readFile(join(import.meta.dirname, "..", "prompts", "worker-system.md"), "utf8")).replace(/\s+/g, " ");
  for (const must of ["Never run is any way of running", "No-exec does not stop an interpreter reading a file", "which is not no-exec at all", "reimplement it, or use a trusted program that does it"]) assert.ok(prompt.includes(must), `prompts/worker-system.md does not say: ${must}`);
});
