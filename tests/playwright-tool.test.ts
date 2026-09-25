/**
 * `playwright` tool fixture. No LLM. Needs `npm install` (playwright
 * devDependency) and `npx playwright install chromium`; the browser test
 * skips with a reason when either is missing so the rest of the suite runs.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  parseActions,
  registerPlaywrightTool,
  resolveTarget,
  runBrowserCheck,
  SCREENSHOT_DIR,
} from "../extensions/playwright-tool.ts";
import { appendEvent, EVENTS_REL, initSandbox } from "../extensions/protocol.ts";

const FIXTURE_HTML = `<!doctype html>
<html><head><title>Slice 2 fixture</title></head>
<body>
  <h1 id="headline">Pelican pending</h1>
  <button id="go" onclick="document.getElementById('headline').textContent='Pelican rendered'">Render</button>
  <input id="name" />
  <script>console.error("fixture console error");</script>
</body></html>
`;

async function browserAvailable(): Promise<string | null> {
  try {
    const pw = await import("playwright");
    const launchOptions: { headless: true; executablePath?: string; channel?: string } = {
      headless: true,
    };
    if (process.env.BROWSER_CHECK_EXECUTABLE) {
      launchOptions.executablePath = process.env.BROWSER_CHECK_EXECUTABLE;
    } else if (process.env.BROWSER_CHECK_CHANNEL) {
      launchOptions.channel = process.env.BROWSER_CHECK_CHANNEL;
    }
    const browser = await pw.chromium.launch(launchOptions);
    await browser.close();
    return null;
  } catch (err) {
    return (err as Error).message.split("\n")[0];
  }
}

test("resolveTarget: sandbox files become file://, remote http is refused by default", async () => {
  const root = await mkdtemp(join(tmpdir(), "slice2-target-"));
  try {
    assert.match(resolveTarget(root, "work/index.html", false), /^file:\/\/.*\/work\/index\.html$/);
    assert.equal(resolveTarget(root, "http://localhost:4321/", false), "http://localhost:4321/");
    assert.equal(resolveTarget(root, "http://127.0.0.1:4321/x", false), "http://127.0.0.1:4321/x");
    assert.throws(() => resolveTarget(root, "https://example.com/", false), /remote target refused/);
    assert.equal(resolveTarget(root, "https://example.com/", true), "https://example.com/");
    assert.throws(() => resolveTarget(root, "../etc/passwd", false), /escapes sandbox/);
    assert.throws(() => resolveTarget(root, "ftp://host/x", false), /unsupported scheme/);
    assert.throws(() => resolveTarget(root, "   ", false), /target is empty/);
    assert.deepEqual(parseActions(undefined), []);
    assert.throws(() => parseActions([{ type: "eval" }]), /type must be one of/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("playwright tool: renders a work/ page, runs actions, captures errors and a screenshot", async (t) => {
  const unavailable = await browserAvailable();
  if (unavailable) {
    t.skip(`playwright/chromium unavailable: ${unavailable}`);
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "slice2-browser-"));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "work", "index.html"), FIXTURE_HTML, "utf8");

    const before = await runBrowserCheck({
      sandboxRoot: root,
      agentId: "agent00",
      target: "work/index.html",
      textSelector: "#headline",
    });
    assert.equal(before.title, "Slice 2 fixture");
    assert.equal(before.text, "Pelican pending");
    assert.deepEqual(before.console_errors, ["fixture console error"]);
    assert.equal(before.screenshot, null);

    const after = await runBrowserCheck({
      sandboxRoot: root,
      agentId: "agent00",
      target: "work/index.html",
      actions: [
        { type: "fill", selector: "#name", value: "scout" },
        { type: "click", selector: "#go" },
        { type: "wait", selector: "#headline" },
      ],
      screenshot: true,
    });
    assert.equal(after.actions_run, 3);
    assert.match(after.text, /Pelican rendered/);
    assert.ok(after.screenshot?.startsWith(`${SCREENSHOT_DIR}/`), "screenshot lives under work/.browser/");
    assert.match(after.screenshot ?? "", /-agent00\.png$/);
    const shot = await stat(join(root, after.screenshot!));
    assert.ok(shot.size > 0);

    await assert.rejects(
      () => runBrowserCheck({ sandboxRoot: root, agentId: "agent00", target: "https://example.com/" }),
      /remote target refused/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("registerPlaywrightTool: registers `playwright`, logs ok/error events in the harness schema", async (t) => {
  const unavailable = await browserAvailable();
  const root = await mkdtemp(join(tmpdir(), "slice2-register-"));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "work", "index.html"), FIXTURE_HTML, "utf8");

    const registered: Array<Record<string, any>> = [];
    const fakePi = { registerTool: (def: Record<string, unknown>) => registered.push(def), on: () => {} };
    registerPlaywrightTool(fakePi as never, {
      getAgentId: () => "agent01",
      logEvent: async (cwd, agent, tool, args, result) => {
        await appendEvent(cwd, { agent, tool, args, result });
      },
    });
    assert.equal(registered.length, 1);
    const tool = registered[0];
    assert.equal(tool.name, "playwright");
    assert.equal(tool.label, "Playwright");

    const ctx = { cwd: root };
    await assert.rejects(
      () => tool.execute("t1", { target: "https://example.com/" }, undefined, undefined, ctx),
      /remote target refused/,
    );
    if (!unavailable) {
      const result = await tool.execute("t2", { target: "work/index.html", screenshot: true, note: "fixture" }, undefined, undefined, ctx);
      assert.equal(result.details.title, "Slice 2 fixture");
      assert.match(result.details.screenshot, /^work\/\.browser\/.*-agent01\.png$/);
    } else {
      t.diagnostic(`browser step skipped: ${unavailable}`);
    }

    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(events.length >= 1);
    for (const event of events) {
      // sid and seq: the sending process and its count (custody reads them).
      assert.deepEqual(Object.keys(event).sort(), ["agent", "args", "result", "seq", "sid", "tool", "ts"]);
      assert.equal(event.tool, "playwright");
      assert.equal(event.agent, "agent01");
    }
    assert.equal(events[0].result.ok, false);
    assert.match(events[0].result.error, /remote target refused/);
    if (!unavailable) {
      assert.equal(events[1].result.ok, true);
      assert.equal(events[1].args.note, "fixture");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
