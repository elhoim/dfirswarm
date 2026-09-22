/**
 * `playwright` tool: real headless Chromium behind the existing `--playwright`
 * kickoff flag. agent-swarm.ts keeps the registration name/activation; this
 * module owns the implementation so the two can evolve separately.
 *
 * Agents use it to verify what they built in a real browser. The signature:
 *
 *   playwright(target, actions?, screenshot?, text_selector?, note?)
 *     -> { ok, url, final_url, title, text, console_errors, page_errors,
 *          screenshot, actions_run }
 *
 * Safety defaults (product decisions):
 *   - `target` is a sandbox-relative file (served as file://) or a URL.
 *     Remote http(s) is refused unless SWARM_BROWSER_REMOTE=1; loopback is
 *     always allowed so a worker can check a dev server it started via bash.
 *   - Screenshots land in `work/.browser/<ts>-<agent>.png`: hidden dir,
 *     unique names, so no claim is needed and workers never collide.
 *   - `playwright` (npm) is a devDependency, imported lazily. Missing package
 *     or browser -> the tool throws an install hint; extension load is fine.
 *
 * Official Pi API used here (verified on @earendil-works/pi-coding-agent
 * 0.74.2): pi.registerTool({ name, label, description, promptSnippet,
 * promptGuidelines, parameters, execute(toolCallId, params, signal, onUpdate,
 * ctx) }) with ctx.cwd; throw from execute() to report an error to the LLM.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Type } from "typebox";
import { claimKey, keepToolOutput, toolOutputRel, toolText, type FullOutputRef } from "./protocol.ts";

export type BrowserAction =
  | { type: "click"; selector: string }
  | { type: "fill"; selector: string; value: string }
  | { type: "press"; selector: string; value: string }
  | { type: "wait"; selector?: string; ms?: number }
  | { type: "goto"; value: string };

export type BrowserCheckOptions = {
  sandboxRoot: string;
  agentId: string;
  target: string;
  actions?: BrowserAction[];
  screenshot?: boolean;
  textSelector?: string;
  maxTextChars?: number;
  timeoutMs?: number;
  allowRemote?: boolean;
};

export type BrowserCheckResult = {
  ok: true;
  url: string;
  final_url: string;
  title: string;
  text: string;
  text_truncated: boolean;
  /** The whole page text under tool-output/ when `text` is a prefix of it. */
  full_text?: FullOutputRef;
  console_errors: string[];
  page_errors: string[];
  screenshot: string | null;
  actions_run: number;
};

export const SCREENSHOT_DIR = "work/.browser";
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"]);
const ACTION_TYPES = new Set(["click", "fill", "press", "wait", "goto"]);

export function resolveTarget(sandboxRoot: string, target: string, allowRemote: boolean): string {
  const trimmed = target.trim();
  if (!trimmed) throw new Error("playwright: target is empty");
  if (/^https?:\/\//i.test(trimmed)) {
    const url = new URL(trimmed);
    if (!LOOPBACK.has(url.hostname.toLowerCase()) && !allowRemote) {
      throw new Error(
        `playwright: remote target refused (${url.hostname}). Set SWARM_BROWSER_REMOTE=1 to allow non-loopback http(s).`,
      );
    }
    return url.toString();
  }
  if (/^file:\/\//i.test(trimmed)) {
    const abs = decodeURIComponent(new URL(trimmed).pathname);
    return pathToFileURL(join(sandboxRoot, claimKey(sandboxRoot, abs))).toString();
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) {
    throw new Error(`playwright: unsupported scheme in ${trimmed}`);
  }
  return pathToFileURL(join(sandboxRoot, claimKey(sandboxRoot, trimmed))).toString();
}

export function parseActions(raw: unknown): BrowserAction[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new Error("playwright: actions must be an array");
  return raw.map((item, index) => {
    if (!item || typeof item !== "object") throw new Error(`playwright: actions[${index}] is not an object`);
    const action = item as Record<string, unknown>;
    if (typeof action.type !== "string" || !ACTION_TYPES.has(action.type)) {
      throw new Error(`playwright: actions[${index}].type must be one of ${[...ACTION_TYPES].join(", ")}`);
    }
    return action as unknown as BrowserAction;
  });
}

type PlaywrightModule = typeof import("playwright");

async function loadPlaywright(): Promise<PlaywrightModule> {
  try {
    return (await import("playwright")) as PlaywrightModule;
  } catch (err) {
    throw new Error(
      `playwright: package not installed (${(err as Error).message}). Run: npm install && npx playwright install chromium`,
    );
  }
}

export async function runBrowserCheck(opts: BrowserCheckOptions): Promise<BrowserCheckResult> {
  const allowRemote = opts.allowRemote ?? process.env.SWARM_BROWSER_REMOTE === "1";
  const url = resolveTarget(opts.sandboxRoot, opts.target, allowRemote);
  const timeout = opts.timeoutMs ?? 15_000;
  const maxChars = opts.maxTextChars ?? 8_000;
  const pw = await loadPlaywright();

  const launchOptions: Record<string, unknown> = { headless: true };
  // Escape hatches for hosts without the Playwright browser download:
  if (process.env.BROWSER_CHECK_EXECUTABLE) launchOptions.executablePath = process.env.BROWSER_CHECK_EXECUTABLE;
  if (process.env.BROWSER_CHECK_CHANNEL) launchOptions.channel = process.env.BROWSER_CHECK_CHANNEL;

  const browser = await pw.chromium.launch(launchOptions);
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  let actionsRun = 0;
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(timeout);
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => pageErrors.push(err.message));

    await page.goto(url, { waitUntil: "load", timeout });

    for (const action of opts.actions ?? []) {
      switch (action.type) {
        case "click":
          await page.click(action.selector);
          break;
        case "fill":
          await page.fill(action.selector, action.value);
          break;
        case "press":
          await page.press(action.selector, action.value);
          break;
        case "wait":
          if (action.selector) await page.waitForSelector(action.selector);
          if (action.ms) await page.waitForTimeout(Math.min(action.ms, timeout));
          break;
        case "goto":
          await page.goto(resolveTarget(opts.sandboxRoot, action.value, allowRemote), { timeout });
          break;
        default:
          throw new Error(`playwright: unknown action ${JSON.stringify(action)}`);
      }
      actionsRun += 1;
    }

    const title = await page.title();
    const rawText = opts.textSelector
      ? await page.locator(opts.textSelector).first().innerText()
      : await page.locator("body").innerText();
    // The model receives the first `maxChars`; the whole text is kept under
    // tool-output/ and named, so nothing a page said is lost to the record.
    const truncated = rawText.length > maxChars;
    const fullText = truncated ? await keepToolOutput(opts.sandboxRoot, toolOutputRel(opts.agentId, "browser_check", "text"), rawText) : undefined;
    const text = truncated ? `${rawText.slice(0, maxChars)}\n\n[Showing the first ${maxChars} of ${rawText.length} characters. Full text: ${fullText?.path}]` : rawText;

    let screenshot: string | null = null;
    if (opts.screenshot) {
      const dir = join(opts.sandboxRoot, SCREENSHOT_DIR);
      await mkdir(dir, { recursive: true });
      const stamp = new Date().toISOString().replace(/[-:.]/g, "");
      const safeAgent = /^[a-z][a-z0-9_-]{0,31}$/.test(opts.agentId) ? opts.agentId : "unknown";
      const rel = `${SCREENSHOT_DIR}/${stamp}-${safeAgent}.png`;
      await page.screenshot({ path: join(opts.sandboxRoot, rel), fullPage: true });
      screenshot = rel;
    }

    return {
      ok: true,
      url,
      final_url: page.url(),
      title,
      text,
      text_truncated: truncated,
      ...(fullText ? { full_text: fullText } : {}),
      console_errors: consoleErrors,
      page_errors: pageErrors,
      screenshot,
      actions_run: actionsRun,
    };
  } finally {
    await browser.close();
  }
}

export const PLAYWRIGHT_TOOL_PARAMS = Type.Object({
  target: Type.String({
    description: "Sandbox-relative file (e.g. work/index.html) or a loopback URL such as http://127.0.0.1:4321/",
  }),
  actions: Type.Optional(
    Type.Array(
      Type.Object({
        type: Type.String({ description: "click | fill | press | wait | goto" }),
        selector: Type.Optional(Type.String()),
        value: Type.Optional(Type.String()),
        ms: Type.Optional(Type.Number()),
      }),
      { description: "Ordered actions to run after load" },
    ),
  ),
  screenshot: Type.Optional(Type.Boolean({ description: "Save a full-page PNG under work/.browser/" })),
  text_selector: Type.Optional(Type.String({ description: "Return innerText of this selector instead of body" })),
  note: Type.Optional(Type.String({ description: "What you wanted to verify (logged only)" })),
});

type ToolCtx = { cwd: string };
type EventLogger = (
  cwd: string,
  agentId: string,
  tool: string,
  args: Record<string, unknown>,
  result: unknown,
) => Promise<void>;

/**
 * Register the `playwright` tool. `getAgentId` is a getter because
 * agent-swarm.ts resolves the id lazily on session_start.
 */
export function registerPlaywrightTool(
  pi: ExtensionAPI,
  deps: { getAgentId: () => string; logEvent: EventLogger },
): void {
  pi.registerTool({
    name: "playwright",
    label: "Playwright",
    description:
      "Headless Chromium check of a work/ HTML file or a loopback URL: optional actions (click, fill, press, wait, goto), then title, visible text, console/page errors and an optional screenshot path under work/.browser/. Off unless --playwright was passed at kickoff. Remote http(s) is refused unless the spawner sets SWARM_BROWSER_REMOTE=1.",
    promptSnippet: "Render a work/ HTML file or local dev server headlessly and read back text/errors",
    promptGuidelines: [
      "Use playwright to verify a rendered artifact (canvas, SVG, HTML) instead of guessing from source; read console_errors and page_errors before posting a result. Do not use it for the hello-file DoD.",
    ],
    parameters: PLAYWRIGHT_TOOL_PARAMS,
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const agent = deps.getAgentId() || "unknown";
      const logArgs = {
        target: params.target,
        actions: (params.actions ?? []).length,
        screenshot: params.screenshot ?? false,
        text_selector: params.text_selector,
        note: params.note,
      };
      try {
        const result = await runBrowserCheck({
          sandboxRoot: toolCtx.cwd,
          agentId: agent,
          target: params.target,
          actions: parseActions(params.actions),
          screenshot: params.screenshot ?? false,
          textSelector: params.text_selector,
        });
        await deps.logEvent(toolCtx.cwd, agent, "playwright", logArgs, {
          ok: true,
          title: result.title,
          errors: result.console_errors.length + result.page_errors.length,
          screenshot: result.screenshot,
          text_chars: result.text.length,
          ...(result.full_text ? { full_text: result.full_text } : {}),
        });
        return { content: [{ type: "text" as const, text: toolText(result) }], details: result };
      } catch (err) {
        await deps.logEvent(toolCtx.cwd, agent, "playwright", logArgs, {
          ok: false,
          error: (err as Error).message,
        });
        throw err;
      }
    },
  });
}
