#!/usr/bin/env node
// A scripted, OpenAI-compatible completions server: a stand-in for a model
// provider so the swarm can be run end to end with no key, no network and no
// money. Everything else in the run is real — real Herdr panes, real Pi
// processes, the real extension, the real file protocol. Only the "thinking"
// is replaced by a program.
//
//   node tests/mock-provider.mjs --port 8787 --script tests/fixtures/<f>.mjs \
//        [--log run.jsonl] [--ready-file PATH]
//
// The script module default-exports plan({agentId, step, messages, tools,
// model, body}) and returns { text?, thinking?, toolCalls?: [{name, arguments}] }.
// `arguments` may be an object (it is JSON-encoded for the wire) or a string.
//
// Two conventions make the scripts simple:
//   agentId  parsed out of the system prompt the swarm extension injects
//            ("Your assigned id is a00."), so a script can branch per agent.
//   step     how many assistant turns this session has already taken, so a
//            script is a plain list of turns instead of a state machine. It is
//            derived from the request, so it stays consistent across retries.
import { createServer } from "node:http";
import { appendFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

function parseArgs(argv) {
  const out = { port: 0, script: "", log: "", readyFile: "" };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--port") out.port = Number(argv[++i]);
    else if (arg === "--script") out.script = argv[++i];
    else if (arg === "--log") out.log = argv[++i];
    else if (arg === "--ready-file") out.readyFile = argv[++i];
    else throw new Error(`mock-provider: unknown argument ${arg}`);
  }
  if (!out.script) throw new Error("mock-provider: --script is required");
  return out;
}

const args = parseArgs(process.argv.slice(2));
const plan = (await import(pathToFileURL(resolve(args.script)).href)).default;
if (typeof plan !== "function") {
  throw new Error(`mock-provider: ${args.script} must default-export a function`);
}

function log(record) {
  if (!args.log) return;
  try {
    appendFileSync(args.log, `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`);
  } catch {
    // A test double must never take the run down over its own bookkeeping.
  }
}

/** Flatten OpenAI content parts to text so scripts can match on it. */
function contentText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((part) => (typeof part === "string" ? part : (part?.text ?? ""))).join("");
}

/**
 * The swarm extension states the id in the system prompt of every turn, which
 * makes it the one identifier that survives compaction and steering.
 */
function findAgentId(messages) {
  for (const message of messages) {
    const match = /Your assigned id is ([a-z][a-z0-9_-]{0,31})\b/.exec(contentText(message.content));
    if (match) return match[1];
  }
  return "";
}

function countAssistantTurns(messages) {
  return messages.filter((message) => message.role === "assistant").length;
}

function chunk(model, delta, finishReason = null) {
  return {
    id: "chatcmpl-mock",
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  };
}

/** Rough but stable: the budget only needs numbers that move, not accuracy. */
function estimateTokens(text) {
  return Math.max(1, Math.ceil(text.length / 4));
}

function usageFor(messages, reply) {
  const promptText = messages.map((message) => contentText(message.content)).join("");
  const prompt = estimateTokens(promptText);
  const completion = estimateTokens(JSON.stringify(reply));
  return {
    prompt_tokens: prompt,
    completion_tokens: completion,
    total_tokens: prompt + completion,
    prompt_tokens_details: { cached_tokens: 0 },
  };
}

function normaliseToolCalls(toolCalls) {
  return (toolCalls ?? []).map((call, index) => ({
    index,
    id: call.id ?? `call_mock_${index}_${Math.random().toString(36).slice(2, 8)}`,
    type: "function",
    function: {
      name: call.name,
      arguments:
        typeof call.arguments === "string" ? call.arguments : JSON.stringify(call.arguments ?? {}),
    },
  }));
}

function streamReply(res, model, reply, messages, includeUsage) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  const send = (payload) => res.write(`data: ${JSON.stringify(payload)}\n\n`);

  send(chunk(model, { role: "assistant", content: "" }));
  if (reply.thinking) send(chunk(model, { reasoning_content: reply.thinking }));
  if (reply.text) send(chunk(model, { content: reply.text }));

  const toolCalls = normaliseToolCalls(reply.toolCalls);
  for (const call of toolCalls) {
    // Split each call across two chunks the way a real provider does, so the
    // client's incremental tool-call assembly is exercised, not bypassed.
    send(
      chunk(model, {
        tool_calls: [
          {
            index: call.index,
            id: call.id,
            type: "function",
            function: { name: call.function.name, arguments: "" },
          },
        ],
      }),
    );
    send(
      chunk(model, {
        tool_calls: [{ index: call.index, function: { arguments: call.function.arguments } }],
      }),
    );
  }

  send(chunk(model, {}, toolCalls.length > 0 ? "tool_calls" : "stop"));
  // The usage-only trailing chunk exists because the client asked for it. A
  // client that did not ask must not get one.
  if (includeUsage) {
    send({
      id: "chatcmpl-mock",
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [],
      usage: usageFor(messages, reply),
    });
  }
  res.write("data: [DONE]\n\n");
  res.end();
}

function jsonReply(res, model, reply, messages) {
  const toolCalls = normaliseToolCalls(reply.toolCalls);
  const body = {
    id: "chatcmpl-mock",
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        logprobs: null,
        message: {
          role: "assistant",
          content: reply.text ?? "",
          refusal: null,
          ...(toolCalls.length > 0
            ? { tool_calls: toolCalls.map(({ index: _index, ...rest }) => rest) }
            : {}),
        },
        finish_reason: toolCalls.length > 0 ? "tool_calls" : "stop",
      },
    ],
    usage: usageFor(messages, reply),
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = createServer((req, res) => {
  // Match on the path alone: a query string is legal, and the base path is
  // whatever the caller put in models.json, so only the suffix is ours to fix.
  const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
  if (!pathname.endsWith("/chat/completions") || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({ error: { message: `mock-provider: no route for ${req.method} ${pathname}` } }),
    );
    return;
  }
  let raw = "";
  req.on("data", (piece) => {
    raw += piece;
  });
  req.on("end", () => {
    let body;
    try {
      body = JSON.parse(raw);
    } catch (error) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message: `mock-provider: bad JSON: ${error}` } }));
      return;
    }
    const messages = body.messages ?? [];
    const agentId = findAgentId(messages);
    const step = countAssistantTurns(messages);
    let reply;
    try {
      reply =
        plan({ agentId, step, messages, tools: body.tools ?? [], model: body.model, body }) ?? {};
    } catch (error) {
      log({ event: "script_error", agentId, step, error: String(error) });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message: `mock-provider script failed: ${error}` } }));
      return;
    }
    log({
      event: "reply",
      agentId,
      step,
      tools: (reply.toolCalls ?? []).map((call) => call.name),
      text: reply.text ? reply.text.slice(0, 120) : undefined,
    });
    if (body.stream) {
      streamReply(res, body.model, reply, messages, body.stream_options?.include_usage === true);
    } else {
      jsonReply(res, body.model, reply, messages);
    }
  });
});

server.listen(args.port, "127.0.0.1", () => {
  const { port } = server.address();
  if (args.readyFile) writeFileSync(args.readyFile, String(port));
  process.stdout.write(`mock-provider listening on http://127.0.0.1:${port}/v1\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
