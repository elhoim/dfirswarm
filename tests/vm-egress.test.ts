/**
 * The VM's fetch sends a body to a host msb swaps a credential in for as a
 * chunked stream: msb 0.7.2 closed a Content-Length request whose first TLS
 * record held a `%` or a `\u` escape next to the Authorization header, and an
 * agent's every compaction summary failed on it (run se064eb). The guest side
 * against a real msb is in vm-integration.test.ts.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { chunkedEgressFetch, installChunkedEgress, secretHosts } from "../extensions/vm-egress.ts";

type Seen = { input: unknown; init: RequestInit | undefined };

function recorder(): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const fake = (async (input: unknown, init?: RequestInit) => {
    seen.push({ input, init });
    return new Response("ok");
  }) as typeof fetch;
  return { fetch: fake, seen };
}

async function bytesOf(body: unknown): Promise<string> {
  assert.ok(body instanceof ReadableStream, "the body is a stream");
  return new Response(body as ReadableStream).text();
}

test("a whole body to a secret host goes as a stream with no Content-Length; the rest of the request is kept", async () => {
  const { fetch: fake, seen } = recorder();
  const f = chunkedEgressFetch(fake, ["api.openai.com"]);
  const body = JSON.stringify({ input: "GET /dvwa/?q=%27%20OR%201%3D1 — x" });
  const signal = new AbortController().signal;
  await f("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), authorization: "Bearer placeholder" },
    body,
    signal,
  });
  const init = seen[0].init as RequestInit & { duplex?: string };
  assert.equal(seen[0].input, "https://api.openai.com/v1/responses");
  assert.equal(init.method, "POST");
  assert.equal(init.duplex, "half");
  assert.equal(init.signal, signal);
  const headers = new Headers(init.headers);
  assert.equal(headers.get("content-length"), null);
  assert.equal(headers.get("content-type"), "application/json");
  assert.equal(headers.get("authorization"), "Bearer placeholder");
  assert.equal(await bytesOf(init.body), body, "the server gets the same bytes");

  // Bytes, a buffer and a URL object are whole bodies too.
  await f(new URL("https://API.openai.com/v1/x"), { method: "POST", body: new TextEncoder().encode("a%41") });
  assert.equal(await bytesOf(seen[1].init?.body), "a%41");
  await f("https://api.openai.com/v1/x", { method: "POST", body: new TextEncoder().encode("b%41").buffer as ArrayBuffer });
  assert.equal(await bytesOf(seen[2].init?.body), "b%41");
});

test("anything else passes as it came: another host, plain http, a Request, a stream, no body", async () => {
  const { fetch: fake, seen } = recorder();
  const f = chunkedEgressFetch(fake, ["api.openai.com"]);
  const cases: Array<[Parameters<typeof fetch>[0], RequestInit | undefined]> = [
    ["https://pypi.org/simple/x", { method: "POST", body: "%41" }],
    ["http://api.openai.com/v1/x", { method: "POST", body: "%41" }],
    [new Request("https://api.openai.com/v1/x", { method: "POST", body: "%41" }), undefined],
    ["https://api.openai.com/v1/x", { method: "POST", body: new ReadableStream(), duplex: "half" } as RequestInit],
    ["https://api.openai.com/v1/models", undefined],
    ["https://api.openai.com/v1/models", { method: "GET" }],
  ];
  for (const [input, init] of cases) await f(input, init);
  for (const [i, [input, init]] of cases.entries()) {
    assert.equal(seen[i].input, input, `case ${i}: input`);
    assert.equal(seen[i].init, init, `case ${i}: the same init, untouched`);
  }
});

test("installed only in a VM with a secret host, once", async () => {
  const before = globalThis.fetch;
  try {
    assert.equal(installChunkedEgress({ SWARM_SECRET_HOSTS: "api.openai.com" }), false, "not in a VM");
    assert.equal(installChunkedEgress({ SWARM_ISOLATION: "microvm", SWARM_SECRET_HOSTS: " , " }), false, "no secret host");
    assert.equal(globalThis.fetch, before);
    assert.deepEqual(secretHosts({ SWARM_SECRET_HOSTS: "API.openai.com, www.virustotal.com,," }), ["api.openai.com", "www.virustotal.com"]);
    assert.equal(installChunkedEgress({ SWARM_ISOLATION: "microvm", SWARM_SECRET_HOSTS: "api.openai.com" }), true);
    const wrapped = globalThis.fetch;
    assert.notEqual(wrapped, before);
    assert.equal(installChunkedEgress({ SWARM_ISOLATION: "microvm", SWARM_SECRET_HOSTS: "api.openai.com" }), true);
    assert.equal(globalThis.fetch, wrapped, "a second load does not wrap the wrapper");
  } finally {
    globalThis.fetch = before;
    delete (globalThis as unknown as Record<symbol, unknown>)[Symbol.for("dfirswarm.vm-egress")];
  }
});
