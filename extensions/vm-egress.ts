/**
 * In a microVM, a request to a host msb swaps a credential in for is sent
 * with its body chunked.
 *
 * msb 0.7.2 stops such a request as a leaked credential when the TLS record
 * that carries the request's headers also carries a body byte it decodes: a
 * `%` or a `\u` escape anywhere in the first ~16 KiB of a Content-Length
 * body. It then finds the placeholder in the Authorization header, reports it
 * as `location=body match_form=percent_decoded`, and closes the connection;
 * Pi sees "Connection error." (run se064eb: every compaction summary of one
 * agent failed, because its summary request began with a web server's
 * URL-encoded access log). A chunked body reaches msb apart from the headers,
 * and passed every time a Content-Length one failed (measured in a VM on
 * macOS and on Linux, plain text and 600 KB bodies alike). The server gets the
 * same bytes; only the framing differs.
 *
 * Standalone on purpose: the VM integration test imports it into a guest's
 * Node as it is.
 */

const INSTALLED = Symbol.for("dfirswarm.vm-egress");

type FetchFn = typeof fetch;

/** The hosts msb substitutes a secret for, as the VM's environment names them. */
export function secretHosts(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.SWARM_SECRET_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

function urlOf(input: Parameters<FetchFn>[0]): URL | null {
  try {
    if (typeof input === "string") return new URL(input);
    if (input instanceof URL) return input;
    return null;
  } catch {
    return null;
  }
}

/** A body held whole in memory, as bytes: what undici would frame with Content-Length. */
function wholeBody(body: unknown): Uint8Array | null {
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  return null;
}

function withoutContentLength(headers: HeadersInit | undefined): Headers {
  const out = new Headers(headers);
  out.delete("content-length");
  return out;
}

/** The fetch that sends a whole body to one of `hosts` as a chunked stream, and everything else as it came. */
export function chunkedEgressFetch(original: FetchFn, hosts: string[]): FetchFn {
  const wanted = new Set(hosts.map((h) => h.toLowerCase()));
  return ((input: Parameters<FetchFn>[0], init?: RequestInit) => {
    const url = urlOf(input);
    const bytes = init ? wholeBody(init.body) : null;
    if (!url || url.protocol !== "https:" || !wanted.has(url.hostname.toLowerCase()) || !bytes) return original(input, init);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });
    return original(input, { ...init, headers: withoutContentLength(init?.headers), body, duplex: "half" } as RequestInit);
  }) as FetchFn;
}

/**
 * Wraps the process's fetch once, in a VM with a secret host; the SDKs Pi's
 * providers use take `globalThis.fetch` when they make a client, which they
 * do per request. Answers whether the wrapper is in place.
 */
export function installChunkedEgress(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.SWARM_ISOLATION !== "microvm") return false;
  const hosts = secretHosts(env);
  if (!hosts.length || typeof globalThis.fetch !== "function") return false;
  const g = globalThis as unknown as Record<symbol, boolean> & { fetch: FetchFn };
  if (g[INSTALLED]) return true;
  g.fetch = chunkedEgressFetch(g.fetch.bind(globalThis), hosts);
  g[INSTALLED] = true;
  return true;
}
