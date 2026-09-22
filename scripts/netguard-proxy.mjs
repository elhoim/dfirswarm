#!/usr/bin/env node
/**
 * netguard helper. Two modes, one file, Node >= 18, no dependencies.
 *
 *   proxy  --listen unix:/path.sock|tcp:127.0.0.1:PORT --allow h1,h2 [--log FILE]
 *          HTTP/1.1 forward proxy. CONNECT (HTTPS) and plain GET/POST http://
 *          are allowed only when the destination host matches the allowlist.
 *          Runs in the HOST network namespace and does all DNS resolution.
 *
 *   bridge --unix /path.sock --port PORT
 *          Tiny TCP -> Unix-socket forwarder. Runs INSIDE the empty network
 *          namespace (only `lo`), so the guarded command can reach the proxy
 *          through 127.0.0.1:PORT while having no route to anything else.
 *          Unix sockets are filesystem objects and cross network namespaces.
 *
 * Allowlist grammar (case-insensitive):
 *   api.openai.com        exact host
 *   .googleapis.com       any subdomain of googleapis.com (not the apex)
 *   *.googleapis.com      same as above
 *   api.x.ai:443          host restricted to one port
 * IP literals must be listed explicitly; nothing is resolved for matching.
 */

import { createServer as createHttpServer } from "node:http";
import { connect as tcpConnect, createServer as createTcpServer } from "node:net";
import { unlinkSync, appendFileSync, existsSync } from "node:fs";

const args = process.argv.slice(2);
const mode = args.shift();

function opt(name, fallback) {
  const idx = args.indexOf(name);
  if (idx === -1) return fallback;
  return args[idx + 1];
}

function log(file, line) {
  const stamped = `${new Date().toISOString()} ${line}`;
  process.stderr.write(`[netguard] ${stamped}\n`);
  if (file) {
    try {
      appendFileSync(file, `${stamped}\n`);
    } catch {
      // logging must never break the proxy
    }
  }
}

export function parseAllowlist(raw) {
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .map((entry) => {
      let host = entry;
      let port = null;
      const m = entry.match(/^(.*):(\d+)$/);
      if (m && !entry.startsWith("[")) {
        host = m[1];
        port = Number.parseInt(m[2], 10);
      }
      if (host.startsWith("*.")) host = host.slice(1);
      return { host, port, suffix: host.startsWith(".") };
    });
}

export function isAllowed(rules, hostRaw, port) {
  const host = hostRaw.toLowerCase().replace(/\.$/, "");
  return rules.some((rule) => {
    // A host with no port is HTTPS. CONNECT 127.0.0.1:22 used to succeed
    // once the host was listed; kickoff now emits host:port for local
    // endpoints, and everything else is 443.
    const allowedPort = rule.port === null ? 443 : rule.port;
    if (allowedPort !== port) return false;
    if (rule.suffix) return host.endsWith(rule.host) && host.length > rule.host.length;
    return host === rule.host;
  });
}

function splitHostPort(authority, defaultPort) {
  const m = authority.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
  if (!m) return null;
  return { host: m[1], port: m[2] ? Number.parseInt(m[2], 10) : defaultPort };
}

function runProxy() {
  const listen = opt("--listen", "");
  const allow = parseAllowlist(opt("--allow", ""));
  const logFile = opt("--log", "");
  if (!listen) {
    console.error("proxy: --listen unix:/path or tcp:127.0.0.1:PORT is required");
    process.exit(2);
  }
  if (allow.length === 0) log(logFile, "WARN empty allowlist: every destination will be denied");

  const server = createHttpServer((req, res) => {
    // Plain HTTP forward request: GET http://host/path HTTP/1.1
    let url;
    try {
      url = new URL(req.url);
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("netguard: absolute-form URL required\n");
      return;
    }
    const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;
    if (url.protocol !== "http:" || !isAllowed(allow, url.hostname, port)) {
      log(logFile, `DENY http ${url.hostname}:${port}`);
      res.writeHead(403, { "Content-Type": "text/plain", "X-Netguard": "denied" });
      res.end(`netguard: ${url.hostname}:${port} is not in the allowlist\n`);
      return;
    }
    log(logFile, `ALLOW http ${url.hostname}:${port}`);
    const upstream = tcpConnect(port, url.hostname, () => {
      const headers = { ...req.headers };
      delete headers["proxy-connection"];
      delete headers["proxy-authorization"];
      headers.connection = "close";
      const head = [`${req.method} ${url.pathname}${url.search} HTTP/1.1`];
      for (const [k, v] of Object.entries(headers)) head.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
      upstream.write(`${head.join("\r\n")}\r\n\r\n`);
      req.pipe(upstream);
      upstream.pipe(req.socket);
    });
    upstream.on("error", (err) => {
      log(logFile, `ERROR http ${url.hostname}:${port} ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end(`netguard: upstream error ${err.message}\n`);
      }
    });
  });

  server.on("connect", (req, clientSocket, head) => {
    // Once the server hands a CONNECT over, the socket is ours, listeners and
    // all. A client that resets while a denial is on its way raises 'error'
    // on it, and with nobody listening Node throws and the proxy dies: on run
    // sfeb5 four DENYs for github.com were followed by exactly that, and every
    // agent's next model call failed with "Connection error". The handler
    // goes on first, before any branch can return.
    clientSocket.on("error", (err) => {
      log(logFile, `ERROR client ${req.url} ${err.message}`);
      clientSocket.destroy();
    });
    const target = splitHostPort(req.url, 443);
    if (!target || !isAllowed(allow, target.host, target.port)) {
      log(logFile, `DENY connect ${req.url}`);
      clientSocket.write("HTTP/1.1 403 Forbidden\r\nX-Netguard: denied\r\nConnection: close\r\n\r\n");
      clientSocket.end();
      return;
    }
    log(logFile, `ALLOW connect ${target.host}:${target.port}`);
    const upstream = tcpConnect(target.port, target.host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    const drop = (err) => {
      if (err) log(logFile, `ERROR connect ${target.host}:${target.port} ${err.message}`);
      clientSocket.destroy();
      upstream.destroy();
    };
    upstream.on("error", drop);
    clientSocket.on("close", () => upstream.destroy());
  });

  server.on("clientError", (_err, socket) => {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });
  // Every agent's road to its provider runs through this process. Whatever
  // slips past the handlers above is a line in the log, not an exit.
  process.on("uncaughtException", (err) => log(logFile, `ERROR uncaught ${err?.stack ?? err}`));
  process.on("unhandledRejection", (err) => log(logFile, `ERROR unhandled ${err?.stack ?? err}`));

  const stop = () => {
    server.close();
    if (listen.startsWith("unix:")) {
      try {
        unlinkSync(listen.slice(5));
      } catch {
        // already gone
      }
    }
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  if (listen.startsWith("unix:")) {
    const path = listen.slice(5);
    if (existsSync(path)) unlinkSync(path);
    server.listen(path, () => log(logFile, `proxy listening on ${listen} allow=[${allow.map((r) => (r.suffix ? "*" : "") + r.host + (r.port ? ":" + r.port : "")).join(", ")}]`));
  } else if (listen.startsWith("tcp:")) {
    const hp = splitHostPort(listen.slice(4), 3128);
    server.listen(hp.port, hp.host, () => log(logFile, `proxy listening on ${listen}`));
  } else {
    console.error("proxy: --listen must start with unix: or tcp:");
    process.exit(2);
  }
}

function runBridge() {
  const unix = opt("--unix", "");
  const port = Number.parseInt(opt("--port", "0"), 10);
  if (!unix || !port) {
    console.error("bridge: --unix /path.sock and --port PORT are required");
    process.exit(2);
  }
  const server = createTcpServer((client) => {
    const upstream = tcpConnect(unix);
    const drop = () => {
      client.destroy();
      upstream.destroy();
    };
    upstream.on("error", drop);
    client.on("error", drop);
    upstream.on("connect", () => {
      client.pipe(upstream);
      upstream.pipe(client);
    });
  });
  server.listen(port, "127.0.0.1", () => {
    process.stderr.write(`[netguard] bridge 127.0.0.1:${port} -> ${unix}\n`);
  });
  const stop = () => {
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

if (mode === "proxy") runProxy();
else if (mode === "bridge") runBridge();
else if (mode === "self-test") {
  // Pure allowlist unit checks; no sockets. Used by tests/netguard.test.sh.
  const rules = parseAllowlist("api.openai.com, .googleapis.com, *.x.ai, api.deepseek.com:443, 127.0.0.1:11434");
  const cases = [
    ["api.openai.com", 443, true],
    ["API.OPENAI.COM.", 443, true],
    ["api.openai.com", 22, false],
    ["api.openai.com", 80, false],
    ["evil-api.openai.com", 443, false],
    ["openai.com", 443, false],
    ["generativelanguage.googleapis.com", 443, true],
    ["googleapis.com", 443, false],
    ["api.x.ai", 443, true],
    ["x.ai", 443, false],
    ["api.deepseek.com", 443, true],
    ["api.deepseek.com", 80, false],
    ["127.0.0.1", 80, false],
    ["127.0.0.1", 22, false],
    ["127.0.0.1", 443, false],
    ["127.0.0.1", 11434, true],
    ["localhost", 11434, false],
  ];
  let failed = 0;
  for (const [host, port, expected] of cases) {
    const got = isAllowed(rules, host, port);
    if (got !== expected) {
      failed += 1;
      console.error(`FAIL isAllowed(${host}:${port}) = ${got}, expected ${expected}`);
    }
  }
  console.log(failed === 0 ? `self-test ok (${cases.length} cases)` : `self-test failed (${failed})`);
  process.exit(failed === 0 ? 0 : 1);
} else {
  console.error("usage: netguard-proxy.mjs proxy|bridge|self-test [options]");
  process.exit(2);
}
