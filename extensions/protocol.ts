/**
 * The DFIR Swarm protocol: the board, exclusive file claims, the write guard,
 * the sentinel, the budget, file history, the bash-write watch, forged tools,
 * read-only inputs, the ledger and the names. Pure functions over the sandbox
 * on disk; nothing here imports Pi. The layout is documented in
 * docs/protocol.md, and the Pi-facing side (tools and hooks) lives in
 * `agent-swarm.ts`.
 *
 * Claim key = sandbox-relative path. Locks use spawner-assigned agent ids,
 * not the names agents choose for themselves.
 */

export * from "./protocol-core.ts";
export * from "./ledger-rules.ts";
export * from "./sensitive.ts";
export * from "./finish-line.ts";
