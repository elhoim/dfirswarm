// The proof-run program for forged tools: two real Pi agents, the real
// extension, and a tool one of them writes that the other then calls.
//
// Same rendezvous machinery as mock-swarm-hello.mjs — one global sequence,
// each step owned by one agent, everyone else told to `wait` — because what
// this run has to prove is an ordering: the tool exists on disk, then a peer
// wakes up, then the peer's harness has registered it, then the peer calls
// it by name and gets its output back. The interesting failure modes are
// probed too: a reserved name, a peer trying to replace a live author's tool,
// and a tool that exits non-zero.
let AGENTS = [];
let cursor = 0;
const lastReply = new Map();
let pending = null;
let rosterSeenAt = 0;
const ROSTER_IDLE_MS = 120_000;

const HELLO = "work/hello.txt";

const COUNT_LINES = `import json, sys
args = json.load(sys.stdin)
with open(args["path"], encoding="utf-8") as f:
    n = sum(1 for _ in f)
print(json.dumps({"path": args["path"], "lines": n}))
`;

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((part) => (typeof part === "string" ? part : (part?.text ?? ""))).join("");
}

function learnAgents(messages) {
  if (AGENTS.length > 0) return;
  for (const message of messages) {
    if (message.role !== "tool") continue;
    const text = textOf(message.content);
    if (!text.includes('"agents"')) continue;
    const ids = [...text.matchAll(/"id"\s*:\s*"([a-z][a-z0-9_-]{0,31})"/g)].map((m) => m[1]);
    if (ids.length > 0) {
      AGENTS = ids;
      rosterSeenAt = Date.now();
      return;
    }
  }
}

function outsider(agentId) {
  if (AGENTS.length === 0) return false;
  if (AGENTS.includes(agentId)) {
    rosterSeenAt = Date.now();
    return false;
  }
  const finished = cursor >= program().length;
  if (!finished && Date.now() - rosterSeenAt < ROSTER_IDLE_MS) return true;
  AGENTS = [];
  cursor = 0;
  pending = null;
  rosterSeenAt = 0;
  lastReply.clear();
  return false;
}

function program() {
  const [first, second] = AGENTS;
  const allIds = `${AGENTS.join("\n")}\n`;
  return [
    { who: 0, text: "Introducing myself.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${first} here. The goal needs a line counter; I will forge one.` } } },
    { who: 1, text: "Introducing myself.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${second} here. I will use whatever ${first} forges and write ${HELLO}.` } } },

    // Nothing forged yet: the catalogue is empty and says so.
    { who: 0, text: "Checking what exists before writing anything.", call: { name: "tools", arguments: {} } },
    // A reserved name is refused before anything touches disk.
    { who: 0, text: "Trying to shadow a built-in on purpose.", call: { name: "make_tool", arguments: { name: "read", description: "shadow", runtime: "bash", script: "echo no" } } },
    // The real thing.
    { who: 0, thinking: "A parser nobody has; forge it once and hand it to the team.", text: "Forging count_lines.", call: { name: "make_tool", arguments: { name: "count_lines", description: "Count the lines in a sandbox file", runtime: "python3", script: COUNT_LINES, params: { path: { type: "string", required: true, description: "sandbox-relative path" } }, example: 'count_lines(path="team.json")' } } },

    // The peer wakes on the announcement; its harness registers the tool and
    // says so in the wait result. Then it calls the tool by name.
    { who: 1, text: "Waiting for the board.", call: { name: "wait", arguments: { seconds: 30 } } },
    { who: 1, text: "Using the forged tool on team.json.", call: { name: "count_lines", arguments: { path: "team.json" } } },
    { who: 1, text: "And on the contract.", call: { name: "count_lines", arguments: { path: "SWARM.md" } } },
    // A peer may not replace a live author's tool.
    { who: 1, text: "Trying to overwrite the author's tool.", call: { name: "make_tool", arguments: { name: "count_lines", description: "my version", runtime: "bash", script: "echo mine" } } },
    // But may forge a different one, including one that fails, which the
    // harness reports as a failure rather than swallowing.
    { who: 1, text: "Forging a tool that fails on purpose.", call: { name: "make_tool", arguments: { name: "always_fails", description: "Exit non-zero", runtime: "bash", script: "echo boom >&2; exit 3" } } },
    { who: 1, text: "Reporting the counts.", call: { name: "post", arguments: { tag: "result", to: "all", body: `count_lines works from ${second}: team.json and SWARM.md counted.` } } },

    { who: 0, text: "Reading the board.", call: { name: "inbox", arguments: {} } },
    { who: 0, text: "The catalogue now has both tools.", call: { name: "tools", arguments: {} } },
    { who: 0, text: "Calling the peer's failing tool to see the harness report it.", call: { name: "always_fails", arguments: {} } },
    { who: 0, text: "Calling my own tool too.", call: { name: "count_lines", arguments: { path: "team.json" } } },

    // Finish the hello goal so the run certifies.
    { who: 1, text: "Claiming the artifact.", call: { name: "claim_file", arguments: { path: HELLO, reason: "write every id", seconds: 120 } } },
    { who: 1, text: "Writing it.", call: { name: "write", arguments: { path: HELLO, content: allIds } } },
    { who: 1, text: "Releasing it.", call: { name: "release_file", arguments: { path: HELLO } } },
    { who: 1, text: "Checking it with the forged tool.", call: { name: "count_lines", arguments: { path: HELLO } } },
    { who: 1, text: "Reporting.", call: { name: "post", arguments: { tag: "result", to: "all", body: `${HELLO} lists every id; count_lines confirms ${AGENTS.length} lines.` } } },

    { who: 0, terminal: true, text: "The definition of done is met.", call: { name: "done", arguments: { reason: "definition_of_done_met", output_file: HELLO } } },
    { who: 1, terminal: true, text: "Sentinel is up; stopping.", call: { name: "done", arguments: { reason: "sentinel_present", output_file: HELLO } } },
  ];
}

function stall(agentId) {
  return {
    text: `Nothing for ${agentId} to do yet; waiting for the board.`,
    toolCalls: [{ name: "wait", arguments: { seconds: 3 } }],
  };
}

function decide({ agentId, messages }) {
  if (outsider(agentId)) {
    return { text: `${agentId} is not part of the swarm this script is running; stopping here.` };
  }
  learnAgents(messages);
  if (AGENTS.length === 0) {
    return {
      text: "Reading the roster before anything else.",
      toolCalls: [{ name: "read", arguments: { path: "team.json" } }],
    };
  }
  const steps = program();
  if (cursor >= steps.length) {
    return { text: `The program is finished; ${agentId} has nothing left to do.` };
  }
  if (pending) {
    if (pending.agent !== agentId) return stall(agentId);
    pending = null;
  }
  const step = steps[cursor];
  if (AGENTS[step.who] !== agentId) return stall(agentId);
  cursor += 1;
  pending = step.terminal ? null : { agent: agentId, at: Date.now() };
  return {
    ...(step.thinking ? { thinking: step.thinking } : {}),
    text: step.text,
    toolCalls: [step.call],
  };
}

function signatureOf(messages) {
  const last = messages[messages.length - 1];
  const text = `${last?.role ?? ""} ${textOf(last?.content)}`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${messages.length}:${text.length}:${hash.toString(16)}`;
}

export default function plan(request) {
  const { agentId, messages } = request;
  if (!agentId) return { text: "No swarm contract in this session; nothing to do." };
  const signature = signatureOf(messages);
  const previous = lastReply.get(agentId);
  if (previous?.signature === signature) return previous.reply;
  const reply = decide(request);
  lastReply.set(agentId, { signature, reply });
  return reply;
}
