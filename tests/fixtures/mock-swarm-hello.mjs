// The proof-run program for the `hello` goal: one ordered script that two real
// Pi agents execute against the real protocol.
//
// Every agent talks to the same mock-provider process, so this module is a
// rendezvous point as well as a script. That buys determinism: the program is
// a single global sequence, each entry owned by one agent, and an agent whose
// turn has not come yet is told to `wait` — the protocol's own idle primitive.
// Without the barrier, two independent Pi processes would race and the run
// would prove something slightly different every time.
//
// The sequence is chosen to touch what fixtures cannot reach: a real claim
// conflict between two processes, a write blocked for want of a claim, a shell
// write the harness has to *detect* rather than block, a protected path, a side
// thread, and the done sentinel.
let AGENTS = [];
let cursor = 0;
/** Last reply per agent, so an identical retried request never advances twice. */
const lastReply = new Map();
/**
 * The agent whose dispatched step has not reported back yet. Ordering the
 * *dispatch* of steps is not enough: the next step must not go out until the
 * previous one has actually run, or the claim the conflict depends on may not
 * be on disk yet. Pi only calls the model again after the tool result lands,
 * so the owner's next request is the completion signal.
 */
let pending = null;
/** When a roster member was last heard from, used to spot an abandoned run. */
let rosterSeenAt = 0;
/** How long the roster must be silent before an outsider may restart it. */
const ROSTER_IDLE_MS = 120_000;

const HELLO = "work/hello.txt";

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((part) => (typeof part === "string" ? part : (part?.text ?? ""))).join("");
}

/**
 * The ids come from team.json, which each agent reads on its first turn. That
 * keeps the script independent of whatever the spawner named them, and makes
 * the read a real part of the run rather than a detail passed in out of band.
 */
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

/**
 * The mock outlives any single swarm, and a leftover pane from an earlier run
 * will happily keep talking to it.
 *
 * An outsider must not disturb a live run — resetting on any unknown id let a
 * stale pane rewind the program and make the current agents repeat steps. So
 * the roster only gives way once the run it belongs to is over: the program is
 * finished, or nobody on the roster has spoken for two minutes. Until then an
 * outsider is told to stop, which ends its turn instead of leaving it spinning.
 *
 * Returns true when the caller does not belong here and should be sent away.
 */
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

/**
 * The program. `who` indexes the assigned ids rather than naming them, so the
 * script does not need to know what the spawner called them.
 */
function program() {
  const [first, second] = AGENTS;
  const allIds = `${AGENTS.join("\n")}\n`;
  return [
    { who: 0, text: "Introducing myself on the board.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${first} here. I will take the first pass at ${HELLO}.` } } },
    { who: 1, text: "Introducing myself too.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${second} here. I will verify and add my id after ${first}.` } } },

    // A real two-process claim conflict: the second agent asks for a path the
    // first already holds, and has to yield.
    { who: 0, text: "Claiming the shared artifact before writing it.", call: { name: "claim_file", arguments: { path: HELLO, reason: "write my id into the shared list", seconds: 120 } } },
    { who: 1, text: "Trying the same path on purpose to see the lease.", call: { name: "claim_file", arguments: { path: HELLO, reason: "add my id to the shared list", seconds: 120 } } },
    { who: 1, text: "It is held; saying so and standing down.", call: { name: "post", arguments: { tag: "hold", to: "all", body: `${HELLO} is leased by ${first}; yielding until it is released.` } } },

    { who: 0, thinking: "The lease is mine, so this write is legitimate.", text: "Writing my id.", call: { name: "write", arguments: { path: HELLO, content: `${first}\n` } } },
    // The harness cannot block a shell write. It has to notice it afterwards.
    { who: 0, text: "Jotting a scratch note through the shell.", call: { name: "bash", arguments: { command: `echo "scratch note from ${first}" >> work/notes.txt` } } },
    { who: 0, text: "Handing the file over.", call: { name: "release_file", arguments: { path: HELLO } } },
    { who: 0, text: "Telling the board it is free.", call: { name: "post", arguments: { tag: "result", to: "all", body: `${HELLO} holds ${first} and the lease is released. ${second}, add yours.` } } },

    { who: 1, text: "Taking the freed lease.", call: { name: "claim_file", arguments: { path: HELLO, reason: "append my id now the path is free", seconds: 120 } } },
    { who: 1, text: "Reading what is already there.", call: { name: "read", arguments: { path: HELLO } } },
    { who: 1, text: "Writing the full list.", call: { name: "write", arguments: { path: HELLO, content: allIds } } },
    { who: 1, text: "Releasing it.", call: { name: "release_file", arguments: { path: HELLO } } },
    { who: 1, text: "Checking the recorded revisions.", call: { name: "file_history", arguments: { path: HELLO } } },
    { who: 1, text: "Reporting the result.", call: { name: "post", arguments: { tag: "result", to: "all", body: `${HELLO} now lists every assigned id.` } } },

    { who: 0, text: "Reading the board.", call: { name: "inbox", arguments: {} } },
    { who: 0, text: "Diffing the artifact against the last revision I saw.", call: { name: "file_diff", arguments: { path: HELLO } } },
    { who: 0, text: "Checking who holds what.", call: { name: "claims", arguments: {} } },

    { who: 1, text: "Opening a side thread for the review.", call: { name: "thread_open", arguments: { name: "review", purpose: "sign-off on the hello artifact" } } },
    { who: 0, text: "Joining the review thread.", call: { name: "thread_join", arguments: { name: "review" } } },
    { who: 0, text: "Signing off there.", call: { name: "post", arguments: { thread: "review", tag: "result", to: "all", body: `Checked ${HELLO}: every assigned id is present, one per line.` } } },

    // Two probes of the protected set: the write must be blocked, the claim refused.
    { who: 1, text: "Trying to edit the contract itself.", call: { name: "write", arguments: { path: "SWARM.md", content: "# rewritten goal\n" } } },
    { who: 1, text: "Trying to lease it instead.", call: { name: "claim_file", arguments: { path: "SWARM.md", reason: "rewrite the goal", seconds: 60 } } },
    { who: 1, text: "Reporting that the harness refused both.", call: { name: "post", arguments: { tag: "ask", to: "all", body: "SWARM.md is harness-owned: the write was blocked and the claim refused." } } },

    // `done` terminates the session, so its owner never comes back to release
    // the barrier. Marking these terminal keeps the last agent from waiting on
    // a process that has already exited. Both `done` calls can therefore be in
    // flight at once, which is fine: the sentinel is an exclusive file create,
    // so the filesystem decides who made it, not this script's ordering.
    { who: 1, terminal: true, text: "The definition of done is met; stopping the swarm.", call: { name: "done", arguments: { reason: "definition_of_done_met", output_file: HELLO } } },
    { who: 0, terminal: true, text: "Sentinel is up; stopping too.", call: { name: "done", arguments: { reason: "sentinel_present", output_file: HELLO } } },
  ];
}

/** An agent whose turn has not come waits on the board instead of spinning. */
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
    // Nothing left to do. Answering with no tool call ends the turn, so the
    // agent goes idle instead of spinning: once the sentinel exists `wait`
    // returns immediately and a stall loop would burn a model call each time.
    return { text: `The program is finished; ${agentId} has nothing left to do.` };
  }

  if (pending) {
    // Only the owner coming back releases the barrier: its tool call has run
    // and landed on disk. There is deliberately no timeout — releasing a step
    // that has not finished would reorder the program and quietly prove
    // something other than what this run claims to prove. If a pane dies the
    // rest sit in `wait` until the swarm's own wall clock ends the run, which
    // is a visibly broken run rather than a misleading one.
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

/** FNV-1a over the tail of the transcript: length alone collides too easily. */
function signatureOf(messages) {
  const last = messages[messages.length - 1];
  const text = `${last?.role ?? ""} ${textOf(last?.content)}`;
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

  // Pi retries a failed request with an identical body. Replaying the previous
  // answer keeps a retry from consuming the next step of the program.
  const signature = signatureOf(messages);
  const previous = lastReply.get(agentId);
  if (previous?.signature === signature) return previous.reply;

  const reply = decide(request);
  lastReply.set(agentId, { signature, reply });
  return reply;
}
