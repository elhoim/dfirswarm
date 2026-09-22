// The proof-run program for read-only inputs: two real Pi agents, the real
// extension, a directory handed over with --inputs, and every way an agent
// could change it tried on purpose — the write tool, a claim, a shell
// append, a shell delete — with the analysis then written where it belongs.
//
// Same rendezvous machinery as mock-swarm-forge.mjs: one global sequence,
// each step owned by one agent, everyone else told to `wait`. What this run
// has to prove is that after all of it the inputs are byte-for-byte what
// they were, that the tool refusals carried the right reason, that a shell
// write either never happened (kernel guard) or was healed and announced,
// and that the result landed in work/.
let AGENTS = [];
let cursor = 0;
const lastReply = new Map();
let pending = null;
let rosterSeenAt = 0;
const ROSTER_IDLE_MS = 120_000;

const CSV = "inputs/readings.csv";
const NOTES = "inputs/sub/notes.md";
const REPORT = "work/report.md";
// With MOCK_INPUTS_CHMOD=1 the shell attempts first give themselves the write
// bits back, which is what a determined agent would do on a host without a
// kernel guard: the point of that run is to watch the harness heal it.
const FORCE = process.env.MOCK_INPUTS_CHMOD === "1" ? "chmod -R u+w inputs 2>/dev/null; " : "";

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
  return [
    { who: 0, text: "Introducing myself.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${first} here. I will read the inputs and write ${REPORT}.` } } },
    { who: 1, text: "Introducing myself.", call: { name: "post", arguments: { tag: "intro", to: "all", body: `${second} here. I will double-check the inputs after ${first} reports.` } } },

    // What was handed over.
    { who: 0, text: "Listing the read-only inputs.", call: { name: "inputs", arguments: {} } },
    { who: 0, text: "Reading the readings.", call: { name: "read", arguments: { path: CSV } } },

    // Every way to change an input, tried on purpose.
    { who: 0, thinking: "The tool guard should refuse this outright.", text: "Trying to overwrite an input with the write tool.", call: { name: "write", arguments: { path: CSV, content: "tampered\n" } } },
    { who: 0, text: "Trying to claim an input.", call: { name: "claim_file", arguments: { path: CSV, reason: "edit it", seconds: 60 } } },
    { who: 0, text: "Trying to append to an input from the shell.", call: { name: "bash", arguments: { command: `${FORCE}echo tampered >> ${CSV}; echo "append rc=$?"` } } },
    { who: 0, text: "Trying to delete an input from the shell.", call: { name: "bash", arguments: { command: `${FORCE}rm -f ${NOTES}; echo "rm rc=$?"; ls inputs/sub` } } },
    { who: 0, text: "Trying to plant a file under inputs from the shell.", call: { name: "bash", arguments: { command: `${FORCE}echo planted > inputs/planted.txt; echo "plant rc=$?"; ls inputs` } } },
    { who: 0, text: "Checking the readings are what they were.", call: { name: "bash", arguments: { command: `cat ${CSV}; wc -l < ${CSV}` } } },

    // The analysis goes where it belongs.
    { who: 0, text: "Claiming the report.", call: { name: "claim_file", arguments: { path: REPORT, reason: "write the analysis", seconds: 120 } } },
    { who: 0, text: "Writing the report.", call: { name: "write", arguments: { path: REPORT, content: `# Readings\n\nSource: ${CSV} (read-only input).\n\nRows: 3. Sensors: a, b, c. Max reading: 7 (sensor c).\n` } } },
    { who: 0, text: "Releasing the report.", call: { name: "release_file", arguments: { path: REPORT } } },
    { who: 0, text: "Reporting.", call: { name: "post", arguments: { tag: "result", to: "all", body: `${REPORT} is written from ${CSV}. Every attempt to change the inputs was refused or undone; please verify.` } } },

    // The peer wakes on the post, checks for itself, and reads the notes.
    { who: 1, text: "Waiting for the board.", call: { name: "wait", arguments: { seconds: 30 } } },
    { who: 1, text: "Listing the inputs myself.", call: { name: "inputs", arguments: {} } },
    { who: 1, text: "Counting the readings from the shell.", call: { name: "bash", arguments: { command: `wc -l < ${CSV}; cat ${NOTES}` } } },
    { who: 1, text: "Confirming.", call: { name: "post", arguments: { tag: "result", to: "all", body: `Verified: ${CSV} still has its 3 rows and ${NOTES} is present. ${REPORT} matches.` } } },

    { who: 0, terminal: true, text: "The definition of done is met.", call: { name: "done", arguments: { reason: "definition_of_done_met", output_file: REPORT } } },
    { who: 1, terminal: true, text: "Sentinel is up; stopping.", call: { name: "done", arguments: { reason: "sentinel_present", output_file: REPORT } } },
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
