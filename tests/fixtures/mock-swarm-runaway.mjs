// A swarm that will not stop itself: every turn is another `wait`, and the
// steer the harness sends when the cap is hit is ignored on purpose.
//
// The point is the kill switch. An agent that complies proves nothing about
// enforcement — it only proves the prompt worked. This script makes the
// harness do the stopping: cap breach -> steer -> grace -> harness writes
// done/SWARM_DONE itself.

// Per agent, not a global counter: whichever agent gets in first would
// otherwise introduce itself twice and the other never at all.
const introduced = new Set();

export default function plan({ agentId }) {
  if (!agentId) return { text: "No swarm contract in this session; nothing to do." };
  if (!introduced.has(agentId)) {
    introduced.add(agentId);
    return {
      text: "Checking in, then settling into a wait loop.",
      toolCalls: [
        {
          name: "post",
          arguments: {
            tag: "intro",
            to: "all",
            body: `${agentId} is here and is going to keep waiting no matter what anyone says.`,
          },
        },
      ],
    };
  }
  return {
    text: "Still waiting.",
    toolCalls: [{ name: "wait", arguments: { seconds: 5 } }],
  };
}
