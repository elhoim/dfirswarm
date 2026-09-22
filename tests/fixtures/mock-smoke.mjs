// Smallest possible script: one tool call, then a closing sentence. Used to
// prove the mock provider speaks the wire format Pi expects before any swarm
// machinery is involved.
export default function plan({ step }) {
  if (step === 0) {
    return {
      thinking: "Checking the working directory before answering.",
      text: "Listing the directory first.",
      toolCalls: [{ name: "bash", arguments: { command: "echo MOCK_OK" } }],
    };
  }
  return { text: "Done: the shell printed MOCK_OK." };
}
