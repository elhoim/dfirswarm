/**
 * A turn that ends in an error is the provider's doing, unless the harness
 * itself ended it. On run sfdc6 the sentinel landed, the harness stopped the
 * three agents still working, aborted their turns, and the board then carried
 * three "PROVIDER ERROR ... This operation was aborted" vetoes that named the
 * provider for something the harness had done five milliseconds earlier. On
 * run s57e9 the abort was excused and the same board carried four more:
 * "Connection error." and "terminated", six seconds after the sentinel, when
 * the last agent out had turned the proxy off under the turns still streaming.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyTurnError } from "../extensions/protocol.ts";

test("an abort after the harness stopped the agent is the harness, whichever way the process learns of it", () => {
  assert.equal(classifyTurnError("This operation was aborted", "sentinel_present", true), "harness");
  assert.equal(classifyTurnError("This operation was aborted", "agent_cap", false), "harness", "a cap stop aborts the turn before any sentinel exists");
  assert.equal(classifyTurnError("This operation was aborted", "hard_kill", false), "harness");
  assert.equal(classifyTurnError("The operation was aborted.", null, true), "harness", "after the sentinel, an abort is the harness even from a process that set no flag");
});

test("a real provider error stays a provider error, stop or no stop", () => {
  assert.equal(classifyTurnError("402 Insufficient Balance", null, false), "provider");
  assert.equal(classifyTurnError("402 Insufficient Balance", null, true), "provider", "a balance error after the sentinel is still the provider's answer");
  assert.equal(classifyTurnError("429 Too Many Requests", "sentinel_present", false), "provider", "a stop flag does not excuse an unrelated error");
  assert.equal(classifyTurnError("the provider returned an error with no message", null, false), "provider");
});

test("an abort with no stop and no sentinel is the provider's, and is reported", () => {
  assert.equal(classifyTurnError("This operation was aborted", null, false), "provider", "a connection the provider dropped mid-stream is worth telling the board");
});

test("a connection that died after the run was over is the teardown, not the provider", () => {
  assert.equal(classifyTurnError("Connection error.", null, true), "harness", "the proxy was turned off by the last agent out");
  assert.equal(classifyTurnError("terminated", null, true), "harness");
  assert.equal(classifyTurnError("read ECONNRESET", "sentinel_present", false), "harness", "a stop the harness began, seen as the socket closing");
  assert.equal(classifyTurnError("Connection error.", "agent_cap", false), "harness");
  assert.equal(classifyTurnError("Connection error.", null, false), "provider", "with the run still on, a dropped connection is worth telling the board");
  assert.equal(classifyTurnError("terminated", null, false), "provider");
});
