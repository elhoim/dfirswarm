import assert from "node:assert/strict";
import { test } from "node:test";
import { harnessStopLabel, isCertifiedDone, isHarnessStop, phaseGroup, reachedDone, stopHasWork } from "../ui/src/lib/overview-status.ts";

const base = { phase: "done" as "done" | "finish_failed" | "stop_incomplete", sentinel_by: "s3f0901" as string | null, stop_reason: null as string | null };

test("a certified finish that spent the cap is not a harness cap-stop", () => {
  const row = { ...base, sentinel_by: "s3f0901", stop_reason: "DoD checks passed" };
  assert.equal(isHarnessStop(row), false);
  assert.equal(isCertifiedDone(row), true);
});

test("overview harness-stop matches the detail header: sentinel by harness", () => {
  const row = { ...base, sentinel_by: "harness", stop_reason: "cap" };
  assert.equal(isHarnessStop(row), true);
  assert.equal(isCertifiedDone(row), false);
  assert.equal(harnessStopLabel(row), "stopped by harness · cap");
  assert.equal(harnessStopLabel({ stop_reason: "wall_clock" }), "stopped by harness · wall clock");
});

test("a run whose hub failed to put the VMs away still reached its finish line, and the list files it under done", () => {
  const row = { ...base, phase: "finish_failed" as const, sentinel_by: "s3f0901" };
  assert.equal(reachedDone(row.phase), true);
  assert.equal(isCertifiedDone(row), true, "the work is certified; the failure is the harness's");
  assert.equal(isHarnessStop({ ...row, sentinel_by: "harness" }), true);
  assert.equal(phaseGroup("finish_failed"), "done");
  assert.equal(phaseGroup("failed"), "stopped");
  assert.equal(phaseGroup("stop_incomplete"), "stopped");
  assert.equal(phaseGroup("unknown"), "other");
});

test("a stop that left a VM up does not undo the work: its sentinel still certifies", () => {
  assert.equal(isCertifiedDone({ ...base, phase: "stop_incomplete", sentinel_by: "s3f0901" }), true);
  assert.equal(isCertifiedDone({ ...base, phase: "stop_incomplete", sentinel_by: null }), false, "no sentinel, nothing to certify");
});

test("Stop stays available while something of the run may still be up, finished runs included", () => {
  for (const state of ["running", "prepared", "finished", "finish_failed", "stop_incomplete"]) assert.equal(stopHasWork(state), true, state);
  for (const state of ["stopped", "done", "failed"]) assert.equal(stopHasWork(state), false, state);
});
