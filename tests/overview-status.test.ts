import assert from "node:assert/strict";
import { test } from "node:test";
import { harnessStopLabel, isCertifiedDone, isHarnessStop } from "../ui/src/lib/overview-status.ts";

const base = { phase: "done" as const, sentinel_by: "s3f0901", stop_reason: null as string | null };

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
