import assert from "node:assert/strict";
import test from "node:test";
import { exactReviewDecisionFrom } from "../dashboard/exact-review-decision.ts";

const base = {
  targetRepo: "AyobamiH/wagging-web-wins",
  targetBranch: "main",
  itemNumber: 89,
  itemKind: "issue" as const,
  sourceEvent: "issues" as const,
  sourceAction: "acceptance_probe",
  supersedesInProgress: true,
};

test("exact-review decision accepts bounded inference policy overrides", () => {
  for (const inferencePolicy of ["auto", "codex", "workers-ai"] as const) {
    const parsed = exactReviewDecisionFrom({ ...base, inferencePolicy });
    assert.equal(parsed?.inferencePolicy, inferencePolicy);
  }
});

test("exact-review decision rejects unknown inference policy overrides", () => {
  assert.equal(exactReviewDecisionFrom({ ...base, inferencePolicy: "anything-else" }), null);
});
