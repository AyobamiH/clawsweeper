import assert from "node:assert/strict";
import test from "node:test";
import { digest } from "../scripts/commercial/contract.mjs";
import {
  assertLiveReleaseReviewBudget,
  MAX_RELEASE_REVIEW_FILES,
  reviewReleaseUnits,
} from "../scripts/commercial/source-review.mjs";

function fixture(count) {
  return {
    schema: "test",
    repository: "AyobamiH/clawsweeper",
    base: "b".repeat(40),
    head: "a".repeat(40),
    files: Array.from({ length: count }, (_, index) => ({
      path: `test/review-part-${String(index).padStart(3, "0")}.ts`,
      before: "before",
      after: "after",
      beforeMode: "100644",
      afterMode: "100644",
    })),
  };
}

const route = { provider: "cloudflare-workers-ai" };

test("entire 68-file release is reviewable through the offline, digest-bound contract", async () => {
  assert.equal(MAX_RELEASE_REVIEW_FILES, 80);
  const bundle = fixture(68);
  const observed = [];
  const infer = async (_route, _prompt, data) => {
    observed.push(data.bundle.files.map((file) => file.path));
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: true,
        summary: "complete isolated offline fixture",
        findings: [],
      },
    };
  };
  const result = await reviewReleaseUnits(route, "controlled offline test", bundle, {}, infer);
  assert.equal(result.passed, true);
  assert.equal(result.sourceDigest, digest(bundle));
  assert.equal(result.coverage.length, 68);
  assert.equal(observed.length, 69);
  assert.deepEqual(
    observed.slice(0, -1).map(([file]) => file),
    bundle.files.map((file) => file.path),
  );
  assert.deepEqual(
    observed.at(-1),
    bundle.files.map((file) => file.path),
  );
});

test("81-file release refuses even with a no-cost deterministic provider", async () => {
  let calls = 0;
  await assert.rejects(
    reviewReleaseUnits(route, "refuse", fixture(81), {}, async () => {
      calls++;
      throw new Error("must not call review provider");
    }),
    /unsupported release file count/,
  );
  assert.equal(calls, 0);
});

test("a valid 68-file bundle does not bypass the eight-call spend ceiling", () => {
  const bundle = fixture(68);
  assert.throws(
    () => assertLiveReleaseReviewBudget(bundle, { CLAWSWEEPER_RELEASE_AI_MAX_CALLS: "8" }),
    (error) => error?.code === "preflight_refused" && error?.phase === "inference_budget",
  );
});
