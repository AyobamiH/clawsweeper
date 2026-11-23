import test from "node:test";
import assert from "node:assert/strict";
import {
  reviewReleaseUnits,
  SourceFindingError,
  releaseSourceChunks,
} from "../scripts/commercial/source-review.mjs";
import { classifyReviewFailure, ReviewFailure } from "../scripts/commercial/review-errors.mjs";
const route = { provider: "cloudflare-workers-ai" };
const file = {
  path: "src/review.ts",
  before: "old\n".repeat(85),
  after: "new\n".repeat(85),
  beforeMode: "100644",
  afterMode: "100644",
};
const bundle = {
  schema: "test",
  repository: "AyobamiH/clawsweeper",
  base: "b".repeat(40),
  head: "a".repeat(40),
  files: [file],
};
const finding = (line, description = "real defect", severity = "P1") => ({
  file: file.path,
  line,
  severity,
  description,
});
function replay(responses) {
  let calls = 0;
  const infer = async (_route, _prompt, data) => {
    const index = calls++;
    const response = responses[index] ?? {};
    if (response.throw) throw response.throw;
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: true,
        summary: "checked",
        findings: [],
        ...response,
      },
    };
  };
  return { run: () => reviewReleaseUnits(route, "review", bundle, {}, infer), count: () => calls };
}
test("offline replay: complete source coverage is deterministic, zero provider credentials", async () => {
  const x = replay([]);
  const result = await x.run();
  assert.equal(x.count(), releaseSourceChunks(file).length + 1);
  assert.equal(result.passed, true);
  assert.equal(result.coverage.length, 2);
});
test("offline replay: unclassified severity retains anchored finding and blocks approval", async () => {
  const x = replay([{ findings: [finding(1, "issue", "CRITICAL")] }]);
  const result = await x.run();
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].severity, "UNCLASSIFIED");
});
test("offline replay: unknown file refuses with source-bound diagnostic", async () => {
  const x = replay([{ findings: [{ ...finding(1), file: "src/other.ts" }] }]);
  await assert.rejects(
    x.run(),
    (e) =>
      e instanceof SourceFindingError &&
      e.reason === "unknown_file" &&
      typeof e.context.pathDigest === "string",
  );
  assert.equal(x.count(), 1);
});
test("offline replay: out-of-chunk line refuses without further calls", async () => {
  const x = replay([{ findings: [finding(400)] }]);
  await assert.rejects(
    x.run(),
    (e) => e instanceof SourceFindingError && e.reason === "line_outside_chunk",
  );
  assert.equal(x.count(), 1);
});
test("offline replay: incomplete chunk refuses without cross-file inference", async () => {
  const x = replay([{ complete: false }]);
  await assert.rejects(x.run(), /incomplete/);
  assert.equal(x.count(), 1);
});
test("offline replay: extra model keys refuse without exposing content", async () => {
  const x = replay([{ privateCredential: "secret" }]);
  await assert.rejects(
    x.run(),
    (e) =>
      classifyReviewFailure(e).phase === "result_extra_fields" &&
      !JSON.stringify(classifyReviewFailure(e)).includes("secret"),
  );
});
test("offline replay: changed source digest refuses", async () => {
  const x = replay([{ sourceDigest: "0".repeat(64) }]);
  await assert.rejects(x.run(), /identity/);
});
test("offline replay: provider timeout remains a typed failure, no replay", async () => {
  const x = replay([
    { throw: new ReviewFailure("provider_network", { phase: "inference", retryEligible: true }) },
  ]);
  await assert.rejects(x.run(), (e) => classifyReviewFailure(e).category === "provider_network");
  assert.equal(x.count(), 1);
});
test("offline replay: exact duplicates grouped, real findings still block", async () => {
  const x = replay([
    { findings: [finding(1)] },
    { findings: [finding(81)] },
    { findings: [finding(1)] },
  ]);
  const result = await x.run();
  assert.equal(result.passed, false);
  assert.deepEqual(result.findingTotals, { observed: 3, distinct: 2, duplicates: 1 });
});
test("offline replay: distinct findings over cap refuse rather than truncate", async () => {
  const many = Array.from({ length: 30 }, (_, i) => finding(1, "issue " + i));
  const x = replay([
    { findings: many },
    { findings: [finding(82, "distinct issue")] },
    { findings: [] },
  ]);
  await assert.rejects(
    x.run(),
    (e) =>
      e.code === "review_incomplete" && e.phase === "aggregation_overflow" && e.findingCount === 31,
  );
});
