import test from "node:test";
import assert from "node:assert/strict";
import {
  aggregateReleaseFindings,
  reviewReleaseUnits,
} from "../scripts/commercial/source-review.mjs";
const f = (line, description = "defect", severity = "P1") => ({
  file: "a.ts",
  line,
  severity,
  description,
});
const bundle = {
  schema: "test",
  repository: "AyobamiH/clawsweeper",
  head: "a".repeat(40),
  base: "b".repeat(40),
  files: [{ path: "a.ts", before: "old", after: "new", beforeMode: "100644", afterMode: "100644" }],
};
const route = { provider: "cloudflare-workers-ai" };
const inferWith = (first, cross) => async (_r, _p, data) => ({
  value: {
    sourceDigest: data.sourceDigest,
    complete: true,
    summary: "checked",
    findings: data.bundle.reviewedSummaries ? cross : first,
  },
});
test("only exact duplicate findings are grouped, with original evidence retained", () => {
  const x = aggregateReleaseFindings([f(1), f(1), f(1, "different"), f(2), f(1, "defect", "P2")]);
  assert.equal(x.total, 5);
  assert.equal(x.duplicates, 1);
  assert.equal(x.findings.length, 4);
  assert.equal(x.findings[0].occurrences, 2);
  assert.equal(x.findings[1].description, "different");
});
test("repeated cross-file finding remains blocking and preserves multiplicity", async () => {
  const result = await reviewReleaseUnits(route, "review", bundle, {}, inferWith([f(1)], [f(1)]));
  assert.equal(result.passed, false);
  assert.deepEqual(result.findingTotals, { observed: 2, distinct: 1, duplicates: 1 });
  assert.equal(result.findings[0].occurrences, 2);
});
test("31 distinct findings refuse release even if duplicates also exist", async () => {
  const distinct = Array.from({ length: 30 }, (_, i) => f(1, "defect " + i));
  await assert.rejects(
    reviewReleaseUnits(
      route,
      "review",
      bundle,
      {},
      inferWith(distinct, [f(1, "new defect"), f(1, "new defect")]),
    ),
    (e) =>
      e.code === "review_incomplete" && e.phase === "aggregation_overflow" && e.findingCount === 31,
  );
});
test("duplicate-heavy review does not overflow but still blocks release", async () => {
  const many = Array.from({ length: 30 }, () => f(1));
  const result = await reviewReleaseUnits(route, "review", bundle, {}, inferWith(many, many));
  assert.equal(result.passed, false);
  assert.deepEqual(result.findingTotals, { observed: 60, distinct: 1, duplicates: 59 });
});
