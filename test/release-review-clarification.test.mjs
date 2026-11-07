import test from "node:test";
import assert from "node:assert/strict";
import {
  reviewReleaseUnits,
  SourceFindingError,
  UNCLASSIFIED_SEVERITY,
} from "../scripts/commercial/source-review.mjs";
const file = {
  path: "a.ts",
  before: "old",
  after: "new",
  beforeMode: "100644",
  afterMode: "100644",
};
const bundle = {
  schema: "test",
  repository: "AyobamiH/clawsweeper",
  head: "a".repeat(40),
  base: "b".repeat(40),
  files: [file],
};
const route = { provider: "cloudflare-workers-ai" };
const run = async (finding) => {
  let calls = 0;
  const infer = async (_r, _p, data) => {
    calls++;
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: true,
        summary: "reviewed",
        findings: calls === 1 ? [finding] : [],
      },
    };
  };
  try {
    return { result: await reviewReleaseUnits(route, "review", bundle, {}, infer), calls };
  } catch (error) {
    error.calls = calls;
    throw error;
  }
};
test("unclassified finding is retained without an additional model clarification", async () => {
  const { result, calls } = await run({
    severity: "Blocker",
    file: "a.ts",
    line: 1,
    description: "genuine issue",
  });
  assert.equal(calls, 2);
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].severity, UNCLASSIFIED_SEVERITY);
  assert.equal(result.findings[0].description, "genuine issue");
});
test("unknown source file fails closed without clarification", async () => {
  await assert.rejects(
    run({ severity: "critical", file: "other.ts", line: 1, description: "issue" }),
    (e) => e instanceof SourceFindingError && e.calls === 1,
  );
});
test("invalid source line fails closed without clarification", async () => {
  await assert.rejects(
    run({ severity: "critical", file: "a.ts", line: -1, description: "issue" }),
    (e) => e instanceof SourceFindingError && e.calls === 1,
  );
});
test("empty finding description fails closed without clarification", async () => {
  await assert.rejects(
    run({ severity: "critical", file: "a.ts", line: 1, description: "" }),
    (e) => e instanceof SourceFindingError && e.calls === 1,
  );
});
