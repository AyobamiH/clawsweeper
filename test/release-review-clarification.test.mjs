import test from "node:test";
import assert from "node:assert/strict";
import { reviewReleaseUnits, SourceFindingError } from "../scripts/commercial/source-review.mjs";
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
const finding = { severity: "Critical", file: "a.ts", line: 1, description: "genuine issue" };
const run = async (change) => {
  let calls = 0;
  const infer = async (_r, _p, data) => {
    calls++;
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: true,
        summary: "reviewed",
        findings: calls === 1 ? [finding] : calls === 2 ? change(finding) : [],
      },
    };
  };
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  return { result, calls };
};
test("bounded clarification preserves real finding and blocks release", async () => {
  const { result, calls } = await run((f) => [{ ...f, severity: "P1" }]);
  assert.equal(calls, 3);
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].description, "genuine issue");
});
test("clarification cannot erase findings", async () => {
  await assert.rejects(
    run(() => []),
    (e) =>
      e instanceof SourceFindingError &&
      e.reason === "invalid_severity" &&
      e.context.clarification === "clarification_contract_violation",
  );
});
test("clarification cannot rewrite valid description", async () => {
  await assert.rejects(
    run((f) => [{ ...f, severity: "P1", description: "changed" }]),
    (e) => e instanceof SourceFindingError,
  );
});
test("clarification cannot alter original source line", async () => {
  await assert.rejects(
    run((f) => [{ ...f, severity: "P1", line: 2 }]),
    (e) => e instanceof SourceFindingError,
  );
});
test("clarification cannot return another invalid severity", async () => {
  await assert.rejects(
    run((f) => [{ ...f, severity: "Blocker" }]),
    (e) => e instanceof SourceFindingError,
  );
});
