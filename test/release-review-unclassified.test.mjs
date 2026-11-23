import test from "node:test";
import assert from "node:assert/strict";
import {
  reviewReleaseUnits,
  sourceReviewDecision,
  retainUnclassifiedReleaseFindings,
  UNCLASSIFIED_SEVERITY,
} from "../scripts/commercial/source-review.mjs";
import { digest } from "../scripts/commercial/contract.mjs";
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
test("malformed severity is retained as blocking unclassified evidence without clarification", async () => {
  let calls = 0;
  const infer = async (_r, _p, data) => {
    calls++;
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: true,
        summary: "reviewed",
        findings:
          calls === 1
            ? [{ severity: "critical", file: "a.ts", line: 1, description: "real defect" }]
            : [],
      },
    };
  };
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  assert.equal(calls, 2);
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].severity, UNCLASSIFIED_SEVERITY);
  assert.equal(result.findings[0].description, "real defect");
});
test("unclassified severity cannot be accepted outside release review", () => {
  const v = {
    sourceDigest: digest(bundle),
    complete: true,
    summary: "reviewed",
    findings: [{ severity: "high", file: "a.ts", line: 1, description: "defect" }],
  };
  const n = retainUnclassifiedReleaseFindings(v, bundle);
  assert.throws(() => sourceReviewDecision(n, bundle), /unbound source finding/);
  assert.equal(sourceReviewDecision(n, bundle, null, true).passed, false);
});
test("malformed severity with invented file stays invalid", () => {
  const v = {
    sourceDigest: digest(bundle),
    complete: true,
    summary: "reviewed",
    findings: [{ severity: "critical", file: "other.ts", line: 1, description: "defect" }],
  };
  const n = retainUnclassifiedReleaseFindings(v, bundle);
  assert.equal(n.findings[0].severity, "critical");
  assert.throws(() => sourceReviewDecision(n, bundle, null, true), /unbound source finding/);
});
test("malformed severity with invalid line stays invalid", () => {
  const v = {
    sourceDigest: digest(bundle),
    complete: true,
    summary: "reviewed",
    findings: [{ severity: "critical", file: "a.ts", line: -1, description: "defect" }],
  };
  const n = retainUnclassifiedReleaseFindings(v, bundle);
  assert.equal(n.findings[0].severity, "critical");
});
