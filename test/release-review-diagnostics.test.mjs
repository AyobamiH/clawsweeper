import test from "node:test";
import assert from "node:assert/strict";
import { digest } from "../scripts/commercial/contract.mjs";
import {
  sourceFindingDiagnostic,
  sourceReviewDecision,
  SourceFindingError,
  reviewReleaseUnits,
} from "../scripts/commercial/source-review.mjs";
const file = {
  path: "src/a.ts",
  before: "old\nold2",
  after: "new\nnew2",
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
const chunk = { lineStart: 1, lineEnd: 2 };
test("classifies invalid finding fields without leaking content", () => {
  for (const [finding, reason] of [
    [{ severity: "P1", file: "elsewhere", line: 1, description: "secret" }, "unknown_file"],
    [{ severity: "P1", file: file.path, line: 0, description: "secret" }, "invalid_line"],
    [{ severity: "P1", file: file.path, line: 3, description: "secret" }, "line_outside_chunk"],
    [{ severity: "P1", file: file.path, line: 1, description: "secret" }, null],
  ])
    assert.equal(sourceFindingDiagnostic(finding, bundle, chunk), reason);
});
test("genuine finding remains actionable and blocks approval", () => {
  const value = {
    sourceDigest: digest(bundle),
    complete: true,
    summary: "checked",
    findings: [{ severity: "P1", file: file.path, line: 2, description: "real defect" }],
  };
  const result = sourceReviewDecision(value, bundle, chunk);
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].description, "real defect");
});
test("unbound finding is refused with bounded reason and index", () => {
  const value = {
    sourceDigest: digest(bundle),
    complete: true,
    summary: "checked",
    findings: [{ severity: "P1", file: "secret-path", line: 2, description: "secret detail" }],
  };
  assert.throws(
    () => sourceReviewDecision(value, bundle, chunk),
    (e) =>
      e instanceof SourceFindingError &&
      e.reason === "unknown_file" &&
      e.context.index === 0 &&
      !JSON.stringify(e).includes("secret"),
  );
});
test("chunk error carries only immutable source identifiers", async () => {
  const route = { provider: "cloudflare-workers-ai" };
  const infer = async (_r, _p, data) => ({
    value: {
      sourceDigest: data.sourceDigest,
      complete: true,
      summary: "checked",
      findings: [
        { severity: "P1", file: "unrecognised", line: 1, description: "sensitive content" },
      ],
    },
  });
  await assert.rejects(
    reviewReleaseUnits(route, "review", bundle, {}, infer),
    (e) =>
      e instanceof SourceFindingError &&
      e.reason === "unknown_file" &&
      e.context.pathDigest === digest(file.path) &&
      !JSON.stringify(e).includes("sensitive"),
  );
});
