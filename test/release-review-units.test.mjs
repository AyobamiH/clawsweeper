import test from "node:test";
import assert from "node:assert/strict";
import { digest } from "../scripts/commercial/contract.mjs";
import { reviewReleaseUnits } from "../scripts/commercial/source-review.mjs";

const route = { provider: "cloudflare-workers-ai" };
const bundle = {
  schema: "test",
  repository: "AyobamiH/clawsweeper",
  head: "a".repeat(40),
  base: "b".repeat(40),
  files: [
    { path: "one.ts", before: "old", after: "new", beforeMode: "100644", afterMode: "100644" },
    { path: "two.ts", before: "before", after: "after", beforeMode: "100644", afterMode: "100644" },
  ],
};

test("release review requires every complete file and a cross-file pass", async () => {
  const seen = [];
  const infer = async (_route, _prompt, data) => {
    seen.push(data.bundle.files.map((f) => f.path));
    return {
      value: { sourceDigest: data.sourceDigest, complete: true, summary: "checked", findings: [] },
    };
  };
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  assert.equal(result.passed, true);
  assert.deepEqual(seen, [["one.ts"], ["two.ts"], ["one.ts", "two.ts"]]);
  assert.equal(result.coverage.length, 2);
  assert.equal(result.sourceDigest, digest(bundle));
});

test("cross-file response is bound to the actual interaction request digest", async () => {
  let crossFileDigest;
  const infer = async (_route, _prompt, data) => {
    if (data.bundle.reviewedSummaries) {
      crossFileDigest = data.sourceDigest;
      assert.notEqual(data.sourceDigest, digest({ ...data.bundle, files: bundle.files }));
    }
    return {
      value: { sourceDigest: data.sourceDigest, complete: true, summary: "checked", findings: [] },
    };
  };
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  assert.match(crossFileDigest, /^[a-f0-9]{64}$/);
  assert.equal(result.passed, true);
});

test("cross-file response with a mismatched request digest refuses release", async () => {
  const infer = async (_route, _prompt, data) => ({
    value: {
      sourceDigest: data.bundle.reviewedSummaries
        ? digest({ ...data.bundle, files: bundle.files })
        : data.sourceDigest,
      complete: true,
      summary: "checked",
      findings: [],
    },
  });
  await assert.rejects(
    reviewReleaseUnits(route, "review", bundle, {}, infer),
    /source review identity or result invalid/,
  );
});

test("missing or incomplete unit refuses release without clean verdict", async () => {
  let calls = 0;
  const infer = async (_route, _prompt, data) => ({
    value: {
      sourceDigest: data.sourceDigest,
      complete: ++calls !== 2,
      summary: "checked",
      findings: [],
    },
  });
  await assert.rejects(reviewReleaseUnits(route, "review", bundle, {}, infer), /incomplete/);
  assert.equal(calls, 2);
});

test("actionable unit finding fails release and is retained", async () => {
  let calls = 0;
  const infer = async (_route, _prompt, data) => ({
    value: {
      sourceDigest: data.sourceDigest,
      complete: true,
      summary: "checked",
      findings:
        ++calls === 1
          ? [{ severity: "P1", file: "one.ts", line: 1, description: "bad retry" }]
          : [],
    },
  });
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  assert.equal(result.passed, false);
  assert.equal(result.findings[0].description, "bad retry");
});
