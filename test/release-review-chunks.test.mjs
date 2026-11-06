import test from "node:test";
import assert from "node:assert/strict";
import { releaseSourceChunks, reviewReleaseUnits } from "../scripts/commercial/source-review.mjs";
const file = {
  path: "big.ts",
  before: Array.from({ length: 181 }, (_, i) => `old${i}`).join("\n"),
  after: Array.from({ length: 181 }, (_, i) => `new${i}`).join("\n"),
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
test("line chunks cover every line once with immutable source identity", () => {
  const c = releaseSourceChunks(file);
  assert.deepEqual(
    c.map((x) => [x.lineStart, x.lineEnd]),
    [
      [1, 80],
      [81, 160],
      [161, 181],
    ],
  );
  assert.match(c[1].after, /81: new80/);
  assert.match(c[2].after, /181: new180/);
  assert.equal(new Set(c.map((x) => x.originalAfterDigest)).size, 1);
});
test("all chunks and cross-file pass required", async () => {
  let calls = 0;
  const infer = async (_r, _p, data) => {
    calls++;
    return {
      value: { sourceDigest: data.sourceDigest, complete: true, summary: "reviewed", findings: [] },
    };
  };
  const result = await reviewReleaseUnits(route, "review", bundle, {}, infer);
  assert.equal(calls, 4);
  assert.equal(result.coverage.length, 3);
  assert.equal(result.passed, true);
});
test("incomplete final chunk blocks cross-file approval", async () => {
  let calls = 0;
  const infer = async (_r, _p, data) => {
    calls++;
    return {
      value: {
        sourceDigest: data.sourceDigest,
        complete: calls !== 3,
        summary: "reviewed",
        findings: [],
      },
    };
  };
  await assert.rejects(reviewReleaseUnits(route, "review", bundle, {}, infer), /chunk incomplete/);
  assert.equal(calls, 3);
});
