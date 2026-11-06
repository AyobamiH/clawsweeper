import test from "node:test";
import assert from "node:assert/strict";
import { ReviewFailure, classifyReviewFailure } from "../scripts/commercial/review-errors.mjs";
import { workersAiJson } from "../scripts/commercial/workers-ai.mjs";
import { selectCommercialRoute } from "../scripts/commercial/inference.mjs";
const env = {
  CLOUDFLARE_ACCOUNT_ID: "fixture_account_123",
  CLOUDFLARE_WORKERS_AI_TOKEN: "fixture_only_not_real",
};
const route = await selectCommercialRoute(env, async () => false);
const options = (fetch) => ({ env, fetch });
const output = (choice) => Response.json({ choices: [choice] });
const choice = (content, finish_reason = "stop") => ({
  finish_reason,
  message: { role: "assistant", content },
});
const cases = [
  [
    "network",
    async () => {
      throw new Error("private-token-value");
    },
    "provider_network",
    true,
  ],
  ["http-429", async () => new Response("private-body", { status: 429 }), "provider_http", true],
  ["http-401", async () => new Response("private-body", { status: 401 }), "provider_http", false],
  ["http-503", async () => new Response("private-body", { status: 503 }), "provider_http", true],
  ["response-json", async () => new Response("bad JSON"), "provider_response", false],
  ["length", async () => output(choice("{}", "length")), "provider_incomplete", false],
  ["model-json", async () => output(choice("not JSON")), "provider_json", false],
  ["shape", async () => output(choice("[]")), "provider_schema", false],
];
for (const [name, fetch, code, retryEligible] of cases)
  test(`classifies ${name} without replay or data leakage`, async () => {
    let calls = 0;
    await assert.rejects(
      workersAiJson(
        route,
        "review",
        {},
        { type: "object" },
        options(async (...args) => {
          calls++;
          return fetch(...args);
        }),
      ),
      (error) => {
        assert.ok(error instanceof ReviewFailure);
        assert.equal(error.code, code);
        assert.equal(error.retryEligible, retryEligible);
        const diagnostic = classifyReviewFailure(error);
        assert.equal(diagnostic.category, code);
        assert.equal(diagnostic.retryEligible, retryEligible);
        assert.ok(!JSON.stringify(diagnostic).includes("private"));
        return true;
      },
    );
    assert.equal(calls, 1);
  });
test("known incomplete review phases remain bounded and fail closed", () => {
  assert.deepEqual(classifyReviewFailure(new Error("release source chunk incomplete")), {
    category: "review_incomplete",
    phase: "chunk",
    retryEligible: false,
  });
  assert.deepEqual(classifyReviewFailure(new Error("cross-file review incomplete")), {
    category: "review_incomplete",
    phase: "cross_file",
    retryEligible: false,
  });
});
test("review result identity and shape failures have sanitised phase codes", () => {
  for (const [message, category, phase] of [
    ["unexpected source-review output", "provider_schema", "result_shape"],
    ["source review identity or result invalid", "provider_schema", "result_identity"],
    ["invalid source findings", "provider_schema", "finding_shape"],
    ["source changed during review", "preflight_refused", "source_integrity"],
  ]) {
    assert.deepEqual(classifyReviewFailure(new Error(message)), {
      category,
      phase,
      retryEligible: false,
    });
  }
});
test("aggregation overflow exposes bounded count without findings content", () => {
  const error = new ReviewFailure("review_incomplete", {
    phase: "aggregation_overflow",
    findingCount: 43,
  });
  assert.deepEqual(classifyReviewFailure(error), {
    category: "review_incomplete",
    phase: "aggregation_overflow",
    findingCount: 43,
    retryEligible: false,
  });
});
test("unexpected errors remain sanitised and non-retryable", () => {
  assert.deepEqual(classifyReviewFailure(new Error("private credential")), {
    category: "unexpected_error",
    retryEligible: false,
  });
});
