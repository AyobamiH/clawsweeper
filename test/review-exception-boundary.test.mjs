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
test("unexpected errors remain sanitised and non-retryable", () => {
  assert.deepEqual(classifyReviewFailure(new Error("private credential")), {
    category: "unexpected_error",
    retryEligible: false,
  });
});
