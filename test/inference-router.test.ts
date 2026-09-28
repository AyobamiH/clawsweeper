import assert from "node:assert/strict";
import test from "node:test";
import { selectInferenceRoute } from "../dist/inference-router.js";

test("auto routing keeps Codex when subscription admission succeeds", async () => {
  const route = await selectInferenceRoute({}, async () => true);
  assert.deepEqual(route, {
    available: true,
    runner: "codex",
    reason: "codex_subscription_available",
  });
});

test("auto routing falls back to Workers AI when Codex admission fails", async () => {
  const route = await selectInferenceRoute(
    {
      CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
      CLOUDFLARE_WORKERS_AI_TOKEN: "model-only-token",
      CLAWSWEEPER_WORKERS_AI_MODEL: "@cf/zai-org/glm-5.3",
    },
    async () => false,
  );
  assert.equal(route.available, true);
  if (!route.available || route.runner !== "openclaw") {
    assert.fail("expected workers ai route");
  }
  assert.equal(route.reason, "codex_subscription_unavailable");
  assert.equal(route.model, "workersai/@cf/zai-org/glm-5.3");
  const providers = JSON.parse(route.providersJson);
  assert.equal(
    providers.workersai.baseUrl,
    "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/v1",
  );
  assert.equal(providers.workersai.apiKey, "${CLOUDFLARE_WORKERS_AI_TOKEN}");
});

test("auto routing fails closed instead of reusing the broad Cloudflare deployment token", async () => {
  const route = await selectInferenceRoute(
    {
      CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
      CLOUDFLARE_API_TOKEN: "broad-token-must-not-be-used",
    },
    async () => false,
  );
  assert.deepEqual(route, {
    available: false,
    runner: "none",
    reason: "workers_ai_configuration_missing",
  });
});

test("forced routes are explicit", async () => {
  assert.deepEqual(
    await selectInferenceRoute({ CLAWSWEEPER_INFERENCE_POLICY: "codex" }, async () => false),
    {
      available: true,
      runner: "codex",
      reason: "forced_codex",
    },
  );
  const workers = await selectInferenceRoute(
    {
      CLAWSWEEPER_INFERENCE_POLICY: "workers-ai",
      CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
      CLOUDFLARE_WORKERS_AI_TOKEN: "model-only-token",
      CLAWSWEEPER_WORKERS_AI_MODEL: "@cf/moonshotai/kimi-k2.7-code",
    },
    async () => true,
  );
  assert.equal(workers.available, true);
  if (!workers.available || workers.runner !== "openclaw") {
    assert.fail("expected workers ai");
  }
  assert.equal(workers.reason, "forced_workers_ai");
  assert.equal(workers.model, "workersai/@cf/moonshotai/kimi-k2.7-code");
});
