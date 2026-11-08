import test from "node:test";
import assert from "node:assert/strict";
import canary from "./fixtures/native-cloudflare-tracing-worker.ts";

const sourceSha = "03d32fb784758d2a3770aaa9721f1212ac061096";

test("local-only native API probe never exposes a request query or header", async () => {
  const request = new Request(
    "https://canary.example/__local/trace-capability?token=should-not-escape",
    {
      headers: { authorization: "Bearer invalid-private-fixture" },
    },
  );
  const response = await canary.fetch(
    request,
    {
      CLAWSWEEPER_DEPLOY_SHA: sourceSha,
    },
    { tracing: { enterSpan: () => null } },
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.local_only, true);
  assert.equal(body.native_api_present, true);
  assert.equal(body.source_revision_claim, sourceSha);
  assert.ok(!JSON.stringify(body).includes("should-not-escape"));
  assert.ok(!JSON.stringify(body).includes("invalid-private-fixture"));
});

test("non-probe requests delegate to ClawSweeper's original Worker health handler", async () => {
  const response = await canary.fetch(
    new Request("https://canary.example/api/health"),
    { CLAWSWEEPER_DEPLOY_SHA: sourceSha, CLAWSWEEPER_ARCH_TRACE_ENABLED: "0" },
    {},
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: "clawsweeper-status",
    deployment_sha: sourceSha,
  });
});
