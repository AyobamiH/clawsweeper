import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  selectCommercialRoute,
  inferenceEvidence,
  validateInferenceEvidence,
  commercialRoute,
} from "../../scripts/commercial/inference.mjs";
import {
  workersAiJson,
  workersAiRequest,
  MAX_INPUT_BYTES,
  MAX_GLM_INPUT_BYTES,
  MAX_SOURCE_REVIEW_INPUT_BYTES,
  MAX_RESPONSE_BYTES,
} from "../../scripts/commercial/workers-ai.mjs";
import { generate } from "../../scripts/commercial/generate.mjs";
import { review, validateSemanticReview } from "../../scripts/commercial/review.mjs";
import { digest, validateContract } from "../../scripts/commercial/contract.mjs";

const env = {
  CLAWSWEEPER_INFERENCE_POLICY: "auto",
  CLOUDFLARE_ACCOUNT_ID: "fixture_account_123",
  CLOUDFLARE_WORKERS_AI_TOKEN: "fixture_only_not_real",
};
const route = await selectCommercialRoute(env, async () => false);
const output = (value) =>
  Response.json({
    choices: [
      { finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(value) } },
    ],
  });
const schema = { type: "object" };
function contract() {
  return validateContract({
    orderId: "eeb44f8b-a15b-4a20-b3a8-cdb48e6517ee",
    operationId: "b2cb485c-e620-4b13-805c-95589cbb34c7",
    generation: 1,
    quoteHash: "f".repeat(64),
    requestedOutcome: "Return the correct total.",
    repository: {
      fullName: "fixture/project",
      id: "19",
      baseSha: "a".repeat(40),
      baseBranch: "main",
    },
    scope: {
      allowedPaths: ["src/"],
      acceptanceCriteria: ["The total is two."],
      requiredChecks: [{ name: "test", appId: 15368 }],
      maxFiles: 2,
      maxPatchBytes: 8192,
    },
  });
}
const snapshot = () => ({
  schema: "tw.repository-snapshot.v1",
  repositoryId: "19",
  baseSha: "a".repeat(40),
  files: [{ path: "src/value.js", mode: "100644", content: "export const value = 1;\n" }],
});
const changes = () => [
  { path: "src/value.js", mode: "100644", content: "export const value = 2;\n" },
];
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "tw-fallback-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "contract.json"), JSON.stringify(contract()));
  await writeFile(path.join(root, "snapshot.json"), JSON.stringify(snapshot()));
  return root;
}

test("commercial auto selection keeps admitted Codex and falls back independently on denial or coordinator failure", async () => {
  assert.equal((await selectCommercialRoute(env, async () => true)).provider, "chatgpt-codex");
  for (const admit of [
    async () => false,
    async () => {
      throw new Error("coordinator down");
    },
  ]) {
    const selected = await selectCommercialRoute(env, admit);
    assert.equal(selected.provider, "cloudflare-workers-ai");
    assert.equal(selected.reason, "codex_subscription_unavailable");
    assert.equal(selected.transport, "workers-ai-json-v1");
    assert.ok(!JSON.stringify(selected).includes(env.CLOUDFLARE_WORKERS_AI_TOKEN));
  }
});
test("explicit provider policies remain explicit and missing fallback config does not use broad deploy token", async () => {
  const forced = await selectCommercialRoute(
    { CLAWSWEEPER_INFERENCE_POLICY: "codex" },
    async () => {
      assert.fail("forced route must not probe");
    },
  );
  assert.equal(forced.provider, "chatgpt-codex");
  await assert.rejects(() =>
    selectCommercialRoute(
      { CLOUDFLARE_ACCOUNT_ID: env.CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN: "broad" },
      async () => false,
    ),
  );
  assert.throws(() =>
    workersAiRequest(route, "test", {}, schema, {
      ...env,
      CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_WORKERS_AI_TOKEN,
    }),
  );
});
test("Workers AI request is fixed-origin, bounded JSON without tools or inherited credentials", async () => {
  const request = workersAiRequest(route, "Return JSON", { fixture: true }, schema, {
    ...env,
    GH_TOKEN: "private-gh",
    OPENAI_API_KEY: "private-openai",
    CLOUDFLARE_API_TOKEN: "private-deploy",
  });
  assert.equal(new URL(request.url).origin, "https://api.cloudflare.com");
  assert.ok(!request.body.includes("private-"));
  assert.ok(!request.body.includes(env.CLOUDFLARE_WORKERS_AI_TOKEN));
  const body = JSON.parse(request.body);
  assert.equal(body.messages.length, 2);
  assert.equal(body.max_tokens, 8192);
  assert.equal(body.stream, false);
  for (const key of ["tools", "functions", "web_search_options"])
    assert.equal(body[key], undefined);
  let calls = 0;
  const result = await workersAiJson(route, "Return JSON", {}, schema, {
    env,
    fetch: async (url, init) => {
      calls++;
      assert.equal(url, request.url);
      assert.equal(init.redirect, "manual");
      return output({ ok: true });
    },
  });
  assert.equal(result.value.ok, true);
  assert.equal(calls, 1);
});
for (const status of [301, 302, 401, 403, 429, 500, 503]) {
  test(`provider HTTP ${status} stops after one attempt with no credential forwarding or raw body leak`, async () => {
    let calls = 0;
    await assert.rejects(
      () =>
        workersAiJson(route, "test", {}, schema, {
          env,
          fetch: async () => {
            calls++;
            return new Response("private-provider-body", {
              status,
              headers: { Location: "https://evil.invalid" },
            });
          },
        }),
      (error) => !error.message.includes("private-provider-body"),
    );
    assert.equal(calls, 1);
  });
}
for (const [name, response] of [
  [
    "network failure",
    () => {
      throw new Error("private-token-diagnostic");
    },
  ],
  [
    "invalid JSON",
    () =>
      Response.json({
        choices: [{ finish_reason: "stop", message: { role: "assistant", content: "not-json" } }],
      }),
  ],
  [
    "truncated result",
    () =>
      Response.json({
        choices: [{ finish_reason: "length", message: { role: "assistant", content: "{}" } }],
      }),
  ],
  [
    "tool call",
    () =>
      Response.json({
        choices: [
          {
            finish_reason: "stop",
            message: { role: "assistant", content: "{}", tool_calls: [{}] },
          },
        ],
      }),
  ],
  [
    "refusal",
    () =>
      Response.json({
        choices: [
          { finish_reason: "stop", message: { role: "assistant", content: "{}", refusal: "no" } },
        ],
      }),
  ],
  ["array result", () => output([])],
  ["oversized result", () => new Response("x".repeat(MAX_RESPONSE_BYTES + 1))],
]) {
  test(`${name} is not retried or accepted`, async () => {
    let calls = 0;
    await assert.rejects(
      () =>
        workersAiJson(route, "test", {}, schema, {
          env,
          fetch: async () => {
            calls++;
            return response();
          },
        }),
      (error) => !error.message.includes("private-token"),
    );
    assert.equal(calls, 1);
  });
}
test("oversized complete context and invalid deadlines fail before any request", async () => {
  let calls = 0;
  const fetcher = async () => {
    calls++;
    return output({});
  };
  await assert.rejects(() =>
    workersAiJson(route, "test", { source: "x".repeat(MAX_GLM_INPUT_BYTES) }, schema, {
      env,
      fetch: fetcher,
    }),
  );
  const smaller = { ...route, model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast" };
  await assert.rejects(() =>
    workersAiJson(smaller, "test", { source: "x".repeat(MAX_INPUT_BYTES) }, schema, {
      env,
      fetch: fetcher,
    }),
  );
  await assert.rejects(() =>
    workersAiJson(route, "test", {}, schema, { env, fetch: fetcher, timeoutMs: 180001 }),
  );
  assert.equal(calls, 0);
});
test("quota-denied generation produces bounded changes and a provider receipt without model tools", async (t) => {
  const root = await fixture(t);
  let calls = 0;
  const result = await generate(root, {
    env,
    admit: async () => false,
    fetch: async (url, init) => {
      calls++;
      const data = JSON.parse(JSON.parse(init.body).messages[1].content);
      assert.equal(data.snapshot.files[0].path, "src/value.js");
      return output({ changes: changes() });
    },
  });
  assert.equal(result.generationEvidence.provider, "cloudflare-workers-ai");
  assert.equal(result.generationEvidence.resultDigest, digest(changes()));
  await assert.rejects(
    () =>
      generate(root, {
        route,
        env,
        fetch: async () => {
          calls++;
          return output({ changes: changes() });
        },
      }),
    /EEXIST/,
  );
  assert.equal(calls, 1);
});
test("fallback cannot smuggle privileged files or provider evidence inside generated changes", async (t) => {
  for (const value of [
    { changes: [{ path: ".github/workflows/evil.yml", mode: "100644", content: "x" }] },
    { changes: changes(), generationEvidence: { forged: true } },
  ]) {
    const root = await fixture(t);
    await assert.rejects(() => generate(root, { route, env, fetch: async () => output(value) }));
    await assert.rejects(() => readFile(path.join(root, "candidate.json")), { code: "ENOENT" });
  }
});
test("fresh independent Workers AI review binds the candidate and cannot reuse a generation receipt", async (t) => {
  const root = await fixture(t);
  const c = contract();
  const patch = changes();
  const generationEvidence = inferenceEvidence(route, "generate", c, patch);
  await writeFile(
    path.join(root, "validated-candidate.json"),
    JSON.stringify({
      changes: patch,
      generationEvidence,
      validation: { passed: true, candidateDigest: digest(patch), contractDigest: digest(c) },
    }),
  );
  let calls = 0;
  const decision = await review(root, {
    route,
    env,
    fetch: async (url, init) => {
      calls++;
      const data = JSON.parse(JSON.parse(init.body).messages[1].content);
      assert.deepEqual(Object.keys(data).sort(), ["changes", "contract", "snapshot"]);
      return output({
        passed: true,
        summary: "Requested value is implemented.",
        criteria: [{ criterionIndex: 0, passed: true, rationale: "src/value.js exports two." }],
      });
    },
  });
  assert.equal(decision.reviewer, "workers-ai-fresh-read-only-v1");
  assert.notEqual(decision.inference.invocationId, generationEvidence.invocationId);
  assert.equal(calls, 1);
  const changed = { ...decision, summary: "altered after review" };
  assert.throws(() => validateSemanticReview(changed, c, patch), /binding mismatch/);
});
test("negative independent review never writes reviewed-candidate.json", async (t) => {
  const root = await fixture(t);
  const c = contract();
  const patch = changes();
  await writeFile(
    path.join(root, "validated-candidate.json"),
    JSON.stringify({
      changes: patch,
      generationEvidence: inferenceEvidence(route, "generate", c, patch),
      validation: { passed: true, candidateDigest: digest(patch), contractDigest: digest(c) },
    }),
  );
  await assert.rejects(() =>
    review(root, {
      route,
      env,
      fetch: async () =>
        output({
          passed: false,
          summary: "Not proven.",
          criteria: [{ criterionIndex: 0, passed: false, rationale: "Missing proof." }],
        }),
    }),
  );
  await assert.rejects(() => readFile(path.join(root, "reviewed-candidate.json")), {
    code: "ENOENT",
  });
});
test("route files are contract-bound and a corrupt persisted route cannot select a new provider", async (t) => {
  const root = await fixture(t);
  await writeFile(
    path.join(root, "generate-route.json"),
    JSON.stringify({ route, phase: "generate", contractDigest: "0".repeat(64) }),
  );
  await assert.rejects(
    () =>
      commercialRoute(root, "generate", {
        env,
        admit: async () => {
          assert.fail("must not select again");
        },
      }),
    /another contract/,
  );
});
test("provider evidence drops neither extra credential fields nor a changed phase", () => {
  const c = contract();
  const record = inferenceEvidence(route, "generate", c, changes());
  assert.throws(() =>
    validateInferenceEvidence({ ...record, secret: "private" }, "generate", c, changes()),
  );
  assert.throws(() => validateInferenceEvidence(record, "review", c, changes()));
});

test("complete source reviews have a separately bounded context without changing commercial budgets", () => {
  const data = { source: "x".repeat(MAX_GLM_INPUT_BYTES) };
  assert.throws(
    () => workersAiRequest(route, "review", data, schema, env),
    /context exceeds budget/,
  );
  const review = workersAiRequest(route, "review", data, schema, env, "source-review");
  assert.ok(Buffer.byteLength(review.body) < MAX_SOURCE_REVIEW_INPUT_BYTES);
  assert.throws(
    () =>
      workersAiRequest(
        route,
        "review",
        { source: "x".repeat(MAX_SOURCE_REVIEW_INPUT_BYTES) },
        schema,
        env,
        "source-review",
      ),
    /context exceeds budget/,
  );
  assert.throws(
    () => workersAiRequest(route, "review", {}, schema, env, "unbounded"),
    /invalid inference purpose/,
  );
});
