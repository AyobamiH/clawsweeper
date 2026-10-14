// Offline integration proof: real HTTP loopback, real runner code and Docker.
// Provider responses are fixtures. There is deliberately no live credential path.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { generate } from "./generate.mjs";
import { validate } from "./validate.mjs";
import { review } from "./review.mjs";
import { selectCommercialRoute } from "./inference.mjs";
import { digest } from "./contract.mjs";

const env = {
  CLAWSWEEPER_INFERENCE_POLICY: "auto",
  CLOUDFLARE_ACCOUNT_ID: "fixture_account_123",
  CLOUDFLARE_WORKERS_AI_TOKEN: "fixture-not-a-real-credential",
};
const route = await selectCommercialRoute(env, async () => false);
const directory = await mkdtemp(path.join(os.tmpdir(), "tw-workers-ai-loopback-proof-"));
const contract = {
  schema: "tw.execution-contract.v1",
  orderId: randomUUID(),
  operationId: randomUUID(),
  generation: 1,
  quoteHash: "a".repeat(64),
  requestedOutcome:
    "Change greet() to return exactly Hello commercial fulfilment. without changing tests.",
  repository: {
    fullName: "example/controlled-proof",
    id: "123456",
    baseSha: "b".repeat(40),
    baseBranch: "main",
  },
  scope: {
    allowedPaths: ["src/"],
    acceptanceCriteria: [
      "greet() returns exactly Hello commercial fulfilment. with the full stop.",
    ],
    requiredChecks: [{ name: "test", appId: 15368 }],
    maxFiles: 1,
    maxPatchBytes: 4096,
    validationProfile: "node",
  },
};
const manifest = {
  name: "controlled-proof",
  version: "1.0.0",
  type: "module",
  scripts: { test: "node --test test.mjs" },
};
const lock = {
  name: "controlled-proof",
  version: "1.0.0",
  lockfileVersion: 3,
  packages: { "": { name: "controlled-proof", version: "1.0.0" } },
};
const fixtureTest =
  "import assert from 'node:assert/strict';\nimport {existsSync} from 'node:fs';\nimport {greet} from './src/greet.mjs';\nassert.equal(greet(),'Hello commercial fulfilment.');\nfor(const key of ['GITHUB_TOKEN','CLOUDFLARE_WORKERS_AI_TOKEN','STRIPE_SECRET_KEY','OPENAI_API_KEY']) assert.equal(process.env[key],undefined);\nassert.equal(existsSync('/var/run/docker.sock'),false);\n";
const snapshot = {
  schema: "tw.repository-snapshot.v1",
  repositoryId: contract.repository.id,
  baseSha: contract.repository.baseSha,
  files: [
    { path: "package.json", mode: "100644", content: JSON.stringify(manifest) },
    { path: "package-lock.json", mode: "100644", content: JSON.stringify(lock) },
    { path: "src/greet.mjs", mode: "100644", content: "export const greet = () => 'old';\n" },
    { path: "test.mjs", mode: "100644", content: fixtureTest },
  ],
};
for (const [file, value] of Object.entries({
  "contract.json": contract,
  "snapshot.json": snapshot,
}))
  await writeFile(path.join(directory, file), JSON.stringify(value), { mode: 0o600 });
const changes = [
  {
    path: "src/greet.mjs",
    mode: "100644",
    content: "export const greet = () => 'Hello commercial fulfilment.';\n",
  },
];
const reviewResult = {
  passed: true,
  summary: "Fixture review: the one changed source function returns the exact greeting.",
  criteria: [
    {
      criterionIndex: 0,
      passed: true,
      rationale: "src/greet.mjs returns Hello commercial fulfilment. and test.mjs is unchanged.",
    },
  ],
};
let requests = 0;
const observed = [];
const server = createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const part of req) chunks.push(part);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    assert.equal(req.headers.authorization, `Bearer ${env.CLOUDFLARE_WORKERS_AI_TOKEN}`);
    assert.equal(req.method, "POST");
    assert.equal(body.model, route.model);
    assert.equal(body.tools, undefined);
    assert.equal(body.messages.length, 2);
    const data = JSON.parse(body.messages[1].content);
    observed.push(Object.keys(data).sort());
    const value = ++requests === 1 ? { changes } : reviewResult;
    assert.ok(requests <= 2);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        choices: [
          { finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(value) } },
        ],
      }),
    );
  } catch {
    res.writeHead(500);
    res.end("fixture contract failure");
  }
});
try {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const loopback = `http://127.0.0.1:${server.address().port}`;
  const fetcher = (url, init) => {
    assert.equal(new URL(url).origin, "https://api.cloudflare.com");
    return fetch(loopback, init);
  };
  await generate(directory, { route, env, fetch: fetcher });
  await validate(directory);
  await review(directory, { route, env, fetch: fetcher });
  const candidate = JSON.parse(
    await readFile(path.join(directory, "reviewed-candidate.json"), "utf8"),
  );
  assert.equal(requests, 2);
  assert.equal(candidate.review.reviewer, "workers-ai-fresh-read-only-v1");
  assert.notEqual(
    candidate.generationEvidence.invocationId,
    candidate.review.inference.invocationId,
  );
  assert.deepEqual(observed, [
    ["contract", "snapshot"],
    ["changes", "contract", "snapshot"],
  ]);
  let backendAccepted = false,
    forgedIdentityRejected = false;
  if (process.argv[2]) {
    const { validateProviderEvidence } = await import(
      pathToFileURL(path.resolve(process.argv[2])).href
    );
    await validateProviderEvidence(candidate, digest(contract), candidate.changes);
    backendAccepted = true;
    const forged = structuredClone(candidate);
    forged.review.reviewer = "codex-fresh-read-only-v1";
    await assert.rejects(() =>
      validateProviderEvidence(forged, digest(contract), candidate.changes),
    );
    forgedIdentityRejected = true;
  }
  await assert.rejects(() => generate(directory, { route, env, fetch: fetcher }), {
    code: "EEXIST",
  });
  assert.equal(requests, 2);
  const proof = {
    schema: "tw.commercial-fallback-integration-proof.v1",
    observedAt: new Date().toISOString(),
    sourceSha: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    sourceHasUncommittedChanges: true,
    provider: "loopback_fixture_only",
    modelTurns: 0,
    realCredentials: false,
    route,
    fixtureRequests: requests,
    generatedFiles: candidate.changes.map((x) => x.path),
    generationEvidence: candidate.generationEvidence,
    review: candidate.review,
    validation: candidate.validation,
    backendAccepted,
    forgedIdentityRejected,
    replayRefused: true,
    result: "passed",
    limits:
      "Actual runner, HTTP and credential-free Docker code; all model responses and Codex denial are fixtures. No live Workers AI, hosted workflow, OAuth, Stripe, customer repository, PR or GitHub checks.",
  };
  await mkdir(".artifacts/fallback-20261014", { recursive: true });
  await writeFile(
    ".artifacts/fallback-20261014/integration-proof.json",
    JSON.stringify(proof, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(JSON.stringify(proof));
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
