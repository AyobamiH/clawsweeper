import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
import { CODEX_VERSION } from "../../scripts/commercial/codex-runtime.mjs";
import { proveBootstrap } from "../../scripts/commercial/prove-bootstrap.mjs";

const workflow = parse(
  readFileSync(
    new URL("../../.github/workflows/commercial-fulfilment.yml", import.meta.url),
    "utf8",
  ),
);

test("commercial provisioning builds and proves the compiled runtime before resource mutation", () => {
  const steps = workflow.jobs.provision.steps;
  const build = steps.findIndex((step) => step.run?.includes("corepack pnpm run build"));
  const proof = steps.findIndex(
    (step) => step.run === "node scripts/commercial/prove-bootstrap.mjs",
  );
  const artifact = steps.findIndex((step) => step.with?.name?.startsWith("commercial-runtime-"));
  const resource = steps.findIndex((step) => step.uses === "./.github/actions/cloudflare-runners");
  assert.ok(build >= 0 && build < proof && proof < artifact && artifact < resource);
  assert.match(steps[build].run, /install --frozen-lockfile --ignore-scripts/);
  assert.equal(steps[artifact].with.path, "dist/");
});

for (const name of ["generate", "semantic-review"]) {
  test(`${name} consumes the same compiled runtime and has no merchant publication authority`, () => {
    const job = workflow.jobs[name];
    assert.ok(job.needs.includes("provision"));
    const download = job.steps.findIndex((step) =>
      step.with?.name?.startsWith("commercial-runtime-"),
    );
    const admission = job.steps.findIndex((step) =>
      step.run?.includes("scripts/commercial/inference.mjs"),
    );
    assert.ok(download >= 0 && admission > download);
    assert.equal(job.steps[download].with.path, "dist");
    assert.match(job.steps[admission].run, /scripts\/commercial\/inference\.mjs/);
    assert.doesNotMatch(job.steps[admission].run, /src\/|\.ts/);
    assert.equal(job.steps[admission].env.CLAWSWEEPER_QUOTA_ENABLED, "1");
    const setup = job.steps.find((step) => step.uses === "./.github/actions/setup-codex");
    assert.equal(setup.with["auth-mode"], "chatgpt");
    assert.match(setup.if, /steps.route.outputs.provider == 'chatgpt-codex'/);
    assert.equal(job.steps[admission].env.CLAWSWEEPER_INFERENCE_POLICY, "auto");
    assert.ok(job.steps[admission].env.CLOUDFLARE_WORKERS_AI_TOKEN);
    assert.ok(!job.steps.some((step) => step.run?.includes("if (!await admitSubscription())")));
    const setupDefinition = parse(
      readFileSync(
        new URL("../../.github/actions/setup-codex/action.yml", import.meta.url),
        "utf8",
      ),
    );
    assert.equal(
      setup.with["codex-version"] || setupDefinition.inputs["codex-version"].default,
      CODEX_VERSION,
    );
    assert.deepEqual(job.permissions || workflow.permissions, { contents: "read" });
    assert.ok(
      !job.steps.some(
        (step) =>
          step.uses?.includes("create-github-app-token") || step.run?.includes("broker.mjs"),
      ),
    );
  });
}

test("commercial failure and cleanup remain explicit without automatic rerun or target merge", () => {
  assert.equal(workflow.concurrency.group, "cloudflare-repair-compute");
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.match(workflow.jobs.cleanup.if, /always\(\)/);
  assert.ok(
    workflow.jobs.cleanup.steps.some(
      (step) =>
        step.uses === "./.github/actions/cloudflare-runners" && step.with.operation === "stop",
    ),
  );
  assert.match(workflow.jobs["report-failure"].if, /cleanup.result != 'success'/);
  for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY", "PROXY_API_KEY"])
    assert.equal(workflow.env[name], "");
  for (const job of Object.values(workflow.jobs)) {
    for (const step of job.steps) {
      if (step.uses?.startsWith("actions/checkout@"))
        assert.equal(step.with["persist-credentials"], false);
    }
  }
});

test(
  "compiled artifact starts without source files or project node_modules and fails closed on denial",
  { timeout: 30000 },
  async () => {
    const proof = await proveBootstrap();
    assert.equal(proof.result, "passed");
    assert.equal(proof.modelTurns, 0);
    assert.equal(proof.realCredentials, false);
    assert.equal(proof.coordinatorRequests, 3);
  },
);
