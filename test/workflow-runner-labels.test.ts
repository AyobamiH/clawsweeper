import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { parse } from "yaml";

test("active workflows cannot select Blacksmith runners", () => {
  for (const name of readdirSync(".github/workflows").filter((entry) => /\.ya?ml$/.test(entry))) {
    const text = readFileSync(join(".github/workflows", name), "utf8");
    assert.doesNotMatch(text, /blacksmith-/i, name);
  }
});

test("repair jobs use provisioned Cloudflare identities and always clean up", () => {
  const workflow = parse(readFileSync(".github/workflows/repair-cluster-worker.yml", "utf8"));
  assert.equal(workflow.concurrency.group, "cloudflare-repair-compute");
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.match(workflow.jobs.cluster["runs-on"], /needs\.provision\.outputs\.attempt/);
  assert.match(workflow.jobs.cluster["runs-on"], /needs\.provision\.outputs\.plan/);
  assert.match(workflow.jobs.execute["runs-on"], /needs\.provision\.outputs\.attempt/);
  assert.match(workflow.jobs.execute["runs-on"], /needs\.provision\.outputs\.execute/);
  assert.equal(workflow.jobs.provision.outputs.attempt, "${{ steps.runners.outputs.attempt }}");
  assert.match(
    workflow.jobs.cluster.steps[0].run,
    /failed-jobs-only rerun cannot reuse destroyed Cloudflare compute/,
  );
  assert.deepEqual(workflow.jobs.cleanup.needs, ["receipt", "provision", "cluster", "execute"]);
  assert.match(workflow.jobs.cleanup.if, /always\(\)/);
  assert.equal(workflow.env.CLAWSWEEPER_RUNNER, "codex");
  assert.equal(workflow.env.OPENAI_API_KEY, "");
  assert.equal(workflow.env.CLAWSWEEPER_QUOTA_ENABLED, "1");
  assert.equal(workflow.env.CLAWSWEEPER_REVIEW_REPO, "${{ github.repository }}");
});

test("operator fixture cleanup derives its identity and runs after partial launch failure", () => {
  const source = readFileSync(".github/workflows/cloudflare-operator-fixtures.yml", "utf8");
  const workflow = parse(source);
  assert.equal(workflow.jobs.cleanup.if, "${{ always() }}");
  assert.doesNotMatch(workflow.jobs.cleanup.if, /needs\.launch\.outputs/);
  assert.match(source, /GITHUB_REPOSITORY:\$GITHUB_RUN_ID/);
  assert.match(source, /permission-administration: write/);
  assert.match(source, /actions\/runners\/\$runner_id/);
  assert.equal(workflow.jobs.launch.outputs.attempt, "${{ steps.launch.outputs.attempt }}");
  assert.match(workflow.jobs.validate["runs-on"], /needs\.launch\.outputs\.attempt/);
  assert.match(
    workflow.jobs.validate.steps[0].run,
    /failed-jobs-only rerun cannot reuse destroyed Cloudflare fixture compute/,
  );
  assert.match(source, /continuing GitHub runner deregistration/);
  assert.match(source, /--retry-max-time 180 --max-time (?:45|60)/);
});

test("hosted review smoke counts only inference starts", () => {
  const source = readFileSync("scripts/hosted-review-scan-smoke.mjs", "utf8");
  assert.match(source, /process\.argv\.slice\(2\)\.includes\(['"]exec['"]\)/);
  assert.match(source, /assert\.equal\(readFileSync\(calls, "utf8"\), "1"\)/);
});
