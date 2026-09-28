import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(".github/workflows/repair-containment-smoke.yml", "utf8");

test("containment smoke provisions two isolated Cloudflare regression runners", () => {
  assert.match(workflow, /group: cloudflare-repair-compute/);
  assert.match(workflow, /uses: \.\/\.github\/actions\/cloudflare-runners/);
  assert.match(workflow, /max-parallel: 2/);
  assert.match(workflow, /sample: 1[\s\S]*lane: plan/);
  assert.match(workflow, /sample: 2[\s\S]*lane: execute/);
  assert.match(workflow, /run: pnpm run repair:containment-smoke/);
  assert.match(workflow, /Destroy containment smoke compute/);
  assert.doesNotMatch(workflow, /continue-on-error/);
});

test("containment smoke excludes untrusted fork pull requests and grants no target authority", () => {
  assert.match(workflow, /permissions:\n  contents: read/);
  assert.match(
    workflow,
    /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/,
  );
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /permission-administration: write/);
  assert.doesNotMatch(
    workflow,
    /permission-issues|permission-pull-requests|permission-contents: write/,
  );
  assert.doesNotMatch(
    workflow,
    /repair:dispatch|repair:worker|repair:execute-fix|repair:apply-result|git push|gh pr/,
  );
});

test("containment changes trigger the smoke workflow", () => {
  for (const changedPath of [
    ".github/workflows/repair-cluster-worker.yml",
    ".github/workflows/repair-containment-smoke.yml",
    "src/repair/contained-command-worker.ts",
    "src/repair/containment-preflight.ts",
    "src/repair/process-tree-containment.ts",
    "test/repair/containment-preflight.test.ts",
  ]) {
    assert.equal(workflow.match(new RegExp(escapeRegExp(`- "${changedPath}"`), "g"))?.length, 2);
  }
  assert.match(workflow, /workflow_dispatch:/);
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
