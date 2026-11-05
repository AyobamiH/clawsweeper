import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("release review is exact-head, committed-only, fail-closed and routed through existing provider selector", () => {
  const entry = readFileSync("scripts/review-release.mjs", "utf8");
  const reviewer = readFileSync("scripts/commercial/source-review.mjs", "utf8");
  const router = readFileSync("src/inference-router.ts", "utf8");
  assert.match(entry, /reviewSource\([\s\S]*?"repository-release"[\s\S]*?\)/);
  assert.match(entry, /git\("rev-parse", "HEAD"\)/);
  assert.match(entry, /tracked checkout is dirty/);
  assert.match(entry, /untracked source in review/);
  assert.match(entry, /base is not an ancestor/);
  assert.match(entry, /if \(!result\.passed\) process\.exitCode = 1/);
  assert.match(reviewer, /selectCommercialRoute\(env\)/);
  assert.match(reviewer, /workersAiJson\(route, prompt, data, SCHEMA/);
  assert.match(router, /if \(await admit\(env\)\)/);
  assert.match(router, /return workersRoute\(\)/);
});

test("release preflight rejects uncommitted source without invoking inference", () => {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/review-release.mjs",
      "--preflight",
      ".",
      "03d32fb784758d2a3770aaa9721f1212ac061096",
      "f3e2d205492b126c81aa729475ce67594a2dbc5e",
    ],
    { encoding: "utf8", timeout: 15000 },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /tracked checkout is dirty/);
  assert.doesNotMatch(result.stdout, /"ready":true/);
});

test("release review uses existing owner runner and dedicated Workers AI secret, never merge authority", () => {
  const workflow = readFileSync(".github/workflows/workers-ai-fallback-acceptance.yml", "utf8");
  assert.match(workflow, /release-source-review:/);
  assert.match(workflow, /runs-on: \[self-hosted, Linux, X64, clawsweeper-operations\]/);
  assert.match(
    workflow,
    /CLOUDFLARE_WORKERS_AI_TOKEN: \$\{\{ secrets\.CLOUDFLARE_WORKERS_AI_TOKEN \}\}/,
  );
  assert.match(workflow, /CLAWSWEEPER_INFERENCE_POLICY: auto/);
  assert.match(workflow, /test "\$REVIEW_HEAD" = "\$GITHUB_SHA"/);
  assert.match(workflow, /node scripts\/review-release\.mjs --preflight/);
  assert.ok(
    workflow.lastIndexOf("Install existing trusted input scanner") <
      workflow.lastIndexOf("Read-only exact-head preflight"),
  );
  assert.doesNotMatch(workflow, /gh pr merge|gh api --method (?:POST|PUT|PATCH)/);
});
