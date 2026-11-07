import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-release-preflight-"));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
  try {
    git("init", "-q");
    git("config", "user.name", "Test");
    git("config", "user.email", "test@example.invalid");
    git("config", "commit.gpgsign", "false");
    writeFileSync(join(root, "sample.md"), "original\n");
    git("add", "sample.md");
    git("commit", "-qm", "fixture");
    const head = git("rev-parse", "HEAD");
    writeFileSync(join(root, "sample.md"), "modified\n");
    const result = spawnSync(
      process.execPath,
      ["scripts/review-release.mjs", "--preflight", root, head, head],
      { encoding: "utf8", timeout: 15000 },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /tracked checkout is dirty/);
    assert.doesNotMatch(result.stdout, /"ready":true/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /ref: \$\{\{ inputs\.release_head \}\}/);
  assert.match(workflow, /path: target/);
  assert.match(workflow, /node scripts\/review-release\.mjs --preflight/);
  assert.ok(
    workflow.lastIndexOf("Install existing trusted input scanner") <
      workflow.lastIndexOf("Read-only exact-head preflight"),
  );
  assert.doesNotMatch(workflow, /gh pr merge|gh api --method (?:POST|PUT|PATCH)/);
});
