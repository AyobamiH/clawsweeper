import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import {
  readInventoryConfig,
  filterEligibleRepositories,
  filterRepositoriesForMode,
} from "../dist/repair/target-fanout.js";
import {
  createExactReviewAdmissionHarness,
  buildExactReviewQueueRequest,
  jsonResponse,
} from "../test/dashboard-worker-harness.ts";
const targets = [
  "ayobamih/openclaw-operator",
  "ayobamih/openclaw-ops",
  "ayobamih/wagging-web-wins",
];
const target = targets[0];
const excluded = [
  "ayobamih/clawsweeper-state",
  "ayobamih/donestate",
  "ayobamih/clawsweeper",
  "openclaw/clawhub",
  "oneclickpostfactory/social-agents",
];
const config = readInventoryConfig();
const repositories = [...targets, ...excluded].map((nameWithOwner) => ({
  nameWithOwner,
  isDisabled: false,
  isArchived: false,
  isFork: false,
  visibility: "PUBLIC",
  hasIssuesEnabled: true,
  defaultBranch: "main",
}));
const inventory = filterEligibleRepositories(repositories, config);
for (const mode of [
  "hot-intake",
  "normal-review",
  "audit",
  "apply",
  "comment-sync",
  "failed-review-retry",
  "idea-archive-revival",
]) {
  assert.deepEqual(
    filterRepositoriesForMode(inventory, config, mode)
      .map((r) => r.targetRepo)
      .sort(),
    mode === "idea-archive-revival"
      ? [target]
      : ["apply", "comment-sync", "failed-review-retry"].includes(mode)
        ? targets.slice(0, 2).sort()
        : [...targets].sort(),
    mode,
  );
}
const reads = [];
const harness = createExactReviewAdmissionHarness(
  (repo) => {
    reads.push(repo);
    return jsonResponse({ state: "open" });
  },
  { maxConcurrent: "16" },
);
try {
  for (const [i, repo] of [...targets, ...excluded.slice(0, 3)].entries()) {
    assert.equal(
      (
        await harness.queue.fetch(
          buildExactReviewQueueRequest(`old-${i}`, 100 + i, "opened", "issue", repo),
        )
      ).status,
      202,
    );
  }
  const wrangler = readFileSync("dashboard/wrangler.toml", "utf8");
  const allowed = wrangler.match(/^EXACT_REVIEW_ALLOWED_TARGET_REPOS = "([^"]+)"/m)[1];
  harness.queue.env.EXACT_REVIEW_ALLOWED_TARGET_REPOS = allowed;
  for (const [i, repo] of excluded.entries()) {
    const result = await (
      await harness.queue.fetch(
        buildExactReviewQueueRequest(`new-${i}`, 200 + i, "opened", "issue", repo),
      )
    ).json();
    assert.equal(result.accepted, false);
  }
  await harness.queue.alarm();
  assert.equal(harness.dispatched.length, 3);
  assert.deepEqual([...reads].sort(), [...targets].sort());
  const stats = await (await harness.queue.fetch(new Request("https://queue/stats"))).json();
  assert.equal(stats.pending, 0);
  const report = {
    activeTargets: inventory.map((r) => r.targetRepo),
    rejectedNewTargets: excluded,
    retiredQueuedTargets: 3,
    targetPreflightReads: reads,
    dispatched: 3,
    limits:
      "Production queue and SQLite harness with controlled GitHub responses. No production queue mutation, model invocation or target writes.",
  };
  console.log(JSON.stringify(report));
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + "\n");
} finally {
  harness.restore();
}
