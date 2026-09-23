import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const retiredInvestigationFiles = [
  "scripts/verify-app-token-smoke.sh",
  "scripts/verify-app-token-fleet-smoke.sh",
  "scripts/verify-codex-runtime-smoke.sh",
  "scripts/run-first-fleet-observation.sh",
  "scripts/recover-proof-state-observation.sh",
  ".github/workflows/app-token-smoke.yml",
  ".github/workflows/app-token-fleet-smoke.yml",
  ".github/workflows/codex-runtime-smoke.yml",
];

test("temporary repository-wide containment tooling stays retired", () => {
  for (const path of retiredInvestigationFiles) {
    assert.equal(existsSync(path), false, path);
  }
});

test("active-surface guard forbids repository-wide Actions and workflow activation mutations", () => {
  const guard = readFileSync("scripts/check-active-surface.ts", "utf8");
  assert.match(guard, /repository-wide GitHub Actions permission mutation/);
  assert.match(guard, /workflow activation mutation/);
  assert.match(guard, /gh workflow activation mutation/);
});

test("production scheduler remains configured for continuous operation", () => {
  const workflow = readFileSync(".github/workflows/sweep.yml", "utf8");
  for (const cron of [
    'cron: "4/20 * * * *"',
    'cron: "41/10 * * * *"',
    'cron: "37 */6 * * *"',
    'cron: "8,23,38,53 * * * *"',
    'cron: "6,21,36,51 * * * *"',
    'cron: "13 * * * 0-6"',
  ]) {
    assert.equal(workflow.includes(cron), true, cron);
  }
});
