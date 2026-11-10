import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { buildInferenceMetric } from "../dist/inference-decision-metrics.js";
import {
  inventoryInferenceMeasurements,
  validateInferenceMeasurement,
} from "../scripts/analysis/decision-inventory.mjs";

const base = {
  taskKind: "review" as const,
  provider: "codex" as const,
  model: "internal",
  sourceKind: "committed" as const,
  elapsedMs: 150,
  outcome: "process_ok" as const,
};

test("read-only inventory aggregates measured invocations without claiming savings", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-inference-inventory-"));
  try {
    const file = join(root, "observations.jsonl");
    const observations = [
      buildInferenceMetric({
        ...base,
        sourceRevision: "b".repeat(40),
        providerUsage: {
          inputTokens: 10,
          outputTokens: 5,
        },
      }),
      buildInferenceMetric({
        ...base,
        taskKind: "repair",
        elapsedMs: 900,
        outcome: "process_failed",
      }),
      buildInferenceMetric({
        ...base,
        taskKind: "repair",
        elapsedMs: 300,
        outcome: "invocation_exception",
      }),
    ];
    writeFileSync(file, observations.map((m) => JSON.stringify(m)).join("\n") + "\n");
    const result = inventoryInferenceMeasurements([file]);
    assert.equal(result.observedInvocations, 3);
    assert.deepEqual(result.byTask, { review: 1, repair: 2 });
    assert.deepEqual(result.outcomes, {
      process_ok: 1,
      process_failed: 1,
      invocation_exception: 1,
    });
    assert.equal(result.elapsedMs.median, 300);
    assert.equal(result.elapsedMs.p95, 900);
    assert.deepEqual(result.providerUsageCoverage, {
      observed: 1,
      inputObserved: 1,
      outputObserved: 1,
      total: 3,
    });
    assert.deepEqual(result.tokensFromProviderResponses, { input: 10, output: 5 });
    assert.equal(result.actualCostUsd, null);
    assert.equal(result.verifiedCompletedTasks, null);
    assert.equal(result.routingPromotion, "not_authorised_by_measurement");
    const cli = spawnSync(process.execPath, ["scripts/analysis/decision-inventory.mjs", file], {
      cwd: process.cwd(),
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(cli.status, 0, cli.stderr);
    assert.equal(JSON.parse(cli.stdout).observedInvocations, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("inventory refuses injected prompt, pricing claims and unknown records", () => {
  const valid = buildInferenceMetric(base);
  assert.throws(() => validateInferenceMeasurement({ ...valid, prompt: "secret" }), /unexpected/);
  for (const noncanonical of [
    "2026-01-01 (secret prompt and credentials here)",
    ["2026-01-01"],
    1767225600000,
    "2026-02-30T00:00:00.000Z",
    "2026-01-01T00:00:00Z",
    "2026-01-01T00:00:00.000Z\nsecrets",
    null,
  ]) {
    assert.throws(
      () => validateInferenceMeasurement({ ...valid, recordedAt: noncanonical }),
      /invalid/,
    );
  }
  assert.throws(() => validateInferenceMeasurement({ ...valid, actualCostUsd: 1 }), /invalid/);
  assert.throws(
    () => validateInferenceMeasurement({ ...valid, completionVerified: true }),
    /invalid/,
  );
  assert.throws(
    () =>
      validateInferenceMeasurement({
        ...valid,
        usageSource: "unavailable",
        inputTokens: 99,
      }),
    /unattributed/,
  );
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-inference-invalid-"));
  try {
    const file = join(root, "invalid.jsonl");
    writeFileSync(file, JSON.stringify({ ...valid, prompt: "secret" }) + "\n");
    assert.throws(() => inventoryInferenceMeasurements([file]), /invalid measurement record/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("inventory preserves independent provider usage when only one token count is known", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-partial-usage-"));
  try {
    const file = join(root, "partial.jsonl");
    const observations = [
      buildInferenceMetric({ ...base, providerUsage: { inputTokens: 32 } }),
      buildInferenceMetric({ ...base, providerUsage: { outputTokens: 7 } }),
    ];
    writeFileSync(file, observations.map((event) => JSON.stringify(event)).join("\n") + "\n");
    const summary = inventoryInferenceMeasurements([file]);
    assert.deepEqual(summary.tokensFromProviderResponses, { input: 32, output: 7 });
    assert.deepEqual(summary.providerUsageCoverage, {
      observed: 0,
      inputObserved: 1,
      outputObserved: 1,
      total: 2,
    });
    assert.equal(summary.actualCostUsd, null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
