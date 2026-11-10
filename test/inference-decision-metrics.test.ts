import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  INFERENCE_MEASUREMENT_SCHEMA,
  buildInferenceMetric,
  recordInferenceDecisionMetric,
} from "../dist/inference-decision-metrics.js";

const observation = {
  taskKind: "review" as const,
  provider: "codex" as const,
  model: "internal",
  sourceKind: "committed" as const,
  sourceRevision: "a".repeat(40),
  elapsedMs: 1300,
  outcome: "process_ok" as const,
};

test("inference measurement is off by default; has no output or files", () => {
  const original = process.env.CLAWSWEEPER_INFERENCE_METRICS_FILE;
  try {
    delete process.env.CLAWSWEEPER_INFERENCE_METRICS_FILE;
    assert.equal(recordInferenceDecisionMetric(observation), false);
  } finally {
    if (original === undefined) delete process.env.CLAWSWEEPER_INFERENCE_METRICS_FILE;
    else process.env.CLAWSWEEPER_INFERENCE_METRICS_FILE = original;
  }
});

test("private opt-in sidecar is structured, append-only and excludes source content", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-inference-metric-"));
  const file = join(root, "inference.jsonl");
  try {
    assert.equal(
      recordInferenceDecisionMetric(observation, { CLAWSWEEPER_INFERENCE_METRICS_FILE: file }),
      true,
    );
    assert.equal(
      recordInferenceDecisionMetric(
        { ...observation, outcome: "process_failed" },
        {
          CLAWSWEEPER_INFERENCE_METRICS_FILE: file,
        },
      ),
      true,
    );
    const text = readFileSync(file, "utf8");
    const metrics = text
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(metrics.length, 2);
    assert.equal(metrics[0].schema, INFERENCE_MEASUREMENT_SCHEMA);
    assert.equal(metrics[0].sourceRevision, "a".repeat(40));
    assert.equal(metrics[0].actualCostUsd, null);
    assert.equal(metrics[0].completionVerified, false);
    assert.deepEqual([metrics[0].inputTokens, metrics[0].outputTokens], [null, null]);
    assert.equal(metrics[1].outcome, "process_failed");
    assert.equal(
      /prompt|secret|stdout|stderr|errorMessage|label|filePath/i.test(
        Object.keys(metrics[0]).join(","),
      ),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("model id is allowlisted and usage is never invented", () => {
  const metric = buildInferenceMetric({
    ...observation,
    model: "bad model? Bearer abc123",
    sourceRevision: "not-a-source-sha",
    providerUsage: { inputTokens: 42, outputTokens: 0 },
  });
  assert.equal(metric.model, "unclassified");
  assert.equal(metric.sourceRevision, null);
  assert.equal(metric.usageSource, "provider_response");
  assert.deepEqual([metric.inputTokens, metric.outputTokens, metric.actualCostUsd], [42, 0, null]);
});

test("refuse public parent directories, symlink destinations and public existing files", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-metric-security-"));
  try {
    const privateFile = join(root, "target.jsonl");
    const link = join(root, "link.jsonl");
    writeFileSync(privateFile, "preserve me\n", { mode: 0o600 });
    symlinkSync(privateFile, link);
    assert.equal(
      recordInferenceDecisionMetric(observation, { CLAWSWEEPER_INFERENCE_METRICS_FILE: link }),
      false,
    );
    assert.equal(readFileSync(privateFile, "utf8"), "preserve me\n");
    chmodSync(privateFile, 0o644);
    assert.equal(
      recordInferenceDecisionMetric(observation, {
        CLAWSWEEPER_INFERENCE_METRICS_FILE: privateFile,
      }),
      false,
    );
    assert.equal(readFileSync(privateFile, "utf8"), "preserve me\n");
    chmodSync(root, 0o755);
    assert.equal(
      recordInferenceDecisionMetric(observation, {
        CLAWSWEEPER_INFERENCE_METRICS_FILE: join(root, "new.jsonl"),
      }),
      false,
    );
    assert.equal(
      recordInferenceDecisionMetric(observation, {
        CLAWSWEEPER_INFERENCE_METRICS_FILE: "relative.jsonl",
      }),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("private writer stops before reaching the offline inventory file limit", () => {
  const root = mkdtempSync(join(tmpdir(), "clawsweeper-metric-cap-"));
  try {
    const file = join(root, "full.jsonl");
    writeFileSync(file, "", { mode: 0o600 });
    truncateSync(file, 8 * 1024 * 1024 - 256 * 1024);
    assert.equal(
      recordInferenceDecisionMetric(observation, { CLAWSWEEPER_INFERENCE_METRICS_FILE: file }),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
