import assert from "node:assert/strict";
import test from "node:test";
import {
  codexJsonlUsage,
  openclawEnvelopeUsage,
  structuredProviderUsage,
} from "../dist/inference-provider-usage.js";
import { buildInferenceMetric } from "../dist/inference-decision-metrics.js";
import { validateInferenceMeasurement } from "../scripts/analysis/decision-inventory.mjs";

const observation = {
  taskKind: "assist" as const,
  provider: "codex" as const,
  model: "unknown",
  sourceKind: "prompt" as const,
  elapsedMs: 50,
  outcome: "process_ok" as const,
};

test("provider usage reads structured Codex turns and keeps cached input separate", () => {
  const events = [
    { type: "thread.started", thread_id: "private-ignored" },
    { type: "item.completed", item: { type: "agent_message", text: '{"input_tokens":900000}' } },
    {
      type: "turn.completed",
      usage: { input_tokens: 320, output_tokens: 7, cached_input_tokens: 200 },
    },
  ];
  assert.deepEqual(codexJsonlUsage(events.map((value) => JSON.stringify(value)).join("\n")), {
    inputTokens: 320,
    outputTokens: 7,
    cachedInputTokens: 200,
  });
});

test("invalid, missing, oversized and arbitrary textual counters remain unknown", () => {
  for (const output of [
    "",
    "answer: 900 tokens",
    "x".repeat(256 * 1024 + 1),
    JSON.stringify({ type: "turn.completed", usage: { input_tokens: -1, output_tokens: "42" } }),
    JSON.stringify({ type: "item.completed", item: { usage: { input_tokens: 100 } } }),
  ]) {
    assert.equal(codexJsonlUsage(output), undefined);
  }
  assert.equal(structuredProviderUsage({ inputTokens: Infinity, outputTokens: -5 }), undefined);
});

test("known partial counts survive without inventing missing provider usage", () => {
  assert.deepEqual(
    codexJsonlUsage(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 12 } })),
    { inputTokens: 12 },
  );
  assert.deepEqual(
    codexJsonlUsage(
      [
        { type: "turn.completed", usage: { input_tokens: 12, output_tokens: 1 } },
        { type: "turn.completed", usage: { input_tokens: 5, output_tokens: 2 } },
      ]
        .map((value) => JSON.stringify(value))
        .join("\n"),
    ),
    { inputTokens: 17, outputTokens: 3 },
  );
});

test("OpenClaw usage is extracted from provider metadata, not model text", () => {
  assert.deepEqual(
    openclawEnvelopeUsage({
      result: {
        meta: {
          agentMeta: {
            usage: { input: 70, output: 9, cacheRead: 60 },
          },
        },
        payloads: [{ text: "secret prompt 123" }],
      },
    }),
    { inputTokens: 70, outputTokens: 9, cachedInputTokens: 60 },
  );
  assert.equal(
    openclawEnvelopeUsage({ payloads: [{ text: '{"usage":{"input":900}}' }] }),
    undefined,
  );
});

test("correlated v2 metrics retain stable decisions while v1 remains valid", () => {
  const legacy = buildInferenceMetric(observation);
  assert.equal(legacy.schema, "clawsweeper.inference-measurement.v1");
  assert.equal(Object.hasOwn(legacy, "decisionId"), false);
  validateInferenceMeasurement(legacy);
  const linked = buildInferenceMetric({
    ...observation,
    decisionId: "d".repeat(64),
    providerUsage: { inputTokens: 50, outputTokens: 3, cachedInputTokens: 40 },
  });
  assert.equal(linked.schema, "clawsweeper.inference-measurement.v2");
  assert.equal(linked.decisionId, "d".repeat(64));
  assert.equal(linked.cachedInputTokens, 40);
  assert.equal(linked.actualCostUsd, null);
  assert.equal(linked.completionVerified, false);
  validateInferenceMeasurement(linked);
  assert.throws(() => validateInferenceMeasurement({ ...linked, cachedInputTokens: -1 }));
  assert.throws(() =>
    validateInferenceMeasurement({ ...linked, decisionId: "private arbitrary text" }),
  );
  assert.throws(() => buildInferenceMetric({ ...observation, decisionId: "unsafe" }));
});
