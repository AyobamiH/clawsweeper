#!/usr/bin/env node
// Offline and read-only. The inventory consumes only the restricted
// inference-measurement JSONL schema; it never makes model/provider calls.
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA = "clawsweeper.inference-measurement.v1";
const SCHEMA_V2 = "clawsweeper.inference-measurement.v2";
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_EVENTS = 50_000;
const FIELDS = [
  "actualCostUsd",
  "completionVerified",
  "elapsedMs",
  "inputTokens",
  "invocationId",
  "model",
  "outcome",
  "outputTokens",
  "provider",
  "recordedAt",
  "schema",
  "sourceKind",
  "sourceRevision",
  "taskKind",
  "usageSource",
]
  .sort()
  .join(",");
const TASKS = new Set([
  "review",
  "repair",
  "assist",
  "cluster_selection",
  "commercial_generate",
  "commercial_review",
  "unspecified",
]);
const PROVIDERS = new Set(["codex", "openclaw", "openai_api", "workers_ai", "unknown"]);
const OUTCOMES = new Set(["process_ok", "process_failed", "invocation_exception"]);

function validNonNegativeInteger(n) {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

function canonicalRecordedAt(value) {
  // The recorder emits exactly Date#toISOString(), not arbitrary parseable text.
  // Reject arrays, numbers, comments, invalid calendar dates and hidden content.
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

export function validateInferenceMeasurement(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid inference measurement object");
  }
  const expectedFields =
    value.schema === SCHEMA_V2
      ? [...FIELDS.split(","), "decisionId", "cachedInputTokens"].sort().join(",")
      : FIELDS;
  if (Object.keys(value).sort().join(",") !== expectedFields) {
    throw new Error("unexpected inference measurement fields");
  }
  if (
    ![SCHEMA, SCHEMA_V2].includes(value.schema) ||
    (value.schema === SCHEMA_V2 &&
      (typeof value.decisionId !== "string" ||
        !/^[a-f0-9]{64}$/.test(value.decisionId) ||
        (value.cachedInputTokens !== null && !validNonNegativeInteger(value.cachedInputTokens)))) ||
    !TASKS.has(value.taskKind) ||
    !PROVIDERS.has(value.provider) ||
    !OUTCOMES.has(value.outcome) ||
    !["prompt", "committed", "snapshot", "unknown"].includes(value.sourceKind) ||
    !["unavailable", "provider_response"].includes(value.usageSource) ||
    !/^[A-Za-z0-9@/_.-]{1,96}$/.test(value.model) ||
    !/^[a-f0-9-]{36}$/.test(value.invocationId) ||
    !canonicalRecordedAt(value.recordedAt) ||
    !validNonNegativeInteger(value.elapsedMs) ||
    (value.sourceRevision !== null &&
      !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(value.sourceRevision)) ||
    (value.inputTokens !== null && !validNonNegativeInteger(value.inputTokens)) ||
    (value.outputTokens !== null && !validNonNegativeInteger(value.outputTokens)) ||
    value.actualCostUsd !== null ||
    value.completionVerified !== false
  ) {
    throw new Error("invalid inference measurement values");
  }
  if (
    value.usageSource === "unavailable" &&
    (value.inputTokens !== null ||
      value.outputTokens !== null ||
      (value.schema === SCHEMA_V2 && value.cachedInputTokens !== null))
  ) {
    throw new Error("unattributed provider usage");
  }
  return value;
}

function percentile(sorted, percent) {
  if (!sorted.length) return null;
  return sorted[Math.max(0, Math.ceil(sorted.length * percent) - 1)];
}

function summary(events) {
  const n = events.length;
  const durations = events.map((e) => e.elapsedMs).sort((a, b) => a - b);
  const byTask = {};
  const byProvider = {};
  const byRevision = {};
  const outcomes = { process_ok: 0, process_failed: 0, invocation_exception: 0 };
  let usageAvailable = 0;
  let inputObserved = 0;
  let outputObserved = 0;
  const correlatedDecisions = new Set();
  let knownCachedInputTokens = 0;
  let knownInputTokens = 0;
  let knownOutputTokens = 0;

  for (const e of events) {
    if (e.schema === SCHEMA_V2) correlatedDecisions.add(e.decisionId);
    if (
      e.schema === SCHEMA_V2 &&
      e.usageSource === "provider_response" &&
      e.cachedInputTokens !== null
    ) {
      knownCachedInputTokens += e.cachedInputTokens;
    }
    byTask[e.taskKind] = (byTask[e.taskKind] || 0) + 1;
    byProvider[e.provider] = (byProvider[e.provider] || 0) + 1;
    const rev = e.sourceRevision || "unknown";
    byRevision[rev] = (byRevision[rev] || 0) + 1;
    outcomes[e.outcome] += 1;
    if (e.usageSource === "provider_response") {
      if (e.inputTokens !== null) {
        inputObserved += 1;
        knownInputTokens += e.inputTokens;
      }
      if (e.outputTokens !== null) {
        outputObserved += 1;
        knownOutputTokens += e.outputTokens;
      }
      if (e.inputTokens !== null && e.outputTokens !== null) {
        usageAvailable += 1;
      }
    }
  }
  return {
    schema: "clawsweeper.inference-inventory.v1",
    observedInvocations: n,
    observationWindow: n
      ? {
          first: events.map((e) => e.recordedAt).sort()[0],
          last: events
            .map((e) => e.recordedAt)
            .sort()
            .at(-1),
        }
      : null,
    byTask,
    byProvider,
    byRevision,
    outcomes,
    elapsedMs: { median: percentile(durations, 0.5), p95: percentile(durations, 0.95) },
    providerUsageCoverage: {
      observed: usageAvailable,
      inputObserved,
      outputObserved,
      total: n,
    },
    tokensFromProviderResponses: { input: knownInputTokens, output: knownOutputTokens },
    correlatedDecisions: correlatedDecisions.size,
    cachedInputTokensFromProviderResponses: knownCachedInputTokens,
    actualCostUsd: null,
    verifiedCompletedTasks: null,
    cashSavingsDetermination: "insufficient_provider_billing_and_verified_task_outcomes",
    routingPromotion: "not_authorised_by_measurement",
  };
}

export function inventoryInferenceMeasurements(paths) {
  const events = [];
  for (const filename of paths) {
    const fullPath = resolve(filename);
    const stat = lstatSync(fullPath);
    if (!stat.isFile()) throw new Error("inventory requires a regular non-symlink file");
    if (stat.size > MAX_FILE_BYTES) {
      throw new Error("measurement file exceeds offline inventory limit");
    }
    const contents = readFileSync(fullPath, "utf8");
    for (const [index, line] of contents.split(/\r?\n/).entries()) {
      if (!line) continue;
      if (events.length >= MAX_EVENTS) throw new Error("inventory event limit exceeded");
      try {
        events.push(validateInferenceMeasurement(JSON.parse(line)));
      } catch {
        throw new Error("invalid measurement record at " + fullPath + ":" + (index + 1));
      }
    }
  }
  return summary(events);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const paths = process.argv.slice(2);
  if (!paths.length || paths.includes("--help")) {
    console.error(
      "usage: node scripts/analysis/decision-inventory.mjs /private/path/inference.jsonl [...]",
    );
    process.exitCode = paths.includes("--help") ? 0 : 2;
  } else {
    try {
      process.stdout.write(JSON.stringify(inventoryInferenceMeasurements(paths), null, 2) + "\n");
    } catch (error) {
      console.error(
        "inference inventory refused: " +
          (error instanceof Error ? error.message : "invalid input"),
      );
      process.exitCode = 1;
    }
  }
}
