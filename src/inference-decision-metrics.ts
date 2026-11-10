import { randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, writeSync } from "node:fs";
import { isAbsolute, dirname } from "node:path";

export const INFERENCE_MEASUREMENT_SCHEMA = "clawsweeper.inference-measurement.v1" as const;

export type InferenceTaskKind =
  | "review"
  | "repair"
  | "assist"
  | "cluster_selection"
  | "commercial_generate"
  | "commercial_review"
  | "unspecified";

export type InferenceMetricProvider =
  | "codex"
  | "openclaw"
  | "openai_api"
  | "workers_ai"
  | "unknown";
export type InferenceMetricOutcome = "process_ok" | "process_failed" | "invocation_exception";

export interface InferenceDecisionObservation {
  taskKind: InferenceTaskKind;
  provider: InferenceMetricProvider;
  model: string;
  sourceKind: "prompt" | "committed" | "snapshot" | "unknown";
  sourceRevision?: string | undefined;
  elapsedMs: number;
  outcome: InferenceMetricOutcome;
  // These values must come from the provider's structured usage response, never
  // an estimate derived from response text, prompt size or a model price sheet.
  providerUsage?: { inputTokens?: number; outputTokens?: number };
}

const SHA = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i;
const MODEL = /^[a-zA-Z0-9@/_.-]{1,96}$/;
const MAX_ELAPSED_MS = 24 * 60 * 60 * 1000;
// Keep a margin below the offline inventory 8 MiB per-file read cap.
const MAX_LOCAL_RECORD_BYTES = 8 * 1024 * 1024 - 256 * 1024;

function safeTokens(value: number | undefined): number | null {
  return Number.isSafeInteger(value) && value !== undefined && value >= 0 ? value : null;
}

export function buildInferenceMetric(input: InferenceDecisionObservation) {
  if (!Number.isFinite(input.elapsedMs) || input.elapsedMs < 0) {
    throw new Error("invalid inference elapsed time");
  }
  const model = MODEL.test(input.model) ? input.model : "unclassified";
  return {
    schema: INFERENCE_MEASUREMENT_SCHEMA,
    invocationId: randomUUID(),
    recordedAt: new Date().toISOString(),
    taskKind: input.taskKind,
    provider: input.provider,
    model,
    sourceKind: input.sourceKind,
    sourceRevision:
      input.sourceRevision && SHA.test(input.sourceRevision) ? input.sourceRevision : null,
    elapsedMs: Math.min(MAX_ELAPSED_MS, Math.round(input.elapsedMs)),
    outcome: input.outcome,
    usageSource: input.providerUsage ? "provider_response" : "unavailable",
    inputTokens: safeTokens(input.providerUsage?.inputTokens),
    outputTokens: safeTokens(input.providerUsage?.outputTokens),
    actualCostUsd: null,
    completionVerified: false,
  };
}

// Explicit local opt-in only. A missing, unsafe or unavailable destination
// must never alter agent execution, stdout/stderr or application return codes.
// Do not persist prompts, output text, error messages, labels, paths or secrets.
export function recordInferenceDecisionMetric(
  observation: InferenceDecisionObservation,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const filename = env.CLAWSWEEPER_INFERENCE_METRICS_FILE;
  if (!filename) return false;
  let fd: number | undefined;
  try {
    if (!isAbsolute(filename) || !filename.endsWith(".jsonl")) return false;
    const directory = lstatSync(dirname(filename));
    if (!directory.isDirectory() || (directory.mode & 0o077) !== 0) return false;
    if (typeof process.getuid === "function" && directory.uid !== process.getuid()) return false;
    const record = JSON.stringify(buildInferenceMetric(observation)) + "\n";
    if (Buffer.byteLength(record) > 2_048) return false;
    fd = openSync(
      filename,
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        (constants.O_NOFOLLOW ?? 0) |
        (constants.O_NONBLOCK ?? 0),
      0o600,
    );
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) return false;
    if (stat.size + Buffer.byteLength(record) > MAX_LOCAL_RECORD_BYTES) return false;
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) return false;
    return writeSync(fd, record) === Buffer.byteLength(record);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* Metrics must never change the agent outcome. */
      }
    }
  }
}
