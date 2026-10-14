import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  API_ORIGIN,
  SNAPSHOT_LIMIT,
  UUID,
  assert,
  digest,
  validateChanges,
  validateContract,
  validateSnapshot,
} from "./contract.mjs";
import { validateInferenceEvidence } from "./inference.mjs";
import { validateSemanticReview } from "./review.mjs";

export function runnerIdentity(env = process.env) {
  assert(env.TW_API_ORIGIN === API_ORIGIN, "unapproved broker origin");
  assert(
    UUID.test(env.TW_ORDER_ID || "") && UUID.test(env.TW_OPERATION_ID || ""),
    "invalid workflow inputs",
  );
  assert(/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID || ""), "invalid GitHub run ID");
  assert(/^[1-9][0-9]{0,3}$/.test(env.GITHUB_RUN_ATTEMPT || ""), "invalid GitHub run attempt");
  return {
    orderId: env.TW_ORDER_ID,
    operationId: env.TW_OPERATION_ID,
    githubRunId: env.GITHUB_RUN_ID,
    githubRunAttempt: Number(env.GITHUB_RUN_ATTEMPT),
  };
}

export async function oidcToken(env = process.env, fetcher = fetch) {
  assert(
    env.ACTIONS_ID_TOKEN_REQUEST_TOKEN && env.ACTIONS_ID_TOKEN_REQUEST_URL,
    "trusted job OIDC permission is required",
  );
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  assert(
    url.protocol === "https:" &&
      url.hostname.endsWith(".actions.githubusercontent.com") &&
      !url.username &&
      !url.password,
    "invalid Actions OIDC origin",
  );
  url.searchParams.set("audience", `${API_ORIGIN}/api/v2/agent/internal/executions`);
  const response = await fetcher(url, {
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
    headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` },
  });
  const token = await boundedJson(response, 32 * 1024);
  assert(
    typeof token.value === "string" &&
      token.value.length < 16000 &&
      token.value.split(".").length === 3,
    "invalid Actions OIDC response",
  );
  return token.value;
}

export async function boundedJson(response, limit) {
  assert(response.ok && response.body, `broker request failed (${response.status})`);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      assert(length <= limit, "broker response exceeds budget");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
}

async function request(action, method, body, env = process.env, fetcher = fetch) {
  const identity = runnerIdentity(env);
  const url = new URL(
    `/api/v2/agent/internal/executions/${identity.operationId}/${action}`,
    API_ORIGIN,
  );
  if (method === "GET") {
    url.searchParams.set("runId", identity.githubRunId);
    url.searchParams.set("runAttempt", String(identity.githubRunAttempt));
  }
  // A lost acknowledgement is reconciled by the merchant against this same
  // operation and exact workflow run. Never dispatch another run from here.
  const token = await oidcToken(env, fetcher);
  const response = await fetcher(url, {
    method,
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return boundedJson(response, action === "snapshot" ? SNAPSHOT_LIMIT * 2 : 2 * 1024 * 1024);
}

export async function prepare(directory, env = process.env, fetcher = fetch) {
  const identity = runnerIdentity(env);
  const response = await request("claim", "POST", identity, env, fetcher);
  const contract = validateContract(response.contract || response, {
    orderId: identity.orderId,
    operationId: identity.operationId,
  });
  const snapshot = validateSnapshot(await request("snapshot", "GET", null, env, fetcher), contract);
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, "contract.json"), JSON.stringify(contract), { mode: 0o600 });
  await writeFile(path.join(directory, "snapshot.json"), JSON.stringify(snapshot), { mode: 0o600 });
  return {
    contractDigest: digest(contract),
    snapshotDigest: digest(snapshot),
    generation: contract.generation,
  };
}

export async function publish(directory, env = process.env, fetcher = fetch) {
  const identity = runnerIdentity(env);
  const contract = validateContract(
    JSON.parse(await readFile(path.join(directory, "contract.json"), "utf8")),
    { orderId: identity.orderId, operationId: identity.operationId },
  );
  const snapshot = validateSnapshot(
    JSON.parse(await readFile(path.join(directory, "snapshot.json"), "utf8")),
    contract,
  );
  const candidate = JSON.parse(
    await readFile(path.join(directory, "reviewed-candidate.json"), "utf8"),
  );
  const changes = validateChanges(candidate.changes, contract, snapshot);
  const validation = candidate.validation;
  assert(
    validation?.passed === true &&
      validation.profile === "node" &&
      validation.candidateDigest === digest(changes),
    "candidate lacks bound validation",
  );
  assert(
    validation.contractDigest === digest(contract),
    "validation belongs to a different contract",
  );
  assert(
    Array.isArray(validation.commands) &&
      validation.commands.length === 2 &&
      validation.commands[0].command === "npm ci --ignore-scripts" &&
      validation.commands[1].command === "npm test" &&
      validation.commands.every((x) => x.exitCode === 0),
    "required local validation missing",
  );
  assert(
    candidate.review?.candidateDigest === digest(changes) &&
      candidate.review.contractDigest === digest(contract),
    "semantic review belongs to another candidate",
  );
  const review = validateSemanticReview(candidate.review, contract, changes);
  assert(candidate.review.reviewer === review.reviewer, "review provider label mismatch");
  let generationEvidence;
  if (candidate.generationEvidence || review.inference) {
    generationEvidence = validateInferenceEvidence(
      candidate.generationEvidence,
      "generate",
      contract,
      changes,
    );
    assert(
      review.inference && review.inference.invocationId !== generationEvidence.invocationId,
      "independent provider review required",
    );
  } else assert(review.reviewer === "codex-fresh-read-only-v1", "legacy evidence is Codex-only");
  return request(
    "candidate",
    "POST",
    {
      schema: "tw.execution-candidate.v1",
      ...identity,
      generation: contract.generation,
      quoteHash: contract.quoteHash,
      baseSha: contract.repository.baseSha,
      repositoryId: contract.repository.id,
      changes,
      ...(generationEvidence ? { generationEvidence } : {}),
      validation,
      review,
    },
    env,
    fetcher,
  );
}

export async function failed(env = process.env, fetcher = fetch) {
  const identity = runnerIdentity(env);
  const reasons = [
    "prepare_failed",
    "generation_failed",
    "validation_failed",
    "publication_unconfirmed",
    "workflow_cancelled",
    "cleanup_unconfirmed",
  ];
  assert(reasons.includes(env.TW_FAILURE_REASON), "invalid failure reason");
  return request(
    "failed",
    "POST",
    { ...identity, reason: env.TW_FAILURE_REASON, stopped: false },
    env,
    fetcher,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command, directory] = process.argv.slice(2);
    assert(["prepare", "publish", "failed"].includes(command), "unknown broker command");
    if (command === "prepare") await prepare(directory);
    if (command === "publish") await publish(directory);
    if (command === "failed") await failed();
    console.log(`Commercial ${command} acknowledged.`);
  } catch {
    // Provider payloads and repository content can contain credentials or
    // workflow commands. Only a constant operational message reaches logs.
    console.error("Commercial broker operation failed; reconcile this operation before retrying.");
    process.exitCode = 1;
  }
}
