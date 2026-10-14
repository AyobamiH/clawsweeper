import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assert, digest } from "./contract.mjs";

const MODEL = /^@cf\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export const RECEIPT_SCHEMA = "tw.inference-evidence.v1";

export function validateRoute(route) {
  assert(route?.schema === "tw.commercial-inference-route.v1", "unsupported inference route");
  assert(
    [
      "codex_subscription_available",
      "forced_codex",
      "codex_subscription_unavailable",
      "forced_workers_ai",
    ].includes(route.reason),
    "invalid inference reason",
  );
  if (route.provider === "chatgpt-codex") {
    assert(
      route.model === "subscription-default" &&
        route.transport === "codex-sandbox-v1" &&
        ["codex_subscription_available", "forced_codex"].includes(route.reason),
      "invalid Codex route",
    );
  } else {
    assert(
      route.provider === "cloudflare-workers-ai" &&
        MODEL.test(route.model) &&
        route.transport === "workers-ai-json-v1" &&
        ["codex_subscription_unavailable", "forced_workers_ai"].includes(route.reason),
      "invalid Workers AI route",
    );
  }
  return {
    schema: route.schema,
    provider: route.provider,
    model: route.model,
    transport: route.transport,
    reason: route.reason,
  };
}

export async function selectCommercialRoute(env = process.env, admit) {
  // Do not fork provider-selection policy or fall back to a broad deploy token.
  const { selectInferenceRoute } = await import("../../dist/inference-router.js");
  const selected = await selectInferenceRoute(env, admit);
  assert(selected.available, "commercial inference unavailable");
  return validateRoute({
    schema: "tw.commercial-inference-route.v1",
    provider: selected.runner === "codex" ? "chatgpt-codex" : "cloudflare-workers-ai",
    model:
      selected.runner === "codex"
        ? "subscription-default"
        : selected.model.replace(/^workersai\//, ""),
    transport: selected.runner === "codex" ? "codex-sandbox-v1" : "workers-ai-json-v1",
    reason: selected.reason,
  });
}

export async function commercialRoute(directory, phase, options = {}) {
  assert(["generate", "review"].includes(phase), "invalid inference phase");
  if (options.route) return validateRoute(options.route);
  // The workflow chooses once before provider setup. A runtime error never
  // starts a second provider call or silently consumes another allowance.
  try {
    const saved = JSON.parse(await readFile(path.join(directory, `${phase}-route.json`), "utf8"));
    const contract = JSON.parse(await readFile(path.join(directory, "contract.json"), "utf8"));
    assert(
      saved.phase === phase && saved.contractDigest === digest(contract),
      "inference route belongs to another contract",
    );
    return validateRoute(saved.route);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return selectCommercialRoute(options.env || process.env, options.admit);
  }
}

export function inferenceEvidence(route, phase, contract, result, invocationId = randomUUID()) {
  route = validateRoute(route);
  assert(
    ["generate", "review"].includes(phase) && UUID.test(invocationId),
    "invalid inference invocation",
  );
  return {
    schema: RECEIPT_SCHEMA,
    phase,
    invocationId,
    provider: route.provider,
    model: route.model,
    transport: route.transport,
    routeReason: route.reason,
    contractDigest: digest(contract),
    resultDigest: digest(result),
  };
}

export function validateInferenceEvidence(evidence, phase, contract, result) {
  assert(
    Object.keys(evidence || {})
      .sort()
      .join(",") ===
      "contractDigest,invocationId,model,phase,provider,resultDigest,routeReason,schema,transport",
    "unexpected inference evidence fields",
  );
  assert(
    evidence?.schema === RECEIPT_SCHEMA &&
      evidence.phase === phase &&
      UUID.test(evidence.invocationId || ""),
    "invalid inference evidence",
  );
  const route = validateRoute({
    schema: "tw.commercial-inference-route.v1",
    provider: evidence.provider,
    model: evidence.model,
    transport: evidence.transport,
    reason: evidence.routeReason,
  });
  assert(
    HASH.test(evidence.contractDigest) &&
      evidence.contractDigest === digest(contract) &&
      HASH.test(evidence.resultDigest) &&
      evidence.resultDigest === digest(result),
    "inference evidence binding mismatch",
  );
  return inferenceEvidence(route, phase, contract, result, evidence.invocationId);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [directory, phase] = process.argv.slice(2);
    assert(["generate", "review"].includes(phase), "invalid phase");
    const contract = JSON.parse(await readFile(path.join(directory, "contract.json"), "utf8"));
    const route = await selectCommercialRoute();
    await writeFile(
      path.join(directory, `${phase}-route.json`),
      JSON.stringify({ phase, contractDigest: digest(contract), route }),
      { mode: 0o600, flag: "wx" },
    );
    if (process.env.GITHUB_OUTPUT)
      await writeFile(process.env.GITHUB_OUTPUT, `provider=${route.provider}\n`, { flag: "a" });
    console.log(
      JSON.stringify({ provider: route.provider, model: route.model, reason: route.reason }),
    );
  } catch {
    console.error("Commercial inference route unavailable; no provider call was started.");
    process.exitCode = 1;
  }
}
