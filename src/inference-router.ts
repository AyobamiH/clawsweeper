import { fileURLToPath } from "node:url";
import { admitSubscription } from "./subscription-quota-client.js";

export type InferenceRoute =
  | { available: true; runner: "codex"; reason: "codex_subscription_available" | "forced_codex" }
  | {
      available: true;
      runner: "openclaw";
      reason: "codex_subscription_unavailable" | "forced_workers_ai";
      model: string;
      providersJson: string;
    }
  | { available: false; runner: "none"; reason: string };

export async function selectInferenceRoute(
  env: NodeJS.ProcessEnv = process.env,
  admit: (env?: NodeJS.ProcessEnv, refresh?: boolean) => Promise<boolean> = admitSubscription,
): Promise<InferenceRoute> {
  const policy = (env.CLAWSWEEPER_INFERENCE_POLICY || "auto").trim();
  if (!["auto", "codex", "workers-ai"].includes(policy)) {
    throw new Error("CLAWSWEEPER_INFERENCE_POLICY must be auto, codex, or workers-ai");
  }
  if (policy === "codex") {
    return { available: true, runner: "codex", reason: "forced_codex" };
  }

  const workersRoute = () => {
    const accountId = (env.CLOUDFLARE_ACCOUNT_ID || "").trim();
    const token = (env.CLOUDFLARE_WORKERS_AI_TOKEN || "").trim();
    const modelId = (env.CLAWSWEEPER_WORKERS_AI_MODEL || "@cf/zai-org/glm-5.3").trim();
    if (!accountId || !token || !modelId) {
      return { available: false as const, runner: "none" as const, reason: "workers_ai_configuration_missing" };
    }
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(accountId)) throw new Error("CLOUDFLARE_ACCOUNT_ID is invalid");
    if (!/^@cf\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(modelId)) {
      throw new Error("CLAWSWEEPER_WORKERS_AI_MODEL must be a Cloudflare @cf model id");
    }
    const provider = {
      workersai: {
        baseUrl: `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/v1`,
        apiKey: "${CLOUDFLARE_WORKERS_AI_TOKEN}",
        api: "openai-completions",
        models: [{ id: modelId, name: modelId }],
      },
    };
    return {
      available: true as const,
      runner: "openclaw" as const,
      reason: (policy === "workers-ai" ? "forced_workers_ai" : "codex_subscription_unavailable") as
        | "forced_workers_ai"
        | "codex_subscription_unavailable",
      model: `workersai/${modelId}`,
      providersJson: JSON.stringify(provider),
    };
  };

  if (policy === "workers-ai") return workersRoute();
  try {
    if (await admit(env)) {
      return { available: true, runner: "codex", reason: "codex_subscription_available" };
    }
  } catch {
    // The alternative provider is independent of the subscription coordinator.
  }
  return workersRoute();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    process.stdout.write(JSON.stringify(await selectInferenceRoute()));
  } catch (error) {
    process.stdout.write(JSON.stringify({
      available: false,
      runner: "none",
      reason: error instanceof Error ? error.message : String(error),
    }));
    process.exitCode = 1;
  }
}
