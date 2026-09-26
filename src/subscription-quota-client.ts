import { createHmac } from "node:crypto";
import { spawnCodex, terminateCodexProcessTree } from "./codex-spawn.js";

export type AllowanceWindow = { remainingPercent: number; windowMinutes: number; resetsAt: number };
export function allowanceWindows(result: any): AllowanceWindow[] {
  // The configured fleet shares the Codex bucket. Do not merge unrelated model buckets.
  const bucket = result?.rateLimitsByLimitId?.codex ?? result?.rateLimits;
  if (bucket?.limitId && bucket.limitId !== "codex") return [];
  const windows = [bucket?.primary, bucket?.secondary].filter(Boolean);
  if (
    windows.some(
      (w) =>
        typeof w.usedPercent !== "number" ||
        !Number.isFinite(w.usedPercent) ||
        w.usedPercent < 0 ||
        w.usedPercent > 100,
    )
  )
    return [];
  return windows.map((w) => ({
    remainingPercent: bucket?.rateLimitReachedType ? 0 : 100 - w.usedPercent,
    windowMinutes: w.windowDurationMins,
    resetsAt: w.resetsAt * 1000,
  }));
}
export async function readChatGPTAllowance(
  env: NodeJS.ProcessEnv = process.env,
): Promise<AllowanceWindow[]> {
  const safeEnv = { ...env };
  for (const key of [
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "PROXY_API_KEY",
    "CLAWSWEEPER_QUOTA_SECRET",
    "CLAWSWEEPER_WEBHOOK_SECRET",
  ])
    delete safeEnv[key];
  const child = spawnCodex(["app-server", "-c", 'forced_login_method="chatgpt"'], {
    cwd: process.cwd(),
    env: safeEnv,
  });
  return new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const finish = (windows?: AllowanceWindow[]) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdin.end();
      terminateCodexProcessTree(child);
      if (windows?.length) resolve(windows);
      else reject(new Error("ChatGPT allowance unavailable"));
    };
    const timer = setTimeout(() => finish(), 20_000);
    const send = (value: unknown) => child.stdin.write(JSON.stringify(value) + "\n");
    child.stdin.on("error", () => finish());
    child.on("error", () => finish());
    child.on("close", () => finish());
    child.stderr.on("data", () => {}); // Never publish auth/provider diagnostics.
    child.stdout.on("data", (chunk) => {
      buffer += chunk.toString();
      if (buffer.length > 256_000) return finish();
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        if (message.id === 1) {
          if (message.error) return finish();
          send({ method: "initialized" });
          send({ method: "account/rateLimits/read", id: 2 });
        }
        if (message.id === 2) finish(message.error ? undefined : allowanceWindows(message.result));
      }
    });
    send({
      method: "initialize",
      id: 1,
      params: { clientInfo: { name: "clawsweeper-quota", version: "1" } },
    });
  });
}
export async function quotaCall(body: unknown, env: NodeJS.ProcessEnv = process.env): Promise<any> {
  const origin = env.CLAWSWEEPER_QUOTA_URL;
  const secret = env.CLAWSWEEPER_QUOTA_SECRET;
  if (!origin || !secret) throw new Error("Shared subscription quota configuration missing");
  const url = new URL("/internal/subscription-quota", origin);
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname))
  )
    throw new Error("Invalid quota origin");
  const text = JSON.stringify({ ...(body as object), sentAt: Date.now() });
  const response = await fetch(url, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: {
      "content-type": "application/json",
      "x-clawsweeper-exact-review-signature": `sha256=${createHmac("sha256", secret).update(text).digest("hex")}`,
    },
    body: text,
  });
  if (!response.ok) throw new Error("Shared subscription quota unavailable");
  return response.json();
}
export async function admitSubscription(env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  const admission = await quotaCall({ action: "admit" }, env);
  if (admission.allowed === true) return true;
  if (!admission.probeId) return false;
  let windows: AllowanceWindow[] = [];
  try {
    windows = await readChatGPTAllowance(env);
  } catch {
    /* fail closed, bounded retry */
  }
  const observation = await quotaCall(
    { action: "observe", probeId: admission.probeId, windows },
    env,
  );
  return observation.allowed === true;
}
