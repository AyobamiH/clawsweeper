import { admitSubscription, quotaCall, readChatGPTAllowance } from "./subscription-quota-client.js";

const command = process.argv[2];
try {
  if (command === "exhausted") {
    await quotaCall({ action: "exhausted" });
  } else if (command === "read") {
    const windows = await readChatGPTAllowance();
    process.stdout.write(
      JSON.stringify({
        observedAt: Date.now(),
        available: windows.length > 0 && windows.every((window) => window.remainingPercent > 0),
        windows,
      }),
    );
  } else {
    process.stdout.write(
      JSON.stringify({
        allowed: await admitSubscription(process.env, command === "refresh"),
      }),
    );
  }
} catch {
  if (command === "read") {
    process.stdout.write(
      JSON.stringify({
        observedAt: Date.now(),
        available: false,
        windows: [],
        error: "chatgpt_allowance_unavailable",
      }),
    );
  } else {
    process.stdout.write(
      JSON.stringify({ allowed: false, error: "subscription_quota_unavailable" }),
    );
    process.exitCode = 1;
  }
}
