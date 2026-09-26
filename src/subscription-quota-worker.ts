import { admitSubscription, quotaCall, readChatGPTAllowance } from "./subscription-quota-client.js";
try {
  if (process.argv[2] === "exhausted") {
    await quotaCall({ action: "exhausted" });
  } else if (process.argv[2] === "read") {
    process.stdout.write(
      JSON.stringify({ observedAt: Date.now(), windows: await readChatGPTAllowance() }),
    );
  } else {
    process.stdout.write(JSON.stringify({ allowed: await admitSubscription() }));
  }
} catch {
  process.stdout.write(JSON.stringify({ allowed: false, error: "subscription_quota_unavailable" }));
  process.exitCode = 1;
}
