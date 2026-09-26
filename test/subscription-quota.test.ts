import assert from "node:assert/strict";
import test from "node:test";
import { emptyQuota, quotaTransition, quotaView } from "../dashboard/subscription-quota.ts";
import { allowanceWindows } from "../dist/subscription-quota-client.js";
const now = 1_800_000_000_000;
function apply(state, action, at = now) {
  return quotaTransition(state, { ...action, sentAt: at }, at);
}
const window = (remainingPercent = 50, resetsAt = now + 3600_000) => ({
  remainingPercent,
  windowMinutes: 300,
  resetsAt,
});
test("only one repository obtains a stale allowance probe", () => {
  const first = apply(emptyQuota(), { action: "admit" });
  assert.ok(first.response.probeId);
  assert.equal(first.response.allowed, false);
  const second = apply(first.state, { action: "admit" });
  assert.equal(second.response.probeId, undefined);
  assert.equal(second.response.allowed, false);
});
test("exhaustion fences late successful observations and every repository", () => {
  const probe = apply(emptyQuota(), { action: "admit" });
  const exhausted = apply(probe.state, { action: "exhausted" });
  const late = apply(exhausted.state, {
    action: "observe",
    probeId: probe.response.probeId,
    windows: [window()],
  });
  assert.equal(late.response.allowed, false);
  assert.equal(apply(late.state, { action: "admit" }).response.allowed, false);
});
test("all exhausted windows must reset and then one fresh probe must pass", () => {
  const probe = apply(emptyQuota(), { action: "admit" });
  const observed = apply(probe.state, {
    action: "observe",
    probeId: probe.response.probeId,
    windows: [window(0), window(0, now + 7200_000)],
  });
  assert.equal(observed.state.blockedUntil, now + 7200_000);
  assert.equal(apply(observed.state, { action: "admit" }, now + 3601_000).response.allowed, false);
  const next = apply(observed.state, { action: "admit" }, now + 7201_000);
  assert.ok(next.response.probeId);
  assert.equal(next.response.allowed, false);
  const recovered = apply(
    next.state,
    { action: "observe", probeId: next.response.probeId, windows: [window(99, now + 10800_000)] },
    now + 7202_000,
  );
  assert.equal(recovered.response.allowed, true);
});
test("unknown, malformed, and expired quota never admit a model", () => {
  for (const windows of [[], [window(NaN)], [window(101)], [window(50, now - 1)]]) {
    const probe = apply(emptyQuota(), { action: "admit" });
    assert.equal(
      apply(probe.state, { action: "observe", probeId: probe.response.probeId, windows }).response
        .allowed,
      false,
    );
  }
  assert.throws(
    () => quotaTransition(emptyQuota(), { action: "exhausted", sentAt: now - 61000 }, now),
    /stale/,
  );
});
test("stale allowances are visibly marked without inventing reset balances", () => {
  const probe = apply(emptyQuota(), { action: "admit" });
  const observed = apply(probe.state, {
    action: "observe",
    probeId: probe.response.probeId,
    windows: [window()],
  });
  assert.equal(quotaView(observed.state, now + 61000).status, "unknown");
  assert.equal(quotaView(observed.state, now + 61000).windows[0]?.stale, true);
});
test("Codex quota normalisation keeps subscription windows and excludes unrelated buckets", () => {
  assert.deepEqual(
    allowanceWindows({
      rateLimitsByLimitId: {
        codex: {
          primary: { usedPercent: 25, windowDurationMins: 300, resetsAt: 1800003600 },
          secondary: null,
        },
      },
    }),
    [window(75)],
  );
  assert.deepEqual(allowanceWindows({ rateLimits: { limitId: "other", primary: {} } }), []);
});

test("signed Worker route uses the singleton SQL store and public view excludes probe authority", async () => {
  const { worker, ExactReviewQueue, MemoryDurableStorage, MemoryDurableNamespace, createHmac } =
    await import("./dashboard-worker-harness.ts");
  const storage = new MemoryDurableStorage();
  const queue = new ExactReviewQueue({ storage }, {});
  const env = {
    EXACT_REVIEW_QUEUE: new MemoryDurableNamespace(queue),
    CLAWSWEEPER_WEBHOOK_SECRET: "fixture",
  };
  const url = "https://test.invalid/internal/subscription-quota";
  const denied = await worker.fetch(new Request(url, { method: "POST", body: "{}" }), env);
  assert.equal(denied.status, 401);
  const body = JSON.stringify({ action: "admit", sentAt: Date.now() });
  const signed = await worker.fetch(
    new Request(url, {
      method: "POST",
      body,
      headers: {
        "x-clawsweeper-exact-review-signature": `sha256=${createHmac("sha256", "fixture").update(body).digest("hex")}`,
      },
    }),
    env,
  );
  assert.equal(signed.status, 200);
  assert.ok((await signed.json()).probeId);
  const publicView = await worker.fetch(
    new Request("https://test.invalid/api/subscription-quota"),
    env,
  );
  const value = await publicView.json();
  assert.equal(value.probeId, undefined);
  assert.equal(value.scope, "shared-chatgpt-subscription");
  const second = new ExactReviewQueue({ storage }, {});
  const resumed = await second.fetch(
    new Request("https://queue/subscription-quota", { method: "POST", body }),
  );
  assert.equal((await resumed.json()).probeId, undefined);
});
