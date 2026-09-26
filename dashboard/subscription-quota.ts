// One shared ChatGPT credential pool. Never stores identity, tokens or raw diagnostics.
const FRESH_MS = 60_000;
const PROBE_MS = 60_000;
const UNKNOWN_RETRY_MS = 15 * 60_000;
export type QuotaWindow = { remainingPercent: number; windowMinutes: number; resetsAt: number };
export type QuotaState = {
  observedAt: number;
  windows: QuotaWindow[];
  blockedUntil: number;
  exhausted: boolean;
  probeId: string | null;
  probeUntil: number;
};
export function emptyQuota(): QuotaState {
  return {
    observedAt: 0,
    windows: [],
    blockedUntil: 0,
    exhausted: false,
    probeId: null,
    probeUntil: 0,
  };
}
export function quotaView(state: QuotaState, now: number) {
  return {
    status: state.exhausted
      ? "cooldown"
      : !state.observedAt || now - state.observedAt > FRESH_MS
        ? "unknown"
        : "available",
    observedAt: state.observedAt || null,
    windows: state.windows.map((w) => ({
      ...w,
      stale: now - state.observedAt > FRESH_MS || now >= w.resetsAt,
    })),
    retryAt: state.exhausted ? Math.max(state.blockedUntil, state.probeUntil) : null,
    scope: "shared-chatgpt-subscription",
  };
}
export function quotaTransition(
  state: QuotaState,
  body: any,
  now: number,
): { state: QuotaState; response: any } {
  if (!body || !Number.isFinite(body.sentAt) || Math.abs(now - body.sentAt) > 60_000)
    throw new Error("stale quota request");
  state = structuredClone(state);
  const denied = () => ({ state, response: { allowed: false, ...quotaView(state, now) } });
  if (body.action === "exhausted") {
    const resets = state.windows
      .filter((w) => w.remainingPercent <= 0 && w.resetsAt > now)
      .map((w) => w.resetsAt);
    state.exhausted = true;
    state.blockedUntil = Math.max(state.blockedUntil, ...resets, now + UNKNOWN_RETRY_MS);
    state.probeId = null;
    state.probeUntil = 0;
    return denied();
  }
  if (body.action === "observe") {
    // Only the current probe may clear a cooldown; late observations cannot reopen it.
    if (!body.probeId || body.probeId !== state.probeId || state.probeUntil <= now) return denied();
    state.probeId = null;
    state.probeUntil = 0;
    const windows = body.windows;
    if (
      !Array.isArray(windows) ||
      !windows.length ||
      windows.length > 8 ||
      windows.some(
        (w) =>
          !Number.isFinite(w.remainingPercent) ||
          w.remainingPercent < 0 ||
          w.remainingPercent > 100 ||
          !Number.isFinite(w.windowMinutes) ||
          w.windowMinutes <= 0 ||
          !Number.isFinite(w.resetsAt) ||
          w.resetsAt <= now ||
          w.resetsAt > now + 40 * 86400_000,
      )
    ) {
      state.blockedUntil = Math.max(state.blockedUntil, now + UNKNOWN_RETRY_MS);
      state.exhausted = true;
      return denied();
    }
    state.windows = windows.map((w) => ({
      remainingPercent: w.remainingPercent,
      windowMinutes: w.windowMinutes,
      resetsAt: w.resetsAt,
    }));
    state.observedAt = now;
    state.exhausted = windows.some((w) => w.remainingPercent <= 0);
    state.blockedUntil = state.exhausted
      ? Math.max(...windows.filter((w) => w.remainingPercent <= 0).map((w) => w.resetsAt))
      : 0;
    return { state, response: { allowed: !state.exhausted, ...quotaView(state, now) } };
  }
  if (body.action !== "admit") throw new Error("invalid quota action");
  if (state.blockedUntil > now) return denied();
  if (state.probeUntil > now)
    return { state, response: { ...denied().response, refreshPending: true } };
  if (
    !state.exhausted &&
    state.observedAt > 0 &&
    now - state.observedAt < FRESH_MS &&
    state.windows.every((w) => w.resetsAt > now)
  ) {
    return { state, response: { allowed: true, ...quotaView(state, now) } };
  }
  state.probeId = crypto.randomUUID();
  state.probeUntil = now + PROBE_MS;
  return { state, response: { allowed: false, probeId: state.probeId, ...quotaView(state, now) } };
}
export function readQuota(storage: any): QuotaState {
  const exists = [
    ...storage.sql.exec(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='subscription_quota'",
    ),
  ];
  if (!exists.length) return emptyQuota();
  const row = [...storage.sql.exec("SELECT value FROM subscription_quota WHERE id=1")][0];
  return row ? JSON.parse(row.value) : emptyQuota();
}
export function quotaRequest(storage: any, body: any, now = Date.now()) {
  return storage.transactionSync(() => {
    storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS subscription_quota (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)",
    );
    const result = quotaTransition(readQuota(storage), body, now);
    storage.sql.exec(
      "INSERT OR REPLACE INTO subscription_quota (id, value) VALUES (1, ?)",
      JSON.stringify(result.state),
    );
    return result.response;
  });
}
