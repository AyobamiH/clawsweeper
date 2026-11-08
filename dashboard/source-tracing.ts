/**
 * Bounded native Cloudflare Workers tracing.
 *
 * This adapter makes no network calls or persistent writes. Production spans are
 * disabled by default and, when enabled, must be sampled by the Worker platform.
 * It labels only an allowlist of source modules, operations and static route families.
 *
 * Important: CLAWSWEEPER_DEPLOY_SHA is a configured claim. A reviewer must match
 * it to the independently read Cloudflare deployment before admitting any traces.
 */

export type SourceTraceSpan = {
  setAttribute(key: string, value: string | number | boolean | undefined): unknown;
};

export type SourceTraceApi = {
  enterSpan<T>(name: string, action: (span: SourceTraceSpan) => T | Promise<T>): T | Promise<T>;
};

export type SourceTraceContext = {
  tracing?: SourceTraceApi;
};

export type SourceTraceEnvironment = Record<string, unknown>;

export const SOURCE_TRACE_MODULE = "dashboard/worker.ts" as const;
export const SOURCE_TRACE_SCHEMA = "clawsweeper-native-workers-tracing/v1" as const;

export type SourceTraceScope =
  | "http.health"
  | "http.status"
  | "http.review_observability"
  | "http.github_webhook"
  | "http.event_intake"
  | "http.exact_review_internal"
  | "cron.health_sample";

const SAFE_SCOPES: ReadonlySet<string> = new Set<SourceTraceScope>([
  "http.health",
  "http.status",
  "http.review_observability",
  "http.github_webhook",
  "http.event_intake",
  "http.exact_review_internal",
  "cron.health_sample",
]);

const SHA_PATTERN = /^[0-9a-f]{40}$/;

export function traceScopeForRequest(request: Request): SourceTraceScope | null {
  const path = new URL(request.url).pathname;
  const method = request.method;
  if (method === "GET" && path === "/api/health") return "http.health";
  if (method === "GET" && path === "/api/status") return "http.status";
  if (method === "GET" && path === "/api/review-observability") return "http.review_observability";
  if (method === "POST" && path === "/github/webhook") return "http.github_webhook";
  if (method === "POST" && path === "/api/events") return "http.event_intake";
  if (method === "POST" && path.startsWith("/internal/exact-review/"))
    return "http.exact_review_internal";
  return null;
}

export function configuredTraceRevision(env: SourceTraceEnvironment): string | null {
  if (env.CLAWSWEEPER_ARCH_TRACE_ENABLED !== "1") return null;
  const sha = env.CLAWSWEEPER_DEPLOY_SHA;
  // Refuse to claim source attribution if deployment metadata is absent.
  if (typeof sha !== "string" || !SHA_PATTERN.test(sha)) return null;
  return sha;
}

/**
 * Never retry an effectful action if the trace engine fails after invoking it.
 *
 * Any tracing error, before or after invocation, must not change the business
 * result or cause a second invocation. The original callback error is preserved.
 */
export function withSourceTrace<T>(
  env: SourceTraceEnvironment,
  ctx: SourceTraceContext | undefined,
  scope: SourceTraceScope | null,
  action: () => T | Promise<T>,
): T | Promise<T> {
  let configuredSha: string | null;
  try {
    configuredSha = configuredTraceRevision(env);
  } catch {
    // Integration shims may proxy tracing configuration. The original
    // business handler must still execute on a tracing-only failure.
    return action();
  }
  if (!configuredSha || !scope || !SAFE_SCOPES.has(scope)) return action();
  // Accessing a tracing capability is itself an optional effect. Some proxies
  // and instrumentation shims can throw from either property getter. No such
  // failure may prevent the original handler from running.
  let tracing: SourceTraceApi | undefined;
  let enter: SourceTraceApi["enterSpan"] | undefined;
  let called = false;
  let result!: T | Promise<T>;
  let thrown = false;
  let originalError: unknown;

  // The same function is shared by the synchronous handler and any deferred
  // tracing callback. Once a business effect has started, *neither* a failed
  // span nor a late callback may replay it.
  const runOnce = (): T | Promise<T> => {
    if (called) {
      if (thrown) throw originalError;
      return result;
    }
    called = true;
    try {
      result = action();
      return result;
    } catch (error) {
      thrown = true;
      originalError = error;
      throw error;
    }
  };

  try {
    tracing = ctx?.tracing;
    enter = tracing?.enterSpan;
  } catch {
    return runOnce();
  }
  if (typeof enter !== "function") return runOnce();

  try {
    const traced = enter.call(tracing, `clawsweeper.${scope}`, (span) => {
      // No URL, query string, request bodies, account names, tokens, user IDs,
      // IP addresses or provider response content may appear in our attributes.
      try {
        span.setAttribute("clawsweeper.source_revision_claim", configuredSha);
        span.setAttribute("clawsweeper.module", SOURCE_TRACE_MODULE);
        span.setAttribute("clawsweeper.route_family", scope);
        span.setAttribute("clawsweeper.trace_schema", SOURCE_TRACE_SCHEMA);
      } catch {
        // An attribute or proxy failure is not a business failure.
      }
      return runOnce();
    });

    // The Cloudflare callback is synchronous. If a mock or future tracing
    // implementation defers it, start business logic immediately and give the
    // late callback the memoised result. Silently consume exporter failures,
    // without swallowing a rejection from the original business promise.
    try {
      if (traced && typeof (traced as Promise<unknown>).then === "function") {
        void Promise.resolve(traced).catch(() => undefined);
      }
    } catch {
      // A throwing then getter is a tracer failure, not a business failure.
    }
  } catch {
    // Even if the tracer throws *after* invoking runOnce, its outcome is
    // authoritative. runOnce will never execute the action a second time.
  }
  return runOnce();
}
