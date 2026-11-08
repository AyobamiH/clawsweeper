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
  if (method === "GET" && path === "/api/review-observability")
    return "http.review_observability";
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
  const configuredSha = configuredTraceRevision(env);
  if (!configuredSha || !scope || !SAFE_SCOPES.has(scope)) return action();
  const enter = ctx?.tracing?.enterSpan;
  if (typeof enter !== "function") return action();

  let invoked = false;
  let businessReturned!: T | Promise<T>;
  let businessThrew = false;
  let businessError: unknown;
  const restoreBusinessOutcome = (): T | Promise<T> => {
    if (!invoked) return action();
    if (businessThrew) throw businessError;
    return businessReturned;
  };
  try {
    const traced = enter.call(ctx?.tracing, `clawsweeper.${scope}`, (span) => {
      invoked = true;
      // No URL, query string, request bodies, account names, tokens, user IDs,
      // IP addresses or provider response content may appear in our attributes.
      try {
        span.setAttribute("clawsweeper.source_revision_claim", configuredSha);
        span.setAttribute("clawsweeper.module", SOURCE_TRACE_MODULE);
        span.setAttribute("clawsweeper.route_family", scope);
        span.setAttribute("clawsweeper.trace_schema", SOURCE_TRACE_SCHEMA);
      } catch {
        // Attribute failures must not change worker behaviour.
      }
      try {
        businessReturned = action();
        return businessReturned;
      } catch (error) {
        businessThrew = true;
        businessError = error;
        throw error;
      }
    });

    // For a native synchronous enterSpan callback, businessReturned is the
    // authoritative outcome. Do not wait for a failing trace exporter, and do
    // not replay the action if the tracing promise rejects after invocation.
    if (invoked) {
      if (traced && typeof (traced as Promise<T>).then === "function") {
        void Promise.resolve(traced).catch(() => undefined);
      }
      return restoreBusinessOutcome();
    }
    // Defensive path for a tracing provider that schedules its callback
    // asynchronously (unlike Cloudflare's documented enterSpan contract).
    return Promise.resolve(traced).then(() => restoreBusinessOutcome(), () => restoreBusinessOutcome());
  } catch {
    return restoreBusinessOutcome();
  }
}
