/**
 * Local Wrangler-only probe. This file is NOT part of the production Worker
 * entry point and must not be deployed under a production route.
 */
import worker from "../../dashboard/worker.ts";

export default {
  async fetch(
    request: Request,
    env: Record<string, unknown>,
    ctx: {
      waitUntil?: (promise: Promise<unknown>) => void;
      tracing?: {
        enterSpan?: (...args: unknown[]) => unknown;
      };
    },
  ): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/__local/trace-capability") {
      return Response.json(
        {
          schema: "clawsweeper-local-native-trace-capability/v1",
          local_only: true,
          native_api_present: typeof ctx?.tracing?.enterSpan === "function",
          source_revision_claim:
            typeof env.CLAWSWEEPER_DEPLOY_SHA === "string" ? env.CLAWSWEEPER_DEPLOY_SHA : null,
        },
        { headers: { "cache-control": "no-store" } },
      );
    }
    // Read-only local health route delegates to the exact real Worker code.
    return worker.fetch(request, env, ctx as never);
  },
};
