import test from "node:test";
import assert from "node:assert/strict";
import {
  configuredTraceRevision,
  SOURCE_TRACE_MODULE,
  SOURCE_TRACE_SCHEMA,
  traceScopeForRequest,
  withSourceTrace,
  type SourceTraceContext,
} from "../dashboard/source-tracing.ts";

const SOURCE_SHA = "03d32fb784758d2a3770aaa9721f1212ac061096";
const enabled = {
  CLAWSWEEPER_ARCH_TRACE_ENABLED: "1",
  CLAWSWEEPER_DEPLOY_SHA: SOURCE_SHA,
};
const disabled = {
  CLAWSWEEPER_ARCH_TRACE_ENABLED: "0",
  CLAWSWEEPER_DEPLOY_SHA: SOURCE_SHA,
};

test("trace scope is a strict method and path allowlist without query strings", () => {
  const cases = [
    ["GET", "https://status.example/api/health?token=secret", "http.health"],
    ["GET", "https://status.example/api/status?private=abc", "http.status"],
    ["GET", "https://status.example/api/review-observability?repo=secret", "http.review_observability"],
    ["POST", "https://status.example/github/webhook?id=private", "http.github_webhook"],
    ["POST", "https://status.example/api/events?token=private", "http.event_intake"],
    ["POST", "https://status.example/internal/exact-review/sensitive/a", "http.exact_review_internal"],
    ["GET", "https://status.example/internal/exact-review/sensitive/a", null],
    ["POST", "https://status.example/api/health", null],
    ["GET", "https://status.example/account/private?id=3", null],
  ] as const;
  for (const [method, url, expected] of cases) {
    assert.equal(traceScopeForRequest(new Request(url, { method })), expected);
  }
});

test("tracing remains disabled by default; callback executes once", async () => {
  let calls = 0;
  const ctx: SourceTraceContext = {
    tracing: { enterSpan() { throw new Error("should-not-be-called"); } },
  };
  const result = await withSourceTrace(disabled, ctx, "http.health", async () => {
    calls++;
    return 204;
  });
  assert.equal(result, 204);
  assert.equal(calls, 1);
});

test("missing, malformed or spoofed source claim never creates a span", async () => {
  let spans = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        spans++;
        return action({ setAttribute() {} });
      },
    },
  };
  const invalid = [
    {},
    { CLAWSWEEPER_ARCH_TRACE_ENABLED: "1" },
    { CLAWSWEEPER_ARCH_TRACE_ENABLED: "yes", CLAWSWEEPER_DEPLOY_SHA: SOURCE_SHA },
    { CLAWSWEEPER_ARCH_TRACE_ENABLED: "1", CLAWSWEEPER_DEPLOY_SHA: "2ea8790" },
    { CLAWSWEEPER_ARCH_TRACE_ENABLED: "1", CLAWSWEEPER_DEPLOY_SHA: SOURCE_SHA.toUpperCase() },
  ];
  for (const env of invalid) {
    assert.equal(configuredTraceRevision(env), null);
    const result = await withSourceTrace(env, ctx, "http.health", () => 200);
    assert.equal(result, 200);
  }
  assert.equal(spans, 0);
});

test("native span contains only approved non-sensitive static source attributes", async () => {
  const spans: Array<{ name: string; attributes: Record<string, unknown> }> = [];
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(name, action) {
        const attributes: Record<string, unknown> = {};
        spans.push({ name, attributes });
        return action({ setAttribute(key, value) { attributes[key] = value; } });
      },
    },
  };
  const result = await withSourceTrace(enabled, ctx, "http.github_webhook", async () => "published-safe");
  assert.equal(result, "published-safe");
  assert.deepEqual(spans, [{
    name: "clawsweeper.http.github_webhook",
    attributes: {
      "clawsweeper.source_revision_claim": SOURCE_SHA,
      "clawsweeper.module": SOURCE_TRACE_MODULE,
      "clawsweeper.route_family": "http.github_webhook",
      "clawsweeper.trace_schema": SOURCE_TRACE_SCHEMA,
    },
  }]);
  assert.ok(!JSON.stringify(spans).includes("token="));
  assert.ok(!JSON.stringify(spans).includes("private"));
});

test("tracing API failure before invocation falls back once", async () => {
  let invocations = 0;
  const ctx: SourceTraceContext = {
    tracing: { enterSpan() { throw new Error("backend unavailable before invocation"); } },
  };
  const value = await withSourceTrace(enabled, ctx, "http.health", async () => {
    invocations++;
    return 200;
  });
  assert.equal(value, 200);
  assert.equal(invocations, 1);
});

test("tracing failure after callback invocation preserves the business result without replay", async () => {
  let invocations = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        action({ setAttribute() {} });
        throw new Error("trace exporter failed after effectful callback");
      },
    },
  };
  const result = await withSourceTrace(enabled, ctx, "http.event_intake", () => {
    invocations++;
    return "effect-already-performed";
  });
  assert.equal(result, "effect-already-performed");
  assert.equal(invocations, 1);
});

test("asynchronous tracing exporter rejection never changes original resolved outcome", async () => {
  let invocations = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        action({ setAttribute() {} });
        return Promise.reject(new Error("async trace exporter failure"));
      },
    },
  };
  const result = await withSourceTrace(enabled, ctx, "http.event_intake", async () => {
    invocations++;
    return "successful-business-operation";
  });
  assert.equal(result, "successful-business-operation");
  assert.equal(invocations, 1);
});

test("business sync errors cannot be replaced by tracing backend errors", () => {
  const businessFailure = new Error("business-error");
  let calls = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        try { action({ setAttribute() {} }); } catch {}
        throw new Error("tracing-backend-error");
      },
    },
  };
  assert.throws(() => withSourceTrace(enabled, ctx, "http.github_webhook", () => {
    calls++;
    throw businessFailure;
  }), (error: unknown) => error === businessFailure);
  assert.equal(calls, 1);
});

test("business logic errors propagate unchanged and cannot trigger retries", async () => {
  const failure = new Error("expected business failure");
  let calls = 0;
  const ctx: SourceTraceContext = {
    tracing: { enterSpan(_name, action) { return action({ setAttribute() {} }); } },
  };
  await assert.rejects(async () => withSourceTrace(enabled, ctx, "http.exact_review_internal", async () => {
    calls++;
    throw failure;
  }), (error: unknown) => error === failure);
  assert.equal(calls, 1);
});

test("tracer attribute errors cannot change the original response", async () => {
  let calls = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        return action({ setAttribute() { throw new Error("invalid attribute"); } });
      },
    },
  };
  const response = await withSourceTrace(enabled, ctx, "http.health", () => {
    calls++;
    return new Response("healthy", { status: 200 });
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "healthy");
  assert.equal(calls, 1);
});

test("a scheduled waitUntil promise stays active until its actual operation settles", async () => {
  let release!: (value: string) => void;
  const original = new Promise<string>((resolve) => { release = resolve; });
  let spanResolved = false;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name, action) {
        const result = action({ setAttribute() {} });
        return Promise.resolve(result).finally(() => { spanResolved = true; });
      },
    },
  };
  const maintenance = Promise.resolve(withSourceTrace(enabled, ctx, "cron.health_sample", () => original));
  assert.equal(spanResolved, false);
  release("complete");
  assert.equal(await maintenance, "complete");
  assert.equal(spanResolved, true);
});

test("unclassified routes never create custom spans", async () => {
  const ctx: SourceTraceContext = {
    tracing: { enterSpan() { throw Error("attempted trace of unknown route"); } },
  };
  assert.equal(await withSourceTrace(enabled, ctx, null, () => 404), 404);
});

test("asynchronous tracing backend which does not invoke the callback cannot fake business success", async () => {
  let executed = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan() {
        return Promise.resolve("fake-success-from-tracer");
      },
    },
  };
  const result = await withSourceTrace(enabled, ctx, "http.event_intake", () => {
    executed++;
    return "real-business-outcome";
  });
  assert.equal(result, "real-business-outcome");
  assert.equal(executed, 1);
});

test("deferred tracing callback still executes the business operation exactly once", async () => {
  let executed = 0;
  const ctx: SourceTraceContext = {
    tracing: {
      enterSpan(_name,action) {
        return Promise.resolve().then(() => action({setAttribute() {}}));
      },
    },
  };
  const result = await withSourceTrace(enabled, ctx, "http.health", () => {
    executed++;
    return 200;
  });
  assert.equal(result, 200);
  assert.equal(executed, 1);
});
