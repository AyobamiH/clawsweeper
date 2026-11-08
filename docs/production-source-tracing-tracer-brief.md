# ClawSweeper — production tracing operator / tracer brief

**Prepared:** 8 November 2026
**Role:** Independent, bounded live-run observer and source-attestation specialist.
**Mission:** Establish real source- and environment-labelled ClawSweeper execution evidence, using existing Cloudflare-native Workers tracing, with no duplicate business effects, excessive data collection or unauthorised deployment.

## 1. Identify the correct production boundary — do this first

The operational service is **https://clawsweeper.openclaw.ai/**, with fallback **https://clawsweeper-status.services-91b.workers.dev/**. Its Worker is documented as `clawsweeper-status`, Cloudflare **Services@openclaw.org**, account `91b59577e757131d68d55a471fe32aca`.

At preparation time, both `GET /api/health` endpoints returned `deployment_sha=2ea8790a6c7c455a7f0291857337d58840d0464f`. This SHA is neither the architecture explorer's pinned `main=03d32fb784758d2a3770aaa9721f1212ac061096` nor a commit independently retrieved from the public repository. Therefore the baseline source mapping is **not admitted**.

The similarly named `ayobamih-clawsweeper-status` Worker belongs to a **different** account and must not be mistaken for this service. The architecture explorer `clawsweeper-codebase-map.pages.dev` is a separate Pages project, and its successful deployment does not verify ClawSweeper production execution.

Before doing anything else: fetch the live `/api/health` from both production domains; retrieve the Worker version/deployment history from the exact Cloudflare account; inspect the current GitHub `main`, open PR chain and runner owner receipts; record IDs and SHA conflicts. Stop with `source_unverified` if the source bundle cannot be tied to a real commit and provider deployment ID. Do not infer source from a string in a health response.

## 2. Constraints and non-negotiable guards

- The production service has real webhooks, queues, Durable Objects, maintenance triggers and private GitHub credentials. Do not reconfigure, invoke or mutate these until independent source approval and correct-account authorisation exist.
- **No production tracing by default.** `dashboard/wrangler.toml` leaves native tracing disabled. A separately approved release may enable `[observability.traces] enabled=true` with explicit head sampling, initially at or below **0.005** (0.5%) unless a documented budget approves less/more.
- Cloudflare's **automatic** spans can contain URL/subrequest or provider metadata, even when custom source spans themselves record only route-family, source-revision claim, static module and schema. Review collection, access, retention and export policy *before* enabling it.
- Never collect API tokens, webhook signatures, request or response bodies, arbitrary account/entity identifiers, IPs or raw GitHub delivery payloads in the source tracing pipeline.
- No new scheduled monitor, runner, CI system, extra publishing worker or provider account. Use existing Cloudflare observability and self-hosted CI infrastructure.
- The guarded Node.js OpenTelemetry preloader in the separate explorer is a **local-only source probe**; it is not a production Cloudflare Workers deployment mechanism.
- Owner-HMAC signed JSONL trace receipts in the explorer guard can establish owner-controlled provenance, **not** provider-side version/source authenticity.

## 3. Independent source-revision and deployment attestation

For every attempted canary and production acceptance, record a version tuple:

```
Cloudflare account ID | Worker script name | deployment/version ID
deployment created_at | deployed source Git SHA | source bundle SHA-256
Wrangler compatibility_date | tracing config/sampling | review approval SHA
observed trace or Cloudflare span ID | observation UTC | route-family | result
```

Check `CLAWSWEEPER_DEPLOY_SHA` from `/api/health` as **a claim**, then independently bind it to the provider's deployment version and the exact source/build receipt. Do not accept a zero-length hash, another account's version or the architecture explorer's `03d32fb...` graph as a replacement.

If direct provider readback or valid source ancestry is unavailable, mark `provider_version_unverified`. Request the authorised OpenClaw account connection/permission or canonical release receipt. Do not deploy using the Ayobami account's token as a substitute.

## 4. Staged execution, starting with a strict local canary

1. Confirm no active release controller or independent reviewer owns the target source/worktree or shared runner before modifying it.
2. Pull a clean, exact-source reviewed commit and run `node scripts/generate-tracing-canary.mjs`. This local-only generator refuses dirty trees and produces no production binding, route, Cron or secret.
3. Run a pinned local Wrangler development instance with the generated canary file. First request `GET /__local/trace-capability` (available only in the isolated fixture) and verify native `ctx.tracing.enterSpan` support. Then issue safe local `GET /api/health` requests and controlled scheduled mocks; it must not send real webhook payloads to production.
4. Confirm identical HTTP response semantics and no duplicate callbacks between tracing enabled/disabled; demonstrate real Cloudflare-native `ctx.tracing.enterSpan` support under the existing compatibility date.
5. Record a redacted trace showing the custom `clawsweeper.http.health` span and source-claim attribute alongside automatic platform spans **only if actually observed**. If local Miniflare does not expose native span readback, mark this gate not independently verified.
6. Obtain independent reviewer **source and canary APPROVE** before attempting any real Worker trace rollout.

## 5. Bounded production admission — only after review and version proof

Use the existing trusted production deployment pipeline for the **correct** OpenClaw Cloudflare account. Do not mutate an unrelated Worker. Preserve its existing release process, DO migrations, queue authority and secrets.

- Prepare an exact reviewed deploy artifact and a low-sampling native-trace configuration, initially `head_sampling_rate <= 0.005`; record the toggle and provider version ID. No default sampling of 100%.
- Use a canary or version-directed traffic slice as supported by the current account. Keep normal production operation intact. Do not route real webhooks into a canary lacking all required credentials/bindings.
- Observe a real read-only `GET /api/health` on a provider-confirmed version, then a naturally occurring approved webhook/scheduled invocation. Do not manufacture duplicate deliveries, GitHub comments or publication effects merely to obtain a trace.
- Include at least one controlled failure/recovery test in an isolated environment. Prove callbacks remain single-effect, timeouts and exceptions do not cause replay, and `ctx.waitUntil` work is still tracked.
- Capture and sanitise only provider observation metadata and allowlisted custom span attributes. Use independently verifiable trace IDs, source SHA, environment and event time. Save immutable receipt digests and the successful provider readback.
- Two healthy cycles must be independently evidenced if admission depends on scheduled observability. No trace seen does **not** prove a path unused: sampling might exclude it.

## 6. Stop, rollback and escalation conditions

Immediately disable tracing or return to the known-good version (following the existing protected rollback process) for any of: source-version mismatch, wrong Cloudflare account, increased 5xx or latency, leaked sensitive metadata, unexpected cost/volume, duplicate webhook/scheduled side effects, DO migration surprises, unbounded queue requests or lost operator visibility.

Do not auto-repeat external effects when the trace adapter encounters an exception. If the platform trace API throws after business logic started, preserve the business callback's original result or original error, record an incomplete tracing attempt separately where supported, and never replay the action. A failed exporter must not convert an otherwise successful webhook effect into a retryable 5xx. Do not make a failed trace look like a successful release.

If the correct account credentials, valid provider version mapping or independent reviewer approval are missing, **halt production changes** but continue source/testing/documentation engineering outside the live service. State the missing concrete approval or access without guessing where secrets are stored.

## 7. Required results and handoff

Publish a portable read-only evidence bundle containing:

- Exact source/PR SHA, independent reviewer decision, account+Worker+version tuple and content hashes.
- Sanitised Cloudflare trace IDs/spans with timestamps and environment, selected route-family and static module labels.
- Configuration and cost/sampling receipt, record of any visible PII/headers/URLs, limits and retention.
- Canary request/status and provider-backed readback; real scheduled/webhook observations where admitted.
- Original vs traced response and durability comparisons, rollback rehearsal and any deliberately withheld effects.
- Clear classification of **source implemented / tested / reviewed / canary accepted / deployed / production verified**.
- A list of unmapped dynamic/indirect modules (443 known unresolved references from the pinned explorer revision) with reasons why absence of observation is not proof of dead code.

Reference current Cloudflare docs:
- https://developers.cloudflare.com/workers/observability/traces/
- https://developers.cloudflare.com/workers/observability/traces/custom-spans/
- https://developers.cloudflare.com/workers/observability/logs/real-time-logs/

**Success is dependable, independently verified operation of the correct live ClawSweeper service — not a generated trace file or a test passing in isolation.**
