# ClawSweeper — independent production-source tracing review brief

**Review date:** 8 November 2026
**Repository:** https://github.com/AyobamiH/clawsweeper
**Review type:** Independent adversarial source, privacy, reliability and release-admission review.
**Decision:** APPROVE, REQUEST CHANGES or REJECT, with an independently reproducible evidence bundle.

## 1. Objective

Decide whether the proposed guarded, native Cloudflare Workers tracing instrumentation can be merged, canary-enabled and eventually accepted for ClawSweeper **without changing existing business effects, leaking sensitive information, falsely attributing source versions or competing with the active ClawSweeper release controller**.

The outcome must be an independent judgement about the *actual integrated source and its operational dependencies*, not an endorsement based on the unit-test count.

## 2. Authoritative state: fetch live before review

- ClawSweeper `main` at the time of preparation: `03d32fb784758d2a3770aaa9721f1212ac061096`.
- Existing multi-PR release chain includes PR #101 and draft PRs #104–#106. PR #106 last observed at `28addfb841f9605e634721d7d360d024ff91c636`. These are **separate work**: do not change, merge or supersede them during this review.
- Architecture explorer: https://clawsweeper-codebase-map.pages.dev/; source-bound static graph is for the above main SHA. Its production deployment proves the explorer, **not ClawSweeper runtime tracing**.
- Actual public ClawSweeper service: https://clawsweeper.openclaw.ai/api/health, fallback https://clawsweeper-status.services-91b.workers.dev/api/health.
- Both ClawSweeper service endpoints returned deployment claim `2ea8790a6c7c455a7f0291857337d58840d0464f` on 8 November 2026. That SHA was not found in the current `AyobamiH/clawsweeper` repository history via local Git or GitHub commit lookup.
- Actual service is documented under **Services@openclaw.org**, Cloudflare account `91b59577e757131d68d55a471fe32aca`, Worker `clawsweeper-status`.
- A separate `ayobamih-clawsweeper-status` Worker and the explorer's Pages project exist in another account. **Do not confuse their versions, credentials, deployments or public-health URLs**.
- The independent review must retrieve current live state and authorised device inventory before relying on any of these observations.

## 3. Proposed source under review

Inspect the *latest exact head of the dedicated tracing PR* at review time, plus every source and configuration file reached by its operational paths. The isolated candidate originally started from `03d32fb...`.

Relevant changes:

- `dashboard/source-tracing.ts`: source-claim guard, fixed route-family allowlist, native `ctx.tracing.enterSpan`, safe span attributes, fail-safe disabled behaviour, and prevention of double execution when the tracing backend throws after calling business logic.
- `dashboard/worker.ts`: non-destructive integration around the existing `fetch` dispatch and `scheduled` health-sampling promise, preserving `ctx.waitUntil` completion semantics.
- `dashboard/wrangler.toml`: native tracing explicitly **disabled** by default, with a documented bounded sampling rate for a separately approved activation.
- `scripts/generate-tracing-canary.mjs`: local-only, no bindings or secrets, exact clean-source canary-config generation.
- `test/dashboard-source-tracing.test.ts`: adversarial, repeated-call, error and privacy contracts.
- Tracer runbook and operator evidence specifications in `docs/`.

**There is no production-tracing approval by creating a PR.** The reviewer must inspect the release ancestry and current implementation again.

## 4. Mandatory adversarial source checks

1. **Effects and retries:** Does every path invoke its original callback exactly once when tracing is disabled, enabled, absent, throws before execution, throws after effect execution, rejects asynchronously or throws from business logic? Look for a replay path, altered webhook acknowledgement, lost `waitUntil`, unhandled scheduled promise or changed response/status/CORS semantics.
2. **Data minimisation:** Trace attributes may include only a fixed route-family label, allowlisted module/source identifiers and schema. No raw URL, query, webhook delivery ID, account/pet/client names, repo-private coordinates, headers, GitHub token, request/response body, IP, GitHub payload, SQL or exception details. Inspect Cloudflare's **automatic** spans as well as the application's custom spans; custom attribute filtering does not suppress platform-collected metadata.
3. **Source authority:** A string in `CLAWSWEEPER_DEPLOY_SHA` is a **claim**, not independent deployment proof. Confirm the correct account, actual Cloudflare Worker version ID, uploaded bundle provenance, Git ancestry and GitHub commit. If any link is missing or the source IDs disagree, admission fails closed.
4. **Execution context:** Validate real Cloudflare Workers `ctx.tracing` behaviour under the pinned `compatibility_date = 2026-05-11`, including the asynchronous callback contract and spans around `fetch`, webhooks and scheduled tasks. Mocked `ctx.tracing` tests are insufficient.
5. **Sampling, cost and privacy:** No activation with default 100% tracing. Confirm the proposed 0.005 head-sampling value or justify a smaller bound, seven-day retention, the account's quota and privacy protections. The Cloudflare platform's automatic HTTP/DO/R2 spans can include metadata not selected by our source adapter.
6. **Isolation:** Verify no new route, secret, queue, durable-object migration, worker binding, credential, timer or auto-publishing system was introduced. Maintain distinct OpenClaw and Ayobami Cloudflare accounts. The canary must never use actual production DO, R2, queues or webhook secrets.
7. **Adversarial compatibility:** Run a clean exact-head type-check and targeted dashboard, webhook, queue and privacy regression suites. Test fail-closed source mismatch and high concurrency; inspect deployment dry-run metadata and delta versus the production Worker.

## 5. Required reproduction and negative tests

- Retrieve exact head SHA from GitHub and verify all local file hashes against it.
- `tsc -p tsconfig.dashboard.json --noEmit` and focused tests (`test/dashboard-source-tracing.test.ts`, existing dashboard health, webhook ingress, status-privacy and observability regressions).
- Run a **local-only** Wrangler/Miniflare canary using a clean, committed source. Probe `GET /api/health` and assert identical pre/post tracing response body and status.
- Force tracing failures **before** and **after** callback invocation. Demonstrate no duplicated external effect.
- Validate scheduled `ctx.waitUntil` boundaries and no false success when its asynchronous work fails.
- Negative: feature disabled, invalid/missing source SHA, missing `ctx.tracing`, nonallowlisted routes, throw/rejection, malicious query strings, potentially sensitive headers, repeated webhook delivery.
- Inspect and independently read back the provider version and actual sample from the **correct** account. Never infer current source from a Pages or different Worker deployment.

## 6. Release decision and acceptance matrix

**Source APPROVE** requires: complete-source review, all specified tests, no unresolved P1/P2 issues, explicit privacy-cost evaluation, exact candidate SHA, and an independently signed reviewer receipt. Approval for source does **not** authorise immediate live traffic collection.

**Canary APPROVE** separately requires: correct-account and version readback, source-bound deployment receipt, no access to production state from the canary, a bounded sampling window, independent trace ingestion/readback, and an operator rollback plan. The presence of a health response alone is not sufficient.

**Production ADMIT** requires: reviewer-approved source that is part of the authorised release lineage; correct Cloudflare account; readback of the exact uploaded Worker version/source; controlled trace observation of real traffic and scheduled execution; absence of PII/token leakage; no behavioural regression; two healthy observation cycles where the applicable workflow requires them; and an independently reproducible evidence package.

Any missing source/version correlation, valid independent reviewer sign-off or required credential is a **HOLD**, not a test pass or permission to deploy an alternative Worker.

## 7. Required reviewer output

State **APPROVE / REQUEST CHANGES / REJECT** separately for (a) source, (b) canary, and (c) production admission. Include:

- Exact reviewed commit, PR, Git ancestry, path/line findings, impact and severity.
- Tests run with commands and results; experiments attempted; negative cases and coverage limitations.
- Independent provider version IDs, account identifier, timestamped redacted trace samples, source-hash readback and sample-rate/cost findings.
- Any duplicated effect, security/privacy leak, unknown dynamic path, failing test, unresolved deployment mismatch or pending owner action.
- A final list of approvals still missing, the precise action to close each, and an explicit do-not-merge/do-not-activate decision until every required gate is evidenced.

Reference documentation: https://developers.cloudflare.com/workers/observability/traces/ and https://developers.cloudflare.com/workers/observability/traces/custom-spans/.

**No earlier assistant assertion or local test result may substitute for your independent source and runtime acceptance.**
