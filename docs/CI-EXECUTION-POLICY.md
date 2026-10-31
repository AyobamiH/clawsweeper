# ClawSweeper CI execution contract (canonical)

**Scope:** development/test execution only. ClawSweeper's production review, repair,
Cloudflare Worker/R2, GitHub apply, Codex sign-in and customer-facing operations are
**not** replaced by this policy. All agents working on either home machine must
read this file and the root `AGENTS.md` before changing CI, release or runners.

## Selection and ownership

1. **Primary:** owner-operated `web`/`Ayobami-Dev` local CI fleet, exact-SHA Node 24
   suite, durable SQLite queue, bounded Docker execution, retained receipts and
   GitHub `local-ci/linux-node24` status. Never bypass a failed check.
2. **Fallback:** CircleCI Free Linux, **full equivalent suite**, only when the
   primary has an *infrastructure* hold (offline, capacity, unavailable Docker,
   or unavailable execution host), not when code tests fail. An authorised local
   controller must atomically own the job, preserve its original SHA and verify
   that no primary execution is active before dispatch.
3. **Special platform:** CircleCI Free macOS on demand for genuine Darwin/ARM64
   evidence, with exact SHA and separately named check; this is not routine Linux
   fallback. AgentProof's successful macOS canary is precedent, not proof that
   ClawSweeper's CircleCI project has been enrolled.
4. **Hold:** if CircleCI is not connected, has insufficient free credits, is
   restricted, or exact-SHA evidence is missing, hold the job and retry primary.
   Never fall back to paid GitHub-hosted Actions, a paid CircleCI tier, API-key
   inference or a reduced test suite.

## Provider contract

- GitHub remains source/PR/status authority. A CircleCI result must be verified
  from the provider API for the **same commit**, job and workflow; publish a
  separate `ci/circleci: clawsweeper-full-linux-node24` context only after
  verifying the job result and retaining an immutable receipt. Never overwrite
  `local-ci/linux-node24` with an unverified fallback success.
- One durable attempt owner per repository/SHA/suite. Do not dispatch both
  providers concurrently. Reconcile uncertain dispatch before retrying; a lost
  API response is not evidence of non-execution. Do not retry failed tests on a
  different provider to chase a pass.
- Fallback must run `pnpm install --frozen-lockfile`, `pnpm run check`, and
  `pnpm run test:workflow-sparse-checkout`. Workflow semantic validation
  remains a separately required primary check until parity is proven.
- CircleCI `.circleci/config.yml` defaults to **no workflows**. The controller
  requests `fallback_ci=true` and `expected_sha=<40-hex commit>`; macOS uses
  `macos_ci=true`. Do not enable automatic branch-triggered paid execution.
- Never export ChatGPT/Codex login cache, GitHub PAT, Cloudflare credentials,
  signing keys or production secrets to CircleCI fallback. Subscription Codex
  authentication stays in its own approved execution boundary.
- Free allowance is finite and provider-specific. Confirm remaining credits and
  account spending controls before enabling dispatch; absence of proof = HOLD.
- Keep runner cleanup scoped to owned containers and temporary workspaces;
  preserve test evidence and failure receipts. No blanket Docker or cache prune.

## Installation and acceptance gates

1. CircleCI ClawSweeper project explicitly connected to the GitHub repository.
2. CircleCI Free billing/credit readback verified; no paid plan or overage.
3. Token provisioned to a local owner-only file (0600), never in Git.
4. Test an explicit CircleCI pipeline on an exact commit; verify all checks and
   independent provider status, with no Codex/production credentials.
5. Simulate local capacity hold; verify one dispatch, idempotent retry, durable
   receipt, recovery after controller interruption and no duplicate execution.
6. Verify that a failing source test is NOT sent to CircleCI and that missing
   CircleCI access results in HOLD rather than false success.

Until these gates pass, **fallback dispatch is NOT enabled**. The primary local
fleet remains authoritative and CircleCI is only a prepared candidate.

## Existing infrastructure

- Local policy: `~/.local/share/local-ci/fleet-policy.json`
- Fleet controller: `~/.local/share/local-ci/fleet_ci.py`
- Fleet tests: `~/.local/share/local-ci/test_fleet_ci.py`
- Systemd timers: `local-ci-fleet.timer`, `local-ci-cleanup.timer`
- Evidence: `~/.local/share/local-ci/evidence/fleet/`
- CircleCI AgentProof macOS proof: `AyobamiH/clawsweeper-state` repository,
  `local-ci/bootstrap/evidence/agentproof-circleci-macos-20261029.json`

**Do not modify the product's operational architecture to satisfy CI cost goals.**
