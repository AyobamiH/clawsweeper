# ClawSweeper CI execution contract (canonical)

**Scope:** development/test execution only. ClawSweeper's production review, repair,
Cloudflare Worker/R2, GitHub apply, Codex sign-in and customer-facing operations are
**not** replaced by this policy. All agents working on either home machine must
read this file and the root `AGENTS.md` before changing CI, release or runners.

## Verified activation checkpoint (2 November 2026)

The guarded CircleCI Free **Linux** fallback is enabled in the home-machine
controller, but admission requires a genuine *infrastructure* hold, a fresh
Free-plan budget receipt, the exact current `main` SHA and exclusive ownership.
A failing source test must never fail over. CircleCI default push pipelines
remain inert. Do not turn on paid execution or export Codex credentials.

- Project: `gh/AyobamiH/clawsweeper`; Free plan, paid overage false; owner-only
  API token on the host (never in this repository). Budget refresh timer runs
  every 20 minutes and a stale receipt blocks dispatch.
- PR [#86](https://github.com/AyobamiH/clawsweeper/pull/86) merged as
  `920ff25f42928262d1346f5293339b3ebf654107`. Controlled CircleCI pipeline
  #10 (verified [job #3](https://circleci.com/gh/AyobamiH/clawsweeper/3)) succeeded on that exact
  SHA: Node 24 full checks, pinned dependency installation, `tmux`/`rsync`,
  sparse-checkout acceptance and configured step checks all returned success.
- Independent provider readback and GitHub context
  `ci/circleci: clawsweeper-full-linux-node24` were both successful; the receipt
  is stored under `~/.local/share/local-ci/evidence/circleci-fallback/` as
  `controlled-live-acceptance-920ff25f42928262d1346f5293339b3ebf654107.json`.
  A self-hosted `local-ci/linux-node24` result also reported 5/5 success.
- On 2 November, 43 CircleCI controller/reconciliation/integration tests passed,
  including simulated infrastructure admission, no duplicate dispatch and
  fail-closed Free-budget conditions. **This is not a demonstration of a
  naturally occurring automatic failover during a real primary outage.**
- ClawSweeper's *macOS* job remains separate and on-demand. Controlled
  pipeline #13 on 2 November 2026 genuinely ran on macOS and failed its
  broad Linux-only test contract. Platform bootstrap and Node 24 checksum
  passed; several tests require Linux descriptor confinement and tmux. This
  is failure evidence, **not** a passing macOS acceptance. The revised macOS
  lane runs native builds, lint, docs validation and six portable test files.
  It must receive its own exact-SHA successful provider receipt before being
  marked accepted; the full Linux suite remains mandatory and unchanged.

## Selection and ownership

1. **Primary:** owner-operated `web`/`Ayobami-Dev` local CI fleet, exact-SHA Node 24
   suite, durable SQLite queue, bounded Docker execution, retained receipts and
   GitHub `local-ci/linux-node24` status. Never bypass a failed check.
2. **Fallback:** CircleCI Free Linux, **full equivalent suite**, only when the
   primary has an *infrastructure* hold (offline, capacity, unavailable Docker,
   or unavailable execution host), not when code tests fail. An authorised local
   controller must atomically own the job, preserve its original SHA and verify
   that no primary execution is active before dispatch.
3. **Special platform:** CircleCI macOS on demand for genuine Darwin/ARM64
   evidence, with exact SHA and a separately named check; this is not routine
   Linux fallback. ClawSweeper's project is enrolled and its Linux job is proven,
   but its macOS job is **not yet independently accepted**. Verify Free-plan
   credit eligibility and capacity before any macOS dispatch.
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

**Current disposition:** Gates 1–4 and fail-closed controller tests are met;
`circleci-fallback-policy.json` is `guarded_infrastructure_fallback_enabled`.
A natural primary-infrastructure outage has not yet independently exercised
automatic dispatch/reconciliation end to end, and ClawSweeper macOS acceptance
is still open. The primary local fleet remains authoritative. No developer
should manufacture an outage, replay an uncertain POST, or spend outside Free
credits to manufacture a green result.

## Existing infrastructure

- Local policy: `~/.local/share/local-ci/fleet-policy.json`
- Fleet controller: `~/.local/share/local-ci/fleet_ci.py`
- Fleet tests: `~/.local/share/local-ci/test_fleet_ci.py`
- Systemd timers: `local-ci-fleet.timer`, `local-ci-cleanup.timer`
- Evidence: `~/.local/share/local-ci/evidence/fleet/`
- CircleCI AgentProof macOS proof: `AyobamiH/clawsweeper-state` repository,
  `local-ci/bootstrap/evidence/agentproof-circleci-macos-20261029.json`

**Do not modify the product's operational architecture to satisfy CI cost goals.**
