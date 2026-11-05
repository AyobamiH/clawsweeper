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
- PR [#87](https://github.com/AyobamiH/clawsweeper/pull/87), exact signed
  candidate `c37692c7ff4471a10d9d4422cb649ef2123d4e29`, subsequently
  passed controlled CircleCI Free **Linux pipeline #17/job #6**. Independent
  provider readback verified the matching SHA, successful full Linux suite,
  sparse checkout and pinned actionlint GitHub-workflow semantics check.
  GitHub status `ci/circleci: clawsweeper-full-linux-node24` was successful
  (status ID `57813859805`). Owner-only evidence:
  `controlled-linux-candidate-acceptance-c37692c7ff4471a10d9d4422cb649ef2123d4e29.json`.
- An earlier, genuine **macOS pipeline #13** on main failed because full Linux
  tests require Linux-only descriptor confinement and tmux; preserve that
  failure. The corrected separate, native Darwin/arm64 portable suite passed
  **macOS pipeline #16/job #5** against the same exact PR candidate.
  Provider readback verified all required steps and GitHub context
  `ci/circleci: clawsweeper-genuine-macos-node24` (status ID
  `57806480052`). Owner-only evidence:
  `controlled-macos-acceptance-c37692c7ff4471a10d9d4422cb649ef2123d4e29.json`.
  The native smoke supplements, but **does not replace**, full Linux CI.
- The owner controller/audit suite most recently passed **114 tests**, including
  durable restart and no-replay safeguards. Both new provider runs were
  controlled acceptances, **not** naturally triggered infrastructure failovers.
  Do not repeat a proven pipeline on the same candidate.

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
   Linux fallback. ClawSweeper's Linux and macOS jobs have both passed controlled
   acceptance on the PR #87 candidate above. Do not repeat either accepted
   dispatch on that SHA. For any genuinely new candidate, verify the Free-plan
   credit eligibility and capacity before on-demand macOS execution.
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
  `pnpm run test:workflow-sparse-checkout`. The pinned actionlint semantic
  check on Linux pipeline #17 verifies parity for that exact candidate;
  independent primary checks must still be preserved, not relabelled.
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

**Current disposition:** Controlled exact-candidate Linux **#17** and native
macOS **#16** provider acceptance, plus fail-closed controller integration
tests, are confirmed; `circleci-fallback-policy.json` is
`guarded_infrastructure_fallback_enabled`. A naturally occurring resource
hold has **not** yet proved automatic dispatch/reconciliation. Complete loss
of the primary controller is a separate standby/lease problem that remains
**unaccepted** until independently verified. GitHub-hosted required checks
remain blocked by account-level billing restrictions (zero executed job steps),
not by demonstrated source-test failures. The PR therefore remains draft,
unmerged and not release-ready without fresh exact-head Codex review, legitimate
required-check resolution and explicit owner merge approval. Do not manufacture
an outage, replay an uncertain POST, repeat previously accepted provider jobs,
or spend outside Free credits to manufacture a green result.

## Existing infrastructure

- Local policy: `~/.local/share/local-ci/fleet-policy.json`
- Fleet controller: `~/.local/share/local-ci/fleet_ci.py`
- Fleet tests: `~/.local/share/local-ci/test_fleet_ci.py`
- Systemd timers: `local-ci-fleet.timer`, `local-ci-cleanup.timer`
- Evidence: `~/.local/share/local-ci/evidence/fleet/`
- CircleCI AgentProof macOS proof: `AyobamiH/clawsweeper-state` repository,
  `local-ci/bootstrap/evidence/agentproof-circleci-macos-20261029.json`

**Do not modify the product's operational architecture to satisfy CI cost goals.**

## Verified feedback-loop timing audits (PR #84, 2026-11-01)

Before changing providers, runner size, caching or test-selection rules, measure
existing exact-commit local-fleet receipts using the read-only command:

```sh
node scripts/ci-feedback-audit.mjs --repo AyobamiH/clawsweeper --limit 150
```

The audit reads the local fleet's receipts and associated test logs, reports
measured checkout, setup, full-validation and sparse-smoke durations, and ranks
slow tests **only when the log SHA-256 and byte count match its receipt**.
Missing, mismatched and unverified logs are reported separately and must not
contribute test timings. Queue time and incomplete validation are marked
**unmeasured**. A failed, skipped, interrupted or missing run is never a pass.
Retain exact commit hashes, runner policy, source receipts, and negative results.

**Historical baseline (captured 1 November 2026):** 17 local ClawSweeper
receipt attempts spanning nine commits/policies. Median completed
full-validation stage was 914 seconds, versus 41 seconds dependency setup,
8 seconds checkout and 2 seconds workflow syntax validation. The closeout
provenance and 4,097-event shard-import fixtures were dominant. Comparing
different commits and environments does not establish any speedup.

PR #83 was subsequently merged after successful exact-SHA local-fleet checks.
Its upstream fixes to test concurrency, timing-sensitive test isolation and
**local signing isolation inside disposable Git fixtures** are authoritative.
Do not restore a blanket `GIT_CONFIG_COUNT` signing override to the whole
Node test process: that obscures tests deliberately exercising malicious or
failing signing callbacks. Preserve the signing security negative controls.
No production code, signing policy, billing setting or CI authority needs
to change for these measurement improvements.

Any performance improvement must be demonstrated with before/after
measurements under comparable exact commits, hosts, resource limits and
identical required assertions. Do not delete slow tests, hide provider
failures, silently skip coverage, activate a paid runner or merge without
the existing review and evidence contract.
