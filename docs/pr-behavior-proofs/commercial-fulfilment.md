# Commercial fulfilment behavior proof

> Current release-review method (14 October 2026): the project owner requested
> a recorded examination in the current implementation session, not a mandatory
> independent/provider review. The scoped `AGENTS.md` rule is authoritative for
> this proposal. Earlier paragraphs recording an external-review blocker are
> historical. Customer-patch semantic review and all runtime safeguards remain.


Claim: the new executor can isolate model tool filesystem/network access and
validate a bounded candidate in a separate credential-free Docker container.
This evidence does not claim an end-to-end paid customer delivery.

## Exercised surfaces and scenarios

- `scripts/commercial/codex-runtime.mjs`: the real pinned Codex 0.157.1 Linux
  sandbox in write and read-only modes. A synthetic authentication file and an
  outside sentinel must be unreadable. The workspace must obey its selected
  write policy. A direct network connection must be denied.
- `scripts/commercial/validate.mjs`: a synthetic public Node project with a
  lockfile v3 and no dependencies. A bounded greeting implementation passes
  real `npm ci --ignore-scripts` and `npm test` containers. An incorrect greeting
  fails and is never accepted as a validated candidate. Inside the test process,
  assertions verify that merchant/GitHub/API environment variables and the host
  authentication path are absent, the Docker socket is absent, `/etc` is
  read-only, and direct network access is denied.

## Commands and environment

Run from the repository root on Linux with Node 24 and Docker. The sandbox
preflight requires user namespaces/bubblewrap support; it fails closed if that
boundary cannot be proved. No model turn or real credential is needed.

```bash
npm install --prefix .artifacts/codex-proof-cli --ignore-scripts --no-audit --no-fund @openai/codex@0.157.1
node scripts/commercial/prove-sandbox.mjs "$PWD/.artifacts/codex-proof-cli/node_modules/.bin/codex"
node scripts/commercial/prove-validation.mjs
pnpm build
node scripts/commercial/prove-bootstrap.mjs
node --test test/repair/commercial-fulfilment.test.ts test/repair/commercial-workflow.test.ts
pnpm check
```

Observed on 2026-10-13 in the isolated Linux worktree
`/home/johnh/commercial-fulfilment-20261013/clawsweeper`, based on commit
`53977a23f6a3fd30f63bc42e5d1ca6c399d4e494` with the proposed commercial files:
Node `24.18.0`, Docker `29.1.3`, native Codex `0.157.1`.
Provider: `local-container`; disposable Docker containers are named
`tw-deps-<synthetic-operation>-<timestamp>` and
`tw-test-<synthetic-operation>-<timestamp>` and removed with `--rm`.

The validation image was `node:24.18.1-bookworm-slim`, observed image ID
`sha256:c825877c1c5a39d12235596e2c89f3892618ac44e99d630660a75837fca8a02f`.

## Observable results and artifacts

- Sandbox proof: both write and read-only profiles returned
  `authReadDenied=true`, `outsideReadDenied=true`, `networkDenied=true`.
  The evidence reports `modelTurns=0` and `realCredentials=false`.
- Docker proof: dependency installation and tests returned exit code zero for
  the correct patch; `negativeRejected=true` for the incorrect patch. All five
  isolation assertions passed.
- Focused contract/security tests: 16 passed, zero failed.

The scripts reproduce durable JSON evidence at
`.artifacts/commercial-sandbox-proof.json` and
`.artifacts/commercial-docker-proof.json`. These contain only synthetic fixture
metadata, hashes, version information and check results. Raw repository source,
authentication material and provider responses are not included in the reports.
The fixtures and assertions are tracked in the two `prove-*.mjs` scripts, so the
proof does not depend on an untracked script or a live customer repository.

## Limits and rollout boundary

This proof does not exercise GitHub workflow dispatch/OIDC, the Cloudflare
provisioning lifecycle, a ChatGPT model turn, Stripe payment/capture, a customer
repository publication, or independent exact-commit PR checks. Those provider
integration checks remain distinct activation/delivery gates. The production
workflow repeats the sandbox preflight before each model session and refuses
publication without container validation and a separate semantic review.

The first service supports public repositories only. The merchant must obtain
explicit consent to public GitHub evidence before dispatch; the executor uses
public workflow artifacts with one-day retention. Private repositories are not
supported by this transport.

OpenClaw Bay is unaffected: this adds a separate merchant execution lane and
does not change the repair observer contract, dashboard, or browser controls.
The existing review/apply/close workflows remain outside this proof.

## Recovered continuation — 14 October 2026

The original proposed workflow and scripts were recovered without replacing the
worktree or changing an existing review/apply/publishing runtime. They remain
uncommitted on the commercial branch based on `53977a23`; that base SHA does not
contain the proposed commercial implementation.

The saved pre-commit review identified an invalid direct TypeScript import of
the subscription quota client. The recovered draft already contained its fix:
the trusted provisioning job builds `dist/`, retains that artifact, and both
model jobs import `dist/subscription-quota-client.js`. The continuation adds a
real compiled-artifact startup proof before compute provisioning, plus workflow
regressions so that the correction cannot silently disappear.

`prove-bootstrap.mjs` copies the real compiled artifact to an isolated temporary
package containing neither source TypeScript nor project `node_modules`. It
loads the same module as the generation and review jobs, then exercises missing
configuration, explicit admission, explicit denial and an unavailable
coordinator. The coordinator is a loopback fixture, uses a synthetic HMAC secret,
and receives exactly three authenticated requests. The child environment has
an empty PATH and no real authentication or API credentials. No model turn is
performed and a fixture allowance response is not evidence of live allowance.
Its report is `.artifacts/commercial-bootstrap-proof.json`.

Fresh local results: 21 commercial tests pass; the pinned Codex sandbox again
rejects access to synthetic authentication and outside files and denies network
access in both read-only and writable profiles; the Docker validator again
accepts the correct patch, rejects the incorrect patch and confirms all five
isolation checks. These are component proofs, not a hosted workflow run.

The fresh local Codex review request was interrupted by the provider's usage
limit. It returned no clean verdict. No paid/API fallback, commit, merge or
commercial admission activation is authorised by these proof results. Fresh
pre-commit and committed-head review remain release gates. Actual GitHub App
consent, dedicated Stripe test configuration, approved merchant terms and the
real test-mode purchase-to-verified-PR path remain separate requirements.

## Approved provider fallback extension — 14 October 2026

Claim: commercial generation and fresh independent review use the existing
`selectInferenceRoute` policy; denied/unavailable Codex admission selects the
configured Workers AI provider before a model request. There is no mid-run
provider replay. The alternative transport returns JSON data only: it has no
shell, filesystem tools, GitHub token, merchant authority or test execution.
Its output passes the same path/budget checks and credential-free Docker tests.
Both providers are identified honestly in versioned, contract/candidate-bound
receipts; separate invocation identities are required for independent review.
Legacy Codex-only receipts remain valid only under the legacy evidence rules.

Proof: deterministic route/HTTP failure tests; real quota-denied Workers AI
fixture generation; real Docker validation; a separate Workers AI review;
backend acceptance/rejection tests for provider mismatch, stale digest and
same-call reuse. Source reviews cover complete bounded source bundles with
recorded hashes and actionable findings, not a model-generated completion claim.
All fixtures are disposable; no customer payment, target PR, production
activation or existing runtime mutation is part of this component proof.


### Source-release review integration

`scripts/commercial/source-review.mjs` provides the alternative source-review
entry point for these two owned repositories. It builds a complete changed-file
bundle against an exact base, rejects unsafe source paths and links, uses the
existing trusted ClawSweeper input scanner before provider access, selects the
provider through the shared router, and rejects incomplete, unbound or stale
reviews. A clean receipt requires zero actionable findings. Receipt identity
must be refreshed before and after committing; runtime tests do not replace it.
No clean live source-review receipt has yet been produced for this extension.
The scoped owner-approved rule in AGENTS.md permits this alternative provider,
but the ordinary evidence and landing requirements are not waived.


### Reproduction commands for the fallback extension

```bash
pnpm build
node --test test/repair/commercial*.test.ts test/inference-router.test.ts test/inference-routing-workflow.test.ts
node scripts/commercial/prove-fallback.mjs /absolute/path/to/wagging-web-wins/worker/fulfilment-inference.js
node scripts/commercial/source-review.mjs /absolute/path/to/repository EXACT_BASE_SHA /private/evidence/review.json
```

The source-review command requires the existing trusted scanner on PATH and the
same dedicated Workers AI environment variables used by the approved shared
router. It never reads a credential file or substitutes the broad deployment
token. Its full-source scan occurs before sending any source to either provider.
The fallback integration proof is explicitly offline, even though it runs actual
HTTP and Docker code. Live provider fixture acceptance is a separate evidence
record and must identify each real provider call and its limited scope.


## Local source-review and verification corrections — 14 October 2026

The source collector now uses `tw.commercial-source-bundle.v2` and review receipts
use `tw.independent-source-review.v2`. Original and proposed executable modes are
included alongside exact UTF-8 file contents, so permission-only changes cannot
reuse an old review digest. Parent symlinks, final symlinks, hardlinks, special
files, invalid encoding and files changing during descriptor reads are rejected.
Original Git tree entries distinguish additions from failures to read a required
baseline object. Only untracked `.artifacts/` and `.wrangler/` output is excluded;
tracked changes there stop capture rather than silently disappearing.

An entirely local synthetic reproduction demonstrated both the old permission
hash omission and an outside-file read through a symlinked parent. The corrected
collector passes 16 focused review-contract tests, including those regressions.
No source was transmitted to a provider by these tests. The guarded independent
source-review invocation remains refused by the session's tool safety check;
local inspection and these tests are not an independent release-review verdict.

The proposed commercial workflow uses the repository-approved checkout v7 commit
and the existing immutable App-token action with its version annotation. Full
verification requires `jq`; the local run uses a checksum-verified jq 1.8.1 binary
in a temporary tool directory. Tests run with an isolated temporary HOME, not
`GIT_CONFIG_GLOBAL=/dev/null`: tests that intentionally create fixture global Git
settings must remain writable without changing the real user's Git configuration.
The initial environment/pin failures were retained and then reproduced passing
by 106 prerequisite tests before the fresh full-suite run.


### Complete-suite findings and fixture corrections

The first complete isolated run finished with 4,459 tests: 4,447 passed, five
failed and seven platform-specific skips. It is retained as a failed run, not a
release pass. The five failures were reproduced and corrected without changing
production process-containment code or skipping the security tests:

- Fixture package-manager invocations outside the repository selected pnpm 12,
  while the repository pins 11.10.0. A disposable Corepack cache now uses
  pnpm 11.10.0 as its default while honoring each fixture's explicit
  packageManager version; production/global Corepack settings are untouched.
- The namespace-init test now verifies that the synthetic target is inside the
  PID namespace, attempts termination, proves the supervisor remains alive,
  and proves detached-child rejection and reaping. It no longer mistakes a
  250ms setup timeout for evidence that the attack was actually exercised.
- Three detached-process fixtures now place their executable shims in explicit
  `bin` directories on the fixture PATH. Those are the already approved
  read-only runtime mounts; arbitrary host temporary directories remain hidden.
  Each test still requires a background-process rejection and no delayed marker.

All five focused regressions pass. These fixture-only corrections are included
in the full source inventory and must be independently reviewed too. No new
production library/runtime permissions are introduced. Source capture allows
individual files up to 512 KiB to include the complete existing target-validation
test file. The source-review-only GLM request cap is 1,200 KiB; commercial
execution request limits remain unchanged. There is no truncation or omission
of tests to fit a review. The external independent-review call remains blocked;
no further source transfer or alternative review route was attempted.


### Version-aware final verification environment

A fixed pnpm 11 launcher on the entire test PATH resolved the unversioned hook
fixture but was not the correct final environment: four other fixtures explicitly
require pnpm 10.33.0. That full run is retained as a failed result, not promoted.
The replacement uses an isolated HOME and COREPACK_HOME with
COREPACK_DEFAULT_TO_LATEST=0. Its default is pnpm 11.10.0 and explicit fixture
versions continue to route normally through Corepack. It does not ignore version
checks or change repository/package-manager configuration. The five focused
version-selection regressions passed before the final full-suite rerun.


## Recorded implementation examination — 14 October 2026

The implementation was examined in the current ChatGPT development session.
This is an implementing-assistant review, not an independent audit or a fabricated
external-provider verdict. Core runner/provider code, the commercial workflow,
backend authority/state/payment/publication paths, release changes and relevant
test/proof changes were inspected. The record distinguishes source inspection,
automated tests, historical live fixture evidence and unperformed acceptance.

Two new backend defects were reproduced and corrected: schema readiness accepted
a surviving migration marker even if required tables/columns were absent; settled
refunds continued to return an obsolete waiting action. Fifteen regression cases
were run first on the old code (13 failures, two control passes) and then on the
correction (all 15 passed). Current backend/release contracts passed 224 tests.
The fixes change neither payment/refund amounts nor provider credentials, and
schema inspection performs zero-row reads without DDL or customer-data mutation.

The external-provider source-review utility remains optional. No refused source
transfer was retried and no model inference was invoked by this examination.
Recorded findings, source hashes/modes and validation outcomes are retained in
the examination evidence. A committed delta must match that record before
landing. Provider setup, hosted acceptance and production enablement remain
separate; a source review does not establish successful customer delivery.
