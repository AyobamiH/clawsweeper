# ClawSweeper whole-estate owner-runner cutover

Current source candidate: integrated PR #101 at 01f0d766cb3b88da36d2ee01faccc4b17b14d0bb.
This code is staged and unmerged. NO production activation, job registration or release review is established by this file.

## Coverage and classes

The source-hashed manifest in config/ci-workflow-estate.json preserves all
41 workflow files and all 88 jobs. The deterministic migration converter staged
67 GitHub-hosted runner selectors across 32 workflows as run-bound owner labels.
The integrated signed-PR106-derived source retains 79 locally labelled jobs,
including two separately owned validation jobs. All four historically hosted
fallback expressions now resolve to an intentionally unregistered sentinel if
their provider's dedicated runner has not been provisioned; a failed launch may
no longer initiate billable GitHub-hosted compute. The five other dynamically
routed jobs retain the provider-provisioned output labels and must be accepted
with their own lifecycle and source evidence before any operational cutover.
The source audit therefore classifies nine dynamic routes, zero hosted fallbacks.
This is a fail-closed migration, NOT proof that those nine jobs run successfully.

Six explicit classes are implemented in scripts/ci/estate_policy.py:
ordinary (untrusted read-only tests), privileged (including mutation-capable
repair/apply/publish/cloud operations), review (full-source review/inference),
codeql (real two-language SARIF), e2e (nested/rootless container execution) and
windows (genuine isolated native Windows test execution). Job names alone do not
give permission. Unrecognised jobs default to privileged and are held.

This branch includes source-level routing and admission for all classes; it
does NOT contain an accepted native Windows JIT host or a rootless/nested Docker
executor. They are intentionally denied until exact native/contained runtime
proof and full scenarios are available. A WSL Linux process is not Windows.
Windows PowerShell and Node were observed on the physical web machine, but that
does not justify running untrusted PR code directly on the Windows host.

## What executes, and how

scripts/ci/estate_controller.py provides inspect (read-only) and cycle
(owner-only gated). It defaults to disabled. GitHub remains the event, PR,
security scanning and check-run authority. The local controller:
- Requires a complete approved exact-source manifest, a default-branch SHA
  pin, per-job allowlist with class and source SHA256, and a bounded run tuple.
- Compares main's immutable workflow bytes with the actual run-commit workflow
  bytes. Incoming PR/ref changes cannot change an admitted workflow.
- Refuses the old controller when enabled, missing runner pagination and any
  untracked ClawSweeper JIT runner or labelled container.
- Atomically reserves a unique job/attempt before any non-idempotent JIT POST,
  up to four explicitly configured slots. Per-class limits, 2 GiB base memory
  reserve, additive class budgets, disk and shared-fleet checks prevent
  oversubscription. Exactly one attempt key cannot be replayed.
- Uses the existing disposable, image-pinned Linux JIT executor for classes
  whose runtime is actually compatible. It passes no host Docker socket to
  workflow jobs, and it does not weaken the separate nested-E2E or Windows
  execution denial.
- Treats registered JIT receipt, GH job conclusion, worker log SHA256,
  deregistration, no residual owned containers and class-specific effects as
  independent acceptance dimensions. Process success alone never means release
  approval.
- Leaves uncertain registrations or provider effects held. Independent
  reconciliation can free slots once all class-specific evidence is read back,
  while preserving original failures and prohibiting automatic replay.
- For CodeQL, the first language may finish before the second; a terminal,
  cleaned job can enter awaiting_evidence without occupying physical RAM while
  the second language runs serially. Both languages and their SARIF analyses
  must subsequently pass verify_codeql_release.py before reconciliation.
- The source-review class remains denied if model inference lacks authorisation,
  a complete source bundle, or independent verdict. This task forbids Workers
  AI inference and has not authorised an alternative provider.
- Privileged operations remain denied pending per-provider effect readbacks and
  owner run-scoped admission. All preview and source changes stay nonproduction.

Owner configuration is an example only: config/ci-estate-controls.example.json.
Do not copy it to a live owner controls path and flip enabled flags until
independent source approval and per-class operational acceptance.

## Evidence contract, approvals and release sequence

Before any cutover, obtain:
1. Unreduced final-head Node/TypeScript, Python, timing-sensitive, static and
   actionlint results for the exact combined candidate, with log digests.
2. Real two-job concurrent JIT readback on the authorised web fleet, including
   class-specific isolated cgroup resource usage and complete cleanup; offline
   thread-barrier tests are not that proof.
3. Native Windows isolation and actual Codex-launcher test results on a genuine
   Windows runner; rootless/nested Docker full E2E receipts; and equivalent
   Cloudflare lifecycle tests for dynamic runner selectors.
4. Independently reviewed source, including all changed workflow YAML,
   controller, JIT recovery, six admission classes and tests. An old review or
   a green CI check cannot be transferred to a new SHA.
5. Owner merge approval; separately merge PRs #93 and #94 under their original
   review gates, preserving fixture PR #92 unmerged. Stage guarded activation
   by class while leaving live sweep behaviour intact until readback proves
   parity. No paid GitHub runner, new inference spend or production mutation.

The 36 GitHub workflow-registry paths absent from main are historical registry
entries, NOT 36 additional workflows to resurrect automatically. Decide their
retirement separately from the 41 current source files.


## Owner-operated complete check timeout contract (2026-11-08)

The `.github/workflows/ci.yml#check` job executes the **unchanged complete**
`pnpm run check` suite. On authorised `web` with two CPU cores, an
independently hash-verified check ran for 26m42s (18:04:17–18:30:59 UTC).
The previous 15-minute GitHub job deadline therefore cannot accommodate
the observed workload. Source-stage sets the job deadline to **38 minutes**,
inside the disposable JIT executor's **42-minute** hard cap, retaining
four minutes for GitHub conclusion, deregistration and cleanup. This is a
bounded timeout correction, *not* a relaxation of the test suite.

`test/ci/test_validation_full_check_budget.py` fails on the old 15-minute
deadline, an unbounded deadline, a return to billable generic runners,
lost `persist-credentials: false`, or removed canonical validation.
No actual GitHub check job has yet been exercised at this new timeout.
The staged correction is uncommitted, requires full exact-source validation
and remains subject to independent review and owner approval.
