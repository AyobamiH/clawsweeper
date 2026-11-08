# Complete ClawSweeper workflow estate — migration gate

This work-in-progress inventory does NOT claim that remaining jobs are migrated
or operational. It covers every current workflow file and job on the signed
integration source. Each source has a SHA-256 and each job its actual runner
selection in ../config/ci-workflow-estate.json. Entries present in GitHub's workflow
registry but absent from current default-branch source are not assumed live.

Commands: node scripts/ci/workflow-estate.mjs --check (fails on source/job
drift), or --write (regenerate for explicit review). --registry PATH compares
a captured GitHub Actions workflow registry without running anything.

## Target: owner-operated computation, GitHub event plane

GitHub remains the source/event/check/alert and PR audit authority. Actual job
execution, admission, isolated workers and recovery belong to the local fleet.
Changing GitHub-hosted runner labels without ensuring the execution and
security contract is NOT a safe migration.

- Untrusted PR, issue and webhook content never receives privileged credentials,
  host files, a host Docker socket or unrestricted private-network egress.
- GitHub mutation, publishing, Cloudflare resource lifecycle and commercial
  tasks require approved immutable workflow source, actor/event checks,
  explicit owner operation approval, durable intent and effect readback.
- CodeQL uses its own pinned image; automerge requires real hermetic Docker;
  the Windows launcher must run on genuine Windows rather than substituting
  Linux, and dynamically provisioned workers must retain their lifecycle.
- Source review requires complete exact-source coverage and findings. No
  model inference or extra spending is authorised by this inventory.
- The single-job controller cannot safely absorb every workflow yet.
  Capacity, per-class reservations, fairness and crash recovery must be
  proven before enabling the full estate.
- Preserve triggers, conditions, permissions, timeouts, concurrency,
  failure cleanup, artefacts and DAG dependencies.

## Gates for every job and dependency

1. Classify the original job, its event and trust boundary.
2. Implement explicit run/job/attempt-scoped JIT admission, immutable trusted
   source hashes, appropriate isolated images and default-off owner controls.
3. Prove exact behaviour including adverse and interrupted scenarios and run
   the complete unreduced test suite at the final combined SHA.
4. For real operational acceptance, independently read back the GitHub job
   steps, log digest, artifacts, source SHA, JIT deregistration, containers and
   provider effects; never replay uncertain external intent blindly.
5. Obtain independent complete-source review and explicit owner merge
   approval. Cut over progressively after live parity proofs.

This inventory does not register runners, dispatch workflows, request
inference, merge pull requests, change production or disable workflows.

## First executable-job migration candidate — not active

The separate clawsweeper-ci-validation-lanes-20261107 worktree stages two
CI jobs (check and sparse-repair-builds) onto unique run-specific JIT
validation labels. Their steps, triggers, build scope and timeouts stay
intact, but checkout credentials are no longer persisted. The reviewer
job remains on its separate secret-bearing lane, and Windows launcher
remains native Windows rather than using a Linux substitute.

The validation policy is default-denied and admits only the exact
workflow/job/event/label identity. It supports normal and stacked PRs,
including forks, plus main-branch pushes and owner manual dispatch.
Pull-request admission verifies both PR head and GitHub synthetic merge
workflow bytes, with exact base/head parent ordering. An unmerged
candidate additionally needs an owner-approved workflow SHA-256 and
run-ID-scoped preview; main's original workflow hash stays pinned.

This is source-staged only: current controls remain disabled. No real
job, runner or external effect has been accepted. Before any cutover,
obtain independent source review and explicit owner approval; reconcile
the existing registration-before-finally cleanup gap; prove a complete
unreduced job in the pinned sandbox, including GH steps, log digest,
runner deregistration and container cleanup. Do not reuse this
credential-free lane for publishing, cloud or commercial actions.
