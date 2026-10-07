# Provider-separated repair acceptance status

Recorded: 2026-10-07.

## Provider decision

The controlled acceptance on https://github.com/AyobamiH/wagging-web-wins/pull/91
must use Cloudflare Workers AI for both planning and execution. Codex live
validation and GitHub Codex review are separate evidence lanes. Their
authentication or allowance failures must not be described as Workers AI
credential failures or as proof that Workers AI cannot run.

Do not enable a paid OpenAI API fallback, remove the existing Codex capability,
or change the fleet-wide provider policy as part of this acceptance. A possible
later migration away from direct OpenAI use is a separate decision. Compare
measured total cost per successfully validated repair, including retries and
compute, rather than assuming a cheaper token price proves a cheaper outcome.
No cost comparison has been completed by this work.

## Verified source validation

For source commit `57c15cb9744e3657e3e4699e5d965fea3a1fa93b`, the full `pnpm check`
job completed successfully at 2026-10-07T06:17:42Z:
https://github.com/AyobamiH/clawsweeper/actions/runs/37579978853/job/112657251460

The existing proof records 39 focused tests plus the pinned OpenClaw version
regression. These tests do not establish a complete live Workers AI repair.

## This acceptance attempt

A temporary PR-specific launcher was committed as
`c943a1231f1b0fea733ef0cd4663afa45104ff28`. It was restricted to the owned candidate
branch, the existing repair workflow, Workers AI, and the repair-only fixture.
It failed at a cross-repository access check before dispatching the repair:
https://github.com/AyobamiH/clawsweeper/actions/runs/37582577349

The launcher used a repository-scoped workflow token, while the target and
operational-state repositories are private. No model execution or target-branch
repair was established by that run.

A proposed credential-bearing launcher revision was refused by the editing
tool's safety check and was not applied. A narrower alternative moved the job
checksum and optional exact-head verification into the existing worker's
already-authenticated state path. Its local controlled tests passed 25 checks,
but publication of that execution-related commit was also refused. The proposed
runtime guards are NOT on this PR branch and must not be described as deployed
or active. The saved job's expected-head metadata alone is not proof that those
unpublished guards are running.

The failed temporary launcher was removed in
`49bab7e5dffac70a5afe7ca70583d22eacc2a0b6`. A GitHub comparison against the validated
`57c15cb` source returned no changed files before this documentation was added.
No new credential grant, merge, deployment, paid OpenAI fallback, or global
provider-policy change was applied.

## Remaining evidence

Status: Workers AI live repair acceptance is incomplete.

The existing guarded repair workflow still needs to demonstrate a fresh
Workers AI planning and execution outcome on the controlled fixture. Completion
requires the one-line repair, unchanged test, retained provider and validation
transcripts, the resulting target head, and the actual quality/boundaries/preview
outcomes. Do not manually change the fixture to manufacture provider acceptance.
Leave the fixture unmerged and undeployed.

Codex integration status remains independent. No fresh Codex authentication or
allowance probe was requested in this follow-through. Any future landing of the
ClawSweeper infrastructure PR must still satisfy its current-head review and
normal landing policy; separating providers does not waive review requirements.

## Live Workers AI acceptance run 37596664105

A fresh provider-specific run was dispatched on 2026-10-07 from the repaired
ClawSweeper branch with `inference_policy=workers-ai`, autonomous mode, explicit
execute/fix authority, and merge authority disabled:
https://github.com/AyobamiH/clawsweeper/actions/runs/37596664105

Observed outcome:

- Cloudflare ephemeral planning and execution runners provisioned successfully.
- Planning completed successfully through OpenClaw + Workers AI; Codex setup was
  skipped.
- Execution reached the credited fix-artifact stage with
  `CLAWSWEEPER_ALLOW_EXECUTE=1`, `CLAWSWEEPER_ALLOW_FIX_PR=1`, and
  `CLAWSWEEPER_ALLOW_MERGE=0`.
- The target validation plan was accepted.
- Execution then entered the generic contributor-branch rebase path and failed
  at `rebaseTargetOntoVerifiedBase` with `git exited 1` before any publication.
- PR #91 remained at
  `dd8e24d9f8c5e7dfafa03055cb0059ebef5c878d`; no fixture edit was published.
- Cloudflare repair compute cleanup completed successfully.

The saved acceptance job already required a narrow one-line edit and prohibited
rebasing/replacement work, but those constraints were not enforced through the
executor's final-base synchronization path. The remediation makes the existing
`allow_rebase: false` policy authoritative both before the edit and during the
final pre-publication synchronization, validates `allow_rebase` and
`allow_replacement_pr` as booleans, and retains the same-repository
case-insensitive writeability fix. The saved job also has
`allow_replacement_pr: false` so this acceptance cannot manufacture success via
a replacement branch or PR.

Local validation for this remediation: build:repair passed, 57 focused repair
checks passed, repair lint passed, static/document/format checks passed, and
`git diff --check` passed. A new live Workers AI run is still required before
this document may claim provider-specific end-to-end acceptance.

## Provider-specific acceptance outcome

The controlled Workers AI acceptance is now complete for the repair behavior
claimed by PR #91.

Run: https://github.com/AyobamiH/clawsweeper/actions/runs/37603814544
ClawSweeper source head: `959d29f42185ee681e03dcd77197ca00d8d9d4ef`
Source PR: https://github.com/AyobamiH/wagging-web-wins/pull/91
Repaired source head: `5fba0cb1d2b924f1fe88652a2d59c338bb4b7f78`

Observed evidence:

- Fresh Cloudflare plan and execute containers provisioned successfully.
- Planning completed successfully with the OpenClaw Workers AI route; direct
  OpenAI/Codex setup was skipped for inference.
- Execution used `workersai/@cf/zai-org/glm-5.3`, with execute/fix authority
  enabled and merge authority disabled.
- The saved job enforced `allow_rebase: false` and
  `allow_replacement_pr: false`; execution logged both the skipped initial
  rebase and `final base sync result ... skipped-by-job-policy`.
- OpenClaw lost its final envelope during cleanup, but the guarded recovery
  detected a real working-tree mutation and continued without replaying the
  mutating agent.
- The repaired contributor branch was pushed at
  `5fba0cb1d2b924f1fe88652a2d59c338bb4b7f78`.
- The diff from the pre-repair head is exactly one line in
  `src/lib/clawsweeper-repair-acceptance.ts`:
  `BROKEN` -> `WORKERS_AI_REPAIR_OK`. The paired test is unchanged.
- The retained review artifact reports `status: passed`, no findings, and
  independently identifies the same repaired head and one-line repair.
- Cloudflare repair compute cleanup completed successfully.
- On the repaired head, quality, boundaries, preview, states, browser, routes,
  Cloudflare Pages, and the rerun design check all completed successfully.

The workflow itself reported failure only after publication while reading the
PR status-check rollup through GitHub GraphQL. The target App token was missing
`checks: read` / `statuses: read` in this workflow even though the repository's
existing target-token pattern already used those permissions. This was a
post-publication verification false-negative, not a Workers AI repair failure.
PR #91 remained open and unmerged as required.

Follow-up commit `6c5c63dbaef6c86914d27b7b7fbccab0fa206cc5` adds the missing
check/status read permissions to the planning, execution, and renewed
post-flight target tokens. Static/format checks and 40 focused workflow/executor
tests passed for that permission repair. No merge, deployment, paid OpenAI
fallback, or replacement PR was introduced.
