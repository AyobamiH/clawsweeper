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

## Historical pre-acceptance snapshot

At this point in the investigation, Workers AI live repair acceptance was still
incomplete. The guarded workflow had not yet demonstrated the one-line repair,
unchanged test, retained provider/validation transcripts, resulting target head,
or target CI outcomes.

The later sections below supersede this snapshot with the completed acceptance
run and its follow-up fixes. Codex integration remains an independent evidence
lane; provider separation does not waive normal landing-policy requirements.

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

## ChatGPT/Codex allowance smoke outcome

The ChatGPT/Codex allowance lane was investigated independently from the
Workers AI repair path.

The local Codex 0.157.1 session on the authorised `web` host reported
`Logged in using ChatGPT` and successfully answered the native
`account/rateLimits/read` request. The current local allowance observation was
82% remaining in the active seven-day window, so the earlier CI failure was not
allowance exhaustion.

The failing GitHub Actions job instead used the repository secret
`CLAWSWEEPER_CODEX_AUTH_JSON`, last updated on 2026-09-26. That stored copy could
be recognised as ChatGPT-backed login material but could not successfully
complete the allowance read in CI. The allowance reader previously collapsed
that condition into a generic process failure, which made the entire CI workflow
red even though build, repair, Workers AI, containment and security lanes were
healthy.

Commit `39d9fbc5b3f52d69e56b5d5ab26aa4a5082c0076` changes the allowance smoke to
classify provider health instead of conflating provider unavailability with core
CI failure. A successful allowance read records `available=true`; an unavailable
or stale ChatGPT/Codex provider records `available=false` with a bounded reason,
skips live Codex inference, and runs the refusal-only proof. Actual Codex work
continues to fail closed when the provider is unavailable.

Validation on that head:

- Hosted native review scan smoke: success.
- Windows Codex launcher: success.
- sparse repair build smoke: success.
- `pnpm check`: success.
- repair containment smoke: success.
- CodeQL: success.
- automerge e2e: success.

The local healthy ChatGPT credential was not copied into GitHub Actions during
this work because the execution safety boundary blocked direct transfer of the
live credential. No credential value was printed or exposed. Restoring hosted
live Codex review requires a separate safe refresh of the GitHub secret, but
that provider availability no longer blocks Workers AI repairs or core CI.

## Final landing hardening: no-rebase invariant

The final GitHub Codex review of `8007fe419ee78fccbc7cc3e371ac831d6b368dc2`
identified one remaining P1 policy gap: `allow_rebase: false` was authoritative
for the initial edit pass but was not yet propagated into every writable
validation/review fix pass, and publication did not independently reject a
rewritten source ancestry.

Commit `4bc2b21aaf360b7e93d77b978b4d15edd56c9dab` closes that gap at three
layers:

- `allowRebase` is propagated into validation-fix and review-fix agents, whose
  no-rebase prompts explicitly forbid rebase, merge, reset, cherry-pick and
  other HEAD/ancestry rewrites;
- every writable pass enforces a runtime invariant: when rebasing is forbidden,
  HEAD must remain unchanged during the agent pass and no rebase/merge or
  unresolved merge state may remain;
- immediately before publication, the original source head must still be an
  ancestor of the accepted repair head. A rewritten ancestry is rejected even
  if some other path were to bypass prompt guidance.

Focused repair/policy/prompt/OpenClaw validation passed 72/72 before commit. A
fresh ChatGPT-backed local Codex review of the uncommitted fix reported no
actionable correctness issue and specifically confirmed that the no-rebase
invariant is enforced across edit, validation-fix, review-fix, pre-checkpoint
and publication paths.

Exact-head GitHub validation for `4bc2b21aaf360b7e93d77b978b4d15edd56c9dab`
then passed:

- CI, including Hosted native review scan smoke, `pnpm check`, sparse repair
  build smoke and Windows Codex launcher;
- repair containment smoke, including both containment samples and Cloudflare
  cleanup;
- CodeQL;
- automerge e2e production hermetic scenarios.

No merge, deploy, paid OpenAI fallback, replacement PR, or broadened repair
authority is introduced by this hardening. OpenClaw Bay remains unaffected.
