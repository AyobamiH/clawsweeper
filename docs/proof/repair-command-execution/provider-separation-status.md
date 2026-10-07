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
