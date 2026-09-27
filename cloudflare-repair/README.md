# Bounded Cloudflare operator acceptance

This directory provisions the owner's Cloudflare compute for ClawSweeper repair.
Operational changes currently live on `ops/cloudflare-compute-inventory`; they are
not evidence that the default-branch deployment migration is complete.

## Operator PR 10 host fixtures

Manually dispatch `.github/workflows/cloudflare-operator-fixtures.yml` to recreate
the pinned validation environment. It creates one ephemeral Cloudflare Actions
runner, checks out operator head `c50244478afcc394732376f7e28448368ef02bad` at the
absolute path required by its existing adapter tests, and installs locked npm
dependencies. The checked-in registry and systemd configuration are test inputs;
no systemd service is activated.

The private canonical renderer source at commit
`495cac2013bc55533751a09e1bb499119b7de0bf` is retained in the existing private state
repository at fixture commit `2baf6b1b2bca132c22756b9d23469bec177a7677`.
Only the exact source file needed for renderer identity hashing is installed;
this is not a runnable renderer installation or live-provider test. No extra
repository is enrolled in the ClawSweeper App.

The workflow uploads raw test JSON/logs, source hashes and provenance, then
cleans up its container. Cleanup uses a task-specific environment name and
bounded retries for Worker-secret propagation. The workflow is manual-only to
avoid repeating validation when maintenance changes are pushed.

Acceptance run 36338829679: 44/44 adapter tests passed at the pinned operator
head, with a clean worktree. Its original cleanup failed; cleanup run
36339182466 subsequently confirmed both temporary fixture containers stopped.
Artifact 10938660135 retains the test evidence. This is not a repository-wide
suite pass or permission to merge.

## Review routing

The repair workflow sets `CLAWSWEEPER_REVIEW_REPO` to `github.repository` so its
post-repair dispatch targets this installed service rather than the upstream
`openclaw/clawsweeper` default. The operator acceptance dispatch uses one explicit
item with apply disabled. The operational sweep is pinned to Codex/ChatGPT,
blanks API model keys, and retains the shared subscription admission gate.
Standard GitHub-hosted review compute follows the owner's approved substitution;
repair and adapter validation compute stay on Cloudflare.

OpenClaw Bay is unaffected: these changes provision runner/test inputs and route
existing server-side reviews. They introduce no public dashboard contract,
browser GitHub calls, or observer-side mutation controls.
