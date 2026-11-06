# GitHub workflow execution migration — November 2026

GitHub remains the source, event, check, security alert and audit authority. Account-level billing restrictions prevent GitHub-hosted `ubuntu-latest` jobs from starting; the failures have zero executed steps. **Do not mark those checks successful.**

This migration reuses the authorised `web` one-job, GitHub JIT self-hosted runner pattern. It intentionally does not reuse personal runner workspaces or mount the host's Docker socket in untrusted jobs. Each admitted job receives a unique run-bound label and a fresh disposable container. The existing owner fleet keeps its own locking, queues and status reports. Deployment, PR merging, GitHub check bypasses and Workers AI spend are not authorised by this migration.

The local executor must be installed, enabled and independently proven before the migrated workflows are considered operational. No runners registered means jobs remain queued, **not** passed. The executor defaults to disabled and holds on missing evidence or conflicting ownership.

Workflow groups:

- **CodeQL:** preserve both `actions` and `javascript-typescript` analyses and `security-events: write`, using a per-run CodeQL JIT label. A real CodeQL analysis and provider readback remain release gates. Existing alert #3 (`js/clear-text-logging`) is not resolved by runner migration.
- **Dispatch and activity:** preserve event callbacks, GitHub App permissions, dispatch semantics and deduplication, using a distinct operational JIT label. Do not execute untrusted PR source with privileged credentials.
- **Containment:** preserve the separate disposable Cloudflare test workers. Only the owner control-plane provisioning and cleanup run through an operational JIT runner. A failed provision never falls back to a different test environment.
- **Automerge E2E:** preserve the full Docker-backed hermetic test rather than passing a reduced smoke. The isolated Docker-capable runner is a **held prerequisite**; never bind the host Docker socket or use privileged Docker just to get a green check.

The existing five-minute local CI timer remains independent; avoid a competing change to the shared fleet while its separate maintenance is active. Each new runner uses an immutable, locally built image with a verified GitHub CLI binary, Linux cgroup limits, non-privileged worker, private-address egress restrictions and terminal GitHub job readback. A single executable is admitted at a time. Uncertain registration and crashes must not replay effects without reconciliation.

A job result is accepted only when its head SHA, run and attempt, job ID, JIT runner identity, GitHub conclusion and local digest-bearing receipt match. A queue entry or successful webhook alone is not completion. Do not merge this migration until a controlled real job in each execution class is verified and the owner explicitly approves.
