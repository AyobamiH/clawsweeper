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

### Explicit release-preview containment acceptance

An unmerged release branch cannot inherit the normal `main` operations authority. The
`workflow_dispatch` provision/cleanup preview is therefore **default-denied**, and
requires all of the following in the owner-only controls before its two jobs can
receive their exact JIT labels:

- `enabled: true`, `enabled_roles: ["ops"]`, an **exclusive** single
  `allowed_run_ids` entry, `operations_accepted: false`, and a pinned,
  unchanged `trusted_main_sha`;
- `release_preview.accepted: true`, exact `branch`, signed `head_sha`,
  `tree_sha`, and SHA-256 of the candidate's containment workflow;
- independent live GitHub verification that the run's branch resolves to its
  signed head, the commit has the pinned tree, and the workflow bytes match.

This exception cannot admit dispatch, activity notification, unrelated runs,
fork or PR-head execution, an unsigned/drifted commit, or production-wide
operations. It does not override the ordinary memory, fleet, image, container
ownership, network or capacity restrictions. The approved preview controls
must be restored after the bounded owner acceptance; the JIT and cleanup
receipts must independently establish both lifecycle roles. A queued job,
successful provision alone, or a scanner/model assertion is never acceptance.

## Signed CodeQL branch/PR release evidence

`scripts/ci/verify_codeql_release.py` is the fail-closed, read-only current-source
verifier. Use a precise `--run-id` and `--head-sha`; specify `--pr NUMBER`
only for a `pull_request` run. The CLI requires the owner-local signed runner
receipts by default (no fabricated GitHub check contexts). A successful
`workflow_dispatch` or push scan must have both CodeQL analyses on the
actual `refs/heads/BRANCH` at the exact signed head. A PR scan may instead
upload to GitHub's synthetic `refs/pull/NUMBER/merge` commit, but the current
merge ref **must** match a commit whose first parent is the PR base and whose
second parent is the exact PR head. A PR branch-head analysis is also valid
when backed by the same completed run.

Both languages must be uploaded during the corresponding successful, exactly
named JIT jobs; the verifier also checks runner labels/names, digest-bearing
local receipts, signing and stable source identity. A stale, absent or
ambiguous analysis refuses, rather than borrowing an earlier successful scan.
The existing alert #3 (`js/clear-text-logging`) remains explicitly visible
in every report. Use `--require-alert-fixed` for *post-deployment* closure;
`dismissed` or `open` do not satisfy that gate. Neither a successful older
branch scan nor a prior PR merge scan approves a newer release revision.

Examples (run on the authorised owner machine with GitHub read access):

```bash
python3 scripts/ci/verify_codeql_release.py \
  --run-id 42342492854 \
  --head-sha 04a27178f304520a7be0844dffd45a9efc439a35
python3 scripts/ci/verify_codeql_release.py \
  --run-id 42319278943 \
  --head-sha f799b068053ddc75cfc73d35e56ce33cf96e7e57 --pr 97
```

Do not use this verifier to override independent source review, protected
dispatch, live containment, hermetic automerge E2E, or owner merge approval.

## Portable exact-head source review without paid model calls

A release of up to 80 changed, regular UTF-8 source files can be exported for
a genuinely independent reviewer without consuming inference allowance:

```bash
node scripts/review-release.mjs --export-bundle \
  /absolute/path/to/clean-checked-out-clawsweeper \
  <signed-base-commit> <signed-final-head-commit> \
  /absolute/path/to/new-owner-only-review-bundle.json
```

The command requires a clean exact-head checkout, a direct ancestor base, the
owned GitHub origin, and the source bundle's existing path, size, symlink and
sensitive-filename restrictions. It preserves the complete before/after bytes,
original file modes and exact digest of **every** changed file, including
systemd `.service` and `.timer` units. The bundle is created with owner-only
permissions and cannot overwrite an earlier review artifact.

Every bundle has `reviewStatus: unreviewed` and reports `modelCalls: 0`.
**Export is not a source-review verdict.** An independent reviewer must
examine the entire bundle, cross-file dependencies and security boundaries,
record exact-head findings/coverage, and return a separately attributable
verdict before release. The existing eight-call Workers AI ceiling is unchanged;
this command cannot convert incomplete inference or author-side examination
into approval.

### Isolated automerge acceptance

The full 28-case automerge test may take longer than one hour on a rootless
host. The GitHub job has a 120-minute timeout and performs only a read-only
nested-user-namespace/no-host-socket preflight. It must never change host
kernel sysctls or use a rootful host Docker socket to shorten execution.
The dedicated isolation JIT role remains default-denied until a real
container-in-container provider, network isolation, all-case completion,
receipt and process-cleanup acceptance has been independently demonstrated.

## CodeQL bootstrap repair (6 November 2026)

Controlled [run #42270282058](https://github.com/AyobamiH/clawsweeper/actions/runs/42270282058) accepted the exact SHA on a one-job runner and checked out source, but `github/codeql-action/init@v4` spent the original 20-minute limit downloading CodeQL. GitHub cancelled the `actions` job before analysis and the `javascript-typescript` job remained queued; the incomplete run was cancelled cleanly after independent readback. Neither language was scanned and no analysis was uploaded. The executor recorded a held (not successful) receipt and deregistered its worker.

The corrective release path uses a separately pinned 418,431,999-byte CodeQL 2.27.4 Linux archive, verified against GitHub release SHA-256 `393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d`, and built into a security-only runner image with no build-time network. Its non-root runner must be able to read `/opt/clawsweeper-codeql/codeql-bundle.tar.gz`. The CodeQL init action receives that local archive through its official `tools` input; the job limit is now 35 minutes. The owner-only controls pin the exact security image digest separately from the standard operational image. No host Docker socket, external filesystem, secrets cache or GitHub-hosted execution is introduced.

Use `scripts/ci/fetch-codeql-bundle.sh`, `scripts/ci/repack-codeql-bundle.sh`, `scripts/ci/build-selfhost-codeql-runner.sh` and `scripts/ci/pin-selfhost-codeql-image.py`, in that order. The final step requires disabled admissions, verifies the local image and provenance, and updates the pinned image without enabling execution. Verify the registered exact-SHA job and GitHub code-scanning analysis records for **both** languages before claiming security acceptance. Do not delete or override existing GitHub CodeQL alerts.

The next exact-head acceptance run [42310930131](https://github.com/AyobamiH/clawsweeper/actions/runs/42310930131) confirmed that the local ZIP eliminated the download, but the CodeQL v4 action refused the ZIP with `Could not infer compression method`; it requires `.tar.gz` or `.tar.zst`. Both job outcomes were retained without approval, and the run was cancelled. The offline repack step creates a deterministic GNU tar/gzip archive after checking all upstream ZIP paths, and verifies derived SHA-256 `ec7d95d9a25734ad9553aed70f04bb3394a79b86b9eee44c84fa7f92970a5176`; the image and workflow now use the supported `.tar.gz` path, preserving the official upstream ZIP checksum and the derived archive digest.

## Post-job cleanup reconciliation

A successful GitHub Actions job is not sufficient to mark the owner-operated fleet receipt passing. The initial `actions` CodeQL job uploaded CodeQL analysis `2116213022` at commit `ec1679b7bfd89cd4fd0e1b4a84d4b88832ac71dc`, but the local receipt remained held after a transient Docker cleanup inspection failure. A completed one-job JIT registration may also have already disappeared when GitHub processes the DELETE request. The controller now retries only owned-container inspection and independently checks the complete GitHub runner inventory. A missing runner is accepted as deregistered only after that readback, never from a DELETE error alone.

`scripts/ci/reconcile_selfhosted_receipt.py` performs a separate read-only readback of exact GitHub run/job identity, immutable log SHA-256, both owned container names and all registered runners. It writes an *additional* owner-only reconciliation record. The original held/failure receipt is preserved byte-for-byte, and a failed job cannot be transformed into success by a later cleanup proof. A verified late cleanup may only supplement a successful job with no other outstanding issues. The controller and timer stay isolated from the production fleet and its separate owner-review operation.
