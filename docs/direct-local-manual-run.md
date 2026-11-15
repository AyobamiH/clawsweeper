# Owner-signed direct-local ordinary CI (source-only, not deployed)

The existing signed r7 ClawSweeper fleet is the only permitted execution
controller. GitHub Actions admission is neither a fallback nor a prerequisite.
This design adds an independent, manual OWNER REQUEST SOURCE. It never forges
a GitHub webhook event or updates a PR to generate one.

## v1 request

An exact JSON file, owned by the current UID with mode 0600, has schema
clawsweeper.owner-signed-local-manual-request.v1. It binds the repository,
the current published develop commit, the web host, the existing linux-node24
suite, and **exactly both** ci.yml ordinary job identities. Its purpose is
ordinary-source-validation. It includes a random 128-bit nonce, issued_at
and expires_at Unix seconds, with at most 15 minutes validity.

Sign the exact file bytes using the EXISTING owner SSH signing identity with
namespace clawsweeper-direct-local-manual-v1. The pinned owner public key
must be present in an explicitly owner-maintained allowed-signers file;
principal heryourbarme@live.com is fixed, not taken from the request.

The source-only adapter checks real ssh-keygen -Y verify, immutable request
shape and expiry, fresh read-only GitHub develop ref, exact clean source and
41-workflow/88-job route, host and suite policy, canonical flock and existing
fleet SQLite WAL. It then claims one ordinary suite row with ref local-manual.
Only request digests and redacted provenance, never raw request/signature,
are recorded in the existing observations table. Duplicate signed requests
deduplicate; colliding nonces, webhook/poller jobs and stale refs are held.

## Signed local-manual worker and command-level readback (source-only)

The guarded worker now has a distinct read-only
`verify_manual_queue_provenance` entry point for the existing fleet's
dispatch lock. It permits only one exact owner-signed admission observation,
two fixed ordinary job identities, the pinned suite and source, and rejects
ambiguous/mixed GitHub-webhook provenance or queued-row relabelling. The
separate production `verify_manual_worker_start` entry point performs a fresh
read-only GitHub **develop** source GET and validates the exact 41/88 plan.
Neither function can enqueue, run, replay or publish.

The existing ordinary receipt verifier now also accepts a **separately marked**
`local-manual` execution with exactly those two command results. It checks
the canonical SQLite row, signed-request digest linkage, fixed command list,
per-step exit codes, immutable source/policy, log SHA-256, isolated-container
cleanup and fresh develop ref. It rejects inherited GitHub status objects.
The required signed-controller receipt fields are:
`origin=owner-signed-local-manual`,
`provider_status=suppressed-local-manual` and
`manual_request_sha256=<admitted exact request digest>`.
These do not claim any GitHub provider-accepted check.

**Not yet installed:** r7's worker-side execution guard, current-reference
check, pending/final status-reporting path and interruption recovery still
recognise only authenticated GitHub webhook origin. Before any live manual
claim, a separately signed exact-source controller must call the above
guard under its canonical dispatch lock AND at worker start, re-check develop
on retries, and suppress *all* GitHub status POST/outbox paths for manual
jobs. It must set the above receipt markers only after the normal isolated
container run and verified cleanup, mark local-only reports durably, and
re-run interrupted jobs exclusively through existing lease/lock recovery.
No new worker, queue or scheduler is authorised. This source-only readback
implementation cannot substitute for that controller release.

## Important production boundary

**Current r7 does NOT accept or execute local-manual jobs.** Its existing
worker admission checks only GitHub webhook provenance, while its source
reference check rejects local-manual. The current receipt verifier also
expects event-bound main/pull_request evidence. Do not run this adapter
against the live fleet or insert a queue row until a separately authorised,
signed exact-source controller update implements and tests ALL of:

1. A separate, source-pinned local-manual worker provenance guard using the
   same existing queue; no HMAC spoofing and no generic manual shell runner.
2. Read-only develop HEAD verification at worker start and after interruption;
   no implicit status POST or CircleCI fallback for local-manual.
3. A distinctly named manual-origin receipt readback for both required
   commands, with exact commit/step/policy/log hashes, sandbox cleanup and
   unique observation. Not a GitHub provider-accepted check.
4. Non-reentrant canonical lock discipline, crash recovery, resource ceilings,
   install-file digests, owner identity/permission verification and rollback.
5. A frozen release/manifest signed by the owner and explicitly authorised
   installation, preserving the previous r7 snapshot and untouched other
   repositories.

Once the gate is approved, stage ONE bounded, already source-verified request,
run the existing controller and independently read back real receipts. Never
claim 2/88 accepted from unit tests, a queue claim, or this document.

No PR, GitHub Actions, protected-main mutation, credential export, or production
release is authorised by this source change.

## Byte-pinned r7 controller release candidate (15 November)

`scripts/ci/build_direct_local_manual_controller.py` builds an **offline staging
candidate**, not a running service. It rejects any existing/dirty target and any
base controller other than SHA-256
`30749cfab0eab608a5a5b23bb06a7510ae277c96fb7accb6689ba64433a73297`.
The seven manual libraries are extracted from existing SSH-signed source
`1da545d4c7aa2ed057160b7576daec8da4c46613`, not copied from a
potentially dirty worktree. The replacement controller embeds their
individual file digests and uses a fresh isolated Python subprocess for
manual source/provenance checks, so existing r7 import-cache entries cannot
substitute older library code.

The candidate adds exactly one `manual-claim` entry point with owner-signed
request/signature file arguments. It invokes the existing fleet queue claim
and canonical control.lock, never a second service, Actions workflow,
fabricated HMAC delivery or blind SQLite insert. During the existing
detached-worker lifecycle, source, host, owner-signature provenance and current
published develop ref must pass both dispatch and worker-start checks.
Interrupted jobs continue through the existing lease, state-file and
container-absence recovery. Both required ordinary commands remain mapped to
the unchanged linux-node24 suite. All 86 other classes remain held.

Manual jobs skip pending/final GitHub API status calls. Their terminal
receipts are marked `origin=owner-signed-local-manual` and
`provider_status=suppressed-local-manual` only after exact job identity,
outcome and owned-container cleanup are checked. The existing reporting outbox
can safely reconcile an interrupted final receipt without a provider POST.
Normal non-manual repository status publishing and the old webhook path remain
unchanged.

**Not authorised for live use:** this is a candidate controller + frozen source
package, not a production installation. It still requires a separately signed
and owner-approved r8 install manifest covering all installed file hashes,
single-owner fleet cutover, exclusive lock, rollback to the exact r7 files and
first genuine owner-signed request. Existing r7 integrity, four foreign queued
jobs and protected main/CodeQL rules must remain intact. Only the production
two-job receipt readback can change 0/88 into 2/88.
