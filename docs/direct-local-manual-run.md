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
