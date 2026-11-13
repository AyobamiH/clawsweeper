# Owner-operated CI: bounded running mode

ClawSweeper must be able to execute accepted work without a fresh owner action
for every natural schedule. This is NOT equivalent to default-allow for all
88 job definitions. The correct long-running mode is active and class-scoped.

GitHub remains the schedule, source, job, check and SARIF authority.
The existing local CI fleet remains the exclusive host-capacity owner.
This change adds no duplicate executor, paid fallback, inference spend or
host Docker socket.

## Automatic CodeQL, only for signed protected main

After the release commit is independently reviewed, passes its exact-source
checks, and is integrated into protected main with the required checks:

The existing estate controller may be started using owner-only (0600)
controls containing:
- enabled = true, allow_live_mutations = true;
- operating_mode = trusted-main-codeql-schedule-v1;
- enabled_classes = exactly ["codeql"];
- trusted_main_sha = the signed current protected main SHA;
- operations_accepted = false and model_inference_permitted = false;
- codeql_sarif_accepted = true only after genuine two-language SARIF proof;
- security_image_sha256 = sha256:<approved immutable image digest>;
- exactly one approved job, .github/workflows/codeql.yml#analyze, with
  class = codeql, exact source_sha256, image_sha256 and the matching
  standing_schedule object below.

Example standing_schedule object (placeholders must be replaced and verified):

    {
      "accepted": true,
      "main_sha": "<signed protected main SHA>",
      "source_sha256": "<exact CodeQL workflow SHA256>",
      "image_sha256": "<image digest without sha256 prefix>",
      "languages": ["actions", "javascript-typescript"]
    }

This authorises only natural CodeQL schedules on exact signed main at the
original attempt 1. Every execution must recheck GitHub source signature,
workflow byte digest, protected branch SHA, run/job/attempt identity,
registered JIT runner, image digest, shared-fleet capacity and original
immutable receipt. Completed scans must upload both SARIF analyses and prove
runner deregistration and container cleanup before acceptance.

PR-triggered, manual, retried, unsigned, foreign or changed-source jobs cannot
use the standing grant. Privileged operations, model review, E2E, native Windows
and unrecognised jobs still require their distinct exact approval and execution
contract. The existing one-shot ledger forbids repeated uncertain effects.

Inspect reports standing_codeql_schedule_configured only as a configuration
claim; standing_codeql_schedule_live_verified remains false until an external
job/receipt readback establishes it.

## Two ordinary jobs: existing validation controller, not a new executor

The ordinary jobs, ci.yml/check and ci.yml/sparse-repair-builds, belong to
the already implemented validation controller. Its main-branch policy
already allows recurring ordinary work once source-hashed CI instructions,
isolated read-only tokens, network egress and disposable runtime have real
validation acceptance. The owner controls may then enable only the
validation role against an exact protected main SHA and its workflow digest.
Do not fabricate validation_accepted while the real provider acceptance is 0/2.

Previewing unmerged develop remains exact-run exclusive. It cannot inherit the
default-main standing schedule. Running the general estate controller in
parallel as a second ordinary executor is prohibited.

## Safe release activation boundary

1. Freeze the current signed combined candidate and reconcile the existing
   unreduced eight-stage exact-tree terminal. Complete independent source
   review; do not transfer predecessor verdicts to new bytes.
2. Prove that branch integration will not trigger billable hosted jobs, and
   preserve branch protection and exact-head required CodeQL checks.
3. Publish and merge only the signed, current reviewed source through the
   protected process. An unmerged source tree is not runtime authority.
4. Under the canonical local fleet lock, verify the exact installed source,
   image, manifest, GitHub main SHA and controls, then install one estate
   controller and enable only the verified CodeQL standing mode.
5. Observe a genuine naturally scheduled CodeQL job, both SARIF results, the
   terminal GitHub jobs and independently verified cleanup. Reconcile crash
   or uncertain registration before admitting another job.
6. After one owner-scoped ordinary validation pilot, allow its existing
   controller to admit only source-verified ordinary jobs automatically.
   Expand to other classes only after matching authority, isolation,
   permissions and external-effect recovery evidence.

GitHub's account billing refusal may still block scheduling even if local
compute is free. Do not relabel a provider refusal as a source test failure
or attempt a paid hosted fallback.

This source file defines an executable control policy. It is not an assertion
that main, installed controls, or the 88-job provider acceptance has changed.
