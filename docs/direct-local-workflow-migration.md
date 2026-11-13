# ClawSweeper: billing-independent, direct-local workflow migration

- Status: **proposed** (source-only bridge; not an installed runner)
- Owner: ClawSweeper / existing `web` local-CI fleet
- Source of truth: `scripts/ci/direct_local_workflow.py`, `config/ci-workflow-estate.json`, existing installed `fleet-policy.json`
- Last verified: signed candidate `ed87c135d6ee21b0c7a28ef7d5113d8fbe130152` on 13 November 2026
- Update when: the candidate is integrated, fleet policy is changed, jobs change, or direct-local acceptance advances

ClawSweeper has **41 workflow sources and 88 job definitions** in its signed release
candidate. Merely replacing `ubuntu-latest` with `self-hosted` does **not**
make GitHub Actions independent: GitHub currently refuses jobs before runner
allocation. The owner will **not pay** to clear the account restriction. Do not
make payment, hosted runners or GitHub Actions admission an operational prerequisite.

The target is one fleet on `web` that owns event ingestion, durable job admission,
dependency order, isolated execution, recovery and exact-source receipt publication.
Use GitHub for source readback, PRs and optional independently verified commit
statuses. Never label an independent local result as a GitHub Actions/CodeQL check.

## Current source mapping

`scripts/ci/direct_local_workflow.py` is a **read-only, no-remote-effects**
migration bridge. It enumerates the existing exact 41/88 manifest, verifies every
workflow's source SHA-256, validates dependency edges and classes, and refuses to
claim execution. It must not become a second CI scheduler.

| Job classes | Count | Direct-local disposition |
| --- | ---: | --- |
| Ordinary validation | 2 | Reuse the **existing** `local-ci` fleet `linux-node24` suite after policy pins the exact released CI workflow source and commit |
| Review | 5 | Hold until isolated review/inference adapter preserves budget and secrets |
| E2E | 2 | Hold until rootless network-isolated local harness and durable evidence are accepted |
| CodeQL | 1 | Hold for independently verified local scanner, SARIF and protected-check policy |
| Native Windows | 1 | Hold for a genuine legally provisioned isolated Windows worker; WSL is not native Windows |
| Privileged / event-driven | 77 | Hold until event-specific, least-privilege local adapters with durable effect ledgers are accepted |

The 77 privileged include an existing external Crabbox-owned runner boundary:
do not transfer that lifecycle into a generic worker merely to inflate counts.
The two ordinary jobs are `.github/workflows/ci.yml#check` and
`.github/workflows/ci.yml#sparse-repair-builds`. The existing local fleet
suite already includes their commands, respectively `pnpm run check` and
`pnpm run test:workflow-sparse-checkout`, **in one bounded execution**.
A successful aggregate suite alone does not establish independent job-level
acceptance without exact receipt and command-level evidence.

The planner checks that the existing fleet has the exact CI workflow SHA-256,
the exact enrolled source commit, the correct host, Node 24, an immutable
container image and both expected step commands. A mismatch holds ordinary
jobs. It never rewrites the owner-installed policy or starts a new worker.

### Read-only proof on `web`

```sh
cd /home/johnh/.local/share/agent-worktrees/clawsweeper/estate-safe-operating-mode-20261113
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/ci/direct_local_workflow.py \
  --fleet-policy /home/johnh/.local/share/local-ci/fleet-policy.json
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s test/ci -p test_direct_local_workflow.py -v
pnpm run check:workflow-estate
```

An output of `mapped_to_existing_fleet=0` on the **unreleased candidate**
is correct while the installed fleet still pins the old `main` workflow.
It is not a failed test and must not be "fixed" by ignoring source identity.
An output of `mapped_to_existing_fleet=2` means a source-pinned **route**
is eligible; it is explicitly **not** proof that either job executed.

## Real cutover gates (no GitHub Actions requirement)

1. Integrate only reviewed, signed, tested source onto the authorised ref.
   Preserve PR #101 ancestry, unmerged worktrees and existing immutable receipts.
2. Verify the exact installed local-fleet code and policy. Bind the released
   workflow digest and exact SHA with an authorised, recoverable update, never
   mutate a shared fleet's controls from an unreviewed PR.
3. Prove a genuine authenticated push/PR webhook and polling fallback, the
   existing SQLite queue's unique job admission, one source-pinned isolated
   execution, individual command results, exact-SHA commit-status readback,
   duplicate delivery handling and restart recovery.
4. Extend the same **single** fleet to per-event job declarations, DAG needs,
   `if`/matrix semantics and output contracts. Treat expressions, workflows
   with secrets and mutable effects as untrusted until mapped to audited
   local adapter types; never evaluate arbitrary YAML shell commands on the host.
5. Activate protected classes incrementally using existing rootless evidence,
   secret segregation, retries, effect fences and native Windows acceptance.
6. Only when real local equivalents are proven, transition GitHub event
   entrypoints away from Actions without removing product workflows or
   silently weakening CodeQL/security branch protection. Billing-locked
   Actions runs may still fail until this source cutover; local progress must
   not wait for them.

Status is **source-planned**, not integrated or operationally accepted. The
installed ordinary local CI route is already live for the older approved
`main` source, but it is not proof of all 88 migrated jobs on the candidate.
Do not create duplicate runners, queue controllers, automations, PRs, or
"successful" status contexts without independently verified exact receipts.

### Signed event preflight (source only)

The direct-local-event-admission module derives exact ordinary job intents from
a bounded, HMAC-SHA256 verified GitHub delivery. It rejects JSON duplicate
keys, stale SHA, forced main pushes, forks, non-owner PRs, draft PRs and all
unrecognised events. The ordinary main push is eligible for check only; an
eligible owner PR is eligible for check and sparse. Workflow dispatch needs
separate actor authority and is held, not silently converted to a push.

The event adapter never executes work or publishes a GitHub required check.
It produces authenticated, source-pinned job intents only.

### Existing-fleet SQLite claim, source-only

`scripts/ci/direct_local_fleet_claim.py` provides the next integration boundary:
an authenticated, exact-SHA ordinary intent can atomically enter the **existing**
`fleet.sqlite3.jobs` table under its **existing** `control.lock`, with
identity-only evidence in its existing `observations` table. It refuses a
foreign owner, missing fleet, unknown queue schema, unpinned revision, changed
signed delivery payload, competing lock, cross-ref suite collision, or
cancelled job replay. An uncertain response is reconciled through the same
unique `(repo, sha, suite, policy)` row. The receiver's own delivery ledger
continues to own webhook receipt deduplication. No new scheduler, queue,
container or credential store is created.

**Not yet installed or accepted:** the caller still needs fresh GitHub ref
readback, an authorised exact-source fleet-policy pin and integration with
the existing webhook/polling controller. Only the fleet controller may execute
the queued job, reconcile interruptions and publish its separately labelled
local CI result. A single suite may represent both ordinary jobs only where
individual required-command execution and successful step receipts are verified;
the suite's aggregate success must not be misreported as two accepted jobs.
Existing protected CodeQL checks remain independent and unaltered.

The no-provider tests use temporary owner-marked SQLite WAL databases and
never write to the installed fleet queue.

### Fresh GitHub ref readback before SQLite claim (source-only)

The direct_local_provider_ref.py module closes the gap between an HMAC-signed
but potentially stale webhook and the actual current remote source identity.
The existing authorised receiver/poller may call
claim_with_fresh_provider_readback after the owner releases the exact
workflow source/policy. It authenticates bounded payload bytes BEFORE any
read-only GitHub request, permits only a main-ref GET or a numbered PR GET,
checks the current SHA and PR trust metadata, then passes the verified SHA to
the existing direct_local_fleet_claim module under the fleet exclusive lock.
Unavailable or changed GET readback is a HOLD. An invalid HMAC, duplicate JSON
key, moved PR head or draft transition cannot enqueue a job. It does not create
a webhook service, dispatch Actions, change fleet policy or execute CI.

The new provider_ref tests use injected GET fixtures, NOT live provider proof.
This code is not installed; genuine acceptance still requires an authorised
exact-source policy pin, natural HMAC delivery, durable queue admission,
isolated execution and independent receipt readback. GitHub application-owned
CodeQL required checks remain separate.


### Event-bound ordinary job receipts (source-only, no provider effect)

`scripts/ci/direct_local_job_receipts.py` is the read-only job-level
acceptance boundary for a completed run of the existing `linux-node24`
suite. It requires an authenticated direct-local delivery observation linked
to the exact fleet job ID, SHA, ref and pinned policy; a completed successful
existing SQLite queue row; an owner-held, non-symlinked terminal receipt;
successful exact checkout, semantic validation, dependency install and both
ordinary commands in the defined order; container cleanup; and a matching
bounded SHA-256 execution log. For a genuine main push it attributes only
`ci.yml#check`; for an eligible owner PR it attributes both ordinary jobs
only when both real commands passed. Historical aggregate successes lacking
an authenticated event claim are deliberately held, not grandfathered in.

It never changes the queue, claims a new job, publishes a GitHub check or
claims that an app-owned CodeQL requirement has been satisfied. A verified
local receipt is distinct from current GitHub provider check acceptance; that
requires a separate authorised readback. The module is not installed in the
fleet and does not by itself advance the 88-definition operational ledger.
