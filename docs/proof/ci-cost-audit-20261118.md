# CI cost and feedback audit   18 November 2026

## Source and scope

Baseline main: `03d32fb784758d2a3770aaa9721f1212ac061096`.
This audit concerns development CI. Operational sweep, repair, publication,
credentials, runner admission and branch protections are unchanged.

Read [Vincent Koc's article](https://vincent.build/openclaw-ci-cost-reduction/)
and its [versioned workflow](https://github.com/openclaw/openclaw/blob/a7d05c7af04aa17ac57c994da238d0c60f058ca6/.github/workflows/ci.yml).
OpenClaw's sponsored compute values and changing workload are not a cost forecast
for this repository. Its selection planner is not copied.

The read-only receipt auditor is recovered from the existing local commit
`578c845b8` (audit implementation introduced by `8d66d0864` and integrity
correction `9e8f2339c`). Earlier fixture-signing changes and stale policy prose
are not copied. Existing runner migration PRs and their ownership remain separate.

## Measured baseline

43 retained local receipt attempts, 26 revisions: 15 success, 13 failure,
14 error, one interrupted/unverified. 18 logs match their receipt SHA-256 and
byte count; 25 logs are missing. Missing logs do not become passing evidence.

| Recorded stage | Samples | Median seconds | P90 seconds |
| --- | ---: | ---: | ---: |
| Full repository validation | 26 | 926.3 | 1327.5 |
| Frozen dependency install | 41 | 71.8 | 80.2 |
| Sparse checkout smoke | 15 | 12.2 | 14.2 |
| Exact checkout | 42 | 6.1 | 31.0 |
| Workflow semantics | 41 | 2.0 | 2.1 |

These aggregates mix outcomes and historical revisions: diagnostic only.
A SQLite-to-receipt join for 26 first attempts gives an enqueue-to-start median
of approximately 7.2 seconds, P90 2449.1 seconds and maximum 44973.0 seconds.
That interval includes machine/capacity holds; it is not CPU execution time.
Retries are excluded from this queue calculation because the job creation
timestamp is not the later attempt's enqueue time.

Successful exact source `944fd5ad04ba5c01d73b8c3059313469aad3357f`, 16 November:
775.8 seconds end-to-end, 743.5 seconds full validation, four allocated CPUs,
3072 MiB memory. Approximately 3103.2 allocated vCPU-seconds; this is capacity
reservation, not measured utilisation, energy consumption or invoiced cost.
An 18 November attempt on that same source ended in a Docker inspect timeout;
it is an infrastructure error, not a faster successful run.

The latest 100 GitHub workflow records inspected span 17 November 08:26 to
18 November 19:15 UTC: 67 failures and 33 skips. Sampled failed jobs had no
runner and no executed steps. Do not include their short durations as CI gains.
The older successful [PR CI run](https://github.com/AyobamiH/clawsweeper/actions/runs/38717126157)
spent 343 seconds in full validation on a different October revision and runner;
it is not a comparable baseline for current local runs.

Live main protection requires `Analyze (javascript-typescript)` and
`Analyze (actions)`; strict checks and administrator enforcement remain enabled.
The separate local full Linux check, Windows launcher and provider smoke retain
their distinct contracts. A local Linux pass never substitutes for native
Windows or credentialed provider acceptance.

## Priorities and reviewable steps

1. **Reliable measurement:** recover the existing integrity-checking auditor and
   separate exact source/resource/policy cohorts. Report unknown monetary cost
   explicitly. Keep failed and incomplete attempts visible.
2. **Avoid known wasted setup:** fail immediately on pnpm's explicit permanent
   frozen-lockfile errors. Retain three attempts and 10/20-second backoff for
   transient or unclassified failures, frozen installation and optional build.
3. **Reduce infrastructure delay through existing owners:** complete the existing
   local executor/recovery and hosted-runner migration work. Do not duplicate
   controllers, change admission thresholds or remove required checks here.
4. **Profile expensive contracts:** provenance/closeout and ledger shard tests
   dominate retained slow-test observations. Their scenarios protect distinct
   behaviours; do not remove them merely because they are expensive.
5. **Selection remains deferred:** imports alone cannot prove filesystem,
   subprocess, generated-output and workflow dependencies. Keep the complete
   `pnpm run check`, coverage thresholds, timing-sensitive suite and sparse smoke.
   Any later selector must backtest deletions, renames, fixtures and regressions,
   retain mandatory checks and fall back to full validation on uncertainty.

## Reproduce the audit

```sh
node scripts/ci-feedback-audit.mjs --repo AyobamiH/clawsweeper --limit 150
node --test test/ci-feedback-audit.test.ts test/pnpm-install-retry.test.ts
pnpm run check
pnpm run test:workflow-sparse-checkout
```

The audit reads existing private local receipts without changing their outcomes.
Each cohort includes source, suite, executor, image, runtime, policy and resources.
Allocated compute totals include completed success/failure attempts only;
errors may consume additional compute. Billing is unavailable, not zero.

## Install behaviour proof and limits

Claim: a known frozen-lockfile rejection reaches the same failing outcome
without two redundant installations or 30 seconds of retry waits.
Surface: the actual pinned pnpm 11.10.0 CLI, Node 24.22.2, disposable manifest
with a dependency and no lockfile, identical host/environment for both commands.
The old action loop and new helper were each executed once; no package downloads,
provider effects or product operations were required.

| Measurement | Existing loop | Candidate helper |
| --- | ---: | ---: |
| Exit code | 1 | 1 |
| Install attempts | 3 | 1 |
| Elapsed seconds | 32.314 | 0.517 |
| User + system CPU seconds | 2.35 | 0.57 |
| Peak RSS KiB | 169292 | 145236 |

This is one controlled permanent-error case, not a successful-build or fleetwide
speed-up. Transient recovery, exhaustion, unknown errors and interrupted exit
codes are exercised by subprocess tests with simulated pnpm output/backoff.
The real command logs, time output and hashes are retained privately.

OpenClaw Bay is unaffected: no product status/data contract or public observer
behaviour changes. Required check names, test inventory and production code are
unchanged.

Full-suite acceptance remains required. At the verification checkpoint, web's
physical C: free space was 6752993280 bytes (about 6.29 GiB), below its existing
6.5 GiB admission requirement; Ayobami-Dev's WSL startup returned
`Wsl/Service/CreateInstance/E_FAIL`. These are holds, not passing results.
No paid fallback, threshold reduction, merge or deployment is authorised by this
document. Complete current-source full checks and review before release.

Additional isolated proof used the existing digest-pinned local-container image,
one CPU, 512 MiB RAM, read-only root, no network, no host socket and 64 MiB
bounded temporary storage. The same real pnpm failure took 32.166 seconds
before and 0.586 seconds after; CPU time was 2.160 versus 0.581 seconds.
Both returned exit 1, with three versus one attempts, and container absence was
verified after cleanup. Two initial harness failures (missing external time
utility and non-executable temporary mount) were retained; neither is counted
as a product success. The final harness used Bash timing and invoked the pinned
pnpm entrypoint directly without changing isolation permissions.

The corrected precommit Codex review reported no actionable defects. Its
sandbox could not execute Bash subprocess tests; those six focused tests passed
separately on the authorised host. Documentation, formatting, focused lint,
Bash syntax and CI actionlint checks passed. Full-suite and release acceptance
remain open. Signed commit creation timed out; the recorded active signing
socket was subsequently found absent. The source is staged, not committed,
published, merged or deployed.
