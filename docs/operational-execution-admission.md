# Operational execution admission (initial inventory)

ClawSweeper's owner-controlled local CI runs **development validation**. It does not execute the GitHub-hosted operational workflows in `.github/workflows/`. GitHub's account billing hold currently prevents many scheduled jobs from starting; a successful local `local-ci/linux-node24` status does not recover those effects.

The read-only inventory tool below classifies triggers, runner selection, potential external effects and secret references from the exact checkout. It is deliberately conservative: **every workflow and job remains unadmitted**. Static classification is not an execution plan or a credential grant.

The inventory requires Python 3 and PyYAML (`python3 -m pip show PyYAML`). It does not require credentials or network access.

```bash
python3 scripts/operational-admission-inventory.py --out /tmp/clawsweeper-operational-inventory.json
python3 -m unittest discover -s test/operational -p 'test_*.py'
```

Before admitting any operational job to the existing local executor, separately verify: its GitHub trigger/event semantics, exact-source binding, required secrets and permissions, outbound provider effects, Worker/R2 canonical authority, lease ownership, replay safety, retries and crash recovery, resource limits, independent receipts, and rollback. Maintain review/apply separation and do not close items or publish anything as part of inventory. GitHub Actions jobs are not interchangeable with the local development CI test suite.

**First pilot candidate:** a strictly read-only observation of the scheduled dead-letter reconciliation job, with no GitHub mutation or queue replay. Admission and execution require a separately reviewed contract and real proof. This inventory does not enable any runner, workflow, schedule, fallback or publication.

The operational automation work does not affect OpenClaw Bay until a verified public status contract changes; Bay remains observer-only.

## Live read-only observer

`scripts/operational-observer.py` records the current `main` SHA, the exact dead-letter workflow content digest and the three latest GitHub workflow-run summaries. A non-blocking process lock prevents concurrent runs, SQLite uniqueness prevents duplicate receipts and an atomic, fsynced JSON receipt makes interrupted writes recoverable. It checks remote `main` against the local checkout before any observation. When the checkout is stale, it fails closed instead of silently claiming current-head evidence. It does not acquire production queue leases, consume dead letters, publish results or write GitHub status.

The first live receipt is under `~/.local/share/local-ci/clawsweeper-operational-observer/receipts/`. The observer requires the owner's existing `gh` authentication, with GitHub metadata read access only. Its execution is independent of the development CI controller and must not be counted as a CI success.

A future mutation-capable local operational executor needs a separately implemented, reviewed and accepted contract for each workflow. No operational job is admitted by this observer.

## Full operational cutover audit (4 November 2026)

`python3 scripts/operational-cutover-audit.py --repo . --out /tmp/clawsweeper-cutover-audit.json` produces an exact-source job-by-job migration contract, including dependencies and potential GitHub App token, artifact, queue lease and write-permission requirements. The initial main revision has 86 jobs across 40 workflows; 44 jobs reference GitHub App token actions, 35 reference artifact actions, 39 contain queue/lease markers and 10 declare write permissions. These categories overlap and static markers are not a complete security review.

All jobs remain `not_admitted`. Before cutover, each job must prove its event mapping, scoped credentials, canonical queue ownership, external effects and readback. Do not disable GitHub workflows on the strength of a passing development CI check or a read-only observer receipt.
