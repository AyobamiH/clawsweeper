# Automatic pre-model CI triage

**Status: proposed scoped runtime activation.** This source integrates triage into the existing GitHub activity notifier; it does not activate a production service, replace CI admission or grant permission to merge, retry jobs, publish or deploy.

## Execution path

`runGithubActivityNotifier` handles a failed workflow-run event, obtains fresh authenticated GitHub run/attempt/job metadata, and claims a stable local decision before any agent handoff. If the complete failed-run job inventory establishes no assigned runner and no executed job steps, the notifier writes a deterministic receipt and does not call the agent. Otherwise it retains the existing OpenClaw hook. Unavailable evidence is not a deterministic result. A stale run/attempt/source is held rather than investigated under the wrong identity.

The result means **no steps executed in these jobs**. It does not identify billing or scheduler root cause, prove successful source tests, or approve a release. Missing runner fields, malformed steps, partial pagination and conflicting job identities cannot qualify. A mixed run containing executed jobs remains an investigation.

## Activation contract

Use a clean, committed checkout built with its pinned dependencies. The operator creates a new private manifest that binds the exact implementation commit and compiled runtime bytes. Changed code, a stale build, or an altered manifest fails closed.

```bash
install -d -m 700 "$HOME/.local/state/clawsweeper-ci-triage"
node scripts/analysis/ci-triage-manifest.mjs \
  "$HOME/.local/state/clawsweeper-ci-triage/runtime.json"
export CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA="$(git rev-parse HEAD)"
export CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST="$HOME/.local/state/clawsweeper-ci-triage/runtime.json"
export CLAWSWEEPER_CI_TRIAGE_STATE_DIR="$HOME/.local/state/clawsweeper-ci-triage"
export CLAWSWEEPER_CI_TRIAGE_REPOSITORIES="AyobamiH/clawsweeper"
export CLAWSWEEPER_CI_TRIAGE_ENABLED=1
```

The existing notification workflow uses its approved `GH_TOKEN`/`GITHUB_TOKEN` for read-only GitHub API calls. Existing OpenClaw hook configuration is unchanged and remains necessary for uncertain cases; do not introduce a new provider or expose credentials in reports. Without a configured hook, an uncertain event is durably held and reports failure, not completion. Restoring the existing hook can resume only a hold with **zero dispatch attempts**.

The optional owner-local observer uses existing authenticated `gh api` GET access and invokes the **same notifier**, rather than selecting a skill or inventing an independent classifier:

```bash
node dist/repair/observe-ci-triage.js --watch-seconds 300 --interval-seconds 30
```

The initial watermark is persisted before observation; default behaviour only observes failures completed/updated after activation. `--catch-up-minutes` is an explicit historical sample and must never be presented as a fresh natural event. Collection is bounded to the latest 100 completed runs and at most five new decisions per iteration by default; this is a sample, not exhaustive backlog coverage. The observer never dispatches workflows. No timer or second CI fleet is installed by this command.

## Durability and rollback

The private SQLite ledger uses full-synchronous transactions and a stable hash of repository, workflow run ID, run attempt and source commit. Minimal receipts include implementation SHA, authenticated evidence digest, job IDs, route, timestamps, latency and dispatch count. Prompts, credentials and arbitrary provider error text are excluded.

Duplicate/concurrent delivery gets the existing decision. A process killed during read-only observation can reclaim its expired lease. Before an external agent POST, a durable intent is committed. A lost response or crash thereafter is held as uncertain and is **not automatically replayed**. This is conservative at-most-once effect initiation, not a fabricated exactly-once completion guarantee. Only a genuine accepted hook run ID is recorded as forwarded; forwarding does not prove model completion or a verified engineering outcome.

Set `CLAWSWEEPER_CI_TRIAGE_ENABLED=0` to roll back the optimisation **while preserving the state directory and source manifest**. Previously accepted or in-flight identities cannot be repeated; new identities use the existing hook. Do not delete the ledger to bypass uncertain-effect fencing. Removing the entire state configuration is a legacy-path migration and requires draining/reconciling existing decisions first.

The ledger refuses unsafe paths and caps retained decisions at 20,000. Capacity exhaustion is an explicit hold. Keep integrity-checked evidence before any operator-managed retirement; this change does not silently prune old deduplication keys.

## Measurement

The generic agent runner now captures structured Codex turn usage and OpenClaw provider metadata when supplied. `inferenceDecisionId` selects metric schema v2 with a stable decision ID and separately reported cached-input count; existing schema v1 remains accepted unchanged. Unknown model/usage/cost fields remain unknown. Hook acceptance does not reveal token usage, so CI fallback receipts retain null counters unless a separately correlated provider result is available. Deterministic receipts explicitly record zero inference calls and tokens.

The bounded Codex JSONL parser intentionally refuses oversized output. Steerable app-server usage without a supported structured result remains unavailable rather than estimated. Cached tokens are not added to input totals or converted into money. Neither an exit code nor a hook run ID verifies completed customer work.

## Acceptance and proof

The proof contract is the real notifier plus local HTTP GitHub/hook boundaries, private SQLite and independently read receipts. Focused tests include authentic-shape zero-step evidence, executed failures, complete pagination, malformed/missing fields, source/attempt drift, concurrent duplicates, process-kill recovery, lost HTTP responses, rollback and configuration restoration. Runtime manifest tests reject stale compiled output and dirty source. Run:

```bash
node --test test/repair/ci-triage.test.ts test/repair/ci-triage-http.test.ts test/repair/ci-triage-runtime.test.ts
```

Local HTTP fixtures are controlled behavioural evidence, **not live provider or naturally arriving event evidence**. Full acceptance also requires source review, repository-native validation, a real automatically observed event after the watermark, provider readback, and verification of the existing agent route. The OpenClaw Bay contract is unaffected: all new receipts are host-private; no public UI, control, browser GitHub call or publication action is added.
