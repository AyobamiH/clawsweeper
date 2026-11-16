# Automatic pre-model CI triage

**Status: proposed scoped runtime activation.** This source integrates triage into the existing GitHub activity notifier; it does not activate a production service, replace CI admission or grant permission to merge, retry jobs, publish or deploy.

## Execution path

`runGithubActivityNotifier` handles a failed workflow-run event, obtains fresh authenticated GitHub run/attempt/job metadata, and claims a stable local decision before any agent handoff. If the complete failed-run job inventory establishes no assigned runner and no executed job steps, the notifier writes a deterministic receipt and does not call the agent. Otherwise it retains the existing OpenClaw hook. Unavailable evidence is not a deterministic result. A stale run/attempt/source is held rather than investigated under the wrong identity.

The result means **no steps executed in these jobs**. It does not identify billing or scheduler root cause, prove successful source tests, or approve a release. Missing runner fields, malformed steps, partial pagination and conflicting job identities cannot qualify. A mixed run containing executed jobs remains an investigation.

## Activation contract

**Security remediation remains source-only; do not activate this candidate.** Manifest schema v3 covers the bounded static NodeNext ESM import closure of the seven triage entrypoints, including `dist/repair/config.js`, `dist/repair/json-types.js` and `dist/repair/lib.js`. Dynamic imports, unlisted dependencies, unsupported package resolution and unsafe paths fail closed. The resolver also rejects syntactically valid but noncanonical static imports/re-exports (including comment-separated, adjacent-token, multiline and same-line declarations) rather than silently leaving a dependency unhashed; both the runtime and builtins-only bootstrap implement the same refusal. The builtins-only bootstrap verifies the closure before any observer/notifier application import. The manifest issuer now verifies a clean exact Git commit, rebuilds a fresh Git archive offline using the locked owner-selected TypeScript toolchain, compares emitted JavaScript bytes against the entire runtime closure and records source/toolchain/build digests. It cannot issue a manifest for stale or tampered `dist` even if tracked source remains clean. Independent source review, full local CI and authorised release remain outstanding.

Use a clean, signed checkout and an owner-controlled offline toolchain whose TypeScript version matches `pnpm-lock.yaml`. The issuer rebuilds from `git archive HEAD`, with no dependency fetching or imported application code before byte comparison. Manifest issuance discovers the complete closure using the same builtins-only, side-effect-free bootstrap resolver; it never imports compiled runtime/application modules to generate the manifest. An adversarial fixture includes executable top-level application code and proves that issuance succeeds without executing it. When the checkout itself has no `node_modules`, point `CLAWSWEEPER_CI_TRIAGE_TOOLCHAIN_ROOT` to the trusted, already-installed repository root containing the compatible `node_modules`. **Require** `CLAWSWEEPER_CI_TRIAGE_NATIVE_COMPILER_SHA256` from the separately signed, owner-controlled toolchain/release policy before issuing the manifest. The issuer refuses missing, malformed or mismatched pins before executing the native compiler. Do not derive this trusted value from the mutable binary at manifest-issuance time; compiler version and an after-the-fact digest are not independent trust anchors. Preserve compiler and lockfile hashes in the private build receipt. Manifest issuance is **local reproducibility evidence, not independent approval or production deployment**.

```bash
install -d -m 700 "$HOME/.local/state/clawsweeper-ci-triage"
node scripts/analysis/ci-triage-manifest.mjs \
  "$HOME/.local/state/clawsweeper-ci-triage/runtime.json"
export CLAWSWEEPER_CI_TRIAGE_SOURCE_SHA="$(git rev-parse HEAD)"
export CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST="$HOME/.local/state/clawsweeper-ci-triage/runtime.json"
# Set this independently in the signed release policy to the issuer's
# runtimeManifestSha256. Do NOT recompute it from a mutable file at launch.
export CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256="<signed-release-pinned-64-hex>"
export CLAWSWEEPER_CI_TRIAGE_STATE_DIR="$HOME/.local/state/clawsweeper-ci-triage"
export CLAWSWEEPER_CI_TRIAGE_REPOSITORIES="AyobamiH/clawsweeper"
export CLAWSWEEPER_CI_TRIAGE_ENABLED=1
```

The existing notification workflow uses its approved `GH_TOKEN`/`GITHUB_TOKEN` for read-only GitHub API calls. Existing OpenClaw hook configuration is unchanged and remains necessary for uncertain cases; do not introduce a new provider or expose credentials in reports. Without a configured hook, an uncertain event is durably held and reports failure, not completion. Restoring the existing hook can resume only a hold with **zero dispatch attempts**.

The triage-enabled notifier and observer now have a dedicated builtins-only
pre-import bootstrap. The trusted release launcher must independently pin its
CLAWSWEEPER_CI_TRIAGE_BOOTSTRAP_SHA256, CLAWSWEEPER_CI_TRIAGE_RUNTIME_MANIFEST_SHA256,
and signed source revision. These pins must be bound to the same signed release
by the trusted launcher; computing either digest from a mutable file at
startup is not a trust guarantee. A rewritten manifest with internally
consistent source-build and runtime hashes is now refused before loading code.
The bootstrap refuses missing/stale manifests and checks every compiled ESM
dependency before importing notifier/observer application code. After verification,
a synchronous builtins-only Node module-load fence supplies only the previously
hashed JavaScript bytes; unlisted ESM, CommonJS and other module resolutions
are rejected before their contents execute, even if unusual syntax evades
static import discovery. This is defence in depth, not permission for dynamic
package resolution. The generic notification route with triage disabled is
preserved unchanged. The normal `github-activity` notifier invocation and all
three package entrypoints now use `scripts/analysis/ci-triage-launch.sh`:
disabled triage executes the existing notifier unchanged; enabled triage and
the explicitly verified notifier/observer routes enter the builtins-only
pre-import bootstrap. Unexpected flag values refuse. The workflow invokes
the shell entry directly rather than first launching `pnpm`, as Node processes
`NODE_OPTIONS=--import/--require` **before** loading any JavaScript bootstrap.
The Linux trusted shell entry executes root-managed `/usr/bin/node` (not a
PATH-resolved `node`) and unsets `NODE_OPTIONS` before Node startup.
Production release policy must pin and attest that absolute Node binary,
the shell, bootstrap and manifest source identities together. Merely
checking this value inside a Node module would be too late. The builtins-only
bootstrap also calls the Linux system Git binary by absolute path during
source verification, with fixed `PATH`, disabled external diff/textconv and
filesystem-monitor hooks, and no inherited global/system Git configuration.
The offline build/manifest issuer likewise uses absolute system Git and tar
with a restricted environment; the signed native compiler receives no caller
PATH/HOME. Negative source-build and shell-launch tests place executable hostile
`git`, `tar` and `node` shims first on PATH and require zero execution.
Otherwise an attacker-controlled `git` executable in inherited `PATH` could
perform an effect **before** the manifest and compiled-runtime checks complete.
The pre-import regression includes an executable hostile Git shim and checks
that it never runs while the normal observer still succeeds. The signed release
must bind the shell entry, bootstrap identity, runtime manifest digest and
reviewed source SHA together; source-only tests do not grant that authority.
Commands that launch via an upstream Node-based package manager may already
execute a preload before the shell entry is reached and are not the trusted
production launch boundary. This remains source-only until independent build
provenance and operator release approval.

The optional owner-local observer uses existing authenticated `gh api` GET access and invokes the **same notifier**, rather than selecting a skill or inventing an independent classifier:

```bash
/bin/sh scripts/analysis/ci-triage-launch.sh observer --watch-seconds 300 --interval-seconds 30
```

Transient authenticated GET transport failures receive at most one immediate read retry. A timed observation continues after a held collection-read cycle, without retrying any agent POST. Source, policy, manifest and storage faults still stop immediately. A window ending with an unresolved read failure exits nonzero; the summary counts held cycles explicitly.

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
