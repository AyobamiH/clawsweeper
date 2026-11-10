# Measurement-first agent inference (opt-in, isolated)

**Status:** development-only measurement instrumentation. No inference provider change, production activation, CI admission change or cost-reduction claim is authorised by this code.

## Coverage

- The agent runner records bounded metadata for agent invocations (review, repair, assist and unspecified) only when the parent process explicitly opts in.
- The metrics module produces schema clawsweeper.inference-measurement.v1 as JSONL in an existing private local directory. It is not the commercial inference evidence or a billing receipt.
- The offline inventory command rejects unknown fields, malformed data, large files and embedded free text.
- The direct cluster selector is also measured when opt-in is enabled, including actual token usage when the OpenAI Responses API returns structured usage. Commercial generation/review and Post-Once are **not measured** by this first change.

The measurement records process outcomes, latency, optional provider-sourced token counts and source revision when available. It does not collect prompts, model responses, error strings, access tokens, credentials, repository content, project labels, GitHub URLs or arbitrary metadata. A successful process exit is **not** independently verified task completion. Tokens missing from a structured provider response remain null. Costs and verified completions remain null.

## Local-only activation procedure (not performed)

Create a private directory on the authorised host independently of running agents:

    install -d -m 700 "$HOME/.local/state/clawsweeper-inference"
    export CLAWSWEEPER_INFERENCE_METRICS_FILE="$HOME/.local/state/clawsweeper-inference/inference.jsonl"

Start _only_ a specifically authorised, bounded ClawSweeper process with this environment. Do not set the flag globally or alter production systemd units, CI workers, OpenClaw gateway, Post-Once or release controls. The recorder requires an absolute JSONL path, a private mode 0700 parent and a regular mode 0600 file with no destination symlinks. Unsafe destinations are refused without affecting model execution. File size is capped below 8 MiB. Rotate evidence privately before it fills.

Read the evidence locally:

    node scripts/analysis/decision-inventory.mjs "$CLAWSWEEPER_INFERENCE_METRICS_FILE"

The analysis reports invocation counts, latency and provider-token metadata coverage. Cost savings remain unproven until provider billing and independently verified task outcomes are joined to the same exact source and invocation. Codex subscription admission must not be conflated with API token billing.

## Safety and acceptance

- Default off; no new API key, model provider, fallback, routing change or inference request.
- No change to commercial evidence schema tw.inference-evidence.v1.
- No change to CI fleet, webhook relay, runner ownership, protected admission, release controls or production deployment.
- Private sidecar only; no OpenClaw Bay or dashboard contract change.
- Controlled behaviour proof: existing agent-runner regression test invokes a fake local Codex process through its normal input scanner and verifies a private, content-free metric and unchanged return result.
- Adversarial checks cover symlinks, world-readable files/directories, malformed records, fabricated billing and false task-completion claims.
- Next decision: whether an observed task type merits isolated shadow comparison. Counts alone never trigger production changes.

## Candidate provenance

Initial branch: agent/inference-measurement-20261109. Base: ClawSweeper develop at 76a20378c8d7efd5e63f26345f8d4c7904f61cc9. Historical tests do not prove deployment. Validate and review the final committed SHA independently before publishing or merging.
