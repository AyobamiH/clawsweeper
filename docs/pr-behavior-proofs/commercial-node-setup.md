# Commercial Node setup proof

Claim: commercial jobs can initialise their pinned Node runtime on a clean runner
without a preinstalled pnpm executable or access to a package cache service.

Observed failure: hosted run 38714897194 at baseline
316e0ad825b2f261f8cab8c199e1ea99411b3e69 failed in prepare and report-failure
because setup-node automatically selected pnpm caching before pnpm existed.
No customer code or model invocation ran.

Proof contract: run the actual pinned setup-node action bundle in disposable
Docker local-container instances with the real repository package metadata,
Node 24.18.1, no pnpm executable, no credentials and networking disabled.
The default cache input must reproduce the missing-pnpm failure; the configured
false input must complete successfully. The image supplies the same Node version,
so binary downloading is outside this fixture. Record action SHA, image identity,
container leases, exit codes and logs. Run workflow regression and pnpm check.
Crabbox CLI is unavailable on this host; the fixture uses the same Docker
local-container boundary directly and does not claim a Crabbox invocation.

Command: node scripts/commercial/prove-node-setup.mjs /absolute/pinned/setup-node

The implementing assistant examines the exact pre-commit and committed delta
under the scoped commercial-release policy. This is not an independent audit.
OpenClaw Bay is unaffected: no observer, queue or dashboard contract changes.
No live model, resource provisioning, payment, PR publication or full delivery
is established by this bootstrap proof; hosted acceptance remains required.

## Observed result — 15 October 2026

The actual setup-node bundle at a0853c24544627f65ddf259abe73b1d18a591444
reproduced the missing-pnpm failure with its default cache input (exit 1).
The same bundle, metadata and image passed with caching explicitly disabled
(exit 0). All six jobs use that input. Image identity:
sha256:c825877c1c5a39d12235596e2c89f3892618ac44e99d630660a75837fca8a02f.
Action bundle SHA-256:
60311b126a217871573d84ec2ff784be83b71d33e15aab7734243111b455eb8a.

Both cases used network-disabled, read-only, credential-free containers and
zero model turns. Evidence is reproduced under .artifacts/node-setup-proof/.
The first harness attempt used the image's shell entrypoint, which stripped
hyphenated GitHub input environment names. The corrected harness directly
executes Node, matching the action runner's execution model.

The hosted failure automatically reached a settled refund: Stripe refund
re_3UQlAZGbPfXt7ec51ZWHbc12 succeeded for GBP 1.00. This demonstrates the
failed-run refund path, not successful customer delivery.
