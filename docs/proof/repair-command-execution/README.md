# Repair-command execution and cleanup replay boundary

## Claim and exercised surface

A repair that has already passed live maintainer or trusted-verdict classification
passes the existing per-run execute/fix flags. It does not grant merge authority
or turn on repository-wide gates. The policy is exercised as executable code,
not just a source-text match.

Only the read-only checkout inspection may retry the exact OpenClaw uncertain
cleanup error. A general agent can have edited files before OpenClaw discards its
final result, so empty output never authorizes replay of a mutating run.

## Reproduction and observed result

Source baseline: `AyobamiH/clawsweeper@6729edf3c9a42a447e7e02aeac4556a38dffefb8`.
The candidate was exercised on Linux with Node 24.21.0 using dependencies from
that same repository's isolated validation artifact. Native child processes and
real temporary files exercised the process boundary; the OpenClaw provider was
controlled and no live model request was made by this proof.

```sh
pnpm run build:all
node --test test/openclaw-process.test.ts \
  test/repair/repair-dispatch-authorization.test.ts \
  test/repair/cluster-workflow-security.test.ts
node --test --test-name-pattern 'agent workflows install pinned CLI releases' \
  test/clawsweeper.test.ts
```

The before-patch regression started a potentially mutating agent **twice** and
lost the first attempt's output. The same scenarios pass after the boundary
change: the general run starts once and remains failed; read-only inspection
starts at most twice with distinct state directories, denies execution tools,
and preserves the original logs plus `.retry-1` logs. Other errors, non-empty
failure output and an insufficient remaining budget do not retry.

The focused run passed 39 tests; the formerly failing pinned-version assertion
passed separately. The pin remains exact at OpenClaw 2026.9.8, not `latest`.
See [results](results.json), [before](replay-regression-red.log),
[after](focused-green.log), and [pin check](pin-regression-green.log).

## Live evidence and limits

The original repair run was
https://github.com/AyobamiH/clawsweeper/actions/runs/37474882406.
It selected Workers AI, received successful provider responses, then failed
with uncertain OpenClaw cleanup. Its execute and fix-PR gates had already been
captured as zero, so it was planning-only. The retry change alone does not prove
that upstream cleanup is fixed for a full mutating repair.

The isolated diagnostic run was
https://github.com/AyobamiH/clawsweeper/actions/runs/37578006116.
Its model-free allowance probe reached `account/rateLimits/read` but received
RPC error -32603 with HTTP 401/expired-auth indicators. No token contents or raw
provider diagnostics were published. This does not prove a depleted quota and
is not a passing live Codex check.

This controlled proof does not establish a completed Workers AI repair of
https://github.com/AyobamiH/wagging-web-wins/pull/91. That fixture must remain
unmerged; a live repair, green target checks and retained evidence are still
required. No production deployment or global policy change is included.

OpenClaw Bay is not affected: the patch changes dispatch inputs and a local
process boundary, not the observer schema, public navigation or mutation controls.
