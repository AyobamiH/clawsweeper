# Cloudflare repair compute

ClawSweeper repair jobs provision two uniquely labelled ephemeral Cloudflare
runners: one for planning, one for execution. Standard GitHub-hosted jobs own
API orchestration, review, deterministic publication and CI. No workflow selects
Blacksmith. Repair and review use ChatGPT subscription authentication, with API
model credentials removed and the shared allowance gate retained.

## Lifecycle and authority

`repair-cluster-worker.yml` deduplicates its command receipt before provisioning.
The shared `cloudflare-repair-compute` concurrency group serializes repair,
provisioning and fixture workflows against the two-container account limit.
The provisioning action derives runner identities from repository/run/attempt;
cleanup can recover both names even when provisioning fails before outputs.
Cleanup runs after planning and execution, including failed or skipped jobs,
and removes surviving runner registrations. A four-hour process timeout and
container inactivity limit bound abandoned runners if GitHub cannot run cleanup.

`runner` and `execution_runner` remain accepted for caller compatibility, but
repair jobs always use their provisioned Cloudflare identities. Requeue depth is
zero so an exhausted or finished ephemeral runner does not receive duplicate
repair attempts. Existing execution and merge gates are unchanged; this workflow
does not toggle repository variables or authorise actions on target repositories.
The post-repair review dispatch explicitly targets this service repository.

The authenticated Worker supports only runner start/stop and containment proof.
It has no arbitrary command endpoint or historical debug/log extraction route.
JIT credentials are masked before use, passed in request files, and removed from
the runner filesystem before execution. Do not print runner payloads or raw
runner logs. Workflow start/stop is serialized because the protected control
credential rotates during each lifecycle phase.

## Deployment and behaviour proof

Run `cloudflare-repair-provision.yml` to build/deploy the pinned image and Worker,
execute the real containment preflight on both Cloudflare runner roles, retain
source/runner-bound artifacts, and destroy both runners. The narrow claim is:
GitHub orchestration can provision Cloudflare compute, execute enforced Linux
containment on two separate ephemeral roles, and clean them up. The proof does
not authorise target mutation and does not invoke a model. The operational branch
push trigger enables pre-merge validation; normal main updates do not deploy it.

For full repair evidence, operator PR 10 was planned/repaired on Cloudflare in
run 36323734781, then independently reviewed with ChatGPT in run 36339024542.
Its exact-head 44/44 adapter proof is artifact 10938660135 from run 36338829679;
cleanup run 36339182466 retired both fixture containers. Those historical runs
prove the repair path, not subsequent lifecycle code changes; use a new provision
run to validate the current lifecycle revision before landing or deployment.

The manual `cloudflare-operator-fixtures.yml` reproduces that pinned adapter
suite at operator head c50244478afcc394732376f7e28448368ef02bad. Its canonical
renderer source fixture remains private in clawsweeper-state at commit
2baf6b1b2bca132c22756b9d23469bec177a7677 (origin revision
495cac2013bc55533751a09e1bb499119b7de0bf). Only the source needed for identity
hashing is installed; no renderer or systemd service is activated. This does not
expand the enrolled project fleet or prove live social publication.

OpenClaw Bay is unaffected: these changes alter server-side compute and dispatch,
not its observer data contract or browser permissions. No public UI mutation
controls are introduced. Landing requires current runtime evidence, validation
and a fresh review; a green workflow alone is insufficient.
