# Owner-operated Windows CI: disposable KVM guest

This is engineering source and NOT a production runner approval.

## Measured infrastructure

The owner machine web currently runs Windows 11 Home and WSL2. Native
PowerShell and Windows Node.js successfully ran five real Windows Codex
launcher tests. However, Windows Home does not support Windows Sandbox,
and no installed QEMU Windows hypervisor, clean licensed guest image or
proven isolated guest execution backend was found.

GitHub warns that self-hosted runners processing public pull requests can
expose host secrets. Do not run untrusted CI on bare Windows, WSL, or any
host with a private signing-agent socket.

## Bounded engineering delivered

scripts/ci/windows_kvm_guest.py provides an owner-only KVM Windows guest
preflight and an offline overlay preparation stage. It validates the exact
repository, private 0600 controls, a lawful guest-image assertion, QEMU
and QEMU-img hashes, a private image root, immutable Windows disk and
UEFI hashes, KVM device permission and network policy. It rejects paths
with symlinks, traversal, unsafe owners/modes and stale or duplicate
job intents.

Read-only invocation from the ClawSweeper source checkout:

    python3 -B scripts/ci/windows_kvm_guest.py inspect

Once all prerequisites are independently approved, a bounded offline
preparation creates a durable pre-effect intent, a new qcow2 overlay,
and per-run UEFI variables for one run/job identity:

    python3 -B scripts/ci/windows_kvm_guest.py prepare-offline --run-id RUN_ID --job-id JOB_ID

This does NOT start QEMU, register a GitHub runner, or execute a workflow.
The source renders an offline VM command with KVM, a private QMP UNIX
socket, no host filesystem mounts, no host Docker socket and -nic none.
This is preparation only, not VM boot attestation or GitHub job acceptance.
A failed or interrupted preparation leaves an owned intent and refuses
automatic replay; never delete it without evidence-backed reconciliation.

A disabled template is in config/ci-windows-kvm-guest.example.json.
It contains no valid licences or binary/image pins and may NOT be
treated as an approved runtime controls file.

## Additional infrastructure needed for an actual Windows JIT runner

1. A clean, legally authorised Windows guest disk with a separate
   applicable licence or valid evaluation entitlement; no cloning of
   the owner Windows user profile or production credentials.
2. Reviewed, content-pinned QEMU/KVM binaries, UEFI firmware, a guest
   image, any required TPM/Secure Boot and VirtIO drivers. Installing
   new packages or changing the Windows edition requires explicit
   budget and operating-system authorisation, not this source stage.
3. A genuinely isolated execution principal for QEMU, not the normal
   owner account with Git or signing credentials, and reproducible VM
   process/guest attestation and teardown.
4. Independent, denied-by-default guest network access, via a tested
   GitHub-domain egress proxy or equivalent. QEMU unrestricted user
   networking is not accepted. The current -nic none prevents all
   access to GitHub and therefore cannot itself run a GitHub job.
5. Exact trusted workflow bytes, PR ancestry, permissions and
   run/job/attempt validation before the first GitHub JIT POST.
   The Windows job label must be exact to its GitHub run.
6. Secure one-shot JIT config delivery into the clean VM, run.cmd
   execution inside Windows only, provider-backed completion receipts,
   off-runner immutable log evidence, deregistration, VM destruction,
   forced-stop recovery and uncertain-effect fencing.

Until the above are implemented AND observed on real infrastructure,
the Windows class stays held. No boolean configuration or user-supplied
guest self-report can establish that acceptance.

## Full migration is larger

Windows is one of 88 manifest jobs. A Windows runner will not close
CodeQL SARIF, privileged GitHub effects, Cloudflare event adapters,
rootless 28-scenario E2E, native review, automatic recovery or the
protected main release. Keep PR #92 unmerged and the existing owners'
separate source/worktrees intact.

References:

- https://docs.github.com/en/actions/reference/runners/self-hosted-runners
- https://docs.github.com/en/actions/reference/security/secure-use
- https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview
- https://www.qemu.org/docs/master/tools/qemu-img.html
