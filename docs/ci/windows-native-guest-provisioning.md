# Native Windows CI: safe provisioning boundary

The owner-operated web host has native Windows PowerShell and Node.js through
WSL interop. This can run a trusted, read-only, offline native test but is not
equivalent to an isolated GitHub Actions self-hosted Windows runner.

## Current measured host (10 November 2026)

- Windows 11 Home (EditionID Core), native AMD64 PowerShell 5.1 and Node.js v24.
- Non-elevated Windows login.
- Windows Sandbox absent; no installed Hyper-V management, VirtualBox, VMware
  or Windows QEMU guest.
- Windows Sandbox is not supported on Home. A successful native test must not
  be described as GitHub workflow acceptance.

## Preflight

The scripts/ci/windows_native_guest_preflight.ps1 -Mode Inspect command returns
a machine-readable, read-only capability report. Admit mode intentionally returns
75 with HOLD_ISOLATED_WINDOWS_GUEST_REQUIRED. It never installs a feature,
invokes an API POST, starts an untrusted process or registers a runner.

This read-only probe is not the future JIT controller. Report fields cannot be
used as user-supplied proof to authorise runner registration.

## Release acceptance contract

A new Windows execution driver must first create and attest an ephemeral,
single-run Windows guest (VM or supported Sandbox), with no host filesystem,
tokens, agent sockets, browser profiles, production credentials or Docker socket
mapped into it. Restrict guest network egress, prove exact reviewed workflow
bytes and GH run/job/attempt/source/merge ancestry, pin guest/runner images,
install dependencies from reviewed sources, and enforce immutable JIT labels.
Create a durable pre-registration intent and atomic owner lease BEFORE the
first GitHub registration POST. Independently prove the correct GitHub job
succeeded, preserve bounded output digests, dispose the guest and verify JIT
deregistration. Crash/timeout, stale workflow, missing cleanup or uncertain
effect must hold release without retrying registration or claiming a pass.

GitHub's documented generate-jitconfig endpoint is consequential; this preflight
does not call it. Native tests on the current Windows Home host are development
evidence only. Do not register a generic self-hosted Windows runner on that
personal host. Do not turn Windows Home into a supposed Pro/Sandbox backend via
undocumented feature hacks.

Keep the production Windows job unadmitted until this independent driver and
provider-backed verification exist. Do not merge the protected release by
substituting a Linux/WSL job or weakening required status/review checks.
