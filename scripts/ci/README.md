# Two-host CI standby: source and offline acceptance

This directory versions the existing owner-operated ClawSweeper standby modules. It does not replace ClawSweeper's product runtime, authorise CircleCI spending or enable automatic provider workflows.

## Authority and installation

- Primary: `web`; standby: `Ayobami-Dev`. Production installation is under `~/.local/share/local-ci/` on each host, with owner-only credentials under `private/`.
- `standby_coord.py` uses GitHub's signed compare-and-swap coordination branch; the shared ledger is the provider-effect ownership authority.
- `standby_agent.py` is executed by the existing standby systemd timer. Installation must be a controlled, revision-pinned operation with backup, checksum comparison and a fresh verification run. **This PR does not deploy or alter the running service.**
- Do not commit `standby-policy.json`, credentials, local receipts or private GitHub issue contents.

## Independent recovery and spending decisions

`recovery_preflight()` checks authenticated primary heartbeat, signed current main, existing primary/fallback status and the global ledger **without billing or provider execution**. Its success is only eligibility evidence, not a provider claim or completed failover.

`readiness()` subsequently checks fresh, authenticated CircleCI Free-plan evidence and dedicated provider credentials. Only `attempt()` may reserve the shared ledger and dispatch; its reservation precedes the irreversible POST. Unknown provider effects are reconciled by readback and must never be replayed.

The observer and unit tests cannot establish genuine primary-offline recovery. Acceptance additionally requires a new eligible revision, an independently observed primary outage, one exclusive CAS owner, one verified CircleCI result, primary restoration and proof that no duplicate external effects occurred.

## Read-only verification

From the repository root:

```sh
PYTHONPATH=scripts/ci python3 -m unittest discover -s test/ci -p 'test_*.py' -q
python3 -m py_compile scripts/ci/standby_agent.py scripts/ci/standby_coord.py
git diff --check
```

Never use an already processed SHA to create a fallback acceptance run. Preserve historical provider receipts with their actual SHA. A stale budget may hold provider dispatch but must not suppress independent recovery diagnosis.

## GitHub status crash recovery

The verified CircleCI result is reconciled through a GitHub commit-status intent. Before any status POST, the shared CAS ledger records the attempt number and timestamp. On restart, the standby independently reads the exact-SHA status context before considering a write. If absent, a second and final attempt is permitted only after a 120-second cooldown and a new CAS reservation. Exhaustion requires manual reconciliation; no CircleCI pipeline POST is ever retried. GitHub commit statuses are append-only, so a delayed first POST can produce a duplicate _identical status_, not duplicate provider execution. Conflicting status payloads fail closed. Tests cover crashes, cooldown, owner mismatch, readback and exhausted attempts.
