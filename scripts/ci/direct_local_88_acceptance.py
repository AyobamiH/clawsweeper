#!/usr/bin/env python3
"""Read-only 88-job acceptance view from an exact owner-signed 2/2 receipt.

A source mapping is not a run. This verifier reports the historical two
independently accepted local jobs while holding the other 86. It never
admits, dispatches, retries, publishes statuses, or executes workflow code.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import re

import direct_local_manual_auth as owner
import direct_local_v3_release_integrity as signatures
import direct_local_workflow as mapping
from estate_policy import Hold, load_manifest

SCHEMA = "clawsweeper.direct_local_first_two_distinct_job_acceptance.v1"
OUT_SCHEMA = "clawsweeper.workflow-estate-acceptance-readback.v1"
EXECUTION_SHA = "944fd5ad04ba5c01d73b8c3059313469aad3357f"
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
INITIAL = {
    ".github/workflows/ci.yml#check": {
        "id": "local-fleet-bf40e3b5fe1b",
        "attempt": 4,
        "suite": "linux-node24-claw-check",
        "last_step": "Full repository validation",
    },
    ".github/workflows/ci.yml#sparse-repair-builds": {
        "id": "local-fleet-602d95280d8f",
        "attempt": 1,
        "suite": "linux-node24-claw-sparse",
        "last_step": "Sparse repair checkout smoke",
    },
}
COMMON_STEPS = (
    "Exact commit checkout",
    "Workflow semantic validation",
    "Pinned pnpm dependency install",
)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Hold(code)


def unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_acceptance_receipt_key")
        result[key] = value
    return result


def read_signed_receipt(receipt: Path, digest: str, signers: Path) -> dict:
    """Require exact caller-pinned bytes, owner signature and a bounded read."""
    require(isinstance(digest, str) and bool(HEX64.fullmatch(digest)),
            "missing_exact_acceptance_receipt_digest")
    try:
        raw = signatures.safe_file(receipt, bound=32768)
        require(hashlib.sha256(raw).hexdigest() == digest,
                "acceptance_receipt_digest_mismatch")
        signed = signatures.verify_signature(receipt, signers, bound=32768)
        require(signed == raw, "acceptance_receipt_changed_after_signature")
        doc = json.loads(raw, object_pairs_hook=unique)
    except (OSError, ValueError, RuntimeError) as exc:
        if isinstance(exc, Hold):
            raise
        raise Hold("acceptance_receipt_or_owner_signature_untrusted") from exc
    require(isinstance(doc, dict), "invalid_acceptance_receipt")
    return doc


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 60:
        return False
    try:
        return dt.datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False


def verify_two(doc: dict) -> dict[str, dict]:
    require(doc.get("schema") == SCHEMA
            and doc.get("host") == "web"
            and doc.get("source_sha") == EXECUTION_SHA
            and doc.get("required") == 2
            and doc.get("distinct_ordinary_jobs_verified") == 2
            and doc.get("execution_mode") == "existing_detached_local_fleet"
            and doc.get("fleet_database_quick_check") == "ok"
            and doc.get("detached_leases") == 0
            and doc.get("pending_jobs") == 0
            and doc.get("fleet_timer_active") is True
            and doc.get("github_provider_accepted") is False
            and doc.get("github_hosted_ci_proven") is False
            and doc.get("new_controller_created") is False
            and doc.get("new_job_ids_created") is False
            and doc.get("signed_permanent_capacity_guard_passed") is True
            and doc.get("paid_ci_dispatched") is False
            and doc.get("other_86_workflow_definitions_accepted") is False
            and _valid_timestamp(doc.get("accepted_utc")),
            "signed_first_two_acceptance_invariant_failed")
    expected_ids = {job["id"] for job in INITIAL.values()}
    accepted_ids = doc.get("accepted_job_ids")
    require(isinstance(accepted_ids, list) and len(accepted_ids) == 2
            and all(isinstance(value, str) for value in accepted_ids)
            and set(accepted_ids) == expected_ids,
            "accepted_job_ids_changed")
    rows = doc.get("jobs")
    require(isinstance(rows, dict) and set(rows) == expected_ids
            and all(isinstance(row, dict) for row in rows.values()),
            "accepted_jobs_missing_or_extra")
    verified = {}
    for key, expected in INITIAL.items():
        row = rows[expected["id"]]
        require(isinstance(row, dict)
                and row.get("suite") == expected["suite"]
                and row.get("attempt") == expected["attempt"]
                and row.get("execution_source_sha") == EXECUTION_SHA
                and row.get("durable_sqlite_state") == "completed"
                and row.get("durable_sqlite_outcome") == "success"
                and row.get("reported") is True
                and row.get("cleanup_verified") is True
                and row.get("owned_container_absent") is True
                and row.get("historical_proofs_retained") is True
                and _valid_timestamp(row.get("started_at"))
                and _valid_timestamp(row.get("finished_at"))
                and all(isinstance(row.get(field), str)
                        and HEX64.fullmatch(row[field])
                        for field in ("engine_container_id", "log_sha256",
                                      "receipt_sha256", "signed_controller_sha256")),
                "signed_local_job_receipt_incomplete")
        require(dt.datetime.fromisoformat(row["started_at"])
                <= dt.datetime.fromisoformat(row["finished_at"]),
                "signed_local_job_timestamp_reversed")
        steps = row.get("steps")
        require(isinstance(steps, list)
                and len(steps) == 4
                and [s.get("name") for s in steps if isinstance(s, dict)]
                   == list(COMMON_STEPS) + [expected["last_step"]]
                and all(isinstance(s, dict) and s.get("exit_code") == 0
                        and type(s.get("exit_code")) is int for s in steps),
                "signed_local_steps_not_all_success")
        verified[key] = {
            "fleet_job_id": expected["id"],
            "attempt": expected["attempt"],
            "source_sha": EXECUTION_SHA,
            "receipt_sha256": row["receipt_sha256"],
            "finished_at": row["finished_at"],
        }
    require(len({rows[identifier]["engine_container_id"] for identifier in expected_ids}) == 2
            and len({rows[identifier]["receipt_sha256"] for identifier in expected_ids}) == 2,
            "signed_independent_job_isolation_missing")
    return verified


def historical_ci_bytes(root: Path) -> bytes:
    """Read the original execution commit's workflow blob, never check it out."""
    try:
        blob = subprocess.run(
            ["/usr/bin/git", "-C", str(root), "show",
             f"{EXECUTION_SHA}:.github/workflows/ci.yml"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise Hold("historical_ci_workflow_unavailable") from exc
    require(0 < len(blob) <= 1024 * 1024,
            "historical_ci_workflow_invalid_size")
    return blob


def verify_historical_ci_workflow(root: Path, observed: dict[str, str]) -> None:
    """Never carry 2 historical acceptances into a changed CI workflow."""
    workflow = ".github/workflows/ci.yml"
    require(workflow in observed, "historical_ci_workflow_not_in_manifest")
    require(hashlib.sha256(historical_ci_bytes(root)).hexdigest()
            == observed[workflow], "historical_ci_workflow_source_drift")


def compile_acceptance(*, root: Path, receipt: Path, expected_digest: str,
                       signers: Path) -> dict:
    """A signed past acceptance is evidence, not fresh provider acceptance."""
    root = root.resolve(strict=True)
    manifest = load_manifest(root / "config/ci-workflow-estate.json")
    observed = mapping.source_check(manifest, root)
    mapping.dag_check(manifest)
    verify_historical_ci_workflow(root, observed)
    source_catalogue_head = mapping.git_head(root)
    signed = read_signed_receipt(receipt, expected_digest, signers)
    accepted = verify_two(signed)
    jobs = []
    for job in manifest["jobs"]:
        key = job["workflow"] + "#" + job["id"]
        verified = accepted.get(key)
        jobs.append({
            "key": key,
            "class": mapping.job_class(job),
            "execution_boundary": job["execution_boundary"],
            "local_terminal_acceptance": "historically_owner_signed_verified"
                                        if verified else "not_accepted",
            "local_proof": verified,
            "github_provider_accepted": False,
            "execution_started_by_this_readback": False,
        })
    require(len(jobs) == 88 and len({j["key"] for j in jobs}) == 88,
            "incomplete_88_job_acceptance_view")
    return {
        "schema": OUT_SCHEMA,
        "catalogue_commit": source_catalogue_head,
        "accepted_execution_commit": EXECUTION_SHA,
        "source_catalogue_exact_41_88": True,
        "historical_acceptance_receipt_sha256": expected_digest,
        "receipt_signature_valid": True,
        "current_fleet_database_reverified": False,
        "github_provider_accepted": False,
        "new_jobs_admitted": 0,
        "new_jobs_executed": 0,
        "summary": {
            "total_workflows": 41,
            "total_jobs": 88,
            "historically_signed_terminal_success": len(accepted),
            "not_yet_accepted": 88 - len(accepted),
            "provider_accepted": 0,
        },
        "jobs": jobs,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=mapping.ROOT)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--allowed-signers", type=Path,
                   default=owner.owner_allowed_signers())
    opts = p.parse_args()
    try:
        report = compile_acceptance(root=opts.root, receipt=opts.receipt,
                                    expected_digest=opts.expected_sha256,
                                    signers=opts.allowed_signers)
    except (Hold, OSError, ValueError) as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
