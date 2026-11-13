"""Fail-closed policy for the complete ClawSweeper owner-runner estate.

Pure classification/admission; never grants trust from a workflow's filename,
GitHub 'active' status, an actor string, or a successful test alone.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

REPO = "AyobamiH/clawsweeper"
BASE = Path(__file__).resolve().parents[2]
MANIFEST = BASE / "config" / "ci-workflow-estate.json"
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
SLOT = re.compile(r"^[a-z][a-z0-9-]{0,60}$")
CLASSES = frozenset(("ordinary", "privileged", "review", "codeql", "e2e", "windows"))

# Class overrides are narrow: write-capable review/apply is *privileged*, never
# accidentally treated as a read-only reviewer because the name says "review".
# These two already have an independently reviewed and guarded validation
# controller. The estate may audit them, but MUST NOT register a second runner.
DELEGATED_VALIDATION = {
    ".github/workflows/ci.yml#check": "check",
    ".github/workflows/ci.yml#sparse-repair-builds": "sparse",
}

OVERRIDES = {
    ".github/workflows/codeql.yml#analyze": "codeql",
    ".github/workflows/ci.yml#check": "ordinary",
    ".github/workflows/ci.yml#sparse-repair-builds": "ordinary",
    ".github/workflows/ci.yml#windows-codex-launch": "windows",
    ".github/workflows/ci.yml#hosted-review-scan": "review",
    ".github/workflows/workers-ai-fallback-acceptance.yml#release-source-review": "review",
    ".github/workflows/automerge-e2e.yml#automerge-e2e": "e2e",
    ".github/workflows/repair-containment-smoke.yml#containment-smoke": "e2e",
    ".github/workflows/sweep.yml#review": "review",
    ".github/workflows/commercial-fulfilment.yml#semantic-review": "review",
    ".github/workflows/repair-cluster-worker.yml#cluster": "review",
}
READ_ONLY_RISKS = frozenset(("container_runtime", "cloud_service", "possible_write_effect", "secret_reference", "write_permission", "workflow_secret_reference", "reusable_secret_inheritance", "sensitive_upstream_dependency"))
SENSITIVE = frozenset(("privileged", "review", "codeql", "e2e", "windows"))
REVIEW_CLASSES = frozenset(("review",))
READONLY_EVENTS = frozenset(("push", "pull_request", "workflow_dispatch", "schedule"))
# GitHub events that carry customer/PR/review content or depend on a previous
# workflow are not authority for mutation-capable local runners. They require
# a dedicated authenticated adapter with an independent intent/effect ledger.
# Merely matching the event name, run SHA or GitHub actor cannot approve them.
UNTRUSTED_PRIVILEGED_EVENTS = frozenset((
    "issues", "issue_comment", "pull_request_target",
    "pull_request", "pull_request_review", "pull_request_review_comment",
    "repository_dispatch", "workflow_run",
))
BOUND_OWNER_EVENTS = frozenset(("workflow_dispatch", "push", "schedule"))


class Hold(ValueError):
    """Expected refusal; no runner registration may follow."""


@dataclass(frozen=True)
class Admission:
    job_key: str
    job_class: str
    run_id: int
    job_id: int
    attempt: int
    sha: str
    workflow: str
    event: str
    label: str
    name: str
    branch: str
    actor_login: str | None = None
    actor_id: int | None = None


def load_manifest(path=MANIFEST):
    data = json.loads(Path(path).read_text())
    if data.get("schema") != "clawsweeper.workflow-estate.v2":
        raise Hold("estate_schema_unrecognised")
    jobs = data.get("jobs")
    sources = data.get("sources")
    if not isinstance(jobs, list) or not isinstance(sources, list) or not jobs:
        raise Hold("estate_manifest_incomplete")
    if len(jobs) != data.get("summary", {}).get("jobs"):
        raise Hold("estate_job_count_mismatch")
    if data.get("summary", {}).get("github_hosted") != 0 or (
            data.get("summary", {}).get("dynamic_hosted_fallback") != 0):
        raise Hold("github_hosted_execution_still_present")
    # A missing Cloudflare runner resolves only to this intentionally
    # unregistered sentinel. Never authorise it as a real execution label.
    for item in jobs:
        runner = str(item.get("runs_on", ""))
        if "ubuntu-latest" in runner or "windows-latest" in runner or "macos-latest" in runner:
            raise Hold("hosted_runner_fallback_not_migrated")
    keys = [j.get("workflow", "") + "#" + j.get("id", "") for j in jobs]
    if len(set(keys)) != len(keys):
        raise Hold("duplicate_estate_jobs")
    source_map = {}
    for s in sources:
        key, digest = s.get("path"), s.get("sha256")
        if not isinstance(key, str) or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise Hold("invalid_source_digest")
        if key in source_map:
            raise Hold("duplicate_workflow_source")
        source_map[key] = digest
    for j in jobs:
        if source_map.get(j.get("workflow")) != j.get("source_sha256"):
            raise Hold("job_source_manifest_mismatch")
        if not isinstance(j.get("events"), list) or not all(isinstance(e, str) for e in j["events"]):
            raise Hold("invalid_job_events")
    for key in OVERRIDES:
        if key not in keys:
            raise Hold("missing_critical_job:" + key)
    return data


def job_class(job):
    key = job["workflow"] + "#" + job["id"]
    if key in OVERRIDES:
        cls = OVERRIDES[key]
        if cls == "ordinary" and set(job.get("risks", [])).intersection(READ_ONLY_RISKS):
            raise Hold("ordinary_job_contains_privileged_behaviour")
        return cls
    # Unknown jobs default to privileged, not to ordinary read-only execution.
    return "privileged"


def classify(manifest, run, job):
    if not isinstance(run, dict) or not isinstance(job, dict):
        raise Hold("invalid_github_objects")
    if run.get("repository", {}).get("full_name") != REPO:
        raise Hold("foreign_repository")
    if job.get("status") != "queued":
        raise Hold("job_not_queued")
    ids = (run.get("id"), job.get("id"), run.get("run_attempt"))
    if any(not isinstance(x, int) or isinstance(x, bool) or x <= 0 for x in ids):
        raise Hold("invalid_job_identity")
    run_id, job_id, attempt = ids
    if job.get("run_id") not in (None, run_id):
        raise Hold("job_run_identity_mismatch")
    sha = run.get("head_sha")
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise Hold("unverifiable_head_sha")
    branch = run.get("head_branch")
    if not isinstance(branch, str) or not branch or len(branch) > 200 or "\n" in branch:
        raise Hold("unverifiable_head_branch")
    workflow = run.get("path")
    name = job.get("name")
    def matches_name(entry):
        if name in (entry.get("display_name"), entry.get("id")):
            return True
        # Match only the source-declared CodeQL matrix values.
        if (entry.get("workflow") == ".github/workflows/codeql.yml"
                and entry.get("id") == "analyze"):
            return name in ("Analyze (actions)", "Analyze (javascript-typescript)")
        # GitHub substitutes matrix.shard and plan output into the review name.
        # The exact resulting job name AND job ID must additionally be present
        # in the owner's run/attempt-scoped approval; this bounded grammar is
        # classification only, never execution authority.
        if (entry.get("workflow") == ".github/workflows/sweep.yml"
                and entry.get("id") == "review" and isinstance(name, str)
                and len(name) <= 280):
            return re.fullmatch(
                r"Review shard [0-9]{1,5} · [A-Za-z0-9_.-]{1,39}/"
                r"[A-Za-z0-9_.-]{1,100}#[\[\]0-9, \t-]{1,110}",
                name,
            ) is not None
        return False
    matches = [j for j in manifest["jobs"] if j.get("workflow") == workflow and matches_name(j)]
    if len(matches) != 1:
        raise Hold("workflow_job_not_in_manifest")
    entry = matches[0]
    event = run.get("event")
    if event not in entry["events"]:
        raise Hold("unapproved_workflow_event")
    cls = job_class(entry)
    if cls not in CLASSES or not SLOT.fullmatch(entry["id"]):
        raise Hold("unsupported_job_class_or_id")
    if entry["workflow"] + "#" + entry["id"] in DELEGATED_VALIDATION:
        # Existing validation admission owns these exact run-bound labels.
        slot = DELEGATED_VALIDATION[entry["workflow"] + "#" + entry["id"]]
        label = "clawsweeper-ci-validation-" + str(run_id) + "-" + slot
    elif cls == "codeql":
        language = name.removeprefix("Analyze (").removesuffix(")")
        if language not in ("actions", "javascript-typescript"):
            raise Hold("unsupported_codeql_language")
        # Preserve existing approved run-bound CodeQL labels, not a new alias.
        label = "clawsweeper-ci-security-" + str(run_id) + "-" + language
    elif (workflow == ".github/workflows/automerge-e2e.yml"
          and entry["id"] == "automerge-e2e" and cls == "e2e"):
        # The source uses the existing *isolation/e2e* JIT label, not the
        # generic estate class/id alias. Do not route it through CodeQL.
        label = f"clawsweeper-ci-isolation-{run_id}-e2e"
    elif (workflow == ".github/workflows/repair-issue-implementation-intake.yml"
          and entry["id"] == "intake"):
        # The owner-configured workflow guard pins BOTH the run and attempt.
        # Keep every other job's established label contract unchanged.
        label = f"clawsweeper-ci-privileged-{run_id}-{attempt}-intake"
    else:
        label = "clawsweeper-ci-" + cls + "-" + str(run_id) + "-" + entry["id"]
    labels = job.get("labels")
    if not isinstance(labels, list) or not {"self-hosted"}.issubset(set(labels)) or label not in labels:
        raise Hold("run_bound_runner_label_missing")
    if sum(x == label for x in labels) != 1:
        raise Hold("duplicate_runner_label")
    actor = run.get("actor")
    login = actor.get("login") if isinstance(actor, dict) else None
    actor_id = actor.get("id") if isinstance(actor, dict) else None
    if not isinstance(login, str) or not login or len(login) > 100:
        login = None
    if type(actor_id) is not int or actor_id <= 0:
        actor_id = None
    return Admission(entry["workflow"] + "#" + entry["id"], cls, run_id, job_id,
                     attempt, sha, workflow, event, label, job.get("name"), branch,
                     login, actor_id)


def admit(candidate, manifest, controls, *, source_sha256, host_platform="linux"):
    """Admission needs independently fetched workflow bytes, not just YAML labels.

    Source sha must be computed from the actual GitHub workflow definition
    executed at its trusted ref. The caller is responsible for verifying that
    ref. A PR head or untrusted synthetic merge is never workflow authority.
    """
    if not isinstance(controls, dict) or controls.get("enabled") is not True:
        raise Hold("estate_controller_disabled")
    if controls.get("repo") != REPO:
        raise Hold("estate_repository_mismatch")
    if candidate.job_class not in controls.get("enabled_classes", []):
        raise Hold("class_not_enabled")
    allowed_jobs = controls.get("approved_jobs", {})
    if not isinstance(allowed_jobs, dict):
        raise Hold("invalid_approved_jobs")
    approved = allowed_jobs.get(candidate.job_key)
    if not isinstance(approved, dict):
        raise Hold("job_not_explicitly_approved")
    if approved.get("class") != candidate.job_class:
        raise Hold("class_authority_mismatch")
    if candidate.job_class not in CLASSES:
        raise Hold("invalid_job_class")
    all_entries = [j for j in manifest["jobs"] if j["workflow"] + "#" + j["id"] == candidate.job_key]
    if len(all_entries) != 1:
        raise Hold("unverified_job_manifest")
    entry = all_entries[0]
    expected = entry["source_sha256"]
    if approved.get("source_sha256") != expected or not isinstance(source_sha256, str) or source_sha256 != expected:
        raise Hold("workflow_source_digest_mismatch")
    if not isinstance(controls.get("trusted_main_sha"), str) or not HEX40.fullmatch(controls["trusted_main_sha"]):
        raise Hold("main_source_not_pinned")

    # Even read-only PR jobs cannot silently use a modified workflow for
    # privileged or secret-bearing execution. Owners must review new bytes.
    if candidate.job_class == "ordinary":
        if candidate.event not in READONLY_EVENTS or set(entry.get("risks", [])).intersection(READ_ONLY_RISKS):
            raise Hold("not_readonly_execution")
        if host_platform != "linux" or not controls.get("untrusted_isolation_verified"):
            raise Hold("untrusted_runner_isolation_not_proven")
        # The container restricts RFC1918/private-address egress but DOES
        # permit public GitHub/API egress. Never claim the runner is offline.
        if (approved.get("egress_policy") != "public-egress-private-denied" or
                controls.get("runner_network_isolation_verified") is not True or
                approved.get("tokens") != "read-only"):
            raise Hold("untrusted_permissions_not_bounded")
    else:
        allowed_runs = approved.get("run_ids")
        if not isinstance(allowed_runs, list) or candidate.run_id not in allowed_runs:
            raise Hold("sensitive_run_not_explicitly_pinned")
        allowed_shas = approved.get("head_shas")
        if not isinstance(allowed_shas, list) or candidate.sha not in allowed_shas:
            raise Hold("sensitive_head_not_pinned")
        # Approval is an exact *tuple*, not the unsafe cross-product of a
        # run list and a head-SHA list. Reject retries/new job IDs or a changed
        # matrix shard even when their workflow and source bytes are identical.
        attempts = approved.get("approved_attempts")
        if not isinstance(attempts, list) or not attempts:
            raise Hold("sensitive_attempt_not_explicitly_pinned")
        required = {"run_id", "job_id", "attempt", "head_sha", "job_name"}
        actual = (candidate.run_id, candidate.job_id, candidate.attempt,
                  candidate.sha, candidate.name)
        recognised = set()
        for record in attempts:
            if (not isinstance(record, dict) or set(record) != required
                    or any(type(record[k]) is not int or record[k] <= 0
                           for k in ("run_id", "job_id", "attempt"))
                    or not isinstance(record["head_sha"], str)
                    or not HEX40.fullmatch(record["head_sha"])
                    or not isinstance(record["job_name"], str)
                    or not record["job_name"] or len(record["job_name"]) > 280):
                raise Hold("invalid_sensitive_attempt_approval")
            item = (record["run_id"], record["job_id"], record["attempt"],
                    record["head_sha"], record["job_name"])
            if item in recognised:
                raise Hold("duplicate_sensitive_attempt_approval")
            recognised.add(item)
        if actual not in recognised:
            raise Hold("sensitive_attempt_not_explicitly_pinned")

    if candidate.job_class == "privileged":
        if host_platform != "linux" or not controls.get("operations_accepted"):
            raise Hold("privileged_operations_not_accepted")
        # No PR, review, or issue content is authority for a mutation-capable
        # runner; a later explicit guarded event adapter is required.
        if candidate.branch != "main" or candidate.sha != controls["trusted_main_sha"]:
            raise Hold("privileged_source_not_exact_main")
        if candidate.event in ("pull_request", "pull_request_target",
                               "pull_request_review", "pull_request_review_comment"):
            raise Hold("privileged_pr_event_denied")
        if candidate.event in UNTRUSTED_PRIVILEGED_EVENTS:
            # A GitHub workflow_run, issue or repository_dispatch record has
            # independently authenticated provenance but can still carry
            # untrusted effect instructions. A dedicated signed event adapter
            # and effect ledger are not implemented in this release.
            raise Hold("privileged_event_adapter_not_accepted")
        if candidate.event not in BOUND_OWNER_EVENTS:
            raise Hold("privileged_event_not_supported")
        event_actors = approved.get("verified_event_actors")
        if not isinstance(event_actors, dict):
            raise Hold("privileged_event_actor_not_pinned")
        authority = event_actors.get(candidate.event)
        if (not isinstance(authority, dict)
                or not isinstance(authority.get("login"), str)
                or not authority["login"]
                or type(authority.get("id")) is not int
                or authority["id"] <= 0):
            raise Hold("privileged_event_actor_not_pinned")
        if (candidate.actor_login != authority["login"]
                or candidate.actor_id != authority["id"]):
            raise Hold("privileged_event_actor_identity_mismatch")
        if approved.get("idempotent_effect_recovery") is not True:
            raise Hold("external_effect_recovery_not_proven")
    elif candidate.job_class == "review":
        if host_platform != "linux" or not controls.get("review_source_verified"):
            raise Hold("review_source_not_independently_verified")
        # No Workers AI inference nor forced Codex without an authenticated
        # allowance and explicit enablement. The current closeout sets false.
        if controls.get("model_inference_permitted") is not True:
            raise Hold("review_inference_not_authorised")
        if approved.get("complete_changed_source") is not True:
            raise Hold("incomplete_review_coverage")
    elif candidate.job_class == "codeql":
        if host_platform != "linux" or not controls.get("codeql_sarif_accepted"):
            raise Hold("codeql_admission_not_accepted")
        if not HEX64.fullmatch(approved.get("image_sha256", "")):
            raise Hold("codeql_image_unpinned")
    elif candidate.job_class == "e2e":
        if host_platform != "linux" or not controls.get("rootless_nested_container_proven"):
            raise Hold("nested_container_isolation_not_proven")
        if not approved.get("no_host_docker_socket") or not approved.get("full_scenarios"):
            raise Hold("e2e_parity_not_proven")
    elif candidate.job_class == "windows":
        if host_platform != "windows" or not controls.get("native_windows_runner_proven"):
            raise Hold("native_windows_runner_unavailable")
        if not approved.get("windows_isolation") or not approved.get("native_tests"):
            raise Hold("native_windows_runner_unisolated")
    return True


def workflow_digest(source_bytes):
    return hashlib.sha256(source_bytes).hexdigest()
