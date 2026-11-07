"""Pure, fail-closed admission policy for the dedicated ClawSweeper JIT runner.

The policy never confuses a GitHub job's enqueueing with a passing check and
never authorises a source/review/merge decision. Only the enumerated workflows
can have an ephemeral runner provisioned by the separately controlled executor.
"""
from dataclasses import dataclass
import re

REPOSITORY = "AyobamiH/clawsweeper"
JOB_LABEL = re.compile(r"^clawsweeper-ci-(security|ops|isolation)-([1-9][0-9]*)-([a-z0-9-]+)$")
SHA = re.compile(r"^[a-f0-9]{40}$")
REVIEW_EVENTS = frozenset(("pull_request_review", "pull_request_review_comment"))
WORKFLOWS = {
    ("security", "actions"): (".github/workflows/codeql.yml", "Analyze (actions)"),
    ("security", "javascript-typescript"): (
        ".github/workflows/codeql.yml", "Analyze (javascript-typescript)"),
    ("ops", "dispatch"): (".github/workflows/clawsweeper-dispatch.yml", "dispatch"),
    ("ops", "notify"): (".github/workflows/github-activity.yml", "notify"),
    ("ops", "provision"): (".github/workflows/repair-containment-smoke.yml", "Provision containment smoke compute"),
    ("ops", "cleanup"): (".github/workflows/repair-containment-smoke.yml", "Destroy containment smoke compute"),
    ("isolation", "e2e"): (".github/workflows/automerge-e2e.yml", "production automerge flow"),
}
# Match each production workflow's actual GitHub event contract. Source code
# authority is separate: every privileged lane must still match the approved
# default-branch workflow hash, regardless of who submitted the event payload.
EVENTS = {
    ("security", "actions"): frozenset(("push", "pull_request", "schedule", "workflow_dispatch")),
    ("security", "javascript-typescript"): frozenset(("push", "pull_request", "schedule", "workflow_dispatch")),
    ("ops", "dispatch"): frozenset(("issues", "issue_comment", "pull_request_target")),
    ("ops", "notify"): frozenset(("repository_dispatch", "issues", "issue_comment",
                                  "pull_request_target", "pull_request_review",
                                  "pull_request_review_comment", "workflow_run")),
    ("ops", "provision"): frozenset(("push", "pull_request", "workflow_dispatch")),
    ("ops", "cleanup"): frozenset(("push", "pull_request", "workflow_dispatch")),
    ("isolation", "e2e"): frozenset(("push", "pull_request", "workflow_dispatch")),
}


@dataclass(frozen=True)
class Candidate:
    run_id: int
    job_id: int
    run_attempt: int
    sha: str
    workflow: str
    event: str
    role: str
    slot: str
    label: str
    job_name: str
    branch: str
    trusted_base_sha: str | None = None


class AdmissionHold(ValueError):
    """An expected hold: a failed admission never generates a runner."""


def classify(run, job):
    """Validate the exact GitHub run/job identity without provider side effects."""
    if not isinstance(run, dict) or not isinstance(job, dict):
        raise AdmissionHold("invalid_source")
    if run.get("repository", {}).get("full_name") != REPOSITORY:
        raise AdmissionHold("foreign_repository")
    if job.get("status") != "queued":
        raise AdmissionHold("not_queued")
    run_id, job_id, attempt = run.get("id"), job.get("id"), run.get("run_attempt")
    if not all(isinstance(i, int) and i > 0 and not isinstance(i, bool) for i in (run_id, job_id, attempt)):
        raise AdmissionHold("invalid_identity")
    if job.get("run_id") not in (run_id, None):
        raise AdmissionHold("run_mismatch")
    labels = job.get("labels")
    if not isinstance(labels, list) or not all(isinstance(v, str) for v in labels):
        raise AdmissionHold("invalid_labels")
    unique = [x for x in labels if JOB_LABEL.fullmatch(x)]
    if len(unique) != 1 or not {"self-hosted", "Linux", "X64"}.issubset(set(labels)):
        raise AdmissionHold("unapproved_label")
    match = JOB_LABEL.fullmatch(unique[0])
    role, claimed_run_id, slot = match.groups()
    if int(claimed_run_id) != run_id:
        raise AdmissionHold("label_run_mismatch")
    contract = WORKFLOWS.get((role, slot))
    if contract is None:
        raise AdmissionHold("unknown_workflow_slot")
    path, name = contract
    if run.get("path") != path or job.get("name") != name:
        raise AdmissionHold("workflow_job_mismatch")
    if run.get("event") not in EVENTS[(role, slot)]:
        raise AdmissionHold("unapproved_event")
    sha, branch = run.get("head_sha"), run.get("head_branch")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise AdmissionHold("invalid_head")
    if not isinstance(branch, str) or len(branch) > 200 or "\n" in branch:
        raise AdmissionHold("invalid_branch")
    actor = run.get("actor", {}).get("login")
    trusted_base_sha = None
    if role == "ops":
        # GitHub's pull_request_target run metadata identifies the incoming PR
        # head branch and SHA, NOT the trusted workflow's base commit. The
        # executor separately pins the default-branch workflow source digest
        # before admitting this privileged class; never infer source authority
        # from the incoming PR's head_sha.
        if run.get("event") == "pull_request_target":
            if path not in (
                ".github/workflows/clawsweeper-dispatch.yml",
                ".github/workflows/github-activity.yml",
            ):
                raise AdmissionHold("untrusted_target_workflow")
            pulls = run.get("pull_requests")
            if not isinstance(pulls, list) or len(pulls) != 1:
                raise AdmissionHold("target_base_unverifiable")
            base = pulls[0].get("base") if isinstance(pulls[0], dict) else None
            if not isinstance(base, dict) or base.get("ref") != "main" or not SHA.fullmatch(str(base.get("sha", ""))):
                # A stacked or foreign target is not entitled to the default
                # branch's privileged runner credentials.
                raise AdmissionHold("target_base_not_main")
            trusted_base_sha = base["sha"]
        elif run.get("event") == "pull_request":
            # Containment provisioning has privileged credentials. Validate
            # GitHub's actual PR head repository, not merely its initiating
            # actor, before ever considering this execution for admission.
            if actor != "AyobamiH":
                raise AdmissionHold("untrusted_privileged_pull_request")
            pulls = run.get("pull_requests")
            repo_id = run.get("repository", {}).get("id")
            if (not isinstance(repo_id, int) or isinstance(repo_id, bool)
                    or not isinstance(pulls, list) or len(pulls) != 1
                    or not isinstance(pulls[0], dict)):
                raise AdmissionHold("privileged_pull_request_source_unverifiable")
            head, base = pulls[0].get("head"), pulls[0].get("base")
            if (not isinstance(head, dict) or not isinstance(base, dict)
                    or not isinstance(head.get("repo"), dict)
                    or not isinstance(base.get("repo"), dict)
                    or head["repo"].get("id") != repo_id
                    or base["repo"].get("id") != repo_id
                    or base.get("ref") != "main"
                    or not SHA.fullmatch(str(base.get("sha", "")))
                    or not SHA.fullmatch(str(head.get("sha", "")))):
                raise AdmissionHold("untrusted_privileged_pull_request_source")
            trusted_base_sha = base["sha"]
        elif run.get("event") in ("push", "workflow_dispatch") and slot in ("provision", "cleanup"):
            # A signed, explicitly pinned release preview is eligible for
            # *classification*, never execution without owner-only controls.
            if actor != "AyobamiH" or (branch != "main" and run.get("event") != "workflow_dispatch"):
                raise AdmissionHold("untrusted_operations_source")
        elif run.get("event") in REVIEW_EVENTS and slot == "notify":
            # GitHub reports reviewer activity on PR feature/merge revisions,
            # not main; the executor must pin their exact workflow bytes.
            pass
        elif run.get("event") not in ("pull_request",) and branch != "main":
            # Issues, comments, review notifications, repository_dispatch and
            # workflow_run are emitted against the trusted default branch even
            # when an external collaborator generated the event payload.
            raise AdmissionHold("untrusted_default_branch_source")
    if role == "isolation" and run.get("event") != "pull_request" and branch != "main":
        raise AdmissionHold("unexpected_e2e_branch")
    return Candidate(run_id, job_id, attempt, sha, path, run["event"], role, slot,
                     unique[0], name, branch, trusted_base_sha)


def is_release_preview(candidate, controls):
    """The only non-main privileged preview: exact owner run and source identity."""
    if not (candidate.role == "ops" and candidate.slot in ("provision", "cleanup")
            and candidate.event == "workflow_dispatch" and candidate.branch != "main"):
        return False
    scope = controls.get("release_preview")
    if not isinstance(scope, dict) or scope.get("accepted") is not True:
        raise AdmissionHold("release_preview_not_accepted")
    branch = str(scope.get("branch", ""))
    if (not re.fullmatch(r"[A-Za-z0-9._/-]{1,160}", branch)
            or ".." in branch or "//" in branch):
        raise AdmissionHold("release_preview_branch_invalid")
    if (scope.get("branch") != candidate.branch or
            scope.get("head_sha") != candidate.sha or
            not SHA.fullmatch(str(scope.get("head_sha", ""))) or
            not SHA.fullmatch(str(scope.get("tree_sha", ""))) or
            not re.fullmatch(r"[a-f0-9]{64}", str(scope.get("workflow_sha256", "")))):
        raise AdmissionHold("release_preview_source_not_pinned")
    runs = controls.get("allowed_run_ids")
    if not isinstance(runs, list) or runs != [candidate.run_id]:
        raise AdmissionHold("release_preview_run_not_exclusive")
    # Do not allow the exceptional preview authority to promote ordinary ops.
    if controls.get("operations_accepted") is True:
        raise AdmissionHold("release_preview_operations_mixed")
    return True


def category_enabled(candidate, controls):
    """Fail closed on missing/invalid enablement or incomplete sandbox parity."""
    if not isinstance(controls, dict) or controls.get("enabled") is not True:
        raise AdmissionHold("controller_disabled")
    if controls.get("repo") != REPOSITORY:
        raise AdmissionHold("controller_repository_mismatch")
    enabled = controls.get("enabled_roles")
    if not isinstance(enabled, list) or candidate.role not in enabled:
        raise AdmissionHold("role_not_accepted")
    scoped_runs = controls.get("allowed_run_ids")
    if scoped_runs is not None:
        if (not isinstance(scoped_runs, list) or not scoped_runs or
                candidate.run_id not in scoped_runs):
            raise AdmissionHold("run_id_not_authorised")
    # The current image has no inner isolated Docker daemon. This lane stays
    # held rather than using the host daemon or reducing E2E coverage.
    if candidate.role == "isolation":
        raise AdmissionHold("nested_docker_isolation_not_proven")
    if candidate.role == "ops":
        release_preview = is_release_preview(candidate, controls)
        if not release_preview and controls.get("operations_accepted") is not True:
            raise AdmissionHold("operations_not_proven")
        # Target-PR events have arbitrary incoming branch names. Their base
        # workflow must instead be pinned by the executor's trusted_main_sha.
        if candidate.event in ("pull_request_target", "pull_request"):
            # A same-repository PR can have a feature-branch source, but its
            # base must still match the owner's exact approved main revision.
            if not SHA.fullmatch(str(controls.get("trusted_main_sha", ""))):
                raise AdmissionHold("trusted_base_not_pinned")
            if candidate.event == "pull_request":
                # An owner PR alone is never privileged execution authority.
                # Every such run must additionally be explicitly owner-pinned.
                if not isinstance(scoped_runs, list) or candidate.run_id not in scoped_runs:
                    raise AdmissionHold("privileged_pr_run_not_pinned")
        elif candidate.slot == "notify" and candidate.event in REVIEW_EVENTS:
            if not SHA.fullmatch(str(controls.get("trusted_main_sha", ""))):
                raise AdmissionHold("trusted_base_not_pinned")
        elif candidate.branch != "main" and not release_preview:
            raise AdmissionHold("branch_not_authorised")
    else:
        allowed_branches = controls.get("allowed_branches", [])
        if not isinstance(allowed_branches, list) or candidate.branch not in allowed_branches:
            raise AdmissionHold("branch_not_authorised")
    max_jobs = controls.get("max_jobs_per_cycle", 1)
    if max_jobs != 1:
        raise AdmissionHold("unbounded_worker_configuration")
    return True
