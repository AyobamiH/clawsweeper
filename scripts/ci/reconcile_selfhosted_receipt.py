#!/usr/bin/env python3
"""Append an independent, read-only cleanup and GitHub result reconciliation.

Never rewrites a failed/held original receipt and never creates another runner.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from self_hosted_executor import (RECEIPTS, REPOSITORY, REPO_SLUG, atomic, gh,
                                  inspect_owned, runner_absent_verified)
from verify_codeql_release import WORKFLOW as CODEQL_WORKFLOW, verify_replacement_lineage

SHA = re.compile(r'^[a-f0-9]{40}$')
KEY = re.compile(r'^run-([1-9][0-9]*)-job-([1-9][0-9]*)-attempt-([1-9][0-9]*)(-replacement-1)?$')


def reconcile(directory):
    directory = Path(directory)
    if directory.is_symlink() or directory.parent.resolve() != RECEIPTS.resolve():
        raise RuntimeError('unowned_receipt_directory')
    match = KEY.fullmatch(directory.name)
    if not match or not directory.is_dir():
        raise RuntimeError('unsafe_receipt_identity')
    original = directory/'receipt.json'
    log = directory/'runner.log'
    addendum = directory/'late-cleanup-reconciliation.json'
    if addendum.exists():
        raise RuntimeError('reconciliation_already_exists')
    if original.is_symlink() or log.is_symlink() or not log.is_file():
        raise RuntimeError('unsafe_receipt_file')
    source_bytes = original.read_bytes()
    receipt = json.loads(source_bytes)
    run_id, job_id, attempt = map(int, match.groups()[:3])
    original_runner = f'csw-ci-{run_id}-{job_id}-{attempt}'
    replacement = bool(match.group(4))
    name = original_runner + (match.group(4) or '')
    if replacement and (directory.stat().st_uid != os.getuid() or
                        directory.stat().st_mode & 0o077 or
                        not original.is_file() or
                        original.stat().st_uid != os.getuid() or
                        original.stat().st_mode & 0o077 or
                        log.stat().st_uid != os.getuid() or
                        log.stat().st_mode & 0o077):
        raise RuntimeError('replacement_receipt_directory_unsafe')
    if (receipt.get('schema') != 'clawsweeper.selfhosted-jit.v1' or
        receipt.get('runner_name') != name or
        [receipt.get('run_id'), receipt.get('job_id'), receipt.get('attempt')] != [run_id,job_id,attempt] or
        not isinstance(receipt.get('head_sha'),str) or not SHA.fullmatch(receipt['head_sha'])):
        raise RuntimeError('receipt_binding_mismatch')
    if receipt.get('state') != 'held':
        raise RuntimeError('only_held_receipts_reconciled')
    lineage = None
    if replacement:
        label = receipt.get('label')
        if (not isinstance(label, str) or
            re.fullmatch(rf'clawsweeper-ci-security-{run_id}-(actions|javascript-typescript)',label) is None or
            receipt.get('workflow') != CODEQL_WORKFLOW):
            raise RuntimeError('replacement_role_not_codeql')
        lineage = verify_replacement_lineage(RECEIPTS,run_id,job_id,attempt,
                                             receipt['head_sha'],original_runner,label,receipt)
    expected_digest = receipt.get('log_sha256')
    if (not isinstance(expected_digest,str) or
        hashlib.sha256(log.read_bytes()).hexdigest() != expected_digest):
        raise RuntimeError('log_digest_mismatch')
    if receipt.get('finished_at') is None:
        raise RuntimeError('nonterminal_original_receipt')
    issues = receipt.get('issues')
    if not isinstance(issues,list):
        raise RuntimeError('unbounded_issue_shape')
    # Read-only Docker evidence: no stop/remove here; do not interfere with
    # anyone else's containers or infer absence from a failed inspect call.
    for suffix in ('-worker','-net'):
        if inspect_owned(name+suffix,name) is not None:
            raise RuntimeError('container_still_present')
    runner_id = receipt.get('runner_id')
    if not isinstance(runner_id,int):
        raise RuntimeError('runner_id_missing')
    runner_absent_verified(runner_id,name)
    remote_run = gh(f'{REPO_SLUG}/actions/runs/{run_id}')
    if (remote_run.get('id') != run_id or
        remote_run.get('head_sha') != receipt['head_sha'] or
        remote_run.get('run_attempt') != attempt or
        remote_run.get('repository',{}).get('full_name') != REPOSITORY):
        raise RuntimeError('github_run_mismatch')
    remote_job = gh(f'{REPO_SLUG}/actions/jobs/{job_id}')
    if (remote_job.get('id') != job_id or remote_job.get('run_id') != run_id or
        remote_job.get('runner_name') != name or remote_job.get('status') != 'completed'):
        raise RuntimeError('github_job_mismatch')
    expected_job = receipt.get('github_job',{})
    if expected_job.get('conclusion') != remote_job.get('conclusion'):
        raise RuntimeError('github_job_conclusion_changed')
    if replacement and (expected_job.get('runner_name') != name or
                        receipt['label'] not in remote_job.get('labels',[])):
        raise RuntimeError('replacement_github_label_or_identity_drift')
    recognised_cleanup_only = set(issues) <= {'owned_cleanup_unverified','runner_deregistration_unverified'}
    passed = (recognised_cleanup_only and receipt.get('runner_exit') == 0 and
              remote_job.get('conclusion') == 'success')
    record = {
        'schema':'clawsweeper.selfhosted-cleanup-reconciliation.v1',
        'run_id':run_id, 'job_id':job_id,'attempt':attempt,
        'head_sha':receipt['head_sha'], 'runner_name':name,
        'original_state':receipt['state'], 'original_issues':issues,
        'original_receipt_sha256':hashlib.sha256(source_bytes).hexdigest(),
        'log_sha256':expected_digest, 'github_job_conclusion':remote_job['conclusion'],
        'local_containers_absent':True,'github_runner_absent':True,
        'decision':'late_cleanup_verified' if passed else 'cleanup_only_no_acceptance',
        'verified_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
    }
    if replacement:
        record['replacement'] = lineage
    atomic(addendum,record)
    return record


if __name__ == '__main__':
    if len(sys.argv)!=2:
        raise SystemExit('Expected one exact owned receipt directory')
    try:
        print(json.dumps(reconcile(sys.argv[1]),sort_keys=True))
    except Exception as exc:
        print(json.dumps({'status':'held','reason':type(exc).__name__}),file=sys.stderr)
        sys.exit(1)
