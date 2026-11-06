"""Validate GitHub webhook signatures and convert trusted events into wake-up signals.

No webhook payload is an instruction to run arbitrary commands. Existing CI
reconciles the exact source SHA independently from GitHub.
"""
import hashlib
import hmac
import json

REPOSITORIES = frozenset(('AyobamiH/clawsweeper', 'AyobamiH/opstruth', 'AyobamiH/agentproof'))
MAX_BYTES = 65536


def authorised(headers, payload, secret):
    if not secret or len(payload) > MAX_BYTES:
        return False
    actual = headers.get('X-Hub-Signature-256', '')
    expected = 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, expected):
        return False
    event = headers.get('X-GitHub-Event')
    if event not in ('push', 'pull_request'):
        return False
    try:
        data = json.loads(payload)
        if data['repository']['full_name'] not in REPOSITORIES:
            return False
        if event == 'pull_request':
            return data.get('action') in ('opened', 'reopened', 'synchronize', 'ready_for_review')
        return isinstance(data.get('after'), str) and len(data['after']) == 40
    except (KeyError, TypeError, ValueError):
        return False
