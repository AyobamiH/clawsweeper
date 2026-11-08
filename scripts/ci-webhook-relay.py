"""Recoverable quick-tunnel relay for the existing local CI wake-up receiver.

An fsynced pre-POST intent gives an otherwise unidentifiable webhook creation
an immutable, unique URL marker. An uncertain POST is never blindly repeated.
Only the exact marker from that intent can be adopted after a crash.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

HOME = pathlib.Path.home()
ROOT = HOME / '.local/share/local-ci'
SECRET = ROOT / 'secrets/webhook-hmac'
STATE = ROOT / 'secrets/webhook-hook-id'
BINDING = ROOT / 'secrets/webhook-hook-binding.json'
UPDATE_INTENT = ROOT / 'secrets/webhook-hook-update-intent.json'
INTENT = ROOT / 'secrets/webhook-hook-intent.json'
LOCK = ROOT / 'secrets/webhook-hook-id.lock'
URL_RE = re.compile(r'https://[a-z0-9-]+\.trycloudflare\.com')
MARKER_RE = re.compile(r'^[a-f0-9]{48}$')
REPO = 'AyobamiH/clawsweeper'
EVENTS = ['push', 'pull_request']


def api(method, path, data=None):
    command = ['gh', 'api', '--method', method, 'repos/' + REPO + '/' + path]
    if data is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('GitHub API request failed')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def durable_write(path, content):
    """Atomically install mode-0600 state and fsync file and directory."""
    if path.is_symlink():
        raise RuntimeError('Unsafe webhook state symlink')
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def durable_remove(path):
    if path.is_symlink():
        raise RuntimeError('Unsafe webhook intent symlink')
    if path.exists():
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


@contextlib.contextmanager
def exclusive_reconcile():
    if LOCK.is_symlink():
        raise RuntimeError('Unsafe webhook lock symlink')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError('Unverifiable owner-private webhook controller lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Webhook reconciliation already running') from exc
        yield
    finally:
        os.close(fd)


def marker_of(hook_url):
    """Recognise only our exact marker format; legacy hooks have no query."""
    parts = urlsplit(hook_url)
    if parts.scheme != 'https' or parts.path != '/github' or parts.fragment:
        raise RuntimeError('Unexpected webhook URL')
    # The marker cannot authorise a different destination authority.
    # Require Cloudflare's exact generated host, without userinfo or port.
    if URL_RE.fullmatch(parts.scheme + '://' + parts.netloc) is None:
        raise RuntimeError('Unexpected webhook host')
    if not parts.query:
        return None
    if not parts.query.startswith('cs_hook=') or not MARKER_RE.fullmatch(parts.query[8:]):
        raise RuntimeError('Unexpected webhook owner marker')
    return parts.query[8:]


def target_url(base, marker=None):
    return base.rstrip('/') + '/github' + ('?cs_hook=' + marker if marker else '')


def matching_hook(hooks, hook_id):
    selected = [h for h in hooks if str(h.get('id')) == str(hook_id)]
    if len(selected) != 1:
        raise RuntimeError('Owned hook identity missing or ambiguous')
    return selected[0]


def verify_hook(hook_id, target):
    """Independent authenticated GET, not merely trusting a POST/PATCH reply."""
    remote = api('GET', 'hooks/' + str(hook_id))
    if str(remote.get('id')) != str(hook_id) or remote.get('name') != 'web':
        raise RuntimeError('GitHub hook identity readback mismatch')
    if remote.get('active') is not True or remote.get('config', {}).get('url') != target:
        raise RuntimeError('GitHub hook URL or active readback mismatch')
    if sorted(remote.get('events', [])) != sorted(EVENTS):
        raise RuntimeError('GitHub hook event readback mismatch')
    config = remote.get('config')
    if (not isinstance(config, dict)
            or config.get('content_type') != 'json'
            or str(config.get('insecure_ssl')) != '0'):
        # Matching URL/events alone does not prove TLS and JSON delivery.
        # Reject a drifted remote hook even when no PATCH is otherwise needed.
        raise RuntimeError('GitHub webhook JSON/TLS contract readback mismatch')
    return remote


def read_intent(secret):
    if INTENT.is_symlink():
        raise RuntimeError('Unsafe webhook intent symlink')
    if not INTENT.exists():
        return None
    intent = json.loads(INTENT.read_text())
    if not isinstance(intent, dict) or intent.get('version') != 1:
        raise RuntimeError('Invalid durable webhook intent')
    marker = intent.get('marker')
    if not isinstance(marker, str) or not MARKER_RE.fullmatch(marker):
        raise RuntimeError('Invalid durable webhook marker')
    if intent.get('repo') != REPO or intent.get('target') is None:
        raise RuntimeError('Wrong durable webhook intent owner')
    if marker_of(intent['target']) != marker:
        raise RuntimeError('Durable webhook intent target mismatch')
    if intent.get('secret_sha256') != hashlib.sha256(secret.encode()).hexdigest():
        raise RuntimeError('Webhook secret rotated during uncertain creation')
    baseline = intent.get('baseline_ids')
    if not isinstance(baseline, list) or not all(isinstance(x, str) and x.isdecimal() for x in baseline):
        raise RuntimeError('Invalid prior hook inventory')
    return intent


def complete_hook_inventory(max_pages=10):
    """Bounded complete GitHub pagination; never adopt from a truncated page."""
    observed, ids = [], set()
    for page in range(1, max_pages + 1):
        chunk = api('GET', f'hooks?per_page=100&page={page}')
        if not isinstance(chunk, list) or len(chunk) > 100:
            raise RuntimeError('Invalid or unbounded webhook inventory page')
        for hook in chunk:
            ident = hook.get('id') if isinstance(hook, dict) else None
            if not isinstance(ident, int) or isinstance(ident, bool) or ident <= 0 or ident in ids:
                raise RuntimeError('Malformed or repeated hook identity in inventory')
            ids.add(ident)
            observed.append(hook)
        if len(chunk) < 100:
            return observed
    raise RuntimeError('Webhook inventory exceeds bounded pagination')



def bound_entry(hook_id, target):
    """An owner-private expected *full* URL, not a marker or wildcard host."""
    return {'version': 1, 'repo': REPO, 'hook_id': str(hook_id),
            'target': target, 'marker': marker_of(target)}


def binding_read():
    if BINDING.is_symlink():
        raise RuntimeError('Unsafe webhook binding symlink')
    if not BINDING.exists():
        return None
    if BINDING.stat().st_mode & 0o077:
        raise RuntimeError('Unsafe webhook binding permissions')
    record = json.loads(BINDING.read_text())
    if (not isinstance(record, dict) or record.get('version') != 1
            or record.get('repo') != REPO
            or not isinstance(record.get('hook_id'), str)
            or not record['hook_id'].isdecimal()
            or not isinstance(record.get('target'), str)
            or record.get('marker') != marker_of(record['target'])):
        raise RuntimeError('Invalid durable webhook binding')
    return record


def update_intent_read():
    if UPDATE_INTENT.is_symlink():
        raise RuntimeError('Unsafe webhook update intent symlink')
    if not UPDATE_INTENT.exists():
        return None
    if UPDATE_INTENT.stat().st_mode & 0o077:
        raise RuntimeError('Unsafe webhook update intent permissions')
    record = json.loads(UPDATE_INTENT.read_text())
    if (not isinstance(record, dict) or record.get('version') != 1
            or record.get('repo') != REPO
            or not isinstance(record.get('hook_id'), str)
            or not record['hook_id'].isdecimal()
            or not isinstance(record.get('previous_target'), str)
            or not isinstance(record.get('target'), str)
            or record['previous_target'] == record['target']
            or marker_of(record['previous_target']) != marker_of(record['target'])
            or record.get('marker') != marker_of(record['target'])):
        raise RuntimeError('Invalid durable webhook update intent')
    return record


def binding_assert(record, hook_id, remote_target):
    if (not record or record['hook_id'] != str(hook_id)
            or record['target'] != remote_target):
        raise RuntimeError('Webhook destination drift from owner-private binding')


def _reconcile_locked(url):
    secret = SECRET.read_text().strip()
    if len(secret) < 32:
        raise RuntimeError('Invalid webhook secret')
    # A tunnel endpoint is supplied only by Cloudflare's bounded startup
    # observer. Validate it again before any possible remote mutation.
    if URL_RE.fullmatch(url) is None:
        raise RuntimeError('Untrusted tunnel destination')
    hooks = complete_hook_inventory()
    if not isinstance(hooks, list):
        raise RuntimeError('Invalid GitHub webhook inventory')
    if STATE.is_symlink():
        raise RuntimeError('Unsafe webhook state symlink')
    hook_id = STATE.read_text().strip() if STATE.exists() else None
    binding = binding_read()
    pending_update = update_intent_read()
    intent = read_intent(secret)
    if pending_update and not hook_id:
        raise RuntimeError('Orphaned webhook update intent')
    if hook_id:
        if not hook_id.isdecimal():
            raise RuntimeError('Invalid owned webhook identity')
        hook = matching_hook(hooks, hook_id)
        current = hook.get('config', {}).get('url', '')
        current_marker = marker_of(current)
        if intent:
            # Only a complete exact creation intent may bootstrap missing
            # binding after a crash between verified POST and state writes.
            if (str(hook.get('id')) in intent['baseline_ids']
                    or current != intent['target']
                    or current_marker != intent['marker']):
                raise RuntimeError('Owned hook and pending intent disagree')
            verify_hook(hook_id, current)
            expected = bound_entry(hook_id, current)
            if binding and binding != expected:
                raise RuntimeError('Owner binding and creation intent disagree')
            if binding is None:
                durable_write(BINDING, json.dumps(expected, sort_keys=True))
                binding = expected
            durable_remove(INTENT)
        if binding is None:
            # A numeric ID alone cannot establish what URL the owner last
            # approved. Never silently trust a mutable remote webhook host.
            raise RuntimeError('Legacy hook lacks owner-approved URL binding')
        if pending_update:
            if (pending_update['hook_id'] != str(hook_id)
                    or binding['target'] not in (
                        pending_update['previous_target'], pending_update['target'])):
                raise RuntimeError('Webhook update ownership drift')
            if current == pending_update['target']:
                verify_hook(hook_id, current)
                expected = bound_entry(hook_id, current)
                durable_write(BINDING, json.dumps(expected, sort_keys=True))
                binding = expected
                durable_remove(UPDATE_INTENT)
                pending_update = None
            elif (current == pending_update['previous_target']
                  and binding['target'] == current):
                raise RuntimeError('Uncertain webhook PATCH: no unproved retry')
            else:
                raise RuntimeError('Webhook update destination tampering')
        binding_assert(binding, hook_id, current)
        current_marker = binding['marker']
    elif intent:
        if pending_update:
            raise RuntimeError('Update intent without an owned hook')
        # A lost POST response cannot authorise another POST. Adopt only the
        # exact target of the fsynced creation intent, with independent GET.
        candidates = [h for h in hooks if h.get('config', {}).get('url') == intent['target']]
        if len(candidates) != 1:
            raise RuntimeError('Uncertain webhook creation: no unique owned hook readback')
        hook = candidates[0]
        hook_id = str(hook.get('id', ''))
        if not hook_id.isdecimal() or hook_id in intent['baseline_ids']:
            raise RuntimeError('Unverifiable webhook creation ownership')
        verify_hook(hook_id, intent['target'])
        expected = bound_entry(hook_id, intent['target'])
        if binding and binding != expected:
            raise RuntimeError('Orphaned webhook binding does not match creation intent')
        if binding is None:
            durable_write(BINDING, json.dumps(expected, sort_keys=True))
        durable_write(STATE, hook_id)
        durable_remove(INTENT)
        current = intent['target']
        current_marker = intent['marker']
    else:
        if binding or pending_update:
            raise RuntimeError('Orphaned webhook binding without ownership receipt')
        # Do not create another hook if an unowned, identical destination is
        # already present; never infer ownership from URL equality alone.
        if any(h.get('config', {}).get('url') == target_url(url) for h in hooks):
            raise RuntimeError('Existing unowned matching hook')
        marker = secrets.token_hex(24)
        target = target_url(url, marker)
        if any(h.get('config', {}).get('url') == target for h in hooks):
            raise RuntimeError('Existing hook with generated marker')
        intent = {'version': 1, 'repo': REPO, 'target': target, 'marker': marker,
                  'secret_sha256': hashlib.sha256(secret.encode()).hexdigest(),
                  'baseline_ids': [str(h['id']) for h in hooks]}
        durable_write(INTENT, json.dumps(intent, sort_keys=True))
        # Creation is non-idempotent. Never automatically retry this POST.
        payload = {'name': 'web', 'active': True, 'events': EVENTS,
                   'config': {'url': target, 'content_type': 'json',
                              'insecure_ssl': '0', 'secret': secret}}
        created = api('POST', 'hooks', payload)
        hook_id = str(created.get('id', ''))
        if not hook_id.isdecimal():
            raise RuntimeError('Unverifiable webhook create response')
        verify_hook(hook_id, target)
        durable_write(BINDING, json.dumps(bound_entry(hook_id, target), sort_keys=True))
        durable_write(STATE, hook_id)
        durable_remove(INTENT)
        return int(hook_id)

    target = target_url(url, current_marker)
    if target == current:
        verify_hook(hook_id, target)
        return int(hook_id)
    # A PATCH has an external effect and can have an ambiguous response.
    # Persist exact old/new targets before issuing it. On crash or timeout,
    # readback may prove that it happened; do not blindly repeat it.
    update = {'version': 1, 'repo': REPO, 'hook_id': str(hook_id),
              'previous_target': current, 'target': target,
              'marker': current_marker}
    durable_write(UPDATE_INTENT, json.dumps(update, sort_keys=True))
    payload = {'name': 'web', 'active': True, 'events': EVENTS,
               'config': {'url': target, 'content_type': 'json',
                          'insecure_ssl': '0', 'secret': secret}}
    api('PATCH', 'hooks/' + hook_id, payload)
    verify_hook(hook_id, target)
    durable_write(BINDING, json.dumps(bound_entry(hook_id, target), sort_keys=True))
    durable_remove(UPDATE_INTENT)
    return int(hook_id)


def reconcile(url):
    with exclusive_reconcile():
        return _reconcile_locked(url)


def wait_for_tunnel_url(tunnel, timeout=45):
    """Deadline-safe stderr monitoring, including silent and unterminated lines."""
    if timeout <= 0 or tunnel.stderr is None:
        raise RuntimeError('Invalid tunnel observation contract')
    fd = tunnel.stderr.fileno()
    old_blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    deadline = time.monotonic() + timeout
    buf = b''
    try:
        while time.monotonic() < deadline:
            remaining = max(0, deadline - time.monotonic())
            ready, _, _ = select.select([fd], [], [], min(0.2, remaining))
            if ready:
                try:
                    chunk = os.read(fd, 16384)
                except BlockingIOError:
                    chunk = b''
                if chunk:
                    # At most the most recent bounded stderr bytes are kept.
                    buf = (buf + chunk)[-65536:]
                    match = URL_RE.search(buf.decode('utf8', errors='replace'))
                    if match:
                        return match.group(0)
                elif tunnel.poll() is not None:
                    break
            elif tunnel.poll() is not None:
                break
        raise RuntimeError('Tunnel URL unavailable before startup deadline')
    finally:
        os.set_blocking(fd, old_blocking)


def main():
    # Own the webhook for the entire tunnel lifetime; never allow a second
    # controller to retarget GitHub while the first tunnel is still running.
    with exclusive_reconcile():
        tunnel = subprocess.Popen([str(HOME / '.local/bin/cloudflared'), 'tunnel',
            '--no-autoupdate', '--loglevel', 'info', '--url', 'http://127.0.0.1:18763'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            url = wait_for_tunnel_url(tunnel, timeout=45)
            hook_id = _reconcile_locked(url)
            print(json.dumps({'hook_id': hook_id, 'relay': 'connected'}), flush=True)
            return tunnel.wait()
        finally:
            if tunnel.poll() is None:
                tunnel.terminate()
                try:
                    tunnel.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    tunnel.kill()


if __name__ == '__main__':
    sys.exit(main())
