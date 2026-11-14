"""Loopback-only webhook receiver for the existing local CI fleet.

Requires a separately provisioned HTTPS relay and a shared HMAC secret.
"""
import json
import os
import re
import subprocess
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from importlib.machinery import SourceFileLoader

wakeup = SourceFileLoader('wakeup', str(Path(__file__).with_name('fleet_webhook_wakeup.py') if Path(__file__).name == 'fleet_webhook_server.py' else Path(__file__).with_name('ci-webhook-wakeup.py'))).load_module()
verify = wakeup.authorised
ledger_module = SourceFileLoader('ci_webhook_deliveries', str(Path(__file__).with_name('ci-webhook-deliveries.py'))).load_module()

def needs_direct_local_claim(event, data):
    """Keep historical wake-only events out of ordinary-job admission.

    Only *provably ineligible* events bypass the direct-local path. Missing or
    malformed identity on a possibly eligible event must still fail closed in
    the authenticated provider/queue adapter, not silently become a wake.
    """
    if event == 'push':
        ref = data.get('ref')
        return not isinstance(ref, str) or ref == 'refs/heads/main'
    if event != 'pull_request':
        return False
    pr = data.get('pull_request')
    if not isinstance(pr, dict):
        return True
    if pr.get('draft') is True:
        return False
    for value, expected in (
        (pr.get('user', {}).get('login') if isinstance(pr.get('user'), dict) else None, 'AyobamiH'),
        (pr.get('head', {}).get('repo', {}).get('full_name')
         if isinstance(pr.get('head'), dict) and
         isinstance(pr['head'].get('repo'), dict) else None, 'AyobamiH/clawsweeper'),
        (pr.get('base', {}).get('ref') if isinstance(pr.get('base'), dict) else None, 'main'),
    ):
        if isinstance(value, str) and value != expected:
            return False
    return True


def unique_payload_object(pairs):
    """Do not let duplicate JSON keys change webhook trust classification."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('ambiguous_webhook_json')
        result[key] = value
    return result


def eligible_ordinary_shape(event, data):
    """Cheap fail-closed envelope check; fleet still owns provider GET/policy."""
    if event == 'push':
        return (data.get('ref') == 'refs/heads/main'
                and data.get('deleted') is False
                and data.get('forced') is False
                and isinstance(data.get('after'), str)
                and re.fullmatch(r'[0-9a-f]{40}', data['after']) is not None)
    if event != 'pull_request':
        return False
    pr = data.get('pull_request')
    if not isinstance(pr, dict) or data.get('action') not in (
            'opened', 'reopened', 'synchronize', 'ready_for_review'):
        return False
    head, base, user = pr.get('head'), pr.get('base'), pr.get('user')
    return (type(pr.get('number')) is int and 1 <= pr['number'] <= 999999999
            and pr.get('state') == 'open' and pr.get('draft') is False
            and isinstance(user, dict) and user.get('login') == 'AyobamiH'
            and isinstance(head, dict) and isinstance(base, dict)
            and isinstance(head.get('sha'), str)
            and re.fullmatch(r'[0-9a-f]{40}', head['sha']) is not None
            and isinstance(head.get('repo'), dict)
            and head['repo'].get('full_name') == 'AyobamiH/clawsweeper'
            and isinstance(base.get('repo'), dict)
            and base['repo'].get('full_name') == 'AyobamiH/clawsweeper'
            and base.get('ref') == 'main')


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # The random, non-authentication owner marker distinguishes a webhook
        # created before a crash. HMAC remains mandatory for every request.
        destination = urlsplit(self.path)
        if destination.path != '/github' or destination.fragment or (destination.query and
                not re.fullmatch(r'cs_hook=[a-f0-9]{48}', destination.query)):
            self.send_error(404)
            return
        size = self.headers.get('Content-Length', '')
        if not size.isdecimal() or int(size) > 65536:
            self.send_error(413)
            return
        payload = self.rfile.read(int(size))
        if self.headers.get('X-GitHub-Event') == 'ping' and wakeup.verified_signature(self.headers, payload, self.server.secret):
            self.send_response(200)
            self.end_headers()
            return
        if not verify(self.headers, payload, self.server.secret):
            self.send_error(403)
            return
        # The network-facing receiver can write only to its existing private
        # delivery journal. Never invoke the SQLite fleet claim from here:
        # the canonical fleet controller owns fleet.sqlite3/control.lock.
        ordinary_args = {}
        verify_ingress = getattr(self.server, 'direct_local_ingress_verify', None)
        if verify_ingress is not None:
            try:
                data = json.loads(payload, object_pairs_hook=unique_payload_object)
                repository = data['repository']['full_name']
            except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                self.send_error(403)
                return
            event_name = self.headers.get('X-GitHub-Event', '')
            if (repository == 'AyobamiH/clawsweeper'
                    and needs_direct_local_claim(event_name, data)):
                delivery_id = self.headers.get('X-GitHub-Delivery', '')
                if (not ledger_module.DELIVERY_ID.fullmatch(delivery_id.lower())
                        or not eligible_ordinary_shape(event_name, data)):
                    self.send_error(403)
                    return
                try:
                    if verify_ingress() is not True:
                        raise RuntimeError('unverified_owner_ingress_release')
                except Exception:
                    self.send_error(503)
                    return
                ordinary_args = {
                    'ordinary_signature': self.headers.get('X-Hub-Signature-256', ''),
                    'ordinary_secret': self.server.secret,
                }
        # GitHub redelivers the same signed event with the same delivery UUID.
        # A durable owner-only claim must exist before requesting any effect.
        # Unknown outcomes remain pending; the independent CI poll timer
        # eventually discovers the exact GitHub state without replaying a wake.
        delivery_id = self.headers.get('X-GitHub-Delivery', '')
        event = self.headers.get('X-GitHub-Event', '')
        try:
            outcome = self.server.ledger.claim(delivery_id, event, payload,
                                               **ordinary_args)
        except Exception:
            self.send_error(503)
            return
        if outcome == 'duplicate':
            self.send_response(200)
            self.end_headers()
            return
        if outcome != 'claimed':
            self.send_error(403 if outcome in ('invalid', 'mismatch') else 503)
            return
        try:
            result = subprocess.run(('systemctl', '--user', 'start', '--no-block', 'local-ci-fleet.service'),
                                    capture_output=True, timeout=5, check=False)
            if result.returncode != 0:
                self.send_error(503)
                return
            self.server.ledger.accept(delivery_id, event, payload)
        except Exception:
            # The POST effect can be uncertain; never auto-replay a wake.
            self.send_error(503)
            return
        self.send_response(202)
        self.end_headers()

    def log_message(self, *_):
        pass

if __name__ == '__main__':
    secret_file = Path(os.environ['FLEET_WEBHOOK_SECRET_FILE'])
    if secret_file.is_symlink() or secret_file.stat().st_mode & 0o077:
        raise RuntimeError('Unsafe webhook secret permissions')
    secret = secret_file.read_bytes().strip()
    if len(secret) < 32:
        raise RuntimeError('Webhook secret too short')
    server = ThreadingHTTPServer(('127.0.0.1', 18763), Handler)
    server.secret = secret
    server.ledger = ledger_module.DeliveryLedger(os.environ['FLEET_WEBHOOK_LEDGER_DIR'])
    # OFF unless the existing fleet owner installs an exact hash-pinned
    # release file; no separate receiver, queue, runner or scheduler.
    release_file = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')
    if release_file:
        sidecar = (Path(__file__).with_name('fleet_direct_local_receiver_integration.py')
                   if Path(__file__).name == 'fleet_webhook_server.py'
                   else Path(__file__).parent / 'ci' / 'direct_local_receiver_integration.py')
        bridge = SourceFileLoader('direct_local_receiver_integration', str(sidecar)).load_module()
        server.direct_local_ingress_verify = bridge.load_released_ingress(Path(release_file))
    server.serve_forever()
