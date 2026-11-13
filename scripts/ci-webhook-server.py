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
        # When a pinned direct-local release is installed, persist the
        # authenticated, fresh-source ordinary suite in the EXISTING fleet
        # before accepting the webhook delivery or requesting a wake.
        # This preserves a queued job across interruption after admission.
        local_claim = getattr(self.server, 'direct_local_claim', None)
        if local_claim is not None:
            try:
                repository = json.loads(payload)['repository']['full_name']
            except (KeyError, TypeError, ValueError):
                self.send_error(403)
                return
            if repository == 'AyobamiH/clawsweeper':
                # Match the existing delivery ledger BEFORE any queue effect.
                delivery_id = self.headers.get('X-GitHub-Delivery', '')
                if not ledger_module.DELIVERY_ID.fullmatch(delivery_id.lower()):
                    self.send_error(403)
                    return
                try:
                    claimed = local_claim(
                        body=payload, event_name=self.headers.get('X-GitHub-Event', ''),
                        signature=self.headers.get('X-Hub-Signature-256', ''),
                        delivery_id=self.headers.get('X-GitHub-Delivery', ''),
                        secret=self.server.secret)
                    if (claimed.get('fresh_provider_source_verified') is not True
                            or claimed.get('suite') != 'linux-node24'
                            or claimed.get('admission') not in ('queued', 'already_admitted')):
                        raise RuntimeError('unverified_direct_local_admission')
                except Exception:
                    # Never wake or mark a delivery accepted on failed admission.
                    self.send_error(503)
                    return
        # GitHub redelivers the same signed event with the same delivery UUID.
        # A durable owner-only claim must exist before requesting any effect.
        # Unknown outcomes remain pending; the independent CI poll timer
        # eventually discovers the exact GitHub state without replaying a wake.
        delivery_id = self.headers.get('X-GitHub-Delivery', '')
        event = self.headers.get('X-GitHub-Event', '')
        try:
            outcome = self.server.ledger.claim(delivery_id, event, payload)
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
        server.direct_local_claim = bridge.load_released_claim(Path(release_file))
    server.serve_forever()
