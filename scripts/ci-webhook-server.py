"""Loopback-only webhook receiver for the existing local CI fleet.

Requires a separately provisioned HTTPS relay and a shared HMAC secret.
"""
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from importlib.machinery import SourceFileLoader

wakeup = SourceFileLoader('wakeup', str(Path(__file__).with_name('fleet_webhook_wakeup.py') if Path(__file__).name == 'fleet_webhook_server.py' else Path(__file__).with_name('ci-webhook-wakeup.py'))).load_module()
verify = wakeup.authorised

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/github':
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
        result = subprocess.run(('systemctl', '--user', 'start', '--no-block', 'local-ci-fleet.service'),
                                capture_output=True, timeout=5, check=False)
        self.send_response(202 if result.returncode == 0 else 503)
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
    server.serve_forever()
