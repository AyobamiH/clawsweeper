"""Recoverable quick-tunnel relay for the existing local CI wake-up receiver.

Uses the GitHub API to maintain a dedicated hook; never alters other hooks.
Quick tunnels are temporary: this controller reconciles the hook after restart.
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import time

HOME = pathlib.Path.home()
ROOT = HOME / '.local/share/local-ci'
SECRET = ROOT / 'secrets/webhook-hmac'
STATE = ROOT / 'secrets/webhook-hook-id'
URL_RE = re.compile(r'https://[a-z0-9-]+\.trycloudflare\.com')
REPO = 'AyobamiH/clawsweeper'


def api(method, path, data=None):
    command = ['gh', 'api', '--method', method, 'repos/' + REPO + '/' + path]
    if data is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('GitHub API request failed')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def reconcile(url):
    secret = SECRET.read_text().strip()
    if len(secret) < 32:
        raise RuntimeError('Invalid webhook secret')
    hooks = api('GET', 'hooks')
    configured = [h for h in hooks if h.get('config', {}).get('url') == url + '/github']
    if len(configured) > 1:
        raise RuntimeError('Ambiguous matching hooks')
    hook_id = STATE.read_text().strip() if STATE.exists() else None
    if hook_id and not any(str(h.get('id')) == hook_id for h in hooks):
        raise RuntimeError('Owned hook identity missing: refusing replacement')
    payload = {'name': 'web', 'active': True, 'events': ['push', 'pull_request'],
               'config': {'url': url + '/github', 'content_type': 'json',
                          'insecure_ssl': '0', 'secret': secret}}
    if hook_id:
        result = api('PATCH', 'hooks/' + hook_id, payload)
    else:
        if configured:
            raise RuntimeError('Existing unowned matching hook')
        result = api('POST', 'hooks', payload)
        fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(str(result['id']))
    if result.get('active') is not True or result.get('config', {}).get('url') != url + '/github':
        raise RuntimeError('GitHub hook readback mismatch')
    return result['id']


def main():
    tunnel = subprocess.Popen([str(HOME / '.local/bin/cloudflared'), 'tunnel',
        '--no-autoupdate', '--loglevel', 'info', '--url', 'http://127.0.0.1:18763'],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        deadline = time.monotonic() + 45
        url = None
        while time.monotonic() < deadline and tunnel.poll() is None:
            line = tunnel.stderr.readline()
            match = URL_RE.search(line)
            if match:
                url = match.group(0)
                break
        if not url:
            raise RuntimeError('Tunnel URL unavailable')
        hook_id = reconcile(url)
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
