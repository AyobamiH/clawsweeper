import hashlib
import hmac
import importlib.util
import json
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'ci-webhook-wakeup.py'
spec = importlib.util.spec_from_file_location('ci_webhook', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.secret = b's' * 40
        self.payload = json.dumps({'repository': {'full_name': 'AyobamiH/clawsweeper'}, 'after': 'a' * 40}).encode()
        self.headers = {'X-GitHub-Event': 'push', 'X-Hub-Signature-256': 'sha256=' + hmac.new(self.secret, self.payload, hashlib.sha256).hexdigest()}

    def test_valid(self):
        self.assertTrue(module.authorised(self.headers, self.payload, self.secret))

    def test_bad_signature(self):
        self.assertFalse(module.authorised({**self.headers, 'X-Hub-Signature-256': 'sha256=' + '0'*64}, self.payload, self.secret))

    def test_modified_payload(self):
        self.assertFalse(module.authorised(self.headers, self.payload+b' ', self.secret))

    def test_wrong_repo(self):
        payload = json.dumps({'repository': {'full_name': 'attacker/repo'}, 'after': 'a'*40}).encode()
        headers = {**self.headers, 'X-Hub-Signature-256': 'sha256=' + hmac.new(self.secret,payload,hashlib.sha256).hexdigest()}
        self.assertFalse(module.authorised(headers,payload,self.secret))

    def test_oversized(self):
        self.assertFalse(module.authorised(self.headers,b'x'*65537,self.secret))

    def test_unapproved_event(self):
        self.assertFalse(module.authorised({**self.headers,'X-GitHub-Event':'workflow_dispatch'},self.payload,self.secret))

if __name__ == '__main__':
    unittest.main()
