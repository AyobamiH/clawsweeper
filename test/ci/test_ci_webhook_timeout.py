"""Bounded webhook inventory and startup deadline tests (no GitHub/cloudflared calls)."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ci-webhook-relay.py"
spec = importlib.util.spec_from_file_location("relay_deadline", SCRIPT)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class PagedInventoryTests(unittest.TestCase):
    def test_all_pages_scanned_for_late_owned_hook(self):
        calls = []
        def fake_api(method, path, body=None):
            calls.append(path)
            page = int(path.rsplit("=", 1)[1])
            return [{"id": n} for n in range(1, 101)] if page == 1 else [{"id": 101}]
        with patch.object(relay, "api", side_effect=fake_api):
            hooks = relay.complete_hook_inventory()
        self.assertEqual(len(hooks), 101)
        self.assertEqual(hooks[-1]["id"], 101)
        self.assertEqual(len(calls), 2)

    def test_repeated_or_truncated_identity_fails_closed(self):
        def fake_api(method, path, body=None):
            page = int(path.rsplit("=", 1)[1])
            return [{"id": n} for n in range(1, 101)] if page == 1 else [{"id": 1}]
        with patch.object(relay, "api", side_effect=fake_api):
            with self.assertRaisesRegex(RuntimeError, "repeated"):
                relay.complete_hook_inventory()
        with patch.object(relay, "api", return_value=[{"id": i} for i in range(1, 101)]):
            with self.assertRaisesRegex(RuntimeError, "bounded pagination"):
                relay.complete_hook_inventory(max_pages=1)
        with patch.object(relay, "api", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Invalid"):
                relay.complete_hook_inventory()

    def test_final_complete_page_requires_confirming_empty_page(self):
        calls = []
        def fake_api(method, path, body=None):
            calls.append(path)
            return [{"id": n} for n in range(1, 101)] if len(calls) == 1 else []
        with patch.object(relay, "api", side_effect=fake_api):
            self.assertEqual(len(relay.complete_hook_inventory()), 100)
        self.assertEqual(len(calls), 2)


class StartupDeadlineTests(unittest.TestCase):
    def run_tunnel(self, code, seconds):
        p = subprocess.Popen(
            [sys.executable, "-u", "-c", code],
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True,
        )
        start = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                relay.wait_for_tunnel_url(p, timeout=seconds)
            self.assertLess(time.monotonic() - start, seconds + 0.45)
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=1)
            if p.stderr:
                p.stderr.close()

    def test_silent_process_has_real_deadline(self):
        self.run_tunnel("import time; time.sleep(2)", 0.25)

    def test_unterminated_line_does_not_defeat_deadline(self):
        self.run_tunnel(
            "import sys,time; sys.stderr.write('partial tunnel output');sys.stderr.flush();time.sleep(2)",
            0.3,
        )

    def test_valid_url_without_newline_is_detectable(self):
        p = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import sys,time;sys.stderr.write('tunnel URL https://proof-123.trycloudflare.com');sys.stderr.flush();time.sleep(2)"],
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True,
        )
        try:
            self.assertEqual(relay.wait_for_tunnel_url(p, timeout=0.9),
                             "https://proof-123.trycloudflare.com")
        finally:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=1)
            p.stderr.close()


if __name__ == "__main__":
    unittest.main()
