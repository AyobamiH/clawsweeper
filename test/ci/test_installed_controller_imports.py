"""Catch missing locally imported modules in the installed security controller.

Only tests the source-derived installation payload in a disposable directory.
No systemd, runner, GitHub API, or production controller effects are invoked.
"""
import ast
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[2]
CI_DIR = SOURCE_ROOT / "scripts" / "ci"
INSTALLER = CI_DIR / "install-selfhosted-controller.sh"


def payload_names():
    script = INSTALLER.read_text(encoding="utf-8")
    loops = re.findall(r"(?m)^for name in ([^;\n]+); do$", script)
    found = [line for line in loops if "self_hosted_executor.py" in line.split()]
    if len(found) != 1:
        raise AssertionError("installer_payload_declaration_missing_or_ambiguous")
    names = found[0].split()
    if len(names) != len(set(names)) or not names:
        raise AssertionError("installer_payload_duplicate_or_empty")
    if any(not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*\.py", name) for name in names):
        raise AssertionError("installer_payload_unsafe_name")
    return names


def local_imports(source):
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            name = node.module.split(".", 1)[0] + ".py"
            if (CI_DIR / name).is_file():
                names.add(name)
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".", 1)[0] + ".py"
                if (CI_DIR / name).is_file():
                    names.add(name)
    return names


class InstalledControllerImports(unittest.TestCase):
    def test_all_installed_imports_have_an_installed_dependency(self):
        names = set(payload_names())
        self.assertTrue({"self_hosted_executor.py", "self_hosted_policy.py",
                         "reconcile_selfhosted_receipt.py", "verify_codeql_release.py",
                         "e2e_evidence_vault.py"} <= names)
        for name in sorted(names):
            source = CI_DIR / name
            self.assertTrue(source.is_file(), name)
            with self.subTest(module=name):
                self.assertEqual(set(), local_imports(source) - names)

    def test_real_reconciler_imports_from_isolated_installed_payload(self):
        with tempfile.TemporaryDirectory(prefix="csw-installer-imports-") as root:
            installed = Path(root)
            for name in payload_names():
                destination = installed / name
                shutil.copyfile(CI_DIR / name, destination)
                destination.chmod(0o600)
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            test_script = (
                "import sys; sys.path.insert(0,sys.argv[1]);"
                "import reconcile_selfhosted_receipt as r;"
                "import verify_codeql_release as v;"
                "import e2e_evidence_vault as e;"
                "assert callable(r.reconcile);"
                "assert callable(v.verify_release);"
                "assert callable(v.verify_replacement_lineage);"
                "assert callable(e.verify_vault)"
            )
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            finished = subprocess.run(
                [sys.executable, "-I", "-B", "-c", test_script, root],
                capture_output=True, text=True, timeout=15, env=env,
            )
            self.assertEqual(finished.returncode, 0, finished.stderr)


if __name__ == "__main__":
    unittest.main()
