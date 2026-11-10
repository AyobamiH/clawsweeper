#!/usr/bin/env python3
"""Fail-closed actionlint 1.7.12 compatibility for GitHub's concurrency.queue.

Run the actual pinned actionlint over every supplied workflow. Its old schema
rejects six legitimate queue: max keys; accept only these six independently
checked, exact-location diagnostics. Do not blanket-ignore any errors.
GitHub workflow syntax: concurrency.queue (introduced 7 May 2026).
actionlint upstream: rhysd/actionlint#657 and #654.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Audited locations, not a broad ignore: adding another queue requires review.
EXPECTED_QUEUES = {
    ".github/workflows/cloudflare-operator-fixtures.yml": 1,
    ".github/workflows/cloudflare-repair-provision.yml": 1,
    ".github/workflows/repair-cluster-worker.yml": 1,
    ".github/workflows/repair-containment-smoke.yml": 1,
    ".github/workflows/sweep.yml": 2,
}
OLD_SCHEMA_MESSAGE = (
    'unexpected key "queue" for "concurrency" section. '
    'expected one of "cancel-in-progress", "group"'
)
QUEUE_LINE = re.compile(r"^( *)queue:\s*(\S+?)(?:\s+#.*)?\s*$")
CONCURRENCY_LINE = re.compile(r"^ *concurrency:\s*(?:#.*)?$")
GROUP_LINE = re.compile(r"^group:\s*(.+?)\s*$")
CANCEL_LINE = re.compile(r"^cancel-in-progress:\s*(\S+)(?:\s+#.*)?\s*$")


class CompatibilityFailure(ValueError):
    pass


def verified_queue_sites(root: Path) -> set[tuple[str, int, int]]:
    """Check source semantics before making any exception for old actionlint."""
    result: set[tuple[str, int, int]] = set()
    for relative, expected_count in EXPECTED_QUEUES.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise CompatibilityFailure(f"missing or symlinked reviewed workflow: {relative}")
        lines = path.read_text(encoding="utf-8").splitlines()
        count = 0
        for index, line in enumerate(lines):
            found = QUEUE_LINE.fullmatch(line)
            if not found:
                continue
            count += 1
            indent, value = len(found.group(1)), found.group(2)
            if value != "max":
                raise CompatibilityFailure(f"{relative}:{index + 1}: queue value not max")
            parent = index - 1
            while parent >= 0:
                prior = lines[parent]
                if prior.strip() and not prior.lstrip().startswith("#"):
                    prior_indent = len(prior) - len(prior.lstrip(" "))
                    if prior_indent < indent:
                        break
                parent -= 1
            if parent < 0 or not CONCURRENCY_LINE.fullmatch(lines[parent]):
                raise CompatibilityFailure(f"{relative}:{index + 1}: queue is not in concurrency")
            parent_indent = len(lines[parent]) - len(lines[parent].lstrip(" "))
            siblings: list[str] = []
            for sibling in lines[parent + 1:]:
                if not sibling.strip() or sibling.lstrip().startswith("#"):
                    continue
                child_indent = len(sibling) - len(sibling.lstrip(" "))
                if child_indent <= parent_indent:
                    break
                if child_indent == indent:
                    siblings.append(sibling.strip())
            if len([s for s in siblings if QUEUE_LINE.fullmatch(s)]) != 1:
                raise CompatibilityFailure(f"{relative}:{index + 1}: duplicate queue")
            if len([s for s in siblings if GROUP_LINE.fullmatch(s)]) != 1:
                raise CompatibilityFailure(f"{relative}:{index + 1}: missing/duplicate group")
            cancels = [CANCEL_LINE.fullmatch(s) for s in siblings if s.startswith("cancel-in-progress:")]
            if len(cancels) > 1 or any(m is None or m.group(1) != "false" for m in cancels):
                raise CompatibilityFailure(f"{relative}:{index + 1}: conflicting cancellation")
            result.add((relative, index + 1, indent + 1))
        if count != expected_count:
            raise CompatibilityFailure(
                f"{relative}: reviewed queue count {expected_count}, actual {count}"
            )
    return result


def adjudicate(
    sites: set[tuple[str, int, int]], exit_code: int, output: str, stderr: str
) -> str:
    """Interpret the unfiltered structured output; never suppress other errors."""
    if stderr.strip():
        raise CompatibilityFailure(f"unexpected actionlint stderr: {stderr[:400]}")
    try:
        errors = json.loads(output) if output.strip() else []
    except json.JSONDecodeError as exc:
        raise CompatibilityFailure("actionlint did not return valid diagnostic JSON") from exc
    if not isinstance(errors, list):
        raise CompatibilityFailure("actionlint diagnostic result is not a JSON list")
    if exit_code == 0 and not errors:
        return "ACTIONLINT_NATIVE_PASS"
    if exit_code != 1 or len(errors) != len(sites):
        raise CompatibilityFailure(f"actionlint exit={exit_code}, diagnostics={len(errors)}")
    observed: set[tuple[str, int, int]] = set()
    for error in errors:
        if not isinstance(error, dict) or (
            error.get("kind") != "syntax-check"
            or error.get("message") != OLD_SCHEMA_MESSAGE
            or not isinstance(error.get("filepath"), str)
            or not isinstance(error.get("line"), int)
            or not isinstance(error.get("column"), int)
            or not isinstance(error.get("snippet"), str)
            or error["snippet"].splitlines()[0].strip() != "queue: max"
        ):
            raise CompatibilityFailure(f"unrecognised actionlint diagnostic: {error!r}")
        observed.add((error["filepath"], error["line"], error["column"]))
    if observed != sites:
        raise CompatibilityFailure(f"diagnostic source mismatch: {observed ^ sites!r}")
    return "ACTIONLINT_1_7_12_REVIEWED_QUEUE_COMPAT_PASS"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actionlint", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--disable-shellcheck", action="store_true")
    parser.add_argument("workflows", nargs="+")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    try:
        files = {Path(value).as_posix() for value in args.workflows}
        discovered = {
            path.relative_to(root).as_posix()
            for path in (root / ".github/workflows").iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        }
        if files != discovered:
            raise CompatibilityFailure("workflow selection drift: all source workflows must be linted")
        if not set(EXPECTED_QUEUES).issubset(files):
            raise CompatibilityFailure("not all audited workflow files were supplied to actionlint")
        if any(not (root / path).is_file() or ".." in Path(path).parts for path in files):
            raise CompatibilityFailure("workflow file missing or escapes source tree")
        sites = verified_queue_sites(root)
        command = [str(args.actionlint.resolve()), "-format", "{{json .}}"]
        if args.disable_shellcheck:
            command.append("-shellcheck=")
        command.extend(sorted(files))
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=180)
        verdict = adjudicate(sites, completed.returncode, completed.stdout, completed.stderr)
        # Retain the actual unfiltered diagnostic JSON for a durable audit trail.
        if completed.stdout.strip():
            print("RAW_ACTIONLINT_DIAGNOSTICS=" + completed.stdout.strip())
        print(verdict)
        return 0
    except (CompatibilityFailure, OSError, subprocess.TimeoutExpired) as error:
        print("ACTIONLINT_FAIL_CLOSED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
