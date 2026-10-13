"""Repository integrity guards.

These tests catch the class of breakage that shipped when merge-conflict
markers were committed straight into ``yerscan.py`` (and ``README.md`` /
``.gitignore``).  A single stray ``<<<<<<< HEAD`` line made the scanner
unparseable, so every dashboard-initiated scan failed with a
``SyntaxError: invalid syntax`` reported back to the browser.

Run without privileges:
    python3 -m unittest discover -s tests -v
"""

import os
import py_compile
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARKERS = ("<<<<<<<", "=======", ">>>>>>>")
# Generated/vendored trees that are not part of the reviewed source.
EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}


def _tracked_files():
    """Return repo-relative paths of every file tracked by git."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise unittest.SkipTest("not a git checkout; cannot enumerate tracked files")
    return [line for line in result.stdout.splitlines() if line.strip()]


class TestNoConflictMarkers(unittest.TestCase):
    """No tracked source file may contain leftover merge-conflict markers."""

    def test_tracked_files_have_no_conflict_markers(self):
        offenders = []
        for relative in _tracked_files():
            path = os.path.join(ROOT, relative)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped in MARKERS or stripped == ">>>>>>> origin/main":
                    offenders.append(f"{relative}:{number}: {stripped}")
                elif stripped.startswith("<<<<<<< ") or stripped.startswith(">>>>>>> "):
                    offenders.append(f"{relative}:{number}: {stripped}")

        self.assertEqual(
            offenders,
            [],
            "Merge-conflict markers committed into tracked files:\n  "
            + "\n  ".join(offenders),
        )


class TestPythonSourcesCompile(unittest.TestCase):
    """Every source file must at least be parseable Python."""

    def test_all_sources_compile(self):
        failures = []
        with tempfile.TemporaryDirectory() as cache:
            bytecode = os.path.join(cache, "out.pyc")
            for relative in _tracked_files():
                if not relative.endswith(".py"):
                    continue
                parts = set(relative.split(os.sep))
                if parts & EXCLUDED_DIRS:
                    continue
                try:
                    py_compile.compile(
                        os.path.join(ROOT, relative),
                        cfile=bytecode,
                        doraise=True,
                    )
                except py_compile.PyCompileError as exc:
                    failures.append(f"{relative}: {exc}")
        self.assertEqual(
            failures,
            [],
            "Python sources failed to compile:\n  " + "\n  ".join(failures),
        )


class TestScannerEntryPoints(unittest.TestCase):
    """The CLI entry points the dashboard shells out to must import cleanly."""

    def test_yerscan_shim_delegates_to_pentrax(self):
        """yerscan.py fronts pentrax.py; app.py invokes the yerscan.py path."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "yerscan_shim_check", os.path.join(ROOT, "yerscan.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertTrue(callable(getattr(module, "main", None)))
        self.assertTrue(hasattr(module, "IS_ROOT"))

    def test_yerscan_cli_help_exits_cleanly(self):
        """`yerscan.py --help` must parse argparse, proving it is runnable."""
        result = subprocess.run(
            ["python3", os.path.join(ROOT, "yerscan.py"), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        for flag in ("--quick", "--fast", "--full", "--stealth"):
            self.assertIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()
