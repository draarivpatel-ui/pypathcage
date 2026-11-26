"""Tests for the ``python3 -m pypathcage inspect`` command."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pypathcage.__main__ import main

from _helpers import make_tar, make_zip


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, *argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_help_returns_two(self):
        code, out, _ = self._run()
        self.assertEqual(code, 2)
        self.assertIn("usage", out)

    def test_inspect_valid_zip(self):
        path = self.root / "a.zip"
        path.write_bytes(make_zip([("a.txt", b"hello")]))
        code, out, err = self._run("inspect", str(path))
        self.assertEqual(code, 0)
        self.assertIn("kind: zip", out)
        self.assertIn("a.txt", out)

    def test_inspect_valid_tar(self):
        path = self.root / "a.tar"
        path.write_bytes(make_tar([("a.txt", b"hello")]))
        code, out, _ = self._run("inspect", str(path))
        self.assertEqual(code, 0)
        self.assertIn("kind: tar", out)

    def test_inspect_valid_targz(self):
        path = self.root / "a.tar.gz"
        path.write_bytes(make_tar([("a.txt", b"hello")], mode="w:gz"))
        code, out, _ = self._run("inspect", str(path))
        self.assertEqual(code, 0)

    def test_inspect_json_output(self):
        path = self.root / "a.zip"
        path.write_bytes(make_zip([("a.txt", b"x")]))
        code, out, _ = self._run("inspect", str(path), "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["kind"], "zip")
        self.assertEqual(payload["names"], ["a.txt"])

    def test_inspect_zip_slip_exit_one(self):
        path = self.root / "evil.zip"
        path.write_bytes(make_zip([("../evil.txt", b"x")]))
        code, out, err = self._run("inspect", str(path))
        self.assertEqual(code, 1)
        self.assertIn("traversal", err)

    def test_inspect_tar_slip_exit_one(self):
        path = self.root / "evil.tar"
        path.write_bytes(make_tar([("../evil.txt", b"x")]))
        code, _, err = self._run("inspect", str(path))
        self.assertEqual(code, 1)
        self.assertIn("traversal", err)

    def test_inspect_unknown_format_exit_one(self):
        path = self.root / "random.bin"
        path.write_bytes(b"not an archive")
        code, _, err = self._run("inspect", str(path))
        self.assertEqual(code, 1)
        self.assertIn("invalid_archive", err)

    def test_inspect_custom_limits(self):
        path = self.root / "a.zip"
        path.write_bytes(make_zip([("a.txt", b"x"), ("b.txt", b"y")]))
        code, _, err = self._run("inspect", str(path), "--max-files", "1")
        self.assertEqual(code, 1)
        self.assertIn("file_count", err)

    def test_inspect_ratio_limit(self):
        path = self.root / "bomb.zip"
        path.write_bytes(make_zip([("bomb.txt", b"A" * 100_000)]))
        code, _, err = self._run(
            "inspect", str(path), "--max-ratio", "2",
            "--max-file-bytes", "1000000", "--max-total-bytes", "1000000",
        )
        self.assertEqual(code, 1)
        self.assertIn("compression_ratio", err)

    def test_inspect_missing_file_exit_one(self):
        code, _, err = self._run("inspect", str(self.root / "missing.zip"))
        self.assertEqual(code, 1)

    def test_module_entry_point(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [sys.executable, "-m", "pypathcage", "--help"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage", result.stdout)

    def test_module_entry_point_inspect(self):
        path = self.root / "a.zip"
        path.write_bytes(make_zip([("a.txt", b"hello")]))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [sys.executable, "-m", "pypathcage", "inspect", str(path), "--json"],
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["kind"], "zip")


if __name__ == "__main__":
    unittest.main()
