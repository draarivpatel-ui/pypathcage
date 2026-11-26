"""Tests for ZIP inspection and safe extraction."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pypathcage import (
    ArchiveLimits,
    ErrorCode,
    PathCageError,
    inspect_zip,
    safe_extract_zip,
)

from _helpers import make_zip


class ZipInspectTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_inspect_simple_zip(self):
        data = make_zip([("a.txt", b"hello")])
        report = inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(report.kind, "zip")
        self.assertEqual(report.member_count, 1)
        self.assertEqual(report.regular_files, 1)
        self.assertEqual(report.names, ["a.txt"])

    def test_inspect_from_path(self):
        path = self.root / "archive.zip"
        path.write_bytes(make_zip([("a.txt", b"x")]))
        report = inspect_zip(path, root=self.root)
        self.assertEqual(report.member_count, 1)

    def test_inspect_from_zipfile(self):
        buffer = io.BytesIO(make_zip([("a.txt", b"x")]))
        with zipfile.ZipFile(buffer) as zf:
            report = inspect_zip(zf, root=self.root)
        self.assertEqual(report.member_count, 1)

    def test_inspect_directory_entry(self):
        data = make_zip([("dir/", b"")])
        report = inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(report.directories, 1)

    def test_inspect_zip_slip(self):
        data = make_zip([("../evil.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_inspect_deep_zip_slip(self):
        data = make_zip([("a/b/../../../evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_zip(io.BytesIO(data), root=self.root)

    def test_inspect_absolute_member(self):
        data = make_zip([("/etc/passwd", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.ABSOLUTE_PATH)

    def test_inspect_windows_member(self):
        data = make_zip([("C:\\evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_zip(io.BytesIO(data), root=self.root)

    def test_inspect_nul_name(self):
        # zipfile truncates NUL bytes at read time; inject one on the live
        # ZipInfo so the inspector sees the exact hostile name.
        buffer = io.BytesIO(make_zip([("ab.txt", b"x")]))
        with zipfile.ZipFile(buffer) as zf:
            zf.infolist()[0].filename = "a\x00b.txt"
            with self.assertRaises(PathCageError) as ctx:
                inspect_zip(zf, root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.NUL_BYTE)

    def test_inspect_fullwidth_slash(self):
        data = make_zip([("a／b.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_inspect_reserved_name(self):
        data = make_zip([("CON.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_RESERVED_NAME)

    def test_inspect_trailing_dot(self):
        data = make_zip([("file.", b"x")])
        with self.assertRaises(PathCageError):
            inspect_zip(io.BytesIO(data), root=self.root)

    def test_inspect_case_collision(self):
        data = make_zip([("Readme.txt", b"x"), ("readme.TXT", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_inspect_duplicate_name_is_collision(self):
        data = make_zip([("a.txt", b"x"), ("a.txt", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_inspect_file_count_limit(self):
        data = make_zip([("a.txt", b"x"), ("b.txt", b"y")])
        limits = ArchiveLimits(max_files=1)
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_COUNT)

    def test_inspect_single_file_limit_header(self):
        data = make_zip([("a.txt", b"x" * 100)])
        limits = ArchiveLimits(max_file_bytes=10)
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_inspect_total_limit(self):
        data = make_zip([("a.txt", b"x" * 60), ("b.txt", b"y" * 60)])
        limits = ArchiveLimits(max_total_bytes=100)
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.TOTAL_TOO_LARGE)

    def test_inspect_compression_ratio(self):
        data = make_zip([("bomb.txt", b"A" * 100_000)])
        limits = ArchiveLimits(max_compression_ratio=2.0, max_file_bytes=1_000_000, max_total_bytes=1_000_000)
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.COMPRESSION_RATIO)

    def test_inspect_stored_large_allowed_at_default_ratio(self):
        data = make_zip([("file.txt", b"x" * 1000)], compression=zipfile.ZIP_STORED)
        report = inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(report.regular_files, 1)

    def test_as_dict(self):
        report = inspect_zip(io.BytesIO(make_zip([("a.txt", b"x")])), root=self.root)
        self.assertEqual(report.as_dict()["kind"], "zip")


class ZipExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "destination"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extract_simple_file(self):
        data = make_zip([("a.txt", b"hello")])
        report = safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(report.member_count, 1)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"hello")

    def test_extract_nested_file(self):
        data = make_zip([("sub/dir/a.txt", b"hello")])
        safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual((self.root / "sub" / "dir" / "a.txt").read_bytes(), b"hello")

    def test_extract_directory_entry(self):
        data = make_zip([("dir/", b"")])
        safe_extract_zip(io.BytesIO(data), self.root)
        self.assertTrue((self.root / "dir").is_dir())

    def test_extract_from_path(self):
        path = self.root.parent / "archive.zip"
        path.write_bytes(make_zip([("a.txt", b"x")]))
        safe_extract_zip(path, self.root)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"x")

    def test_extract_from_zipfile(self):
        buffer = io.BytesIO(make_zip([("a.txt", b"x")]))
        with zipfile.ZipFile(buffer) as zf:
            safe_extract_zip(zf, self.root)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"x")

    def test_extract_zip_slip_blocked(self):
        data = make_zip([("../evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)
        self.assertFalse((self.root.parent / "evil.txt").exists())

    def test_extract_backslash_slip_blocked(self):
        data = make_zip([("..\\evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)

    def test_extract_absolute_blocked(self):
        data = make_zip([("/tmp/evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)

    def test_extract_case_collision_blocked(self):
        data = make_zip([("A.txt", b"x"), ("a.txt", b"y")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)

    def test_extract_file_count_limit(self):
        data = make_zip([("a.txt", b"x"), ("b.txt", b"y")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root, limits=ArchiveLimits(max_files=1))

    def test_extract_single_file_limit_streamed(self):
        data = make_zip([("a.txt", b"x" * 1000)])
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root, limits=ArchiveLimits(max_file_bytes=10))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_extract_ratio_limit_streamed(self):
        data = make_zip([("bomb.txt", b"Z" * 200_000)])
        limits = ArchiveLimits(max_compression_ratio=2.0, max_file_bytes=10_000_000, max_total_bytes=10_000_000)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.COMPRESSION_RATIO)

    def test_extract_empty_archive(self):
        data = make_zip([])
        report = safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(report.member_count, 0)

    def test_extract_missing_destination_raises(self):
        data = make_zip([("a.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root / "missing")

    def test_extract_large_binary_roundtrip(self):
        payload = bytes(range(256)) * 100
        data = make_zip([("blob.bin", payload)])
        safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual((self.root / "blob.bin").read_bytes(), payload)

    def test_extract_multiple_files(self):
        data = make_zip([("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")])
        report = safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(report.regular_files, 3)

    def test_extract_total_limit_streamed(self):
        data = make_zip([("a.txt", b"x" * 60), ("b.txt", b"y" * 60)])
        limits = ArchiveLimits(max_total_bytes=100, max_compression_ratio=500.0)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.TOTAL_TOO_LARGE)


if __name__ == "__main__":
    unittest.main()
