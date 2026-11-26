"""Tests for TAR inspection and safe extraction, including CVE-2007-4559 vectors."""

from __future__ import annotations

import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pypathcage import (
    ArchiveLimits,
    ErrorCode,
    PathCageError,
    inspect_tar,
    safe_extract_tar,
)

from _helpers import has_symlink_support, make_tar


def _tar_with_member(member: tarfile.TarInfo, data: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        tf.addfile(member, io.BytesIO(data) if member.size else None)
    return buffer.getvalue()


class TarInspectTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_inspect_simple_tar(self):
        data = make_tar([("a.txt", b"hello")])
        report = inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(report.kind, "tar")
        self.assertEqual(report.member_count, 1)
        self.assertEqual(report.regular_files, 1)

    def test_inspect_from_path(self):
        path = self.root / "a.tar"
        path.write_bytes(make_tar([("a.txt", b"x")]))
        report = inspect_tar(path, root=self.root)
        self.assertEqual(report.member_count, 1)

    def test_inspect_from_tarfile(self):
        buffer = io.BytesIO(make_tar([("a.txt", b"x")]))
        with tarfile.open(fileobj=buffer, mode="r:") as tf:
            report = inspect_tar(tf, root=self.root)
        self.assertEqual(report.member_count, 1)

    def test_inspect_gzip_tar(self):
        data = make_tar([("a.txt", b"x")], mode="w:gz")
        report = inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(report.regular_files, 1)

    def test_inspect_tar_slip(self):
        data = make_tar([("../evil.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_inspect_deep_tar_slip(self):
        data = make_tar([("a/b/../../../evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_inspect_absolute_path(self):
        data = make_tar([("/etc/passwd", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.ABSOLUTE_PATH)

    def test_inspect_nul_name(self):
        # tarfile strips NUL bytes from the raw header; inject one on the
        # live TarInfo so the inspector sees the exact hostile name.
        buffer = io.BytesIO(make_tar([("ab.txt", b"x")]))
        with tarfile.open(fileobj=buffer, mode="r:") as tf:
            tf.getmembers()[0].name = "a\x00b.txt"
            with self.assertRaises(PathCageError) as ctx:
                inspect_tar(tf, root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.NUL_BYTE)

    def test_inspect_reserved_name(self):
        data = make_tar([("CON.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_RESERVED_NAME)

    def test_inspect_case_collision(self):
        data = make_tar([("File.txt", b"x"), ("file.TXT", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_inspect_file_count_limit(self):
        data = make_tar([("a", b"x"), ("b", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root, limits=ArchiveLimits(max_files=1))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_COUNT)

    def test_inspect_single_file_limit(self):
        data = make_tar([("a", b"x" * 100)])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root, limits=ArchiveLimits(max_file_bytes=10))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_inspect_total_limit(self):
        data = make_tar([("a", b"x" * 60), ("b", b"y" * 60)])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root, limits=ArchiveLimits(max_total_bytes=100))
        self.assertEqual(ctx.exception.code, ErrorCode.TOTAL_TOO_LARGE)

    def test_inspect_symlink_rejected_by_default(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "target.txt"
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_inspect_hardlink_rejected_by_default(self):
        member = tarfile.TarInfo("hard")
        member.type = tarfile.LNKTYPE
        member.linkname = "target.txt"
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_inspect_escaping_symlink_rejected(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../etc/passwd"
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_inspect_fifo_rejected(self):
        member = tarfile.TarInfo("pipe")
        member.type = tarfile.FIFOTYPE
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_MEMBER)

    def test_inspect_chr_device_rejected(self):
        member = tarfile.TarInfo("chr")
        member.type = tarfile.CHRTYPE
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_MEMBER)

    def test_inspect_blk_device_rejected(self):
        member = tarfile.TarInfo("blk")
        member.type = tarfile.BLKTYPE
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_inspect_links_allowed_when_opted_in(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "target.txt"
        data = _tar_with_member(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        report = inspect_tar(io.BytesIO(data), root=self.root, limits=limits)
        self.assertEqual(report.links, 1)

    def test_as_dict(self):
        report = inspect_tar(io.BytesIO(make_tar([("a", b"x")])), root=self.root)
        self.assertEqual(report.as_dict()["member_count"], 1)


class TarExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "destination"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extract_simple_file(self):
        data = make_tar([("a.txt", b"hello")])
        report = safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(report.member_count, 1)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"hello")

    def test_extract_nested_file(self):
        data = make_tar([("sub/dir/a.txt", b"hello")])
        safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual((self.root / "sub" / "dir" / "a.txt").read_bytes(), b"hello")

    def test_extract_directory_entry(self):
        member = tarfile.TarInfo("dir")
        member.type = tarfile.DIRTYPE
        data = _tar_with_member(member)
        safe_extract_tar(io.BytesIO(data), self.root)
        self.assertTrue((self.root / "dir").is_dir())

    def test_extract_from_path(self):
        path = self.root.parent / "a.tar"
        path.write_bytes(make_tar([("a.txt", b"x")]))
        safe_extract_tar(path, self.root)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"x")

    def test_extract_from_tarfile(self):
        buffer = io.BytesIO(make_tar([("a.txt", b"x")]))
        with tarfile.open(fileobj=buffer, mode="r:") as tf:
            safe_extract_tar(tf, self.root)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"x")

    def test_extract_tar_slip_blocked(self):
        data = make_tar([("../evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)
        self.assertFalse((self.root.parent / "evil.txt").exists())

    def test_extract_absolute_blocked(self):
        data = make_tar([("/tmp/evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)

    def test_extract_case_collision_blocked(self):
        data = make_tar([("A.txt", b"x"), ("a.txt", b"y")])
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)

    def test_extract_symlink_rejected_by_default(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "target"
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_extract_hardlink_rejected_by_default(self):
        member = tarfile.TarInfo("hard")
        member.type = tarfile.LNKTYPE
        member.linkname = "target"
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)

    def test_extract_escaping_symlink_rejected(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../etc/passwd"
        data = _tar_with_member(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root, limits=limits)

    def test_extract_absolute_symlink_target_rejected(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        data = _tar_with_member(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root, limits=limits)

    def test_extract_fifo_rejected(self):
        member = tarfile.TarInfo("pipe")
        member.type = tarfile.FIFOTYPE
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)

    def test_extract_device_rejected(self):
        member = tarfile.TarInfo("dev")
        member.type = tarfile.CHRTYPE
        data = _tar_with_member(member)
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root)

    def test_extract_single_file_limit_streamed(self):
        data = make_tar([("a", b"x" * 1000)])
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(data), self.root, limits=ArchiveLimits(max_file_bytes=10))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_extract_total_limit_streamed(self):
        data = make_tar([("a", b"x" * 60), ("b", b"y" * 60)])
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(data), self.root, limits=ArchiveLimits(max_total_bytes=100))
        self.assertEqual(ctx.exception.code, ErrorCode.TOTAL_TOO_LARGE)

    def test_extract_empty_archive(self):
        data = make_tar([])
        report = safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(report.member_count, 0)

    def test_extract_missing_destination_raises(self):
        data = make_tar([("a", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_tar(io.BytesIO(data), self.root / "missing")

    def test_extract_large_binary_roundtrip(self):
        payload = bytes(range(256)) * 100
        data = make_tar([("blob.bin", payload)])
        safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual((self.root / "blob.bin").read_bytes(), payload)

    def test_extract_multiple_files(self):
        data = make_tar([("a", b"a"), ("b", b"b"), ("c", b"c")])
        report = safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(report.regular_files, 3)

    @unittest.skipUnless(has_symlink_support(), "symlinks unsupported")
    def test_extract_symlink_allowed_inside_root(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "target"
        data = _tar_with_member(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        safe_extract_tar(io.BytesIO(data), self.root, limits=limits)
        self.assertTrue(os.path.islink(str(self.root / "link")))


if __name__ == "__main__":
    unittest.main()
