"""Additional adversarial vectors: spoofed headers, prefix confusion, deep links."""

from __future__ import annotations

import io
import os
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pypathcage import (
    ArchiveLimits,
    ErrorCode,
    PathCage,
    PathCageError,
    inspect_tar,
    inspect_zip,
    resolve_safe_path,
    safe_extract_tar,
    safe_extract_zip,
)

from _helpers import has_symlink_support, make_tar, make_zip


class PrefixConfusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "cage"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_prefix_sibling_path_rejected(self):
        sibling = self.base / "cage-evil"
        with self.assertRaises(PathCageError):
            resolve_safe_path(self.root, "../cage-evil/secret.txt")

    def test_prefix_sibling_contains_rejected(self):
        sibling = Path(str(self.root) + "-evil")
        self.assertFalse(PathCage(self.root).contains(sibling))

    def test_double_prefix_sibling_rejected(self):
        sibling = self.base / "cage-evil" / "deep"
        with self.assertRaises(PathCageError):
            resolve_safe_path(self.root, "../cage-evil/deep/file.txt")

    def test_legit_prefix_child_allowed(self):
        child = self.root / "cage-notes.txt"
        result = resolve_safe_path(self.root, "cage-notes.txt")
        self.assertEqual(result, child.resolve())


class ArchiveSyntaxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_zip_backslash_slip(self):
        data = make_zip([("..\\evil.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_zip_dotdot_inside_root_normalizes(self):
        data = make_zip([("a/../b.txt", b"x")])
        report = inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(report.member_count, 1)

    def test_zip_mixed_slash_slip(self):
        data = make_zip([("foo\\..\\..\\evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_zip(io.BytesIO(data), root=self.root)

    def test_tar_backslash_slip(self):
        data = make_tar([("..\\evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_zip_rtl_override(self):
        data = make_zip([("safe‮evil.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.BIDI_OVERRIDE)

    def test_tar_rtl_override(self):
        data = make_tar([("safe‮evil.txt", b"x")])
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_zip_ads_name(self):
        data = make_zip([("file.txt:hidden", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_ADS)

    def test_tar_ads_name(self):
        data = make_tar([("file.txt:hidden", b"x")])
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(data), root=self.root)

    def test_zip_case_collision_mixed_separators(self):
        data = make_zip([("dir/A.txt", b"x"), ("dir/a.txt", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_tar_case_collision_mixed_separators(self):
        data = make_tar([("dir/A.txt", b"x"), ("dir/a.txt", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_zip_empty_name(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            info = zipfile.ZipInfo("ab")
            zf.writestr(info, b"x")
            zf.infolist()[0].filename = ""
            with self.assertRaises(PathCageError):
                inspect_zip(zf, root=self.root)

    def test_invalid_archive_bytes(self):
        with self.assertRaises(Exception):
            inspect_zip(io.BytesIO(b"not a zip"), root=self.root)


class SpoofedHeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_streaming_writer_counts_actual_bytes_not_headers(self):
        """The extractor's write helper enforces limits on real stream bytes."""
        from pypathcage.archives import _write_stream

        sink = io.BytesIO()
        with self.assertRaises(PathCageError) as ctx:
            _write_stream(io.BytesIO(b"x" * 1000), sink, limit=100, label="a.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_zip_header_size_lie_is_rejected_before_extract(self):
        data = make_zip([("a.txt", b"x" * 1000)])
        buffer = io.BytesIO(data)
        with zipfile.ZipFile(buffer) as zf:
            zf.infolist()[0].file_size = 10_000_000
            limits = ArchiveLimits(max_file_bytes=100)
            with self.assertRaises(PathCageError) as ctx:
                safe_extract_zip(zf, self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_tar_header_size_lie_is_rejected_before_extract(self):
        data = make_tar([("a.txt", b"x")])
        buffer = io.BytesIO(data)
        with tarfile.open(fileobj=buffer, mode="r:") as tf:
            tf.getmembers()[0].size = 10_000_000
            limits = ArchiveLimits(max_file_bytes=100)
            with self.assertRaises(PathCageError) as ctx:
                safe_extract_tar(tf, self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)

    def test_compressed_bomb_rejected_by_stream_ratio(self):
        payload = b"\x00" * 1_000_000
        data = make_zip([("bomb.bin", payload)])
        limits = ArchiveLimits(max_compression_ratio=20.0, max_file_bytes=10_000_000, max_total_bytes=10_000_000)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.COMPRESSION_RATIO)

    def test_stored_large_file_with_high_ratio_allowed(self):
        payload = b"y" * 5000
        data = make_zip([("plain.bin", payload)], compression=zipfile.ZIP_STORED)
        report = safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(report.total_uncompressed, 5000)


@unittest.skipUnless(has_symlink_support(), "symlinks unsupported")
class DeepLinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.root = self.base / "out"
        self.root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extract_blocked_by_existing_escaping_symlink_directory(self):
        os.symlink(str(self.outside), str(self.root / "escape"))
        data = make_zip([("escape/payload.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)

    def test_extract_blocked_by_dangling_escaping_symlink(self):
        os.symlink(str(self.outside / "child"), str(self.root / "escape"))
        data = make_zip([("escape/deep/file.txt", b"x")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)

    def test_hardlink_escape_target_rejected_by_inspect(self):
        member = tarfile.TarInfo("hard")
        member.type = tarfile.LNKTYPE
        member.linkname = "../../etc/passwd"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tf:
            tf.addfile(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        with self.assertRaises(PathCageError):
            inspect_tar(io.BytesIO(buffer.getvalue()), root=self.root, limits=limits)

    def test_safe_symlink_inside_root_inspect(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "target.txt"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tf:
            tf.addfile(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        report = inspect_tar(io.BytesIO(buffer.getvalue()), root=self.root, limits=limits)
        self.assertEqual(report.links, 1)


if __name__ == "__main__":
    unittest.main()
