"""Regression tests from the L1333 filesystem and archive red-team audit."""

from __future__ import annotations

import io
import os
import stat
import sys
import tarfile
import tempfile
import unicodedata
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
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
from pypathcage.__main__ import main
from pypathcage.core import sanitize_filename

from _helpers import has_symlink_support, make_tar, make_zip


def _tar_with_member(member: tarfile.TarInfo, data: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        tf.addfile(member, io.BytesIO(data) if member.size else None)
    return buffer.getvalue()


def _tar_with_members(members) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        for member, data in members:
            tf.addfile(member, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def _plain_tar(name: str, data: bytes = b"") -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    return member


class DuplicateNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_zip_alias_spellings_collide(self):
        variants = [
            [("a//b.txt", b"1"), ("a/b.txt", b"2")],
            [("./evil.txt", b"1"), ("evil.txt", b"2")],
            [("a/./b.txt", b"1"), ("a/b.txt", b"2")],
            [("a\\b.txt", b"1"), ("a/b.txt", b"2")],
        ]
        for entries in variants:
            with self.subTest(entries=entries):
                with self.assertRaises(PathCageError) as ctx:
                    inspect_zip(io.BytesIO(make_zip(entries)), root=self.root)
                self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_tar_alias_spellings_collide(self):
        variants = [
            [("a//b.txt", b"1"), ("a/b.txt", b"2")],
            [("./evil.txt", b"1"), ("evil.txt", b"2")],
            [("a/./b.txt", b"1"), ("a/b.txt", b"2")],
        ]
        for entries in variants:
            with self.subTest(entries=entries):
                with self.assertRaises(PathCageError) as ctx:
                    inspect_tar(io.BytesIO(make_tar(entries)), root=self.root)
                self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_zip_directory_and_file_same_key(self):
        data = make_zip([("dir/", b""), ("dir", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_zip_nfc_nfd_collision(self):
        composed = unicodedata.normalize("NFC", "café.txt")
        decomposed = unicodedata.normalize("NFD", "café.txt")
        self.assertNotEqual(composed, decomposed)
        data = make_zip([(composed, b"1"), (decomposed, b"2")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_tar_nfc_nfd_collision(self):
        composed = unicodedata.normalize("NFC", "café.txt")
        decomposed = unicodedata.normalize("NFD", "café.txt")
        data = make_tar([(composed, b"1"), (decomposed, b"2")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_NAME)

    def test_alias_collision_extract_writes_nothing(self):
        data = make_zip([("./e.txt", b"1"), ("e.txt", b"2")])
        with self.assertRaises(PathCageError):
            safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(list(self.root.iterdir()), [])


class ZipMemberTypeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _symlink_zip(self) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
        return buffer.getvalue()

    def test_zip_symlink_member_rejected_by_inspect(self):
        data = self._symlink_zip()
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_zip_symlink_member_rejected_by_extract(self):
        data = self._symlink_zip()
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)
        self.assertFalse(os.path.lexists(str(self.root / "link")))

    def _encrypted_zip(self) -> bytes:
        data = bytearray(make_zip([("a.txt", b"x")]))
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        data[local + 6] |= 0x1
        data[central + 8] |= 0x1
        return bytes(data)

    def test_encrypted_zip_member_rejected_by_inspect(self):
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(self._encrypted_zip()), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_MEMBER)

    def test_encrypted_zip_member_rejected_by_extract(self):
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(self._encrypted_zip()), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNSUPPORTED_MEMBER)


class PartialWriteCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_zip_bad_crc_leaves_no_partial_file(self):
        data = bytearray(make_zip([("a.txt", b"hello world" * 1000)]))
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        data[local + 14:local + 18] = b"\x00\x00\x00\x00"
        data[central + 16:central + 20] = b"\x00\x00\x00\x00"
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(bytes(data)), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)
        self.assertFalse(os.path.lexists(str(self.root / "a.txt")))

    def test_zip_zero_compress_size_rejected_and_cleaned(self):
        data = bytearray(make_zip([("bomb.bin", b"\x00" * 100_000)]))
        central = data.find(b"PK\x01\x02")
        data[central + 20:central + 24] = b"\x00\x00\x00\x00"
        limits = ArchiveLimits(max_compression_ratio=2.0, max_file_bytes=10_000_000, max_total_bytes=10_000_000)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(bytes(data)), self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)
        self.assertFalse(os.path.lexists(str(self.root / "bomb.bin")))

    def test_zip_understated_file_size_is_typed_and_cleaned(self):
        data = bytearray(make_zip([("big.bin", b"x" * 200_000)]))
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        data[local + 22:local + 26] = (1).to_bytes(4, "little")
        data[central + 24:central + 28] = (1).to_bytes(4, "little")
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(bytes(data)), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)
        self.assertFalse(os.path.lexists(str(self.root / "big.bin")))

    def test_zip_declared_size_limit_leaves_no_file(self):
        buffer = io.BytesIO(make_zip([("a.txt", b"x" * 1000)]))
        with zipfile.ZipFile(buffer) as zf:
            zf.infolist()[0].file_size = 10_000_000
            with self.assertRaises(PathCageError) as ctx:
                safe_extract_zip(zf, self.root, limits=ArchiveLimits(max_file_bytes=100))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)
        self.assertFalse(os.path.lexists(str(self.root / "a.txt")))

    def test_tar_truncated_member_leaves_no_partial_file(self):
        data = make_tar([("a.bin", b"z" * 10_000), ("b.txt", b"x")])
        truncated = data[: 512 + 5000]
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(truncated), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)
        self.assertFalse(os.path.lexists(str(self.root / "a.bin")))

    def test_tar_truncated_member_inspect_is_typed(self):
        data = make_tar([("a.bin", b"z" * 10_000), ("b.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(data[: 512 + 5000]), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)

    def test_tar_declared_size_limit_leaves_no_file(self):
        buffer = io.BytesIO(make_tar([("a.txt", b"x")]))
        with tarfile.open(fileobj=buffer, mode="r:") as tf:
            tf.getmembers()[0].size = 10_000_000
            with self.assertRaises(PathCageError) as ctx:
                safe_extract_tar(tf, self.root, limits=ArchiveLimits(max_file_bytes=100))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)
        self.assertFalse(os.path.lexists(str(self.root / "a.txt")))

    def test_zip_file_prefix_conflict_is_typed_error(self):
        data = make_zip([("a", b"x"), ("a/b", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_zip(io.BytesIO(data), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)

    def test_tar_file_prefix_conflict_is_typed_error(self):
        data = make_tar([("a", b"x"), ("a/b", b"y")])
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)


class TolerantLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tar_dot_root_entry_allowed(self):
        directory = tarfile.TarInfo(".")
        directory.type = tarfile.DIRTYPE
        data = _tar_with_members([(directory, b""), (_plain_tar("./a.txt", b"x"), b"x")])
        report = safe_extract_tar(io.BytesIO(data), self.root)
        self.assertEqual(report.member_count, 2)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"x")

    def test_zip_dot_directory_entry_allowed(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr(zipfile.ZipInfo("./"), b"")
        report = safe_extract_zip(io.BytesIO(buffer.getvalue()), self.root)
        self.assertEqual(report.member_count, 1)

    def test_tar_dot_file_member_rejected(self):
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(make_tar([(".", b"x")])), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)

    def test_zip_dot_file_member_rejected(self):
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(make_zip([(".", b"x")])), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)


@unittest.skipUnless(has_symlink_support(), "symlinks unsupported")
class TarLinkResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_relative_link_target_resolves_to_real_location(self):
        directory = tarfile.TarInfo("sub")
        directory.type = tarfile.DIRTYPE
        link = tarfile.TarInfo("sub/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../target.txt"
        data = _tar_with_members(
            [(_plain_tar("target.txt", b"T"), b"T"), (directory, b""), (link, b"")]
        )
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        safe_extract_tar(io.BytesIO(data), self.root, limits=limits)
        link_path = self.root / "sub" / "link"
        self.assertTrue(link_path.is_symlink())
        self.assertEqual(os.readlink(str(link_path)), "../target.txt")
        self.assertEqual(os.path.realpath(str(link_path)), str((self.root / "target.txt").resolve()))

    def test_relative_link_target_escape_still_blocked(self):
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        with self.assertRaises(PathCageError) as ctx:
            safe_extract_tar(io.BytesIO(_tar_with_member(link)), self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)


class ArchiveLimitTests(unittest.TestCase):
    def test_nan_ratio_rejected(self):
        with self.assertRaises(ValueError):
            ArchiveLimits(max_compression_ratio=float("nan"))

    def test_infinite_ratio_rejected(self):
        with self.assertRaises(ValueError):
            ArchiveLimits(max_compression_ratio=float("inf"))

    def test_negative_limits_rejected(self):
        with self.assertRaises(ValueError):
            ArchiveLimits(max_files=-1)
        with self.assertRaises(ValueError):
            ArchiveLimits(max_total_bytes=-1)

    def test_tar_member_count_bounded(self):
        entries = [("f{0}".format(i), b"x") for i in range(200)]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PathCageError) as ctx:
                inspect_tar(io.BytesIO(make_tar(entries)), root=Path(directory), limits=ArchiveLimits(max_files=5))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_COUNT)


class CliLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "a.zip"
        self.path.write_bytes(make_zip([("a.txt", b"x")]))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, *argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_negative_max_files_is_usage_error(self):
        code, _, err = self._run("inspect", str(self.path), "--max-files", "-1")
        self.assertEqual(code, 2)
        self.assertIn("usage", err)

    def test_nan_ratio_is_usage_error(self):
        code, _, err = self._run("inspect", str(self.path), "--max-ratio", "nan")
        self.assertEqual(code, 2)
        self.assertIn("usage", err)


class NfkcLookalikeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_small_reverse_solidus_rejected(self):
        with self.assertRaises(PathCageError) as ctx:
            resolve_safe_path(self.root, "a﹨b")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_small_colon_rejected(self):
        with self.assertRaises(PathCageError) as ctx:
            resolve_safe_path(self.root, "a﹕b")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_small_reverse_solidus_rejected_in_archive_name(self):
        data = make_zip([("a﹨b.txt", b"x")])
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(data), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_fullwidth_reserved_name_rejected(self):
        fullwidth_con = "ＣＯＮ.txt"
        with self.assertRaises(PathCageError) as ctx:
            resolve_safe_path(self.root, fullwidth_con)
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)
        self.assertEqual(sanitize_filename(fullwidth_con), "unnamed")

    def test_ellipsis_filename_is_not_over_blocked(self):
        name = "note…txt"
        self.assertEqual(sanitize_filename(name), name)
        self.assertEqual(resolve_safe_path(self.root, name), (self.root / name).resolve())

    def test_sanitize_replaces_nfkc_separators(self):
        self.assertNotIn("﹨", sanitize_filename("a﹨b"))
        self.assertNotIn("﹕", sanitize_filename("a﹕b"))

    def test_sanitize_truncation_reserved_name_falls_back(self):
        self.assertEqual(sanitize_filename("CONSOLE", max_length=3), "unnamed")


@unittest.skipUnless(has_symlink_support(), "symlinks unsupported")
class AbsoluteSymlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "cage"
        self.root.mkdir()
        self.inner = self.root / "inner"
        self.inner.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_absolute_candidate_through_in_root_symlink_rejected(self):
        os.symlink(str(self.inner), str(self.root / "lnk"))
        cage = PathCage(self.root, allow_absolute=True)
        with self.assertRaises(PathCageError) as ctx:
            cage.resolve(str(self.root / "lnk" / "file.txt"))
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_absolute_plain_path_still_allowed(self):
        target = self.root / "plain.txt"
        target.write_text("x")
        cage = PathCage(self.root, allow_absolute=True)
        self.assertEqual(cage.resolve(str(target)), target.resolve())

    @unittest.skipUnless(os.path.isdir("/private/tmp"), "no /private/tmp")
    def test_private_tmp_ancestor_symlink_escape(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            base = Path(directory)
            root = base / "cage"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            os.symlink(str(outside), str(root / "escape"))
            with self.assertRaises(PathCageError) as ctx:
                PathCage(root).resolve("escape/secret.txt")
            self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)
            strict = PathCage(root, no_symlinks=False)
            with self.assertRaises(PathCageError) as ctx:
                strict.resolve("escape/secret.txt")
            self.assertEqual(ctx.exception.code, ErrorCode.OUTSIDE_ROOT)


class RootContainmentTests(unittest.TestCase):
    @unittest.skipUnless(os.sep == "/", "POSIX separator only")
    def test_root_separator_contains_absolute_paths(self):
        cage = PathCage("/")
        self.assertTrue(cage.contains("/etc"))
        self.assertEqual(
            PathCage("/", allow_absolute=True).resolve("/etc"),
            Path("/etc").resolve(),
        )


class ModeBitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "out"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tar_setuid_bit_not_preserved(self):
        member = _plain_tar("suid", b"x")
        member.mode = 0o4777
        safe_extract_tar(io.BytesIO(_tar_with_member(member, b"x")), self.root)
        mode = stat.S_IMODE(os.lstat(str(self.root / "suid")).st_mode)
        self.assertFalse(mode & stat.S_ISUID)
        self.assertFalse(mode & stat.S_ISGID)

    def test_zip_setuid_bits_not_preserved(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            info = zipfile.ZipInfo("suid")
            info.external_attr = 0o4777 << 16
            zf.writestr(info, b"x")
        safe_extract_zip(io.BytesIO(buffer.getvalue()), self.root)
        mode = stat.S_IMODE(os.lstat(str(self.root / "suid")).st_mode)
        self.assertFalse(mode & stat.S_ISUID)
        self.assertFalse(mode & stat.S_ISGID)


class PaxHeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pax_path_override_is_validated(self):
        buffer = io.BytesIO()
        member = _plain_tar("../evil.txt", b"x")
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(buffer.getvalue()), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_pax_linkpath_override_is_validated(self):
        buffer = io.BytesIO()
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "safe"
        member.pax_headers = {"linkpath": "../../etc/passwd"}
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(member)
        limits = ArchiveLimits(no_symlinks=False, allow_links=True)
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(buffer.getvalue()), root=self.root, limits=limits)
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_long_pax_name_still_extracts(self):
        name = "d/" + "x" * 150 + ".txt"
        buffer = io.BytesIO()
        member = _plain_tar(name, b"x")
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(member, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as directory:
            report = safe_extract_tar(io.BytesIO(buffer.getvalue()), Path(directory))
            self.assertEqual(report.member_count, 1)
            self.assertTrue((Path(directory) / name).is_file())

    def test_pax_size_override_is_enforced(self):
        buffer = io.BytesIO()
        member = _plain_tar("a.txt", b"x" * 50)
        member.pax_headers = {"size": "1000"}
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(member, io.BytesIO(b"x" * 50))
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(buffer.getvalue()), root=self.root, limits=ArchiveLimits(max_file_bytes=100))
        self.assertEqual(ctx.exception.code, ErrorCode.FILE_TOO_LARGE)


class InvalidArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_invalid_zip_bytes_are_typed(self):
        with self.assertRaises(PathCageError) as ctx:
            inspect_zip(io.BytesIO(b"not a zip"), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)

    def test_invalid_tar_bytes_are_typed(self):
        with self.assertRaises(PathCageError) as ctx:
            inspect_tar(io.BytesIO(b"not a tar archive" * 100), root=self.root)
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_ARCHIVE)


if __name__ == "__main__":
    unittest.main()
