"""Tests for PathCage, resolve_safe_path and realpath containment."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pypathcage import ErrorCode, PathCage, PathCageError, resolve_safe_path
from pypathcage.core import sanitize_filename

from _helpers import has_symlink_support


class PathCageBasicTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cage_accepts_existing_dir(self):
        cage = PathCage(self.root)
        self.assertEqual(cage.root, self.root)

    def test_cage_root_real_is_absolute(self):
        cage = PathCage(self.root)
        self.assertTrue(os.path.isabs(cage.root_real))

    def test_cage_rejects_missing_root(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root / "missing")
        self.assertEqual(ctx.exception.code, ErrorCode.MISSING_MEMBER)

    def test_cage_rejects_file_root(self):
        target = self.root / "file"
        target.write_text("x")
        with self.assertRaises(PathCageError) as ctx:
            PathCage(target)
        self.assertEqual(ctx.exception.code, ErrorCode.NOT_A_DIRECTORY)

    def test_resolve_simple_file(self):
        (self.root / "a.txt").write_text("x")
        result = PathCage(self.root).resolve("a.txt")
        self.assertEqual(result, self.root.resolve() / "a.txt")

    def test_resolve_nested_file(self):
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("x")
        result = PathCage(self.root).resolve("sub/b.txt")
        self.assertEqual(result, self.root.resolve() / "sub" / "b.txt")

    def test_resolve_nonexistent_path_is_allowed(self):
        result = PathCage(self.root).resolve("new/deep/file.txt")
        self.assertEqual(result, self.root.resolve() / "new" / "deep" / "file.txt")

    def test_resolve_dot_component(self):
        result = PathCage(self.root).resolve("./a.txt")
        self.assertEqual(result, self.root.resolve() / "a.txt")

    def test_resolve_multiple_slashes(self):
        result = PathCage(self.root).resolve("a//b///c.txt")
        self.assertEqual(result, self.root.resolve() / "a" / "b" / "c.txt")

    def test_reject_single_dotdot(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("../evil")
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_reject_nested_dotdot_escape(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a/b/../../../../etc/passwd")
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_allow_dotdot_that_stays_inside(self):
        result = PathCage(self.root).resolve("a/../b.txt")
        self.assertEqual(result, self.root.resolve() / "b.txt")

    def test_reject_backslash_traversal(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("..\\evil.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_reject_mixed_slash_traversal(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a\\..\\..\\evil")
        self.assertEqual(ctx.exception.code, ErrorCode.TRAVERSAL)

    def test_reject_nul_byte(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a\x00b.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.NUL_BYTE)

    def test_reject_control_character(self):
        for ch in ("\x01", "\x1f", "\x7f", "\t", "\n", "\r"):
            with self.subTest(ch=repr(ch)):
                with self.assertRaises(PathCageError) as ctx:
                    PathCage(self.root).resolve("a" + ch + "b")
                self.assertEqual(ctx.exception.code, ErrorCode.CONTROL_CHARACTER)

    def test_reject_fullwidth_solidus(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a／b")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_reject_fullwidth_reverse_solidus(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a＼b")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_reject_fullwidth_dot(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("a．b")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)

    def test_reject_rtl_override(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("safe‮evil.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.BIDI_OVERRIDE)

    def test_reject_absolute_path(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("/etc/passwd")
        self.assertEqual(ctx.exception.code, ErrorCode.ABSOLUTE_PATH)

    def test_prefix_confusion_rejected_by_dotdot(self):
        sibling = self.root.parent / (self.root.name + "-evil")
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("../" + sibling.name)

    def test_contains_own_root(self):
        self.assertTrue(PathCage(self.root).contains(self.root))

    def test_contains_child(self):
        self.assertTrue(PathCage(self.root).contains(self.root.resolve() / "a" / "b"))

    def test_contains_rejects_parent(self):
        self.assertFalse(PathCage(self.root).contains(self.root.parent))

    def test_contains_rejects_prefix_sibling(self):
        sibling = Path(str(self.root) + "-evil")
        self.assertFalse(PathCage(self.root).contains(sibling))

    def test_assert_contained_accepts_child(self):
        result = PathCage(self.root).assert_contained(self.root / "a")
        self.assertEqual(result, self.root.resolve() / "a")

    def test_assert_contained_rejects_outside(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).assert_contained(self.root.parent)
        self.assertEqual(ctx.exception.code, ErrorCode.OUTSIDE_ROOT)

    def test_allow_absolute_inside_root(self):
        target = self.root / "ok.txt"
        target.write_text("x")
        result = PathCage(self.root, allow_absolute=True).resolve(str(target))
        self.assertEqual(result, target.resolve())

    def test_allow_absolute_outside_still_rejected(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root, allow_absolute=True).resolve("/etc/passwd")

    def test_resolve_safe_path_wrapper(self):
        result = resolve_safe_path(self.root, "hello.txt")
        self.assertEqual(result, self.root.resolve() / "hello.txt")

    def test_resolve_safe_path_rejects_traversal(self):
        with self.assertRaises(PathCageError):
            resolve_safe_path(self.root, "../../evil")

    def test_empty_path_rejected(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("")
        self.assertEqual(ctx.exception.code, ErrorCode.EMPTY_PATH)

    def test_bytes_path_rejected(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve(b"abc")

    def test_error_code_is_string_enum(self):
        err = PathCageError(ErrorCode.TRAVERSAL, "bad")
        self.assertEqual(err.code.value, "traversal")
        self.assertIsInstance(err, ValueError)

    def test_error_str_with_detail(self):
        err = PathCageError(ErrorCode.TRAVERSAL, "bad", "detail")
        self.assertIn("detail", str(err))


class WindowsLexicalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_drive_letter_absolute(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("C:\\evil.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_DRIVE)

    def test_drive_relative(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("C:foo")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_DRIVE)

    def test_unc_path(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("\\\\server\\share\\evil")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_UNC)

    def test_device_prefix(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("\\\\?\\C:\\evil")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_UNC)

    def test_device_prefix_dot(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("\\\\.\\COM1")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_UNC)

    def test_ads_stream(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("file.txt:hidden")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_ADS)

    def test_reserved_con(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("CON")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_RESERVED_NAME)

    def test_reserved_con_with_extension(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("con.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_RESERVED_NAME)

    def test_reserved_prn(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("PRN")

    def test_reserved_aux(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("AUX")

    def test_reserved_nul(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("NUL")

    def test_reserved_com1(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("COM1")

    def test_reserved_com9(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("COM9.log")

    def test_reserved_lpt1(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("LPT1")

    def test_reserved_lpt9(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("LPT9")

    def test_reserved_in_subdirectory(self):
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("sub/con.txt")

    def test_trailing_dot(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("file.")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_TRAILING_CHAR)

    def test_trailing_space(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("file ")
        self.assertEqual(ctx.exception.code, ErrorCode.WINDOWS_TRAILING_CHAR)

    def test_fullwidth_colon_ads(self):
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("file：stream")
        self.assertEqual(ctx.exception.code, ErrorCode.UNICODE_CONFUSABLE)


@unittest.skipUnless(has_symlink_support(), "symlinks unsupported")
class SymlinkEscapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "cage"
        self.root.mkdir()
        self.outside = Path(self._tmp.name) / "outside"
        self.outside.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_direct_symlink_escape_rejected(self):
        os.symlink(str(self.outside), str(self.root / "escape"))
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("escape/secret.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_dangling_symlink_escape_rejected(self):
        os.symlink(str(self.outside / "missing"), str(self.root / "escape"))
        with self.assertRaises(PathCageError) as ctx:
            PathCage(self.root).resolve("escape")
        self.assertEqual(ctx.exception.code, ErrorCode.SYMLINK)

    def test_multilevel_path_through_escaping_symlink(self):
        os.symlink(str(self.outside), str(self.root / "escape"))
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("escape/deep/dir/file.txt")

    def test_symlink_to_nonexistent_ancestor(self):
        os.symlink(str(self.outside / "notyet"), str(self.root / "escape"))
        with self.assertRaises(PathCageError):
            PathCage(self.root).resolve("escape/deep/file.txt")

    def test_symlink_inside_root_allowed_when_disabled(self):
        (self.root / "real").mkdir()
        os.symlink(str(self.root / "real"), str(self.root / "link"))
        cage = PathCage(self.root, no_symlinks=False)
        result = cage.resolve("link/file.txt")
        self.assertEqual(result, self.root.resolve() / "real" / "file.txt")

    def test_symlink_escape_rejected_when_disabled(self):
        os.symlink(str(self.outside), str(self.root / "escape"))
        cage = PathCage(self.root, no_symlinks=False)
        with self.assertRaises(PathCageError) as ctx:
            cage.resolve("escape/secret.txt")
        self.assertEqual(ctx.exception.code, ErrorCode.OUTSIDE_ROOT)

    def test_symlink_target_checking_realpath(self):
        os.symlink(str(self.outside / "secret.txt"), str(self.root / "link.txt"))
        cage = PathCage(self.root, no_symlinks=False)
        with self.assertRaises(PathCageError):
            cage.resolve("link.txt")

    def test_contains_follows_symlink(self):
        os.symlink(str(self.outside), str(self.root / "escape"))
        self.assertFalse(PathCage(self.root).contains(self.root / "escape"))

    def test_symlink_in_parent_of_root_allowed(self):
        cage = PathCage(self.root)
        result = cage.resolve("ok.txt")
        self.assertEqual(result, self.root.resolve() / "ok.txt")


class SanitizeFilenameTests(unittest.TestCase):
    def test_plain_name_unchanged(self):
        self.assertEqual(sanitize_filename("hello.txt"), "hello.txt")

    def test_dotdot_replaced(self):
        self.assertNotIn("..", sanitize_filename("../evil"))

    def test_slashes_replaced(self):
        result = sanitize_filename("a/b\\c")
        self.assertNotIn("/", result)
        self.assertNotIn("\\", result)

    def test_nul_replaced(self):
        self.assertNotIn("\x00", sanitize_filename("a\x00b"))

    def test_control_replaced(self):
        self.assertNotIn("\n", sanitize_filename("a\nb"))

    def test_fullwidth_slash_replaced(self):
        self.assertNotIn("／", sanitize_filename("a／b"))

    def test_colon_replaced(self):
        self.assertNotIn(":", sanitize_filename("file:stream"))

    def test_reserved_name_handled(self):
        result = sanitize_filename("CON.txt")
        self.assertTrue(result != "CON.txt")

    def test_empty_name_returns_unnamed(self):
        self.assertEqual(sanitize_filename(""), "unnamed")

    def test_only_separators_returns_unnamed(self):
        self.assertNotIn("/", sanitize_filename("///"))

    def test_trailing_dots_stripped(self):
        self.assertFalse(sanitize_filename("file...").endswith("."))

    def test_max_length(self):
        self.assertEqual(len(sanitize_filename("a" * 500, max_length=50)), 50)

    def test_unicode_allowed(self):
        self.assertEqual(sanitize_filename("caf\u00e9.txt"), "caf\u00e9.txt")

    def test_custom_replacement(self):
        self.assertIn("-", sanitize_filename("a/b", replacement="-"))

    def test_non_string_raises(self):
        with self.assertRaises(PathCageError):
            sanitize_filename(123)


if __name__ == "__main__":
    unittest.main()
