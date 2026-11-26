"""Typed error codes raised by pypathcage."""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    """Stable, machine readable reason for a rejected path or archive."""

    EMPTY_PATH = "empty_path"
    NUL_BYTE = "nul_byte"
    CONTROL_CHARACTER = "control_character"
    UNICODE_CONFUSABLE = "unicode_confusable"
    BIDI_OVERRIDE = "bidi_override"
    ABSOLUTE_PATH = "absolute_path"
    TRAVERSAL = "traversal"
    WINDOWS_DRIVE = "windows_drive"
    WINDOWS_UNC = "windows_unc"
    WINDOWS_DEVICE_PREFIX = "windows_device_prefix"
    WINDOWS_ADS = "windows_ads"
    WINDOWS_RESERVED_NAME = "windows_reserved_name"
    WINDOWS_TRAILING_CHAR = "windows_trailing_char"
    OUTSIDE_ROOT = "outside_root"
    SYMLINK = "symlink"
    NOT_A_DIRECTORY = "not_a_directory"
    MISSING_MEMBER = "missing_member"
    FILE_COUNT = "file_count"
    FILE_TOO_LARGE = "file_too_large"
    TOTAL_TOO_LARGE = "total_too_large"
    COMPRESSION_RATIO = "compression_ratio"
    DUPLICATE_NAME = "duplicate_name"
    UNSUPPORTED_MEMBER = "unsupported_member"
    INVALID_ARCHIVE = "invalid_archive"
    PERMISSION_DENIED = "permission_denied"


class PathCageError(ValueError):
    """Raised whenever a path or archive member fails a security check.

    ``code`` is a :class:`ErrorCode` member and ``detail`` carries optional
    context (the offending name, a limit, and so on).
    """

    def __init__(self, code: ErrorCode, message: str, detail: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        base = super().__str__()
        if self.detail is None:
            return base
        return "{0} (detail: {1!r})".format(base, self.detail)
