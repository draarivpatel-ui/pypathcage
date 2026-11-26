"""String level normalization and platform agnostic filename validation.

Every check here is purely lexical (it never touches the filesystem) so it can
be applied uniformly to user supplied paths and to archive member names.
"""

from __future__ import annotations

import re
from typing import Iterable, Tuple

from .errors import ErrorCode, PathCageError

# Confidence: map "look alike" code points to the ASCII character an attacker
# is trying to impersonate.  This is deliberately a small, high confidence
# table rather than a full confusables list, so ordinary international names
# are not rejected.  NFKC would also fold fullwidth slashes/dots, but doing it
# explicitly lets us raise a precise error code and keeps the order of checks
# deterministic.
_CONFUSABLES = {
    "\uff0f": "/",   # FULLWIDTH SOLIDUS
    "\uff3c": "\\",  # FULLWIDTH REVERSE SOLIDUS
    "\uff0e": ".",   # FULLWIDTH FULL STOP
    "\u2215": "/",   # DIVISION SLASH
    "\u2216": "\\",  # SET MINUS
    "\u2044": "/",   # FRACTION SLASH
    "\u30fb": ".",   # KATAKANA MIDDLE DOT (often used as a dot look alike)
    "\u2024": ".",   # ONE DOT LEADER
    "\uff1a": ":",   # FULLWIDTH COLON (ADS look alike)
    "\uff04": "$",
}

_BIDI_OVERRIDES = frozenset(
    ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]
)

# C0 controls, DEL and the C1 range.  Tab/newline are included because they
# are common in "benign head + hidden tail" command and archive smuggling.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_WINDOWS_RESERVED_BASE = frozenset(
    ["con", "prn", "aux", "nul"]
    + ["com{0}".format(i) for i in range(1, 10)]
    + ["lpt{0}".format(i) for i in range(1, 10)]
)

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
# \\?\, \\.\, \\??\, and any other UNC style prefix starting with two slashes.
_UNC_RE = re.compile(r"^[\\/]{2}")
_DEVICE_PREFIX_RE = re.compile(r"^[\\/]{2}[?.]")


def normalize_confusables(text: str) -> Tuple[str, bool]:
    """Return ``(normalized, changed)`` with high risk look alikes folded.

    Unicode normalization is intentionally limited to NFKC for the confusable
    scan; we do not silently accept the folded text, we only use it to decide
    whether the original contained a character that must be rejected.
    """
    folded = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    return folded, folded != text


def check_lexical(value: str, *, allow_nul: bool = False) -> str:
    """Validate that ``value`` contains no characters that can subvert paths.

    Raises :class:`PathCageError` with a precise code on the first problem.
    The returned string is the original value, unmodified.
    """
    if not isinstance(value, str):
        raise PathCageError(ErrorCode.EMPTY_PATH, "path must be a string", type(value).__name__)
    if value == "":
        raise PathCageError(ErrorCode.EMPTY_PATH, "path must not be empty")

    for ch in value:
        if ch == "\x00":
            if not allow_nul:
                raise PathCageError(ErrorCode.NUL_BYTE, "path contains a NUL byte")
        elif ch in _BIDI_OVERRIDES:
            raise PathCageError(ErrorCode.BIDI_OVERRIDE, "path contains a bidirectional override")
        elif _CONTROL_RE.match(ch):
            raise PathCageError(ErrorCode.CONTROL_CHARACTER, "path contains a control character")
        elif ch in _CONFUSABLES:
            raise PathCageError(ErrorCode.UNICODE_CONFUSABLE, "path contains a Unicode look alike", hex(ord(ch)))
    return value


def split_components(value: str) -> Iterable[str]:
    """Split a lexical path on both POSIX and Windows separators.

    Collapses repeated separators but keeps ``.`` and ``..`` components so the
    caller can apply its own traversal policy.
    """
    normalized = value.replace("\\", "/")
    return [part for part in normalized.split("/") if part != ""]


def is_windows_reserved(component: str) -> bool:
    """True for CON, PRN, AUX, NUL, COM1..9, LPT1..9 with any extension."""
    base = component.split(".", 1)[0].rstrip(" ")
    return base.lower() in _WINDOWS_RESERVED_BASE


def check_windows_lexical(value: str) -> None:
    """Reject Windows paths that are unsafe even when running on POSIX.

    Archive names must be portable: a member named ``C:\\evil`` or
    ``file.txt:stream`` is not a normal file on any supported platform, so we
    reject it everywhere rather than depending on the host OS.
    """
    if _DEVICE_PREFIX_RE.match(value) or _UNC_RE.match(value):
        raise PathCageError(ErrorCode.WINDOWS_UNC, "UNC or device prefix is not allowed", value)
    if _DRIVE_RE.match(value):
        raise PathCageError(ErrorCode.WINDOWS_DRIVE, "Windows drive letter is not allowed", value)
    for part in split_components(value):
        if part in (".", ".."):
            # Navigation components are handled by the traversal policy.
            continue
        if ":" in part:
            raise PathCageError(ErrorCode.WINDOWS_ADS, "Windows alternate data stream is not allowed", part)
        if is_windows_reserved(part):
            raise PathCageError(ErrorCode.WINDOWS_RESERVED_NAME, "Windows reserved device name is not allowed", part)
        if part != part.rstrip(" ."):
            raise PathCageError(
                ErrorCode.WINDOWS_TRAILING_CHAR,
                "Windows trailing dot or space is not allowed",
                part,
            )


def is_safe_component(component: str) -> bool:
    """Cheap boolean form used by the filename sanitizer."""
    if component in ("", ".", ".."):
        return False
    try:
        check_lexical(component)
        check_windows_lexical(component)
    except PathCageError:
        return False
    return True
