"""Path containment primitives built on :func:`os.path.realpath`."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

from ._text import (
    check_lexical,
    check_windows_lexical,
    folds_to_path_syntax,
    is_safe_component,
    split_components,
)
from .errors import ErrorCode, PathCageError

PathLike = Union[str, "os.PathLike[str]"]

_SEPARATOR_RE = re.compile(r"[\\/]+")


@dataclass
class PathCage:
    """A root directory that all paths must stay inside.

    ``no_symlinks=True`` (the default) rejects any symlink encountered while
    resolving a candidate, including a symlinked ancestor of a path that does
    not itself exist yet.  ``no_symlinks=False`` still guarantees containment:
    the resolved real path must be the root itself or below it.
    """

    root: Path
    no_symlinks: bool = True
    allow_absolute: bool = False
    _root_real: str = field(init=False, repr=False)
    _root_alias: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        if not self.root.exists():
            raise PathCageError(ErrorCode.MISSING_MEMBER, "cage root does not exist", str(self.root))
        if not self.root.is_dir():
            raise PathCageError(ErrorCode.NOT_A_DIRECTORY, "cage root is not a directory", str(self.root))
        self._root_alias = os.path.abspath(os.fspath(self.root))
        self._root_real = os.path.realpath(self._root_alias)

    @property
    def root_real(self) -> str:
        """The fully resolved root path."""
        return self._root_real

    def resolve(self, candidate: PathLike) -> Path:
        """Resolve ``candidate`` inside the cage and return its real path.

        The candidate is first validated lexically and (unless
        ``allow_absolute`` is set) required to be relative.  Every existing
        prefix is then checked for symlinks before containment is checked.
        """
        candidate_str = os.fspath(candidate)
        if isinstance(candidate_str, bytes):
            raise PathCageError(ErrorCode.EMPTY_PATH, "bytes paths are not supported")
        check_lexical(candidate_str)
        check_windows_lexical(candidate_str)

        if os.path.isabs(candidate_str):
            if not self.allow_absolute:
                raise PathCageError(ErrorCode.ABSOLUTE_PATH, "absolute paths are not allowed", candidate_str)
            resolved_abs = os.path.realpath(candidate_str)
            if not self.contains(resolved_abs):
                raise PathCageError(ErrorCode.OUTSIDE_ROOT, "absolute path escapes the cage root", candidate_str)
            if self.no_symlinks:
                # realpath alone would silently follow a symlink that stays
                # inside the root.  The no_symlinks contract covers absolute
                # candidates too, so probe the chain when the candidate is
                # expressed through the root path or its real path.
                self._reject_symlink_chain(candidate_str, resolved_abs)
            return Path(resolved_abs)

        parts = list(split_components(candidate_str))
        stack: List[str] = []
        for part in parts:
            if part == "..":
                if not stack:
                    raise PathCageError(ErrorCode.TRAVERSAL, "path escapes the cage root", candidate_str)
                stack.pop()
            elif part != ".":
                stack.append(part)

        # Walk every ancestor of the joined path so symlinks in a not-yet
        # existing tail cannot hide behind a symlinked parent directory.
        if self.no_symlinks:
            probe = self._root_real
            for part in stack:
                probe = os.path.join(probe, part)
                if os.path.islink(probe):
                    raise PathCageError(ErrorCode.SYMLINK, "symlink components are not allowed", probe)

        joined = os.path.join(self._root_real, *stack) if stack else self._root_real
        resolved = os.path.realpath(joined)
        if not self.contains(resolved):
            raise PathCageError(ErrorCode.OUTSIDE_ROOT, "resolved path escapes the cage root", resolved)
        return Path(resolved)

    def _reject_symlink_chain(self, candidate: str, resolved: str) -> None:
        """Reject symlinks below the root for an absolute candidate path."""
        relative = self._relative_to_root(candidate)
        if relative is None:
            relative = os.path.relpath(resolved, self._root_real)
        probe = self._root_real
        for part in relative.split(os.sep):
            if part in ("", "."):
                continue
            probe = os.path.join(probe, part)
            if os.path.islink(probe):
                raise PathCageError(ErrorCode.SYMLINK, "symlink components are not allowed", probe)

    def _relative_to_root(self, candidate: str) -> Optional[str]:
        """Return ``candidate`` relative to the root when it is spelled that way.

        Both the caller supplied root path and its realpath are accepted so a
        root reached through ``/tmp`` style aliases still gets probed.
        """
        normalized = os.path.normpath(candidate)
        for alias in (self._root_alias, self._root_real):
            if normalized == alias:
                return ""
            if normalized.startswith(alias + os.sep):
                return os.path.relpath(normalized, alias)
        return None

    def contains(self, path: PathLike) -> bool:
        """True when ``path`` (realpath-ed) is the root or lies below it."""
        resolved = os.path.realpath(os.path.abspath(os.fspath(path)))
        root = self._root_real
        if resolved == root:
            return True
        prefix = root if root.endswith(os.sep) else root + os.sep
        return resolved.startswith(prefix)

    def assert_contained(self, path: PathLike) -> Path:
        """Like :meth:`resolve` but also usable on already absolute paths."""
        resolved = Path(os.path.realpath(os.path.abspath(os.fspath(path))))
        if not self.contains(resolved):
            raise PathCageError(ErrorCode.OUTSIDE_ROOT, "path escapes the cage root", str(resolved))
        return resolved


def resolve_safe_path(
    base: PathLike,
    candidate: PathLike,
    *,
    no_symlinks: bool = True,
    allow_absolute: bool = False,
) -> Path:
    """Convenience wrapper for :class:`PathCage`."""
    return PathCage(base, no_symlinks=no_symlinks, allow_absolute=allow_absolute).resolve(candidate)


def sanitize_filename(name: str, *, replacement: str = "_", max_length: int = 255) -> str:
    """Return a conservative, single component safe filename.

    Separators and traversal/control/Windows constructs are replaced, not
    merely removed, so distinct hostile inputs get distinct repairs.  If the
    entire input is unsafe, or truncation leaves a reserved or otherwise
    unsafe name, ``"unnamed"`` is the fallback; that fallback, like the
    ``max_length`` truncation, can collapse names that were already unusable.
    """
    if not isinstance(name, str):
        raise PathCageError(ErrorCode.EMPTY_PATH, "filename must be a string", type(name).__name__)

    out: List[str] = []
    for ch in name:
        if ch in ("/", "\\") or ord(ch) < 32 or ord(ch) == 127:
            out.append(replacement)
        elif ch in ("／", "＼", "．", "：", "‮"):
            out.append(replacement)
        elif ch == ":":
            out.append(replacement)
        elif 0x80 <= ord(ch) <= 0x9F:
            out.append(replacement)
        elif folds_to_path_syntax(ch):
            out.append(replacement)
        else:
            out.append(ch)

    cleaned = "".join(out).strip(" .")
    cleaned = _SEPARATOR_RE.sub(replacement, cleaned)
    while ".." in cleaned:
        cleaned = cleaned.replace("..", replacement)
    cleaned = cleaned.replace("\x00", "")

    max_length = max(1, int(max_length))
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    if not cleaned or not is_safe_component(cleaned):
        cleaned = "unnamed"
    return cleaned


__all__ = [
    "PathCage",
    "resolve_safe_path",
    "sanitize_filename",
    "PathCageError",
    "ErrorCode",
]
