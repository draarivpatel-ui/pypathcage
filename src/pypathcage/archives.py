"""Safe inspection and extraction of ZIP and TAR archives.

The extractors never trust header declared sizes or names.  Every member is
validated lexically, every resolved target is contained, and extracted bytes
are counted while streaming so a spoofed or compressed header cannot defeat
the bomb limits.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Dict, List, Optional, Set, Tuple, Union

from ._text import check_lexical, check_windows_lexical, split_components
from .core import PathCage
from .errors import ErrorCode, PathCageError

PathLike = Union[str, "os.PathLike[str]"]

_CHUNK = 64 * 1024


@dataclass(frozen=True)
class ArchiveLimits:
    """Resource limits applied to a single inspection/extraction run."""

    max_files: int = 10_000
    max_file_bytes: int = 100 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_compression_ratio: float = 200.0
    no_symlinks: bool = True
    allow_links: bool = False

    def __post_init__(self) -> None:
        if self.max_files < 0 or self.max_file_bytes < 0 or self.max_total_bytes < 0:
            raise ValueError("archive limits must be non-negative")
        if self.max_compression_ratio < 0:
            raise ValueError("compression ratio must be non-negative")


DEFAULT_LIMITS = ArchiveLimits()


@dataclass
class ArchiveReport:
    """Summary returned by the ``inspect_*`` helpers."""

    kind: str
    member_count: int
    regular_files: int
    directories: int
    links: int
    total_uncompressed: int
    names: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "member_count": self.member_count,
            "regular_files": self.regular_files,
            "directories": self.directories,
            "links": self.links,
            "total_uncompressed": self.total_uncompressed,
            "names": list(self.names),
        }


def _check_name(name: str, cage: PathCage) -> List[str]:
    """Lexically validate ``name`` and return its path components."""
    if name == "":
        raise PathCageError(ErrorCode.INVALID_ARCHIVE, "archive member has an empty name")
    check_lexical(name)
    check_windows_lexical(name)
    if os.path.isabs(name) or name.startswith("/") or name.startswith("\\"):
        raise PathCageError(ErrorCode.ABSOLUTE_PATH, "archive member has an absolute path", name)
    stack: List[str] = []
    for part in split_components(name):
        if part == "..":
            if not stack:
                raise PathCageError(ErrorCode.TRAVERSAL, "archive member escapes the root", name)
            stack.pop()
        elif part != ".":
            stack.append(part)
    if not stack:
        raise PathCageError(ErrorCode.INVALID_ARCHIVE, "archive member has no usable path", name)
    return stack


def _target_for(cage: PathCage, parts: List[str]) -> Path:
    """Resolve the destination for validated ``parts`` inside ``cage``."""
    clean = [p for p in parts if p not in (".", "..")]
    if not clean:
        return Path(cage.root_real)
    return cage.resolve(os.path.join(*clean))


def _register_name(key: str, seen: Set[str], name: str) -> None:
    """Register a normalized member key, rejecting case-insensitive clashes."""
    folded = key.replace("\\", "/").casefold()
    if folded in seen:
        raise PathCageError(ErrorCode.DUPLICATE_NAME, "case-insensitive filename collision", name)
    seen.add(folded)


def _write_stream(
    source: IO[bytes],
    destination: IO[bytes],
    *,
    limit: int,
    label: str,
    declared: Optional[int] = None,
) -> int:
    """Copy a member stream while enforcing the byte limit on real bytes.

    When ``declared`` is supplied, a header that claims more than the limit is
    rejected immediately.  The running total still counts every byte actually
    read, so an understated header cannot defeat the limit either.
    """
    if declared is not None and declared > limit:
        raise PathCageError(ErrorCode.FILE_TOO_LARGE, "member exceeds the single-file byte limit", label)
    total = 0
    while True:
        try:
            chunk = source.read(_CHUNK)
        except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            raise PathCageError(ErrorCode.INVALID_ARCHIVE, "cannot read archive member", label) from exc
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise PathCageError(ErrorCode.FILE_TOO_LARGE, "member exceeds the single-file byte limit", label)
        destination.write(chunk)
    return total


def _open_tar(archive: Union[PathLike, IO[bytes]], mode: str = "r:*") -> tarfile.TarFile:
    """Open a TAR from either a path or a binary file-like object."""
    if isinstance(archive, (str, bytes, os.PathLike)):
        return tarfile.open(archive, mode)
    return tarfile.open(fileobj=archive, mode=mode)


def _check_tar_member(member: tarfile.TarInfo, limits: ArchiveLimits) -> None:
    """Reject special TAR entries that can create devices, links or pipes."""
    if member.isdev():
        raise PathCageError(ErrorCode.UNSUPPORTED_MEMBER, "device or FIFO tar member is not allowed", member.name)
    if member.issym() or member.islnk():
        if not limits.allow_links or limits.no_symlinks:
            raise PathCageError(ErrorCode.SYMLINK, "link members are not allowed", member.name)


def _check_link_target(link_name: str, cage: PathCage, parts: List[str], member_name: str) -> None:
    """Ensure a permitted link target cannot point outside the cage."""
    check_lexical(link_name)
    if os.path.isabs(link_name) or link_name.startswith(("/", "\\")):
        raise PathCageError(ErrorCode.ABSOLUTE_PATH, "link target is absolute", link_name)
    parent_parts = [p for p in parts[:-1] if p not in (".", "..")]
    combined = parent_parts + list(split_components(link_name))
    depth = 0
    for part in combined:
        if part == "..":
            depth -= 1
            if depth < 0:
                raise PathCageError(ErrorCode.TRAVERSAL, "link target escapes the root", member_name)
        else:
            depth += 1
    _target_for(cage, combined)


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------


def inspect_zip(
    archive: Union[PathLike, IO[bytes], zipfile.ZipFile],
    *,
    root: Optional[PathLike] = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveReport:
    """Validate a ZIP archive without extracting it."""
    owns = False
    zf: zipfile.ZipFile
    if isinstance(archive, zipfile.ZipFile):
        zf = archive
    else:
        zf = zipfile.ZipFile(archive, "r")
        owns = True
    try:
        cage = PathCage(root or Path.cwd())
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise PathCageError(ErrorCode.FILE_COUNT, "archive has too many members", len(infos))

        seen: Set[str] = set()
        regular = dirs = links = 0
        total = 0
        names: List[str] = []
        for info in infos:
            parts = _check_name(info.filename, cage)
            _target_for(cage, parts)
            _register_name(info.filename, seen, info.filename)
            names.append(info.filename)
            if info.file_size > limits.max_file_bytes:
                raise PathCageError(ErrorCode.FILE_TOO_LARGE, "member header exceeds the single-file limit", info.filename)
            total += info.file_size
            if total > limits.max_total_bytes:
                raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_compression_ratio:
                    raise PathCageError(
                        ErrorCode.COMPRESSION_RATIO,
                        "member compression ratio is too high",
                        round(ratio, 2),
                    )
            if info.is_dir():
                dirs += 1
            else:
                regular += 1
        return ArchiveReport("zip", len(infos), regular, dirs, links, total, names)
    finally:
        if owns:
            zf.close()


def safe_extract_zip(
    archive: Union[PathLike, IO[bytes], zipfile.ZipFile],
    destination: PathLike,
    *,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveReport:
    """Validate and extract ``archive`` into ``destination`` safely."""
    owns = False
    zf: zipfile.ZipFile
    if isinstance(archive, zipfile.ZipFile):
        zf = archive
    else:
        zf = zipfile.ZipFile(archive, "r")
        owns = True
    try:
        cage = PathCage(destination)
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise PathCageError(ErrorCode.FILE_COUNT, "archive has too many members", len(infos))

        seen: Set[str] = set()
        regular = dirs = links = 0
        total = 0
        names: List[str] = []
        planned: List[Tuple[zipfile.ZipInfo, Path]] = []
        for info in infos:
            parts = _check_name(info.filename, cage)
            target = _target_for(cage, parts)
            _register_name(info.filename, seen, info.filename)
            names.append(info.filename)
            total += info.file_size
            if total > limits.max_total_bytes:
                raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
            planned.append((info, target))
            if info.is_dir():
                dirs += 1
            else:
                regular += 1

        for info, target in planned:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source:
                with open(target, "wb") as sink:
                    written = _write_stream(
                        source, sink, limit=limits.max_file_bytes, label=info.filename, declared=info.file_size
                    )
            total = total - info.file_size + written
            if total > limits.max_total_bytes:
                raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
            if info.compress_size > 0 and written / info.compress_size > limits.max_compression_ratio:
                raise PathCageError(
                    ErrorCode.COMPRESSION_RATIO,
                    "member compression ratio is too high",
                    round(written / info.compress_size, 2),
                )
        return ArchiveReport("zip", len(infos), regular, dirs, links, total, names)
    finally:
        if owns:
            zf.close()


# ---------------------------------------------------------------------------
# TAR
# ---------------------------------------------------------------------------


def inspect_tar(
    archive: Union[PathLike, IO[bytes], tarfile.TarFile],
    *,
    root: Optional[PathLike] = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveReport:
    """Validate a TAR archive without extracting it."""
    owns = False
    tf: tarfile.TarFile
    if isinstance(archive, tarfile.TarFile):
        tf = archive
    else:
        tf = _open_tar(archive)
        owns = True
    try:
        cage = PathCage(root or Path.cwd())
        members = tf.getmembers()
        if len(members) > limits.max_files:
            raise PathCageError(ErrorCode.FILE_COUNT, "archive has too many members", len(members))

        seen: Set[str] = set()
        regular = dirs = links = 0
        total = 0
        names: List[str] = []
        for member in members:
            parts = _check_name(member.name, cage)
            _target_for(cage, parts)
            _check_tar_member(member, limits)
            if member.issym() or member.islnk():
                _check_link_target(member.linkname, cage, parts, member.name)
            _register_name(member.name, seen, member.name)
            names.append(member.name)
            if member.isfile():
                if member.size > limits.max_file_bytes:
                    raise PathCageError(
                        ErrorCode.FILE_TOO_LARGE, "member exceeds the single-file limit", member.name
                    )
                total += member.size
                if total > limits.max_total_bytes:
                    raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
            if member.isdir():
                dirs += 1
            elif member.issym() or member.islnk():
                links += 1
            else:
                regular += 1
        return ArchiveReport("tar", len(members), regular, dirs, links, total, names)
    finally:
        if owns:
            tf.close()


def safe_extract_tar(
    archive: Union[PathLike, IO[bytes], tarfile.TarFile],
    destination: PathLike,
    *,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveReport:
    """Validate and extract ``archive`` into ``destination`` safely."""
    owns = False
    tf: tarfile.TarFile
    if isinstance(archive, tarfile.TarFile):
        tf = archive
    else:
        tf = _open_tar(archive)
        owns = True
    try:
        cage = PathCage(destination)
        members = tf.getmembers()
        if len(members) > limits.max_files:
            raise PathCageError(ErrorCode.FILE_COUNT, "archive has too many members", len(members))

        seen: Set[str] = set()
        regular = dirs = links = 0
        total = 0
        names: List[str] = []
        planned: List[Tuple[tarfile.TarInfo, Path]] = []
        for member in members:
            parts = _check_name(member.name, cage)
            target = _target_for(cage, parts)
            _check_tar_member(member, limits)
            if member.issym() or member.islnk():
                _check_link_target(member.linkname, cage, parts, member.name)
            _register_name(member.name, seen, member.name)
            names.append(member.name)
            if member.isfile():
                total += member.size
                if total > limits.max_total_bytes:
                    raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
            planned.append((member, target))
            if member.isdir():
                dirs += 1
            elif member.issym() or member.islnk():
                links += 1
            else:
                regular += 1

        for member, target in planned:
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym() or member.islnk():
                # Links only reach here when explicitly allowed by the caller.
                link_target = member.linkname
                if os.path.isabs(link_target):
                    raise PathCageError(ErrorCode.ABSOLUTE_PATH, "link target is absolute", member.name)
                parts = list(split_components(member.name))
                _check_link_target(link_target, cage, parts, member.name)
                parent = Path(cage.root_real).joinpath(*[p for p in parts[:-1] if p not in (".", "..")])
                resolved_target = _target_for(
                    cage, [p for p in parts[:-1] if p not in (".", "..")] + list(split_components(link_target))
                )
                if target.exists() or os.path.lexists(target):
                    os.unlink(target)
                os.symlink(os.path.relpath(resolved_target, str(parent)), str(target))
                continue
            if not member.isfile():
                # GNUTYPE_LONGNAME and similar metadata entries are handled by
                # tarfile itself; anything left is an unsupported special type.
                continue
            source = tf.extractfile(member)
            if source is None:
                raise PathCageError(ErrorCode.INVALID_ARCHIVE, "cannot read tar member", member.name)
            with source:
                with open(target, "wb") as sink:
                    written = _write_stream(
                        source, sink, limit=limits.max_file_bytes, label=member.name, declared=member.size
                    )
            total = total - member.size + written
            if total > limits.max_total_bytes:
                raise PathCageError(ErrorCode.TOTAL_TOO_LARGE, "archive exceeds the total uncompressed limit", total)
        return ArchiveReport("tar", len(members), regular, dirs, links, total, names)
    finally:
        if owns:
            tf.close()


__all__ = [
    "ArchiveLimits",
    "ArchiveReport",
    "DEFAULT_LIMITS",
    "inspect_zip",
    "inspect_tar",
    "safe_extract_zip",
    "safe_extract_tar",
]
