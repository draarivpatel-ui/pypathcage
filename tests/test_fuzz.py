"""Deterministic security-boundary fuzz tests for pypathcage."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import zipfile

try:
    import atheris
except ImportError:
    atheris = None

from pypathcage import (
    ArchiveLimits,
    PathCage,
    PathCageError,
    inspect_tar,
    inspect_zip,
    safe_extract_zip,
    sanitize_filename,
)

_TOKEN_STRINGS = (
    "",
    "a",
    "file",
    ".txt",
    ".",
    "..",
    "/",
    "\\",
    "../",
    "..\\",
    "%2e%2e",
    "%252e%252e",
    "%00",
    "\x00",
    "\u202e",
    "\ufeff",
    "C:",
    "CON",
    "etc/passwd",
    "safe/",
)

_LIMITS = ArchiveLimits(
    max_files=8,
    max_file_bytes=512,
    max_total_bytes=2048,
    max_compression_ratio=80,
)


def _text_from_bytes(data: bytes, limit: int = 48) -> str:
    if not data:
        return "safe.txt"
    pieces = []
    for byte in data[:limit]:
        pieces.append(_TOKEN_STRINGS[byte % len(_TOKEN_STRINGS)])
    value = "".join(pieces)
    return value[:160] or "safe.txt"


def _archive_name(data: bytes) -> str:
    value = _text_from_bytes(data).replace("\x00", "0")
    return value or "file.txt"


def _check_path_text(cage: PathCage, value: str) -> None:
    try:
        resolved = cage.resolve(value)
    except PathCageError:
        return
    if not cage.contains(resolved):
        raise AssertionError("resolved path escaped the cage")
    if "\x00" in str(resolved):
        raise AssertionError("resolved path contains a null byte")


def _check_filename(value: str) -> None:
    cleaned = sanitize_filename(value, max_length=64)
    if not cleaned or len(cleaned) > 64:
        raise AssertionError("sanitized filename is empty or too long")
    if "/" in cleaned or "\\" in cleaned or "\x00" in cleaned or ".." in cleaned:
        raise AssertionError("sanitized filename retained path syntax")
    if cleaned in {".", ".."}:
        raise AssertionError("sanitized filename is a dot path")


def _check_raw_archives(root: str, data: bytes) -> None:
    raw = bytes(data[:512]) or b"0"
    for inspector in (inspect_zip, inspect_tar):
        try:
            report = inspector(io.BytesIO(raw), root=root, limits=_LIMITS)
        except PathCageError:
            continue
        if report.member_count < 0 or report.total_uncompressed < 0:
            raise AssertionError("archive report contains negative counts")
        for name in report.names:
            if "\x00" in name:
                raise AssertionError("accepted archive member contains a null byte")


def _check_generated_zip(root: str, data: bytes) -> None:
    first = _archive_name(data[:40])
    second = _archive_name(data[40:80] or b"nested-file")
    payload = bytes(data[:128]) or b"fuzz"
    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(first, payload)
            archive.writestr(second, payload)
    except (ValueError, TypeError):
        return
    raw = buffer.getvalue()
    cage = PathCage(root)
    try:
        inspect_zip(io.BytesIO(raw), root=root, limits=_LIMITS)
    except PathCageError:
        return
    destination = tempfile.mkdtemp(prefix="extract-", dir=root)
    try:
        safe_extract_zip(io.BytesIO(raw), destination, limits=_LIMITS)
    except PathCageError:
        pass
    for directory, dirnames, filenames in os.walk(destination):
        for name in dirnames + filenames:
            if not cage.contains(os.path.join(directory, name)):
                raise AssertionError("archive extraction wrote outside the cage")


def exercise(data: bytes) -> None:
    data = bytes(data[:512])
    text = _text_from_bytes(data)
    _check_filename(text)
    with tempfile.TemporaryDirectory(prefix="pypathcage-fuzz-") as root:
        cage = PathCage(root)
        _check_path_text(cage, text)
        _check_path_text(cage, "../" + text)
        _check_raw_archives(root, data)
        _check_generated_zip(root, data)


def _seed_bytes(seed: int, length: int = 96) -> bytes:
    return bytes((((seed + 1) * (index + 17)) ^ (index * 29)) & 0xFF for index in range(length))


class SecurityBoundaryFuzzTests(unittest.TestCase):
    def test_deterministic_generated_corpus(self) -> None:
        for seed in range(32):
            with self.subTest(seed=seed):
                exercise(_seed_bytes(seed))

    def test_targeted_archive_and_path_corpus(self) -> None:
        vectors = (
            b"../../../../etc/passwd",
            b"%2e%2e%2f%2e%2e%2fpasswd",
            b"safe/../inside.txt",
            b"\x00" * 512,
            b"PK\x03\x04" + bytes(128),
            b"0" * 512,
        )
        for index, vector in enumerate(vectors):
            with self.subTest(index=index):
                exercise(vector)


def main() -> int:
    if atheris is not None:
        atheris.Setup(sys.argv, exercise)
        atheris.Fuzz()
        return 0
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityBoundaryFuzzTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
