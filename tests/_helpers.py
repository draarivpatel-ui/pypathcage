"""Shared test helpers. Nothing here is a test case."""

from __future__ import annotations

import io
import tarfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Tuple


def make_zip(entries: List[Tuple[str, bytes]], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = compression
            zf.writestr(info, data)
    return buffer.getvalue()


def make_tar(entries: List[Tuple[str, bytes]], *, mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@contextmanager
def temp_root() -> Iterator[Path]:
    """Alias kept so individual tests can import a single helper name."""
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as directory:
        yield Path(directory)


def has_symlink_support() -> bool:
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        target.write_text("x")
        link = Path(directory) / "link"
        try:
            os.symlink(str(target), str(link))
            return True
        except (OSError, NotImplementedError):
            return False
