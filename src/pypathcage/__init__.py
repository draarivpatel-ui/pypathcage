"""pypathcage: zero-dependency path traversal and archive security for Python.

Public API:

- :class:`PathCage`, :func:`resolve_safe_path`, :func:`sanitize_filename`
- :func:`safe_extract_zip`, :func:`safe_extract_tar`
- :func:`inspect_zip`, :func:`inspect_tar`
- :class:`PathCageError` with a typed ``.code``
"""

from .archives import (
    DEFAULT_LIMITS,
    ArchiveLimits,
    ArchiveReport,
    inspect_tar,
    inspect_zip,
    safe_extract_tar,
    safe_extract_zip,
)
from .core import PathCage, resolve_safe_path, sanitize_filename
from .errors import ErrorCode, PathCageError

__version__ = "1.0.0"

__all__ = [
    "PathCage",
    "resolve_safe_path",
    "sanitize_filename",
    "safe_extract_zip",
    "safe_extract_tar",
    "inspect_zip",
    "inspect_tar",
    "PathCageError",
    "ErrorCode",
    "ArchiveLimits",
    "ArchiveReport",
    "DEFAULT_LIMITS",
    "__version__",
]
