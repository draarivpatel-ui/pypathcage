# pypathcage

Zero-dependency path traversal, Zip-Slip, Tar-Slip (CVE-2007-4559) and decompression-bomb protection for Python 3.9+.

`pypathcage` gives you small, auditable primitives that reject hostile paths and hostile archive members before they touch your filesystem. It has no runtime dependencies at all: just the Python standard library.

## Install

```sh
pip install pypathcage
```

## Why

Real attacks are not just `../`. They include:

- Mixed separators: `..\..\evil`
- NUL bytes and control characters in names
- Fullwidth Unicode look alikes such as `／`, `＼` and `．`
- RTL overrides that hide the real extension
- Windows drive letters, UNC paths, `\\?\` prefixes, alternate data streams and reserved device names such as `CON`, `COM1` and `LPT9`
- Prefix confusion (`/tmp/cage-evil` next to `/tmp/cage`)
- Symlinks in an existing ancestor of a path that does not exist yet
- Archive members that are symlinks or hardlinks pointing outside the destination
- ZIP members marked as Unix symlinks, which a naive extractor turns into real links
- Encrypted archive members that cannot be inspected or extracted
- TAR device and FIFO entries
- Compression bombs that lie about their uncompressed size

`pypathcage` covers all of these, and it enforces byte limits on the bytes actually extracted rather than trusting headers.

## Core API

### PathCage and resolve_safe_path

```python
from pathlib import Path
from pypathcage import PathCage, resolve_safe_path, PathCageError, ErrorCode

root = Path("/srv/uploads")
cage = PathCage(root)

try:
    safe = cage.resolve(user_supplied_path)
except PathCageError as exc:
    if exc.code == ErrorCode.TRAVERSAL:
        print("rejected traversal attempt")
```

`resolve_safe_path(root, candidate)` is a one-shot wrapper around `PathCage`.

The default `no_symlinks=True` rejects any symlink encountered on the resolved path, including a symlinked ancestor of a nonexistent tail. With `no_symlinks=False`, containment is still enforced using `os.path.realpath`, so a symlink that points outside the root is rejected with `OUTSIDE_ROOT`.

### sanitize_filename

```python
from pypathcage import sanitize_filename

safe_name = sanitize_filename(user_filename)  # single safe path component
```

Separators, control characters, NUL bytes, Unicode look alikes and Windows constructs are replaced. The result never contains `..`, a separator, or a reserved device name.

## Drop-in safe archive extraction

### Replace tarfile.extractall()

```python
# Before (unsafe)
with tarfile.open(upload) as tf:
    tf.extractall(destination)

# After
from pypathcage import safe_extract_tar
safe_extract_tar(upload, destination)
```

### Replace zipfile.extractall()

```python
# Before (unsafe)
with zipfile.ZipFile(upload) as zf:
    zf.extractall(destination)

# After
from pypathcage import safe_extract_zip
safe_extract_zip(upload, destination)
```

Both extractors accept a path, a file object, or an already-open `ZipFile` / `TarFile`. They also accept an `ArchiveLimits` object:

ZIP symlink entries (Unix mode `0o120000` in the external attributes) and encrypted ZIP members are rejected instead of being silently turned into regular files, because the extractor never calls `ZipFile.extract`. TAR link members are rejected by default and can be enabled explicitly with `ArchiveLimits(no_symlinks=False, allow_links=True)`, which still checks every target for containment.

```python
from pypathcage import ArchiveLimits, safe_extract_zip

limits = ArchiveLimits(
    max_files=1000,
    max_file_bytes=10 * 1024 * 1024,
    max_total_bytes=50 * 1024 * 1024,
    max_compression_ratio=100.0,
)
report = safe_extract_zip(upload, destination, limits=limits)
print(report.total_uncompressed)
```

### Inspect without extracting

```python
from pypathcage import inspect_zip, inspect_tar

report = inspect_zip("bundle.zip")
print(report.member_count, report.names)
```

## CLI

```sh
python3 -m pypathcage inspect bundle.zip
python3 -m pypathcage inspect bundle.tar.gz --json
python3 -m pypathcage inspect bundle.zip --max-files 100 --max-ratio 50
```

Exit status is `0` for a safe archive, `1` for a rejection and `2` for a usage error.

## Error codes

Every failure raises `PathCageError`, a `ValueError` subclass with a typed `.code` from the `ErrorCode` enum. Codes cover traversal, absolute paths, NUL bytes, control characters, Unicode confusables, bidirectional overrides, Windows drive/UNC/ADS/reserved-name/trailing-character constructs, symlinks, out-of-root resolution, file count, per-file and total byte limits, compression ratio, duplicate names and unsupported members.

## Threat model

`pypathcage` assumes the archive or path is fully attacker-controlled and that the destination directory is trusted. It guarantees:

1. Every extracted member resolves inside the destination root, including through symlinked ancestors and link members.
2. No archive member can create a device, FIFO or other special file.
3. File count, per-file bytes, total uncompressed bytes and compression ratio are enforced on real extracted bytes, not just headers.
4. Lexically hostile names are rejected consistently on every platform.

It does not scan for malware, decrypt archives or provide an antivirus boundary. Links are rejected by default; callers who opt in must accept the documented containment checks. ZIP symlink and encrypted members are always rejected. `inspect_*` reports header-derived sizes, so use extraction when the limits must be enforced against the bytes actually written.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The suite contains 246 deterministic tests that build real hostile ZIP and TAR archives in temporary directories and clean them up automatically.

## License

MIT. See [LICENSE](LICENSE).
