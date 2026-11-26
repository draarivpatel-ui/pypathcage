# Security Policy

## Supported versions

The latest released 1.x version receives security fixes.

## Reporting a vulnerability

Please open a private security advisory through the repository's security tab rather than a public issue. Include:

- A minimal proof of concept (a path string or a small crafted archive)
- The version of Python and pypathcage you tested
- The impact you observed

Do not publish the advisory until a fix is available. Reports are acknowledged within seven days.

## What is in scope

- Path containment bypasses, including symlink and realpath edge cases
- Archive member names that escape the extraction root
- Link members that point outside the root
- Resource exhaustion that defeats the configured limits
- Cases where header values are trusted over actual extracted bytes
- Case-insensitive collisions that overwrite another member

## What is out of scope

- Malware scanning or content inspection
- Vulnerabilities in Python's `zipfile` or `tarfile` themselves
- Callers who deliberately disable containment with custom limits
- Denial of service through archives accepted with caller-raised limits

## Hardening notes

Extraction is safe only when the destination root itself is trusted. Do not extract into a directory that an attacker can modify concurrently. The library rejects links by default; enabling `allow_links` requires `no_symlinks=False` and still checks containment of every link target.
