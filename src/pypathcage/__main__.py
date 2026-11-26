"""Command line entry point: ``python3 -m pypathcage inspect <archive>``."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
import zipfile
from typing import List, Optional

from .archives import ArchiveLimits, inspect_tar, inspect_zip
from .errors import ErrorCode, PathCageError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m pypathcage",
        description="Inspect ZIP/TAR archives for traversal and bomb risks.",
    )
    sub = parser.add_subparsers(dest="command")
    inspect = sub.add_parser("inspect", help="inspect an archive without extracting it")
    inspect.add_argument("archive", help="path to a .zip, .tar, .tar.gz or .tgz file")
    inspect.add_argument("--json", action="store_true", help="emit the report as JSON")
    inspect.add_argument(
        "--max-files", type=int, default=10_000, help="maximum member count"
    )
    inspect.add_argument(
        "--max-file-bytes", type=int, default=100 * 1024 * 1024, help="maximum bytes per member"
    )
    inspect.add_argument(
        "--max-total-bytes", type=int, default=512 * 1024 * 1024, help="maximum total uncompressed bytes"
    )
    inspect.add_argument(
        "--max-ratio", type=float, default=200.0, help="maximum compression ratio per member"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "inspect":
        parser.print_help()
        return 2

    try:
        limits = ArchiveLimits(
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            max_compression_ratio=args.max_ratio,
        )
        if zipfile.is_zipfile(args.archive):
            report = inspect_zip(args.archive, limits=limits)
        elif tarfile.is_tarfile(args.archive):
            report = inspect_tar(args.archive, limits=limits)
        else:
            raise PathCageError(
                ErrorCode.INVALID_ARCHIVE, "unrecognized archive format", args.archive
            )
    except PathCageError as exc:
        print("error [{0}]: {1}".format(exc.code.value, exc), file=sys.stderr)
        return 1
    except ValueError as exc:
        # ArchiveLimits rejects negative and non-finite values; argparse has
        # already validated the types, so this is a usage error, not a crash.
        print("error [usage]: {0}".format(exc), file=sys.stderr)
        return 2
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print("error [invalid_archive]: {0}".format(exc), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_dict(), sort_keys=True))
    else:
        print("kind: {0}".format(report.kind))
        print("members: {0}".format(report.member_count))
        print("regular files: {0}".format(report.regular_files))
        print("directories: {0}".format(report.directories))
        print("links: {0}".format(report.links))
        print("uncompressed bytes: {0}".format(report.total_uncompressed))
        for name in report.names:
            print("  {0}".format(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
