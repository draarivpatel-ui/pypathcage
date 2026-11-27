# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes land on the latest 1.x release. Upgrade before reporting an issue that only reproduces on an older release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/pypathcage/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected pypathcage version or commit.
- The Python version and operating system.
- A minimal proof of concept or input that demonstrates the problem.
- The expected behavior and the observed behavior.
- A short assessment of impact and any preconditions.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix or documented mitigation within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

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

Extraction is safe only when the destination root itself is trusted. Do not extract into a directory that an attacker can modify concurrently. The library rejects TAR links by default; enabling `allow_links` requires `no_symlinks=False` and still checks containment of every link target. ZIP members marked as Unix symlinks and encrypted members are always rejected.
