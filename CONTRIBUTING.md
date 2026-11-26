# Contributing

Thanks for helping improve pypathcage.

## Setup

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

There are no runtime dependencies. Editable installation is only for convenience.

## Test before you open a pull request

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The suite must stay deterministic: no network, no real user data, and all filesystem fixtures created inside `tempfile.TemporaryDirectory()`.

## Adding a security check

1. Add a failing test that constructs the hostile path or archive.
2. Implement the smallest lexical or containment check that fixes it.
3. Make sure the error code is specific and documented.
4. Update README and the threat model if the guarantee changes.

Avoid adding dependencies. The library intentionally uses only the Python standard library.

## Style

- Python 3.9 compatible syntax only
- `from __future__ import annotations` in modules
- No em dashes or en dashes in documentation
- Keep public API names stable

## Commit messages

Use a short imperative subject line and explain the security impact in the body when relevant.

## Code of conduct

Be respectful. Assume good faith. Security reports should follow SECURITY.md.
