#!/usr/bin/env python3
"""Guard: every runtime dependency in uv.lock must be named somewhere in NOTICE.

This does not generate NOTICE (it is maintained by hand, see the file's own header) and it does
not check licenses or source links, only that a new runtime dependency cannot silently land in
the image without at least a name-check against the third-party notices. Run directly
(`uv run python scripts/check_notice_coverage.py`) or via `tests/test_notice.py`, and in CI
alongside the other lint/test gates.

Exit status: 0 when every runtime dependency is named in NOTICE, 1 when the tool itself could not
run (uv export failed, NOTICE missing), 2 when one or more dependencies are missing from NOTICE.
Each failure mode prints a distinct, unambiguous message so a broken guard is never mistaken for
a passing one.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTICE_PATH = REPO_ROOT / "NOTICE"

# Requirement lines uv export can produce that are not a package name.
_SKIP_PREFIXES = ("#", "-e ", "-r ", "--")


def normalize(name: str) -> str:
    """Fold PyPI name variants (case, -, _, .) to one comparable form."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def runtime_dependency_names() -> list[str]:
    """The exact set uv would install for the image: frozen, no dev group."""
    try:
        result = subprocess.run(
            ["uv", "export", "--frozen", "--no-dev", "--no-hashes"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not run `uv export`: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"`uv export --frozen --no-dev --no-hashes` failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    names = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        # Lines look like "package==1.2.3" or "package==1.2.3 ; sys_platform == '...'"
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)==", line)
        if match:
            names.append(match.group(1))
    if not names:
        raise RuntimeError(
            "`uv export` produced no dependency lines; refusing to treat an empty list as 'everything is covered'"
        )
    return names


def load_notice_text() -> str:
    if not NOTICE_PATH.exists():
        raise RuntimeError(f"NOTICE not found at {NOTICE_PATH}")
    text = NOTICE_PATH.read_text(encoding="utf-8")
    if not text.strip():
        raise RuntimeError(f"NOTICE at {NOTICE_PATH} is empty")
    return text


def find_missing(dependency_names: list[str], notice_text: str) -> list[str]:
    """Names not present as a distinct token anywhere in NOTICE (table row or prose)."""
    # Normalize the NOTICE text into the same token space: split on anything that is not
    # alphanumeric/dot, then normalize each token the same way as a dependency name.
    notice_tokens = {normalize(tok) for tok in re.split(r"[^A-Za-z0-9.\-_]+", notice_text) if tok}
    missing = []
    for dep in dependency_names:
        if normalize(dep) not in notice_tokens:
            missing.append(dep)
    return missing


def main() -> int:
    try:
        dependency_names = runtime_dependency_names()
        notice_text = load_notice_text()
    except RuntimeError as exc:
        print(f"GUARD COULD NOT RUN: {exc}", file=sys.stderr)
        return 1

    missing = find_missing(dependency_names, notice_text)
    if missing:
        print(
            f"NOTICE is missing {len(missing)} runtime dependency name(s) from uv.lock:",
            file=sys.stderr,
        )
        for name in sorted(missing):
            print(f"  - {name}", file=sys.stderr)
        return 2

    print(f"NOTICE covers all {len(dependency_names)} runtime dependencies from uv.lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
