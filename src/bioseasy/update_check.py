# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional, privacy-respecting update check against GitHub Releases.

Off by default; an admin turns it on from Settings. `GITHUB_REPO` below is the one place naming
the repository to check. While it is empty the checker never contacts anything, regardless of the
admin toggle, and the Settings page says so - which is what a fork or a private build can set it
to. With it set, turning the toggle on lets a worker task compare the newest GitHub release
against the running version, at most once a day, and show a small notice to admins. Nothing about
this install is sent: the request is a plain, unauthenticated GET to GitHub's public releases API,
carrying only the User-Agent GitHub requires of API callers - no device counts, UDIDs, or other
identifying data.

The result (or the fact that the last attempt failed) is cached in the `settings` table
(`db.get_setting`/`set_setting`, the same key-value table other one-off state already lives in),
so a page render never itself makes the network call - only the periodic worker task does that,
gated by `should_check` so a check missing (timeout, GitHub down) never gets reported as "up to
date": the cached result then still says "check failed" until the next attempt succeeds.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

import httpx

from . import db

log = logging.getLogger("bioseasy")

# Where releases are published. Empty disables the checker entirely, see module docstring.
GITHUB_REPO = "werk-xyz/bioseasy"

_ENABLED_KEY = "update_check_enabled"
_RESULT_KEY = "update_check_result"
MIN_CHECK_INTERVAL = timedelta(days=1)
_REQUEST_TIMEOUT = 5.0


@dataclass
class UpdateCheckResult:
    checked_at: str  # ISO 8601 UTC
    ok: bool
    latest_version: str | None = None
    update_available: bool = False
    error: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def is_enabled(conn: sqlite3.Connection) -> bool:
    return db.get_setting(conn, _ENABLED_KEY, "false") == "true"


def set_enabled(conn: sqlite3.Connection, value: bool) -> None:
    db.set_setting(conn, _ENABLED_KEY, "true" if value else "false")


def last_result(conn: sqlite3.Connection) -> UpdateCheckResult | None:
    raw = db.get_setting(conn, _RESULT_KEY)
    if raw is None:
        return None
    try:
        return UpdateCheckResult(**json.loads(raw))
    except (json.JSONDecodeError, TypeError):
        return None


def _store(conn: sqlite3.Connection, result: UpdateCheckResult) -> None:
    db.set_setting(conn, _RESULT_KEY, json.dumps(asdict(result)))


def should_check(conn: sqlite3.Connection, now: datetime | None = None) -> bool:
    """True only when the admin turned the checker on, a repository is configured, and either no
    check has happened yet or the last one is at least MIN_CHECK_INTERVAL old."""
    if not GITHUB_REPO or not is_enabled(conn):
        return False
    previous = last_result(conn)
    if previous is None:
        return True
    now = now or _now()
    checked_at = datetime.fromisoformat(previous.checked_at)
    return now - checked_at >= MIN_CHECK_INTERVAL


def _parse_version(text: str) -> tuple[int, ...] | None:
    """A best-effort numeric version for comparison ("v1.2.3" / "1.2.3" -> (1, 2, 3)); None for
    anything that does not parse, so the caller falls back to a plain string comparison instead
    of guessing. Deliberately dependency-free (no `packaging` import): this is a "newer exists,
    go look" notice, not a resolver decision."""
    text = text.strip().lstrip("vV")
    parts = text.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _is_newer(latest: str, current: str) -> bool:
    a, b = _parse_version(latest), _parse_version(current)
    if a is not None and b is not None:
        return a > b
    return latest != current


def run_check(
    conn: sqlite3.Connection,
    current_version: str,
    now: datetime | None = None,
    client: httpx.Client | None = None,
) -> None:
    """Performs the check (if `should_check` says one is due) and stores the result. Always call
    through `should_check` first; this does not re-check the gate itself so a caller in tests can
    force a check regardless of timing.
    """
    now = now or _now()
    owns_client = client is None
    client = client or httpx.Client(timeout=_REQUEST_TIMEOUT)
    try:
        response = client.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
            headers={"User-Agent": "bioseasy-update-check", "Accept": "application/vnd.github+json"},
        )
        response.raise_for_status()
        latest = str(response.json()["tag_name"])
        result = UpdateCheckResult(
            checked_at=now.isoformat(),
            ok=True,
            latest_version=latest,
            update_available=_is_newer(latest, current_version),
        )
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        log.warning("Update check failed: %s", exc)
        result = UpdateCheckResult(checked_at=now.isoformat(), ok=False, error=exc.__class__.__name__)
    finally:
        if owns_client:
            client.close()
    _store(conn, result)
