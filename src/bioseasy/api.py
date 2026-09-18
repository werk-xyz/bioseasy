# SPDX-License-Identifier: GPL-3.0-or-later
"""Status API: a user queries the status of their own devices with a personal API token (see
`tokens.py`), and -- for a token with scope='backup' -- starts a backup of one of them. Mounted
at /api/v1 as its own FastAPI sub-application, so it gets its own OpenAPI schema (served at
/api/v1/openapi.json) and its own JSON-only error handling, independent of the main app's HTML
error pages.

Bearer auth only. Mounting does not remove the main app's SessionMiddleware from the request
path (it wraps the whole outer ASGI app, mount included, so `request.session` is technically
reachable here too), but nothing below ever reads it: no route here checks or authorizes
anything from `request.session`, so a session cookie carries no authority on these routes and
there is nothing for CSRF to ride. No CSRF token is needed here for the same reason (CSRF relies
on a cookie the browser attaches automatically; a bearer token the caller must set explicitly in
a header is not sent that way).

Every read goes through `status.for_owner` or `status.for_admin`, never a route-local query, so
the scoping guarantee documented in status.py (an owner can only ever see their own devices) is
what protects these routes too. The one write route, POST /devices/{udid}/backup, resolves the
device the same way before it does anything else, so a foreign device is a 404 here exactly like
everywhere else in the app, never a 403 that would confirm the udid exists.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from . import auth, status, tokens
from .config import Settings

# The limiters' clock, one name so tests can hold it inside one window without freezing the
# process-wide time.monotonic that the event loop also relies on.
_clock = time.monotonic

RATE_LIMIT_PER_MINUTE = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
# Deliberately generic and identical for every failure mode: a missing header, a malformed
# token, an unknown prefix and a revoked token must not be distinguishable from the response,
# or the error itself becomes an oracle for probing tokens.
_UNAUTHORIZED_DETAIL = "Missing, malformed, unknown or revoked API token"


class FixedWindowLimiter:
    """60 requests per whole-minute window per key, held in memory only.

    In memory on purpose, the same trade-off as auth.LoginThrottle: a restart resets it, which
    is fine for a single home server, and it keeps the database free of attacker-controlled rows.
    A fixed window (not a sliding one) can allow a short burst across a window boundary; that is
    an accepted, documented simplicity trade-off for a slim read-only API, not an oversight.
    """

    def __init__(self, limit: int = RATE_LIMIT_PER_MINUTE, window_seconds: float = RATE_LIMIT_WINDOW_SECONDS):
        self._limit, self._window = limit, window_seconds
        self._counts: dict[str, tuple[int, int]] = {}  # key -> (window index, count in it)

    def check(self, key: str, now: float) -> float:
        """Records one request for `key` and returns 0.0 if it is allowed, else the number of
        seconds until the window resets (for a Retry-After header)."""
        window = int(now // self._window)
        count, seen_window = self._counts.get(key, (0, window))
        count = count + 1 if seen_window == window else 1
        self._counts[key] = (count, window)
        if count > self._limit:
            return self._window - (now % self._window)
        return 0.0


@dataclass(frozen=True)
class ApiPrincipal:
    """The authenticated caller plus the token's own scope, so a route can tell a read-only
    token from one allowed to start backups without a second database round trip."""

    user: auth.User
    scope: str


def build_api_app(
    settings: Settings, connect: Callable[[], sqlite3.Connection], backup_device: Callable[[str, str], None]
) -> FastAPI:
    api = FastAPI(
        title="bioseasy status API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    token_limiter = FixedWindowLimiter()
    ip_limiter = FixedWindowLimiter()

    def get_conn() -> Iterator[sqlite3.Connection]:
        with closing(connect()) as conn:
            yield conn

    def unauthorized() -> HTTPException:
        return HTTPException(status_code=401, detail=_UNAUTHORIZED_DETAIL, headers={"WWW-Authenticate": "Bearer"})

    def rate_limited(wait: float) -> HTTPException:
        return HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(int(wait) + 1)})

    def bearer_token(request: Request, authorization: str | None = Header(default=None)) -> str:
        # The per-IP limit counts every request before any token lookup, so a flood of guessed
        # tokens is throttled too instead of costing a hash comparison each (OWASP API4).
        ip_key = request.client.host if request.client else "unknown"
        wait = ip_limiter.check(f"ip:{ip_key}", _clock())
        if wait > 0:
            raise rate_limited(wait)
        # The auth scheme name is case-insensitive (RFC 7235 section 2.1, RFC 6750 section 2.1).
        scheme, _, credentials = (authorization or "").partition(" ")
        token = credentials.strip()
        if scheme.lower() != "bearer" or not token:
            raise unauthorized()
        return token

    def current_api_principal(
        token: str = Depends(bearer_token),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> ApiPrincipal:
        row = tokens.authenticate(conn, token)
        if row is None:
            raise unauthorized()
        user = auth.get_user(conn, row["user_id"])
        if user is None:
            # Defensive only: ON DELETE CASCADE (db.py) removes a user's tokens with them, so a
            # token row with no matching user should not exist by the time we get here.
            raise unauthorized()

        wait = token_limiter.check(f"tok:{row['id']}", _clock())
        if wait > 0:
            raise rate_limited(wait)

        tokens.touch_last_used(conn, row["id"])
        return ApiPrincipal(user=user, scope=row["scope"])

    def visible_statuses(conn: sqlite3.Connection, user: auth.User) -> list[status.DeviceStatus]:
        now = datetime.now(UTC)
        if user.is_admin:
            return status.for_admin(conn, settings.backup_root, now)
        return status.for_owner(conn, settings.backup_root, now, user.id)

    def visible_status(conn: sqlite3.Connection, user: auth.User, udid: str) -> status.DeviceStatus:
        match = next((s for s in visible_statuses(conn, user) if s.udid == udid), None)
        if match is None:
            # Same body and status for "does not exist" and "belongs to someone else": a member
            # must not learn which UDIDs exist, the same rule app.py's visible_device follows.
            raise HTTPException(status_code=404, detail="Device not found")
        return match

    @api.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @api.get("/devices")
    def list_devices(
        principal: ApiPrincipal = Depends(current_api_principal), conn: sqlite3.Connection = Depends(get_conn)
    ) -> list[dict]:
        return [status.to_public(s) for s in visible_statuses(conn, principal.user)]

    @api.get("/devices/{udid}")
    def get_device(
        udid: str,
        principal: ApiPrincipal = Depends(current_api_principal),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> dict:
        return status.to_public(visible_status(conn, principal.user, udid))

    @api.post("/devices/{udid}/backup", status_code=202)
    def start_backup(
        udid: str,
        principal: ApiPrincipal = Depends(current_api_principal),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> dict:
        # Resolve the device (and so 404 a foreign or unknown udid) before the scope check, the
        # same order app.py's visible_device-then-admin_user routes use: a read-only token must
        # not learn whether a udid exists just by getting 403 instead of 404 for someone else's.
        device = visible_status(conn, principal.user, udid)
        if principal.scope != tokens.SCOPE_BACKUP:
            raise HTTPException(status_code=403, detail="This token cannot start backups")
        if device.state in ("running", "waiting_for_passcode"):
            raise HTTPException(status_code=409, detail="A backup is already running for this device")
        # Enqueue exactly like the web UI's "Back up now" (app.py's backup_now): the web/API
        # process only ever enqueues, the worker runs the backup through the same JobManager path.
        backup_device(udid, "api")
        return status.to_public(visible_status(conn, principal.user, udid))

    return api
