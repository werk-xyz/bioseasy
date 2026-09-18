# SPDX-License-Identifier: GPL-3.0-or-later
"""The web application: pages, htmx partials and the guards in front of them.

Every route that touches a device resolves it through `visible_device`, which applies the
ownership rule once for reads and writes alike.
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

from authlib.integrations.starlette_client import OAuthError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from joserfc.errors import JoseError
from starlette.middleware.sessions import SessionMiddleware

from . import (
    activity,
    api,
    auth,
    browse,
    connectors,
    db,
    demo_seed,
    diagnostics,
    docs,
    events,
    export,
    extract,
    handoff,
    inventory,
    logview,
    mountinfo,
    mqtt,
    notify,
    oidc,
    pairing,
    password_check,
    reachability,
    snapshots,
    status,
    storage,
    tasks,
    tokens,
    update_check,
    verify,
    webpush,
)
from . import defaults as backup_defaults
from .config import Settings, load
from .engine.base import Engine
from .jobs import JobState
from .runtime import build as build_runtime
from .runtime import (
    mark_backup_starting,
    mark_netcheck_running,
    mark_setup_action_running,
    mark_setup_detect_running,
    run_encryption_enable,
    run_password_change,
    setup_detect_due,
    setup_detect_state,
)

log = logging.getLogger("bioseasy")
WEB = Path(__file__).parent / "web"
MAX_PASSWORD_CHECK_CHARS = 1024
# A confirmed password older than this counts as stale; the device page asks again.
PASSWORD_CHECK_MAX_AGE_DAYS = 90
# The setup wizard's own backup-encryption password (src/bioseasy/runtime.py,
# run_encryption_enable). Minimum matches iOS's own backup password rule; maximum only guards
# against an absurd request body, the same role MAX_PASSWORD_CHECK_CHARS plays for the password
# check below.
MIN_ENCRYPTION_PASSWORD_CHARS = 8
MAX_ENCRYPTION_PASSWORD_CHARS = 1024
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
# One RFC 1123 label: 1 to 63 letters/digits/hyphens, never starting or ending with a hyphen.
_HOSTNAME_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")


def _valid_time_of_day(value: str) -> bool:
    return bool(_TIME_RE.fullmatch(value))


def valid_fixed_address(value: str) -> bool:
    """True for an IPv4/IPv6 literal or an RFC 1123 hostname; false for a URL, a host:port pair,
    anything with whitespace, or anything else that is not plainly an address (engine/pmd3.py
    connects to this value directly, so it is never allowed to carry scheme, path or query)."""
    if not value or any(ch.isspace() for ch in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if "://" in value or len(value) > 253:
        return False
    labels = value.split(".")
    return bool(labels) and all(_HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)


def resolve_base_url(settings: Settings, request: Request) -> str:
    """Where a script served by this process should send its result back to.

    BIOSEASY_BASE_URL wins when set (the operator knows their own public address, e.g. behind a
    reverse proxy); otherwise this falls back to the scheme and host the request itself came in
    on, matching every other self-reported URL in the app (see oidc.py's redirect_uri).
    """
    if settings.base_url:
        return settings.base_url.rstrip("/")
    return f"{request.url.scheme}://{request.url.netloc}"


def base_url_is_unencrypted(base_url: str) -> bool:
    """True when `base_url` is plain HTTP and not obviously confined to this machine or LAN.

    The pair-hand-off command's own page warns next to it: a pair record is a device credential
    (pairing.py), and plain HTTP would carry it across the network in the clear. A hostname that
    is not an IP literal cannot be checked without a DNS lookup this never performs, so anything
    that is not "localhost" or a private/loopback IP literal is treated as unencrypted-and-open.
    """
    parsed = urlsplit(base_url)
    if parsed.scheme != "http":
        return False
    host = parsed.hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_private or ip.is_loopback)


def _int_in_range(raw: str, low: int, high: int, label: str) -> tuple[int | None, str | None]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, f"{label} must be a whole number"
    if not (low <= value <= high):
        return None, f"{label} must be between {low} and {high}"
    return value, None


RETENTION_LABELS = {
    "keep_last": "Latest generations to keep",
    "keep_daily": "Daily generations to keep",
    "keep_weekly": "Weekly generations to keep",
    "keep_monthly": "Monthly generations to keep",
    "keep_yearly": "Yearly generations to keep",
}


def validate_retention_form(form: dict) -> tuple[dict, list[str]]:
    """Explicit allowlist for the device retention fields.

    Returns cleaned values for `snapshots.RETENTION_FIELDS` (each an int, or None meaning "use
    the server default") plus any problems. "default" mode (or an unrecognised mode) always
    yields None for every field; only "custom" reads the five number fields.
    """
    errors: list[str] = []
    if form.get("retention_mode", "default") != "custom":
        return dict.fromkeys(snapshots.RETENTION_FIELDS), errors
    values: dict[str, int] = {}
    for field in snapshots.RETENTION_FIELDS:
        value, err = _int_in_range(form.get(field, ""), 0, 1000, RETENTION_LABELS[field])
        if err:
            errors.append(err)
        else:
            values[field] = value
    if errors:
        return {}, errors
    problem = snapshots.retention_error(snapshots.RetentionPolicy(**values))
    if problem:
        errors.append(problem)
        return {}, errors
    return values, errors


def validate_global_defaults_form(form: dict) -> tuple[backup_defaults.GlobalDefaults | None, list[str]]:
    """Explicit allowlist and server-side validation for the admin Settings page's global backup
    defaults. Unlike a device override, every field here is required - there is no "inherit"
    level above the global defaults themselves."""
    errors: list[str] = []

    window_start = form.get("window_start", "").strip()
    window_end = form.get("window_end", "").strip()
    if not (_valid_time_of_day(window_start) and _valid_time_of_day(window_end)):
        errors.append("The scheduled window needs times in HH:MM format")

    only_when_charging = bool(form.get("only_when_charging"))

    interval, err = _int_in_range(form.get("interval_hours", ""), 1, 720, "Backup interval (hours)")
    if err:
        errors.append(err)

    overdue, err = _int_in_range(form.get("overdue_days", ""), 1, 60, "Overdue after (days)")
    if err:
        errors.append(err)

    retention_values: dict[str, int] = {}
    for field in snapshots.RETENTION_FIELDS:
        value, field_err = _int_in_range(form.get(field, ""), 0, 1000, RETENTION_LABELS[field])
        if field_err:
            errors.append(field_err)
        else:
            retention_values[field] = value
    retention = None
    if len(retention_values) == len(snapshots.RETENTION_FIELDS):
        retention = snapshots.RetentionPolicy(**retention_values)
        problem = snapshots.retention_error(retention)
        if problem:
            errors.append(problem)
            retention = None

    threshold, err = _int_in_range(form.get("free_space_threshold_gb", ""), 1, 10_000, "Free space threshold (GB)")
    if err:
        errors.append(err)

    notice_lead_minutes, err = _int_in_range(form.get("notice_lead_minutes", ""), 1, 120, "Notice lead time (minutes)")
    if err:
        errors.append(err)

    if errors:
        return None, errors
    return (
        backup_defaults.GlobalDefaults(
            window_start=window_start,
            window_end=window_end,
            only_when_charging=only_when_charging,
            interval_hours=interval,
            overdue_days=overdue,
            retention=retention,
            free_space_threshold_gb=threshold,
            notice_lead_minutes=notice_lead_minutes,
        ),
        errors,
    )


def validate_device_settings(form: dict) -> tuple[dict, list[str]]:
    """Explicit allowlist and server-side validation for the device settings form.

    Returns the cleaned values (only for fields that validated) and a list of readable problems.
    Never trusts the client for range or format checks, since a member can edit only their own
    device but the same form structure is reachable by anyone signed in.

    Every backup-behaviour field (interval, window, charging, overdue, retention) is its own
    "use the global default" / "custom" pair, matching the schema (db.py: NULL means inherit):
    "default" mode always yields None, so the row keeps inheriting even while the admin later
    changes the global default. "custom" reads and validates the field's own input.
    """
    errors: list[str] = []
    cleaned: dict = {}

    name = form.get("name", "").strip()
    if not (1 <= len(name) <= 64):
        errors.append("Name must be 1 to 64 characters")
    else:
        cleaned["name"] = name

    owner_label = form.get("owner_label", "").strip()
    if len(owner_label) > 64:
        errors.append("Owner label must be at most 64 characters")
    else:
        cleaned["owner_label"] = owner_label or None

    if form.get("interval_mode", "default") == "custom":
        interval, err = _int_in_range(form.get("interval_hours", ""), 1, 720, "Backup interval (hours)")
        if err:
            errors.append(err)
        else:
            cleaned["interval_hours"] = interval
    else:
        cleaned["interval_hours"] = None

    retention_values, retention_errors = validate_retention_form(form)
    if retention_errors:
        errors.extend(retention_errors)
    else:
        cleaned.update(retention_values)

    if form.get("window_mode", "default") == "custom":
        window_start = form.get("window_start", "").strip()
        window_end = form.get("window_end", "").strip()
        if not (window_start and window_end):
            errors.append("Set both the window start and end for a custom window")
        elif not (_valid_time_of_day(window_start) and _valid_time_of_day(window_end)):
            errors.append("The scheduled window needs times in HH:MM format")
        else:
            cleaned["window_start"] = window_start
            cleaned["window_end"] = window_end
    else:
        cleaned["window_start"] = None
        cleaned["window_end"] = None

    if form.get("charging_mode", "default") == "custom":
        cleaned["only_when_charging"] = 1 if form.get("only_when_charging") else 0
    else:
        cleaned["only_when_charging"] = None

    if form.get("overdue_mode", "default") == "custom":
        overdue, err = _int_in_range(form.get("overdue_days", ""), 1, 60, "Overdue after (days)")
        if err:
            errors.append(err)
        else:
            cleaned["overdue_days"] = overdue
    else:
        cleaned["overdue_days"] = None

    host_raw = form.get("host", "").strip()
    if host_raw and not valid_fixed_address(host_raw):
        errors.append("Fixed address must be an IP address or hostname, not a URL, port or anything with spaces")
    else:
        cleaned["host"] = host_raw or None  # empty clears it

    return cleaned, errors


def _ago(value: datetime | str | None) -> str:
    if value is None:
        return "never"
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    seconds = int((datetime.now(UTC) - value).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds // size} {unit} ago"
    return "just now"


def _duration_text(seconds: float) -> str:
    """ "3 min", "1 h", "20 s" - the same buckets as `_ago`, but down to whole seconds and
    without the trailing "ago", so it reads naturally after "running for" as well as before it."""
    seconds = max(0, int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds // size} {unit}"
    return f"{seconds} s"


# How long a running backup may go without a progress update before the device page starts
# showing the stall hint: more than 2 minutes. Independent of the engine's own
# stall watchdog (STALL_HINT_SECONDS is only about when to reassure the user; the engine decides
# when to actually give up).
STALL_HINT_SECONDS = 120
# Mirrors engine.pmd3.STALL_TIMEOUT's own default. Kept as a separate constant, not an import of
# engine.pmd3, because that module pulls in pymobiledevice3 at import time and runtime.py only
# ever imports it lazily inside make_engine() for exactly that reason; used only as a fallback
# when the configured engine does not expose a public `stall_timeout` attribute (DemoEngine).
DEFAULT_STALL_TIMEOUT = 600.0


def phase_text(phase: str, kind: str) -> str:
    """The setup wizard step 4 and the device page's status section both show this; `kind` is
    "iPhone" or "iPad" (device_kind), matching the rest of the setup wizard's copy."""
    if phase == "waiting_for_passcode":
        return f"Waiting for you to enter the passcode on the {kind}."
    if phase == "transferring":
        return "Transferring"
    if phase == "finishing":
        return "Finishing"
    return phase.replace("_", " ").capitalize() if phase else ""


def password_check_status(device: sqlite3.Row) -> dict:
    """Whether `device`'s last confirmed backup password is still within its freshness window.

    Only the most recent check is stored (db.py), so a stored result of 'wrong'
    (or none at all) is indistinguishable from "never confirmed" here by design: there is no
    history of past correct checks to fall back on.
    """
    checked_at = device["password_checked_at"]
    confirmed = device["password_check_result"] == "correct" and checked_at is not None  # noqa: S105
    stale = True
    if confirmed:
        checked_dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        stale = (datetime.now(UTC) - checked_dt).days >= PASSWORD_CHECK_MAX_AGE_DAYS
    return {"confirmed": confirmed, "stale": stale, "checked_at": checked_at}


def device_kind(product_type: str | None) -> str:
    """iPhone vs iPad wording for the setup wizard: the two flows are
    identical, only the noun in the copy changes. Anything unrecognised defaults to "iPhone"
    rather than showing "device" or "None", which matches every demo and test device."""
    if product_type and product_type.startswith("iPad"):
        return "iPad"
    return "iPhone"


def setup_incomplete(device: sqlite3.Row, backup) -> bool:
    """Whether the assisted setup wizard (docs/setup.md) still has an open step for `device`.

    `backup` is the BackupInfo device_summary() already read from disk (or None without one),
    passed in rather than re-read here so a dashboard loop over every device does not read each
    backup directory twice. "Paired" is not checked here: every row in `devices` was only ever
    inserted once a pair record existed (add_submit, add_device_from_pairing, add_pair_record),
    so it is never the open step.
    """
    wifi_and_encryption = device["wifi_enabled_at"] and device["encryption_enabled_at"]
    return not (wifi_and_encryption and backup is not None and backup.complete)


def setup_state(device: sqlite3.Row, backup) -> str:
    """ "done", "unconfirmed" or "open" - which is not the same question as `setup_incomplete`.

    The two timestamps are written when bioseasy itself switched Wi-Fi backups or encryption on,
    or when detection confirmed them. They can be empty on a device that is demonstrably fine: a
    pair record survives a recreated database, and detection only runs when the device is re-added
    or its setup page is opened (docs/setup.md, "Adding a device again"). Until then the dashboard
    told such a device to finish a setup it had plainly finished - it was backing up, encrypted,
    every night.

    So a device with a finished, encrypted backup on disk and no timestamps is reported as
    unconfirmed rather than open. The backup settles the encryption question by itself - it is
    encrypted or it is not - while the Wi-Fi flag cannot be read off a backup, which is exactly why
    this is "unconfirmed" and not "done".
    """
    if not setup_incomplete(device, backup):
        return "done"
    settled = backup is not None and backup.complete and backup.encrypted
    if settled and not (device["wifi_enabled_at"] and device["encryption_enabled_at"]):
        return "unconfirmed"
    return "open"


def create_app(
    settings: Settings | None = None, engine: Engine | None = None, *, huey_immediate: bool = False
) -> FastAPI:
    """`huey_immediate` runs every enqueued task synchronously, in-process, instead of through a
    separate `bioseasy worker` consumer - for tests only (tasks.build's docstring explains why);
    production always leaves it False, so the web process returns from a request at once."""
    settings = settings or load()
    pair_records = settings.data_dir / "pair-records"
    docs_dir = settings.docs_dir or docs.default_docs_dir()

    # The web process only ever enqueues (backups, discovery, pairing, the Wi-Fi setup step: all
    # through tasks.py) or reads the database and the backup directory back; the worker process
    # (bioseasy worker, __init__.py's _worker) is the one running JobManager and the schedule
    # tick, built the same way from runtime.build(). The one exception is run_encryption_enable,
    # always a plain thread here regardless: the setup wizard's encryption step never runs
    # through Huey.
    rt = build_runtime(settings, engine)
    built_tasks = tasks.build(rt)
    if huey_immediate:
        built_tasks.huey.immediate = True
    (
        backup_device,
        discover_now,
        pair_device,
        enable_wifi_step,
        netcheck_step,
        detect_setup_step,
        verify_snapshot_task,
    ) = (
        built_tasks.backup_device,
        built_tasks.discover_now,
        built_tasks.pair_device,
        built_tasks.enable_wifi_step,
        built_tasks.netcheck_step,
        built_tasks.detect_setup_step,
        built_tasks.verify_snapshot,
    )
    connect, notify_targets, storage_check, tz = (
        rt.connect,
        rt.notify_targets,
        rt.storage_check,
        rt.tz,
    )
    # Automatic demo sign-in exists for a demo deployment only. It needs all three switches, so a
    # real installation that copies one environment variable from a demo deployment stays locked.
    demo_autologin = settings.demo_autologin and settings.demo_seed and settings.engine == "demo"
    if settings.demo_autologin and not demo_autologin:
        log.warning("BIOSEASY_DEMO_AUTOLOGIN ignored: it needs BIOSEASY_ENGINE=demo and BIOSEASY_DEMO_SEED=true")

    disk_usage_cache = storage.DiskUsageCache()
    login_throttle_by_user = auth.LoginThrottle()
    login_throttle_by_ip = auth.LoginThrottle()
    # Same shape as the login throttle: 5 free attempts, then exponential backoff. Keyed by
    # device too, not just IP, so a shared address (family behind one router) cannot be used to
    # drain one device's free attempts and mask a targeted guess as someone else's traffic.
    password_check_throttle_by_device = auth.LoginThrottle()
    password_check_throttle_by_ip = auth.LoginThrottle()
    # Same shape again, for POST /pair/{code}: a wrong, expired or already-used code counts as a
    # failure, the same as a wrong password, so guessing codes gets exponentially slower per IP.
    pair_handoff_throttle_by_ip = auth.LoginThrottle()
    # None when OIDC is not configured: every OIDC route below 404s in that case, and the
    # login page and account page hide the button, so there is nothing an unconfigured
    # installation exposes.
    oauth_client = oidc.build_oauth(settings) if settings.oidc_enabled else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with closing(connect()) as conn:
            db.migrate(conn)
        # After migrate, so the handler's first write never races the table's own creation; see
        # logview.install (idempotent - safe to call again if the app is built more than once,
        # as every test using create_app() does).
        logview.install(connect, "web")
        if settings.demo_seed and settings.engine == "demo":
            from . import demo_seed

            demo_seed.seed(connect, settings.backup_root, data_dir=settings.data_dir)
        with closing(connect()) as conn:
            if not auth.has_users(conn):
                # Deliberate: the setup token is a one-time, first-run-only value with no admin
                # account yet to protect. README and setup.html both send the operator to the
                # container log to retrieve it (`docker compose logs bioseasy`); that is the
                # documented retrieval path, not a leak.
                log.warning(  # nosemgrep: python-logger-credential-disclosure
                    "No admin account yet. Open /setup and use this token: %s", auth.setup_token(settings.data_dir)
                )
        # The worker process (bioseasy worker, __init__.py's _worker) is the one actually running
        # jobs and ticking: it does its own startup sweep, heartbeat and schedule tick. The web
        # process only enqueues and must never also run either, or a run could be swept out from
        # under the worker and the schedule would run twice.
        #
        # The one thing the worker cannot do for us: backup passwords live in THIS process's
        # memory, so only this process can drop them. Sweeping them on access alone was not
        # enough - a reader who unlocks a backup and then closes the browser leaves the plaintext
        # in the heap until somebody else happens to open a files page, which on a home server can
        # be days. Nobody could use it (a read sweeps before it looks anything up, so the password
        # is asked for again), but "held for fifteen minutes" has to be true of the memory too,
        # not only of the behaviour.
        sweeper = threading.Thread(target=sweep_backup_passwords_forever, name="backup-password-sweep", daemon=True)
        sweeper.start()
        try:
            yield
        finally:
            backup_password_sweeper_stop.set()
            sweeper.join(timeout=2)

    app = FastAPI(title="bioseasy", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        max_age=settings.session_max_age,
        https_only=settings.secure_cookies,
        same_site="lax",
    )
    # Exposed on app.state so tests can monkeypatch the provider calls (authorize_redirect,
    # authorize_access_token) instead of reaching a real identity provider over the network.
    app.state.oidc_client = oauth_client.oidc if oauth_client else None
    # Exposed so a test can spy on or inspect enqueuing (e.g. proving a route really goes
    # through Huey, or that a particular call never enqueues) without reaching into create_app's
    # own closures.
    app.state.huey = built_tasks.huey
    app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")
    # Its own sub-application, not a router on `app`: bearer auth only, JSON-only errors, and its
    # own OpenAPI schema at /api/v1/openapi.json, independent of the HTML app around it (api.py).
    app.mount("/api/v1", api.build_api_app(settings, connect, backup_device))
    templates = Jinja2Templates(directory=WEB / "templates")
    templates.env.filters["ago"] = _ago
    templates.env.filters["duration"] = _duration_text
    # Computed once, not per request: the package version never changes while the process runs.
    app_version = diagnostics._package_version("bioseasy")
    templates.env.filters["kind"] = device_kind
    templates.env.filters["phase_text"] = phase_text

    def get_conn() -> Iterator[sqlite3.Connection]:
        with closing(connect()) as conn:
            yield conn

    def session_or_demo_user(request: Request, conn: sqlite3.Connection) -> auth.User | None:
        user = auth.session_user(conn, request.session)
        if user is not None or not demo_autologin:
            return user
        row = conn.execute("SELECT id FROM users WHERE username = ?", (demo_seed.DEMO_USER,)).fetchone()
        demo = auth.get_user(conn, row["id"]) if row else None
        if demo is not None:
            auth.start_session(request.session, demo)
        return demo

    def current_user(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> auth.User:
        user = session_or_demo_user(request, conn)
        if user is None:
            target = "/login" if auth.has_users(conn) else "/setup"
            raise HTTPException(status_code=303, headers={"Location": target})
        return user

    def admin_user(user: auth.User = Depends(current_user)) -> auth.User:
        if not user.is_admin:
            raise HTTPException(status_code=404)
        return user

    async def csrf_form(request: Request) -> dict[str, str]:
        form = await request.form()
        expected = request.session.get("csrf", "")
        if not expected or not secrets.compare_digest(str(form.get("csrf", "")), expected):
            raise HTTPException(status_code=403, detail="Form expired, reload the page")
        return {k: str(v) for k, v in form.items()}

    def visible_devices(conn: sqlite3.Connection, user: auth.User) -> list[sqlite3.Row]:
        if user.is_admin:
            return conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
        return conn.execute("SELECT * FROM devices WHERE owner_id = ? ORDER BY name", (user.id,)).fetchall()

    def visible_device(conn: sqlite3.Connection, user: auth.User, udid: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()
        # 404 for foreign devices too: a member must not learn which UDIDs exist.
        if row is None or (not user.is_admin and row["owner_id"] != user.id):
            raise HTTPException(status_code=404)
        return row

    def header_storage_context() -> dict:
        """Free/total space on the backup volume for the header storage bar - cheap
        shutil.disk_usage, cached briefly (storage.DiskUsageCache), never the heavier
        storage.check (a write probe, unsuited to running on every page load). Unknown or
        unmounted (the cache returns None) always reads "Storage unavailable", never a fabricated
        0 free of 0 total.
        """
        usage = disk_usage_cache.get(settings.backup_root)
        if usage is None:
            return {
                "storage_available": False,
                "storage_free_bytes": None,
                "storage_total_bytes": None,
                "storage_low": False,
                "storage_percent_used": None,
            }
        with closing(connect()) as conn:
            threshold_bytes = backup_defaults.get_global_defaults(conn).free_space_threshold_bytes
        low = usage.free_bytes < threshold_bytes
        used = max(0, usage.total_bytes - usage.free_bytes)
        percent_used = 100 if usage.total_bytes <= 0 else min(100, round(100 * used / usage.total_bytes))
        return {
            "storage_available": True,
            "storage_free_bytes": usage.free_bytes,
            "storage_total_bytes": usage.total_bytes,
            "storage_low": low,
            "storage_percent_used": percent_used,
        }

    def header_activity_context(user: auth.User | None) -> dict:
        """What the gear icon and its popover show: scoped like status.py, so a member never
        sees another owner's device activity (activity.for_owner's INNER JOIN). Covers both
        what is running now and what finished recently, showing a check mark for a while once
        something has finished, plus the single latest event the toast script compares against
        what it last saw."""
        empty = {
            "activities": [],
            "activity_count": 0,
            "activity_running": False,
            "finished_activities": [],
            "activity_outcome": None,
            "latest_event_id": "",
            "latest_event_text": "",
        }
        if user is None:
            return empty
        with closing(connect()) as conn:
            if user.is_admin:
                running_rows = activity.for_admin(conn)
                finished_rows = activity.for_admin_finished(conn)
            else:
                running_rows = activity.for_owner(conn, user.id)
                finished_rows = activity.for_owner_finished(conn, user.id)
        running = activity.running_for(running_rows)
        finished = activity.finished_for(finished_rows)
        event = activity.latest_event(running_rows, finished_rows)
        # The badge only reflects the most recent finished job, and only while nothing is
        # running - a spinning gear already says "busy", the badge is what shows once it stops.
        outcome = None if running else (finished[0]["outcome"] if finished else None)
        return {
            "activities": running,
            "activity_count": len(running),
            "activity_running": bool(running),
            "finished_activities": finished,
            "activity_outcome": outcome,
            "latest_event_id": event["id"] if event else "",
            "latest_event_text": event["text"] if event else "",
        }

    def cookie_will_be_dropped(request: Request) -> bool:
        """Whether the browser is about to throw the session cookie away.

        With secure cookies on (the default) and the page opened over plain HTTP at an address other
        than this machine itself, the browser refuses to store the cookie. Sign-in and setup then
        fail with "form expired" and nothing that says why - the most likely first experience of
        anyone following the quick start on a LAN. Browsers treat localhost as secure, so it is
        exempt. The scheme is the one uvicorn derived, forwarded headers from a trusted proxy
        included.
        """
        if not settings.secure_cookies or request.url.scheme != "http":
            return False
        return (request.url.hostname or "") not in ("localhost", "127.0.0.1", "::1")

    def render(request: Request, name: str, status_code: int = 200, **context) -> HTMLResponse:
        context.setdefault("user", None)
        context.setdefault("devices", [])
        context.setdefault("current_udid", None)
        context.setdefault("pairings", {})
        # Only device_settings.html and admin_settings.html use these; defaulted here (rather
        # than in every render() call on those templates) so a route that forgets one degrades
        # to an empty connector list instead of an undefined-variable error.
        context.setdefault("connectors", [])
        # Only device_settings.html (admin's owner-reassignment select) and users.html; defaulted
        # here for the same reason as connectors above, so an error re-render that forgot it still
        # shows an empty list instead of a template error.
        context.setdefault("local_users", [])
        context.setdefault("create_errors", {})
        context.setdefault("create_values", {})
        context.setdefault("edit_error_id", None)
        context.setdefault("edit_errors", [])
        context.setdefault("edit_values", {})
        # Only device_setup.html/_device_setup.html and device_settings.html include
        # _netcheck.html; defaulted here so a render() call that forgot it (a form error
        # re-render, a partial unrelated to the connectivity check) still shows "no result yet"
        # instead of a template error.
        context.setdefault("netcheck_run", None)
        context.setdefault("netcheck_return_to", "setup")
        # Only admin_settings.html; defaulted here for the same reason as the connector fields
        # above, so its own error-path render() calls (invalid connector form, etc.) do not need
        # to repeat these.
        # Every page in the Admin area renders the same section nav (_macros.html's
        # section_nav); set once here rather than in each of the eight routes, so a new
        # sub-page cannot silently come up without it. Pages outside the area simply never
        # ask for it - their templates guard with {% if admin_nav %}.
        context.setdefault("admin_nav", ADMIN_NAV)
        context.setdefault("settings_nav", SETTINGS_NAV)
        context.setdefault("update_check_repo_configured", False)
        context.setdefault("update_check_enabled", False)
        context.setdefault("update_check_result", None)
        # admin_settings.html only; defaulted here for the same reason as the connector context
        # above, so an error-path render() call does not need to repeat these.
        context.setdefault("mqtt_settings", {})
        context.setdefault("mqtt_password_set", False)
        context.setdefault("mqtt_errors", [])
        context["csrf"] = request.session.get("csrf", "")
        context["cookie_will_be_dropped"] = cookie_will_be_dropped(request)
        context["demo_mode"] = demo_autologin
        context["app_version"] = app_version
        context["app_revision"] = settings.revision
        context.update(header_storage_context())
        context.update(header_activity_context(context["user"]))
        return templates.TemplateResponse(request, name, context, status_code=status_code)

    def connectors_context(conn: sqlite3.Connection, scope: str, udid: str | None = None) -> list[dict]:
        return [connectors.connector_public(r) for r in connectors.list_connectors(conn, scope, udid)]

    def validate_connector_form(kind: str, form: dict) -> connectors.ConnectorForm:
        if kind not in connectors.KINDS:
            raise HTTPException(status_code=404)
        result = connectors.VALIDATORS[kind](form)
        if result.secret == "" and kind in connectors.REQUIRED_SECRET_LABEL:
            result.errors.append(connectors.REQUIRED_SECRET_LABEL[kind])
        return result

    def connector_test_response(row: sqlite3.Row) -> HTMLResponse:
        target = f"notify-test-{row['id']}"
        try:
            secret = (
                connectors.decrypt_secret(settings.data_dir, row["secret_ciphertext"])
                if row["secret_ciphertext"] is not None
                else None
            )
            url = connectors.build_apprise_url(row["kind"], json.loads(row["settings_json"]), secret)
        except (connectors.ConnectorSecretError, ValueError) as exc:
            return HTMLResponse(f'<p id="{target}" class="flash bad">{html.escape(str(exc))}</p>')
        result = notify.send([url], "Test notification from bioseasy", f"This is a test message for {row['label']}.")
        if result.ok:
            return HTMLResponse(f'<p id="{target}" class="flash">Test message sent.</p>')
        return HTMLResponse(f'<p id="{target}" class="flash bad">{html.escape(result.error)}</p>')

    def device_summary(conn: sqlite3.Connection, device: sqlite3.Row) -> dict:
        # Read running state from the runs row rather than JobManager.state(): backups run in a
        # separate worker process, so the web process's own in-memory dict
        # never sees them, but every process shares the database. The runs_one_running index
        # (db.py) guarantees at most one running row per device, and it is always the most
        # recent by started_at, so it is found within this LIMIT 7 without a second query.
        runs = conn.execute(
            "SELECT * FROM runs WHERE udid = ? ORDER BY started_at DESC LIMIT 7", (device["udid"],)
        ).fetchall()
        running_run = next((r for r in runs if r["status"] == "running"), None)
        backup = inventory.read_backup(settings.backup_root / device["udid"], with_size=False)
        has_backup = (settings.backup_root / device["udid"]).is_dir()
        last_ok = next((r for r in runs if r["status"] == "succeeded"), None)
        effective = backup_defaults.resolve_device(device, backup_defaults.get_global_defaults(conn))
        if running_run is not None:
            health = "running"
        elif not has_backup:
            health = "none"
        elif not backup.complete:
            health = "incomplete"
        elif (
            backup.last_backup
            and (datetime.now(UTC) - backup.last_backup).total_seconds() > effective.interval_hours * 3600 * 1.5
        ):
            health = "stale"
        else:
            health = "ok"
        job = None
        run_running_for = run_last_data = run_stall_hint = None
        if running_run is not None:
            job = JobState(
                udid=device["udid"],
                run_id=running_run["id"],
                phase=running_run["phase"] or "starting",
                percent=running_run["percent"],
                message=running_run["progress_message"] or "",
            )
            # heartbeat_at is set at INSERT time (jobs.py's start()) and refreshed on every
            # throttled progress write (jobs.py's _write_progress), so it is always the newest
            # of "a progress update landed" and "the run just started" - exactly "last data".
            now = datetime.now(UTC)
            started = datetime.fromisoformat(running_run["started_at"].replace("Z", "+00:00"))
            heartbeat_raw = running_run["heartbeat_at"] or running_run["started_at"]
            heartbeat = datetime.fromisoformat(heartbeat_raw.replace("Z", "+00:00"))
            run_running_for = _duration_text((now - started).total_seconds())
            seconds_since_data = (now - heartbeat).total_seconds()
            run_last_data = _duration_text(seconds_since_data)
            if job.phase == "transferring" and seconds_since_data > STALL_HINT_SECONDS:
                stall_timeout = getattr(rt.engine, "stall_timeout", DEFAULT_STALL_TIMEOUT)
                stall_minutes = int(stall_timeout // 60)
                run_stall_hint = (
                    f"No data for {run_last_data}. The device may be preparing files; bioseasy stops the "
                    f"run after {stall_minutes} min without data."
                )
        pair_days = status.pair_days_unused(device["paired_at"], device["pair_used_at"], datetime.now(UTC))
        return {
            "device": device,
            "runs": runs,
            "backup": backup if has_backup else None,
            "last_ok": last_ok,
            "health": health,
            "job": job,
            "run_running_for": run_running_for,
            "run_last_data": run_last_data,
            "run_stall_hint": run_stall_hint,
            "setup_incomplete": setup_incomplete(device, backup if has_backup else None),
            "setup_state": setup_state(device, backup if has_backup else None),
            "pair_days_unused": pair_days,
            "pair_warning": status.pair_warning(pair_days),
            "pair_expired": pair_days is not None and pair_days >= status.PAIR_EXPIRED_DAYS,
        }

    def device_policy(conn: sqlite3.Connection, device: sqlite3.Row) -> snapshots.RetentionPolicy:
        return backup_defaults.resolve_device(device, backup_defaults.get_global_defaults(conn)).retention

    def field_modes(device: sqlite3.Row) -> dict:
        """ "default"/"custom" for each of the device settings page's four override toggles, read
        from the saved row - the same NULL-means-inherit rule as validate_device_settings, just
        in the other direction, for every render() call that is not the settings page's own GET
        (which also needs this) but hits the "custom or not" question through a re-render."""
        return {
            "retention_mode": "custom" if any(device[f] is not None for f in snapshots.RETENTION_FIELDS) else "default",
            "interval_mode": "custom" if device["interval_hours"] is not None else "default",
            "window_mode": "custom" if device["window_start"] is not None else "default",
            "charging_mode": "custom" if device["only_when_charging"] is not None else "default",
            "overdue_mode": "custom" if device["overdue_days"] is not None else "default",
        }

    def retention_preview(udid: str, policy: snapshots.RetentionPolicy) -> str:
        """Short summary of what `policy` would do to the device's existing generations, for the
        settings page - computed with the same plan_retention the actual prune run uses, never a
        separate guess."""
        snaps = snapshots.list_snapshots(settings.backup_root, udid)
        if not snaps:
            return "No generations yet."
        removed = sum(1 for _, reasons in snapshots.plan_retention(snaps, policy, tz) if not reasons)
        return f"{removed} of {len(snaps)} generations would be removed on the next backup."

    def generations_context(conn: sqlite3.Connection, device: sqlite3.Row) -> dict:
        """Snapshot rows and total on-disk size for one device's Generations section.

        Sizing walks every snapshot directory, so this must only be called for a single
        device's own page, never for the dashboard's device list.
        """
        udid = device["udid"]
        live = settings.backup_root / udid
        snaps = snapshots.list_snapshots(settings.backup_root, udid)
        planned = snapshots.plan_retention(snaps, device_policy(conn, device), tz)
        verify_results = verify.load_results(conn, udid)
        # Which generation, if any, a "verify" activity is checking right now (activity.py's
        # snapshot_name, SCHEMA_VERSION 16) - so the row itself can show "Verifying..." instead of
        # only the header's activity indicator saying a verification is running somewhere.
        verifying_names = activity.running_snapshot_names(conn, "verify", udid)
        rows = [
            {
                "snapshot": s,
                "size_bytes": snapshots.disk_usage([s.path]),
                "kept_by": reasons,
                "verify": verify_results.get(s.path.name),
                "verifying": s.path.name in verifying_names,
            }
            for s, reasons in planned
        ]
        paths = ([live] if live.is_dir() else []) + [s.path for s in snaps]
        return {"udid": udid, "rows": rows, "total_bytes": snapshots.disk_usage(paths)}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        if exc.status_code == 303:
            return RedirectResponse(exc.headers["Location"], status_code=303)
        if request.headers.get("hx-request"):
            return HTMLResponse(f'<p class="flash bad">{html.escape(str(exc.detail))}</p>', status_code=exc.status_code)
        return render(request, "error.html", status_code=exc.status_code, status=exc.status_code, detail=exc.detail)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/setup")
    def setup_page(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
        if auth.has_users(conn):
            return RedirectResponse("/login", status_code=303)
        request.session.setdefault("csrf", secrets.token_urlsafe(24))
        return render(request, "setup.html")

    @app.post("/setup")
    def setup_submit(request: Request, form: dict = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_conn)):
        if auth.has_users(conn):
            return RedirectResponse("/login", status_code=303)
        if not auth.check_setup_token(settings.data_dir, form.get("token", "")):
            return render(request, "setup.html", error="The setup token is not valid. Copy it from the container log.")
        if form.get("password") != form.get("password2"):
            return render(request, "setup.html", error="The passwords do not match.", username=form.get("username"))
        try:
            # register_user, not create_user: the first admin gets the same required address as
            # every account created after it.
            user = auth.register_user(
                conn, form.get("username", ""), form.get("password", ""), "admin", form.get("email", "")
            )
        except ValueError as exc:
            return render(request, "setup.html", error=str(exc), username=form.get("username"), email=form.get("email"))
        auth.consume_setup_token(settings.data_dir)
        auth.start_session(request.session, user)
        return RedirectResponse("/", status_code=303)

    @app.get("/login")
    def login_page(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
        if not auth.has_users(conn):
            return RedirectResponse("/setup", status_code=303)
        request.session.setdefault("csrf", secrets.token_urlsafe(24))
        return render(
            request, "login.html", oidc_enabled=app.state.oidc_client is not None, oidc_name=settings.oidc_name
        )

    @app.post("/login")
    def login_submit(request: Request, form: dict = Depends(csrf_form), conn: sqlite3.Connection = Depends(get_conn)):
        now = time.monotonic()
        username_key = form.get("username", "").strip().lower()
        ip_key = request.client.host if request.client else "unknown"
        wait = max(
            login_throttle_by_user.wait_seconds(username_key, now), login_throttle_by_ip.wait_seconds(ip_key, now)
        )
        if wait > 0:
            # Throttled attempts never touch the password, so guessing does not even cost a
            # hash comparison once the free attempts are used up.
            return render(
                request,
                "login.html",
                status_code=429,
                error=f"Too many attempts, try again in {int(wait) + 1} seconds.",
                username=form.get("username"),
            )
        user = auth.authenticate(conn, form.get("username", ""), form.get("password", ""))
        if user is None:
            login_throttle_by_user.failed(username_key, now)
            login_throttle_by_ip.failed(ip_key, now)
            return render(request, "login.html", error="Username or password is wrong.", username=form.get("username"))
        login_throttle_by_user.succeeded(username_key)
        login_throttle_by_ip.succeeded(ip_key)
        auth.start_session(request.session, user)
        auth.record_sign_in(conn, user.id)
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request, form: dict = Depends(csrf_form)):
        # Drop any backup password the current session unlocked, rather than leaving it in memory
        # until its own expiry. Clearing the session alone would only lose the handle to it.
        forget_backup_passwords(request)
        forget_selections(request)
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/login/oidc")
    async def login_oidc(request: Request):
        if app.state.oidc_client is None:
            raise HTTPException(status_code=404)
        # A plain sign-in is never a linking flow, even if one was left half-started earlier.
        request.session.pop("oidc_link_uid", None)
        return await app.state.oidc_client.authorize_redirect(request, oidc.redirect_uri(settings))

    async def remote_userinfo(token: dict, claims: dict) -> dict | None:
        """The userinfo endpoint's answer, but only when the id_token cannot answer the group
        question on its own - authentik leaves the group claim out of the id_token unless the
        provider is told to include it, while Keycloak and Entra ID put it there. One extra HTTP
        call, skipped whenever no group is required or the claim is already in hand.
        """
        if not settings.oidc_required_group:
            return None
        if oidc.groups_of(claims, settings.oidc_groups_claim) is not None:
            return None
        try:
            return dict(await app.state.oidc_client.userinfo(token=token))
        except Exception as exc:  # the provider's problem, never a 500 here
            log.warning("userinfo could not be fetched from the provider (%s)", type(exc).__name__)
            return None

    async def resolve_by_email(conn: sqlite3.Connection, claims: dict, issuer: str, subject: str) -> auth.User:
        """Which account this identity signs in as, when no link exists for it yet: the account
        carrying the address the provider vouched for, or a newly registered one. Raises
        oidc.Refused with the reason in every other case (see oidc.py's module docstring)."""
        email = oidc.claimed_email(claims, require_verified=settings.oidc_require_verified_email)
        matched = oidc.find_user_by_email(conn, email)
        if matched is not None:
            user = auth.get_user(conn, matched)
            if user is None:  # pragma: no cover - the row was read one statement ago
                raise oidc.Refused("That account no longer exists.")
            oidc.bind(conn, user.id, issuer, subject)
            return user
        if not settings.oidc_allow_registration:
            raise oidc.Refused(
                "No account here uses that email address. Ask an administrator to create one, or "
                "to add your address to the account you already have."
            )
        try:
            user = auth.create_sso_user(conn, oidc.username_for(conn, claims, email), email)
        except ValueError as exc:
            raise oidc.Refused(str(exc)) from exc
        oidc.link(conn, user.id, issuer, subject)
        log.info("a new member account was created for a single sign-on identity")
        return user

    @app.get("/login/oidc/callback")
    async def login_oidc_callback(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
        if app.state.oidc_client is None:
            raise HTTPException(status_code=404)
        now = time.monotonic()
        ip_key = request.client.host if request.client else "unknown"
        wait = login_throttle_by_ip.wait_seconds(ip_key, now)
        if wait > 0:
            raise HTTPException(status_code=429, detail=f"Too many attempts, try again in {int(wait) + 1} seconds.")
        link_uid = request.session.pop("oidc_link_uid", None)
        try:
            token = await app.state.oidc_client.authorize_access_token(request)
        except (OAuthError, JoseError):
            # Covers a state mismatch and every other thing the provider or the browser can get
            # wrong about this exchange: never a 500, since none of it is our own bug.
            #
            # JoseError is the other half: Authlib checks the
            # id_token's signature and claims through joserfc, which raises its own errors rather
            # than OAuthError: a token signed with a key the provider does not publish, or one
            # naming a different issuer, must be refused rather than leave this route as a 500.
            # Caught by running the exchange against a provider told to misbehave on purpose
            # (tests/dummy_oidc.py), which is exactly what a patched client could never show.
            login_throttle_by_ip.failed(ip_key, now)
            raise HTTPException(status_code=400, detail="Sign-in failed, please try again.") from None
        claims = token.get("userinfo") or {}
        issuer, subject = claims.get("iss"), claims.get("sub")
        if not issuer or not subject:
            login_throttle_by_ip.failed(ip_key, now)
            raise HTTPException(status_code=400, detail="Sign-in failed, please try again.")

        if link_uid is not None:
            # Only the user who started this from /account may complete it, and only while
            # their session is still the one that started it (a password change in another tab
            # would end it, since session_user checks session_version).
            user = auth.session_user(conn, request.session)
            if user is None or user.id != link_uid:
                raise HTTPException(status_code=403, detail="Sign in again before linking a single sign-on identity.")
            try:
                # The same group gate as a plain sign-in: an identity that may not sign in here
                # must not be linkable either, or the gate would be one POST away from useless.
                oidc.check_group(claims, await remote_userinfo(token, claims), settings)
            except oidc.Refused as refused:
                return render(request, "error.html", status_code=403, status=403, detail=str(refused))
            try:
                oidc.link(conn, user.id, issuer, subject)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            return RedirectResponse("/settings", status_code=303)

        user_id = oidc.find_linked_user(conn, issuer, subject)
        user = auth.get_user(conn, user_id) if user_id is not None else None
        try:
            # Applies to every sign-in, not only to a new one: losing the required group has to
            # end access for an identity that was already linked, or the check would only ever
            # have gated the first visit.
            oidc.check_group(claims, await remote_userinfo(token, claims), settings)
            if user is None:
                user = await resolve_by_email(conn, claims, issuer, subject)
        except oidc.Refused as refused:
            login_throttle_by_ip.failed(ip_key, now)
            # 403 with the reason, as before: the exchange itself was fine, and an admin reading
            # this over the user's shoulder needs to know which of the checks said no. None of
            # these sentences says whether an account exists here.
            return render(request, "error.html", status_code=403, status=403, detail=str(refused))
        login_throttle_by_ip.succeeded(ip_key)
        auth.start_session(request.session, user)
        auth.record_sign_in(conn, user.id)
        return RedirectResponse("/", status_code=303)

    def account_context(conn: sqlite3.Connection, user: auth.User) -> dict:
        return {
            "user": user,
            "devices": visible_devices(conn, user),
            "links": oidc.list_links(conn, user.id),
            "oidc_enabled": app.state.oidc_client is not None,
            "oidc_name": settings.oidc_name,
            # Read-only on this page on purpose: the address decides which account a single
            # sign-on identity lands on, so only an admin changes it (auth.set_email).
            "email": user.email,
            "api_tokens": tokens.list_for_user(conn, user.id),
            "has_password": auth.has_password(conn, user.id),
            "min_password_length": auth.MIN_PASSWORD_LENGTH,
            "push_subscriptions": webpush.list_for_user(conn, user.id),
            "push_available": webpush.vapid_status(settings.data_dir),
            "push_vapid_public_key": webpush.public_key_b64url(settings.data_dir),
            "push_status": webpush.push_delivery_status(conn, user.id),
        }

    # The Admin area's sub-pages, in the order they appear in its section nav: everything
    # system-wide lives under one entry. One list, passed to every page in
    # the area, so a new sub-page is added here and nowhere else.
    ADMIN_NAV = (
        ("/admin", "Overview"),
        ("/admin/notifications", "Notifications"),
        ("/admin/storage", "Storage"),
        ("/admin/users", "Users"),
        ("/admin/defaults", "Defaults"),
        ("/admin/update", "Update check"),
        ("/admin/logs", "Logs"),
        ("/admin/about", "About"),
    )

    # The personal Settings area's sub-pages. Same shape as ADMIN_NAV, and the same reason for
    # living in one place: a new sub-page is added here, not in four route handlers.
    SETTINGS_NAV = (
        ("/settings", "Password"),
        ("/settings/sso", "Single sign-on"),
        ("/settings/tokens", "API tokens"),
        ("/settings/notifications", "Browser notifications"),
    )

    # The two things an admin can mean by "the log". They are
    # genuinely different sources, not two filters over one: the system log is free text from both
    # processes (`log_entries`), the application log is structured per-device events across every
    # owner (`events.py`). They are shown on one page with a switch rather than on two pages
    # because the question "what happened" is one question; they keep separate filters because
    # their vocabularies differ - a level and a process mean nothing to an event, and the system
    # log knows devices only by a shortened UDID.
    LOG_VIEWS = (("system", "System log"), ("application", "Application log"))

    @app.get("/admin")
    def admin_home(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(request, "admin.html", user=user, devices=visible_devices(conn, user), admin_nav=ADMIN_NAV)

    @app.get("/admin/notifications")
    def admin_notifications_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(
            request,
            "admin_notifications.html",
            user=user,
            devices=visible_devices(conn, user),
            admin_nav=ADMIN_NAV,
            saved=request.query_params.get("saved") == "1",
            connectors=connectors_context(conn, "admin"),
            mqtt_settings=mqtt.form_defaults(mqtt.stored_settings(conn) or {}),
            mqtt_password_set=mqtt.password_set(conn),
        )

    @app.get("/admin/update")
    def admin_update_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(
            request,
            "admin_update.html",
            user=user,
            devices=visible_devices(conn, user),
            admin_nav=ADMIN_NAV,
            saved=request.query_params.get("saved") == "1",
            update_check_repo_configured=bool(update_check.GITHUB_REPO),
            update_check_enabled=update_check.is_enabled(conn),
            update_check_result=update_check.last_result(conn),
        )

    @app.get("/settings/sso")
    def settings_sso_page(
        request: Request, user: auth.User = Depends(current_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(request, "settings_sso.html", **account_context(conn, user))

    @app.get("/settings/tokens")
    def settings_tokens_page(
        request: Request, user: auth.User = Depends(current_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(request, "settings_tokens.html", **account_context(conn, user))

    @app.get("/settings/notifications")
    def settings_notifications_page(
        request: Request, user: auth.User = Depends(current_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(request, "settings_notifications.html", **account_context(conn, user))

    def _moved_to(new_path: str):
        """One redirect handler for an address that moved when the admin area was introduced."""

        def redirect() -> RedirectResponse:
            # 308, not 303: the page did not move for this one request, it moved for good, and a
            # permanent redirect lets a browser stop asking. Never 301, which historically lets
            # clients turn a POST into a GET - only GET is redirected here anyway, and every form
            # in this app posts to the new address directly.
            return RedirectResponse(new_path, status_code=308)

        return redirect

    # Addresses that moved, so an open tab, a bookmark or a link in an older copy of
    # the docs still arrives. `/settings` deliberately gets no redirect: it is now the personal
    # settings page, so an old bookmark to the global defaults lands on the user's own settings
    # instead. That is a changed meaning, not a move, and it is written down rather than papered
    # over with a redirect that would send an admin somewhere they did not ask for.
    for _old, _new in (
        ("/storage", "/admin/storage"),
        ("/logs", "/admin/logs"),
        ("/users", "/admin/users"),
        ("/about", "/admin/about"),
        ("/account", "/settings"),
    ):
        app.add_api_route(_old, _moved_to(_new), methods=["GET"], include_in_schema=False)

    @app.get("/settings")
    def account_page(
        request: Request, user: auth.User = Depends(current_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(request, "account.html", **account_context(conn, user))

    @app.post("/settings/password")
    def account_password_change(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """The sign-in password only (never the Apple ID and never a device's own backup
        encryption password - see the note account.html shows next to this form). Reuses
        auth.authenticate/change_password, the same hashing and the same session_version bump
        every other password change in this app already relies on (auth.py's own docstring); this
        route never reimplements either.
        """
        if not auth.has_password(conn, user.id):
            raise HTTPException(status_code=404)

        def respond(status_code: int, *, error: str | None = None) -> HTMLResponse:
            return render(
                request, "account.html", status_code=status_code, password_error=error, **account_context(conn, user)
            )

        current = form.get("current_password", "")
        new = form.get("new_password", "")
        new2 = form.get("new_password2", "")
        if auth.authenticate(conn, user.username, current) is None:
            del current, new, new2
            return respond(400, error="Current password is wrong.")
        del current
        if new != new2:
            del new, new2
            return respond(400, error="The new passwords do not match.")
        del new2
        try:
            auth.change_password(conn, user.id, new)
        except ValueError as exc:
            del new
            return respond(400, error=str(exc))
        del new
        # session_version just changed: every other session of this account is now signed out,
        # but this request's own session must stay signed in, so it is re-started against the
        # freshly bumped version instead of being caught by the same invalidation.
        auth.start_session(request.session, auth.get_user(conn, user.id))
        return render(request, "account.html", password_changed=True, **account_context(conn, user))

    @app.post("/settings/tokens")
    def account_tokens_create(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        try:
            issued = tokens.create(conn, user.id, form.get("name", ""), form.get("scope", tokens.SCOPE_READ))
        except ValueError as exc:
            return render(
                request,
                "settings_tokens.html",
                status_code=400,
                token_error=str(exc),
                **account_context(conn, user),
            )
        # The full token lives only in this one response: account_context() re-reads the table,
        # which holds only the hash, so a second page load (or the "created" row itself) never
        # carries it again.
        return render(request, "settings_tokens.html", new_token=issued, **account_context(conn, user))

    @app.post("/settings/tokens/{token_id}/revoke")
    def account_tokens_revoke(
        token_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # 404, not 403, for a foreign token id: same shape as visible_device and oidc.unlink, so
        # a member cannot learn whether a given token id exists at all.
        if not tokens.revoke(conn, user.id, token_id):
            raise HTTPException(status_code=404)
        return RedirectResponse("/settings/tokens", status_code=303)

    @app.post("/settings/notifications/push/subscribe")
    def account_push_subscribe(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Stores a browser's PushSubscription (push-subscribe.js posts endpoint/p256dh/auth as a plain
        form after `PushManager.subscribe()` succeeds). 400, not a crash, for a malformed or
        incomplete post -- the subscribe button is client-side JavaScript, not something the
        server ever fully trusts.
        """
        endpoint, p256dh, auth_key = form.get("endpoint", ""), form.get("p256dh", ""), form.get("auth", "")
        if not endpoint or not p256dh or not auth_key:
            raise HTTPException(status_code=400, detail="Incomplete push subscription")
        try:
            webpush.save_subscription(
                conn,
                user.id,
                webpush.Subscription(endpoint=endpoint, p256dh=p256dh, auth=auth_key),
                form.get("label", ""),
            )
        except webpush.ForeignSubscriptionError:
            # 409, not a hint about who the endpoint actually belongs to (same reasoning as the
            # 404-not-403 shape elsewhere): a signed-in user must not be able to take over
            # another user's push subscription just by knowing its endpoint URL.
            raise HTTPException(status_code=409, detail="This push subscription cannot be used here") from None
        return render(request, "settings_notifications.html", push_subscribed=True, **account_context(conn, user))

    @app.post("/settings/notifications/push/{subscription_id}/revoke")
    def account_push_revoke(
        subscription_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # 404, not 403, for a foreign subscription id: same shape as tokens.revoke/oidc.unlink.
        if not webpush.revoke(conn, user.id, subscription_id):
            raise HTTPException(status_code=404)
        return RedirectResponse("/settings/notifications", status_code=303)

    @app.post("/settings/sso/link")
    async def account_oidc_link(
        request: Request, form: dict = Depends(csrf_form), user: auth.User = Depends(current_user)
    ):
        if app.state.oidc_client is None:
            raise HTTPException(status_code=404)
        # Read back and checked in the callback, so the link can only land on this same user.
        request.session["oidc_link_uid"] = user.id
        return await app.state.oidc_client.authorize_redirect(request, oidc.redirect_uri(settings))

    @app.post("/settings/sso/{link_id}/unlink")
    def account_oidc_unlink(
        link_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if not oidc.unlink(conn, user.id, link_id):
            raise HTTPException(status_code=404)
        return RedirectResponse("/settings/sso", status_code=303)

    @app.get("/activity")
    def activity_indicator(request: Request, user: auth.User = Depends(current_user)):
        """Polled by the header's gear icon (base.html, every few seconds): the fragment carries
        its own state (header_activity_context), so this route needs nothing beyond the signed-in
        user render() already requires."""
        return render(request, "_activity_indicator.html", user=user)

    @app.get("/log")
    def user_log_page(
        request: Request,
        kind: str = "",
        device: str = "",
        page: int = 1,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """The signed-in user's own device events.

        This page has no admin branch at all: it always scopes to `user.id`, an admin included.
        That is deliberate rather than an oversight - an admin's system-wide view lives under
        `/admin/logs`, so there is no role test here to get wrong, and nothing on this route can
        widen the scope. `device` narrows within that scope and cannot leave it: the owner clause
        and the filter sit in the same query (events._query), so a hand-edited query string
        naming another owner's device returns nothing rather than that device's events.
        """
        event_page = events.list_events(conn, owner_id=user.id, kind=kind or None, udid=device or None, page=page)
        return render(
            request,
            "log.html",
            user=user,
            devices=visible_devices(conn, user),
            event_page=event_page,
            entries=events.shape(event_page.rows),
            scope_devices=events.devices_in_scope(conn, user.id),
            kinds=events.KINDS,
            kind_labels=events.KIND_LABELS,
            filter_kind=kind if kind in events.KINDS else "",
            filter_device=device,
        )

    def dashboard_groups(conn: sqlite3.Connection, user: auth.User, summaries: list[dict]) -> list[dict]:
        """The overview, grouped by owner: your own devices first, then everyone else's by name.

        Grouped here rather than filtered in the template, and built from the summaries the caller
        already scoped through `visible_devices` - so a member's list cannot grow a foreign device
        by going through this function, whatever it does. A member sees exactly one group; the
        label is still set for them, so device headings sit at the same level (h3 under a group
        h2) in both views instead of skipping a level on one of them.
        """
        own = [s for s in summaries if s["device"]["owner_id"] == user.id]
        if not user.is_admin:
            return [{"label": "Your devices", "summaries": own}] if own else []

        names = {row["id"]: row["username"] for row in auth.list_users(conn)}
        by_owner: dict[str, list] = {}
        unowned: list = []
        for summary in summaries:
            owner_id = summary["device"]["owner_id"]
            if owner_id == user.id:
                continue
            if owner_id is None:
                unowned.append(summary)
            else:
                by_owner.setdefault(names.get(owner_id) or f"user {owner_id}", []).append(summary)

        groups = [{"label": "Your devices", "summaries": own}] if own else []
        groups += [{"label": name, "summaries": by_owner[name]} for name in sorted(by_owner)]
        # Last, not sorted in among the usernames: "no owner" is a state to fix, not a person.
        if unowned:
            groups.append({"label": "No owner yet", "summaries": unowned})
        return groups

    @app.get("/")
    def dashboard(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
        user = session_or_demo_user(request, conn)
        if user is None:
            # The entry page answers 200 when signed out instead of redirecting: a deploy health
            # check and uptime monitors request "/" without following redirects.
            request.session.setdefault("csrf", secrets.token_urlsafe(24))
            return render(request, "login.html" if auth.has_users(conn) else "setup.html")
        devices = visible_devices(conn, user)
        summaries = [device_summary(conn, d) for d in devices]
        return render(
            request,
            "dashboard.html",
            user=user,
            devices=devices,
            summaries=summaries,
            groups=dashboard_groups(conn, user, summaries),
            storage=storage_check() if user.is_admin else None,
        )

    def device_page_context(conn: sqlite3.Connection, user: auth.User, device: sqlite3.Row) -> dict:
        udid = device["udid"]
        try:
            record = pairing.load(pair_records, udid)
        except pairing.PairRecordError:
            record = None
        return {
            "user": user,
            "devices": visible_devices(conn, user),
            "current_udid": udid,
            "s": device_summary(conn, device),
            "generations": generations_context(conn, device),
            "pair_warnings": pairing.warnings(record) if record else [],
            "password_check": password_check_status(device),
            "pwcheck_message": None,
            "pwcheck_error": None,
            "pwcheck_outcome": None,
            "reachability": reachability.for_device(conn, udid, datetime.now(UTC)),
        }

    @app.get("/devices/{udid}")
    def device_page(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        return render(request, "device.html", **device_page_context(conn, user, device))

    def netcheck_context(conn: sqlite3.Connection, device: sqlite3.Row, *, return_to: str = "setup") -> dict:
        row = conn.execute("SELECT * FROM netcheck_runs WHERE udid = ?", (device["udid"],)).fetchone()
        run = {"state": row["state"], "steps": json.loads(row["steps_json"])} if row is not None else None
        return {"netcheck_run": run, "netcheck_return_to": return_to}

    def maybe_enqueue_setup_detect(device: sqlite3.Row) -> None:
        """Enqueues one run_setup_detect (tasks.detect_setup_step) for `device` when it still has
        an open setup step and detection is neither already running nor on cooldown
        (runtime.setup_detect_due) - called whenever a device is (re-)added and whenever its
        setup page is opened (docs/setup.md, "Adding a device again"): a pair record can survive
        a recreated database while the device itself already has Wi-Fi and encryption on, and
        this is what notices without the owner walking the wizard again."""
        udid = device["udid"]
        backup_path = settings.backup_root / udid
        backup = inventory.read_backup(backup_path, with_size=False) if backup_path.is_dir() else None
        if not setup_incomplete(device, backup):
            return
        if not setup_detect_due(rt, udid):
            return
        mark_setup_detect_running(rt, udid)
        detect_setup_step(udid)

    def setup_context(conn: sqlite3.Connection, user: auth.User, device: sqlite3.Row, **extra) -> dict:
        udid = device["udid"]
        try:
            record = pairing.load(pair_records, udid)
        except pairing.PairRecordError:
            record = None
        actions = {r["step"]: r for r in conn.execute("SELECT * FROM setup_actions WHERE udid = ?", (udid,))}
        s = device_summary(conn, device)
        existing_snapshots = snapshots.list_snapshots(settings.backup_root, udid)
        context = {
            "user": user,
            "devices": visible_devices(conn, user),
            "current_udid": udid,
            "device": device,
            "kind": device_kind(device["product_type"]),
            "s": s,
            "pair_warnings": pairing.warnings(record) if record else [],
            # Without these, a pair record - or a whole backup history - that survived a recreated
            # database was invisible in the UI (docs/setup.md, "Adding a device again").
            "already_paired": record is not None,
            "existing_snapshot_count": len(existing_snapshots),
            "existing_last_backup": s["backup"].last_backup if s["backup"] else None,
            "wifi_action": actions.get("wifi"),
            "encryption_action": actions.get("encryption"),
            "setup_detect": setup_detect_state(rt, udid),
            "min_password_chars": MIN_ENCRYPTION_PASSWORD_CHARS,
            "encryption_error": None,
            "host_error": None,
            "host_saved": False,
            **netcheck_context(conn, device, return_to="setup"),
        }
        context.update(extra)
        return context

    @app.get("/devices/{udid}/setup")
    def device_setup_page(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        maybe_enqueue_setup_detect(device)
        return render(request, "device_setup.html", **setup_context(conn, user, device))

    @app.get("/devices/{udid}/setup/status")
    def device_setup_status(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        maybe_enqueue_setup_detect(device)
        return render(request, "_device_setup.html", **setup_context(conn, user, device))

    @app.post("/devices/{udid}/setup/host")
    def device_setup_host(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Saves devices.host from the wizard's own "device in a different network?" section
        (docs/setup.md): the same fixed-address column the device settings page edits
        (validate_device_settings), offered here too and right away, since a device the server
        cannot find over Bonjour never even gets this far otherwise."""
        device = visible_device(conn, user, udid)
        host_raw = form.get("host", "").strip()
        if host_raw and not valid_fixed_address(host_raw):
            context = setup_context(
                conn,
                user,
                device,
                host_error="Enter an IP address or hostname, not a URL, port or anything with spaces.",
            )
            if request.headers.get("hx-request"):
                return render(request, "_device_setup.html", status_code=400, **context)
            return render(request, "device_setup.html", status_code=400, **context)
        conn.execute("UPDATE devices SET host = ? WHERE udid = ?", (host_raw or None, udid))
        device = visible_device(conn, user, udid)  # re-read so the checklist reflects the write
        context = setup_context(conn, user, device, host_saved=True)
        if request.headers.get("hx-request"):
            return render(request, "_device_setup.html", **context)
        return RedirectResponse(f"/devices/{udid}/setup", status_code=303)

    @app.post("/devices/{udid}/netcheck")
    def device_netcheck_start(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Starts a connectivity check in the worker (tasks.netcheck_step), shared by the setup
        wizard and the device settings page (runtime.run_netcheck). `owner` is
        enough here, same as every other setup and settings action - this only ever reads from
        the device, so an admin-only guard would not add anything."""
        device = visible_device(conn, user, udid)
        return_to = form.get("return_to", "setup")
        if return_to not in ("setup", "settings"):
            return_to = "setup"
        mark_netcheck_running(rt, udid)
        netcheck_step(udid)
        context = {"device": device, **netcheck_context(conn, device, return_to=return_to)}
        if request.headers.get("hx-request"):
            return render(request, "_netcheck.html", **context)
        return RedirectResponse(f"/devices/{udid}/{return_to}", status_code=303)

    @app.get("/devices/{udid}/netcheck/status")
    def device_netcheck_status(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        return_to = request.query_params.get("return_to", "setup")
        if return_to not in ("setup", "settings"):
            return_to = "setup"
        context = {"device": device, **netcheck_context(conn, device, return_to=return_to)}
        return render(request, "_netcheck.html", **context)

    @app.post("/devices/{udid}/setup/wifi")
    def device_setup_wifi(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        mark_setup_action_running(rt, udid, "wifi")
        enable_wifi_step(udid)
        if request.headers.get("hx-request"):
            return render(request, "_device_setup.html", **setup_context(conn, user, device))
        return RedirectResponse(f"/devices/{udid}/setup", status_code=303)

    @app.post("/devices/{udid}/setup/encryption")
    def device_setup_encryption(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)

        def respond(status_code: int, *, error: str | None = None) -> HTMLResponse:
            context = setup_context(conn, user, device, encryption_error=error)
            if request.headers.get("hx-request"):
                return render(request, "_device_setup.html", status_code=status_code, **context)
            return render(request, "device_setup.html", status_code=status_code, **context)

        password = form.get("password", "")
        password2 = form.get("password2", "")
        if len(password) > MAX_ENCRYPTION_PASSWORD_CHARS or len(password2) > MAX_ENCRYPTION_PASSWORD_CHARS:
            del password, password2
            return respond(400, error="Password is too long.")
        if len(password) < MIN_ENCRYPTION_PASSWORD_CHARS:
            del password, password2
            return respond(400, error=f"Password must be at least {MIN_ENCRYPTION_PASSWORD_CHARS} characters.")
        if password != password2:
            del password, password2
            return respond(400, error="The passwords do not match.")
        del password2
        mark_setup_action_running(rt, udid, "encryption")
        # SECURITY RULE: the setup wizard's encryption step never runs through Huey. This
        # password must never be stored, logged, rendered back, or put in
        # the Huey queue, so this always runs as a plain thread in the web process, never
        # enqueued. The thread's own args tuple is the only place left holding it once this
        # function returns.
        threading.Thread(
            target=run_encryption_enable, args=(rt, udid, password), name=f"encrypt-{udid}", daemon=True
        ).start()
        del password
        return respond(200)

    @app.post("/devices/{udid}/password-check")
    def password_check_submit(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)

        def respond(status_code: int, *, message: str | None = None, error: str | None = None, outcome=None):
            context = device_page_context(conn, user, device)
            context["pwcheck_message"] = message
            context["pwcheck_error"] = error
            context["pwcheck_outcome"] = outcome
            if request.headers.get("hx-request"):
                return render(request, "_password_check.html", status_code=status_code, **context)
            return render(request, "device.html", status_code=status_code, **context)

        now = time.monotonic()
        ip_key = request.client.host if request.client else "unknown"
        wait = max(
            password_check_throttle_by_device.wait_seconds(udid, now),
            password_check_throttle_by_ip.wait_seconds(ip_key, now),
        )
        if wait > 0:
            # Throttled attempts never touch the keybag, so guessing does not even cost a key
            # derivation once the free attempts are used up.
            return respond(429, error=f"Too many attempts, try again in {int(wait) + 1} seconds.")

        password = form.get("password", "")
        if len(password) > MAX_PASSWORD_CHECK_CHARS:
            del password
            return respond(400, error="Password is too long.")

        with activity.track(connect, "password_check", udid=udid):
            result = password_check.check(settings.backup_root / device["udid"], password)
        del password

        if result.outcome == "wrong":
            password_check_throttle_by_device.failed(udid, now)
            password_check_throttle_by_ip.failed(ip_key, now)
        elif result.outcome == "correct":
            password_check_throttle_by_device.succeeded(udid)
            password_check_throttle_by_ip.succeeded(ip_key)

        if result.outcome in ("correct", "wrong"):
            conn.execute(
                "UPDATE devices SET password_checked_at = ?, password_check_result = ? WHERE udid = ?",
                (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), result.outcome, device["udid"]),
            )
            device = visible_device(conn, user, udid)  # re-read so the section reflects the write

        return respond(200, message=result.message, outcome=result.outcome)

    @app.post("/devices/{udid}/snapshots/{name}/pin")
    def snapshot_pin(
        udid: str,
        name: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        # Match against the real snapshot list before touching the filesystem at all: a name
        # is never turned into a path unless it is already exactly one of ours, so a traversal
        # attempt (e.g. "..%2F..") or a marker filename (e.g. "<name>.pinned") 404s here rather
        # than reaching snapshots.pin(), which would also refuse it, but only after building the
        # path.
        known = {s.path.name for s in snapshots.list_snapshots(settings.backup_root, device["udid"])}
        if name not in known:
            raise HTTPException(status_code=404)
        snapshots.pin(settings.backup_root, device["udid"], name, form.get("pinned") == "1")
        if request.headers.get("hx-request"):
            return render(request, "_generations.html", user=user, generations=generations_context(conn, device))
        return RedirectResponse(f"/devices/{udid}", status_code=303)

    @app.get("/devices/{udid}/snapshots/{name}/download")
    def device_snapshot_download(
        udid: str,
        name: str,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """One whole generation as a tar, byte for byte as it lies on disk.

        This is what a restore actually needs, and it is not what the file browser hands out: that
        one decrypts and renames, which is right for reading a file and useless for restoring a
        device. Here nothing is decrypted, nothing renamed, nothing filtered - unpack it into
        `MobileSync/Backup/<UDID>` and Finder takes it from there, asking for the backup password
        itself. The password is therefore never needed on this path and never leaves the server.

        Generations only, never the live backup: a generation is finished and immutable, while the
        live directory is rewritten in place by the next run - and a download of a full backup can
        easily outlast the gap between two runs.

        Signed-in session only: `current_user` is the session
        guard, and the JSON API's tokens do not reach this route. `visible_device` keeps it to the
        caller's own devices, and the generation name is matched against the real snapshot list
        before it is ever turned into a path.
        """
        device = visible_device(conn, user, udid)
        known = {s.path.name: s for s in snapshots.list_snapshots(settings.backup_root, udid)}
        if name not in known:
            raise HTTPException(status_code=404)
        # The one action that takes a complete device backup off this machine, so it is said out
        # loud in the log: who, when, which generation. A shortened UDID, as everywhere else.
        log.info("Full backup export: user %s, device %s, generation %s", user.username, udid[:8], name)
        return StreamingResponse(
            export.tar_stream(known[name].path),
            media_type="application/octet-stream",
            headers=_download_headers(export.archive_name(device["name"], udid, name)),
        )

    @app.post("/devices/{udid}/snapshots/{name}/verify")
    def snapshot_verify(
        udid: str,
        name: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Deep-verify one generation on demand. Only ever
        enqueues: the actual check runs in the worker (tasks.py's verify_snapshot task), streamed
        row by row against Manifest.db, which can take a while for a large backup. The page keeps
        showing the last stored result (or "never") until that task finishes and the operator
        reloads or the row is re-rendered - the same on-demand, non-blocking shape as "Scan now"
        and the storage browse "Recalculate" button.
        """
        device = visible_device(conn, user, udid)
        # Same guard as snapshot_pin: match against the real snapshot list before a name is ever
        # turned into a path, so a traversal attempt 404s here rather than reaching the task.
        known = {s.path.name for s in snapshots.list_snapshots(settings.backup_root, device["udid"])}
        if name not in known:
            raise HTTPException(status_code=404)
        verify_snapshot_task(device["udid"], name)
        if request.headers.get("hx-request"):
            return render(request, "_generations.html", user=user, generations=generations_context(conn, device))
        return RedirectResponse(f"/devices/{udid}", status_code=303)

    # Backup passwords for browsing an encrypted backup. Held in the web process only, keyed by an
    # opaque handle that lives in the session cookie - the password itself never goes into the
    # cookie, the database or a log. Entries expire on their own and are dropped on sign-out:
    # in memory, per session, deliberately.
    #
    # Keyed per *generation*, not per device, and that is not pedantry: a snapshot is a full copy of
    # the live backup, so every generation carries its own Manifest.plist with its own keybag. After
    # a backup password change the device writes a new backup with a new keybag while older
    # generations keep theirs, so two generations of one device genuinely can need two passwords.
    # In the normal case they share one, which is why opening a generation first tries every
    # password the current session already holds for that device before asking.
    backup_passwords: dict[str, tuple[str, float]] = {}
    backup_passwords_guard = threading.Lock()
    BACKUP_PASSWORD_TTL = 15 * 60
    BACKUP_PASSWORD_SWEEP_SECONDS = 60
    backup_password_sweeper_stop = threading.Event()

    # What the reader has ticked, per session and per generation. Entries are (domain, path) pairs
    # rather than file ids, and that is the whole reason a folder of five thousand photos costs one
    # entry instead of five thousand: the paths are expanded into files only when the archive is
    # built (extract.selection_file_ids). An empty path means the whole domain.
    file_selections: dict[str, tuple[set[tuple[str, str]], float]] = {}
    file_selections_guard = threading.Lock()
    # A ceiling so a script cannot grow the map without bound. Reached only by ticking a thousand
    # separate rows by hand; ticking their folder instead costs one.
    MAX_SELECTION_ENTRIES = 1000

    def browse_handle(request: Request) -> str:
        """An opaque per-session handle. Not the user id: signing out and back in must not inherit
        a password the previous session unlocked."""
        handle = request.session.get("browse")
        if not handle:
            handle = secrets.token_urlsafe(16)
            request.session["browse"] = handle
        return handle

    def _key(handle: str, udid: str, generation: str) -> str:
        return f"{handle}:{udid}:{generation}"

    def _sweep(now: float) -> None:
        for key, (_pw, expires) in list(backup_passwords.items()):
            if expires <= now:
                del backup_passwords[key]

    def sweep_backup_passwords() -> int:
        """Drop every expired password, and say how many went. Selections go with them: they hold
        no secret, but an abandoned session should not keep anything at all."""
        now = time.monotonic()
        with backup_passwords_guard:
            before = len(backup_passwords)
            _sweep(now)
            dropped = before - len(backup_passwords)
        with file_selections_guard:
            sweep_file_selections(now)
        return dropped

    def _selection_key(request: Request, udid: str, generation: str) -> str:
        return f"{browse_handle(request)}:{udid}:{generation}"

    def selection_of(request: Request, udid: str, generation: str) -> set[tuple[str, str]]:
        handle = request.session.get("browse")
        if not handle:
            return set()
        with file_selections_guard:
            found = file_selections.get(f"{handle}:{udid}:{generation}")
            if found is None:
                return set()
            chosen, _expires = found
            file_selections[f"{handle}:{udid}:{generation}"] = (chosen, time.monotonic() + BACKUP_PASSWORD_TTL)
            return set(chosen)

    def change_selection(request: Request, udid: str, generation: str, change) -> None:
        """Apply `change` to the current session's selection for one generation, under the lock."""
        key = _selection_key(request, udid, generation)
        with file_selections_guard:
            chosen, _expires = file_selections.get(key, (set(), 0.0))
            chosen = set(chosen)
            change(chosen)
            if len(chosen) > MAX_SELECTION_ENTRIES:
                return
            if chosen:
                file_selections[key] = (chosen, time.monotonic() + BACKUP_PASSWORD_TTL)
            else:
                file_selections.pop(key, None)

    def forget_selections(request: Request, udid: str | None = None) -> None:
        handle = request.session.get("browse")
        if not handle:
            return
        prefix = f"{handle}:" if udid is None else f"{handle}:{udid}:"
        with file_selections_guard:
            for key in [k for k in file_selections if k.startswith(prefix)]:
                del file_selections[key]

    def covered_by(chosen: set[tuple[str, str]], domain: str, path: str) -> str | None:
        """The selected ancestor that already includes this row, if there is one.

        Selecting a folder means everything below it, so a file inside a selected folder is
        already in the archive. Its own checkbox is then shown ticked and disabled rather than
        pretending it could be removed on its own - taking one photo out of five thousand would
        mean storing the other 4,999 by hand.
        """
        if (domain, "") in chosen and path:
            return f"{domain} (whole area)"
        parts = path.strip("/").split("/")
        for depth in range(len(parts) - 1, 0, -1):
            parent = "/".join(parts[:depth])
            if (domain, parent) in chosen:
                return parent
        return None

    def sweep_file_selections(now: float) -> None:
        for key, (_chosen, expires) in list(file_selections.items()):
            if expires <= now:
                del file_selections[key]

    def sweep_backup_passwords_forever() -> None:
        """The sweeper the lifespan runs, so an idle process does not keep plaintext past its
        time. Defined here rather than next to the lifespan because it belongs to the store; the
        lifespan only ever calls it after create_app has finished building the closure."""
        while not backup_password_sweeper_stop.wait(BACKUP_PASSWORD_SWEEP_SECONDS):
            sweep_backup_passwords()

    # Exposed so a test can drive the sweep itself instead of waiting a minute for the thread,
    # and can see what the store holds. Nothing outside this module writes either of them.
    app.state.sweep_backup_passwords = sweep_backup_passwords
    app.state.backup_passwords = backup_passwords

    def remember_backup_password(request: Request, udid: str, generation: str, password: str) -> None:
        with backup_passwords_guard:
            backup_passwords[_key(browse_handle(request), udid, generation)] = (
                password,
                time.monotonic() + BACKUP_PASSWORD_TTL,
            )

    def recall_backup_password(request: Request, udid: str, generation: str) -> tuple[str | None, int]:
        """The password held for this generation, and the seconds left before it expires.

        Reading it pushes the deadline out again: the limit is fifteen minutes of *inactivity*, so
        a long browse does not lock up underneath the reader mid-click.
        """
        handle = request.session.get("browse")
        if not handle:
            return None, 0
        now = time.monotonic()
        with backup_passwords_guard:
            _sweep(now)
            found = backup_passwords.get(_key(handle, udid, generation))
            if found is None:
                return None, 0
            password, _expires = found
            deadline = now + BACKUP_PASSWORD_TTL
            backup_passwords[_key(handle, udid, generation)] = (password, deadline)
        return password, BACKUP_PASSWORD_TTL

    def candidate_passwords(request: Request, udid: str) -> list[str]:
        """Every password the current session holds for any generation of this device.

        Tried before asking: generations usually share one password, and making the reader retype
        it for each one would be a worse answer to a case that is itself the exception.
        """
        handle = request.session.get("browse")
        if not handle:
            return []
        prefix = f"{handle}:{udid}:"
        now = time.monotonic()
        with backup_passwords_guard:
            _sweep(now)
            seen: list[str] = []
            for key, (password, _expires) in backup_passwords.items():
                if key.startswith(prefix) and password not in seen:
                    seen.append(password)
        return seen

    def forget_backup_passwords(request: Request, udid: str | None = None) -> None:
        handle = request.session.get("browse")
        if not handle:
            return
        prefix = f"{handle}:" if udid is None else f"{handle}:{udid}:"
        with backup_passwords_guard:
            for key in [k for k in backup_passwords if k.startswith(prefix)]:
                del backup_passwords[key]

    LIVE = "latest"

    def live_backup_is_being_written(conn: sqlite3.Connection, udid: str) -> bool:
        """Whether a backup is writing the live directory for this device right now.

        The engine rewrites the live backup in place, so its `Manifest.db` and its
        payload files are both moving targets while a run is on. Reading the index then fails in a
        confusing way at best; reading a payload hands out half of the old file and half of the new
        one with nothing to show for it, which is the worse half of the problem because a restored
        file looks fine until someone opens it. A generation is not affected - `rsync --link-dest`
        writes a fresh directory and never touches one that already exists.

        `runs_one_running` keeps this to at most one row per device, so the question has an answer.
        """
        row = conn.execute("SELECT 1 FROM runs WHERE udid = ? AND status = 'running' LIMIT 1", (udid,)).fetchone()
        return row is not None

    def files_source(device: sqlite3.Row, snapshot: str | None) -> tuple[Path, object | None, list]:
        """The directory to browse: the live backup, or one named generation.

        Same guard as the restore page and the snapshot actions: a requested name is matched
        against the real snapshot list before it is ever turned into a path, so anything that is
        not an actual generation 404s rather than being trusted.
        """
        snaps = snapshots.list_snapshots(settings.backup_root, device["udid"])
        if snapshot is None or snapshot == LIVE:
            return settings.backup_root / device["udid"], None, snaps
        known = {s.path.name: s for s in snaps}
        if snapshot not in known:
            raise HTTPException(status_code=404)
        return known[snapshot].path, known[snapshot], snaps

    def generation_timeline(device: sqlite3.Row, snaps: list, chosen: str | None) -> list[dict]:
        """The live backup and every generation, newest first, for the chooser and the strip that
        stays above a browse view so one can be swapped for another without going back."""
        live_dir = settings.backup_root / device["udid"]
        timeline = [
            {
                "key": LIVE,
                "label": "Latest backup",
                "taken_at": None,
                "exists": live_dir.is_dir(),
                "encrypted": live_dir.is_dir() and extract.is_encrypted(live_dir),
                "current": chosen == LIVE,
            }
        ]
        for snap in snaps:
            timeline.append(
                {
                    "key": snap.path.name,
                    "label": snap.taken_at.strftime("%d %b %Y, %H:%M UTC"),
                    "taken_at": snap.taken_at,
                    "exists": True,
                    "encrypted": extract.is_encrypted(snap.path),
                    "current": chosen == snap.path.name,
                }
            )
        return timeline

    def browse_columns(source_dir: Path, password: str | None, domain: str, path: str, page: int) -> list[dict]:
        """The Finder-style columns for one position in the tree.

        Column one is the areas, then one column per level of `path`, the last of which is the
        open one. Each column knows which of its rows leads to the next, so the whole trail stays
        visible instead of being replaced by a breadcrumb.

        Only the open column pages; the ones behind it are already narrowed by the row that was
        chosen in them. Paging grows the page rather than replacing it, which is what a reader
        scrolling a folder of five thousand photos expects - and selecting all of them never needs
        them on screen at all, because a folder is selected by its path.
        """
        columns = [
            {
                "kind": "domains",
                "title": "Areas",
                "domain": "",
                "path": "",
                # Every row carries the `(domain, path)` pair it stands for, whatever kind of column
                # it sits in. That pair is what a selection stores, so deriving it in one place
                # keeps the template, the marking loop and the search column from each working it
                # out their own way.
                "rows": [
                    {
                        "name": name,
                        "is_folder": True,
                        "count": count,
                        "file_id": None,
                        "size": None,
                        "domain": name,
                        "path": "",
                    }
                    for name, count in extract.domains(source_dir, password)
                ],
                "total": 0,
                "shown": 0,
                "current": domain,
            }
        ]
        if not domain:
            return columns

        levels = [p for p in path.strip("/").split("/") if p]
        for depth in range(len(levels) + 1):
            prefix = "/".join(levels[:depth])
            open_column = depth == len(levels)
            size = extract.CHILD_PAGE_SIZE * (page if open_column else 1)
            column = extract.children(source_dir, domain, prefix, page=1, page_size=size, password=password)
            columns.append(
                {
                    "kind": "files",
                    "title": prefix.rsplit("/", 1)[-1] if prefix else domain,
                    "domain": domain,
                    "path": prefix,
                    "rows": [
                        {
                            "name": c.name,
                            "is_folder": c.is_folder,
                            "count": c.count,
                            "file_id": c.file_id,
                            "size": c.size,
                            "domain": domain,
                            "path": f"{prefix}/{c.name}" if prefix else c.name,
                        }
                        for c in column.rows
                    ],
                    "total": column.total,
                    "shown": len(column.rows),
                    "current": levels[depth] if depth < len(levels) else "",
                }
            )
        return columns

    def search_column(source_dir: Path, password: str | None, domain: str, scope: str, query: str, hits: int) -> dict:
        """The matches for a search, shaped as one more column at the right-hand end of the strip.

        A search used to be a table under the browser, which meant two ways of picking a file on
        one page. It is a column now: same rows, same checkboxes, same select route, and the
        folder columns it was searched from stay exactly where they were.

        Paging follows the folder columns rather than the old Previous/Next: `hits` grows the page
        instead of replacing it, so "Show more" never takes away a match somebody has already
        looked at, and a tick further up the list is still on screen afterwards. It is its own
        parameter and not the `page` the folder columns use - the two columns page independently,
        and one of them growing must not quietly expand the other.

        There is deliberately no "Select all N" at its foot. A selection is stored as paths, which
        is what makes a folder of five thousand photos one entry; a result list is not a path and
        has no ancestor that covers exactly it, so the honest options were N entries pretending to
        be one, or none. The folder columns keep their bulk control, where a path does exist.
        """
        page = extract.list_entries(
            source_dir,
            domain=domain if scope == "domain" and domain else None,
            query=query,
            page=1,
            page_size=extract.PAGE_SIZE * max(1, hits),
            password=password,
        )
        return {
            "kind": "search",
            "title": "Matches",
            # The column itself stands for no path, so the marking loop leaves its foot alone.
            "domain": "",
            "path": "",
            "rows": [
                {
                    "name": entry.name,
                    "is_folder": False,
                    "count": 1,
                    "file_id": entry.file_id,
                    "size": entry.size,
                    "domain": entry.domain,
                    "path": entry.relative_path,
                }
                for entry in page.rows
            ],
            "total": page.total,
            "shown": len(page.rows),
            "current": "",
        }

    @app.get("/devices/{udid}/files")
    def device_files(
        udid: str,
        request: Request,
        snapshot: str | None = None,
        domain: str = "",
        path: str = "",
        q: str = "",
        scope: str = "all",
        page: int = 1,
        hits: int = 1,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Browse one generation's files and pick one or several to download.

        Three states, shown one at a time rather than all at once (a search box
        above a backup that is still locked is a control that cannot work):
        choose a generation -> unlock it if it is encrypted -> browse it.

        A member reaches this for their own devices only - `visible_device` is the same guard the
        rest of the device pages use, and there is no separate scope here to get wrong.
        """
        return files_page(request, conn, user, udid, snapshot, domain, path, q, scope, page, hits)

    def files_page(
        request: Request,
        conn: sqlite3.Connection,
        user: auth.User,
        udid: str,
        snapshot: str | None,
        domain: str = "",
        path: str = "",
        q: str = "",
        scope: str = "all",
        page: int = 1,
        hits: int = 1,
        unlock_error: str | None = None,
    ):
        """Render whichever of the three states applies.

        `unlock_error` is a parameter of this helper and deliberately not of the route: as a query
        parameter it would let anyone put an arbitrary message on the page through a crafted link.
        """
        device = visible_device(conn, user, udid)
        source_dir, selected, snaps = files_source(device, snapshot)
        timeline = generation_timeline(device, snaps, snapshot)
        writing = live_backup_is_being_written(conn, udid)
        # Only in a seeded demo environment, where the generations were written with it and it
        # protects nothing. A real installation never reaches this.
        demo_backup_password = (
            demo_seed.DEMO_BACKUP_PASSWORD if settings.demo_seed and settings.engine == "demo" else None
        )

        if snapshot is None or (snapshot == LIVE and writing):
            return render(
                request,
                "device_files.html",
                user=user,
                devices=visible_devices(conn, user),
                current_udid=udid,
                device=device,
                state="choose",
                timeline=timeline,
                writing=writing,
                demo_backup_password=demo_backup_password,
            )

        generation = snapshot
        password, seconds_left = recall_backup_password(request, udid, generation)
        encrypted = extract.is_encrypted(source_dir)
        if encrypted and password is None:
            # Try what the current session already holds for another generation of the same device
            # before asking again; generations normally share one password.
            for candidate in candidate_passwords(request, udid):
                try:
                    extract.domains(source_dir, candidate)
                except extract.ExtractError:
                    continue
                remember_backup_password(request, udid, generation, candidate)
                password, seconds_left = candidate, BACKUP_PASSWORD_TTL
                break

        columns: list[dict] = []
        hits_column = None
        problem = None
        try:
            columns = browse_columns(source_dir, password, domain, path, page)
            if q:
                # Search is its own column at the right-hand end, not a replacement for the tree:
                # the trail stays put so a reader can go back to where they were.
                hits_column = search_column(source_dir, password, domain, scope, q, hits)
        except extract.WrongPassword:
            forget_backup_passwords(request, udid)
            problem = "locked"
        except extract.PasswordRequired:
            problem = "locked"
        except extract.ExtractError as exc:
            problem = str(exc)

        chosen = selection_of(request, udid, generation)
        for column in [*columns, *([hits_column] if hits_column else [])]:
            # The column's own path, for the "select everything in here" action at its foot.
            column["selected"] = (column["domain"], column["path"]) in chosen
            column["covered"] = covered_by(chosen, column["domain"], column["path"])
            for row in column["rows"]:
                row["selected"] = (row["domain"], row["path"]) in chosen
                row["covered"] = covered_by(chosen, row["domain"], row["path"])

        return render(
            request,
            "device_files.html",
            user=user,
            devices=visible_devices(conn, user),
            current_udid=udid,
            device=device,
            state="locked" if problem == "locked" else ("problem" if problem else "browse"),
            timeline=timeline,
            generation=generation,
            selected=selected,
            columns=columns,
            open_domain=domain,
            open_path=path,
            hits_column=hits_column,
            chosen=sorted(chosen),
            problem=problem,
            unlocked=encrypted and problem is None,
            seconds_left=seconds_left,
            unlock_error=unlock_error,
            filter_domain=domain,
            filter_query=q,
            filter_scope=scope,
            page=page,
            hits=hits,
            writing=writing,
            demo_backup_password=demo_backup_password,
        )

    @app.post("/devices/{udid}/files/unlock")
    def device_files_unlock(
        udid: str,
        request: Request,
        snapshot: str | None = None,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Take the backup password for one generation and keep it for a while.

        Checked immediately by opening that generation's file index with it, so a wrong one is
        reported here instead of sitting in memory until the next click.
        """
        device = visible_device(conn, user, udid)
        generation = snapshot or LIVE
        source_dir, _selected, _snaps = files_source(device, generation)
        password = form.get("backup_password", "")
        try:
            extract.domains(source_dir, password)
        except extract.WrongPassword:
            # Keyword arguments from here on: positionally, that trailing 1 landed on `q` and made
            # the failed unlock page carry a search for "1".
            return files_page(
                request,
                conn,
                user,
                udid,
                generation,
                unlock_error="That password does not open this generation.",
            )
        except extract.ExtractError as exc:
            return files_page(request, conn, user, udid, generation, unlock_error=str(exc))
        remember_backup_password(request, udid, generation, password)
        return RedirectResponse(f"/devices/{udid}/files?snapshot={quote(generation)}", status_code=303)

    @app.post("/devices/{udid}/files/select")
    def device_files_select(
        udid: str,
        request: Request,
        snapshot: str | None = None,
        domain: str = "",
        path: str = "",
        q: str = "",
        scope: str = "all",
        page: int = 1,
        hits: int = 1,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Tick or untick one row, or clear the lot.

        The selection lives on the server rather than in the form, so it survives walking into
        another folder - which is the whole point of a column browser - and so that a whole area
        or a folder of thousands stays one value instead of thousands of hidden inputs.
        """
        visible_device(conn, user, udid)
        generation = snapshot or LIVE
        target = (form.get("target_domain", ""), form.get("target_path", "").strip("/"))

        if form.get("clear"):
            forget_selections(request, udid)
        elif target[0]:
            on = form.get("on") == "1"
            change_selection(request, udid, generation, lambda c: c.add(target) if on else c.discard(target))
        return files_page(request, conn, user, udid, snapshot, domain, path, q, scope, page, hits)

    @app.post("/devices/{udid}/files/lock")
    def device_files_lock(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Forget every backup password the current session holds for this device, now."""
        visible_device(conn, user, udid)
        forget_backup_passwords(request, udid)
        forget_selections(request, udid)
        return RedirectResponse(f"/devices/{udid}/files", status_code=303)

    def _download_headers(name: str) -> dict:
        # Always octet-stream, always an attachment, always nosniff - never the file's real type.
        # A backup holds arbitrary files the server never produced; serving one as text/html from
        # this origin would be stored cross-site scripting against the signed-in user.
        return {
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="{name}"',
        }

    @app.get("/devices/{udid}/files/download")
    def device_file_download(
        udid: str,
        request: Request,
        file_id: str,
        snapshot: str | None = None,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Stream one file out of a backup, decrypted on the way if it needs to be."""
        device = visible_device(conn, user, udid)
        generation = snapshot or LIVE
        if generation == LIVE and live_backup_is_being_written(conn, udid):
            # 409, not 404: the file is there, this is simply the wrong moment. Handing out bytes
            # from a directory the engine is rewriting would give a plausible-looking broken file.
            raise HTTPException(status_code=409, detail="A backup is running; this generation is being written.")
        source_dir, _selected, _snaps = files_source(device, generation)
        password, _left = recall_backup_password(request, udid, generation)
        try:
            if not extract.is_encrypted(source_dir):
                entry, path = extract.open_file(source_dir, file_id)
                return FileResponse(
                    path,
                    media_type="application/octet-stream",
                    filename=extract.download_name(entry),
                    headers={"X-Content-Type-Options": "nosniff"},
                )
            entry, chunks = extract.stream_file(source_dir, file_id, password)
        except extract.ExtractError:
            # One answer for "no such file", "wrong password", "not unlocked" and "that is a
            # folder": a download link is not a place to learn which of those it was.
            raise HTTPException(status_code=404) from None
        return StreamingResponse(
            chunks, media_type="application/octet-stream", headers=_download_headers(extract.download_name(entry))
        )

    @app.post("/devices/{udid}/files/download")
    async def device_files_download_many(
        udid: str,
        request: Request,
        snapshot: str | None = None,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Several selected files as one streamed tar archive.

        POST rather than GET because a selection of a hundred file ids does not belong in a URL,
        and because the CSRF token comes with the form either way.
        """
        device = visible_device(conn, user, udid)
        generation = snapshot or LIVE
        if generation == LIVE and live_backup_is_being_written(conn, udid):
            # 409, not 404: the file is there, this is simply the wrong moment. Handing out bytes
            # from a directory the engine is rewriting would give a plausible-looking broken file.
            raise HTTPException(status_code=409, detail="A backup is running; this generation is being written.")
        source_dir, _selected, _snaps = files_source(device, generation)
        password, _left = recall_backup_password(request, udid, generation)
        raw = await request.form()
        chosen = selection_of(request, udid, generation)
        # A row can still be posted directly (the Download link on a single file); a stored
        # selection is expanded from paths into files here, at the last possible moment.
        file_ids = [str(v) for v in raw.getlist("file_id")]
        if chosen:
            file_ids += extract.selection_file_ids(source_dir, sorted(chosen), password)
        file_ids = list(dict.fromkeys(file_ids))
        if not file_ids:
            return RedirectResponse(f"/devices/{udid}/files?snapshot={quote(generation)}", status_code=303)
        # "files", against the "backup" the whole-generation export produces: same device, same
        # generation, two archives that are not interchangeable - only one of them restores.
        name = export.archive_name(device["name"], udid, generation, kind="files")
        return StreamingResponse(
            extract.tar_stream(source_dir, file_ids, password),
            media_type="application/octet-stream",
            headers=_download_headers(name),
        )

    @app.get("/devices/{udid}/restore")
    def restore_page(
        udid: str,
        request: Request,
        snapshot: str | None = None,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        live_path = settings.backup_root / device["udid"]
        snaps = snapshots.list_snapshots(settings.backup_root, device["udid"])
        selected = None
        if snapshot is not None:
            # Same guard as snapshot_pin/snapshot_verify: match the raw query value against the
            # real snapshot list before it is ever turned into a path, so a traversal attempt
            # (or any name that is not an actual generation) 404s here instead of being trusted.
            known = {s.path.name: s for s in snaps}
            if snapshot not in known:
                raise HTTPException(status_code=404)
            selected = known[snapshot]
        return render(
            request,
            "restore.html",
            user=user,
            devices=visible_devices(conn, user),
            current_udid=udid,
            device=device,
            live_path=live_path,
            live_exists=live_path.is_dir(),
            snaps=snaps,
            selected=selected,
            pymobiledevice3_version=diagnostics._package_version("pymobiledevice3"),
        )

    @app.get("/devices/{udid}/status")
    def device_status(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        return render(request, "_status_live.html", user=user, s=device_summary(conn, device))

    @app.post("/devices/{udid}/backup")
    def backup_now(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        # The running `runs` row is inserted synchronously (mark_backup_starting) before the
        # actual backup task is even enqueued, so this response already reflects the running
        # state - without it, the page looked unchanged until the worker process got around to
        # dequeuing backup_device and JobManager.start inserted the row itself, moments (or, if
        # the queue was busy, much longer) later. None means a backup was already running.
        run_id = mark_backup_starting(rt, udid, "manual")
        backup_error = None
        if run_id is None:
            backup_error = "A backup is already running for this device."
        else:
            backup_device(device["udid"], "manual", run_id)
        if request.headers.get("hx-request"):
            s = device_summary(conn, device)
            return render(request, "_status_live.html", user=user, s=s, backup_error=backup_error)
        # The plain form submit still redirects, same as before: a full reload is normal browser
        # behaviour here, not the "unchanged page" bug this fix targets. The redirect target
        # already shows the correct state at once either way, because the running row (if any)
        # was inserted synchronously above, before this response - a fresh backup_error is only
        # ever "a backup is already running", which the device page's own running status already
        # makes visible without a separate flash message.
        return RedirectResponse(f"/devices/{udid}", status_code=303)

    @app.get("/devices/{udid}/settings")
    def device_settings_page(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        policy = device_policy(conn, device)
        return render(
            request,
            "device_settings.html",
            user=user,
            devices=visible_devices(conn, user),
            current_udid=udid,
            device=device,
            saved=request.query_params.get("saved") == "1",
            connectors=connectors_context(conn, "device", udid),
            global_defaults=backup_defaults.get_global_defaults(conn),
            retention_defaults=backup_defaults.get_global_defaults(conn).retention,
            retention_preview=retention_preview(udid, policy),
            # Admin-only: the owner reassignment select. Never computed for a member - visible_device
            # already 404s a foreign device for them, but this also keeps the local user list itself
            # out of a member's response entirely, not merely unrendered.
            local_users=auth.list_users(conn) if user.is_admin else [],
            **field_modes(device),
            **password_change_context(conn, device),
            **netcheck_context(conn, device, return_to="settings"),
        )

    def password_change_context(conn: sqlite3.Connection, device: sqlite3.Row, *, error: str | None = None) -> dict:
        action = conn.execute(
            "SELECT * FROM setup_actions WHERE udid = ? AND step = 'password_change'", (device["udid"],)
        ).fetchone()
        return {
            "password_change_action": action,
            "password_change_error": error,
            "min_password_chars": MIN_ENCRYPTION_PASSWORD_CHARS,
        }

    @app.post("/devices/{udid}/settings")
    def device_settings_submit(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        cleaned, errors = validate_device_settings(form)
        if errors:
            # Re-render with what the user typed, not the saved row, so a single typo does not
            # discard the rest of the form.
            merged = {
                "udid": device["udid"],
                "encryption_enabled_at": device["encryption_enabled_at"],
                "name": form.get("name", ""),
                "owner_label": form.get("owner_label", ""),
                "interval_hours": form.get("interval_hours", ""),
                "window_start": form.get("window_start", ""),
                "window_end": form.get("window_end", ""),
                "only_when_charging": 1 if form.get("only_when_charging") else 0,
                "overdue_days": form.get("overdue_days", ""),
                "host": form.get("host", ""),
                **{f: form.get(f, "") for f in snapshots.RETENTION_FIELDS},
            }
            retention_mode = form.get("retention_mode", "default")
            retention_values, retention_errors = validate_retention_form(form)
            global_defaults = backup_defaults.get_global_defaults(conn)
            # Only meaningful when the posted retention fields themselves validated - otherwise
            # there is no usable policy to preview yet, and the field-level errors already say why.
            preview = (
                retention_preview(udid, snapshots.resolve_policy(retention_values, global_defaults.retention))
                if not retention_errors
                else "Fix the retention fields above to see a preview."
            )
            return render(
                request,
                "device_settings.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                current_udid=udid,
                device=merged,
                errors=errors,
                connectors=connectors_context(conn, "device", udid),
                retention_mode=retention_mode,
                interval_mode=form.get("interval_mode", "default"),
                window_mode=form.get("window_mode", "default"),
                charging_mode=form.get("charging_mode", "default"),
                overdue_mode=form.get("overdue_mode", "default"),
                global_defaults=global_defaults,
                retention_defaults=global_defaults.retention,
                retention_preview=preview,
                **password_change_context(conn, device),
                **netcheck_context(conn, device, return_to="settings"),
            )
        name_custom = 1 if cleaned["name"] != (device["name"] or "") else device["name_custom"]
        conn.execute(
            "UPDATE devices SET name = ?, owner_label = ?, interval_hours = ?, "
            "keep_last = ?, keep_daily = ?, keep_weekly = ?, keep_monthly = ?, keep_yearly = ?, "
            "window_start = ?, window_end = ?, only_when_charging = ?, overdue_days = ?, host = ?, "
            "name_custom = ? "
            "WHERE udid = ?",
            (
                cleaned["name"],
                cleaned["owner_label"],
                cleaned["interval_hours"],
                cleaned["keep_last"],
                cleaned["keep_daily"],
                cleaned["keep_weekly"],
                cleaned["keep_monthly"],
                cleaned["keep_yearly"],
                cleaned["window_start"],
                cleaned["window_end"],
                cleaned["only_when_charging"],
                cleaned["overdue_days"],
                cleaned["host"],
                name_custom,
                device["udid"],
            ),
        )
        return RedirectResponse(f"/devices/{udid}/settings?saved=1", status_code=303)

    @app.post("/devices/{udid}/settings/owner")
    def device_settings_owner(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Reassigns a device to another local user. Admin-only by
        the admin_user dependency, same 404-for-members shape as every other admin route - a
        member must never even learn this route exists, let alone reach it."""
        device = visible_device(conn, user, udid)
        raw = form.get("owner_id", "").strip()
        owner_id: int | None = None
        if raw:
            try:
                owner_id = int(raw)
            except ValueError:
                raise HTTPException(status_code=400, detail="Unknown user") from None
            if auth.get_user(conn, owner_id) is None:
                raise HTTPException(status_code=400, detail="Unknown user")
        conn.execute("UPDATE devices SET owner_id = ? WHERE udid = ?", (owner_id, device["udid"]))
        return RedirectResponse(f"/devices/{udid}/settings?saved=1", status_code=303)

    @app.post("/devices/{udid}/settings/password")
    def device_settings_password(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)

        def respond(status_code: int, *, error: str | None = None) -> HTMLResponse:
            context = password_change_context(conn, device, error=error)
            if request.headers.get("hx-request"):
                return render(
                    request, "_password_change.html", status_code=status_code, user=user, device=device, **context
                )
            global_defaults = backup_defaults.get_global_defaults(conn)
            return render(
                request,
                "device_settings.html",
                status_code=status_code,
                user=user,
                devices=visible_devices(conn, user),
                current_udid=udid,
                device=device,
                saved=False,
                connectors=connectors_context(conn, "device", udid),
                global_defaults=global_defaults,
                retention_defaults=global_defaults.retention,
                retention_preview=retention_preview(udid, device_policy(conn, device)),
                **field_modes(device),
                **context,
            )

        if not device["encryption_enabled_at"]:
            return respond(400, error="Turn on backup encryption for this device first.")
        old = form.get("old_password", "")
        new = form.get("new_password", "")
        new2 = form.get("new_password2", "")
        if len(old) > MAX_ENCRYPTION_PASSWORD_CHARS or len(new) > MAX_ENCRYPTION_PASSWORD_CHARS:
            del old, new, new2
            return respond(400, error="Password is too long.")
        if len(new) < MIN_ENCRYPTION_PASSWORD_CHARS:
            del old, new, new2
            return respond(400, error=f"New password must be at least {MIN_ENCRYPTION_PASSWORD_CHARS} characters.")
        if new != new2:
            del old, new, new2
            return respond(400, error="The new passwords do not match.")
        del new2
        mark_setup_action_running(rt, udid, "password_change")
        # SECURITY RULE: the setup wizard's encryption step never runs through Huey, and the
        # same rule applies here, for the same reason - see
        # runtime.run_password_change. Never enqueued, always a plain thread in the web process.
        threading.Thread(
            target=run_password_change, args=(rt, udid, old, new), name=f"pwchange-{udid}", daemon=True
        ).start()
        del old, new
        return respond(200)

    @app.get("/devices/{udid}/settings/password/status")
    def device_settings_password_status(
        udid: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        context = password_change_context(conn, device)
        return render(request, "_password_change.html", user=user, device=device, **context)

    @app.post("/devices/{udid}/settings/test-notification")
    def device_settings_test(
        udid: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        urls = notify_targets(conn, device)
        if not urls:
            return HTMLResponse('<p id="notify-test" class="flash bad">No notification URLs are saved yet.</p>')
        title, body = (
            "Test notification from bioseasy",
            f"This is a test message for {device['name'] or device['udid']}.",
        )
        result = notify.send(urls, title, body)
        if result.ok:
            return HTMLResponse('<p id="notify-test" class="flash">Test message sent.</p>')
        return HTMLResponse(f'<p id="notify-test" class="flash bad">{html.escape(result.error)}</p>')

    @app.post("/devices/{udid}/connectors/{kind}")
    def device_connector_create(
        udid: str,
        kind: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        result = validate_connector_form(kind, form)
        if result.errors:
            return render(
                request,
                "device_settings.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                current_udid=udid,
                device=device,
                connectors=connectors_context(conn, "device", udid),
                create_errors={kind: result.errors},
                create_values={kind: form},
                global_defaults=backup_defaults.get_global_defaults(conn),
                retention_defaults=backup_defaults.get_global_defaults(conn).retention,
                retention_preview=retention_preview(udid, device_policy(conn, device)),
                **field_modes(device),
                **password_change_context(conn, device),
            )
        secret_ciphertext = connectors.encrypt_secret(settings.data_dir, result.secret) if result.secret else None
        connectors.create_connector(
            conn,
            scope="device",
            udid=udid,
            kind=kind,
            label=result.label,
            settings=result.settings,
            secret_ciphertext=secret_ciphertext,
        )
        return RedirectResponse(f"/devices/{udid}/settings?saved=1", status_code=303)

    @app.post("/devices/{udid}/connectors/{connector_id}/edit")
    def device_connector_update(
        udid: str,
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        device = visible_device(conn, user, udid)
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "device" or row["udid"] != udid:
            raise HTTPException(status_code=404)
        result = connectors.VALIDATORS[row["kind"]](form)
        if result.errors:
            return render(
                request,
                "device_settings.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                current_udid=udid,
                device=device,
                connectors=connectors_context(conn, "device", udid),
                edit_error_id=connector_id,
                edit_errors=result.errors,
                edit_values=form,
                global_defaults=backup_defaults.get_global_defaults(conn),
                retention_defaults=backup_defaults.get_global_defaults(conn).retention,
                retention_preview=retention_preview(udid, device_policy(conn, device)),
                **field_modes(device),
                **password_change_context(conn, device),
            )
        secret_ciphertext = (
            connectors.encrypt_secret(settings.data_dir, result.secret) if result.secret else row["secret_ciphertext"]
        )
        connectors.update_connector(
            conn,
            connector_id,
            label=result.label,
            settings=result.settings,
            secret_ciphertext=secret_ciphertext,
            enabled=bool(form.get("enabled")),
        )
        return RedirectResponse(f"/devices/{udid}/settings?saved=1", status_code=303)

    @app.post("/devices/{udid}/connectors/{connector_id}/delete")
    def device_connector_delete(
        udid: str,
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        visible_device(conn, user, udid)
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "device" or row["udid"] != udid:
            raise HTTPException(status_code=404)
        connectors.delete_connector(conn, connector_id)
        return RedirectResponse(f"/devices/{udid}/settings?saved=1", status_code=303)

    @app.post("/devices/{udid}/connectors/{connector_id}/test")
    def device_connector_test(
        udid: str,
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        visible_device(conn, user, udid)
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "device" or row["udid"] != udid:
            raise HTTPException(status_code=404)
        return connector_test_response(row)

    @app.get("/add")
    def add_page(request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)):
        # Reads seen_devices instead of calling engine.discover(): discovery can block for
        # seconds against real hardware, so it never runs inside a request.
        # It is kept fresh by the scheduler tick and by "Scan now" (add_scan, below).
        known = {r["udid"] for r in conn.execute("SELECT udid FROM devices")}
        seen = [
            r
            for r in conn.execute("SELECT * FROM seen_devices ORDER BY last_seen_at DESC").fetchall()
            if r["udid"] not in known
        ]
        pairings_by_udid = {r["udid"]: r for r in conn.execute("SELECT * FROM pairings")}
        return render(
            request, "add.html", user=user, devices=visible_devices(conn, user), seen=seen, pairings=pairings_by_udid
        )

    @app.post("/add/scan")
    def add_scan(request: Request, form: dict = Depends(csrf_form), user: auth.User = Depends(admin_user)):
        discover_now()
        return RedirectResponse("/add", status_code=303)

    @app.post("/add")
    def add_submit(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # The fast path for a device seen_devices already reports as paired: no engine call, no
        # pairing wait, just record it. An unpaired device goes through add_pair_start instead.
        udid = pairing.normalize_udid(form.get("udid", ""))
        match = conn.execute("SELECT * FROM seen_devices WHERE udid = ? AND paired = 1", (udid,)).fetchone()
        if match is None:
            raise HTTPException(status_code=404, detail="Device is no longer reachable. Try Scan now.")
        conn.execute(
            "INSERT OR IGNORE INTO devices (udid, name, product_type, os_version, owner_id, paired_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                udid,
                match["name"],
                match["product_type"],
                match["os_version"],
                user.id,
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        # A device re-added from the Scan list can already have Wi-Fi and encryption on - the
        # pair record, and any backup, can survive a recreated database (docs/setup.md, "Adding
        # a device again") - so detection runs right away, before the wizard is ever shown.
        device = conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()
        maybe_enqueue_setup_detect(device)
        # Lands on the setup wizard, not the device page directly: every newly added device
        # still needs Wi-Fi backups turned on, encryption turned on and a first backup, even on
        # this fast path (docs/setup.md).
        return RedirectResponse(f"/devices/{udid}/setup", status_code=303)

    @app.post("/add/pair")
    def add_pair_start(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # Pairing waits on the device's own Trust dialog for up to 120s, so
        # it always runs off this request through the Huey pair_device task, never here. The
        # pairings row is what the Add page and the pairing status page poll with htmx from here.
        udid = pairing.normalize_udid(form.get("udid", ""))
        seen = conn.execute("SELECT 1 FROM seen_devices WHERE udid = ?", (udid,)).fetchone()
        if seen is None:
            raise HTTPException(status_code=404, detail="Device is no longer reachable. Try Scan now.")
        if conn.execute("SELECT 1 FROM devices WHERE udid = ?", (udid,)).fetchone() is not None:
            raise HTTPException(status_code=409, detail="Device is already added.")
        conn.execute(
            "INSERT INTO pairings (udid, state, message, updated_at) VALUES (?, 'pending', NULL, ?) "
            "ON CONFLICT(udid) DO UPDATE SET state = 'pending', message = NULL, updated_at = excluded.updated_at",
            (udid, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        pair_device(udid)
        return RedirectResponse(f"/add/pairing/{udid}", status_code=303)

    def add_device_from_pairing(conn: sqlite3.Connection, user: auth.User, udid: str) -> None:
        # The pairing task (runtime.run_pairing) only owns the pairing itself, not ownership:
        # the add happens here, in the web process, with the admin who actually requested it -
        # the same shape as add_submit's fast path, just triggered once state == 'done' instead
        # of by a form post. INSERT OR IGNORE: both routes below can reach this for the same
        # udid (a full page load that finds the pairing already done, and a poll that finds it
        # done moments later), and it must be harmless either way.
        seen = conn.execute("SELECT * FROM seen_devices WHERE udid = ?", (udid,)).fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO devices (udid, name, product_type, os_version, owner_id, paired_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                udid,
                seen["name"] if seen else None,
                seen["product_type"] if seen else None,
                seen["os_version"] if seen else None,
                user.id,
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        device = conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()
        if device is not None:
            maybe_enqueue_setup_detect(device)

    @app.get("/add/pairing/{udid}")
    def pairing_status_page(
        udid: str,
        request: Request,
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = conn.execute("SELECT * FROM pairings WHERE udid = ?", (udid,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404)
        # The demo engine (and a fast real pairing) can finish before this first page load ever
        # happens: without this, only the htmx poll below would ever add the device, and a
        # pairing that was already 'done' by the time the redirect from add_pair_start landed
        # here would show "Opening the device page..." forever, having added nothing.
        if row["state"] == "done":
            add_device_from_pairing(conn, user, udid)
            return RedirectResponse(f"/devices/{udid}/setup", status_code=303)
        return render(request, "pairing_status.html", user=user, devices=visible_devices(conn, user), pairing=row)

    @app.get("/add/pairing/{udid}/status")
    def pairing_status_partial(
        udid: str,
        request: Request,
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = conn.execute("SELECT * FROM pairings WHERE udid = ?", (udid,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404)
        if row["state"] == "done":
            add_device_from_pairing(conn, user, udid)
            response = render(request, "_pairing_status.html", user=user, pairing=row)
            response.headers["HX-Redirect"] = f"/devices/{udid}/setup"
            return response
        return render(request, "_pairing_status.html", user=user, pairing=row)

    @app.post("/add/pair-record")
    async def add_pair_record(request: Request, user: auth.User = Depends(admin_user)):
        # Multipart form: read it here instead of csrf_form, which flattens values to strings.
        form = await request.form()
        expected = request.session.get("csrf", "")
        if not expected or not secrets.compare_digest(str(form.get("csrf", "")), expected):
            raise HTTPException(status_code=403, detail="Form expired, reload the page")
        udid = pairing.normalize_udid(str(form.get("udid", "")))
        upload = form.get("record")
        problems: list[str] = []
        record = None
        if not pairing.valid_udid(udid):
            problems.append("Enter the device UDID as shown by pymobiledevice3 usbmux list")
        if upload is None or isinstance(upload, str):
            problems.append("Choose the pair record file")
        else:
            try:
                record = pairing.parse(await upload.read(pairing.MAX_RECORD_BYTES + 1))
                pairing.require_escrow_bag(record)
            except pairing.PairRecordError as exc:
                problems.append(str(exc))
                record = None
        with closing(connect()) as conn:
            if problems:
                return render(
                    request,
                    "add.html",
                    status_code=400,
                    user=user,
                    devices=visible_devices(conn, user),
                    seen=[],
                    pairings={},
                    upload_errors=problems,
                    upload_udid=udid,
                )
            pairing.store(pair_records, udid, record)
            conn.execute(
                "INSERT OR IGNORE INTO devices (udid, name, owner_id, paired_at) VALUES (?, ?, ?, ?)",
                (udid, udid, user.id, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
            )
            device = conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()
            if device is not None:
                maybe_enqueue_setup_detect(device)
        # The record is a device credential: log that it arrived, never what it contains.
        log.info("pair record uploaded for device %s", udid)
        return RedirectResponse(f"/devices/{udid}/setup", status_code=303)

    @app.post("/add/pair-code")
    def add_pair_code_start(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # The preferred onboarding path (docs/pairing.md, "Pair from my computer"): a short-lived,
        # single-use code the user trades for a pair record with a one-line command on their own
        # computer, over POST /pair/{code} below - no USB at the server, no manual file upload.
        try:
            code, _expires_at = handoff.create_code(conn, user.id, datetime.now(UTC))
        except handoff.TooManyOpenCodesError as exc:
            return render(
                request,
                "add.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                seen=[],
                pairings={},
                pair_code_error=str(exc),
            )
        return RedirectResponse(f"/add/pair-code/{code}", status_code=303)

    @app.get("/add/pair-code/{code}")
    def pair_code_page(
        code: str,
        request: Request,
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = handoff.get_code(conn, user.id, code)
        if row is None:
            raise HTTPException(status_code=404)
        if row["used_at"] is not None:
            return RedirectResponse(f"/devices/{row['consumed_udid']}/setup", status_code=303)
        base_url = resolve_base_url(settings, request)
        expired = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= datetime.now(UTC)
        return render(
            request,
            "pair_code.html",
            user=user,
            devices=visible_devices(conn, user),
            code=code,
            expires_at=row["expires_at"],
            base_url=base_url,
            unencrypted_warning=base_url_is_unencrypted(base_url),
            helper_url_macos=settings.helper_url_macos,
            helper_url_linux=settings.helper_url_linux,
            helper_url_windows=settings.helper_url_windows,
            done=False,
            expired=expired,
        )

    @app.get("/add/pair-code/{code}/status")
    def pair_code_status_partial(
        code: str,
        request: Request,
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = handoff.get_code(conn, user.id, code)
        if row is None:
            raise HTTPException(status_code=404)
        if row["used_at"] is not None:
            response = render(request, "_pair_code_status.html", user=user, code=code, done=True, expired=False)
            response.headers["HX-Redirect"] = f"/devices/{row['consumed_udid']}/setup"
            return response
        expired = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= datetime.now(UTC)
        return render(request, "_pair_code_status.html", user=user, code=code, done=False, expired=expired)

    @app.get("/pair/{code}/bioseasy-pair.py")
    def pair_handoff_script(code: str, request: Request) -> Response:
        # No session, no admin check: this is fetched by `uv run <url>` on the user's own
        # computer, which never signs in to bioseasy. Served only while the code could still
        # succeed, so a stale or copy-pasted link stops working the same moment the code would.
        # Throttled per IP with the same counter as POST /pair/{code}: guessing codes here must
        # not be cheaper than guessing them there. A served script is not a success - only the
        # POST that follows is - so a correct code does not clear the counter here.
        ip_key = request.client.host if request.client else "unknown"
        wait = pair_handoff_throttle_by_ip.wait_seconds(ip_key, time.monotonic())
        if wait > 0:
            return PlainTextResponse(
                "Too many attempts, try again later", status_code=429, headers={"Retry-After": str(int(wait) + 1)}
            )
        with closing(connect()) as conn:
            row = handoff.consume(conn, code, datetime.now(UTC))  # read-only use: checked, never marked used
        if row is None:
            pair_handoff_throttle_by_ip.failed(ip_key, time.monotonic())
            return PlainTextResponse("Not found", status_code=404)
        base_url = resolve_base_url(settings, request)
        script = handoff.build_script(base_url, code, diagnostics._package_version("pymobiledevice3"))
        return PlainTextResponse(script, media_type="text/x-python; charset=utf-8")

    @app.post("/pair/{code}")
    async def pair_handoff(code: str, request: Request) -> Response:
        # The hand-off endpoint the script above POSTs to. Deliberately outside admin_user/
        # csrf_form: the caller is a plain script on the user's own computer, holding only the
        # code, never a session cookie - there is no cookie for CSRF to ride, so none is checked
        # (the same reasoning api.py documents for the bearer-token status API).
        now = datetime.now(UTC)
        ip_key = request.client.host if request.client else "unknown"
        wait = pair_handoff_throttle_by_ip.wait_seconds(ip_key, time.monotonic())
        if wait > 0:
            return PlainTextResponse(
                "Too many attempts, try again later", status_code=429, headers={"Retry-After": str(int(wait) + 1)}
            )
        body = await request.body()
        udid = pairing.normalize_udid(request.headers.get("x-bioseasy-udid", ""))
        device_name = request.headers.get("x-bioseasy-device-name", "").strip()

        def rejected() -> Response:
            pair_handoff_throttle_by_ip.failed(ip_key, time.monotonic())
            # One generic body for every failure reason (unknown/expired/used code, bad UDID, an
            # unusable record): telling them apart would tell a guesser which reason they hit.
            return PlainTextResponse("Not found", status_code=404)

        if len(body) > pairing.MAX_RECORD_BYTES or not pairing.valid_udid(udid):
            return rejected()
        with closing(connect()) as conn:
            row = handoff.consume(conn, code, now)
            if row is None:
                return rejected()
            try:
                record = pairing.parse(body)
                pairing.require_escrow_bag(record)
            except pairing.PairRecordError:
                return rejected()
            pairing.store(pair_records, udid, record)
            conn.execute(
                "INSERT OR IGNORE INTO devices (udid, name, owner_id, paired_at) VALUES (?, ?, ?, ?)",
                (udid, device_name or udid, row["created_by"], now.strftime("%Y-%m-%dT%H:%M:%SZ")),
            )
            handoff.mark_consumed(conn, row["id"], udid, now)
        pair_handoff_throttle_by_ip.succeeded(ip_key)
        # The record is a device credential, same rule as the upload path above: log that it
        # arrived, never what it contains, and only a shortened UDID (docs/pairing.md).
        log.info("pair hand-off completed for device %s...", udid[:8])
        return PlainTextResponse(f"Paired {device_name or 'device'}. Continue in your browser.")

    @app.get("/admin/storage")
    def storage_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        mount_result = mountinfo.backup_root_mount(storage.read_mountinfo(), str(settings.backup_root))
        return render(
            request,
            "storage.html",
            user=user,
            devices=visible_devices(conn, user),
            check=storage_check(),
            root=settings.backup_root,
            initialised=db.get_setting(conn, "backup_root_id") is not None,
            mount_message=mount_result[0] if mount_result else None,
            mount_warning=mount_result[1] if mount_result else False,
        )

    @app.post("/admin/storage/initialise")
    def storage_initialise(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if not settings.backup_root.is_dir():
            raise HTTPException(status_code=409, detail="Backup root does not exist in the container")
        db.set_setting(conn, "backup_root_id", storage.initialise(settings.backup_root))
        return RedirectResponse("/admin/storage", status_code=303)

    @app.get("/admin/storage/browse")
    def storage_browse(
        request: Request,
        path: str = "",
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        target = browse.resolve_within_root(settings.backup_root, path)
        if target is None:
            raise HTTPException(status_code=404)
        rel = browse.relative_path(settings.backup_root, target)
        entries = browse.list_directory(target, rel)
        dir_sizes = {e.rel_path: browse.get_dir_size(conn, e.rel_path) for e in entries if e.is_dir}
        device_names = {r["udid"]: (r["name"] or r["udid"]) for r in conn.execute("SELECT udid, name FROM devices")}
        return render(
            request,
            "storage_browse.html",
            user=user,
            devices=visible_devices(conn, user),
            root_rel=rel,
            breadcrumbs=browse.breadcrumbs(rel),
            entries=entries,
            dir_sizes=dir_sizes,
            device_names=device_names,
        )

    @app.get("/admin/storage/browse/size")
    def storage_browse_size(
        request: Request,
        path: str = "",
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        target = browse.resolve_within_root(settings.backup_root, path)
        if target is None:
            raise HTTPException(status_code=404)
        rel = browse.relative_path(settings.backup_root, target)
        return render(request, "_dir_size.html", user=user, rel_path=rel, row=browse.get_dir_size(conn, rel))

    @app.post("/admin/storage/browse/recalculate")
    def storage_browse_recalculate(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        target = browse.resolve_within_root(settings.backup_root, form.get("path", ""))
        if target is None:
            raise HTTPException(status_code=404)
        rel = browse.relative_path(settings.backup_root, target)
        browse.mark_calculating(conn, rel)
        # Captured before the task can possibly finish, so the response always reflects the
        # "calculating" state it just set - re-querying afterwards would race a fast background
        # computation that could already have overwritten it with the finished result.
        calculating_row = browse.get_dir_size(conn, rel)
        built_tasks.compute_dir_size(rel)
        if request.headers.get("hx-request"):
            return render(request, "_dir_size.html", user=user, rel_path=rel, row=calculating_row)
        path = form.get("path", "")
        target_url = f"/admin/storage/browse?path={quote(path)}" if path else "/admin/storage/browse"
        return RedirectResponse(target_url, status_code=303)

    @app.get("/admin/defaults")
    def admin_settings_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        global_defaults = backup_defaults.get_global_defaults(conn)
        return render(
            request,
            "admin_settings.html",
            user=user,
            devices=visible_devices(conn, user),
            saved=request.query_params.get("saved") == "1",
            connectors=connectors_context(conn, "admin"),
            global_defaults=global_defaults,
            retention_defaults=global_defaults.retention,
            update_check_repo_configured=bool(update_check.GITHUB_REPO),
            update_check_enabled=update_check.is_enabled(conn),
            update_check_result=update_check.last_result(conn),
            mqtt_settings=mqtt.form_defaults(mqtt.stored_settings(conn) or {}),
            mqtt_password_set=mqtt.password_set(conn),
        )

    @app.post("/admin/defaults")
    def admin_settings_submit(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        new_defaults, errors = validate_global_defaults_form(form)
        if errors or new_defaults is None:
            return render(
                request,
                "admin_settings.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                connectors=connectors_context(conn, "admin"),
                errors=errors,
                global_defaults=backup_defaults.get_global_defaults(conn),
                retention_defaults=backup_defaults.get_global_defaults(conn).retention,
                defaults_form=form,
            )
        backup_defaults.set_global_defaults(conn, new_defaults)
        return RedirectResponse("/admin/defaults?saved=1", status_code=303)

    @app.post("/admin/update")
    def admin_update_check_toggle(
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # Silently a no-op while GITHUB_REPO is unset: the form control is disabled in the
        # template for that case too, but a direct POST must not flip a switch that then does
        # nothing but confuse - and must also never look like it turned checking on.
        if update_check.GITHUB_REPO:
            update_check.set_enabled(conn, bool(form.get("enabled")))
        return RedirectResponse("/admin/update?saved=1", status_code=303)

    @app.post("/admin/notifications/test")
    def admin_settings_test(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        urls = connectors.apprise_urls_for(conn, settings.data_dir, "admin")
        if not urls:
            return HTMLResponse('<p id="notify-test" class="flash bad">No notification URLs are saved yet.</p>')
        result = notify.send(urls, "Test notification from bioseasy", "This is a test message for the admin alerts.")
        if result.ok:
            return HTMLResponse('<p id="notify-test" class="flash">Test message sent.</p>')
        return HTMLResponse(f'<p id="notify-test" class="flash bad">{html.escape(result.error)}</p>')

    @app.post("/admin/notifications/connectors/{kind}")
    def admin_connector_create(
        kind: str,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        result = validate_connector_form(kind, form)
        if result.errors:
            return render(
                request,
                "admin_notifications.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                connectors=connectors_context(conn, "admin"),
                create_errors={kind: result.errors},
                create_values={kind: form},
                global_defaults=backup_defaults.get_global_defaults(conn),
                retention_defaults=backup_defaults.get_global_defaults(conn).retention,
            )
        secret_ciphertext = connectors.encrypt_secret(settings.data_dir, result.secret) if result.secret else None
        connectors.create_connector(
            conn,
            scope="admin",
            udid=None,
            kind=kind,
            label=result.label,
            settings=result.settings,
            secret_ciphertext=secret_ciphertext,
        )
        return RedirectResponse("/admin/notifications?saved=1", status_code=303)

    @app.post("/admin/notifications/connectors/{connector_id}/edit")
    def admin_connector_update(
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "admin":
            raise HTTPException(status_code=404)
        result = connectors.VALIDATORS[row["kind"]](form)
        if result.errors:
            return render(
                request,
                "admin_notifications.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                connectors=connectors_context(conn, "admin"),
                edit_error_id=connector_id,
                edit_errors=result.errors,
                edit_values=form,
                global_defaults=backup_defaults.get_global_defaults(conn),
                retention_defaults=backup_defaults.get_global_defaults(conn).retention,
            )
        secret_ciphertext = (
            connectors.encrypt_secret(settings.data_dir, result.secret) if result.secret else row["secret_ciphertext"]
        )
        connectors.update_connector(
            conn,
            connector_id,
            label=result.label,
            settings=result.settings,
            secret_ciphertext=secret_ciphertext,
            enabled=bool(form.get("enabled")),
        )
        return RedirectResponse("/admin/notifications?saved=1", status_code=303)

    @app.post("/admin/notifications/connectors/{connector_id}/delete")
    def admin_connector_delete(
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "admin":
            raise HTTPException(status_code=404)
        connectors.delete_connector(conn, connector_id)
        return RedirectResponse("/admin/notifications?saved=1", status_code=303)

    @app.post("/admin/notifications/mqtt")
    def admin_mqtt_submit(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        result = mqtt.validate_form(form)
        if result.errors:
            global_defaults = backup_defaults.get_global_defaults(conn)
            return render(
                request,
                "admin_notifications.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                connectors=connectors_context(conn, "admin"),
                global_defaults=global_defaults,
                retention_defaults=global_defaults.retention,
                mqtt_settings=form,
                mqtt_password_set=mqtt.password_set(conn),
                mqtt_errors=result.errors,
            )
        mqtt.save_config(conn, settings.data_dir, result.settings, result.secret)
        return RedirectResponse("/admin/notifications?saved=1", status_code=303)

    @app.post("/admin/notifications/mqtt/test")
    def admin_mqtt_test(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        cfg = mqtt.load_config(conn, settings.data_dir)
        if cfg is None or not cfg.host:
            return HTMLResponse('<p id="mqtt-test" class="flash bad">Save the broker settings first.</p>')
        statuses = [status.to_public(s) for s in status.for_admin(conn, settings.backup_root, datetime.now(UTC))]
        try:
            mqtt.publish_all(cfg, statuses)
        except Exception as exc:
            # Never the exception's own text: it can echo the broker host or an auth failure
            # built from the password (mqtt.py's module docstring).
            return HTMLResponse(
                f'<p id="mqtt-test" class="flash bad">Publish failed: {html.escape(type(exc).__name__)}</p>'
            )
        return HTMLResponse('<p id="mqtt-test" class="flash">Test state published.</p>')

    @app.post("/admin/notifications/connectors/{connector_id}/test")
    def admin_connector_test(
        connector_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        row = connectors.get_connector(conn, connector_id)
        if row is None or row["scope"] != "admin":
            raise HTTPException(status_code=404)
        return connector_test_response(row)

    @app.get("/admin/logs")
    def logs_page(
        request: Request,
        view: str = "system",
        level: str = "",
        process: str = "",
        device: str = "",
        kind: str = "",
        page: int = 1,
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        view = view if view in dict(LOG_VIEWS) else "system"
        if view == "application":
            # The same feed /log renders, with no owner clause: an admin is the one role that may
            # see every device, which `admin_user` above has already established. The scope is
            # still decided in one place (events.list_events' owner_id) rather than by a filter
            # this route could forget to apply.
            event_page = events.list_events(conn, owner_id=None, kind=kind or None, udid=device or None, page=page)
            return render(
                request,
                "logs.html",
                user=user,
                devices=visible_devices(conn, user),
                view=view,
                log_views=LOG_VIEWS,
                event_page=event_page,
                entries=events.shape(event_page.rows),
                scope_devices=events.devices_in_scope(conn, None),
                kinds=events.KINDS,
                kind_labels=events.KIND_LABELS,
                filter_kind=kind if kind in events.KINDS else "",
                filter_device=device,
            )
        level = level if level in logview.LEVELS else ""
        process = process if process in logview.PROCESSES else ""
        log_page = logview.list_entries(
            conn, level=level or None, process=process or None, udid=device or None, page=page
        )
        # Device names for the filter dropdown and for showing a name instead of a bare
        # shortened UDID next to a row: keyed by the same first-8-characters shortening the log
        # itself stores, so a device whose full UDID differs only after that prefix is
        # indistinguishable here - the same trade-off as the log redaction itself.
        device_names = {r["udid"][:8]: (r["name"] or r["udid"]) for r in conn.execute("SELECT udid, name FROM devices")}
        return render(
            request,
            "logs.html",
            user=user,
            devices=visible_devices(conn, user),
            view=view,
            log_views=LOG_VIEWS,
            log_page=log_page,
            device_names=device_names,
            levels=logview.LEVELS,
            processes=logview.PROCESSES,
            filter_level=level,
            filter_process=process,
            filter_device=device,
        )

    def send_invitation(conn: sqlite3.Connection, recipient: str, base_url: str) -> None:
        """Tell a newly created account's owner that it exists, if an email connector can carry it.

        The URL is built here, on the request's own connection, and only the send itself runs on a
        detached thread: that thread must never touch a connection the request is about to close.
        Creating the account never depends on this - the account exists before this is called, and
        a broken or missing mail setup leaves a log line, not a failed creation.

        The message carries a link and nothing else. Never the initial password: the admin who
        typed it passes it on themselves, through whatever channel they trust.
        """
        url = connectors.email_invite_url(conn, settings.data_dir, recipient)
        if url is None:
            return

        def send_it() -> None:
            try:
                result = notify.send(
                    [url],
                    "Your bioseasy account",
                    f"An account has been created for you on this bioseasy server: {base_url}/login\n"
                    "Your password was set by the administrator who created the account; ask them for it.",
                )
                if not result.ok:
                    # Short, secret-free text from NotifyResult, and never the recipient address.
                    log.warning("invitation could not be sent: %s", result.error)
            except Exception as exc:
                log.warning("invitation could not be sent (%s)", type(exc).__name__)

        threading.Thread(target=send_it, name="invite", daemon=True).start()

    def users_context(conn: sqlite3.Connection, **extra) -> dict:
        return {
            "local_users": auth.list_users(conn),
            "admin_count": auth.admin_count(conn),
            "min_password_length": auth.MIN_PASSWORD_LENGTH,
            # Whether an invitation could go out at all, so the email field says which it is
            # instead of promising a mail that no configured connector could send.
            "invite_possible": connectors.email_invite_url(conn, settings.data_dir, "probe@example.invalid")
            is not None,
            # Accounts from before an address was required. Nothing can fill these in on its own -
            # no address exists for them and none may be invented - so the page asks.
            "users_without_email": auth.users_without_email(conn),
            **extra,
        }

    @app.get("/admin/users")
    def users_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(
            request,
            "users.html",
            user=user,
            devices=visible_devices(conn, user),
            saved=request.query_params.get("saved") == "1",
            **users_context(conn),
        )

    @app.post("/admin/users")
    def users_create(
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        email = (form.get("email") or "").strip()
        try:
            # auth.register_user validates username length, password length (the same policy the
            # setup wizard and every other account use), role and the address, which is required
            # because it is what an SSO sign-in is matched by; never logged,
            # and the plain password is discarded the moment this call returns.
            auth.register_user(
                conn, form.get("username", ""), form.get("password", ""), form.get("role", "member"), email
            )
        except ValueError as exc:
            return render(
                request,
                "users.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                create_error=str(exc),
                create_values={
                    "username": form.get("username", ""),
                    "role": form.get("role", "member"),
                    "email": email,
                },
                **users_context(conn),
            )
        if email:
            send_invitation(conn, email, resolve_base_url(settings, request))
        return RedirectResponse("/admin/users?saved=1", status_code=303)

    @app.post("/admin/users/{user_id}/email")
    def users_set_email(
        user_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        """Fill in (or correct) an account's address. The only way an account created before
        the address requirement existed ever gets one, and admin-only on purpose: the address
        decides which account a single sign-on identity signs in as (auth.set_email)."""
        target = auth.get_user(conn, user_id)
        if target is None:
            raise HTTPException(status_code=404)
        try:
            auth.set_email(conn, target.id, form.get("email", ""))
        except ValueError as exc:
            return render(
                request,
                "users.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                action_error=str(exc),
                **users_context(conn),
            )
        return RedirectResponse("/admin/users?saved=1", status_code=303)

    @app.post("/admin/users/{user_id}/role")
    def users_change_role(
        user_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        target = auth.get_user(conn, user_id)
        if target is None:
            raise HTTPException(status_code=404)
        new_role = form.get("role", "")
        error = None
        if new_role not in ("admin", "member"):
            error = "Unknown role."
        elif target.role == "admin" and new_role == "member" and auth.admin_count(conn) <= 1:
            # Safety rule: the last remaining admin can neither be demoted nor removed (below),
            # or the instance would end up with nobody able to reach any admin-only page again.
            error = "The last remaining admin cannot be demoted."
        if error:
            return render(
                request,
                "users.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                action_error=error,
                **users_context(conn),
            )
        auth.set_role(conn, target.id, new_role)
        return RedirectResponse("/admin/users?saved=1", status_code=303)

    @app.post("/admin/users/{user_id}/remove")
    def users_remove(
        user_id: int,
        request: Request,
        form: dict = Depends(csrf_form),
        user: auth.User = Depends(admin_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        target = auth.get_user(conn, user_id)
        if target is None:
            raise HTTPException(status_code=404)
        error = None
        if target.role == "admin" and auth.admin_count(conn) <= 1:
            # Checked before the self-removal rule below: with only one admin left, that admin
            # removing themselves would also trip the self rule, but this is the rule that
            # actually explains why - losing the last admin, not who asked for it.
            error = "The last remaining admin cannot be removed."
        elif target.id == user.id:
            # Self-removal from this page is refused on purpose: the user's own Settings stay the only
            # place to manage your own account, so an admin can never lock themselves out here.
            error = "You cannot remove your own account from this page. Use Account for that."
        else:
            device_count = conn.execute("SELECT COUNT(*) FROM devices WHERE owner_id = ?", (target.id,)).fetchone()[0]
            if device_count > 0:
                noun = "device" if device_count == 1 else "devices"
                error = (
                    f"{target.username} still owns {device_count} {noun}. Reassign them to another "
                    "user on each device's settings page first."
                )
        if error:
            return render(
                request,
                "users.html",
                status_code=400,
                user=user,
                devices=visible_devices(conn, user),
                action_error=error,
                **users_context(conn),
            )
        auth.remove_user(conn, target.id)
        return RedirectResponse("/admin/users?saved=1", status_code=303)

    @app.get("/admin/about")
    def about_page(
        request: Request, user: auth.User = Depends(admin_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        # No discovery here: this page must load instantly and never touch USB or the network.
        report = diagnostics.collect(settings, connect, None, discover=False)
        return render(
            request,
            "about.html",
            user=user,
            devices=visible_devices(conn, user),
            report=report,
            report_text=diagnostics.render_text(report),
            tested_with=diagnostics.TESTED_WITH,
        )

    # Not "/docs": the app already reserves that path to mean "no interactive OpenAPI explorer
    # here" (FastAPI(..., docs_url=None) above, and test_status_api.py checks it stays 404).
    # "/guide" is this project's own rendered docs/*.md instead, gated on sign-in like the rest
    # of the app.
    @app.get("/guide")
    def docs_index(
        request: Request, user: auth.User = Depends(current_user), conn: sqlite3.Connection = Depends(get_conn)
    ):
        return render(
            request,
            "docs_index.html",
            user=user,
            devices=visible_devices(conn, user),
            pages=docs.nav(),
            doc_sections=docs.sections(),
        )

    @app.get("/guide/{slug}")
    def docs_page(
        slug: str,
        request: Request,
        user: auth.User = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        page = docs.render(docs_dir, slug)
        if page is None:
            raise HTTPException(status_code=404)
        return render(
            request, "docs_page.html", user=user, devices=visible_devices(conn, user), pages=docs.nav(), page=page
        )

    return app


def asgi() -> FastAPI:
    """Entry point for `uvicorn --factory bioseasy.app:asgi`."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
