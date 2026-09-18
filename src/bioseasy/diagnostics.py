# SPDX-License-Identifier: GPL-3.0-or-later
"""A report a user can paste into a public bug report without leaking anything.

Never include: notify URLs, the secret key, the setup token, session data, pair record
content, full UDIDs, or device names (they often carry a person's name). Everything here is
built to be safe first: only counts, booleans, masked identifiers and non-secret facts leave
this module.
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from stat import S_IMODE

from . import defaults as backup_defaults
from . import storage
from .config import Settings
from .db import get_setting
from .engine.base import Engine

PAIR_RECORDS_DIRNAME = "pair-records"

# What bioseasy has actually been run against, for the About page. One constant, not scattered
# strings, so the page and any future export read the same facts. This is a short compatibility
# note, not an evidence trail, so it names the device and the versions and stops there.
TESTED_WITH: list[dict[str, str]] = [
    {
        "device": "iPad",
        "os_version": "iPadOS 26.3.1",
        "pymobiledevice3_version": "11.12.5",
    },
]

# Every single sign-on setting starts with this prefix (config.py). The report says only whether
# any is set, never a value: the client secret is one of them.
_OIDC_ENV_PREFIX = "BIOSEASY_OIDC"


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def _versions() -> dict[str, str]:
    return {
        "bioseasy": _package_version("bioseasy"),
        "python": platform.python_version(),
        "pymobiledevice3": _package_version("pymobiledevice3"),
        "apprise": _package_version("apprise"),
        "fastapi": _package_version("fastapi"),
    }


def _oidc_env_set(env: dict[str, str]) -> bool:
    return any(key.startswith(_OIDC_ENV_PREFIX) for key in env)


def mask_udid(udid: str) -> str:
    """Last 6 characters only; enough to tell devices apart in a bug thread, not to identify one."""
    tail = udid[-6:] if len(udid) > 6 else udid
    return f"...{tail}"


def _storage_report(backup_root: Path, conn: sqlite3.Connection | None) -> dict:
    root_id = get_setting(conn, "backup_root_id") if conn is not None else None
    threshold = (
        backup_defaults.get_global_defaults(conn).free_space_threshold_bytes
        if conn is not None
        else backup_defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB * 2**30
    )
    check = storage.check(backup_root, root_id, threshold)
    return {
        "ok": check.ok,
        "problems": list(check.problems),
        "free_bytes": check.free_bytes,
        "total_bytes": check.total_bytes,
        "hardlinks": check.hardlinks,
    }


def _pair_records_report(folder: Path) -> dict:
    if not folder.is_dir():
        return {"count": 0, "all_mode_0600": True}
    # Never open these files: only the mode bit is inspected, never the plist content.
    files = [p for p in folder.iterdir() if p.is_file() and p.suffix == ".plist"]
    all_0600 = all(S_IMODE(p.stat().st_mode) == 0o600 for p in files)
    return {"count": len(files), "all_mode_0600": all_0600}


def _devices_report(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM devices ORDER BY udid").fetchall()
    devices = []
    for row in rows:
        last_run = conn.execute(
            "SELECT status, started_at FROM runs WHERE udid = ? ORDER BY started_at DESC LIMIT 1",
            (row["udid"],),
        ).fetchone()
        last_seen = conn.execute(
            "SELECT seen_at, transport FROM sightings WHERE udid = ? ORDER BY seen_at DESC LIMIT 1",
            (row["udid"],),
        ).fetchone()
        devices.append(
            {
                "udid": mask_udid(row["udid"]),
                "name": "set" if row["name"] else "not set",
                "model": row["product_type"],
                "os_version": row["os_version"],
                "last_run_status": last_run["status"] if last_run else None,
                "last_run_at": last_run["started_at"] if last_run else None,
                "last_seen_at": last_seen["seen_at"] if last_seen else None,
                "last_seen_transport": last_seen["transport"] if last_seen else None,
            }
        )
    return devices


def _runs_report(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT udid, trigger, status, message, started_at FROM runs ORDER BY started_at DESC LIMIT 10"
    ).fetchall()
    runs = []
    for row in rows:
        message = row["message"] or ""
        runs.append(
            {
                "udid": mask_udid(row["udid"]),
                "trigger": row["trigger"],
                "status": row["status"],
                "started_at": row["started_at"],
                "message": message[:120],
            }
        )
    return runs


def _discovery_report(engine: Engine) -> dict:
    start = time.monotonic()
    try:
        found = engine.discover()
    except Exception as exc:
        # Only the exception class name leaves this function: the message could name a
        # hostname, an IP or another environment detail.
        return {"duration_seconds": round(time.monotonic() - start, 3), "exception": type(exc).__name__}
    duration = round(time.monotonic() - start, 3)
    return {
        "duration_seconds": duration,
        "devices": [
            {
                "udid": mask_udid(d.udid),
                "transport": str(d.transport),
                "name": "set" if d.name else "not set",
                "model": d.product_type,
                "os_version": d.os_version,
                "paired": d.paired,
            }
            for d in found
        ],
    }


def collect(
    settings: Settings,
    connect: Callable[[], sqlite3.Connection | None],
    engine: Engine | None,
    discover: bool,
) -> dict:
    """Build the report. `connect` returns None when there is no database to open yet.

    `engine` is only used for discovery; pass None to skip it (the caller decides whether to
    build one, since constructing the real engine can touch the host's USB or network stack).
    """
    report: dict = {
        "versions": _versions(),
        "engine": settings.engine,
        "platform": platform.platform(),
        "config": {
            "data_dir": str(settings.data_dir),
            "backup_root": str(settings.backup_root),
            "timezone": settings.timezone,
            "schedule_minutes": settings.schedule_minutes,
            "secure_cookies": settings.secure_cookies,
            "oidc_env_set": _oidc_env_set(os.environ),
        },
        "pair_records": _pair_records_report(settings.data_dir / PAIR_RECORDS_DIRNAME),
    }

    conn = connect()
    if conn is None:
        report["database"] = {"present": False}
        report["storage"] = _storage_report(settings.backup_root, None)
    else:
        with closing(conn):
            report["database"] = {"present": True}
            report["storage"] = _storage_report(settings.backup_root, conn)
            report["devices"] = _devices_report(conn)
            report["runs"] = _runs_report(conn)

    if discover:
        report["discovery"] = _discovery_report(engine) if engine is not None else {"error": "no engine available"}

    return report


def _fmt_bytes(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value / 2**30:.1f} GiB"


def render_text(report: dict) -> str:
    """Plain text for copy-paste into an issue. Deliberately verbose over compact: a maintainer
    reading a pasted report should not have to ask a follow-up question for a fact already here.
    """
    lines: list[str] = ["bioseasy diagnostics report", "=" * 27, ""]

    lines.append("Versions")
    for name, value in report["versions"].items():
        lines.append(f"  {name}: {value}")
    lines.append(f"Engine: {report['engine']}")
    lines.append(f"Platform: {report['platform']}")
    lines.append("")

    cfg = report["config"]
    lines.append("Configuration")
    lines.append(f"  Data directory: {cfg['data_dir']}")
    lines.append(f"  Backup root: {cfg['backup_root']}")
    lines.append(f"  Timezone: {cfg['timezone']}")
    lines.append(f"  Schedule interval: {cfg['schedule_minutes']} minutes")
    lines.append(f"  Secure cookies: {'yes' if cfg['secure_cookies'] else 'no'}")
    lines.append(f"  OIDC-like environment variables set: {'yes' if cfg['oidc_env_set'] else 'no'}")
    lines.append("")

    storage_check = report["storage"]
    lines.append("Storage check")
    lines.append(f"  Status: {'OK' if storage_check['ok'] else 'problem'}")
    if storage_check["problems"]:
        for problem in storage_check["problems"]:
            lines.append(f"    - {problem}")
    lines.append(f"  Free: {_fmt_bytes(storage_check['free_bytes'])} of {_fmt_bytes(storage_check['total_bytes'])}")
    hardlinks = {True: "supported", False: "not supported", None: "unknown"}[storage_check["hardlinks"]]
    lines.append(f"  Hard links: {hardlinks}")
    lines.append("")

    pair = report["pair_records"]
    lines.append(f"Pair records: {pair['count']}, all mode 0600: {'yes' if pair['all_mode_0600'] else 'no'}")
    lines.append("")

    if not report["database"]["present"]:
        lines.append("Database: not found (never started, or a different data directory)")
        lines.append("")
    else:
        devices = report["devices"]
        lines.append(f"Devices ({len(devices)})")
        for d in devices:
            lines.append(
                f"  {d['udid']}  model={d['model']}  iOS={d['os_version']}  name={d['name']}  "
                f"last run={d['last_run_status']} at {d['last_run_at']}  "
                f"last seen={d['last_seen_at']} via {d['last_seen_transport']}"
            )
        lines.append("")

        runs = report["runs"]
        lines.append(f"Last {len(runs)} runs")
        for r in runs:
            lines.append(f"  {r['udid']}  {r['trigger']}  {r['status']}  {r['started_at']}  {r['message']}")
        lines.append("")

    if "discovery" in report:
        disc = report["discovery"]
        lines.append("Discovery")
        if "exception" in disc:
            lines.append(f"  Failed after {disc['duration_seconds']}s: {disc['exception']}")
        elif "error" in disc:
            lines.append(f"  {disc['error']}")
        else:
            lines.append(f"  Duration: {disc['duration_seconds']}s")
            lines.append(f"  Found {len(disc['devices'])} device(s)")
            for d in disc["devices"]:
                paired = "paired" if d["paired"] else "not paired"
                lines.append(
                    f"    {d['udid']}  {d['transport']}  model={d['model']}  iOS={d['os_version']}  "
                    f"name={d['name']}  {paired}"
                )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def readonly_connector(db_path: Path) -> Callable[[], sqlite3.Connection | None]:
    """A `connect` for the CLI: opens the database read-only, never creates or migrates it.

    Plain sqlite3.connect() would create an empty file if db_path did not exist yet, which is
    exactly the side effect `bioseasy diagnose` must not have on a host that never ran the
    server before.
    """

    def connect() -> sqlite3.Connection | None:
        if not db_path.is_file():
            return None
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    return connect
