# SPDX-License-Identifier: GPL-3.0-or-later
"""Refreshes the seen_devices table from engine.discover().

Two call sites need the same result: the scheduler tick (ticker.py) and the Huey discover_now
task (tasks.py, used by the web process's "Scan now" button). Keeping the discover-then-persist
logic here means a change reaches both instead of drifting apart: the Add page reads
seen_devices and never calls engine.discover() inside the request handler.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime

from .engine.base import DeviceSeen, Engine


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def refresh_seen_devices(conn: sqlite3.Connection, devices: list[DeviceSeen], now: str | None = None) -> None:
    """Upsert every discovered device into seen_devices. Devices no longer seen are left as they
    were (a stale-but-once-real row is more useful than losing a device that missed one scan)."""
    now = now or _now()
    for d in devices:
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(udid) DO UPDATE SET "
            "name = excluded.name, product_type = excluded.product_type, os_version = excluded.os_version, "
            "transport = excluded.transport, paired = excluded.paired, last_seen_at = excluded.last_seen_at",
            (d.udid, d.name, d.product_type, d.os_version, d.transport.value, int(d.paired), now),
        )
        fill_device_identity(conn, d.udid, d.product_type, d.os_version, d.name)


def fill_device_identity(
    conn: sqlite3.Connection, udid: str, product_type: str | None, os_version: str | None, name: str | None = None
) -> None:
    """Keeps model, iOS version and name of an added device current. A device added through the
    code hand-off was never discovered by the server, so its row starts without any of the three
    (the owner saw "Unknown model" after the first real backup); a scan (lockdown DeviceName) or
    a finished backup (Info.plist "Device Name", inventory.BackupInfo.device_name) fills them in.

    Missing values never overwrite known ones, and name is additionally only ever written while
    devices.name_custom is 0: once the device settings page saves a name that differs from what
    was last synced here, the owner has renamed it and this stops touching that column (db.py).
    """
    conn.execute(
        "UPDATE devices SET "
        "product_type = COALESCE(?, product_type), "
        "os_version = COALESCE(?, os_version), "
        "name = CASE WHEN name_custom = 0 THEN COALESCE(?, name) ELSE name END "
        "WHERE udid = ?",
        (product_type or None, os_version or None, name or None, udid),
    )


def discover_and_refresh(
    connect: Callable[[], sqlite3.Connection],
    engine: Engine,
    mark_pair_used: Callable[[str], None] | None = None,
) -> list[DeviceSeen]:
    """Runs engine.discover() and persists the result to seen_devices in one place."""
    devices = engine.discover(on_pair_used=mark_pair_used)
    with closing(connect()) as conn:
        refresh_seen_devices(conn, devices)
    return devices
