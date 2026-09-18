# SPDX-License-Identifier: GPL-3.0-or-later
"""One status per device, shared by the web UI, the read-only API, MQTT and Home Assistant.

Scoping happens in the SQL query, not by filtering a full list afterwards, and there is no
parameter that widens it: `for_owner` can only ever return that owner's devices, `for_admin` is a
separate function a route has to call on purpose. A route that forgets a filter therefore cannot
hand out another user's device (OWASP API1, broken object level authorization).

A status carries no secrets and no locations: no notification URLs, no fixed address, no pair
record, no backup path. `to_public` is the only shape that may leave the process.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from . import defaults as backup_defaults
from . import inventory

State = Literal["running", "waiting_for_passcode", "never", "incomplete", "overdue", "due", "ok"]

# The newest run per device comes from a correlated subquery, so a list of devices is still one
# statement from Python's side, however many devices there are. d.* so defaults.resolve_device
# has every override column it needs, not only the two this module reads itself.
_SELECT = """
    SELECT d.*,
           r.status AS last_status, r.started_at AS last_started, r.phase AS last_phase,
           r.percent AS last_percent
    FROM devices d
    LEFT JOIN runs r ON r.id = (
        SELECT id FROM runs WHERE runs.udid = d.udid ORDER BY started_at DESC, id DESC LIMIT 1
    )
"""

# Apple Support, "Physical pairing model security for iPad and iPhone"
# (https://support.apple.com/guide/security/pairing-model-security-secadb5b6434/web, retrieved
# 2026-09-15): "On devices with iOS 11 and iPadOS 13.1, or later, if a pairing record hasn't been
# used for more than 30 days, it expires." db.py's devices.pair_used_at tracks the "used" side of
# that sentence; these thresholds decide when the UI starts saying so.
PAIR_WARN_DAYS = 21
PAIR_EXPIRED_DAYS = 30


@dataclass(frozen=True)
class DeviceStatus:
    udid: str
    name: str | None
    model: str | None
    os_version: str | None
    state: State
    last_success_at: datetime | None
    next_due_at: datetime | None
    last_run_status: str | None
    last_run_at: datetime | None
    progress_percent: float | None
    backup_complete: bool | None
    encrypted: bool | None
    pair_days_unused: int | None


def for_owner(conn: sqlite3.Connection, backup_root: Path, now: datetime, owner_id: int) -> list[DeviceStatus]:
    defaults = backup_defaults.get_global_defaults(conn)
    rows = conn.execute(_SELECT + " WHERE d.owner_id = ? ORDER BY d.name, d.udid", (owner_id,))
    return [_status(row, backup_root, now, defaults) for row in rows]


def for_admin(conn: sqlite3.Connection, backup_root: Path, now: datetime) -> list[DeviceStatus]:
    defaults = backup_defaults.get_global_defaults(conn)
    rows = conn.execute(_SELECT + " ORDER BY d.name, d.udid")
    return [_status(row, backup_root, now, defaults) for row in rows]


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def pair_days_unused(paired_at: str | None, pair_used_at: str | None, now: datetime) -> int | None:
    """Days since a device's pair record was last proven to work, or None if it was never paired.

    Falls back to `paired_at` when `pair_used_at` is still NULL (paired, but no backup, Wi-Fi
    enable, encryption check or discovery reconnect has succeeded since): the risk the warning
    is about - an unused record ageing towards Apple's 30-day expiry - starts at pairing, not at
    the first later use. Shared by the web UI (app.py's device_summary) and the API (to_public
    below) so both read the same number.
    """
    basis = pair_used_at or paired_at
    if not basis:
        return None
    return (now - _parse(basis)).days


def pair_warning(days: int | None) -> str | None:
    """The device/dashboard warning text for `days` of pair-record inactivity, or None below the
    threshold. Words, not colour alone (docs/design.md): the sentence itself says how urgent this
    is, so it reads the same in a screen reader and in a printout.
    """
    if days is None or days < PAIR_WARN_DAYS:
        return None
    if days >= PAIR_EXPIRED_DAYS:
        return f"Not connected for {days} days. This device needs pairing again."
    return f"Not connected for {days} days. After 30 days without use the device needs pairing again."


def _status(
    row: sqlite3.Row, backup_root: Path, now: datetime, defaults: backup_defaults.GlobalDefaults
) -> DeviceStatus:
    effective = backup_defaults.resolve_device(row, defaults)
    backup_dir = backup_root / row["udid"]
    info = inventory.read_backup(backup_dir, with_size=False) if backup_dir.is_dir() else None
    last_success = info.last_backup if info is not None and info.complete else None
    interval = timedelta(hours=effective.interval_hours)
    running = row["last_status"] == "running"

    state: State
    if running:
        state = "waiting_for_passcode" if row["last_phase"] == "waiting_for_passcode" else "running"
    elif info is None:
        state = "never"
    elif not info.complete:
        state = "incomplete"
    elif last_success is None:
        # A complete backup without a readable date: it asks for a new backup, but calling it
        # overdue would claim an age nobody knows.
        state = "due"
    elif now - last_success > timedelta(days=effective.overdue_days):
        state = "overdue"
    elif now - last_success > interval:
        state = "due"
    else:
        state = "ok"

    return DeviceStatus(
        udid=row["udid"],
        name=row["name"],
        model=row["product_type"],
        os_version=row["os_version"],
        state=state,
        last_success_at=last_success,
        next_due_at=last_success + interval if last_success else None,
        last_run_status=row["last_status"],
        last_run_at=_parse(row["last_started"]),
        progress_percent=row["last_percent"] if running else None,
        backup_complete=info.complete if info is not None else None,
        encrypted=info.encrypted if info is not None else None,
        pair_days_unused=pair_days_unused(row["paired_at"], row["pair_used_at"], now),
    )


def to_public(status: DeviceStatus) -> dict:
    """JSON-safe, the same keys for the API, MQTT state payloads and Home Assistant."""
    return {
        "udid": status.udid,
        "name": status.name,
        "model": status.model,
        "os_version": status.os_version,
        "state": status.state,
        "last_success_at": _iso(status.last_success_at),
        "next_due_at": _iso(status.next_due_at),
        "last_run_status": status.last_run_status,
        "last_run_at": _iso(status.last_run_at),
        "progress_percent": status.progress_percent,
        "backup_complete": status.backup_complete,
        "encrypted": status.encrypted,
        # Never the pair record itself, only how long it has gone unused (see module docstring).
        "pair_days_unused": status.pair_days_unused,
    }
