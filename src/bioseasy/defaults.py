# SPDX-License-Identifier: GPL-3.0-or-later
"""Global backup defaults: admin-configurable on the web UI Settings page, DB-backed (not
compose/env), each overridable per device.

A device's own column is NULL to inherit the matching global default; `resolve_device` is the
one function that layers a device row onto the global defaults, and every caller that needs a
device's effective backup behaviour - scheduler.py (due/window/charging/overdue), status.py (the
dashboard state), jobs.py (retention) and the web UI (device_settings.html's placeholders) - goes
through it instead of re-implementing the NULL-means-inherit rule.

All the actual default values live in one block below, on purpose: the window default was
revised once already, from an overnight placeholder (02:00-05:00) to 20:00-23:00, once research
(iMazing's docs, libimobiledevice#1380/#1691, and a real iPad) confirmed that since iOS 16.1 every
backup - locked device or not - asks for the passcode on the device, so a window while the owner
sleeps would never actually run. Keeping every default together makes a future revision a
one-place edit.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import db
from .snapshots import RETENTION_FIELDS, RetentionPolicy, resolve_policy

# --- defaults, one block ------------------------------------------------------------------------

DEFAULT_WINDOW_START = "20:00"
DEFAULT_WINDOW_END = "23:00"
DEFAULT_ONLY_WHEN_CHARGING = True
DEFAULT_INTERVAL_HOURS = 24
DEFAULT_OVERDUE_DAYS = 7
DEFAULT_KEEP_LAST = 3
DEFAULT_KEEP_DAILY = 7
DEFAULT_KEEP_WEEKLY = 4
DEFAULT_KEEP_MONTHLY = 6
DEFAULT_KEEP_YEARLY = 0
DEFAULT_FREE_SPACE_THRESHOLD_GB = 10
# Minutes before a window's first scheduled attempt that the pre-attempt notice goes out to the
# device owner's connectors ("put it on the charger, unlock it, wait for the passcode prompt").
# Global only, no per-device override: admin-editable on the Settings page alongside the other
# defaults.
DEFAULT_NOTICE_LEAD_MINUTES = 5

# settings.key for each field, all under one prefix so they sort and grep together.
_KEY_PREFIX = "backup_default_"
_SCALAR_KEYS = {
    "window_start": f"{_KEY_PREFIX}window_start",
    "window_end": f"{_KEY_PREFIX}window_end",
    "only_when_charging": f"{_KEY_PREFIX}only_when_charging",
    "interval_hours": f"{_KEY_PREFIX}interval_hours",
    "overdue_days": f"{_KEY_PREFIX}overdue_days",
    "free_space_threshold_gb": f"{_KEY_PREFIX}free_space_threshold_gb",
    "notice_lead_minutes": f"{_KEY_PREFIX}notice_lead_minutes",
}
_RETENTION_KEYS = {field: f"{_KEY_PREFIX}{field}" for field in RETENTION_FIELDS}


@dataclass(frozen=True)
class GlobalDefaults:
    window_start: str
    window_end: str
    only_when_charging: bool
    interval_hours: int
    overdue_days: int
    retention: RetentionPolicy
    free_space_threshold_gb: int
    notice_lead_minutes: int

    @property
    def free_space_threshold_bytes(self) -> int:
        return self.free_space_threshold_gb * 2**30


@dataclass(frozen=True)
class EffectiveDevice:
    """One device's backup behaviour after layering its own overrides onto the global defaults -
    everything scheduler.decide, status._status and the retention/backup path need."""

    interval_hours: int
    window_start: str
    window_end: str
    only_when_charging: bool
    overdue_days: int
    retention: RetentionPolicy


def get_global_defaults(conn: sqlite3.Connection) -> GlobalDefaults:
    def get_str(field: str, fallback: str) -> str:
        return db.get_setting(conn, _SCALAR_KEYS[field], fallback)

    def get_int(field: str, fallback: int) -> int:
        raw = db.get_setting(conn, _SCALAR_KEYS[field])
        if raw is None:
            return fallback
        try:
            return int(raw)
        except ValueError:
            return fallback

    def get_bool(field: str, fallback: bool) -> bool:
        raw = db.get_setting(conn, _SCALAR_KEYS[field])
        return fallback if raw is None else raw == "1"

    def get_retention_int(field: str, fallback: int) -> int:
        raw = db.get_setting(conn, _RETENTION_KEYS[field])
        if raw is None:
            return fallback
        try:
            return int(raw)
        except ValueError:
            return fallback

    retention = RetentionPolicy(
        keep_last=get_retention_int("keep_last", DEFAULT_KEEP_LAST),
        keep_daily=get_retention_int("keep_daily", DEFAULT_KEEP_DAILY),
        keep_weekly=get_retention_int("keep_weekly", DEFAULT_KEEP_WEEKLY),
        keep_monthly=get_retention_int("keep_monthly", DEFAULT_KEEP_MONTHLY),
        keep_yearly=get_retention_int("keep_yearly", DEFAULT_KEEP_YEARLY),
    )
    return GlobalDefaults(
        window_start=get_str("window_start", DEFAULT_WINDOW_START),
        window_end=get_str("window_end", DEFAULT_WINDOW_END),
        only_when_charging=get_bool("only_when_charging", DEFAULT_ONLY_WHEN_CHARGING),
        interval_hours=get_int("interval_hours", DEFAULT_INTERVAL_HOURS),
        overdue_days=get_int("overdue_days", DEFAULT_OVERDUE_DAYS),
        retention=retention,
        free_space_threshold_gb=get_int("free_space_threshold_gb", DEFAULT_FREE_SPACE_THRESHOLD_GB),
        notice_lead_minutes=get_int("notice_lead_minutes", DEFAULT_NOTICE_LEAD_MINUTES),
    )


def set_global_defaults(conn: sqlite3.Connection, values: GlobalDefaults) -> None:
    db.set_setting(conn, _SCALAR_KEYS["window_start"], values.window_start)
    db.set_setting(conn, _SCALAR_KEYS["window_end"], values.window_end)
    db.set_setting(conn, _SCALAR_KEYS["only_when_charging"], "1" if values.only_when_charging else "0")
    db.set_setting(conn, _SCALAR_KEYS["interval_hours"], str(values.interval_hours))
    db.set_setting(conn, _SCALAR_KEYS["overdue_days"], str(values.overdue_days))
    db.set_setting(conn, _SCALAR_KEYS["free_space_threshold_gb"], str(values.free_space_threshold_gb))
    db.set_setting(conn, _SCALAR_KEYS["notice_lead_minutes"], str(values.notice_lead_minutes))
    for field in RETENTION_FIELDS:
        db.set_setting(conn, _RETENTION_KEYS[field], str(getattr(values.retention, field)))


def resolve_device(device: sqlite3.Row, defaults: GlobalDefaults) -> EffectiveDevice:
    """The one function that resolves a device's effective backup settings.

    Every one of the five scalar fields, and each of the five retention fields, uses the device's
    own value when set and the matching global default when NULL - never a group toggle, so a
    device can override just its window while still inheriting the default interval, say.
    """
    return EffectiveDevice(
        interval_hours=device["interval_hours"] if device["interval_hours"] is not None else defaults.interval_hours,
        window_start=device["window_start"] if device["window_start"] is not None else defaults.window_start,
        window_end=device["window_end"] if device["window_end"] is not None else defaults.window_end,
        only_when_charging=(
            bool(device["only_when_charging"])
            if device["only_when_charging"] is not None
            else defaults.only_when_charging
        ),
        overdue_days=device["overdue_days"] if device["overdue_days"] is not None else defaults.overdue_days,
        retention=resolve_policy({f: device[f] for f in RETENTION_FIELDS}, defaults.retention),
    )
