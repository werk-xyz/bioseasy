# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure decision logic for scheduled backups: no threads, no APScheduler, no web code.

iOS asks for the passcode on every backup, so a scheduled start only proposes a backup the
owner still has to confirm on the device; it must not fire outside the device's own window, and
it must not spam a nudge or an overdue alert more than once per period (docs/concept.md,
"Triggers and the passcode"). Keeping the decision here, separate from
whatever timer drives it, makes every rule testable without a running scheduler or a database.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta, tzinfo

from . import defaults as backup_defaults

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Stepped retry schedule within one window occurrence: first attempt at window start (offset 0),
# then at +30, +60 and +120 minutes if the previous one did not succeed. Replaces the old flat
# 30-minute cooldown outright - a single mechanism, not two: once `due` goes False after a success (see
# `decide` below), the stepped schedule stops mattering on its own, no separate "already
# succeeded" check needed.
_RETRY_OFFSETS: tuple[timedelta, ...] = (
    timedelta(minutes=0),
    timedelta(minutes=30),
    timedelta(minutes=60),
    timedelta(minutes=120),
)
_OVERDUE_ALERT_COOLDOWN = timedelta(hours=24)


def _parse_hhmm(value: str) -> time:
    parts = value.split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise ValueError(f"malformed time {value!r}, expected 'HH:MM'")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"malformed time {value!r}, expected 'HH:MM'")
    return time(hour, minute)


def in_window(now_local: datetime, start: str | None, end: str | None) -> bool:
    """Whether now_local's clock time falls inside the device's scheduling window.

    Both None means the device never starts on a schedule. Exactly one of them set is a
    malformed configuration, the same as an unparsable time, so both raise ValueError rather
    than guessing which half was meant.
    """
    if start is None and end is None:
        return False
    if start is None or end is None:
        raise ValueError("window_start and window_end must both be set or both be None")
    start_t = _parse_hhmm(start)
    end_t = _parse_hhmm(end)
    now_t = now_local.time()
    if start_t == end_t:
        # A zero-width window is not a useful "never" (that is spelled with two Nones); read
        # equal bounds as the whole day so a device set up this way still gets scheduled.
        return True
    if start_t < end_t:
        return start_t <= now_t < end_t
    # Crosses midnight, e.g. 22:00-06:00: inside from start to midnight, then midnight to end.
    return now_t >= start_t or now_t < end_t


def _last_window_start_at_or_before(now_local: datetime, start: str) -> datetime:
    """The instant the current (or most recent) window occurrence began: today's `start`
    clock-time, or yesterday's if today's has not happened yet. Works for a same-day window, a
    midnight-crossing one, and the zero-width "whole day" case alike, since none of them need
    anything about `end` to answer "when did the occurrence covering now begin" - only `in_window`
    needs the pair."""
    start_t = _parse_hhmm(start)
    candidate = now_local.replace(hour=start_t.hour, minute=start_t.minute, second=0, microsecond=0)
    if candidate > now_local:
        candidate -= timedelta(days=1)
    return candidate


def _next_window_start_after_or_at(now_local: datetime, start: str) -> datetime:
    """The instant the next window occurrence begins: today's `start` clock-time, or tomorrow's
    if today's has already passed. The mirror image of `_last_window_start_at_or_before`, used to
    find how many minutes remain until a not-yet-started window, for the pre-attempt notice."""
    start_t = _parse_hhmm(start)
    candidate = now_local.replace(hour=start_t.hour, minute=start_t.minute, second=0, microsecond=0)
    if candidate < now_local:
        candidate += timedelta(days=1)
    return candidate


def window_notice_identity(window_start: str, now_utc: datetime, tz: tzinfo) -> datetime:
    """The UTC instant identifying the next (or current, if now is exactly at its start) window
    occurrence - used both by `decide` to judge whether the pre-attempt notice for it has already
    gone out, and by the caller to stamp devices.last_window_notice_at once it has."""
    now_local = now_utc.astimezone(tz)
    return _next_window_start_after_or_at(now_local, window_start).astimezone(UTC)


def _attempt_allowed(now_local: datetime, window_start_at: datetime, last_attempt_local: datetime | None) -> bool:
    """Whether the stepped retry schedule permits a start attempt right now, given the current
    window occurrence's own start instant and the device's last attempt (already converted to the
    device's local time zone, or None)."""
    if last_attempt_local is None or last_attempt_local < window_start_at:
        return True  # nothing attempted yet in this window occurrence: the window-start slot.
    elapsed_at_last_attempt = last_attempt_local - window_start_at
    for offset in _RETRY_OFFSETS:
        if offset > elapsed_at_last_attempt:
            return now_local >= window_start_at + offset
    return False  # last attempt was already at or past the final (120 min) slot: no more retries.


@dataclass(frozen=True)
class DeviceView:
    """Everything decide() needs about one device, already resolved from the database."""

    udid: str
    interval_hours: int
    window_start: str | None
    window_end: str | None
    only_when_charging: bool
    overdue_days: int
    added_at: datetime | None
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    last_nudge_at: datetime | None
    last_overdue_alert_at: datetime | None
    last_window_notice_at: datetime | None
    running: bool


@dataclass(frozen=True)
class Decision:
    start_backup: bool
    nudge: bool
    overdue: bool
    reason: str
    notice: bool = False


def _stale(last: datetime | None, now_utc: datetime, threshold: timedelta) -> bool:
    """True if `last` is unset or old enough that a new alert is allowed."""
    return last is None or now_utc - last >= threshold


def decide(
    device: DeviceView,
    now_utc: datetime,
    tz: tzinfo,
    reachable: bool,
    charging: bool | None,
    notice_lead_minutes: int = 0,
) -> Decision:
    """Decide whether to start a backup, send a nudge, raise an overdue alert, or send the
    pre-attempt notice, right now.

    now_utc must be aware and in UTC; tz is the device owner's local time zone, used only to
    evaluate the scheduling window. charging is None when the engine cannot tell; per
    docs/concept.md an unknown charging state does not satisfy "only while charging".
    notice_lead_minutes is the global default (defaults.DEFAULT_NOTICE_LEAD_MINUTES), not a
    per-device setting, so callers pass it in rather than it living on DeviceView.
    """
    if device.running:
        return Decision(False, False, False, "A backup is already running for this device.")

    due = device.last_success_at is None or now_utc - device.last_success_at >= timedelta(hours=device.interval_hours)

    now_local = now_utc.astimezone(tz)
    inside_window = in_window(now_local, device.window_start, device.window_end)
    charging_ok = not device.only_when_charging or charging is True

    attempt_allowed = False
    if inside_window:
        window_start_at = _last_window_start_at_or_before(now_local, device.window_start)
        last_attempt_local = device.last_attempt_at.astimezone(tz) if device.last_attempt_at is not None else None
        attempt_allowed = _attempt_allowed(now_local, window_start_at, last_attempt_local)

    start_backup = due and reachable and inside_window and charging_ok and attempt_allowed

    nudge_allowed = _stale(device.last_nudge_at, now_utc, timedelta(hours=device.interval_hours))
    nudge = due and not start_backup and nudge_allowed

    if device.last_success_at is not None:
        overdue_span = now_utc - device.last_success_at >= timedelta(days=device.overdue_days)
    elif device.added_at is not None:
        overdue_span = now_utc - device.added_at >= timedelta(days=device.overdue_days)
    else:
        # Neither a success nor an added_at to measure from: cannot establish overdue, and a
        # false alert is worse than a missed one here (devices.created_at always has a default
        # in practice, so this is a defensive fallback, not the expected path).
        overdue_span = False
    overdue_allowed = _stale(device.last_overdue_alert_at, now_utc, _OVERDUE_ALERT_COOLDOWN)
    overdue = overdue_span and overdue_allowed

    notice = False
    if due and not inside_window and device.window_start is not None and device.window_end is not None:
        next_start_utc = window_notice_identity(device.window_start, now_utc, tz)
        minutes_until = (next_start_utc - now_utc).total_seconds() / 60
        if 0 <= minutes_until <= notice_lead_minutes:
            notice = device.last_window_notice_at != next_start_utc

    if not due:
        reason = "Last backup is within the interval; nothing due."
    elif start_backup:
        reason = "Due, reachable, inside the window and charging requirement met; starting the backup."
    elif not reachable:
        reason = "Due, but the device is not reachable."
    elif not inside_window:
        reason = "Due, but outside the scheduled window."
    elif not attempt_allowed:
        reason = "Due, inside the window, but the next scheduled attempt has not arrived yet."
    elif not charging_ok:
        reason = "Due, but charging is required and the device is not confirmed to be charging."
    else:
        reason = "Due, but blocked."
    if overdue:
        reason += " Overdue alert is due."
    if nudge:
        reason += " Sending a reminder."
    if notice:
        reason += " Sending the pre-attempt notice."
    return Decision(start_backup, nudge, overdue, reason, notice)


def _parse_utc(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=UTC)


def load_views(
    conn: sqlite3.Connection, running_udids: set[str], defaults: backup_defaults.GlobalDefaults
) -> list[DeviceView]:
    """One row per device, with its latest succeeded run and latest run of any status.

    A single query with two aggregated joins avoids one round trip per device (N+1); running
    state is not in the database at all, since jobs.JobManager keeps it in memory only. Every
    device-specific field goes through defaults.resolve_device, the one function that layers a
    device's own overrides onto `defaults` - the same one status.py and the web UI use.
    """
    rows = conn.execute(
        """
        SELECT
            d.*,
            last_success.at AS last_success_at,
            last_attempt.at AS last_attempt_at
        FROM devices d
        LEFT JOIN (
            SELECT udid, MAX(finished_at) AS at FROM runs WHERE status = 'succeeded' GROUP BY udid
        ) last_success ON last_success.udid = d.udid
        LEFT JOIN (
            SELECT udid, MAX(started_at) AS at FROM runs GROUP BY udid
        ) last_attempt ON last_attempt.udid = d.udid
        """
    ).fetchall()
    views = []
    for row in rows:
        effective = backup_defaults.resolve_device(row, defaults)
        views.append(
            DeviceView(
                udid=row["udid"],
                interval_hours=effective.interval_hours,
                window_start=effective.window_start,
                window_end=effective.window_end,
                only_when_charging=effective.only_when_charging,
                overdue_days=effective.overdue_days,
                added_at=_parse_utc(row["created_at"]),
                last_success_at=_parse_utc(row["last_success_at"]),
                last_attempt_at=_parse_utc(row["last_attempt_at"]),
                last_nudge_at=_parse_utc(row["last_nudge_at"]),
                last_overdue_alert_at=_parse_utc(row["last_overdue_alert_at"]),
                last_window_notice_at=_parse_utc(row["last_window_notice_at"]),
                running=row["udid"] in running_udids,
            )
        )
    return views
