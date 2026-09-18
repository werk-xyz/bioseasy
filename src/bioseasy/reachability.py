# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-device reachability history for the device page: when it was last seen, and how often
over the last 7 days.

Reads the `sightings` table (one row per tick that found the device) and the `ticks` table (one
row per completed tick, regardless of what it found); both are pruned after 30 days in ticker.py
(SIGHTINGS_KEPT, TICKS_KEPT), so a 7-day window always fits inside what is kept. Both the "seen"
and the "checks" figures are exact counts, not estimates: `ticks` used to not exist, so "checks"
was derived from the configured tick interval (settings.schedule_minutes) instead, which was
wrong whenever the interval changed mid-window or a tick was skipped outright (a worker restart,
a missed tick_lease).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

DAYS = 7
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class DayReachability:
    day: date
    seen: int
    checks: int

    @property
    def share_text(self) -> str:
        unit = "check" if self.checks == 1 else "checks"
        return f"{self.seen} of {self.checks} {unit}"


@dataclass(frozen=True)
class Reachability:
    last_seen_at: datetime | None
    last_transport: str | None
    daily: list[DayReachability]  # oldest to newest, DAYS entries, today last


def _checks_in(conn: sqlite3.Connection, day_start: datetime, day_end: datetime) -> int:
    """Exact number of completed ticks recorded between day_start and day_end (ticker.py)."""
    if day_end <= day_start:
        return 0
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM ticks WHERE tick_at >= ? AND tick_at < ?",
        (_iso(day_start), _iso(day_end)),
    ).fetchone()
    return row["n"]


def for_device(conn: sqlite3.Connection, udid: str, now: datetime) -> Reachability:
    """Reachability for one device, scoped to its own sightings and bounded to the last DAYS
    calendar days (UTC): the query never reads another device's rows and never reaches further
    back than that window."""
    last = conn.execute(
        "SELECT seen_at, transport FROM sightings WHERE udid = ? ORDER BY seen_at DESC LIMIT 1", (udid,)
    ).fetchone()
    last_seen_at = _parse(last["seen_at"]) if last else None
    last_transport = last["transport"] if last else None

    today = now.astimezone(UTC).date()
    first_day = today - timedelta(days=DAYS - 1)
    window_start = datetime.combine(first_day, time.min, tzinfo=UTC)
    rows = conn.execute(
        "SELECT seen_at FROM sightings WHERE udid = ? AND seen_at >= ? ORDER BY seen_at",
        (udid, _iso(window_start)),
    ).fetchall()
    seen_by_day: dict[date, int] = {}
    for row in rows:
        day = _parse(row["seen_at"]).date()
        seen_by_day[day] = seen_by_day.get(day, 0) + 1

    daily = []
    for offset in range(DAYS):
        day = first_day + timedelta(days=offset)
        day_start = datetime.combine(day, time.min, tzinfo=UTC)
        day_end = min(day_start + timedelta(days=1), now)
        daily.append(
            DayReachability(
                day=day,
                seen=seen_by_day.get(day, 0),
                checks=_checks_in(conn, day_start, day_end),
            )
        )

    return Reachability(last_seen_at=last_seen_at, last_transport=last_transport, daily=daily)
