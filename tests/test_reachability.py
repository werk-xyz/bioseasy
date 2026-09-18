# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from bioseasy import db, reachability

UDID = "00008110-000A1B2C3D4E5F60"
OTHER_UDID = "00008103-001122334455667A"


@pytest.fixture
def connect(tmp_path):
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (UDID, "Demo iPhone"))
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (OTHER_UDID, "Demo iPad"))
    return lambda: db.connect(path)


def insert(connect, udid, seen_at, transport="wifi"):
    with closing(connect()) as conn:
        conn.execute("INSERT INTO sightings (udid, seen_at, transport) VALUES (?, ?, ?)", (udid, seen_at, transport))


def tick(connect, tick_at):
    with closing(connect()) as conn:
        conn.execute("INSERT INTO ticks (tick_at) VALUES (?)", (tick_at,))


def hourly_ticks(connect, day: str, hours: int) -> None:
    """Plant `hours` ticks an hour apart starting at `day`T00:00:00Z, the way a real schedule
    ticking once an hour would have recorded them."""
    for h in range(hours):
        tick(connect, f"{day}T{h:02d}:00:00Z")


def test_never_seen_device_has_no_last_seen_and_zero_daily_counts(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    assert result.last_seen_at is None
    assert result.last_transport is None
    assert len(result.daily) == 7
    assert all(d.seen == 0 for d in result.daily)
    assert result.daily[-1].day == now.date()


def test_last_seen_reports_the_most_recent_sighting_and_its_transport(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    insert(connect, UDID, "2026-09-14T08:00:00Z", "usb")
    insert(connect, UDID, "2026-09-15T09:30:00Z", "wifi")
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    assert result.last_seen_at == datetime(2026, 9, 15, 9, 30, tzinfo=UTC)
    assert result.last_transport == "wifi"


def test_daily_counts_split_correctly_across_a_day_boundary(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    # Two sightings just before midnight (the 14th), one just after (the 15th).
    insert(connect, UDID, "2026-09-14T23:00:00Z")
    insert(connect, UDID, "2026-09-14T23:30:00Z")
    insert(connect, UDID, "2026-09-15T00:15:00Z")
    hourly_ticks(connect, "2026-09-14", 24)  # a full past day at one tick/hour
    hourly_ticks(connect, "2026-09-15", 12)  # only up to "now" (12:00) so far today
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    by_day = {d.day.isoformat(): d for d in result.daily}
    assert by_day["2026-09-14"].seen == 2
    assert by_day["2026-09-14"].checks == 24
    assert by_day["2026-09-15"].seen == 1
    assert by_day["2026-09-15"].checks == 12
    assert by_day["2026-09-15"].share_text == "1 of 12 checks"


def test_window_is_bounded_to_the_last_seven_days(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    insert(connect, UDID, "2026-09-01T00:00:00Z")  # well outside the 7-day window
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    assert all(d.seen == 0 for d in result.daily)
    assert result.daily[0].day == now.date() - timedelta(days=6)


def test_query_is_scoped_to_the_one_device(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    insert(connect, UDID, "2026-09-15T08:00:00Z")
    insert(connect, OTHER_UDID, "2026-09-15T09:00:00Z")
    insert(connect, OTHER_UDID, "2026-09-15T10:00:00Z")
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    today = next(d for d in result.daily if d.day == now.date())
    assert today.seen == 1  # only UDID's own sighting, not OTHER_UDID's two


def test_no_ticks_recorded_reports_zero_checks(connect):
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    insert(connect, UDID, "2026-09-15T08:00:00Z")
    with closing(connect()) as conn:
        result = reachability.for_device(conn, UDID, now)
    today = next(d for d in result.daily if d.day == now.date())
    assert today.checks == 0
    assert today.seen == 1
    assert today.share_text == "1 of 0 checks"


def test_checks_count_is_shared_across_devices(connect):
    """ticks has no udid column: every device on the same server sees the same tick count for a
    given day, only "seen" is per device."""
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    hourly_ticks(connect, "2026-09-15", 5)
    with closing(connect()) as conn:
        a = reachability.for_device(conn, UDID, now)
        b = reachability.for_device(conn, OTHER_UDID, now)
    today_a = next(d for d in a.daily if d.day == now.date())
    today_b = next(d for d in b.daily if d.day == now.date())
    assert today_a.checks == today_b.checks == 5
