# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from bioseasy import db
from bioseasy import defaults as backup_defaults
from bioseasy.scheduler import Decision, DeviceView, decide, in_window, load_views

DEFAULTS = backup_defaults.GlobalDefaults(
    window_start=backup_defaults.DEFAULT_WINDOW_START,
    window_end=backup_defaults.DEFAULT_WINDOW_END,
    only_when_charging=backup_defaults.DEFAULT_ONLY_WHEN_CHARGING,
    interval_hours=backup_defaults.DEFAULT_INTERVAL_HOURS,
    overdue_days=backup_defaults.DEFAULT_OVERDUE_DAYS,
    retention=backup_defaults.RetentionPolicy(),
    free_space_threshold_gb=backup_defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB,
    notice_lead_minutes=backup_defaults.DEFAULT_NOTICE_LEAD_MINUTES,
)

BERLIN = UTC  # decide() only needs a tzinfo; UTC keeps the arithmetic in these tests obvious.
NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)  # a Tuesday noon, matches "today's date"


def _view(**overrides) -> DeviceView:
    base = dict(
        udid="udid-1",
        interval_hours=24,
        window_start="08:00",
        window_end="20:00",
        only_when_charging=False,
        overdue_days=3,
        added_at=NOW - timedelta(days=100),
        last_success_at=NOW - timedelta(hours=1),  # recent: not due by default
        last_attempt_at=None,
        last_nudge_at=None,
        last_overdue_alert_at=None,
        last_window_notice_at=None,
        running=False,
    )
    base.update(overrides)
    return DeviceView(**base)


# --- in_window -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("hhmm", "expected"),
    [
        ("21:59", False),
        ("22:00", True),  # start is inclusive
        ("23:30", True),
        ("00:00", True),
        ("05:59", True),
        ("06:00", False),  # end is exclusive
        ("12:00", False),
    ],
)
def test_in_window_crossing_midnight(hhmm, expected):
    hour, minute = (int(p) for p in hhmm.split(":"))
    now_local = datetime(2026, 9, 15, hour, minute)
    assert in_window(now_local, "22:00", "06:00") is expected


@pytest.mark.parametrize(
    ("hhmm", "expected"),
    [
        ("07:59", False),  # before start
        ("08:00", True),  # start is inclusive
        ("19:59", True),
        ("20:00", False),  # end is exclusive
    ],
)
def test_in_window_boundaries(hhmm, expected):
    hour, minute = (int(p) for p in hhmm.split(":"))
    now_local = datetime(2026, 9, 15, hour, minute)
    assert in_window(now_local, "08:00", "20:00") is expected


def test_in_window_both_none_means_never():
    assert in_window(datetime(2026, 9, 15, 12, 0), None, None) is False


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("08:00", None),
        (None, "20:00"),
    ],
)
def test_in_window_one_sided_is_malformed(start, end):
    with pytest.raises(ValueError):
        in_window(datetime(2026, 9, 15, 12, 0), start, end)


@pytest.mark.parametrize("bad", ["25:00", "12:60", "1200", "noon", "12:00:00", ""])
def test_in_window_malformed_time_raises(bad):
    with pytest.raises(ValueError):
        in_window(datetime(2026, 9, 15, 12, 0), bad, "20:00")


# --- decide ------------------------------------------------------------------------------------


def test_not_due_yet():
    d = decide(_view(last_success_at=NOW - timedelta(hours=1)), NOW, UTC, reachable=True, charging=None)
    assert d == Decision(False, False, False, d.reason)
    assert "within the interval" in d.reason


def test_due_but_outside_window():
    device = _view(last_success_at=NOW - timedelta(hours=25), window_start="22:00", window_end="23:00")
    d = decide(device, NOW, UTC, reachable=True, charging=None)  # NOW is 12:00, outside 22:00-23:00
    assert d.start_backup is False
    assert "outside the scheduled window" in d.reason


def test_charging_required_and_unknown_does_not_satisfy_it():
    device = _view(last_success_at=NOW - timedelta(hours=25), only_when_charging=True)
    unknown = decide(device, NOW, UTC, reachable=True, charging=None)
    not_charging = decide(device, NOW, UTC, reachable=True, charging=False)
    charging = decide(device, NOW, UTC, reachable=True, charging=True)
    assert unknown.start_backup is False
    assert not_charging.start_backup is False
    assert charging.start_backup is True


# --- stepped retries: window start, then +30, +60, +120 minutes -------------------------------


def test_first_attempt_fires_at_window_start():
    # window 08:00-20:00, NOW is noon: well past window start, no attempt yet this occurrence.
    device = _view(last_success_at=NOW - timedelta(hours=25), last_attempt_at=None)
    d = decide(device, NOW, UTC, reachable=True, charging=None)
    assert d.start_backup is True


@pytest.mark.parametrize(
    ("minutes_since_first_attempt", "expected"),
    [
        (5, False),  # inside the first 30-minute gap
        (29, False),
        (30, True),  # the second slot opens
    ],
)
def test_second_attempt_waits_for_the_30_minute_slot(minutes_since_first_attempt, expected):
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    now = window_start + timedelta(minutes=minutes_since_first_attempt)
    device = _view(last_success_at=window_start - timedelta(days=2), last_attempt_at=window_start)
    d = decide(device, now, UTC, reachable=True, charging=None)
    assert d.start_backup is expected


def test_third_and_fourth_attempts_follow_the_60_and_120_minute_slots():
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)

    after_second = window_start + timedelta(minutes=30)
    still_waiting = decide(
        _view(last_success_at=window_start - timedelta(days=2), last_attempt_at=after_second),
        window_start + timedelta(minutes=59),
        UTC,
        reachable=True,
        charging=None,
    )
    assert still_waiting.start_backup is False

    third_slot = decide(
        _view(last_success_at=window_start - timedelta(days=2), last_attempt_at=after_second),
        window_start + timedelta(minutes=60),
        UTC,
        reachable=True,
        charging=None,
    )
    assert third_slot.start_backup is True

    after_third = window_start + timedelta(minutes=60)
    fourth_slot = decide(
        _view(last_success_at=window_start - timedelta(days=2), last_attempt_at=after_third),
        window_start + timedelta(minutes=120),
        UTC,
        reachable=True,
        charging=None,
    )
    assert fourth_slot.start_backup is True


def test_no_attempt_after_the_final_120_minute_slot():
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    after_fourth = window_start + timedelta(minutes=120)
    d = decide(
        _view(last_success_at=window_start - timedelta(days=2), last_attempt_at=after_fourth),
        window_start + timedelta(minutes=180),  # well after the last slot, still inside the window
        UTC,
        reachable=True,
        charging=None,
    )
    assert d.start_backup is False
    assert "next scheduled attempt has not arrived" in d.reason


def test_no_attempt_when_the_step_schedule_would_land_outside_the_window():
    # window 08:00-08:20: window start's +30/+60/+120 offsets fall outside it: the window gate
    # (checked before the step schedule) blocks those, never a stray attempt past the end.
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    device = _view(
        last_success_at=window_start - timedelta(days=2),
        window_start="08:00",
        window_end="08:20",
        last_attempt_at=window_start,
    )
    d = decide(device, window_start + timedelta(minutes=30), UTC, reachable=True, charging=None)
    assert d.start_backup is False
    assert "outside the scheduled window" in d.reason


def test_previous_windows_attempt_does_not_block_a_new_window_occurrence():
    # window 08:00-20:00 crosses days: an attempt from yesterday's occurrence must not count
    # against today's window-start slot.
    window_start_today = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    last_attempt_yesterday = window_start_today - timedelta(days=1, minutes=-90)  # yesterday 09:30
    device = _view(last_success_at=window_start_today - timedelta(days=3), last_attempt_at=last_attempt_yesterday)
    d = decide(device, window_start_today, UTC, reachable=True, charging=None)
    assert d.start_backup is True


def test_no_attempt_after_success():
    # A success mid-window makes the device no longer due, so the stepped schedule cannot fire
    # again this window even though a slot is open.
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    device = _view(last_success_at=window_start + timedelta(minutes=5), last_attempt_at=window_start)
    d = decide(device, window_start + timedelta(minutes=30), UTC, reachable=True, charging=None)
    assert d.start_backup is False
    assert "within the interval" in d.reason


def test_nudge_fires_once_per_period_then_falls_silent_then_fires_again():
    # Due, but not reachable, so start_backup is always False here and only nudge is in play.
    device = _view(last_success_at=NOW - timedelta(hours=25), last_nudge_at=None)
    first = decide(device, NOW, UTC, reachable=False, charging=None)
    assert first.nudge is True

    just_nudged = _view(last_success_at=NOW - timedelta(hours=25), last_nudge_at=NOW - timedelta(hours=1))
    second = decide(just_nudged, NOW, UTC, reachable=False, charging=None)
    assert second.nudge is False

    stale_nudge = _view(last_success_at=NOW - timedelta(hours=25), last_nudge_at=NOW - timedelta(hours=25))
    third = decide(stale_nudge, NOW, UTC, reachable=False, charging=None)
    assert third.nudge is True


def test_nudge_does_not_fire_when_a_start_is_decided():
    device = _view(last_success_at=NOW - timedelta(hours=25))  # due, reachable, in window, no cooldown
    d = decide(device, NOW, UTC, reachable=True, charging=None)
    assert d.start_backup is True
    assert d.nudge is False


def test_overdue_for_a_device_that_never_backed_up():
    device = _view(last_success_at=None, added_at=NOW - timedelta(days=10), overdue_days=3, last_overdue_alert_at=None)
    d = decide(device, NOW, UTC, reachable=False, charging=None)
    assert d.overdue is True

    recently_alerted = _view(
        last_success_at=None,
        added_at=NOW - timedelta(days=10),
        overdue_days=3,
        last_overdue_alert_at=NOW - timedelta(hours=1),
    )
    quiet = decide(recently_alerted, NOW, UTC, reachable=False, charging=None)
    assert quiet.overdue is False  # at most one overdue alert per day

    alert_stale = _view(
        last_success_at=None,
        added_at=NOW - timedelta(days=10),
        overdue_days=3,
        last_overdue_alert_at=NOW - timedelta(hours=25),
    )
    again = decide(alert_stale, NOW, UTC, reachable=False, charging=None)
    assert again.overdue is True


def test_overdue_cooldown_is_independent_of_the_nudge_cooldown():
    """The bug this guards against: overdue and nudge cooldowns used to share one column
    (devices.last_nudge_at), so a device nudged more often than once a day never got its overdue
    alert at all - the nudge kept resetting the shared column before the 24h overdue cooldown
    could elapse. A recent nudge alone must not suppress the overdue alert."""
    device = _view(
        last_success_at=None,
        added_at=NOW - timedelta(days=10),
        overdue_days=3,
        last_nudge_at=NOW - timedelta(minutes=1),  # nudged moments ago
        last_overdue_alert_at=None,  # but never overdue-alerted
    )
    d = decide(device, NOW, UTC, reachable=False, charging=None)
    assert d.overdue is True


def test_overdue_alert_survives_a_nudge_interval_shorter_than_a_day():
    """Simulation, in the style of ticker.tick: repeatedly calls decide() and feeds each
    decision's write-back into the next view exactly as ticker.py does (only last_nudge_at on a
    nudge, only last_overdue_alert_at on an overdue alert - never both from one column). A device
    that never backs up, overdue_days=3, interval_hours=6 (so the nudge fires every tick), ticked
    every 6 hours over 12 days: the overdue alert must still fire roughly once every 24 hours,
    not zero times. Before the fix, one shared column meant the nudge - firing every tick - kept
    resetting the same cooldown the overdue alert used, so overdue never fired at all."""
    start = NOW
    step = timedelta(hours=6)
    ticks = 48  # 12 days
    last_nudge_at: datetime | None = None
    last_overdue_alert_at: datetime | None = None
    overdue_count = 0
    nudge_count = 0
    for i in range(ticks):
        now = start + step * i
        device = _view(
            last_success_at=None,
            added_at=start - timedelta(days=100),
            interval_hours=6,
            overdue_days=3,
            last_nudge_at=last_nudge_at,
            last_overdue_alert_at=last_overdue_alert_at,
        )
        d = decide(device, now, UTC, reachable=False, charging=None)
        if d.overdue:
            overdue_count += 1
            last_overdue_alert_at = now
        if d.nudge:
            nudge_count += 1
            last_nudge_at = now

    assert nudge_count == ticks  # nudges every tick: interval_hours=6 equals the tick step
    # 12 days at one overdue alert per ~24h: 9 in the failing simulation this test reproduces
    # (48 ticks / 24h-step counted from a device already long overdue), never zero.
    assert overdue_count >= 9
    assert overdue_count > 0


def test_running_device_never_starts_nudges_or_alerts():
    device = _view(last_success_at=NOW - timedelta(days=10), added_at=NOW - timedelta(days=100), running=True)
    d = decide(device, NOW, UTC, reachable=True, charging=True)
    assert d == Decision(False, False, False, d.reason)
    assert "already running" in d.reason


# --- pre-attempt notice -----------------------------------------------------------------------


def test_notice_fires_inside_the_lead_time_before_window_start():
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    device = _view(last_success_at=window_start - timedelta(days=2))  # due
    too_early = decide(
        device, window_start - timedelta(minutes=6), UTC, reachable=True, charging=None, notice_lead_minutes=5
    )
    assert too_early.notice is False

    in_band = decide(
        device, window_start - timedelta(minutes=5), UTC, reachable=True, charging=None, notice_lead_minutes=5
    )
    assert in_band.notice is True

    at_start = decide(device, window_start, UTC, reachable=True, charging=None, notice_lead_minutes=5)
    assert at_start.notice is False  # inside the window already: the attempt itself takes over


def test_notice_fires_once_per_window_then_falls_silent():
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    device = _view(last_success_at=window_start - timedelta(days=2))
    first = decide(
        device, window_start - timedelta(minutes=3), UTC, reachable=True, charging=None, notice_lead_minutes=5
    )
    assert first.notice is True

    already_sent = _view(
        last_success_at=window_start - timedelta(days=2),
        last_window_notice_at=window_start,  # identity stamp: the notice for *this* window went out
    )
    second = decide(
        already_sent, window_start - timedelta(minutes=1), UTC, reachable=True, charging=None, notice_lead_minutes=5
    )
    assert second.notice is False


def test_notice_does_not_fire_once_a_success_already_covers_the_interval():
    window_start = NOW.replace(hour=8, minute=0, second=0, microsecond=0)
    device = _view(last_success_at=NOW - timedelta(hours=1))  # recent success, not due
    d = decide(device, window_start - timedelta(minutes=2), UTC, reachable=True, charging=None, notice_lead_minutes=5)
    assert d.notice is False


def test_notice_never_fires_for_a_device_without_a_window():
    device = _view(last_success_at=NOW - timedelta(hours=25), window_start=None, window_end=None)
    d = decide(device, NOW, UTC, reachable=False, charging=None, notice_lead_minutes=5)
    assert d.notice is False


# --- load_views ----------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as c:
        db.migrate(c)
        yield c


def _insert_device(conn, udid, **overrides):
    columns = dict(
        udid=udid,
        name="Test phone",
        interval_hours=24,
        window_start="08:00",
        window_end="20:00",
        only_when_charging=0,
        overdue_days=3,
        last_nudge_at=None,
        created_at="2026-06-01T00:00:00Z",
    )
    columns.update(overrides)
    # Column list is a fixed literal, never built from `columns`, so this is not a SQL
    # injection vector despite the values coming from a dict.
    conn.execute(
        """
        INSERT INTO devices (
            udid, name, interval_hours, window_start, window_end,
            only_when_charging, overdue_days, last_nudge_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            columns["udid"],
            columns["name"],
            columns["interval_hours"],
            columns["window_start"],
            columns["window_end"],
            columns["only_when_charging"],
            columns["overdue_days"],
            columns["last_nudge_at"],
            columns["created_at"],
        ),
    )


def _insert_run(conn, udid, status, started_at, finished_at=None):
    conn.execute(
        "INSERT INTO runs (udid, trigger, started_at, finished_at, status) VALUES (?, 'manual', ?, ?, ?)",
        (udid, started_at, finished_at, status),
    )


def test_load_views_has_no_n_plus_one_and_parses_timestamps(conn):
    _insert_device(conn, "udid-a", created_at="2026-06-01T00:00:00Z")
    _insert_run(conn, "udid-a", "failed", "2026-09-01T10:00:00Z", "2026-09-01T10:05:00Z")
    _insert_run(conn, "udid-a", "succeeded", "2026-09-10T10:00:00Z", "2026-09-10T10:20:00Z")

    _insert_device(conn, "udid-b", created_at="2026-06-02T00:00:00Z")
    # udid-b never succeeded and never ran: last_success_at and last_attempt_at stay None.

    views = {v.udid: v for v in load_views(conn, running_udids={"udid-b"}, defaults=DEFAULTS)}

    assert set(views) == {"udid-a", "udid-b"}

    a = views["udid-a"]
    assert a.last_success_at == datetime(2026, 9, 10, 10, 20, tzinfo=UTC)  # succeeded run's finish, not start
    assert a.last_attempt_at == datetime(2026, 9, 10, 10, 0, tzinfo=UTC)  # latest run of any status
    assert a.added_at == datetime(2026, 6, 1, tzinfo=UTC)
    assert a.running is False

    b = views["udid-b"]
    assert b.last_success_at is None
    assert b.last_attempt_at is None
    assert b.running is True


def test_load_views_query_count_stays_constant_with_more_devices(conn):
    # A real N+1 would issue one query per device; count statements sqlite actually executes
    # instead of timing, so the test is fast and deterministic. sqlite3.Connection.execute is
    # a read-only attribute (cannot be monkeypatched), but set_trace_callback is the module's
    # own hook for exactly this.
    for i in range(5):
        _insert_device(conn, f"udid-{i}", created_at="2026-06-01T00:00:00Z")
        _insert_run(conn, f"udid-{i}", "succeeded", "2026-09-01T00:00:00Z", "2026-09-01T00:10:00Z")

    executed = []
    conn.set_trace_callback(executed.append)
    try:
        views = load_views(conn, running_udids=set(), defaults=DEFAULTS)
    finally:
        conn.set_trace_callback(None)

    assert len(views) == 5
    assert len(executed) == 1
