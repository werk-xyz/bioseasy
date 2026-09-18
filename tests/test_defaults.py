# SPDX-License-Identifier: GPL-3.0-or-later
"""defaults.resolve_device is the one function scheduler.py, status.py, jobs.py (retention) and
the web UI all resolve a device's effective backup settings through; these tests are its only
direct coverage, so a regression there would otherwise only show up as a scheduler/status/jobs
symptom several layers away."""

from contextlib import closing

import pytest

from bioseasy import db, defaults
from bioseasy.snapshots import RetentionPolicy


@pytest.fixture
def conn(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as c:
        db.migrate(c)
        yield c


def test_get_global_defaults_falls_back_to_constants_when_nothing_saved(conn):
    values = defaults.get_global_defaults(conn)
    assert values.window_start == defaults.DEFAULT_WINDOW_START
    assert values.window_end == defaults.DEFAULT_WINDOW_END
    assert values.only_when_charging is defaults.DEFAULT_ONLY_WHEN_CHARGING
    assert values.interval_hours == defaults.DEFAULT_INTERVAL_HOURS
    assert values.overdue_days == defaults.DEFAULT_OVERDUE_DAYS
    assert values.free_space_threshold_gb == defaults.DEFAULT_FREE_SPACE_THRESHOLD_GB
    assert values.retention == RetentionPolicy(
        keep_last=defaults.DEFAULT_KEEP_LAST,
        keep_daily=defaults.DEFAULT_KEEP_DAILY,
        keep_weekly=defaults.DEFAULT_KEEP_WEEKLY,
        keep_monthly=defaults.DEFAULT_KEEP_MONTHLY,
        keep_yearly=defaults.DEFAULT_KEEP_YEARLY,
    )


def test_set_then_get_round_trips_every_field(conn):
    written = defaults.GlobalDefaults(
        window_start="01:00",
        window_end="04:30",
        only_when_charging=False,
        interval_hours=48,
        overdue_days=14,
        retention=RetentionPolicy(keep_last=1, keep_daily=2, keep_weekly=3, keep_monthly=4, keep_yearly=5),
        free_space_threshold_gb=25,
        notice_lead_minutes=10,
    )
    defaults.set_global_defaults(conn, written)
    assert defaults.get_global_defaults(conn) == written


def test_set_global_defaults_is_visible_on_a_fresh_read_after_a_partial_change(conn):
    # A field not touched by a second write must still read back from the first write, not
    # silently reset to the hard-coded constant - the settings table is read field by field.
    first = defaults.GlobalDefaults(
        window_start="03:00",
        window_end="05:00",
        only_when_charging=True,
        interval_hours=12,
        overdue_days=9,
        retention=RetentionPolicy(keep_last=9, keep_daily=1, keep_weekly=1, keep_monthly=1, keep_yearly=1),
        free_space_threshold_gb=15,
        notice_lead_minutes=5,
    )
    defaults.set_global_defaults(conn, first)
    second = defaults.get_global_defaults(conn)
    second_written = defaults.GlobalDefaults(**{**second.__dict__, "interval_hours": 99})
    defaults.set_global_defaults(conn, second_written)
    result = defaults.get_global_defaults(conn)
    assert result.interval_hours == 99
    assert result.window_start == "03:00"  # untouched by the second write, still round-trips


def _device_row(conn, **overrides):
    columns = dict(
        udid="udid-1",
        interval_hours=None,
        window_start=None,
        window_end=None,
        only_when_charging=None,
        overdue_days=None,
        keep_last=None,
        keep_daily=None,
        keep_weekly=None,
        keep_monthly=None,
        keep_yearly=None,
    )
    columns.update(overrides)
    conn.execute(
        "INSERT INTO devices (udid, interval_hours, window_start, window_end, only_when_charging, overdue_days, "
        "keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        tuple(columns.values()),
    )
    return conn.execute("SELECT * FROM devices WHERE udid = ?", (columns["udid"],)).fetchone()


def test_resolve_device_with_no_overrides_uses_every_global_default(conn):
    row = _device_row(conn)
    values = defaults.get_global_defaults(conn)
    effective = defaults.resolve_device(row, values)
    assert effective.interval_hours == values.interval_hours
    assert effective.window_start == values.window_start
    assert effective.window_end == values.window_end
    assert effective.only_when_charging == values.only_when_charging
    assert effective.overdue_days == values.overdue_days
    assert effective.retention == values.retention


def test_resolve_device_overrides_are_independent_per_field(conn):
    # A device can override just one field (its window) while every other field still inherits -
    # not an all-or-nothing group toggle.
    row = _device_row(conn, window_start="10:00", window_end="12:00", only_when_charging=1)
    values = defaults.get_global_defaults(conn)
    effective = defaults.resolve_device(row, values)
    assert effective.window_start == "10:00"
    assert effective.window_end == "12:00"
    assert effective.only_when_charging is True
    assert effective.interval_hours == values.interval_hours  # not overridden: still the default
    assert effective.overdue_days == values.overdue_days


def test_resolve_device_retention_field_is_independent_too(conn):
    row = _device_row(conn, keep_last=1, keep_yearly=9)
    values = defaults.get_global_defaults(conn)
    effective = defaults.resolve_device(row, values)
    assert effective.retention.keep_last == 1
    assert effective.retention.keep_yearly == 9
    assert effective.retention.keep_daily == values.retention.keep_daily  # inherited
