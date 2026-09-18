# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from bioseasy import db
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.ticker import Ticker

PHONE = DEMO_DEVICES[0]
NOW = datetime(2026, 9, 15, 3, 0, tzinfo=UTC)


class FakeJobs:
    def __init__(self):
        self.started = []

    def running(self):
        return {}

    def start(self, udid, trigger):
        self.started.append((udid, trigger))


class BrokenEngine(DemoEngine):
    def discover(self):
        raise OSError("no network")


@pytest.fixture
def connect(tmp_path):
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    return lambda: db.connect(path)


def add_device(connect, window=(None, None)):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, window_start, window_end, created_at) VALUES (?, ?, ?, ?, ?)",
            (PHONE.udid, PHONE.name, window[0], window[1], "2026-09-14T00:00:00Z"),
        )


def make(connect, engine=None):
    jobs, alerts = FakeJobs(), []
    ticker = Ticker(connect, engine or DemoEngine(step_seconds=0), jobs, lambda *a: alerts.append(a), UTC)
    return ticker, jobs, alerts


def test_due_reachable_device_inside_its_window_is_backed_up(connect):
    add_device(connect, window=("00:00", "00:00"))
    ticker, jobs, alerts = make(connect)
    assert ticker.tick(NOW)[PHONE.udid].start_backup
    assert jobs.started == [(PHONE.udid, "schedule")]
    with closing(connect()) as conn:
        assert conn.execute("SELECT transport FROM sightings WHERE udid = ?", (PHONE.udid,)).fetchone()[0] == "wifi"


def test_tick_prunes_sightings_older_than_30_days(connect):
    add_device(connect)
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO sightings (udid, seen_at, transport) VALUES (?, ?, 'wifi')",
            (PHONE.udid, "2026-08-01T00:00:00Z"),  # well over 30 days before NOW
        )
    ticker, jobs, alerts = make(connect)
    ticker.tick(NOW)
    with closing(connect()) as conn:
        rows = conn.execute("SELECT seen_at FROM sightings WHERE udid = ?", (PHONE.udid,)).fetchall()
    seen_ats = {r[0] for r in rows}
    assert "2026-08-01T00:00:00Z" not in seen_ats
    assert "2026-09-15T03:00:00Z" in seen_ats  # this tick's own sighting survives


def test_tick_records_itself_in_the_ticks_table(connect):
    add_device(connect)
    ticker, jobs, alerts = make(connect)
    ticker.tick(NOW)
    with closing(connect()) as conn:
        rows = conn.execute("SELECT tick_at FROM ticks").fetchall()
    assert [r[0] for r in rows] == ["2026-09-15T03:00:00Z"]


def test_tick_prunes_ticks_older_than_30_days(connect):
    add_device(connect)
    with closing(connect()) as conn:
        conn.execute("INSERT INTO ticks (tick_at) VALUES (?)", ("2026-08-01T00:00:00Z",))  # over 30 days before NOW
    ticker, jobs, alerts = make(connect)
    ticker.tick(NOW)
    with closing(connect()) as conn:
        rows = conn.execute("SELECT tick_at FROM ticks").fetchall()
    tick_ats = {r[0] for r in rows}
    assert "2026-08-01T00:00:00Z" not in tick_ats
    assert "2026-09-15T03:00:00Z" in tick_ats  # this tick's own row survives


def test_device_without_window_gets_one_reminder_per_period(connect):
    add_device(connect)
    ticker, jobs, alerts = make(connect)
    ticker.tick(NOW)
    ticker.tick(NOW)
    assert jobs.started == []
    assert [a[0] for a in alerts] == ["due"]
    with closing(connect()) as conn:
        assert conn.execute("SELECT last_nudge_at FROM devices").fetchone()[0] == "2026-09-15T03:00:00Z"


def test_reminders_still_go_out_when_discovery_fails(connect):
    add_device(connect, window=("00:00", "00:00"))
    ticker, jobs, alerts = make(connect, engine=BrokenEngine())
    ticker.tick(NOW)
    assert jobs.started == []
    assert [a[0] for a in alerts] == ["due"]


def add_device_with_charging(connect, only_when_charging):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, window_start, window_end, only_when_charging, created_at) "
            "VALUES (?, ?, '00:00', '00:00', ?, ?)",
            (PHONE.udid, PHONE.name, only_when_charging, "2026-09-14T00:00:00Z"),
        )


def test_only_when_charging_probes_the_engine_and_blocks_when_not_charging(connect):
    """Regression for the bug fixed alongside this test: ticker.py used to call
    scheduler.decide(..., charging=None) unconditionally, so a device with only_when_charging on
    could never start on a schedule at all (an unknown charging state never satisfies the
    requirement). This proves the real charging state is now read and actually gates the start."""
    add_device_with_charging(connect, only_when_charging=1)
    from bioseasy.engine.demo import DemoEngine as _DemoEngine

    engine = _DemoEngine(step_seconds=0, not_charging_udids=frozenset({PHONE.udid}))
    ticker, jobs, alerts = make(connect, engine=engine)
    decisions = ticker.tick(NOW)
    assert decisions[PHONE.udid].start_backup is False
    assert jobs.started == []


def test_only_when_charging_starts_once_the_probe_says_charging(connect):
    add_device_with_charging(connect, only_when_charging=1)
    ticker, jobs, alerts = make(connect)  # default DemoEngine: paired devices report as charging
    decisions = ticker.tick(NOW)
    assert decisions[PHONE.udid].start_backup is True
    assert jobs.started == [(PHONE.udid, "schedule")]


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _insert_attempt(connect, udid, at):
    """Mimics what JobManager.start really does to the runs table (a fresh row with started_at),
    without pulling in JobManager itself: FakeJobs.start only appends to a list, so the stepped
    retry schedule - which reads last_attempt_at back out of `runs` via load_views - would
    otherwise never see a previous attempt."""
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, finished_at, status) VALUES (?, 'schedule', ?, ?, 'failed')",
            (udid, _iso(at), _iso(at)),
        )


def _insert_success(connect, udid, at):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, finished_at, status) "
            "VALUES (?, 'schedule', ?, ?, 'succeeded')",
            (udid, _iso(at), _iso(at + timedelta(minutes=5))),
        )


def test_stepped_retries_fire_at_window_start_then_30_60_120_minutes(connect):
    add_device(connect, window=("08:00", "20:00"))
    ticker, jobs, alerts = make(connect)
    window_start = datetime(2026, 9, 15, 8, 0, tzinfo=UTC)

    assert ticker.tick(window_start)[PHONE.udid].start_backup is True
    _insert_attempt(connect, PHONE.udid, window_start)

    assert ticker.tick(window_start + timedelta(minutes=10))[PHONE.udid].start_backup is False
    assert ticker.tick(window_start + timedelta(minutes=29))[PHONE.udid].start_backup is False

    assert ticker.tick(window_start + timedelta(minutes=30))[PHONE.udid].start_backup is True
    _insert_attempt(connect, PHONE.udid, window_start + timedelta(minutes=30))

    assert ticker.tick(window_start + timedelta(minutes=45))[PHONE.udid].start_backup is False

    assert ticker.tick(window_start + timedelta(minutes=60))[PHONE.udid].start_backup is True
    _insert_attempt(connect, PHONE.udid, window_start + timedelta(minutes=60))

    assert ticker.tick(window_start + timedelta(minutes=90))[PHONE.udid].start_backup is False

    assert ticker.tick(window_start + timedelta(minutes=120))[PHONE.udid].start_backup is True
    _insert_attempt(connect, PHONE.udid, window_start + timedelta(minutes=120))

    # Past the final (120 min) slot: no fifth attempt, still inside the window.
    assert ticker.tick(window_start + timedelta(minutes=150))[PHONE.udid].start_backup is False

    assert jobs.started == [(PHONE.udid, "schedule")] * 4


def test_no_attempts_outside_the_window(connect):
    add_device(connect, window=("08:00", "20:00"))
    ticker, jobs, alerts = make(connect)
    before = ticker.tick(datetime(2026, 9, 15, 7, 59, tzinfo=UTC))
    after = ticker.tick(datetime(2026, 9, 15, 20, 0, tzinfo=UTC))
    assert before[PHONE.udid].start_backup is False
    assert after[PHONE.udid].start_backup is False
    assert jobs.started == []


def test_no_attempt_after_a_success_even_with_an_open_retry_slot(connect):
    add_device(connect, window=("08:00", "20:00"))
    ticker, jobs, alerts = make(connect)
    window_start = datetime(2026, 9, 15, 8, 0, tzinfo=UTC)
    _insert_success(connect, PHONE.udid, window_start)
    decision = ticker.tick(window_start + timedelta(minutes=30))[PHONE.udid]
    assert decision.start_backup is False
    assert jobs.started == []


def test_notice_fires_once_before_window_start_with_the_default_lead_time(connect):
    # Note: a device that has never had a successful backup is also "due" for the nudge alert
    # (scheduler.decide's separate, pre-existing "due" reminder), so every tick here also emits a
    # "due" alert; only "upcoming" alerts are asserted on.
    add_device(connect, window=("08:00", "20:00"))
    ticker, jobs, alerts = make(connect)
    window_start = datetime(2026, 9, 15, 8, 0, tzinfo=UTC)

    def upcoming_alerts():
        return [a for a in alerts if a[0] == "upcoming"]

    ticker.tick(window_start - timedelta(minutes=6))  # outside the default 5-minute lead time
    assert upcoming_alerts() == []

    ticker.tick(window_start - timedelta(minutes=5))  # exactly at the lead time
    assert len(upcoming_alerts()) == 1
    assert upcoming_alerts()[0][2] == "5"  # minutes-until-start, passed through to notify.message_for

    ticker.tick(window_start - timedelta(minutes=2))  # still before start: already notified
    assert len(upcoming_alerts()) == 1

    with closing(connect()) as conn:
        stored = conn.execute("SELECT last_window_notice_at FROM devices").fetchone()[0]
    assert stored == "2026-09-15T08:00:00Z"


def test_no_notice_once_a_success_already_covers_the_interval(connect):
    add_device(connect, window=("08:00", "20:00"))
    ticker, jobs, alerts = make(connect)
    _insert_success(connect, PHONE.udid, datetime(2026, 9, 15, 7, 0, tzinfo=UTC))
    ticker.tick(datetime(2026, 9, 15, 7, 55, tzinfo=UTC))  # 5 min before window start, due to fire
    assert [a for a in alerts if a[0] == "upcoming"] == []


def test_charging_probe_is_skipped_when_the_device_would_not_start_anyway(connect):
    # Outside the window: optimistic decide() already says no, so the charging probe (which
    # would raise here) must never run.
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, window_start, window_end, only_when_charging, created_at) "
            "VALUES (?, ?, '08:00', '09:00', 1, ?)",
            (PHONE.udid, PHONE.name, "2026-09-14T00:00:00Z"),
        )

    class ExplodingChargingEngine(DemoEngine):
        def charging_state(self, udid, on_pair_used=None):
            raise AssertionError("charging_state must not be called when the device would not start anyway")

    ticker, jobs, alerts = make(connect, engine=ExplodingChargingEngine(step_seconds=0))
    decisions = ticker.tick(NOW)  # NOW is 03:00, outside 08:00-09:00
    assert decisions[PHONE.udid].start_backup is False
    assert jobs.started == []
