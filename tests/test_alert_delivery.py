# SPDX-License-Identifier: GPL-3.0-or-later
"""ticker.py hands an alert to runtime.notify_event and moves on without knowing whether it
arrived (notify_event sends off its own thread, with its own explicit timeout). The state
recorded in the database must still match reality:

- devices.last_nudge_at / last_overdue_alert_at / last_window_notice_at are attempt timestamps,
  written unconditionally (unchanged from before this fix) so a target that is down for a long
  time is retried at a slow, bounded cadence instead of on every tick.
- devices.last_alert_ok / last_alert_error / last_alert_at are written only once notify.send()
  actually returns, so a failed or timed-out send is never recorded as if it had succeeded - a
  timestamp that means "the user was told" is only written when the telling actually happened.

These tests drive the real Ticker wired to the real runtime.notify_event (build_runtime), with
only notify.send() itself replaced by a fake - the same pattern test_runtime_storage_notify.py
uses - so the interaction between the tick, the cooldown and the async send is exercised for
real, not reconstructed from its parts.
"""

import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, connectors, db
from bioseasy import notify as notify_mod
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.notify import NotifyResult
from bioseasy.runtime import build as build_runtime

PASSWORD = "correct horse battery"
PHONE = DEMO_DEVICES[0]

UDID = "dead-beef-0000"
NOW = datetime(2026, 9, 20, 3, 0, tzinfo=UTC)
OVERDUE_COOLDOWN = timedelta(hours=24)


def _wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _settings(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    return Settings(data, root, "demo", "test-secret", False, 3600)


def _build(tmp_path):
    settings = _settings(tmp_path)
    rt = build_runtime(settings, DemoEngine(step_seconds=0))
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        # overdue_days=1 and an old created_at so the device reads overdue at NOW without a
        # backup ever needing to run; no window, so the scheduling window never gates it.
        # interval_hours is pushed out far enough, with a stale-looking last_nudge_at already in
        # place, that the "due" nudge cooldown never lifts during the test - isolating the
        # overdue alert as the only one under test, rather than tracking two interleaved
        # cooldowns for the same assertions.
        conn.execute(
            "INSERT INTO devices (udid, name, overdue_days, interval_hours, last_nudge_at, created_at) "
            "VALUES (?, ?, 1, 1000000, ?, ?)",
            (UDID, "Test iPhone", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        connectors.create_connector(
            conn,
            scope="admin",
            udid=None,
            kind="apprise",
            label="test",
            settings={},
            secret_ciphertext=connectors.encrypt_secret(rt.settings.data_dir, "json://192.0.2.1:1/hook"),
        )
    return rt


def _device_row(rt):
    with closing(rt.connect()) as conn:
        return conn.execute("SELECT * FROM devices WHERE udid = ?", (UDID,)).fetchone()


def test_failing_sender_is_retried_at_the_cooldown_cadence_not_every_tick(tmp_path, monkeypatch):
    calls = []

    def failing_send(urls, title, body):
        calls.append(1)
        return NotifyResult(False, error="Sending the notification timed out")

    monkeypatch.setattr(notify_mod, "send", failing_send)
    rt = _build(tmp_path)

    # First tick: the device is overdue, so ticker.py hands an alert to notify_event and stamps
    # last_overdue_alert_at immediately (the attempt clock) - unchanged from before this fix.
    rt.ticker.tick(NOW)
    assert _wait_for(lambda: len(calls) == 1)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 0)
    row = _device_row(rt)
    assert row["last_overdue_alert_at"] is not None
    assert row["last_alert_error"]

    # A second tick one hour later: well inside the 24h overdue cooldown. Must not attempt again -
    # this is the storm guard, driven off the same attempt timestamp as before this fix.
    rt.ticker.tick(NOW + timedelta(hours=1))
    time.sleep(0.2)
    assert len(calls) == 1

    # A third tick past the cooldown: the target is still down, so this is the retry - at the
    # cooldown's slower, bounded cadence, not on every intervening tick.
    rt.ticker.tick(NOW + OVERDUE_COOLDOWN + timedelta(minutes=1))
    assert _wait_for(lambda: len(calls) == 2)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 0)


def test_a_successful_send_behaves_exactly_as_today(tmp_path, monkeypatch):
    def ok_send(urls, title, body):
        return NotifyResult(True)

    monkeypatch.setattr(notify_mod, "send", ok_send)
    rt = _build(tmp_path)

    rt.ticker.tick(NOW)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 1)
    row = _device_row(rt)
    assert row["last_alert_error"] is None
    assert row["last_overdue_alert_at"] is not None

    # Same cooldown as the failure case: a success does not cause a second attempt within the
    # 24h window either.
    rt.ticker.tick(NOW + timedelta(hours=1))
    time.sleep(0.2)


def test_recovery_after_repeated_failures_is_recorded_once_it_succeeds(tmp_path, monkeypatch):
    outcomes = iter([NotifyResult(False, error="boom"), NotifyResult(False, error="boom"), NotifyResult(True)])
    calls = []

    def flaky_send(urls, title, body):
        calls.append(1)
        return next(outcomes)

    monkeypatch.setattr(notify_mod, "send", flaky_send)
    rt = _build(tmp_path)

    # Every step waits for its own send to have been counted, not for a column value an earlier
    # attempt already wrote: last_alert_error reads "boom" from the first failure onwards, so
    # waiting on that passed instantly and let the next tick start while the previous attempt was
    # still in flight - which is how this test used to fail roughly one full-suite run in three.
    rt.ticker.tick(NOW)
    assert _wait_for(lambda: len(calls) == 1)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 0)

    rt.ticker.tick(NOW + OVERDUE_COOLDOWN + timedelta(minutes=1))
    assert _wait_for(lambda: len(calls) == 2)
    assert _wait_for(lambda: _device_row(rt)["last_alert_error"] == "boom")

    rt.ticker.tick(NOW + 2 * OVERDUE_COOLDOWN + timedelta(minutes=2))
    assert _wait_for(lambda: len(calls) == 3)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 1)
    row = _device_row(rt)
    assert row["last_alert_error"] is None


def test_a_slow_older_attempt_never_overwrites_a_newer_verdict(tmp_path, monkeypatch):
    """The newest attempt decides what the device page says, not the one that happens to finish
    last. Two alerts for the same device do overlap in practice (ticker.py raising an overdue
    alert while jobs.py reports a backup outcome), and each wrote its own verdict when its own
    send returned. This drives the bad ordering deliberately rather than waiting for it to occur:
    the first attempt fails slowly, the second succeeds at once. Before notify_event serialised
    per device, the stale failure landed last and the page claimed a delivered alert had failed.
    """

    started = []

    def ordered_send(urls, title, body):
        attempt = len(started)
        started.append(attempt)
        if attempt == 0:
            time.sleep(1.0)
            return NotifyResult(False, error="boom")
        return NotifyResult(True)

    monkeypatch.setattr(notify_mod, "send", ordered_send)
    rt = _build(tmp_path)

    rt.ticker.tick(NOW)
    assert _wait_for(lambda: len(started) == 1), "the first alert never went out"
    rt.ticker.tick(NOW + OVERDUE_COOLDOWN + timedelta(minutes=1))

    assert _wait_for(lambda: len(started) == 2, timeout=10), "the second alert never went out"
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 1, timeout=10), "success not recorded"

    # Comfortably longer than the first attempt's own delay, so it has certainly finished and
    # written whatever it was going to write by the time this reads the row back.
    time.sleep(1.5)
    row = _device_row(rt)
    assert row["last_alert_ok"] == 1, f"a stale failure overwrote the newer success: {dict(row)}"
    assert row["last_alert_error"] is None


def test_failed_delivery_state_survives_a_fresh_connection_like_a_worker_restart(tmp_path, monkeypatch):
    """Nothing about the outcome may live only in memory: a worker restart opens a brand new
    sqlite3 connection to the same file (db.connect), never resumes an in-process object, so the
    failed state must be readable back through exactly that path."""

    def failing_send(urls, title, body):
        return NotifyResult(False, error="Sending the notification failed")

    monkeypatch.setattr(notify_mod, "send", failing_send)
    rt = _build(tmp_path)
    rt.ticker.tick(NOW)
    assert _wait_for(lambda: _device_row(rt)["last_alert_ok"] == 0)

    # A fresh connection to the same on-disk database, exactly what `bioseasy worker` opens again
    # after a restart - not the same in-memory Runtime or connection object.
    with closing(db.connect(rt.settings.data_dir / "bioseasy.db")) as fresh:
        row = fresh.execute(
            "SELECT last_alert_ok, last_alert_error, last_overdue_alert_at FROM devices WHERE udid = ?",
            (UDID,),
        ).fetchone()
    assert row["last_alert_ok"] == 0
    assert row["last_alert_error"] == "Sending the notification failed"
    assert row["last_overdue_alert_at"] is not None


@pytest.fixture
def web_env(tmp_path):
    settings = _settings(tmp_path)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def _csrf(client, url):
    import re

    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def _login_admin(client, settings):
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        db.migrate(conn)
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO devices (udid, name, created_at) VALUES (?, ?, ?)",
            (PHONE.udid, PHONE.name, "2026-01-01T00:00:00Z"),
        )
    token = _csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": "admin", "password": PASSWORD})
    assert r.status_code == 303


def test_device_page_shows_a_failed_alert_and_never_claims_it_was_delivered(web_env):
    """Where the failure is visible: the device page carries a plain-text notice when the most
    recent alert send failed. It must never render a "delivered"/"notified" message for a device
    whose last send did not succeed - honesty over reassurance."""
    client, settings = web_env
    _login_admin(client, settings)
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        conn.execute(
            "UPDATE devices SET last_alert_ok = 0, last_alert_error = ? WHERE udid = ?",
            ("Sending the notification timed out", PHONE.udid),
        )
    page = client.get(f"/devices/{PHONE.udid}").text
    assert "could not be delivered" in page
    assert "Sending the notification timed out" in page


def test_device_page_says_nothing_when_no_alert_has_failed(web_env):
    client, settings = web_env
    _login_admin(client, settings)
    # last_alert_ok is NULL by default (never attempted) - must not be reported as a failure.
    page = client.get(f"/devices/{PHONE.udid}").text
    assert "could not be delivered" not in page

    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        conn.execute("UPDATE devices SET last_alert_ok = 1 WHERE udid = ?", (PHONE.udid,))
    page = client.get(f"/devices/{PHONE.udid}").text
    assert "could not be delivered" not in page
