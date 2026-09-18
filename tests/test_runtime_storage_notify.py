# SPDX-License-Identifier: GPL-3.0-or-later
"""runtime.notify_storage_failed: a volume-wide admin alert, throttled to at most once per
STORAGE_ALERT_COOLDOWN, so a run of backup attempts hitting the same low-space volume does not
each trigger their own message (see docs/concept.md)."""

import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

from bioseasy import connectors, db
from bioseasy import notify as notify_mod
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine
from bioseasy.notify import NotifyResult
from bioseasy.runtime import build as build_runtime


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


def _add_admin_connector(rt):
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        connectors.create_connector(
            conn,
            scope="admin",
            udid=None,
            kind="apprise",
            label="test",
            settings={},
            secret_ciphertext=connectors.encrypt_secret(rt.settings.data_dir, "json://192.0.2.1:1/hook"),
        )


def test_notify_storage_failed_sends_and_sets_the_throttle_key(tmp_path, monkeypatch):
    sent = []

    def fake_send(urls, title, body):
        sent.append((title, body))
        return NotifyResult(True)

    monkeypatch.setattr(notify_mod, "send", fake_send)

    settings = _settings(tmp_path)
    rt = build_runtime(settings, DemoEngine(step_seconds=0))
    _add_admin_connector(rt)

    rt.notify_storage_failed("Less than 10 GiB free")
    assert _wait_for(lambda: len(sent) == 1)
    assert "storage" in sent[0][0].lower() or "backup" in sent[0][0].lower()

    with closing(rt.connect()) as conn:
        key = f"storage_alert_sent_at:{settings.backup_root}"
        assert db.get_setting(conn, key) is not None


def _add_device(rt, udid="dead-beef-0000", name="Anna's iPhone"):
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        conn.execute(
            "INSERT INTO devices (udid, name, created_at) VALUES (?, ?, ?)",
            (udid, name, "2026-09-14T00:00:00Z"),
        )
    return udid


def test_notify_event_failure_is_logged_where_the_user_can_see_it_without_the_secret(tmp_path, monkeypatch, caplog):
    """A failing send must not vanish silently: runtime.notify_event logs a warning naming the
    device and event, the only place a failure is currently recorded (there is no per-connector
    failure state in the UI). The secret behind the connector (here a fake Telegram-shaped
    Apprise URL) must never appear in that log record."""
    secret_url = "tgram://123456789:super-secret-bot-token/@channel"

    def fake_send(urls, title, body):
        assert urls == [secret_url]
        return NotifyResult(False, error="Sending the notification timed out")

    monkeypatch.setattr(notify_mod, "send", fake_send)

    settings = _settings(tmp_path)
    rt = build_runtime(settings, DemoEngine(step_seconds=0))
    udid = _add_device(rt)
    with closing(rt.connect()) as conn:
        connectors.create_connector(
            conn,
            scope="admin",
            udid=None,
            kind="apprise",
            label="test",
            settings={},
            secret_ciphertext=connectors.encrypt_secret(rt.settings.data_dir, secret_url),
        )

    with caplog.at_level("WARNING", logger="bioseasy"):
        rt.notify_event("overdue", udid, "No complete backup in the configured period")
        assert _wait_for(lambda: any("overdue" in r.message for r in caplog.records))

    log_text = "\n".join(r.message for r in caplog.records)
    assert "super-secret-bot-token" not in log_text
    assert secret_url not in log_text
    assert udid in log_text or udid[:8] in log_text


def test_notify_storage_failed_is_throttled_within_the_cooldown(tmp_path, monkeypatch):
    sent = []

    def fake_send(urls, title, body):
        sent.append((title, body))
        return NotifyResult(True)

    monkeypatch.setattr(notify_mod, "send", fake_send)

    settings = _settings(tmp_path)
    rt = build_runtime(settings, DemoEngine(step_seconds=0))
    _add_admin_connector(rt)

    # Pretend an alert already went out a minute ago: well within the 24h cooldown.
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        key = f"storage_alert_sent_at:{settings.backup_root}"
        recent = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.set_setting(conn, key, recent)

    rt.notify_storage_failed("Less than 10 GiB free")
    time.sleep(0.2)  # give the background thread a chance; nothing should arrive
    assert sent == []
