# SPDX-License-Identifier: GPL-3.0-or-later
"""The live backup progress the setup wizard and the device page show while a run is active.

Found during a real Wi-Fi backup: after clicking "Back up now" the page
showed nothing for minutes while the backup was actually transferring, and the progress was
only ever on the device page, not in the setup wizard where the click happened.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from test_setup_wizard import (  # noqa: F401 (env is a fixture)
    PASSWORD,
    PHONE,
    TABLET,
    add_paired_phone,
    conn_for,
    csrf,
    env,
    pair_and_add_tablet,
    wait_until,
)

from bioseasy import auth

TABLET_KIND = "iPad"
PHONE_KIND = "iPhone"


def _insert_running_run(settings, udid, *, phase, percent=None, started_at=None, heartbeat_at=None):
    now = datetime.now(UTC)
    started_at = started_at or now
    heartbeat_at = heartbeat_at if heartbeat_at is not None else started_at

    def iso(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase, percent, heartbeat_at) "
            "VALUES (?, 'manual', ?, 'running', ?, ?, ?)",
            (udid, iso(started_at), phase, percent, iso(heartbeat_at)),
        )


# --- phase text, percent and the progress bar ---------------------------------------------------


def test_step4_shows_waiting_for_passcode_in_words(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    _insert_running_run(settings, TABLET.udid, phase="waiting_for_passcode")

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert f"Waiting for you to enter the passcode on the {TABLET_KIND}" in page


def test_step4_shows_transferring_with_percent_and_bar(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    _insert_running_run(settings, TABLET.udid, phase="transferring", percent=42.0)

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert "Transferring" in page
    assert "42" in page and "%" in page
    assert "<progress" in page and 'value="42.0"' in page


def test_step4_shows_finishing(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    _insert_running_run(settings, TABLET.udid, phase="finishing")

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert "Finishing" in page


def test_transferring_without_percent_shows_bar_but_no_number(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    _insert_running_run(settings, TABLET.udid, phase="transferring", percent=None)

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert "Transferring" in page
    assert "<progress" in page


# --- "running for" / "last data" -----------------------------------------------------------------


def test_running_for_and_last_data_lines_render(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    now = datetime.now(UTC)
    _insert_running_run(
        settings,
        TABLET.udid,
        phase="transferring",
        percent=10.0,
        started_at=now - timedelta(minutes=3),
        heartbeat_at=now - timedelta(seconds=20),
    )

    page = client.get(f"/devices/{TABLET.udid}/status").text
    assert "Running for 3 min" in page
    assert "last data" in page and "s ago" in page


def test_you_can_close_this_page_note_shows_on_the_device_page_while_running(env):  # noqa: F811
    client, settings = env
    add_paired_phone(client, settings)
    _insert_running_run(settings, PHONE.udid, phase="transferring", percent=10.0)

    page = client.get(f"/devices/{PHONE.udid}").text
    assert "you can close this page" in page.lower()


# --- the stall hint --------------------------------------------------------------------------


def test_no_stall_hint_before_two_minutes_without_data(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    now = datetime.now(UTC)
    _insert_running_run(
        settings,
        TABLET.udid,
        phase="transferring",
        percent=10.0,
        started_at=now - timedelta(minutes=1),
        heartbeat_at=now - timedelta(seconds=90),
    )

    page = client.get(f"/devices/{TABLET.udid}/status").text
    assert "No data for" not in page


def test_stall_hint_appears_past_two_minutes_without_data(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    now = datetime.now(UTC)
    _insert_running_run(
        settings,
        TABLET.udid,
        phase="transferring",
        percent=10.0,
        started_at=now - timedelta(minutes=5),
        heartbeat_at=now - timedelta(minutes=3),
    )

    page = client.get(f"/devices/{TABLET.udid}/status").text
    assert "No data for 3 min" in page
    assert "bioseasy stops the run after 10 min without data" in page  # DemoEngine has no
    # stall_timeout attribute, so this is the DEFAULT_STALL_TIMEOUT fallback (600 s = 10 min),
    # which matches engine.pmd3.STALL_TIMEOUT's own default.


def test_stall_hint_only_shows_while_transferring(env):  # noqa: F811
    client, settings = env
    pair_and_add_tablet(client, settings)
    now = datetime.now(UTC)
    _insert_running_run(
        settings,
        TABLET.udid,
        phase="waiting_for_passcode",
        started_at=now - timedelta(minutes=5),
        heartbeat_at=now - timedelta(minutes=5),
    )

    page = client.get(f"/devices/{TABLET.udid}/status").text
    assert "No data for" not in page


# --- the started note, right after the click ----------------------------------------------------


class _GatedEngine:
    """Wraps another engine and blocks its backup() on `gate` before doing anything else, so a
    test can inspect the response the request itself got back - the very first render after
    JobManager.start() returns - before any progress callback has had a chance to run and move
    the run row past its initial 'starting' phase. Every other Engine method delegates straight
    through."""

    def __init__(self, inner, gate: threading.Event):
        self._inner = inner
        self._gate = gate
        self.name = inner.name

    def discover(self, on_pair_used=None):
        return self._inner.discover(on_pair_used)

    def pair(self, udid):
        return self._inner.pair(udid)

    def enable_wifi(self, udid, on_pair_used=None):
        return self._inner.enable_wifi(udid, on_pair_used)

    def encryption_enabled(self, udid, on_pair_used=None):
        return self._inner.encryption_enabled(udid, on_pair_used)

    def enable_encryption(self, udid, password):
        return self._inner.enable_encryption(udid, password)

    def change_encryption_password(self, udid, old, new):
        return self._inner.change_encryption_password(udid, old, new)

    def detect_setup_state(self, udid, on_pair_used=None):
        return self._inner.detect_setup_state(udid, on_pair_used)

    def backup(self, udid, target_root, on_progress, on_pair_used=None, on_transport=None):
        self._gate.wait(timeout=5)
        return self._inner.backup(udid, target_root, on_progress, on_pair_used, on_transport=on_transport)


def _setup_client(tmp_path, engine):

    from fastapi.testclient import TestClient

    from bioseasy import auth
    from bioseasy.app import create_app
    from bioseasy.config import Settings

    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    client = TestClient(create_app(settings, engine, huey_immediate=True), follow_redirects=False)
    client.__enter__()
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": "admin", "password": PASSWORD})
    assert r.status_code == 303
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{PHONE.udid}/setup"
    return client, settings


STARTED_TEXT = "The first backup can take a long time; it runs on the server, so you can close this page."


def test_started_note_appears_at_once_after_backup_htmx(tmp_path):
    from bioseasy.engine.demo import DemoEngine

    gate = threading.Event()
    engine = _GatedEngine(DemoEngine(step_seconds=0), gate)
    client, settings = _setup_client(tmp_path, engine)
    try:
        token = csrf(client, f"/devices/{PHONE.udid}/setup")
        r = client.post(
            f"/devices/{PHONE.udid}/backup",
            data={"csrf": token},
            headers={"hx-request": "true"},
        )
        assert r.status_code == 200
        assert "Backup started." in r.text
        assert STARTED_TEXT in r.text
        assert PHONE_KIND in r.text
    finally:
        gate.set()
        wait_until(lambda: "running" not in (row_status(settings, PHONE.udid) or ""))
        client.__exit__(None, None, None)


def test_started_note_appears_at_once_after_backup_non_htmx(tmp_path):
    from bioseasy.engine.demo import DemoEngine

    gate = threading.Event()
    engine = _GatedEngine(DemoEngine(step_seconds=0), gate)
    client, settings = _setup_client(tmp_path, engine)
    try:
        token = csrf(client, f"/devices/{PHONE.udid}/setup")
        r = client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": token})
        assert r.status_code == 303 and r.headers["location"] == f"/devices/{PHONE.udid}"
        page = client.get(f"/devices/{PHONE.udid}").text
        assert "Backup started." in page
        assert STARTED_TEXT in page
    finally:
        gate.set()
        wait_until(lambda: "running" not in (row_status(settings, PHONE.udid) or ""))
        client.__exit__(None, None, None)


def row_status(settings, udid):
    with conn_for(settings) as conn:
        row = conn.execute(
            "SELECT status FROM runs WHERE udid = ? ORDER BY started_at DESC LIMIT 1", (udid,)
        ).fetchone()
    return row["status"] if row else None


# --- access control ---------------------------------------------------------------------------


def test_member_404_on_a_foreign_devices_status_and_setup_status(env):  # noqa: F811
    client, settings = env
    add_paired_phone(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": "member", "password": PASSWORD})
    assert r.status_code == 303
    assert client.get(f"/devices/{PHONE.udid}/status").status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/setup/status").status_code == 404
