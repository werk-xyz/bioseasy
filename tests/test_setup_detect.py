# SPDX-License-Identifier: GPL-3.0-or-later
"""Detecting a device's real Wi-Fi/encryption state (docs/setup.md, "Adding a device again"):
a pair record - and a whole backup history - can survive a recreated database while the device
itself already has both on, and the wizard must notice instead of forcing the owner through
steps the device does not need again. Also covers a succeeded backup itself confirming the same
two steps (jobs.py), and the "Back up now" button's immediate feedback (app.py's backup_now).
"""

import re
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, jobs, runtime, snapshots, storage
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.base import SetupState, Transport
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine, write_backup

PHONE = DEMO_DEVICES[0]
TABLET = DEMO_DEVICES[1]
PASSWORD = "correct horse battery"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    # step_seconds left at its default (not 0): the backup_now tests below need the backup
    # thread to still be running immediately after the POST returns, to prove the response
    # itself reflects the running state rather than a race with an instantly-finished backup.
    engine = DemoEngine(data_dir=data)
    with TestClient(create_app(settings, engine, huey_immediate=True), follow_redirects=False) as client:
        yield client, settings, engine


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username="admin"):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def device_row(settings, udid):
    with conn_for(settings) as conn:
        return conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()


def wait_until(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    raise AssertionError("condition was never met in time")


def re_add_phone_after_a_recreated_database(client, settings):
    """The scenario from docs/setup.md: the pair record (here, the demo engine's own "paired"
    membership) survives a recreated database, and the device itself already has Wi-Fi and
    encryption on - the demo engine's default state for the phone - but the fresh devices row
    has both columns NULL, exactly like a real re-add after the database was recreated."""
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    login(client)
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{PHONE.udid}/setup"


def add_unpaired_tablet_and_pair_it(client, settings):
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 0, '2026-09-15T00:00:00Z')",
            (TABLET.udid, TABLET.name, TABLET.product_type, TABLET.os_version, TABLET.transport.value),
        )
    login(client)
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add/pair", data={"csrf": csrf(client, "/add"), "udid": TABLET.udid})
    assert r.status_code == 303

    def pairing_settled():
        with conn_for(settings) as conn:
            row = conn.execute("SELECT state FROM pairings WHERE udid = ?", (TABLET.udid,)).fetchone()
        return row is not None and row["state"] in ("done", "failed")

    wait_until(pairing_settled)
    r = client.get(f"/add/pairing/{TABLET.udid}")
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{TABLET.udid}/setup"


# --- detection closes the re-add gap -----------------------------------------------------------


def test_readd_with_wifi_and_encryption_already_on_completes_setup_without_the_wizard(env):
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)

    row = device_row(settings, PHONE.udid)
    assert row["wifi_enabled_at"] is not None
    assert row["encryption_enabled_at"] is not None

    page = client.get(f"/devices/{PHONE.udid}/setup").text
    assert "Already on (detected)" in page
    assert page.count("Already on (detected)") == 2  # both the Wi-Fi and the encryption step


def test_readd_with_a_complete_backup_already_on_disk_reaches_setup_complete(env):
    client, settings, engine = env
    write_backup(settings.backup_root / PHONE.udid, PHONE)
    snapshots.take(settings.backup_root, PHONE.udid, datetime.now(UTC), hardlinks=True)

    re_add_phone_after_a_recreated_database(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/setup").text
    assert "Setup complete" in page
    assert "Found existing backups of this device" in page


def test_failed_detection_read_sets_nothing(env, monkeypatch):
    client, settings, engine = env

    def boom(udid, on_pair_used=None):
        raise RuntimeError("simulated device read failure")

    monkeypatch.setattr(engine, "detect_setup_state", boom)
    re_add_phone_after_a_recreated_database(client, settings)

    row = device_row(settings, PHONE.udid)
    assert row["wifi_enabled_at"] is None
    assert row["encryption_enabled_at"] is None


def test_confirmed_false_never_unsets_an_already_recorded_column(env):
    """A stronger claim than "a failed read sets nothing": even a confirmed False must never
    unset a column bioseasy already recorded (COALESCE in runtime.run_setup_detect)."""
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)
    # A distinguishable, deliberately old value: if run_setup_detect below ever overwrites it
    # (with a fresh _now() timestamp), the difference cannot be hidden by timestamp granularity
    # the way two calls landing in the same second otherwise could.
    with conn_for(settings) as conn:
        conn.execute(
            "UPDATE devices SET wifi_enabled_at = '2020-01-01T00:00:00Z', "
            "encryption_enabled_at = '2020-01-01T00:00:00Z' WHERE udid = ?",
            (PHONE.udid,),
        )

    class _AlwaysOff:
        def detect_setup_state(self, udid, on_pair_used=None):
            return SetupState(wifi_enabled=False, encryption_enabled=False)

    rt_off = runtime.build(settings, _AlwaysOff())
    runtime.run_setup_detect(rt_off, PHONE.udid)
    after = device_row(settings, PHONE.udid)
    assert after["wifi_enabled_at"] == "2020-01-01T00:00:00Z"
    assert after["encryption_enabled_at"] == "2020-01-01T00:00:00Z"


# --- rate limiting: polling the setup page must not hammer the device --------------------------


def test_polling_the_setup_page_only_detects_once_per_cooldown(env, monkeypatch):
    client, settings, engine = env

    calls = []
    original = engine.detect_setup_state

    def spy(udid, on_pair_used=None):
        calls.append(udid)
        return original(udid, on_pair_used)

    monkeypatch.setattr(engine, "detect_setup_state", spy)

    add_unpaired_tablet_and_pair_it(client, settings)  # paired, but Wi-Fi/encryption stay off;
    # pairing itself already opens the setup page once (the redirect target), which is call 1.
    client.get(f"/devices/{TABLET.udid}/setup")
    client.get(f"/devices/{TABLET.udid}/setup/status")
    client.get(f"/devices/{TABLET.udid}/setup/status")
    assert len(calls) == 1  # the cooldown (runtime.SETUP_DETECT_COOLDOWN) collapsed the rest


def test_stuck_running_state_from_a_killed_worker_eventually_clears(env):
    """A worker can be killed (OOM, container restart) between
    runtime.mark_setup_detect_running and run_setup_detect's own terminal write, exactly the gap
    a request handler always leaves open between marking the state and enqueueing the task
    (runtime.mark_setup_detect_running's own docstring). Nothing else in the app ever offers a
    manual re-check button, so setup_detect_due must eventually stop treating a 'running' state
    as still in flight, or this device is stuck until someone edits the database by hand."""
    client, settings, engine = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    rt = runtime.build(settings, engine)

    runtime.mark_setup_detect_running(rt, PHONE.udid)
    assert runtime.setup_detect_due(rt, PHONE.udid) is False  # a run is genuinely in flight

    # Simulate the crash: the worker never came back to write 'done' or 'failed', so the stored
    # state is still 'running', just old - rewrite only its timestamp, the one thing a real crash
    # would leave stale.
    stuck_since = (datetime.now(UTC) - runtime.SETUP_DETECT_STUCK_AFTER - timedelta(seconds=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    with conn_for(settings) as conn:
        db.set_setting(
            conn,
            f"setup_detect:{PHONE.udid}",
            f'{{"state": "running", "message": null, "updated_at": "{stuck_since}"}}',
        )

    assert runtime.setup_detect_due(rt, PHONE.udid) is True


def test_rate_limit_guard_is_real_broken_red_then_fixed_green(env, monkeypatch):
    """A guard that has never been red proves nothing. Disable
    runtime.setup_detect_due on purpose, see every poll re-detect (RED), then restore it and see
    the real cooldown collapse repeated polls again (GREEN)."""
    client, settings, engine = env
    add_unpaired_tablet_and_pair_it(client, settings)

    calls = []
    original = engine.detect_setup_state

    def spy(udid, on_pair_used=None):
        calls.append(udid)
        return original(udid, on_pair_used)

    monkeypatch.setattr(engine, "detect_setup_state", spy)

    import bioseasy.app as app_module

    monkeypatch.setattr(app_module, "setup_detect_due", lambda rt, udid: True)  # break the guard: RED
    client.get(f"/devices/{TABLET.udid}/setup/status")
    client.get(f"/devices/{TABLET.udid}/setup/status")
    client.get(f"/devices/{TABLET.udid}/setup/status")
    assert len(calls) == 3  # proves the guard, when disabled, lets every single poll through

    monkeypatch.setattr(app_module, "setup_detect_due", runtime.setup_detect_due)  # restore: GREEN
    calls.clear()
    client.get(f"/devices/{TABLET.udid}/setup/status")
    client.get(f"/devices/{TABLET.udid}/setup/status")
    # The RED phase's own last call just recorded "updated_at" = now, so the real cooldown is
    # freshly in effect: unlike the broken guard, the real one keeps every one of these polls
    # from re-detecting until SETUP_DETECT_COOLDOWN has actually passed.
    assert len(calls) == 0


# --- member access control still holds -----------------------------------------------------


def test_member_still_gets_404_on_a_foreign_devices_setup_routes(env):
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    assert client.get(f"/devices/{PHONE.udid}/setup").status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/setup/status").status_code == 404


# --- a succeeded backup is itself evidence (jobs.py) --------------------------------------------


def _run_status(connect, run_id):
    with closing(connect()) as conn:
        return conn.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()["status"]


def _run_and_wait(mgr, udid, connect):
    state = mgr.start(udid, "manual")
    wait_until(lambda: _run_status(connect, state.run_id) != "running")
    return _run_status(connect, state.run_id)


def _build_manager(dbpath, root, engine):
    def connect():
        return db.connect(dbpath)

    mgr = jobs.JobManager(
        connect,
        engine,
        root,
        lambda: storage.StorageCheck(True, []),
        mark_setup_confirmed=lambda udid, transport, encrypted: runtime.mark_setup_confirmed_from_backup(
            connect, udid, transport, encrypted
        ),
    )
    return mgr, connect


def test_succeeded_wifi_encrypted_backup_confirms_both_setup_steps(tmp_path):
    class _Engine:
        name = "demo"

        def backup(self, udid, target_root, on_progress, on_pair_used=None, on_transport=None):
            if on_transport:
                on_transport(Transport.WIFI)
            write_backup(target_root / udid, PHONE, encrypted=True)

    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    dbpath = data / "bioseasy.db"
    with closing(db.connect(dbpath)) as conn:
        db.migrate(conn)
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO devices (udid, name, owner_id, paired_at) VALUES (?, ?, ?, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, admin.id),
        )
    mgr, connect = _build_manager(dbpath, root, _Engine())
    assert _run_and_wait(mgr, PHONE.udid, connect) == "succeeded"
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["wifi_enabled_at"] is not None
    assert row["encryption_enabled_at"] is not None


def test_unencrypted_success_sets_only_wifi(tmp_path):
    class _Engine:
        name = "demo"

        def backup(self, udid, target_root, on_progress, on_pair_used=None, on_transport=None):
            if on_transport:
                on_transport(Transport.WIFI)
            write_backup(target_root / udid, PHONE, encrypted=False)

    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    dbpath = data / "bioseasy.db"
    with closing(db.connect(dbpath)) as conn:
        db.migrate(conn)
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO devices (udid, name, owner_id, paired_at) VALUES (?, ?, ?, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, admin.id),
        )
    mgr, connect = _build_manager(dbpath, root, _Engine())
    assert _run_and_wait(mgr, PHONE.udid, connect) == "succeeded"
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["wifi_enabled_at"] is not None
    assert row["encryption_enabled_at"] is None


# --- "Back up now" gives immediate feedback (app.py's backup_now) -------------------------------


def test_backup_now_shows_running_state_at_once(env):
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}")
    r = client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": token}, headers={"hx-request": "true"})
    assert r.status_code == 200
    # "Backup running" (the disabled button) is present for the whole run; the exact "Backup
    # started." wording only shows during the first, very short "starting" phase, and its own
    # timing is already covered by test_backup_progress.py's gated engine - asserting it here too
    # would make this test race the backup thread's own progress callback.
    assert "Backup running" in r.text


def test_backup_now_refuses_a_second_concurrent_start(env):
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)

    # Simulate a run already in flight - the same state mark_backup_starting itself would have
    # left behind.
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase, heartbeat_at) "
            "VALUES (?, 'manual', '2026-09-15T00:00:00Z', 'running', 'starting', '2026-09-15T00:00:00Z')",
            (PHONE.udid,),
        )
    token = csrf(client, f"/devices/{PHONE.udid}")
    r = client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": token}, headers={"hx-request": "true"})
    assert r.status_code == 200
    assert "already running" in r.text.lower()


def test_backup_now_non_htmx_path_also_shows_the_running_state(env):
    client, settings, engine = env
    re_add_phone_after_a_recreated_database(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}")
    r = client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{PHONE.udid}"
    # The run row was inserted synchronously before this redirect, so the very next page load
    # already reflects it - no waiting for the worker to dequeue the backup task.
    page = client.get(f"/devices/{PHONE.udid}").text
    assert "Backup running" in page


def test_pressing_back_up_now_also_refreshes_the_run_history(env):
    """ "Back up now" replaces only the status block, so the history below it stayed as it was: a
    run that had just failed was announced at the top while the table two centimetres lower still
    listed the last three as fine, until somebody reloaded. The history now travels with the swap.
    """
    client, settings, _engine = env
    re_add_phone_after_a_recreated_database(client, settings)

    response = client.post(
        f"/devices/{PHONE.udid}/backup",
        data={"csrf": csrf(client, f"/devices/{PHONE.udid}")},
        headers={"hx-request": "true"},
    )

    assert response.status_code == 200
    assert 'id="status"' in response.text
    assert 'id="recent-runs"' in response.text
    assert 'id="backup-on-disk"' in response.text
    assert response.text.count('hx-swap-oob="true"') == 2
