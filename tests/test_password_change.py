# SPDX-License-Identifier: GPL-3.0-or-later
"""Changing the backup password of an already-encrypted device (docs/setup.md, "Changing the
backup password"): the device settings page's own "Backup password" section, run the same way as
the setup wizard's encryption step - a web-process thread, never Huey.
"""

import logging
import re
import time
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DEMO_WRONG_OLD_PASSWORD, DemoEngine

PHONE = DEMO_DEVICES[0]  # already paired and encrypted in the demo story
TABLET = DEMO_DEVICES[1]  # unpaired, unencrypted
PASSWORD = "correct horse battery"
OLD_BACKUP_PASSWORD = "old-iphone-backup-pw"
NEW_BACKUP_PASSWORD = "new-iphone-backup-pw"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


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


def add_paired_encrypted_phone(client, settings):
    """The phone is already paired; walk it through the wizard's encryption step so
    devices.encryption_enabled_at is set the same way it would be for a real device - the demo
    engine's own "starts encrypted" story (engine/demo.py) only affects engine.encryption_enabled(),
    never that column, which the "Backup password" section keys off."""
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
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(
        f"/devices/{PHONE.udid}/setup/encryption",
        data={"csrf": token, "password": OLD_BACKUP_PASSWORD, "password2": OLD_BACKUP_PASSWORD},
    )
    assert r.status_code == 200
    wait_until(lambda: device_row(settings, PHONE.udid)["encryption_enabled_at"] is not None)


def add_unencrypted_tablet(client, settings):
    """The iPad starts unpaired and unencrypted; add it through the fast Add path (skips
    pairing entirely, which this module does not need to exercise) so its device row exists."""
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (TABLET.udid, TABLET.name, TABLET.product_type, TABLET.os_version, TABLET.transport.value),
        )
    login(client)
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": TABLET.udid})
    assert r.status_code == 303


# --- form validation -------------------------------------------------------------------------


def test_new_password_mismatch_is_a_400_with_a_field_message(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(
        f"/devices/{PHONE.udid}/settings/password",
        data={
            "csrf": token,
            "old_password": OLD_BACKUP_PASSWORD,
            "new_password": "abcdefgh",
            "new_password2": "different",
        },
    )
    assert r.status_code == 400
    assert "do not match" in r.text


def test_new_password_too_short_is_a_400(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(
        f"/devices/{PHONE.udid}/settings/password",
        data={"csrf": token, "old_password": OLD_BACKUP_PASSWORD, "new_password": "short1", "new_password2": "short1"},
    )
    assert r.status_code == 400
    assert "at least 8" in r.text


def test_section_is_absent_and_change_refused_when_encryption_is_off(env):
    client, settings = env
    add_unencrypted_tablet(client, settings)
    page = client.get(f"/devices/{TABLET.udid}/settings").text
    assert "Backup password" not in page

    token = csrf(client, f"/devices/{TABLET.udid}/settings")
    r = client.post(
        f"/devices/{TABLET.udid}/settings/password",
        data={
            "csrf": token,
            "old_password": OLD_BACKUP_PASSWORD,
            "new_password": NEW_BACKUP_PASSWORD,
            "new_password2": NEW_BACKUP_PASSWORD,
        },
    )
    assert r.status_code == 400
    assert "turn on backup encryption" in r.text.lower()


# --- access control ---------------------------------------------------------------------------


def test_member_gets_404_on_a_foreign_devices_password_change(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")
    assert client.get(f"/devices/{PHONE.udid}/settings").status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/settings/password/status").status_code == 404
    assert (
        client.post(
            f"/devices/{PHONE.udid}/settings/password",
            data={
                "csrf": token,
                "old_password": OLD_BACKUP_PASSWORD,
                "new_password": NEW_BACKUP_PASSWORD,
                "new_password2": NEW_BACKUP_PASSWORD,
            },
        ).status_code
        == 404
    )


# --- passwords never leak ----------------------------------------------------------------------


def test_passwords_never_appear_in_response_log_db_or_huey(env, caplog, monkeypatch):
    client, settings = env
    add_paired_encrypted_phone(client, settings)

    enqueued = []
    original_enqueue = client.app.state.huey.enqueue

    def spy(task):
        enqueued.append(task)
        return original_enqueue(task)

    monkeypatch.setattr(client.app.state.huey, "enqueue", spy)

    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    with caplog.at_level(logging.DEBUG):
        r = client.post(
            f"/devices/{PHONE.udid}/settings/password",
            data={
                "csrf": token,
                "old_password": OLD_BACKUP_PASSWORD,
                "new_password": NEW_BACKUP_PASSWORD,
                "new_password2": NEW_BACKUP_PASSWORD,
            },
        )
        assert r.status_code == 200
        assert OLD_BACKUP_PASSWORD not in r.text and NEW_BACKUP_PASSWORD not in r.text

        def done():
            with conn_for(settings) as conn:
                row = conn.execute(
                    "SELECT state FROM setup_actions WHERE udid = ? AND step = 'password_change'", (PHONE.udid,)
                ).fetchone()
            return row is not None and row["state"] == "done"

        wait_until(done)

    assert OLD_BACKUP_PASSWORD not in caplog.text and NEW_BACKUP_PASSWORD not in caplog.text
    page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert OLD_BACKUP_PASSWORD not in page and NEW_BACKUP_PASSWORD not in page
    assert len(enqueued) == 0  # nothing was ever enqueued for the password change
    for task in enqueued:
        assert OLD_BACKUP_PASSWORD not in repr(task.args) and NEW_BACKUP_PASSWORD not in repr(task.args)

    with conn_for(settings) as conn:
        # The whole database, not just the obvious columns: a password must not have landed
        # anywhere by accident.
        dump = "\n".join(conn.iterdump())
    assert OLD_BACKUP_PASSWORD not in dump and NEW_BACKUP_PASSWORD not in dump


# --- demo engine: success and wrong-old-password paths ----------------------------------------


def test_demo_flow_changes_the_password_and_shows_success(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)

    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(
        f"/devices/{PHONE.udid}/settings/password",
        data={
            "csrf": token,
            "old_password": OLD_BACKUP_PASSWORD,
            "new_password": NEW_BACKUP_PASSWORD,
            "new_password2": NEW_BACKUP_PASSWORD,
        },
    )
    assert r.status_code == 200

    def done():
        with conn_for(settings) as conn:
            row = conn.execute(
                "SELECT state FROM setup_actions WHERE udid = ? AND step = 'password_change'", (PHONE.udid,)
            ).fetchone()
        return row is not None and row["state"] == "done"

    wait_until(done)
    page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert "Backup password changed" in page
    assert "does not keep it" in page
    assert "Run the password check again" in page


def test_wrong_old_password_is_a_recorded_failure_not_a_crash(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)

    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(
        f"/devices/{PHONE.udid}/settings/password",
        data={
            "csrf": token,
            "old_password": DEMO_WRONG_OLD_PASSWORD,
            "new_password": NEW_BACKUP_PASSWORD,
            "new_password2": NEW_BACKUP_PASSWORD,
        },
    )
    assert r.status_code == 200  # accepted for background processing, like the encryption step

    def failed():
        with conn_for(settings) as conn:
            row = conn.execute(
                "SELECT state, message FROM setup_actions WHERE udid = ? AND step = 'password_change'", (PHONE.udid,)
            ).fetchone()
        return row is not None and row["state"] == "failed"

    wait_until(failed)
    with conn_for(settings) as conn:
        row = conn.execute(
            "SELECT message FROM setup_actions WHERE udid = ? AND step = 'password_change'", (PHONE.udid,)
        ).fetchone()
    assert row["message"] == "The current backup password is not correct"
    page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert "The current backup password is not correct" in page


# --- password-check reminder reset --------------------------------------------------------------


def test_successful_change_resets_the_password_check_reminder(env):
    client, settings = env
    add_paired_encrypted_phone(client, settings)

    # A finished backup is needed for the password-check endpoint to have something to read, but
    # what matters here is only the devices row, which this test writes directly to simulate an
    # existing confirmed check.
    with conn_for(settings) as conn:
        conn.execute(
            "UPDATE devices SET password_checked_at = '2026-09-01T00:00:00Z', password_check_result = 'correct' "
            "WHERE udid = ?",
            (PHONE.udid,),
        )
    row = device_row(settings, PHONE.udid)
    assert row["password_checked_at"] is not None
    assert row["password_check_result"] == "correct"

    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    client.post(
        f"/devices/{PHONE.udid}/settings/password",
        data={
            "csrf": token,
            "old_password": OLD_BACKUP_PASSWORD,
            "new_password": NEW_BACKUP_PASSWORD,
            "new_password2": NEW_BACKUP_PASSWORD,
        },
    )

    wait_until(lambda: device_row(settings, PHONE.udid)["password_checked_at"] is None)
    row = device_row(settings, PHONE.udid)
    assert row["password_checked_at"] is None
    assert row["password_check_result"] is None
