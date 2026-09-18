# SPDX-License-Identifier: GPL-3.0-or-later
"""The assisted setup wizard (docs/setup.md): a device's Wi-Fi, encryption and
first-backup steps after it is paired and added.
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
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE = DEMO_DEVICES[0]
TABLET = DEMO_DEVICES[1]
PASSWORD = "correct horse battery"
BACKUP_PASSWORD = "iphone-backup-pw"


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


def wait_for_pairing(settings, udid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with conn_for(settings) as conn:
            row = conn.execute("SELECT state FROM pairings WHERE udid = ?", (udid,)).fetchone()
        if row is not None and row["state"] in ("done", "failed"):
            return row["state"]
        time.sleep(0.02)
    raise AssertionError("pairing did not reach a terminal state in time")


def add_paired_phone(client, settings):
    """The phone is already paired in DEMO_DEVICES: the fast "Add" path, which lands straight on
    the setup wizard."""
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


def pair_and_add_tablet(client, settings):
    """The iPad starts unpaired in DEMO_DEVICES: the full "Pair and add" flow, so its setup
    wizard starts with every step open."""
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
    assert wait_for_pairing(settings, TABLET.udid) == "done"
    r = client.get(f"/add/pairing/{TABLET.udid}")
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{TABLET.udid}/setup"


# --- checklist rendering -------------------------------------------------------------------


def test_checklist_shows_the_open_steps_for_a_freshly_paired_device(env):
    client, settings = env
    pair_and_add_tablet(client, settings)

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert "1. Paired" in page and "Done" in page
    assert "Not enabled" in page  # step 2, Wi-Fi
    assert "Off" in page  # step 3, encryption
    assert "Not started" in page  # step 4, first backup
    assert "iPad" in page  # device_kind names the right product

    row = device_row(settings, TABLET.udid)
    assert row["wifi_enabled_at"] is None
    assert row["encryption_enabled_at"] is None
    # "Finish setup": the overview flags the same state, but as the way out of it
    # rather than as a diagnosis. What this asserts is unchanged - an unfinished device is called
    # out on the overview and links to its setup page.
    assert "Finish setup" in client.get("/").text
    assert "Setup incomplete" in client.get(f"/devices/{TABLET.udid}").text


def test_iphone_gets_iphone_copy(env):
    client, settings = env
    add_paired_phone(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/setup").text
    assert "iPhone" in page
    assert "iPad" not in page


# --- access control --------------------------------------------------------------------------


def test_member_gets_404_on_a_foreign_devices_setup_page(env):
    client, settings = env
    add_paired_phone(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")
    assert client.get(f"/devices/{PHONE.udid}/setup").status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/setup/status").status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/setup/wifi", data={"csrf": token}).status_code == 404
    assert (
        client.post(
            f"/devices/{PHONE.udid}/setup/encryption",
            data={"csrf": token, "password": "12345678", "password2": "12345678"},
        ).status_code
        == 404
    )


# --- the encryption password form -------------------------------------------------------------


def test_password_mismatch_is_a_400_with_a_field_message(env):
    client, settings = env
    pair_and_add_tablet(client, settings)
    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    r = client.post(
        f"/devices/{TABLET.udid}/setup/encryption",
        data={"csrf": token, "password": "abcdefgh", "password2": "different"},
    )
    assert r.status_code == 400
    assert "do not match" in r.text
    assert device_row(settings, TABLET.udid)["encryption_enabled_at"] is None


def test_password_too_short_is_a_400(env):
    client, settings = env
    pair_and_add_tablet(client, settings)
    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    r = client.post(
        f"/devices/{TABLET.udid}/setup/encryption",
        data={"csrf": token, "password": "short1", "password2": "short1"},
    )
    assert r.status_code == 400
    assert "at least 8" in r.text
    assert device_row(settings, TABLET.udid)["encryption_enabled_at"] is None


def test_password_never_appears_in_the_response_or_the_log(env, caplog):
    client, settings = env
    pair_and_add_tablet(client, settings)
    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    with caplog.at_level(logging.DEBUG):
        r = client.post(
            f"/devices/{TABLET.udid}/setup/encryption",
            data={"csrf": token, "password": BACKUP_PASSWORD, "password2": BACKUP_PASSWORD},
        )
        assert r.status_code == 200
        assert BACKUP_PASSWORD not in r.text
        wait_until(lambda: device_row(settings, TABLET.udid)["encryption_enabled_at"] is not None)
    assert BACKUP_PASSWORD not in caplog.text
    assert BACKUP_PASSWORD not in client.get(f"/devices/{TABLET.udid}/setup").text
    with conn_for(settings) as conn:
        queue_rows = conn.execute(
            "SELECT message FROM setup_actions WHERE udid = ? AND step = 'encryption'", (TABLET.udid,)
        ).fetchall()
    assert all(row["message"] is None or BACKUP_PASSWORD not in row["message"] for row in queue_rows)


def test_encryption_step_never_enqueues_through_huey_even_when_wifi_does(env, monkeypatch):
    # Wi-Fi uses the same background path as pairing and backups: a Huey task, enqueued through
    # app.state.huey (app.py's create_app). Encryption is the one exception - the setup wizard's
    # encryption step never runs through Huey - because queue.db is a
    # persistent file and the password must never be written to it. Spying on huey.enqueue
    # itself (not on a particular task function) proves this for any task that might exist, not
    # just the ones this test happens to know about.
    client, settings = env
    add_paired_phone(client, settings)  # the fast path: no engine.pair() call at all

    enqueued = []
    original_enqueue = client.app.state.huey.enqueue

    def spy(task):
        enqueued.append(task)
        return original_enqueue(task)

    monkeypatch.setattr(client.app.state.huey, "enqueue", spy)
    before = len(enqueued)

    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    client.post(f"/devices/{PHONE.udid}/setup/wifi", data={"csrf": token})
    assert len(enqueued) == before + 1  # the Wi-Fi step really did go through Huey
    wait_until(lambda: device_row(settings, PHONE.udid)["wifi_enabled_at"] is not None)

    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(
        f"/devices/{PHONE.udid}/setup/encryption",
        data={"csrf": token, "password": BACKUP_PASSWORD, "password2": BACKUP_PASSWORD},
    )
    assert r.status_code == 200
    assert len(enqueued) == before + 1  # unchanged: nothing was enqueued for it
    wait_until(lambda: device_row(settings, PHONE.udid)["encryption_enabled_at"] is not None)

    for task in enqueued:
        assert BACKUP_PASSWORD not in repr(task.args) and BACKUP_PASSWORD not in repr(task.kwargs)


# --- the full flow, end to end -----------------------------------------------------------------


def test_demo_flow_reaches_every_step_done(env):
    client, settings = env
    pair_and_add_tablet(client, settings)

    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    client.post(f"/devices/{TABLET.udid}/setup/wifi", data={"csrf": token})
    wait_until(lambda: device_row(settings, TABLET.udid)["wifi_enabled_at"] is not None)

    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    r = client.post(
        f"/devices/{TABLET.udid}/setup/encryption",
        data={"csrf": token, "password": BACKUP_PASSWORD, "password2": BACKUP_PASSWORD},
    )
    assert r.status_code == 200
    wait_until(lambda: device_row(settings, TABLET.udid)["encryption_enabled_at"] is not None)

    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    r = client.post(f"/devices/{TABLET.udid}/backup", data={"csrf": token})
    assert r.status_code == 303
    wait_until(lambda: "Backup running" not in client.get(f"/devices/{TABLET.udid}/status").text)

    page = client.get(f"/devices/{TABLET.udid}/setup").text
    assert "Setup complete" in page
    assert "Setup incomplete" not in client.get("/").text
    assert "Setup incomplete" not in client.get(f"/devices/{TABLET.udid}").text


def test_backup_before_encryption_is_refused_by_the_demo_engine_too(env):
    # The demo engine mirrors Pmd3Engine's own check (get_will_encrypt before backup), so trying
    # to skip the wizard's encryption step fails the same way it would against a real device.
    client, settings = env
    pair_and_add_tablet(client, settings)
    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    client.post(f"/devices/{TABLET.udid}/setup/wifi", data={"csrf": token})
    wait_until(lambda: device_row(settings, TABLET.udid)["wifi_enabled_at"] is not None)

    token = csrf(client, f"/devices/{TABLET.udid}/setup")
    client.post(f"/devices/{TABLET.udid}/backup", data={"csrf": token})
    wait_until(lambda: "Backup running" not in client.get(f"/devices/{TABLET.udid}/status").text)
    with conn_for(settings) as conn:
        run = conn.execute(
            "SELECT status, message FROM runs WHERE udid = ? ORDER BY started_at DESC LIMIT 1", (TABLET.udid,)
        ).fetchone()
    assert run["status"] == "failed"
    assert "encryption is off" in run["message"]
