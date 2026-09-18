# SPDX-License-Identifier: GPL-3.0-or-later
"""The connectivity check (docs/setup.md) and the wizard's "device in a different network?"
fixed-address section: schema, access guard, and the htmx flow with the demo engine.
"""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import activity, auth, db, runtime
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE = DEMO_DEVICES[0]  # starts paired
PASSWORD = "correct horse battery"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    # No engine passed: create_app then builds one through runtime.make_engine, which wires
    # devices.host into DemoEngine's fixed_hosts the same way it wires Pmd3Engine's (runtime.py) -
    # passing a bare DemoEngine() instance here would leave fixed_hosts at its empty default and
    # every netcheck would see "no fixed address", regardless of what the wizard just saved.
    with TestClient(create_app(settings, huey_immediate=True), follow_redirects=False) as client:
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username="admin"):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def add_paired_phone(client, settings):
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


def device_row(settings, udid):
    with conn_for(settings) as conn:
        return conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()


# --- schema ------------------------------------------------------------------------------------


def test_netcheck_runs_table_exists(env):
    _client, settings = env
    with conn_for(settings) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
        conn.execute("SELECT udid, state, steps_json, started_at, updated_at FROM netcheck_runs")


# --- the wizard's fixed-address section ---------------------------------------------------------


def test_wizard_saves_a_fixed_address(env):
    client, settings = env
    add_paired_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(
        f"/devices/{PHONE.udid}/setup/host",
        data={"csrf": token, "host": "192.0.2.42"},
        headers={"hx-request": "true"},
    )
    assert r.status_code == 200
    assert "Address saved." in r.text
    assert device_row(settings, PHONE.udid)["host"] == "192.0.2.42"


def test_wizard_rejects_an_invalid_address(env):
    client, settings = env
    add_paired_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(
        f"/devices/{PHONE.udid}/setup/host",
        data={"csrf": token, "host": "https://example.com/"},
        headers={"hx-request": "true"},
    )
    assert r.status_code == 400
    assert "IP address or hostname" in r.text
    assert device_row(settings, PHONE.udid)["host"] is None


def test_wizard_empty_address_clears_it(env):
    client, settings = env
    add_paired_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    client.post(f"/devices/{PHONE.udid}/setup/host", data={"csrf": token, "host": "192.0.2.42"})
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    client.post(f"/devices/{PHONE.udid}/setup/host", data={"csrf": token, "host": ""})
    assert device_row(settings, PHONE.udid)["host"] is None


# --- the connectivity check itself --------------------------------------------------------------


def test_netcheck_without_a_fixed_address_shows_the_remediation_text(env):
    client, settings = env
    add_paired_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(f"/devices/{PHONE.udid}/netcheck", data={"csrf": token, "return_to": "setup"})
    assert r.status_code == 303
    row = None
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM netcheck_runs WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["state"] == "done"
    assert "different network" in row["steps_json"]


def test_netcheck_full_success_is_persisted_and_polled(env):
    client, settings = env
    add_paired_phone(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    client.post(f"/devices/{PHONE.udid}/setup/host", data={"csrf": token, "host": "192.0.2.9"})

    token = csrf(client, f"/devices/{PHONE.udid}/setup")
    r = client.post(
        f"/devices/{PHONE.udid}/netcheck",
        data={"csrf": token, "return_to": "setup"},
        headers={"hx-request": "true"},
    )
    assert r.status_code == 200
    assert "Heartbeat" in r.text
    assert "OK" in r.text

    r2 = client.get(f"/devices/{PHONE.udid}/netcheck/status?return_to=setup")
    assert r2.status_code == 200
    assert "Heartbeat" in r2.text

    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM netcheck_runs WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["state"] == "done"
    for secret_marker in ("fake", "EscrowBag", "HostPrivateKey"):
        assert secret_marker not in row["steps_json"]


def test_netcheck_shows_on_the_device_settings_page_too(env):
    client, settings = env
    add_paired_phone(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert "Connectivity check" in page
    assert "Run connectivity check" in page


# --- access control ------------------------------------------------------------------------------


def test_member_gets_404_on_a_foreign_devices_netcheck_routes(env):
    client, settings = env
    add_paired_phone(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")
    host_resp = client.post(f"/devices/{PHONE.udid}/setup/host", data={"csrf": token, "host": "192.0.2.9"})
    assert host_resp.status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/netcheck", data={"csrf": token}).status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/netcheck/status").status_code == 404


# --- The check shows up in the activity registry ------------------------------------------------


def _runtime_for(tmp_path, engine):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir(exist_ok=True)
    root.mkdir(exist_ok=True)
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with closing(db.connect(data / "bioseasy.db")) as conn:
        db.migrate(conn)
    return runtime.build(settings, engine), settings


def _finished(settings):
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        return activity.for_admin_finished(conn)


def test_a_connectivity_check_appears_in_the_activity_registry(tmp_path):
    """It runs in the worker and takes a while, so it belongs in the header's "what is running"
    popover like every other device operation. `activity.KINDS` listed `connectivity_check` from
    the start before anything ever registered one."""
    rt, settings = _runtime_for(tmp_path, DemoEngine(step_seconds=0))

    runtime.run_netcheck(rt, DEMO_DEVICES[0].udid)

    rows = _finished(settings)
    assert [r["kind"] for r in rows] == ["connectivity_check"]
    assert rows[0]["outcome"] == "succeeded"
    assert rows[0]["udid"] == DEMO_DEVICES[0].udid


def test_a_crashing_connectivity_check_is_recorded_as_failed(tmp_path):
    """The function catches its own exception and records a result row, so the `with` block
    returns normally - without an explicit outcome the registry would call that a success."""

    class Exploding(DemoEngine):
        def netcheck(self, udid, on_pair_used=None):
            raise RuntimeError("simulated device read failure")

    rt, settings = _runtime_for(tmp_path, Exploding(step_seconds=0))

    runtime.run_netcheck(rt, DEMO_DEVICES[0].udid)

    rows = _finished(settings)
    assert [r["outcome"] for r in rows] == ["failed"]
