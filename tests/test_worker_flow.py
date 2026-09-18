# SPDX-License-Identifier: GPL-3.0-or-later
"""Discovery, pairing and the tick lease, all off the request thread.

The Add page must never call engine.discover() or engine.pair() inside a
request handler (discovery is comparatively cheap but still real I/O; pairing can block for up
to 120s on the device's own Trust dialog), and a second worker ticking within the same interval
must be a no-op, not a double schedule run.
"""

import re
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.base import DeviceSeen, EngineError, Transport
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.runtime import build as build_runtime
from bioseasy.runtime import run_pairing
from bioseasy.ticker import acquire_tick_lease

PHONE = DEMO_DEVICES[0]
TABLET = DEMO_DEVICES[1]
PASSWORD = "correct horse battery"


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username=PASSWORD):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": "admin", "password": PASSWORD})
    assert r.status_code == 303


# --- tick lease ----------------------------------------------------------------------------


def test_acquire_tick_lease_prevents_a_double_tick(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
        interval = timedelta(minutes=5)
        assert acquire_tick_lease(conn, now, interval) is True
        # A second worker (or the same one, ticking again too soon) must be refused.
        assert acquire_tick_lease(conn, now, interval) is False
        assert acquire_tick_lease(conn, now + timedelta(minutes=1), interval) is False
        # Once the interval has genuinely elapsed, the lease is acquirable again.
        assert acquire_tick_lease(conn, now + timedelta(minutes=6), interval) is True


# --- pairing off the request -------------------------------------------------------------------


@pytest.fixture
def rt(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    runtime = build_runtime(settings, DemoEngine(step_seconds=0))
    with closing(runtime.connect()) as conn:
        db.migrate(conn)
    return runtime


def test_run_pairing_moves_pending_to_done_with_the_demo_engine(rt):
    with closing(rt.connect()) as conn:
        conn.execute(
            "INSERT INTO pairings (udid, state, message, updated_at) "
            "VALUES (?, 'pending', NULL, '2026-01-01T00:00:00Z')",
            (TABLET.udid,),
        )
    run_pairing(rt, TABLET.udid)
    with closing(rt.connect()) as conn:
        row = conn.execute("SELECT state, message FROM pairings WHERE udid = ?", (TABLET.udid,)).fetchone()
    assert row["state"] == "done"
    assert row["message"] is None


def _pair_used_at(rt, udid):
    with closing(rt.connect()) as conn:
        return conn.execute("SELECT pair_used_at FROM devices WHERE udid = ?", (udid,)).fetchone()["pair_used_at"]


def test_run_wifi_enable_marks_pair_used_at(rt):
    """runtime.run_wifi_enable's "Wi-Fi enable" trigger for devices.pair_used_at (db.py)."""
    with closing(rt.connect()) as conn:
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, NULL)", (PHONE.udid, PHONE.name))
    assert _pair_used_at(rt, PHONE.udid) is None
    from bioseasy.runtime import run_wifi_enable

    run_wifi_enable(rt, PHONE.udid)
    assert _pair_used_at(rt, PHONE.udid) is not None


def test_discover_marks_pair_used_at_for_the_paired_demo_device(rt):
    """discovery.discover_and_refresh's "successful discovery connection" trigger; only the
    already-paired demo phone counts, mirroring Pmd3Engine._wifi_lockdowns (only a device that
    authenticated with our stored record does)."""
    with closing(rt.connect()) as conn:
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, NULL)", (PHONE.udid, PHONE.name))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, NULL)", (TABLET.udid, TABLET.name))
    from bioseasy.discovery import discover_and_refresh

    discover_and_refresh(rt.connect, rt.engine, rt.mark_pair_used)
    assert _pair_used_at(rt, PHONE.udid) is not None  # PHONE starts paired in DEMO_DEVICES
    assert _pair_used_at(rt, TABLET.udid) is None  # TABLET does not


def test_a_failed_pairing_shows_its_message(rt):
    bogus = "00008888-BOGUSUDIDNOTINDEMO01"
    with closing(rt.connect()) as conn:
        conn.execute(
            "INSERT INTO pairings (udid, state, message, updated_at) "
            "VALUES (?, 'pending', NULL, '2026-01-01T00:00:00Z')",
            (bogus,),
        )
    run_pairing(rt, bogus)
    with closing(rt.connect()) as conn:
        row = conn.execute("SELECT state, message FROM pairings WHERE udid = ?", (bogus,)).fetchone()
    assert row["state"] == "failed"
    assert row["message"] == f"Device {bogus} is not reachable"


# --- the Add page: no engine.discover() in the request handler ---------------------------------


class RaisesOnDiscover(DemoEngine):
    """Same behaviour as DemoEngine except discover() proves it was never called synchronously
    from within a request: raising here turns a regression into a failing test, not a silent
    slow request."""

    def discover(self, on_pair_used=None):
        raise AssertionError("engine.discover() must not be called from a request handler")


@pytest.fixture
def env_no_discover(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(create_app(settings, RaisesOnDiscover(), huey_immediate=True), follow_redirects=False) as client:
        with conn_for(settings) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
            conn.execute(
                "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
                (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
            )
            conn.execute(
                "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, 0, '2026-09-15T00:00:00Z')",
                (TABLET.udid, TABLET.name, TABLET.product_type, TABLET.os_version, TABLET.transport.value),
            )
        yield client, settings


def test_add_page_never_calls_engine_discover(env_no_discover):
    client, settings = env_no_discover
    login(client)
    r = client.get("/add")
    assert r.status_code == 200
    assert PHONE.name in r.text
    assert TABLET.name in r.text


def test_add_submit_never_calls_engine_discover(env_no_discover):
    client, settings = env_no_discover
    login(client)
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303
    assert r.headers["location"] == f"/devices/{PHONE.udid}/setup"


def test_add_pair_start_never_calls_engine_discover(env_no_discover):
    # engine.pair() still runs, off the request, in a background thread; only discover() (the
    # call add_page and add_submit used to make) is forbidden here.
    client, settings = env_no_discover
    login(client)
    r = client.post("/add/pair", data={"csrf": csrf(client, "/add"), "udid": TABLET.udid})
    assert r.status_code == 303
    assert r.headers["location"] == f"/add/pairing/{TABLET.udid}"


# --- end-to-end pairing flow through the web routes ----------------------------


@pytest.fixture
def paired_env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        with conn_for(settings) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
            conn.execute(
                "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, 0, '2026-09-15T00:00:00Z')",
                (TABLET.udid, TABLET.name, TABLET.product_type, TABLET.os_version, TABLET.transport.value),
            )
            bogus = "00008888-BOGUSUDIDNOTINDEMO01"
            conn.execute(
                "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
                "VALUES (?, 'Ghost device', NULL, NULL, 'wifi', 0, '2026-09-15T00:00:00Z')",
                (bogus,),
            )
        yield client, settings, bogus


def _wait_for_pairing(settings, udid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with conn_for(settings) as conn:
            row = conn.execute("SELECT state FROM pairings WHERE udid = ?", (udid,)).fetchone()
        if row is not None and row["state"] in ("done", "failed"):
            return row["state"]
        time.sleep(0.02)
    raise AssertionError("pairing did not reach a terminal state in time")


def test_pairing_succeeds_and_the_status_poll_adds_the_device(paired_env):
    client, settings, _bogus = paired_env
    login(client)
    r = client.post("/add/pair", data={"csrf": csrf(client, "/add"), "udid": TABLET.udid})
    assert r.status_code == 303

    assert _wait_for_pairing(settings, TABLET.udid) == "done"

    status = client.get(f"/add/pairing/{TABLET.udid}/status")
    assert status.status_code == 200
    assert status.headers.get("hx-redirect") == f"/devices/{TABLET.udid}/setup"
    with conn_for(settings) as conn:
        row = conn.execute("SELECT owner_id FROM devices WHERE udid = ?", (TABLET.udid,)).fetchone()
    assert row is not None  # added by the status poll, with the requesting admin as owner


def test_pairing_finished_before_the_first_page_load_still_adds_the_device(paired_env):
    # Regression: the demo engine (and a fast real pairing) can finish before the browser's
    # first GET /add/pairing/{udid} ever lands. Only the htmx poll used to add the device, so a
    # pairing already 'done' at that first load showed "Opening the device page..." forever and
    # never actually added anything - caught by driving the real app in a browser, not by the
    # original version of this test suite, which only ever hit /status directly.
    client, settings, _bogus = paired_env
    login(client)
    r = client.post("/add/pair", data={"csrf": csrf(client, "/add"), "udid": TABLET.udid})
    assert r.status_code == 303

    assert _wait_for_pairing(settings, TABLET.udid) == "done"

    # The very first page load, after pairing already finished - no /status poll involved yet.
    page = client.get(f"/add/pairing/{TABLET.udid}")
    assert page.status_code == 303
    assert page.headers["location"] == f"/devices/{TABLET.udid}/setup"
    with conn_for(settings) as conn:
        row = conn.execute("SELECT owner_id FROM devices WHERE udid = ?", (TABLET.udid,)).fetchone()
    assert row is not None


def test_a_failed_pairing_shows_its_message_on_the_status_page(paired_env):
    client, settings, bogus = paired_env
    login(client)
    r = client.post("/add/pair", data={"csrf": csrf(client, "/add"), "udid": bogus})
    assert r.status_code == 303

    assert _wait_for_pairing(settings, bogus) == "failed"

    page = client.get(f"/add/pairing/{bogus}").text
    assert "Pairing failed" in page
    assert f"Device {bogus} is not reachable" in page
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM devices WHERE udid = ?", (bogus,)).fetchone() is None


def test_scan_now_populates_seen_devices_off_the_request(paired_env):
    client, settings, _bogus = paired_env
    login(client)
    r = client.post("/add/scan", data={"csrf": csrf(client, "/add")})
    assert r.status_code == 303
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with conn_for(settings) as conn:
            row = conn.execute("SELECT 1 FROM seen_devices WHERE udid = ?", (PHONE.udid,)).fetchone()
        if row is not None:
            break
        time.sleep(0.02)
    else:
        raise AssertionError("scan now did not populate seen_devices in time")


# --- discovery.refresh_seen_devices is a pure DB helper, worth its own direct check ------------


def test_refresh_seen_devices_upserts(tmp_path):
    from bioseasy.discovery import refresh_seen_devices

    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        devices = [DeviceSeen(PHONE.udid, Transport.WIFI, "First name", "iPhoneX", "18.0", paired=False)]
        refresh_seen_devices(conn, devices, "2026-01-01T00:00:00Z")
        row = conn.execute("SELECT * FROM seen_devices WHERE udid = ?", (PHONE.udid,)).fetchone()
        assert row["name"] == "First name" and row["paired"] == 0

        devices = [DeviceSeen(PHONE.udid, Transport.WIFI, "New name", "iPhoneX", "18.1", paired=True)]
        refresh_seen_devices(conn, devices, "2026-01-02T00:00:00Z")
        row = conn.execute("SELECT * FROM seen_devices WHERE udid = ?", (PHONE.udid,)).fetchone()
        assert row["name"] == "New name" and row["paired"] == 1 and row["last_seen_at"] == "2026-01-02T00:00:00Z"
        assert conn.execute("SELECT COUNT(*) FROM seen_devices").fetchone()[0] == 1


def test_engine_error_message_used_verbatim():
    # Guards the exact string run_pairing stores, since the web test above matches on it too.
    try:
        DemoEngine().pair("nonexistent")
    except EngineError as exc:
        assert str(exc) == "Device nonexistent is not reachable"
    else:
        raise AssertionError("expected EngineError")
