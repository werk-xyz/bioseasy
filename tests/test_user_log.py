# SPDX-License-Identifier: GPL-3.0-or-later
"""GET /log: the signed-in user's own device events.

tests/test_events.py covers the query module's scope directly. This file covers the same rule one
level up, through HTTP, because that is where it would actually be broken: a route that forgets to
pass the owner id, a filter that reaches past it, or a page that quietly shows an admin everything
because they are an admin. The route has no admin branch at all - it always scopes to the signed-in
user - and the last test here is what says so.
"""

from __future__ import annotations

import re
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
MINE = "00008103-001122334455667A"
YOURS = "00008103-00AABBCCDDEEFF12"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303


def iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_two_users_with_a_device_each(settings):
    """One member with a device and a finished backup, one other user with the same, so every
    test below has a foreign device to fail to reach."""
    with conn_for(settings) as conn:
        mine = auth.create_user(conn, "member", PASSWORD, "member")
        yours = auth.create_user(conn, "other", PASSWORD, "member")
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        for udid, owner, name in ((MINE, mine.id, "My iPhone"), (YOURS, yours.id, "Their iPad")):
            conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)", (udid, name, owner))
            conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) "
                "VALUES (?, 'schedule', ?, ?, 'failed', ?)",
                (udid, iso(), iso(), f"secret detail about {name}"),
            )
        conn.commit()
        return mine, yours, admin


def test_a_member_sees_their_own_events_and_not_another_owners(env):
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    login(client, "member")

    page = client.get("/log").text
    assert "My iPhone" in page
    assert "secret detail about My iPhone" in page
    assert "Their iPad" not in page
    assert "secret detail about Their iPad" not in page


def test_the_device_filter_cannot_reach_a_foreign_device(env):
    """Asking for another owner's device by its UDID returns an empty page, not that device.

    A 200 with nothing in it is the right answer here rather than a 404: the member is allowed on
    this page, they simply have no event matching that filter. What matters is that no data and no
    device name crosses over.
    """
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    login(client, "member")

    response = client.get(f"/log?device={YOURS}")
    assert response.status_code == 200
    assert "Their iPad" not in response.text
    assert "secret detail about Their iPad" not in response.text


def test_the_device_filter_offers_only_the_members_own_devices(env):
    """The select must not name a foreign device either - a filter list is a disclosure too."""
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    login(client, "member")

    page = client.get("/log").text
    select = re.search(r'<select name="device".*?</select>', page, re.DOTALL).group(0)
    assert MINE in select
    assert YOURS not in select


def test_an_admin_log_page_is_personal_too(env):
    """The route has no admin branch: an admin opening /log sees their own devices, which here is
    none at all. The system-wide view is /admin/logs, deliberately somewhere else."""
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    login(client, "admin")

    page = client.get("/log").text
    assert "Nothing has happened to your devices yet." in page
    # Asserted on the event detail, not on the device names: an admin's header carries the device
    # switcher listing every device, which is long-standing and correct - an admin may see every
    # device. What must not appear is another owner's event on this personal page.
    assert "secret detail about My iPhone" not in page
    assert "secret detail about Their iPad" not in page
    assert '<table class="runs">' not in page


def test_a_running_backup_does_not_show_up_as_an_event(env):
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    with conn_for(settings) as conn:
        conn.execute("DELETE FROM runs")
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status) VALUES (?, 'manual', ?, 'running')",
            (MINE, iso()),
        )
        conn.commit()
    login(client, "member")

    assert "Nothing has happened to your devices yet." in client.get("/log").text


def test_the_log_is_in_the_main_navigation_for_a_member(env):
    client, settings = env
    seed_two_users_with_a_device_each(settings)
    login(client, "member")

    header = re.search(r"<header\b.*?</header>", client.get("/").text, re.DOTALL).group(0)
    assert 'href="/log"' in header
    # The system-wide log stays out of a member's header, as it always has.
    assert 'href="/admin/logs"' not in header


def test_signed_out_visitors_are_sent_to_login(env):
    client, settings = env
    seed_two_users_with_a_device_each(settings)

    response = client.get("/log")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
