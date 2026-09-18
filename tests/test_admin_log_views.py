# SPDX-License-Identifier: GPL-3.0-or-later
"""The two views of GET /admin/logs: the free-text system log from
both processes, and the structured per-device application log across every owner.

tests/test_logs_page.py covers the system view and its admin-only guard; this file covers the
switch itself and the application view, including the one thing that distinguishes it from the
personal `/log` page - it is supposed to show every owner's events, and it may, because only an
admin reaches this route at all.
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
ALICE_DEVICE = "00008103-001122334455667A"
BOB_DEVICE = "00008103-00AABBCCDDEEFF12"


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


def seed(settings):
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        for udid, owner, name in (
            (ALICE_DEVICE, alice.id, "Alice iPhone"),
            (BOB_DEVICE, bob.id, "Bob iPad"),
        ):
            conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)", (udid, name, owner))
            conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) "
                "VALUES (?, 'schedule', ?, ?, 'succeeded', ?)",
                (udid, iso(), iso(), f"finished for {name}"),
            )
        conn.execute(
            "INSERT INTO snapshot_verifications (udid, snapshot_name, outcome, checked_at) "
            "VALUES (?, '2026-09-15', 'missing', ?)",
            (BOB_DEVICE, iso()),
        )
        conn.commit()


def test_the_system_view_is_the_default(env):
    client, settings = env
    seed(settings)
    login(client, "admin")

    page = client.get("/admin/logs").text
    assert 'href="/admin/logs?view=system" aria-current="page"' in page
    # The system log's own vocabulary is present, the application log's is not.
    assert "All (warning and above)" in page
    assert "Owner" not in re.search(r"<thead>.*?</thead>", page, re.DOTALL).group(0)


def test_the_application_view_shows_every_owners_events(env):
    """The point of this view: an admin sees all of it, with the owner named.

    A member never reaches this route - admin_user answers 404 - and their own `/log` page is
    scoped to their devices, which tests/test_user_log.py covers.
    """
    client, settings = env
    seed(settings)
    login(client, "admin")

    page = client.get("/admin/logs?view=application").text
    assert 'href="/admin/logs?view=application" aria-current="page"' in page
    for expected in ("Alice iPhone", "Bob iPad", "alice", "bob", "Files missing", "Generation check"):
        assert expected in page, expected


def test_the_application_view_can_be_narrowed_to_one_device(env):
    client, settings = env
    seed(settings)
    login(client, "admin")

    page = client.get(f"/admin/logs?view=application&device={BOB_DEVICE}").text
    body = re.search(r"<tbody>.*?</tbody>", page, re.DOTALL).group(0)
    assert "Bob iPad" in body
    assert "Alice iPhone" not in body


def test_the_application_view_can_be_narrowed_to_one_kind(env):
    client, settings = env
    seed(settings)
    login(client, "admin")

    page = client.get("/admin/logs?view=application&kind=verification").text
    body = re.search(r"<tbody>.*?</tbody>", page, re.DOTALL).group(0)
    assert "Generation check" in body
    assert "Backup" not in body


def test_an_unknown_view_falls_back_to_the_system_log(env):
    """A hand-edited query string must land on the safe, known view rather than an empty page or
    an error - the same allowlisting the level and process filters already use."""
    client, settings = env
    seed(settings)
    login(client, "admin")

    page = client.get("/admin/logs?view=nonsense").text
    assert 'href="/admin/logs?view=system" aria-current="page"' in page
    assert "All (warning and above)" in page


def test_a_member_reaches_neither_view(env):
    client, settings = env
    seed(settings)
    login(client, "alice")

    assert client.get("/admin/logs").status_code == 404
    assert client.get("/admin/logs?view=application").status_code == 404
