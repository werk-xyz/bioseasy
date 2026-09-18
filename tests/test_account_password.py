# SPDX-License-Identifier: GPL-3.0-or-later
"""Account page: changing the sign-in password (never the Apple ID, never a device's backup
encryption password - src/bioseasy/app.py's account_password_change)."""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
NEW_PASSWORD = "new correct horse battery"


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


def login(client, username="admin", password=PASSWORD):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": password})
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_wrong_current_password_is_rejected(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password",
        data={
            "csrf": token,
            "current_password": "totally wrong",
            "new_password": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )
    assert r.status_code == 400
    assert "Current password is wrong" in r.text
    # The old password still works; nothing was changed.
    with conn_for(settings) as conn:
        assert auth.authenticate(conn, "admin", PASSWORD) is not None
        assert auth.authenticate(conn, "admin", NEW_PASSWORD) is None


def test_mismatched_new_passwords_are_rejected(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password",
        data={"csrf": token, "current_password": PASSWORD, "new_password": NEW_PASSWORD, "new_password2": "different"},
    )
    assert r.status_code == 400
    assert "do not match" in r.text
    with conn_for(settings) as conn:
        assert auth.authenticate(conn, "admin", PASSWORD) is not None


def test_too_short_new_password_is_rejected(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password",
        data={"csrf": token, "current_password": PASSWORD, "new_password": "short", "new_password2": "short"},
    )
    assert r.status_code == 400
    assert "at least" in r.text


def test_successful_change_bumps_session_version_and_ends_other_sessions(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    # A second "session" (another browser) signed in with the old password.
    other = TestClient(client.app, follow_redirects=False)
    login(other)
    assert other.get("/settings").status_code == 200

    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password",
        data={
            "csrf": token,
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )
    assert r.status_code == 200
    assert "Password changed" in r.text

    # The browser that made the change stays signed in.
    assert client.get("/settings").status_code == 200
    # The other session is now signed out (current_user redirects to /login).
    r_other = other.get("/settings")
    assert r_other.status_code == 303
    assert r_other.headers["location"] == "/login"

    with conn_for(settings) as conn:
        assert auth.authenticate(conn, "admin", NEW_PASSWORD) is not None
        assert auth.authenticate(conn, "admin", PASSWORD) is None


def test_account_page_shows_password_section_for_a_local_user(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    page = client.get("/settings").text
    assert 'name="current_password"' in page
    assert "Apple ID" in page
    assert "backup encryption password" in page


def test_account_page_hides_password_form_for_an_oidc_only_user(env):
    """An OIDC-only account (password_hash NULL) never has this route reachable in a way that
    could succeed - auth.authenticate always fails against a NULL hash (the dummy-hash path) -
    but the page must also not show a form nobody can use. Log in first (setting session_version
    the session cookie relies on), then null the hash directly: this changes nothing about the
    already-signed-in session (session_version is untouched), the same way an admin removing a
    user's local password later would not have to sign them out to do it."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    with conn_for(settings) as conn:
        conn.execute("UPDATE users SET password_hash = NULL WHERE username = 'admin'")
    page = client.get("/settings").text
    assert 'name="current_password"' not in page
    assert "no local password to change" in page

    # The route itself agrees: even a forged, well-formed POST 404s instead of pretending to work.
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/password",
        data={"csrf": token, "current_password": "x", "new_password": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    assert r.status_code == 404
