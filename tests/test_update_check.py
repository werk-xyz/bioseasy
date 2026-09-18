# SPDX-License-Identifier: GPL-3.0-or-later
"""update_check.py: off-by-default gating, the daily interval, version comparison, and that a
failed or timed-out check is stored and shown as "check failed", never as "up to date". Every
HTTP call here goes through httpx.MockTransport; nothing in this file touches the network.
"""

import re
from contextlib import closing
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, update_check
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"


def mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def releases_handler(tag_name: str, status_code: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "api.github.com/repos/" in str(request.url)
        assert request.headers.get("user-agent")  # GitHub requires one
        return httpx.Response(status_code, json={"tag_name": tag_name})

    return handler


def timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("connect timed out", request=request)


# --- Unit tests: gating, interval, version comparison ---


def test_parse_version_handles_a_leading_v_and_rejects_garbage():
    assert update_check._parse_version("v1.2.3") == (1, 2, 3)
    assert update_check._parse_version("1.2.3") == (1, 2, 3)
    assert update_check._parse_version("not-a-version") is None


@pytest.mark.parametrize(
    "latest,current,expected",
    [
        ("v1.2.0", "1.1.0", True),
        ("v1.1.0", "1.1.0", False),
        ("v1.0.0", "1.1.0", False),
        ("banana", "1.1.0", True),  # unparsable: falls back to "different string" = newer
        ("1.1.0", "1.1.0", False),
    ],
)
def test_is_newer(latest, current, expected):
    assert update_check._is_newer(latest, current) is expected


def test_should_check_is_false_when_repo_is_unset(tmp_path, monkeypatch):
    monkeypatch.setattr(update_check, "GITHUB_REPO", "")
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.set_enabled(conn, True)
    assert update_check.should_check(conn) is False


def test_should_check_is_false_when_admin_never_turned_it_on(tmp_path, monkeypatch):
    monkeypatch.setattr(update_check, "GITHUB_REPO", "example/bioseasy")
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    assert update_check.is_enabled(conn) is False
    assert update_check.should_check(conn) is False


def test_should_check_is_true_the_first_time_once_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(update_check, "GITHUB_REPO", "example/bioseasy")
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.set_enabled(conn, True)
    assert update_check.should_check(conn) is True


def test_should_check_is_false_right_after_a_check_and_true_a_day_later(tmp_path, monkeypatch):
    monkeypatch.setattr(update_check, "GITHUB_REPO", "example/bioseasy")
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.set_enabled(conn, True)
    now = datetime.now(UTC)
    update_check.run_check(conn, "1.0.0", now=now, client=mock_client(releases_handler("v1.0.0")))
    assert update_check.should_check(conn, now=now + timedelta(hours=1)) is False
    assert update_check.should_check(conn, now=now + timedelta(days=1, minutes=1)) is True


def test_run_check_stores_update_available_on_success(tmp_path):
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.run_check(conn, "1.0.0", client=mock_client(releases_handler("v2.0.0")))
    result = update_check.last_result(conn)
    assert result.ok is True
    assert result.latest_version == "v2.0.0"
    assert result.update_available is True


def test_run_check_on_timeout_is_stored_as_failed_never_as_up_to_date(tmp_path):
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.run_check(conn, "1.0.0", client=mock_client(timeout_handler))
    result = update_check.last_result(conn)
    assert result.ok is False
    assert result.error
    assert result.update_available is False


def test_run_check_on_http_error_status_is_stored_as_failed(tmp_path):
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    update_check.run_check(conn, "1.0.0", client=mock_client(releases_handler("v1.0.0", status_code=500)))
    result = update_check.last_result(conn)
    assert result.ok is False


# --- Route-level tests ---


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


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_settings_page_says_off_when_no_repo_is_configured(env, monkeypatch):
    """With GITHUB_REPO emptied - what a fork or a private build does - the Settings page must say
    the checker has nothing to check against, not offer a toggle that does nothing."""
    client, settings = env
    monkeypatch.setattr(update_check, "GITHUB_REPO", "")
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/update").text
    # Asserted on the meaning, not on one phrasing: the page has to tell the admin there is
    # nothing to check against, and must not render the toggle. The wording has changed before
    # ("has no GitHub repository configured" was the build talking about itself); this test broke
    # on the sentence while both facts it cares about were still true.
    assert "does not know where to look" in page
    assert 'name="enabled"' not in page


def test_toggling_update_check_requires_admin(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    r = client.post("/admin/update", data={"csrf": csrf(client, "/settings")})
    assert r.status_code == 404


def test_toggle_route_is_a_noop_while_repo_is_unset(env, monkeypatch):
    client, settings = env
    # Relied on the shipped default being empty until 1.0.0 set it; now the empty case is made
    # explicitly, the way a fork or private build would.
    monkeypatch.setattr(update_check, "GITHUB_REPO", "")
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    r = client.post("/admin/update", data={"csrf": csrf(client, "/admin/defaults"), "enabled": "1"})
    assert r.status_code == 303
    with conn_for(settings) as conn:
        assert update_check.is_enabled(conn) is False


def test_the_release_build_checks_the_published_repository():
    """1.0.0 is the first public release, so the shipped default names where it is published.
    Until then this was empty and the update check was dead code in every installation."""
    assert update_check.GITHUB_REPO == "werk-xyz/bioseasy"
