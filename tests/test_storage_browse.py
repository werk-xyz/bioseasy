# SPDX-License-Identifier: GPL-3.0-or-later
"""The storage browse route (GET /storage/browse, admin-only): listing, breadcrumbs, device name
lookup, path-traversal rejection and the cached-size display states.
"""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, browse, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
UDID = "00008030-001A2B3C4D5E6F7A"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    (root / UDID).mkdir()
    (root / UDID / "Manifest.db").write_bytes(b"m" * 42)
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    with TestClient(create_app(settings, DemoEngine(step_seconds=0)), follow_redirects=False) as client:
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303


def test_admin_sees_the_device_folder_with_its_human_name(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (UDID, "Anna's iPhone"))
    login(client, "admin")
    page = client.get("/admin/storage/browse").text
    assert UDID in page
    assert "Anna&#39;s iPhone" in page or "Anna's iPhone" in page


def test_breadcrumbs_reflect_the_current_path(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/storage/browse", params={"path": UDID}).text
    breadcrumbs = re.search(r'<ol class="breadcrumbs">.*?</ol>', page, re.DOTALL).group(0)
    assert "backups" in breadcrumbs
    assert UDID in breadcrumbs
    assert re.search(r'href="/admin/storage/browse"[^>]*>backups<', breadcrumbs)


def test_file_entry_shows_its_own_size_directly(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/storage/browse", params={"path": UDID}).text
    assert "Manifest.db" in page
    assert "42 Bytes" in page


@pytest.mark.parametrize("bad_path", ["..", "../data", "/etc/passwd", "%2e%2e/%2e%2e"])
def test_path_traversal_attempts_get_a_plain_404(env, bad_path):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    r = client.get("/admin/storage/browse", params={"path": bad_path})
    assert r.status_code == 404


def test_symlink_escape_gets_a_plain_404(env, tmp_path):
    client, settings = env
    outside = tmp_path / "outside-the-root"
    outside.mkdir()
    (settings.backup_root / "escape").symlink_to(outside)
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    r = client.get("/admin/storage/browse", params={"path": "escape"})
    assert r.status_code == 404


def test_member_gets_404_not_403(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    assert client.get("/admin/storage/browse").status_code == 404


def test_signed_out_is_redirected_not_shown_the_listing(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    r = client.get("/admin/storage/browse")
    assert r.status_code == 303


def test_storage_page_links_to_browse(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/storage").text
    assert re.search(r'href="/admin/storage/browse"', page)


def test_uncalculated_directory_shows_not_calculated_yet(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/storage/browse").text
    assert "not calculated yet" in page


def test_calculating_directory_shows_calculating_and_polls(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        browse.mark_calculating(conn, UDID)
    login(client, "admin")
    page = client.get("/admin/storage/browse").text
    assert "calculating" in page
    assert f'hx-get="/admin/storage/browse/size?path={UDID}"' in page
    assert 'hx-trigger="every 2s"' in page


def test_calculated_directory_shows_size_and_file_count(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        browse.store_size(conn, UDID, 12345, 3)
    login(client, "admin")
    page = client.get("/admin/storage/browse").text
    assert "12.3 kB" in page  # Jinja2's filesizeformat, decimal by default
    assert "3 files" in page


def test_recalculate_marks_calculating_and_is_csrf_protected(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    no_csrf = client.post("/admin/storage/browse/recalculate", data={"path": UDID})
    assert no_csrf.status_code == 403

    token = csrf(client, "/admin/storage/browse")
    r = client.post(
        "/admin/storage/browse/recalculate", data={"csrf": token, "path": UDID}, headers={"hx-request": "true"}
    )
    assert r.status_code == 200
    # The response reflects the "calculating" state set synchronously by the request, regardless
    # of how fast the background computation (started right after) finishes.
    assert "calculating" in r.text
