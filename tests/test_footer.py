# SPDX-License-Identifier: GPL-3.0-or-later
"""The footer carries the theme toggle, the version and the less frequent settings links.

The header nav lost the Theme button and the Settings link; both moved to the new footer.
"""

import importlib.metadata
import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

# Read, not written in: the version changes with every release, and a test pinned to the literal
# string broke on the move to 1.0.0 for no reason that had anything to do with the footer.
VERSION = importlib.metadata.version("bioseasy")

PASSWORD = "correct horse battery"


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


def footer_html(page_text):
    match = re.search(r"<footer\b.*?</footer>", page_text, re.DOTALL)
    assert match, "no <footer> on the page"
    return match.group(0)


def test_admin_sees_the_version_in_the_footer_and_nothing_admin_only(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    footer = footer_html(client.get("/").text)
    assert f"bioseasy {VERSION}" in footer
    # The footer carries the version and the Docs link and nothing admin-only: About moved into
    # the Admin section nav, Settings into the header before that.
    assert "/admin/about" not in footer
    assert "/admin/defaults" not in footer
    # The version stays plain text, never a link - and since About moved into the Admin section
    # nav, the footer holds no link to it at all any more.
    assert footer.count('href="/admin/about"') == 0


def test_member_sees_version_but_no_about(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    footer = footer_html(client.get("/").text)
    assert f"bioseasy {VERSION}" in footer
    assert "/admin/defaults" not in footer
    assert "/admin/about" not in footer
    # For a member the version is not a link.
    assert f'<a href="/admin/about">bioseasy {VERSION}</a>' not in footer


def test_signed_out_page_has_theme_button_but_no_version(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    page = client.get("/login").text
    footer = footer_html(page)
    assert 'id="theme"' in footer
    assert f"bioseasy {VERSION}" not in footer
    assert VERSION not in footer


def test_header_nav_has_overview_and_settings_but_no_theme_word(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/").text
    header = re.search(r"<header\b.*?</header>", page, re.DOTALL).group(0)
    assert "Theme" not in header
    # "Settings" in the header is the signed-in user's own account; everything
    # system-wide sits behind "Admin", which only an admin sees.
    assert re.search(r'href="/settings"[^>]*>Settings<', header)
    assert re.search(r'href="/admin"[^>]*>Admin<', header)
    # The primary items stay in the header.
    assert re.search(r'href="/"[^>]*>Overview<', header)
    assert re.search(r'href="/add"[^>]*>Add device<', header)
    # Storage, Logs and Users left the header for the Admin section nav, and the
    # "Account" entry became "Settings". Checked as the absence of the link, not of the word:
    # the header also carries the storage bar, which legitimately says "storage".
    assert not re.search(r'href="/admin/storage"', header)
    assert not re.search(r'href="/admin/logs"', header)
    assert ">Account<" not in header
    assert "Sign out" in header


def test_overview_link_has_aria_current_on_the_dashboard_only(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    dashboard_header = re.search(r"<header\b.*?</header>", client.get("/").text, re.DOTALL).group(0)
    assert re.search(r'href="/"[^>]*aria-current="page"[^>]*>Overview<', dashboard_header)
    account_header = re.search(r"<header\b.*?</header>", client.get("/settings").text, re.DOTALL).group(0)
    assert "aria-current" not in re.search(r'href="/"[^>]*>Overview<', account_header).group(0)


def test_member_sees_overview_but_no_admin_only_header_items(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    header = re.search(r"<header\b.*?</header>", client.get("/").text, re.DOTALL).group(0)
    assert re.search(r'href="/"[^>]*>Overview<', header)
    assert "/admin/defaults" not in header
    assert "/add" not in header
    assert "/admin/storage" not in header


def test_footer_shows_short_revision_with_full_sha_in_title_when_configured(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(
        data, root, "demo", "test-secret", False, 3600, revision="a1b2c3d4e5f6789012345678901234567890abcd"
    )
    with TestClient(create_app(settings, DemoEngine(step_seconds=0)), follow_redirects=False) as client:
        with conn_for(settings) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
        login(client, "admin")
        footer = footer_html(client.get("/").text)
    assert f"bioseasy {VERSION}" in footer
    assert re.search(r'title="a1b2c3d4e5f6789012345678901234567890abcd">\(a1b2c3d\)<', footer)


def test_footer_omits_revision_when_not_configured(env):
    client, settings = env
    assert settings.revision is None
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    footer = footer_html(client.get("/").text)
    assert f"bioseasy {VERSION}" in footer
    assert "(" not in footer.split(f"bioseasy {VERSION}", 1)[1].split("</span>")[0]


def test_theme_button_has_aria_label(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    footer = footer_html(client.get("/login").text)
    match = re.search(r'<button[^>]*id="theme"[^>]*>', footer)
    assert match and "aria-label=" in match.group(0)
