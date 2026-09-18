# SPDX-License-Identifier: GPL-3.0-or-later
"""The header slogan, storage bar and activity indicator (src/bioseasy/app.py's
header_storage_context/header_activity_context, base.html, _activity_indicator.html)."""

import re
from contextlib import closing
from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from bioseasy import activity, auth, db, storage
from bioseasy import defaults as backup_defaults
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"


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


def header_html(page_text):
    match = re.search(r"<header\b.*?</header>", page_text, re.DOTALL)
    assert match, "no <header> on the page"
    return match.group(0)


def test_header_shows_slogan_next_to_wordmark(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    header = header_html(client.get("/").text)
    assert "Backup iOS easy" in header
    assert "bioseasy" in header


def test_storage_bar_shows_free_and_total_when_available(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    header = header_html(client.get("/").text)
    assert "free of" in header
    assert "Storage unavailable" not in header


def test_storage_bar_shows_unavailable_never_zero_when_root_is_missing(tmp_path):
    # A fresh app/cache, and a backup root that never existed (an unmounted network share looks
    # the same to shutil.disk_usage): DiskUsageCache.get() is a per-process, briefly-cached
    # value, so reusing the `env` fixture's client here could still read an earlier, valid answer
    # cached before the root went away.
    data, root = tmp_path / "data", tmp_path / "backups-never-created"
    data.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        with conn_for(settings) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
        login(client)
        header = header_html(client.get("/").text)
    assert "Storage unavailable" in header
    assert "0 Bytes" not in header
    assert "free of" not in header


def test_storage_bar_warns_below_the_low_space_threshold(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    fake_usage = storage.DiskUsage(free_bytes=5 * 2**30, total_bytes=100 * 2**30)
    with patch.object(storage.DiskUsageCache, "get", return_value=fake_usage):
        header = header_html(client.get("/").text)
    assert "Low space" in header
    assert 'class="storage-bar-text low"' in header or "storage-bar-text low" in header


def test_storage_bar_state_is_not_colour_alone(env):
    """docs/design.md: state is never carried by colour alone - the low-space state must also
    say so in words, not only through a CSS class."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    fake_usage = storage.DiskUsage(free_bytes=1 * 2**30, total_bytes=50 * 2**30)
    with patch.object(storage.DiskUsageCache, "get", return_value=fake_usage):
        header = header_html(client.get("/").text)
    assert "Low space" in header


def test_storage_bar_threshold_reads_the_configured_global_default(env):
    """storage.py used to carry its own LOW_SPACE_THRESHOLD_BYTES constant; the header now reads
    defaults.get_global_defaults instead, so a value the admin actually configured takes effect
    - proven here with a threshold that disagrees with the old 10 GiB constant in both directions
    would have shown "Low space"."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        current = backup_defaults.get_global_defaults(conn)
        backup_defaults.set_global_defaults(conn, replace(current, free_space_threshold_gb=2))
    login(client)
    # 5 GiB free trips the old hard-coded 10 GiB constant, but not the configured 2 GiB one.
    fake_usage = storage.DiskUsage(free_bytes=5 * 2**30, total_bytes=100 * 2**30)
    with patch.object(storage.DiskUsageCache, "get", return_value=fake_usage):
        header = header_html(client.get("/").text)
    assert "Low space" not in header


def test_activity_gear_is_present_but_not_spinning_with_nothing_running(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    header = header_html(client.get("/").text)
    assert 'id="activity-button"' in header
    assert "icon-gear spin" not in header
    # The popover's content is pre-rendered (so the JS toggle only has to flip visibility) but
    # stays hidden until the button is clicked.
    assert re.search(r'<div class="popover" id="activity-popover"[^>]*\bhidden\b', header)


def test_activity_button_is_keyboard_and_screen_reader_accessible(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    header = header_html(client.get("/").text)
    button = re.search(r'<button[^>]*id="activity-button"[^>]*>', header).group(0)
    assert 'aria-haspopup="true"' in button
    assert 'aria-expanded="false"' in button
    assert 'aria-controls="activity-popover"' in button
    assert "aria-label=" in button


def test_activity_fragment_lists_a_running_job(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    with activity.track(connect, "discovery"):
        page = client.get("/activity").text
    assert "spin" in page
    assert "Scanning for devices" in page


def test_activity_fragment_shows_no_running_jobs_when_idle(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    page = client.get("/activity").text
    assert "No running jobs" in page


def test_member_never_sees_another_owners_device_activity(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        owner_a = auth.create_user(conn, "alice", PASSWORD, "member")
        auth.create_user(conn, "bob", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAA', 'Alice iPhone', ?)", (owner_a.id,))

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    with activity.track(connect, "backup", udid="AAA"):
        login(client, "bob")
        page = client.get("/activity").text
        assert "No running jobs" in page
        client.post("/logout", data={"csrf": csrf(client, "/settings")})
        login(client, "alice")
        page = client.get("/activity").text
        assert "No running jobs" not in page


def test_gear_shows_check_badge_and_accessible_name_after_a_success(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    with activity.track(connect, "discovery"):
        pass  # succeeds on normal exit

    page = client.get("/activity").text
    assert "icon-gear spin" not in page
    assert "activity-badge-ok" in page
    button = re.search(r'<button[^>]*id="activity-button"[^>]*>', page).group(0)
    assert "finished" in button
    assert "Scanning for devices" in button


def test_gear_shows_warning_badge_and_word_after_a_failure(env):
    """docs/design.md: state is never colour alone - the failure must also be a word, and the
    badge shape must differ from the success one (triangle vs. circle, both plain assertions
    here since the accessible name is what a screen reader actually gets)."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    class Boom(Exception):
        pass

    try:
        with activity.track(connect, "backup"):
            raise Boom("engine unreachable")
    except Boom:
        pass

    page = client.get("/activity").text
    assert "icon-gear spin" not in page
    assert "activity-badge-warn" in page
    assert "activity-badge-ok" not in page
    button = re.search(r'<button[^>]*id="activity-button"[^>]*>', page).group(0)
    assert "Backup failed" in button
    assert "aria-label=" in button


def test_recently_finished_section_lists_outcome_and_detail(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    class Boom(Exception):
        pass

    try:
        with activity.track(connect, "backup"):
            raise Boom("engine unreachable")
    except Boom:
        pass

    page = client.get("/activity").text
    assert "Recently finished" in page
    assert "failed" in page
    assert "engine unreachable" in page


def test_event_id_changes_when_an_activity_starts_and_again_when_it_ends(env):
    """The toast script only compares this id against what it last saw (base.html); it has to
    change on start and change again (differently) on finish for the toast to fire twice."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    idle_id = re.search(r'data-event-id="([^"]*)"', client.get("/activity").text).group(1)
    assert idle_id == ""

    with activity.track(connect, "discovery"):
        running_id = re.search(r'data-event-id="([^"]*)"', client.get("/activity").text).group(1)
        assert running_id != idle_id
        assert running_id != ""

    finished_id = re.search(r'data-event-id="([^"]*)"', client.get("/activity").text).group(1)
    assert finished_id not in (idle_id, running_id)
    assert finished_id != ""


def test_member_never_sees_a_foreign_devices_finished_activity(env):
    """Same scoping proof as test_member_never_sees_another_owners_device_activity, for the
    'Recently finished' section - a foreign device's outcome must never leak into the popover,
    the toast text, or the accessible name."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        owner_a = auth.create_user(conn, "alice", PASSWORD, "member")
        auth.create_user(conn, "bob", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAA', 'Alice iPhone', ?)", (owner_a.id,))

    def connect():
        return db.connect(settings.data_dir / "bioseasy.db")

    with activity.track(connect, "backup", udid="AAA"):
        pass  # succeeds on normal exit, scoped to Alice's device

    login(client, "bob")
    page = client.get("/activity").text
    assert "Alice iPhone" not in page
    assert "activity-badge-ok" not in page
    assert "Nothing finished recently" in page

    client.post("/logout", data={"csrf": csrf(client, "/settings")})
    login(client, "alice")
    page = client.get("/activity").text
    assert "Alice iPhone" in page
    assert "activity-badge-ok" in page


def test_hidden_attribute_is_not_overridden_by_a_class_rule():
    """The popover's `hidden` attribute has to actually hide it.

    The gear's popover opened but could never be closed. Neither the server
    nor the script was at fault - both set `hidden` correctly. `.activity-indicator .popover` sets
    `display: grid`, and a two-class selector (0,2,0) outranks the browser's own
    `[hidden] { display: none }` (0,1,0), so the attribute was set and then ignored. One global
    rule in app.css settles it for every future use of `hidden` in this app, not just this popover.

    What this test can and cannot show: pytest has no CSS engine, so it checks that the rule is
    there, never that the cascade resolves as intended. The cascade itself was measured in a real
    browser the same day - `hidden = true` gave a computed `display` of "none", and two clicks on
    the gear took the popover from 256x141 px to 0x0. Remove the rule and this test goes red;
    weaken it in a subtler way and only a browser would catch it.
    """
    from bioseasy.app import WEB

    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    # Strip comments first. Without this, the search finds the `[hidden] { display: none }` quoted
    # in the comment above the rule - the browser's default, written there to explain the problem -
    # and judges that instead of the real declaration. It made this test red on its first run
    # against a stylesheet that was already correct, which would have invited "fixing" working CSS.
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rule = re.search(r"\[hidden\][^{]*\{([^}]*)\}", css)
    assert rule, "app.css has no [hidden] rule, so any class rule setting display silently wins over it"
    body = rule.group(1).replace(" ", "")
    assert "display:none" in body, f"[hidden] must set display:none, found: {rule.group(1).strip()}"
    assert "!important" in body, (
        "[hidden] needs !important to beat class rules that set display - .activity-indicator "
        ".popover has the higher specificity and would otherwise win"
    )
