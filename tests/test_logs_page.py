# SPDX-License-Identifier: GPL-3.0-or-later
"""GET /logs: admin-only. A member
gets 404, an admin sees stored warnings with a shortened device id and the traceback behind a
<details>, and the level/process/device filters narrow the list."""

from __future__ import annotations

import logging
import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
UDID = "00008103-001122334455667A"


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
    assert r.status_code == 303


def _log_a_warning(message="pairing failed for a device", udid=UDID, with_traceback=False):
    # create_app() (in the `env` fixture, run inside the TestClient context manager) already
    # installed logview.DBLogHandler on the "bioseasy" logger during lifespan startup - a plain
    # child logger call reaches it through normal propagation, the same as every real warning
    # jobs.py/runtime.py/etc. log today.
    logger = logging.getLogger("bioseasy.test_logs_page")
    if with_traceback:
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception(message)
    else:
        logger.warning("%s %s", message, udid[:8])


def test_member_gets_404(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    r = client.get("/admin/logs")
    assert r.status_code == 404


def test_admin_sees_a_stored_warning_with_shortened_udid(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (UDID, "Anna's iPhone"))
    _log_a_warning()
    login(client, "admin")
    page = client.get("/admin/logs").text
    # Scoped to <main>: the header's device switcher legitimately lists every device's full UDID
    # (an admin can already see it there and on /devices/<udid>), so the real claim - the log
    # row itself carries only the shortened form - has to be checked against the log table, not
    # the whole page.
    main = re.search(r"<main\b.*?</main>", page, re.DOTALL).group(0)
    assert "pairing failed for a device 00008103" in main
    assert "001122334455667A" not in main
    assert "Anna" in main  # the device name, resolved from the shortened udid


def test_admin_sees_traceback_behind_details(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    _log_a_warning(message="setup step failed", with_traceback=True)
    login(client, "admin")
    page = client.get("/admin/logs").text
    assert "<details>" in page
    assert "ValueError: boom" in page
    # The traceback text sits inside the <details>, not loose in the row.
    details = re.search(r"<details>.*?</details>", page, re.DOTALL).group(0)
    assert "ValueError: boom" in details


def test_filter_by_level_excludes_other_levels(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO log_entries (ts, process, logger, level, message) VALUES "
            "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'web', 'x', 'ERROR', 'an error happened')"
        )
        conn.execute(
            "INSERT INTO log_entries (ts, process, logger, level, message) VALUES "
            "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'web', 'x', 'WARNING', 'a warning happened')"
        )
    login(client, "admin")
    page = client.get("/admin/logs?level=ERROR").text
    assert "an error happened" in page
    assert "a warning happened" not in page


def test_filter_by_process_and_device(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO log_entries (ts, process, logger, level, message, udid) VALUES "
            "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'worker', 'x', 'WARNING', 'worker side issue', '00008103')"
        )
        conn.execute(
            "INSERT INTO log_entries (ts, process, logger, level, message, udid) VALUES "
            "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'web', 'x', 'WARNING', 'web side issue', '0000abcd')"
        )
    login(client, "admin")
    only_worker = client.get("/admin/logs?process=worker").text
    assert "worker side issue" in only_worker
    assert "web side issue" not in only_worker
    only_device = client.get("/admin/logs?device=0000abcd").text
    assert "web side issue" in only_device
    assert "worker side issue" not in only_device


def test_setup_token_warning_is_redacted_on_the_page(env):
    # app.py's own startup WARNING ("No admin account yet. Open /setup and use this token: ...",
    # nosemgrep-exempted there because the container log is its documented retrieval path) now
    # also reaches this page through the same handler as every other warning. Confirms the
    # redaction actually applies to a real call site, not only to the crafted strings in
    # test_logview.py.
    client, settings = env
    with conn_for(settings) as conn:
        token = auth.setup_token(settings.data_dir)
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/logs").text
    assert "No admin account yet" in page
    assert token not in page


def test_logs_page_has_no_entries_message_when_empty(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    # Not a plain GET /logs: app startup itself already logged one WARNING (app.py's "No admin
    # account yet" line, before this test created one), so it is filtered out here with a level
    # that line never uses - the empty state is real, not an artefact of what booted the app.
    page = client.get("/admin/logs?level=ERROR").text
    assert "No log entries match this filter" in page
