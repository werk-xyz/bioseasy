# SPDX-License-Identifier: GPL-3.0-or-later
"""The entry page must answer 200 without following redirects: a health or deployment probe
(`curl -w %{http_code} http://127.0.0.1:<port>/`) treats anything else as down."""

import re
from contextlib import closing

from fastapi.testclient import TestClient

from bioseasy import auth, db, demo_seed
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine


def _settings(tmp_path, **extra):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    return Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0, **extra)


def test_signed_out_entry_page_answers_200(tmp_path):
    settings = _settings(tmp_path)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        first = client.get("/")
        assert first.status_code == 200 and "Create the admin account" in first.text
        with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
            auth.create_user(conn, "admin", "correct horse battery", "admin")
        second = client.get("/")
        assert second.status_code == 200 and "Sign in" in second.text and "location" not in second.headers


def test_demo_seed_makes_the_sandbox_usable(tmp_path):
    settings = _settings(tmp_path, demo_seed=True)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        token = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text).group(1)
        r = client.post(
            "/login", data={"csrf": token, "username": demo_seed.DEMO_USER, "password": demo_seed.DEMO_PASSWORD}
        )
        assert r.status_code == 303
        page = client.get("/").text
        assert "Demo iPhone" in page and "Demo iPad" in page


def test_demo_seed_is_ignored_without_the_flag(tmp_path):
    settings = _settings(tmp_path)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        assert "Create the admin account" in client.get("/").text
