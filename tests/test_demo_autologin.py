# SPDX-License-Identifier: GPL-3.0-or-later
"""Automatic demo sign-in must work in a demo deployment and nowhere else."""

import pytest
from fastapi.testclient import TestClient

from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine


def _client(tmp_path, engine="demo", seed=True, autologin=True):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(
        data, root, engine, "test-secret", False, 3600, schedule_minutes=0, demo_seed=seed, demo_autologin=autologin
    )
    return TestClient(create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False)


def test_sandbox_visitor_lands_signed_in(tmp_path):
    with _client(tmp_path) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "Demo iPhone" in page.text and "Sign out" in page.text
        assert "signed in automatically" in page.text
        assert client.get("/admin/storage").status_code == 200


@pytest.mark.parametrize(
    ("engine", "seed", "autologin"),
    [("pymobiledevice3", True, True), ("demo", False, True), ("demo", True, False)],
)
def test_autologin_stays_off_unless_all_switches_are_set(tmp_path, engine, seed, autologin):
    with _client(tmp_path, engine=engine, seed=seed, autologin=autologin) as client:
        page = client.get("/")
        assert "Sign out" not in page.text
        assert "signed in automatically" not in page.text
        assert client.get("/admin/storage").status_code == 303
