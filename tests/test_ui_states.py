# SPDX-License-Identifier: GPL-3.0-or-later
"""Every run status the database allows must render with a visible label.

A status without an entry in the label map does not raise in Jinja; it renders an empty label,
which is why these tests look for the word, not only for a 200.
"""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE = DEMO_DEVICES[0]
LABELS = {
    "running": "Running",
    "succeeded": "OK",
    "failed": "Failed",
    "not_confirmed": "Not confirmed",
    "cancelled": "Cancelled",
}


def test_schema_and_labels_agree():
    allowed = re.search(r"status TEXT NOT NULL CHECK \(status IN \(([^)]*)\)\)", db.SCHEMA).group(1)
    assert {s.strip(" '") for s in allowed.split(",")} == set(LABELS)


@pytest.mark.parametrize(("status", "label"), LABELS.items())
def test_every_run_status_renders_its_label(tmp_path, status, label):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        with closing(db.connect(data / "bioseasy.db")) as conn:
            auth.create_user(conn, "admin", "correct horse battery", "admin")
            conn.execute("INSERT INTO devices (udid, name) VALUES (?, ?)", (PHONE.udid, PHONE.name))
            conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, status) VALUES (?, 'manual', '2026-09-15T01:00:00Z', ?)",
                (PHONE.udid, status),
            )
        token = re.search(r'name="csrf" value="([^"]+)"', client.get("/login").text).group(1)
        client.post("/login", data={"csrf": token, "username": "admin", "password": "correct horse battery"})
        for url in ("/", f"/devices/{PHONE.udid}"):
            page = client.get(url)
            assert page.status_code == 200
            labels = re.findall(r'<span class="label">([^<]*)</span>', page.text)
            assert label in labels, (url, labels)


def test_device_page_is_navigable_without_sight(tmp_path):
    """Skip link, table captions, column scopes and named row buttons; checked on the markup."""
    data, root = tmp_path / "a11y-data", tmp_path / "a11y-backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(
        data, root, "demo", "test-secret", False, 3600, schedule_minutes=0, demo_seed=True, demo_autologin=True
    )
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        page = client.get(f"/devices/{PHONE.udid}").text
    assert '<a class="skip-link" href="#main">' in page and '<main id="main"' in page
    assert page.count("<table") == 3 and page.count("<caption") == 3
    # <th followed by whitespace or ">" only, so <thead> is not counted as a header cell.
    assert re.findall(r"<th(?=[\s>])(?![^>]*scope=)[^>]*>", page) == []
    # One pin/unpin button per demo generation (see demo_seed.py's generation_days_ago).
    buttons = re.findall(r"<button[^>]*>\s*(?:Pin|Unpin)\s*</button>", page)
    assert len(buttons) == 7 and all("aria-label=" in b for b in buttons)
