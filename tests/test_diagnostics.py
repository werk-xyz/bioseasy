# SPDX-License-Identifier: GPL-3.0-or-later
"""The diagnostics report is meant to be pasted into a public issue, so every secret and every
personal detail planted in a realistic data directory here must stay out of it.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
from contextlib import closing
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from bioseasy import _diagnose, auth, connectors, db, defaults, diagnostics
from bioseasy.app import create_app
from bioseasy.config import Settings, load
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

UDID = "00008110-000A1B2C3D4E5F60"
FAKE_BOT_TOKEN = "123456789:AAFakeTelegramTokenPlantedByTest0000000"  # not a real credential
DEVICE_NAME = "Alice's iPhone"
SETUP_TOKEN_TEXT = "super-secret-setup-token-value"
SECRET_KEY_TEXT = "super-secret-cookie-signing-key"
PASSWORD = "correct horse battery"

# Every one of these must be absent from any diagnostics output, in any form (text or JSON).
SECRETS = (FAKE_BOT_TOKEN, SETUP_TOKEN_TEXT, SECRET_KEY_TEXT, DEVICE_NAME, UDID)


def plant_secrets(settings: Settings) -> None:
    """Populate a data directory the way a real, running instance would, secrets included."""
    (settings.data_dir / "setup_token").write_text(SETUP_TOKEN_TEXT)
    (settings.data_dir / "setup_token").chmod(0o600)
    (settings.data_dir / "secret_key").write_text(SECRET_KEY_TEXT)
    (settings.data_dir / "secret_key").chmod(0o600)

    pair_dir = settings.data_dir / "pair-records"
    pair_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = pair_dir / f"{UDID}.plist"
    record.write_bytes(b"<plist>fake pair record bytes; diagnostics must never open this file</plist>")
    record.chmod(0o600)

    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        db.migrate(conn)  # no-op if the schema is already current
        conn.execute(
            "INSERT INTO devices (udid, name, product_type, os_version, paired_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (UDID, DEVICE_NAME, "iPhone15,2", "18.6"),
        )
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) "
            "VALUES (?, 'manual', '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'succeeded', 'ok')",
            (UDID,),
        )
        conn.execute(
            "INSERT INTO sightings (udid, seen_at, transport) VALUES (?, '2026-01-01T00:00:00Z', 'wifi')",
            (UDID,),
        )
        # A connector's secret (here a Telegram bot token) lives encrypted at rest, but the plain
        # value passes through this same process on the way in; diagnostics must never see it.
        secret = connectors.encrypt_secret(settings.data_dir, FAKE_BOT_TOKEN)
        connectors.create_connector(
            conn,
            scope="device",
            udid=UDID,
            kind="telegram",
            label="Alice's Telegram",
            settings={"chat_id": "-100111111", "topic_id": None},
            secret_ciphertext=secret,
        )
        connectors.create_connector(
            conn,
            scope="admin",
            udid=None,
            kind="telegram",
            label="Admin Telegram",
            settings={"chat_id": "-100222222", "topic_id": None},
            secret_ciphertext=secret,
        )


def assert_no_secrets(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"leaked: {secret!r}"
    assert diagnostics.mask_udid(UDID) in text


# --- collect() / render_text() -----------------------------------------------------------------


@pytest.fixture
def settings(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    return Settings(data, root, "demo", "test-secret", False, 3600)


def test_collect_and_render_never_leak_planted_secrets(settings):
    plant_secrets(settings)
    connect = diagnostics.readonly_connector(settings.data_dir / "bioseasy.db")
    report = diagnostics.collect(settings, connect, None, discover=False)

    assert_no_secrets(json.dumps(report))
    assert_no_secrets(diagnostics.render_text(report))
    # The masked form is a genuine mask, not a truncated prefix that still identifies the device.
    assert report["devices"][0]["udid"] == "...4E5F60"
    assert report["devices"][0]["name"] == "set"


def test_json_report_is_actually_valid_json(settings):
    plant_secrets(settings)
    connect = diagnostics.readonly_connector(settings.data_dir / "bioseasy.db")
    report = diagnostics.collect(settings, connect, None, discover=False)
    # Round-trips without error; the CLI's --json path relies on this.
    assert json.loads(json.dumps(report))["devices"][0]["udid"] == "...4E5F60"


def test_discovery_masks_demo_devices_too(settings):
    connect = diagnostics.readonly_connector(settings.data_dir / "bioseasy.db")
    report = diagnostics.collect(settings, connect, DemoEngine(step_seconds=0), discover=True)
    text = diagnostics.render_text(report)
    for device in DEMO_DEVICES:
        assert device.udid not in text
        assert device.name not in text
        assert diagnostics.mask_udid(device.udid) in text


def test_missing_database_is_reported_and_never_created(settings):
    db_path = settings.data_dir / "bioseasy.db"
    assert not db_path.exists()
    connect = diagnostics.readonly_connector(db_path)
    report = diagnostics.collect(settings, connect, None, discover=False)
    assert report["database"] == {"present": False}
    assert "devices" not in report
    assert not db_path.exists()  # collect() must not create or migrate it
    assert "not found" in diagnostics.render_text(report)


def test_storage_check_drives_the_ok_flag(settings, monkeypatch):
    connect = diagnostics.readonly_connector(settings.data_dir / "bioseasy.db")

    failing = diagnostics.collect(settings, connect, None, discover=False)
    assert failing["storage"]["ok"] is False  # backup root was never initialised

    from bioseasy import storage as storage_mod

    root_id = storage_mod.initialise(settings.backup_root)
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        db.migrate(conn)
        db.set_setting(conn, "backup_root_id", root_id)
        # 0 GB required, same as test_jobs_storage.py, so free disk space never flakes this.
        defaults.set_global_defaults(conn, replace(defaults.get_global_defaults(conn), free_space_threshold_gb=0))
    passing = diagnostics.collect(settings, connect, None, discover=False)
    assert passing["storage"]["ok"] is True


# --- CLI (bioseasy diagnose), called directly, no subprocess -----------------------------------


def test_cli_diagnose_exit_code_matches_storage_state(tmp_path, monkeypatch, capsys):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    monkeypatch.setenv("BIOSEASY_DATA_DIR", str(data))
    monkeypatch.setenv("BIOSEASY_BACKUP_ROOT", str(root))
    monkeypatch.setenv("BIOSEASY_ENGINE", "demo")

    settings = load()
    plant_secrets(settings)

    assert _diagnose(discover=False, as_json=False) == 1  # storage root not initialised
    out = capsys.readouterr().out
    assert_no_secrets(out)

    from bioseasy import storage as storage_mod

    root_id = storage_mod.initialise(root)
    with closing(db.connect(data / "bioseasy.db")) as conn:
        db.set_setting(conn, "backup_root_id", root_id)
        defaults.set_global_defaults(conn, replace(defaults.get_global_defaults(conn), free_space_threshold_gb=0))
    assert _diagnose(discover=False, as_json=False) == 0
    assert_no_secrets(capsys.readouterr().out)


def test_cli_diagnose_json_mode_never_leaks_secrets(tmp_path, monkeypatch, capsys):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    monkeypatch.setenv("BIOSEASY_DATA_DIR", str(data))
    monkeypatch.setenv("BIOSEASY_BACKUP_ROOT", str(root))
    monkeypatch.setenv("BIOSEASY_ENGINE", "demo")

    settings = load()
    plant_secrets(settings)

    _diagnose(discover=False, as_json=True)
    out = capsys.readouterr().out
    json.loads(out)  # must be parseable
    assert_no_secrets(out)


def test_cli_diagnose_handles_a_missing_database(tmp_path, monkeypatch, capsys):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    monkeypatch.setenv("BIOSEASY_DATA_DIR", str(data))
    monkeypatch.setenv("BIOSEASY_BACKUP_ROOT", str(root))
    monkeypatch.setenv("BIOSEASY_ENGINE", "demo")

    _diagnose(discover=False, as_json=False)
    out = capsys.readouterr().out
    assert "not found" in out
    assert not (data / "bioseasy.db").exists()


# --- GET /about ----------------------------------------------------------------------------------


@pytest.fixture
def client_env(tmp_path):
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


def login(client, username):
    client.post("/login", data={"csrf": csrf(client, "/login"), "username": username, "password": PASSWORD})


def test_about_page_is_admin_only_and_never_leaks_a_secret(client_env):
    client, settings = client_env
    plant_secrets(settings)
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")

    login(client, "admin")
    r = client.get("/admin/about")
    assert r.status_code == 200
    # Scoped to the diagnostics content itself (<main>...</main>): base.html's shared device
    # switcher in the header already shows an admin the real name and UDID on every admin page
    # (as it does today on /settings and /storage too), which is expected and out of scope here.
    # What must never carry a secret is the report this page exists to let someone paste
    # elsewhere.
    # Attribute-tolerant: the main landmark carries id="main" for the skip link.
    main = re.search(r"<main\b[^>]*>(.*)</main>", r.text, re.DOTALL).group(1)
    assert_no_secrets(main)
    assert diagnostics.mask_udid(UDID) in main
    assert "iPhone15,2" in main  # the model is not sensitive and should still show up

    client.cookies.clear()
    login(client, "member")
    assert client.get("/admin/about").status_code == 404


def test_about_page_names_what_bioseasy_was_tested_with(client_env):
    client, settings = client_env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    r = client.get("/admin/about")
    assert r.status_code == 200
    text = r.text
    assert "Compatibility" in text
    assert "iPadOS 26.3.1" in text
    # The About page is a compatibility note, not an evidence trail: it names
    # the device and the versions, not what was measured when.
    assert "Not verified" not in text
    # The currently installed pymobiledevice3 version (package metadata), not only the one the
    # matrix row was tested against.
    assert importlib.metadata.version("pymobiledevice3") in text


def test_about_is_reachable_from_every_page_of_the_admin_area(client_env):
    client, settings = client_env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")

    login(client, "admin")
    # About left the footer for the Admin section nav: it is
    # diagnostics - versions and what it was tested with - not a link every page needs. What
    # matters is that an admin still reaches it from anywhere inside the area.
    assert 'href="/admin/about"' in client.get("/admin").text
    assert 'href="/admin/about"' in client.get("/admin/defaults").text
    assert client.get("/admin/about").status_code == 200


# --- the guard itself: masking really has to run ------------------------------------------------


def test_mask_udid_actually_masks(settings):
    # Regression pin: mask_udid must never return the input unchanged. This is the guard broken
    # on purpose during development (returning `udid` as-is) and confirmed to turn this test red
    # before being restored.
    masked = diagnostics.mask_udid(UDID)
    assert masked != UDID
    assert masked.endswith(UDID[-6:])
    assert UDID[:-6] not in masked
