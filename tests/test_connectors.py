# SPDX-License-Identifier: GPL-3.0-or-later
import logging
import re
import stat
import threading
import traceback
from contextlib import closing

import apprise
import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, connectors, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE = DEMO_DEVICES[0]
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


def make_admin_with_device(client, settings):
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    login(client, "admin")
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303


EMAIL_FORM = {
    "label": "Family mail",
    "host": "smtp.example.com",
    "port": "587",
    "security": "starttls",
    "username": "alerts",
    "password": "p@ss:w/o#rd",
    "from_addr": "alerts@example.com",
    "to": "me@example.com\nyou@example.com",
}

TELEGRAM_FORM = {
    "label": "Phone Telegram",
    "bot_token": "123456789:AA-test-token_1",
    "chat_id": "@mychannel",
    "topic_id": "42",
}

APPRISE_FORM = {"label": "Raw webhook", "url": "json://localhost/webhook"}


# --- URL building: verified against the installed apprise package, see connectors.py ------------


def test_build_email_url_round_trips_through_apprise_with_special_password_characters():
    settings = {
        "host": "smtp.example.com",
        "port": 587,
        "security": "starttls",
        "username": "alerts",
        "from_addr": "alerts@example.com",
        "to": ["me@example.com", "you@example.com"],
    }
    password = "p@ss:w/o#rd"
    url = connectors.build_email_url(settings, password)
    assert password not in url  # never sitting unescaped in the URL's userinfo part

    service = apprise.Apprise()
    assert service.add(url)
    plugin = service[0]
    assert plugin.password == password
    assert plugin.user == "alerts"
    assert plugin.host == "smtp.example.com"
    assert plugin.port == 587
    assert plugin.secure_mode == "starttls"
    assert sorted(t[1] for t in plugin.targets) == ["me@example.com", "you@example.com"]
    assert plugin.from_addr[1] == "alerts@example.com"


def test_build_email_url_without_a_password_is_still_valid():
    settings = {
        "host": "smtp.example.com",
        "port": 25,
        "security": "none",
        "username": None,
        "from_addr": "alerts@example.com",
        "to": ["me@example.com"],
    }
    url = connectors.build_email_url(settings, None)
    service = apprise.Apprise()
    assert service.add(url)
    assert service[0].secure_mode == "insecure"


def test_build_telegram_url_round_trips_through_apprise():
    settings = {"chat_id": "@mychannel", "topic_id": 42}
    url = connectors.build_telegram_url(settings, "123456789:AA-test-token_1")
    assert "123456789:AA-test-token_1" not in url.split("/", 3)[-1]  # token stays out of the target segment

    service = apprise.Apprise()
    assert service.add(url)
    plugin = service[0]
    assert plugin.bot_token == "123456789:AA-test-token_1"
    assert plugin.targets == [("@mychannel", 42)]


def test_build_telegram_url_with_numeric_chat_and_no_topic():
    url = connectors.build_telegram_url({"chat_id": "-100123456789", "topic_id": None}, "1:token")
    service = apprise.Apprise()
    assert service.add(url)
    assert service[0].targets == [(-100123456789, None)]


def test_build_apprise_url_returns_the_raw_url_unchanged():
    assert connectors.build_apprise_url("apprise", {}, "json://localhost") == "json://localhost"


def test_build_apprise_url_without_a_secret_raises():
    with pytest.raises(ValueError):
        connectors.build_apprise_url("apprise", {}, None)
    with pytest.raises(ValueError):
        connectors.build_apprise_url("telegram", {"chat_id": "1", "topic_id": None}, None)


# --- form validation -------------------------------------------------------------------------


def test_validate_email_form_accepts_good_input():
    result = connectors.validate_email_form(EMAIL_FORM)
    assert result.errors == []
    assert result.settings["to"] == ["me@example.com", "you@example.com"]
    assert result.secret == "p@ss:w/o#rd"


def test_validate_email_form_rejects_bad_input():
    bad = dict(EMAIL_FORM, port="99999", from_addr="not-an-email", to="also not an email")
    result = connectors.validate_email_form(bad)
    assert any("port" in e.lower() for e in result.errors)
    assert any("From address" in e for e in result.errors)
    assert any("recipient" in e.lower() for e in result.errors)


def test_validate_telegram_form_rejects_bad_chat_id():
    bad = dict(TELEGRAM_FORM, chat_id="not valid")
    result = connectors.validate_telegram_form(bad)
    assert any("Chat id" in e for e in result.errors)


def test_validate_telegram_form_rejects_bad_bot_token_format():
    bad = dict(TELEGRAM_FORM, bot_token="not-a-token")
    result = connectors.validate_telegram_form(bad)
    assert any("Bot token" in e for e in result.errors)


def test_validate_apprise_form_rejects_bad_url():
    result = connectors.validate_apprise_form({"label": "x", "url": "not a url"})
    assert result.errors


# --- secrets at rest ---------------------------------------------------------------------------


def test_key_file_created_with_owner_only_permissions(tmp_path):
    key1 = connectors._load_key(tmp_path)
    mode = stat.S_IMODE((tmp_path / "connector.key").stat().st_mode)
    assert mode == 0o600
    key2 = connectors._load_key(tmp_path)  # a second call reuses the same key, not a new one
    assert key1 == key2


@pytest.mark.parametrize("attempt", range(10))
def test_concurrent_first_use_ends_with_one_key_for_everybody(tmp_path, attempt):
    """The web service and the worker can both create the key on first use."""
    barrier = threading.Barrier(8)
    keys, errors = [], []

    def first_use():
        try:
            barrier.wait(timeout=10)
            keys.append(connectors._load_key(tmp_path))
        except Exception:  # the full traceback, so a failure says where it happened
            errors.append(traceback.format_exc())

    threads = [threading.Thread(target=first_use, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert errors == []
    assert len(keys) == 8
    assert set(keys) == {(tmp_path / "connector.key").read_bytes()}
    assert [p.name for p in tmp_path.iterdir()] == ["connector.key"]  # no temp file left behind


def test_decrypt_without_a_key_file_fails_and_never_creates_one(tmp_path):
    ciphertext = connectors.encrypt_secret(tmp_path, "top secret value")
    (tmp_path / "connector.key").unlink()
    with pytest.raises(connectors.ConnectorSecretError):
        connectors.decrypt_secret(tmp_path, ciphertext)
    assert not (tmp_path / "connector.key").exists()


def test_encrypt_decrypt_round_trip(tmp_path):
    ciphertext = connectors.encrypt_secret(tmp_path, "top secret value")
    assert b"top secret value" not in ciphertext
    assert connectors.decrypt_secret(tmp_path, ciphertext) == "top secret value"


def test_email_connector_secret_is_encrypted_in_the_database(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    r = client.post(f"/devices/{PHONE.udid}/connectors/email", data={**EMAIL_FORM, "csrf": csrf(client, url)})
    assert r.status_code == 303

    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM notification_connectors WHERE kind = 'email'").fetchone()
    assert row is not None
    assert row["secret_ciphertext"] is not None
    assert b"p@ss:w/o#rd" not in row["secret_ciphertext"]
    assert connectors.decrypt_secret(settings.data_dir, row["secret_ciphertext"]) == "p@ss:w/o#rd"
    # Non-secret fields are stored as plain JSON: nothing secret belongs there.
    assert "smtp.example.com" in row["settings_json"]


def test_saved_secret_never_appears_in_the_settings_page_html_or_logs(env, caplog):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    with caplog.at_level(logging.DEBUG):
        r = client.post(f"/devices/{PHONE.udid}/connectors/email", data={**EMAIL_FORM, "csrf": csrf(client, url)})
        assert r.status_code == 303
        page = client.get(url).text
    assert "p@ss:w/o#rd" not in page
    assert "set; leave blank to keep it" in page  # the write-only placeholder, not the value
    for record in caplog.records:
        assert "p@ss:w/o#rd" not in record.getMessage()


# --- blank vs filled secret on edit --------------------------------------------------------------


def test_blank_secret_field_keeps_the_stored_secret_filled_field_replaces_it(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    client.post(f"/devices/{PHONE.udid}/connectors/telegram", data={**TELEGRAM_FORM, "csrf": csrf(client, url)})
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM notification_connectors WHERE kind = 'telegram'").fetchone()
    original_ciphertext = row["secret_ciphertext"]

    # Edit with the bot token field left blank: the stored secret must be unchanged.
    edit_url = f"/devices/{PHONE.udid}/connectors/{row['id']}/edit"
    r = client.post(
        edit_url,
        data={"csrf": csrf(client, url), "label": "Renamed", "bot_token": "", "chat_id": "@mychannel", "enabled": "1"},
    )
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM notification_connectors WHERE id = ?", (row["id"],)).fetchone()
    assert row["secret_ciphertext"] == original_ciphertext
    assert row["label"] == "Renamed"

    # Edit again with a new bot token: the stored secret must change.
    r = client.post(
        edit_url,
        data={
            "csrf": csrf(client, url),
            "label": "Renamed",
            "bot_token": "987654321:BB-new-token",
            "chat_id": "@mychannel",
            "enabled": "1",
        },
    )
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM notification_connectors WHERE id = ?", (row["id"],)).fetchone()
    assert row["secret_ciphertext"] != original_ciphertext
    assert connectors.decrypt_secret(settings.data_dir, row["secret_ciphertext"]) == "987654321:BB-new-token"


# --- validation errors return 400 with field messages --------------------------------------------


def test_invalid_connector_form_returns_400_with_field_messages(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    r = client.post(
        f"/devices/{PHONE.udid}/connectors/email",
        data={**EMAIL_FORM, "csrf": csrf(client, url), "from_addr": "not-an-email"},
    )
    assert r.status_code == 400
    assert "From address" in r.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM notification_connectors").fetchone() is None


def test_unknown_connector_kind_is_404(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    r = client.post(f"/devices/{PHONE.udid}/connectors/sms", data={"csrf": csrf(client, url), "label": "x"})
    assert r.status_code == 404


def test_telegram_requires_a_bot_token_on_creation(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    bad = dict(TELEGRAM_FORM, bot_token="")
    r = client.post(f"/devices/{PHONE.udid}/connectors/telegram", data={**bad, "csrf": csrf(client, url)})
    assert r.status_code == 400
    assert "Bot token is required" in r.text


# --- send test never talks to a real service ------------------------------------------------------


def test_connector_test_notification_never_sends_a_real_message(env, monkeypatch):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    client.post(f"/devices/{PHONE.udid}/connectors/apprise", data={**APPRISE_FORM, "csrf": csrf(client, url)})
    with conn_for(settings) as conn:
        row = conn.execute("SELECT id FROM notification_connectors WHERE kind = 'apprise'").fetchone()

    sent = {}

    def fake_send(urls, title, body):
        sent["urls"] = urls
        from bioseasy.notify import NotifyResult

        return NotifyResult(ok=True)

    monkeypatch.setattr("bioseasy.app.notify.send", fake_send)
    r = client.post(f"/devices/{PHONE.udid}/connectors/{row['id']}/test", data={"csrf": csrf(client, url)})
    assert r.status_code == 200
    assert "Test message sent" in r.text
    assert sent["urls"] == ["json://localhost/webhook"]


# --- ownership guards ------------------------------------------------------------------------


def test_member_cannot_see_or_change_a_foreign_devices_connectors(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    client.post(f"/devices/{PHONE.udid}/connectors/apprise", data={**APPRISE_FORM, "csrf": csrf(client, url)})
    with conn_for(settings) as conn:
        row = conn.execute("SELECT id FROM notification_connectors WHERE kind = 'apprise'").fetchone()
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")

    assert client.get(url).status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/connectors/email", data={**EMAIL_FORM, "csrf": token}).status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/connectors/{row['id']}/edit", data={"csrf": token}).status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/connectors/{row['id']}/delete", data={"csrf": token}).status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/connectors/{row['id']}/test", data={"csrf": token}).status_code == 404


def test_member_cannot_reach_admin_connectors(env):
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")

    assert client.get("/admin/defaults").status_code == 404
    assert client.post("/admin/notifications/connectors/email", data={**EMAIL_FORM, "csrf": token}).status_code == 404
    assert client.post("/admin/notifications/connectors/1/edit", data={"csrf": token}).status_code == 404
    assert client.post("/admin/notifications/connectors/1/delete", data={"csrf": token}).status_code == 404
    assert client.post("/admin/notifications/connectors/1/test", data={"csrf": token}).status_code == 404


def test_device_connector_route_404s_for_a_connector_belonging_to_another_device(env):
    # A second device's connector id must not be reachable through the first device's URL space,
    # even for the same admin: the ownership check is on (scope, udid), not only on the caller.
    client, settings = env
    make_admin_with_device(client, settings)
    other_udid = DEMO_DEVICES[1].udid
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, (SELECT id FROM users WHERE username = 'admin'))",
            (other_udid, "Other device"),
        )
    other_url = f"/devices/{other_udid}/settings"
    client.post(f"/devices/{other_udid}/connectors/apprise", data={**APPRISE_FORM, "csrf": csrf(client, other_url)})
    with conn_for(settings) as conn:
        other_row = conn.execute("SELECT id FROM notification_connectors WHERE udid = ?", (other_udid,)).fetchone()

    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(f"/devices/{PHONE.udid}/connectors/{other_row['id']}/edit", data={"csrf": token})
    assert r.status_code == 404


def test_admin_connector_routes_404_for_a_device_scoped_connector_id(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    client.post(f"/devices/{PHONE.udid}/connectors/apprise", data={**APPRISE_FORM, "csrf": csrf(client, url)})
    with conn_for(settings) as conn:
        row = conn.execute("SELECT id FROM notification_connectors WHERE scope = 'device'").fetchone()
    token = csrf(client, "/admin/defaults")
    assert client.post(f"/admin/notifications/connectors/{row['id']}/edit", data={"csrf": token}).status_code == 404
    assert client.post(f"/admin/notifications/connectors/{row['id']}/delete", data={"csrf": token}).status_code == 404


# --- csrf ----------------------------------------------------------------------------------------


def test_connector_routes_without_csrf_token_are_refused(env):
    client, settings = env
    make_admin_with_device(client, settings)
    client.get(f"/devices/{PHONE.udid}/settings")
    assert client.post(f"/devices/{PHONE.udid}/connectors/email", data=EMAIL_FORM).status_code == 403
    client.get("/admin/defaults")
    assert client.post("/admin/notifications/connectors/email", data=EMAIL_FORM).status_code == 403
