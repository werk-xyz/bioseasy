# SPDX-License-Identifier: GPL-3.0-or-later
import re
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, mqtt
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.ticker import Ticker

PHONE = DEMO_DEVICES[0]
PASSWORD = "correct horse battery"

STATUS_PUBLIC = {
    "udid": "00008030-001A2B3C4D5E6F00",
    "name": "Anna's iPhone",
    "model": "iPhone14,2",
    "os_version": "17.5",
    "state": "overdue",
    "last_success_at": "2026-09-10T08:00:00Z",
    "next_due_at": "2026-09-11T08:00:00Z",
    "last_run_status": "succeeded",
    "last_run_at": "2026-09-10T08:00:00Z",
    "progress_percent": None,
    "backup_complete": True,
    "encrypted": True,
    "pair_days_unused": 3,
}


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


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


MQTT_FORM = {
    "mqtt_enabled": "1",
    "host": "mqtt.example.com",
    "port": "1883",
    "username": "bioseasy",
    "password": "s3cr3t-broker-pw",  # pragma: allowlist secret - test fixture, not a real broker
    "base_topic": "bioseasy",
    "discovery_prefix": "homeassistant",
}


# --- topic and payload builders: pure functions --------------------------------------------------


def test_device_id_is_stable_and_not_the_udid():
    dev_id = mqtt.device_id(STATUS_PUBLIC["udid"])
    assert dev_id == mqtt.device_id(STATUS_PUBLIC["udid"])
    assert len(dev_id) == 12
    assert STATUS_PUBLIC["udid"] not in dev_id
    assert dev_id != STATUS_PUBLIC["udid"]


def test_topics_are_built_under_the_configured_base_and_prefix():
    assert mqtt.availability_topic("bioseasy") == "bioseasy/status"
    dev_id = mqtt.device_id(STATUS_PUBLIC["udid"])
    assert mqtt.state_topic("bioseasy", dev_id) == f"bioseasy/device/{dev_id}/state"
    expected = f"homeassistant/sensor/{dev_id}_status/config"
    assert mqtt.discovery_topic("homeassistant", "sensor", dev_id, "status") == expected


def test_state_payload_drops_the_udid_and_adds_a_fresh_age():
    now = datetime(2026, 9, 15, 8, 0, tzinfo=UTC)
    payload = mqtt.state_payload(STATUS_PUBLIC, now)
    assert "udid" not in payload
    assert payload["state"] == "overdue"
    assert payload["age_hours"] == pytest.approx(5 * 24, abs=0.1)


def test_state_payload_age_is_none_without_a_last_success():
    payload = mqtt.state_payload({**STATUS_PUBLIC, "last_success_at": None}, datetime.now(UTC))
    assert payload["age_hours"] is None


def test_discovery_configs_for_one_device():
    dev_id = mqtt.device_id(STATUS_PUBLIC["udid"])
    entries = mqtt.discovery_configs("bioseasy", "homeassistant", dev_id, STATUS_PUBLIC)
    by_topic = dict(entries)
    assert len(entries) == 4

    status_cfg = by_topic[f"homeassistant/sensor/{dev_id}_status/config"]
    assert status_cfg["unique_id"] == f"{dev_id}_status"
    assert "device_class" not in status_cfg  # deliberately plain text, see mqtt.py docstring
    assert status_cfg["state_topic"] == f"bioseasy/device/{dev_id}/state"
    assert status_cfg["availability_topic"] == "bioseasy/status"
    assert status_cfg["device"]["identifiers"] == [dev_id]
    assert status_cfg["device"]["model"] == STATUS_PUBLIC["model"]

    last_success_cfg = by_topic[f"homeassistant/sensor/{dev_id}_last_success/config"]
    assert last_success_cfg["device_class"] == "timestamp"

    age_cfg = by_topic[f"homeassistant/sensor/{dev_id}_age_hours/config"]
    assert age_cfg["unit_of_measurement"] == "h"

    overdue_cfg = by_topic[f"homeassistant/binary_sensor/{dev_id}_overdue/config"]
    assert overdue_cfg["device_class"] == "problem"

    # Never the UDID anywhere in a discovery payload.
    for _, payload in entries:
        assert STATUS_PUBLIC["udid"] not in str(payload)


# --- form validation ------------------------------------------------------------------------------


def test_validate_form_accepts_the_defaults():
    result = mqtt.validate_form({"host": "mqtt.example.com", "port": "1883"})
    assert result.errors == []
    assert result.settings["base_topic"] == mqtt.DEFAULT_BASE_TOPIC
    assert result.settings["discovery_prefix"] == mqtt.DEFAULT_DISCOVERY_PREFIX


def test_validate_form_rejects_a_bad_port():
    result = mqtt.validate_form({"host": "mqtt.example.com", "port": "70000"})
    assert any("port" in e.lower() for e in result.errors)


def test_validate_form_requires_a_host_only_when_enabled():
    disabled = mqtt.validate_form({"host": "", "port": "1883"})
    assert disabled.errors == []

    enabled = mqtt.validate_form({"mqtt_enabled": "1", "host": "", "port": "1883"})
    assert any("host" in e.lower() for e in enabled.errors)


def test_validate_form_rejects_unsafe_topic_characters():
    result = mqtt.validate_form({"host": "mqtt.example.com", "port": "1883", "base_topic": "a/b"})
    assert any("base topic" in e.lower() for e in result.errors)


# --- password stays write-only ---------------------------------------------------------------------


def test_mqtt_password_is_never_rendered_back(env):
    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/notifications")
    r = client.post("/admin/notifications/mqtt", data={**MQTT_FORM, "csrf": token})
    assert r.status_code == 303

    page = client.get("/admin/notifications").text
    assert MQTT_FORM["password"] not in page
    assert "leave blank to keep it" in page

    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        assert mqtt.password_set(conn)
        cfg = mqtt.load_config(conn, settings.data_dir)
    assert cfg.password == MQTT_FORM["password"]  # round trips through Fernet, never through HTML
    assert cfg.host == "mqtt.example.com"


def test_blank_password_keeps_the_stored_secret(env):
    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/defaults")
    client.post("/admin/notifications/mqtt", data={**MQTT_FORM, "csrf": token})

    token = csrf(client, "/admin/defaults")
    r = client.post(
        "/admin/notifications/mqtt",
        data={**MQTT_FORM, "password": "", "host": "other.example.com", "csrf": token},
    )
    assert r.status_code == 303

    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        cfg = mqtt.load_config(conn, settings.data_dir)
    assert cfg.host == "other.example.com"
    assert cfg.password == MQTT_FORM["password"]


def test_mqtt_settings_form_400s_on_invalid_input(env):
    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/defaults")
    r = client.post("/admin/notifications/mqtt", data={**MQTT_FORM, "port": "not-a-number", "csrf": token})
    assert r.status_code == 400
    assert "whole number" in r.text.lower()


# --- the section behaves like every other connector ---------------------------------------------

_MQTT_SECTION = r'<details class="connector"[^>]*>\s*<summary>\s*Broker settings'


def test_mqtt_section_is_collapsed_like_the_other_connectors(env):
    """Home Assistant sits on the settings page the same way the
    notification connectors do - a collapsed block you open to configure, not a form permanently
    taking up the page."""
    import re as _re

    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    section = _re.search(_MQTT_SECTION, client.get("/admin/notifications").text)
    assert section, "the Home Assistant section is not rendered as a collapsible connector block"
    assert "open" not in section.group(0), "it has to start collapsed"


def test_mqtt_section_opens_itself_when_the_form_came_back_with_errors(env):
    """A collapsed flap must never hide why a save was refused: `_connectors_section.html` opens
    the matching block on a validation error, and this section does the same. Without it the page
    would come back looking unchanged, with the reason folded away out of sight."""
    import re as _re

    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/defaults")

    r = client.post("/admin/notifications/mqtt", data={**MQTT_FORM, "port": "not-a-number", "csrf": token})
    assert r.status_code == 400
    section = _re.search(_MQTT_SECTION, r.text)
    assert section, "the Home Assistant section is missing from the error response"
    assert "open" in section.group(0), "it has to be open, or the error message sits behind a closed flap"


# --- authorization -----------------------------------------------------------------------------


def test_member_gets_404_on_mqtt_routes(env):
    client, settings = env
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    token = csrf(client, "/")
    assert client.get("/admin/defaults").status_code == 404
    assert client.post("/admin/notifications/mqtt", data={**MQTT_FORM, "csrf": token}).status_code == 404
    assert client.post("/admin/notifications/mqtt/test", data={"csrf": token}).status_code == 404


# --- publish failures never break the tick ----------------------------------------------------


@pytest.fixture
def connect(tmp_path):
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    return lambda: db.connect(path)


class FakeJobs:
    def running(self):
        return {}

    def start(self, udid, trigger):
        pass


def test_a_raising_on_tick_hook_does_not_escape_tick(connect):
    def boom():
        raise RuntimeError("broker unreachable")

    ticker = Ticker(connect, DemoEngine(step_seconds=0), FakeJobs(), lambda *a: None, UTC, on_tick=boom)
    ticker.tick(datetime(2026, 9, 15, 3, 0, tzinfo=UTC))  # must not raise


def test_publish_all_raises_on_a_connection_failure(monkeypatch):
    """mqtt.publish_all itself raises rather than swallowing a broker error - it is runtime.py's
    mqtt_publish_all (the worker's actual entry point, exercised above through Ticker's on_tick)
    that must catch it and log only the exception's class name. Uses a fake paho Client standing
    in for a real broker, since no real broker is available in this test environment."""

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def username_pw_set(self, *a, **k):
            pass

        def tls_set(self, *a, **k):
            pass

        def will_set(self, *a, **k):
            pass

        def connect(self, *a, **k):
            raise ConnectionRefusedError("no broker listening")

        def loop_start(self):
            pass

        def loop_stop(self):
            pass

        def disconnect(self):
            pass

    import paho.mqtt.client as real_client

    monkeypatch.setattr(real_client, "Client", FakeClient)
    cfg = mqtt.MqttConfig(True, "127.0.0.1", 1, False, None, None, "bioseasy", "homeassistant")
    with pytest.raises(ConnectionRefusedError):
        mqtt.publish_all(cfg, [STATUS_PUBLIC])
