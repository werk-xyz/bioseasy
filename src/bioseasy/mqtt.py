# SPDX-License-Identifier: GPL-3.0-or-later
"""MQTT connector for Home Assistant: publishes each device's backup state and Home Assistant
MQTT discovery messages, so entities appear in Home Assistant without a custom integration.

Publishes from `status.to_public` (status.py) only - this module never re-derives a device's
state from the database or the backup directory itself, the same rule the read-only API follows.
status.py's own module docstring already names this module as one of `to_public`'s consumers.

Licensing: paho-mqtt is `EPL-2.0 OR BSD-3-Clause`; bioseasy uses it under the BSD-3-Clause option
(see NOTICE). The installed package's `Client.__init__` defaults `callback_api_version` to
`CallbackAPIVersion.VERSION1`, which upstream marks for removal; this module passes
`CallbackAPIVersion.VERSION2` explicitly instead of relying on that default.

Home Assistant MQTT discovery:
- Discovery topic: `<discovery_prefix>/<component>/<object_id>/config` - the `<node_id>` segment
  the docs show is optional; skipped here since `object_id` (built from the device id and the
  entity) is already unique on its own.
- A discovery payload's `device` block (identifiers, name, manufacturer, model, sw_version) is
  "mandatory and cannot be overridden at the entity/component level".
- `availability_topic` / `payload_available` (default `"online"`) / `payload_not_available`
  (default `"offline"`).
- Sensor `device_class: timestamp` expects a "Datetime object or timestamp string (ISO 8601)" -
  exactly the shape `status.to_public`'s `last_success_at` already produces.
- Binary sensor `device_class: problem`: "on means problem detected, off means no problem (OK)".
- The backup-status sensor below is deliberately a plain sensor with no `device_class` - an HA
  `enum` device class would mean keeping its `options` in step with `status.State` by hand for no
  behavioural gain.

Connecting: one short-lived client per publish, not a persistent client kept in the worker. The
tick interval is minutes, not seconds, so a fresh TCP/TLS handshake every time is cheap, and it
avoids owning reconnect and keepalive state across the worker's lifetime. The trade-off, stated
plainly: the availability LWT (`<base>/status` = `"offline"`, retained) can only fire during the
narrow window this module is actually connected; it cannot detect bioseasy itself being down
between ticks. The retained `"online"` message this module publishes at the start of every
connection is what a viewer actually sees between ticks, not a live heartbeat.

Device identity: topics and `unique_id` use `device_id()`, the first 12 hex characters of
sha256(udid) - never the UDID itself, and never the pair record. `state_payload` drops the `udid`
key that `status.to_public` carries before anything is published.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

log = logging.getLogger("bioseasy")

DEFAULT_PORT = 1883
DEFAULT_BASE_TOPIC = "bioseasy"
DEFAULT_DISCOVERY_PREFIX = "homeassistant"
# Bounds a hung connect() or a broker that never PUBACKs; see module docstring on why a broker
# outage must not stall a backup or a tick for long.
CONNECT_TIMEOUT = 5.0
PUBLISH_TIMEOUT = 5.0


@dataclass(frozen=True)
class MqttConfig:
    enabled: bool
    host: str
    port: int
    tls: bool
    username: str | None
    password: str | None  # decrypted; never logged, never rendered back into a page
    base_topic: str
    discovery_prefix: str


# --- topics and payloads: pure functions, no network -------------------------------------------


def device_id(udid: str) -> str:
    """A stable, non-reversible id for MQTT topics and `unique_id`. Never the UDID itself."""
    return hashlib.sha256(udid.encode()).hexdigest()[:12]


def availability_topic(base_topic: str) -> str:
    return f"{base_topic}/status"


def state_topic(base_topic: str, dev_id: str) -> str:
    return f"{base_topic}/device/{dev_id}/state"


def discovery_topic(discovery_prefix: str, component: str, dev_id: str, object_id: str) -> str:
    return f"{discovery_prefix}/{component}/{dev_id}_{object_id}/config"


def _age_hours(last_success_at: str | None, now: datetime) -> float | None:
    if not last_success_at:
        return None
    dt = datetime.fromisoformat(last_success_at.replace("Z", "+00:00"))
    return round((now - dt).total_seconds() / 3600, 2)


def state_payload(status_public: dict, now: datetime) -> dict:
    """The device state topic's JSON payload: `status.to_public`'s fields, minus `udid` (never
    published - see module docstring), plus an age in hours computed fresh at publish time so it
    stays current between backups."""
    payload = {k: v for k, v in status_public.items() if k != "udid"}
    payload["age_hours"] = _age_hours(status_public.get("last_success_at"), now)
    return payload


def _device_block(status_public: dict, dev_id: str) -> dict:
    return {
        "identifiers": [dev_id],
        "name": status_public.get("name") or dev_id,
        "manufacturer": "Apple",
        "model": status_public.get("model") or "iPhone/iPad",
    }


def discovery_configs(
    base_topic: str, discovery_prefix: str, dev_id: str, status_public: dict
) -> list[tuple[str, dict]]:
    """The (topic, payload) pairs for one device's four HA entities: backup status, last
    successful backup, backup age in hours, and overdue."""
    common = {
        "availability_topic": availability_topic(base_topic),
        "payload_available": "online",
        "payload_not_available": "offline",
        "state_topic": state_topic(base_topic, dev_id),
        "device": _device_block(status_public, dev_id),
    }
    return [
        (
            discovery_topic(discovery_prefix, "sensor", dev_id, "status"),
            {
                **common,
                "unique_id": f"{dev_id}_status",
                "object_id": f"{dev_id}_status",
                "name": "Backup status",
                "value_template": "{{ value_json.state }}",
            },
        ),
        (
            discovery_topic(discovery_prefix, "sensor", dev_id, "last_success"),
            {
                **common,
                "unique_id": f"{dev_id}_last_success",
                "object_id": f"{dev_id}_last_success",
                "name": "Last successful backup",
                "device_class": "timestamp",
                "value_template": "{{ value_json.last_success_at }}",
            },
        ),
        (
            discovery_topic(discovery_prefix, "sensor", dev_id, "age_hours"),
            {
                **common,
                "unique_id": f"{dev_id}_age_hours",
                "object_id": f"{dev_id}_age_hours",
                "name": "Backup age",
                "unit_of_measurement": "h",
                "state_class": "measurement",
                "value_template": "{{ value_json.age_hours }}",
            },
        ),
        (
            discovery_topic(discovery_prefix, "binary_sensor", dev_id, "overdue"),
            {
                **common,
                "unique_id": f"{dev_id}_overdue",
                "object_id": f"{dev_id}_overdue",
                "name": "Backup overdue",
                "device_class": "problem",
                "value_template": "{{ 'ON' if value_json.state == 'overdue' else 'OFF' }}",
            },
        ),
    ]


# --- publishing: the only part that touches the network -----------------------------------------


def publish_all(cfg: MqttConfig, statuses: list[dict], now: datetime | None = None) -> None:
    """Connect once, publish availability plus every device's discovery and state, disconnect.

    `statuses` is a list of `status.to_public(...)` dicts (still carrying `udid`, stripped here
    per device). Raises on any connection or publish failure - callers must catch broadly and log
    only `type(exc).__name__`, since a broker error's text could echo the host or an auth failure
    and must never be assumed safe to print (the same rule connector secrets follow).
    """
    import paho.mqtt.client as mqtt

    now = now or datetime.now(UTC)
    client_id = f"bioseasy-{uuid.uuid4().hex[:8]}"
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    if cfg.username:
        client.username_pw_set(cfg.username, cfg.password)
    if cfg.tls:
        client.tls_set()
    client.connect_timeout = CONNECT_TIMEOUT
    avail = availability_topic(cfg.base_topic)
    # Only fires on an unclean disconnect (a crash mid-publish, the network dropping); a normal
    # disconnect() below does not send it. See the module docstring's "Connecting" section.
    client.will_set(avail, payload="offline", retain=True)
    try:
        client.connect(cfg.host, cfg.port, keepalive=10)
        client.loop_start()
        client.publish(avail, "online", qos=1, retain=True).wait_for_publish(timeout=PUBLISH_TIMEOUT)
        for status_public in statuses:
            dev_id = device_id(status_public["udid"])
            for topic, payload in discovery_configs(cfg.base_topic, cfg.discovery_prefix, dev_id, status_public):
                client.publish(topic, json.dumps(payload), qos=1, retain=True).wait_for_publish(timeout=PUBLISH_TIMEOUT)
            client.publish(
                state_topic(cfg.base_topic, dev_id),
                json.dumps(state_payload(status_public, now)),
                qos=1,
                retain=True,
            ).wait_for_publish(timeout=PUBLISH_TIMEOUT)
    finally:
        client.disconnect()
        client.loop_stop()


# --- admin config: the settings table, one broker -----------------------------------------------

_CONFIG_KEY = "mqtt_config"
_PASSWORD_KEY = "mqtt_password"  # noqa: S105 - a settings-table key name, not a password value


@dataclass(frozen=True)
class MqttForm:
    """Result of validating the admin MQTT settings form. `secret` is the password field exactly
    as typed, including blank - blank always means "keep whatever is stored", the same write-only
    rule connectors.py uses, since the password is optional (a broker may allow anonymous auth)
    and there is deliberately no way to type a request that clears a stored password."""

    settings: dict
    secret: str
    errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.errors is None:
            object.__setattr__(self, "errors", [])


def _int_in_range(raw: str, low: int, high: int, label: str) -> tuple[int | None, str | None]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, f"{label} must be a whole number"
    if not (low <= value <= high):
        return None, f"{label} must be between {low} and {high}"
    return value, None


# MQTT topics may contain '/', but base_topic and discovery_prefix here are always a single
# level (device and discovery topics are built by appending fixed suffixes below them), and
# restricting them to this class rules out an admin fat-fingering a leading '/', a MQTT wildcard
# ('#', '+') or embedded whitespace into a topic prefix everything else is built from.
_TOPIC_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def validate_form(form: dict) -> MqttForm:
    """Explicit field allowlist for the admin MQTT settings form; never spreads the request body.
    Invalid input comes back as field errors, for the route to turn into a 400 - never a 500."""
    errors: list[str] = []
    # "mqtt_enabled", not the plain "enabled" every other on/off toggle in this codebase uses:
    # admin_settings.html renders this section unconditionally next to the update-check toggle,
    # which also has a checkbox literally named "enabled" - tests/test_update_check.py asserts
    # `'name="enabled"' not in page` when update-checking has nothing to check against, and a
    # second, unrelated `name="enabled"` input on the same page would make that assertion false
    # for a reason that has nothing to do with update-checking.
    enabled = bool(form.get("mqtt_enabled"))

    host = (form.get("host") or "").strip()
    if enabled and not (1 <= len(host) <= 255):
        errors.append("Broker host is required when Home Assistant (MQTT) is enabled")
    elif host and re.search(r"\s", host):
        errors.append("Broker host must not contain whitespace")

    port, err = _int_in_range(form.get("port") or str(DEFAULT_PORT), 1, 65535, "Broker port")
    if err:
        errors.append(err)

    tls = bool(form.get("tls"))

    username = (form.get("username") or "").strip()
    if len(username) > 254:
        errors.append("Username is too long")

    password = form.get("password") or ""
    if len(password) > 512:
        errors.append("Password is too long")

    base_topic = (form.get("base_topic") or DEFAULT_BASE_TOPIC).strip()
    if not _TOPIC_SEGMENT_RE.fullmatch(base_topic):
        errors.append("Base topic must be 1 to 64 characters: letters, digits, '_' or '-' only")

    discovery_prefix = (form.get("discovery_prefix") or DEFAULT_DISCOVERY_PREFIX).strip()
    if not _TOPIC_SEGMENT_RE.fullmatch(discovery_prefix):
        errors.append("Discovery prefix must be 1 to 64 characters: letters, digits, '_' or '-' only")

    settings: dict = {}
    if not errors:
        settings = {
            "enabled": enabled,
            "host": host,
            "port": port,
            "tls": tls,
            "username": username or None,
            "base_topic": base_topic,
            "discovery_prefix": discovery_prefix,
        }
    return MqttForm(settings=settings, secret=password, errors=errors)


def form_defaults(settings: dict) -> dict:
    """A stored config's non-secret fields, reshaped for the template's form fields."""
    return {
        "enabled": bool(settings.get("enabled")),
        "host": settings.get("host", ""),
        "port": str(settings.get("port") or DEFAULT_PORT),
        "tls": bool(settings.get("tls")),
        "username": settings.get("username") or "",
        "base_topic": settings.get("base_topic", DEFAULT_BASE_TOPIC),
        "discovery_prefix": settings.get("discovery_prefix", DEFAULT_DISCOVERY_PREFIX),
    }


def save_config(conn, data_dir, settings: dict, secret: str) -> None:
    from . import db

    db.set_setting(conn, _CONFIG_KEY, json.dumps(settings))
    if secret:
        from . import connectors

        db.set_setting(conn, _PASSWORD_KEY, connectors.encrypt_secret(data_dir, secret).decode("ascii"))


def stored_settings(conn) -> dict | None:
    from . import db

    raw = db.get_setting(conn, _CONFIG_KEY)
    return json.loads(raw) if raw is not None else None


def password_set(conn) -> bool:
    from . import db

    return bool(db.get_setting(conn, _PASSWORD_KEY))


def load_config(conn, data_dir) -> MqttConfig | None:
    """The saved broker config, password decrypted, or None if nothing has been saved yet.

    A password that fails to decrypt (missing or wrong key file, corrupted row - the same cases
    connectors.decrypt_secret already handles) is logged by exception class only and treated as
    "no password" rather than failing the whole publish; a broker that actually needs one will
    then simply refuse the connection, which the caller already treats as a normal publish
    failure.
    """
    from . import connectors, db

    data = stored_settings(conn)
    if data is None:
        return None
    password = None
    ciphertext_text = db.get_setting(conn, _PASSWORD_KEY)
    if ciphertext_text:
        try:
            password = connectors.decrypt_secret(data_dir, ciphertext_text.encode("ascii"))
        except connectors.ConnectorSecretError as exc:
            # Class name only, never the exception's own text, which can echo key or ciphertext
            # material. The message names the password solely to say it could not be read; the
            # value itself is never interpolated, which is what the suppressed rule looks for.
            log.warning(  # nosemgrep: python-logger-credential-disclosure
                "mqtt: stored password could not be decrypted (%s), publishing without it", type(exc).__name__
            )
    return MqttConfig(
        enabled=bool(data.get("enabled")),
        host=data.get("host", ""),
        port=int(data.get("port") or DEFAULT_PORT),
        tls=bool(data.get("tls")),
        username=data.get("username") or None,
        password=password,
        base_topic=data.get("base_topic", DEFAULT_BASE_TOPIC),
        discovery_prefix=data.get("discovery_prefix", DEFAULT_DISCOVERY_PREFIX),
    )
