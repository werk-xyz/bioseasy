# SPDX-License-Identifier: GPL-3.0-or-later
"""A device added through the code hand-off starts without model and iOS version; a scan or a
finished backup fills them in, and the pages never show "Unknown model"."""

from contextlib import closing
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from bioseasy import db
from bioseasy.discovery import fill_device_identity, refresh_seen_devices
from bioseasy.engine.base import DeviceSeen, Transport

UDID = "00008103-000A1B2C3D4E5F60"
TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "bioseasy" / "web" / "templates"


def _conn(tmp_path):
    conn = db.connect(tmp_path / "bioseasy.db")
    db.migrate(conn)
    conn.execute("INSERT INTO devices (udid, name) VALUES (?, 'Test iPad')", (UDID,))
    return conn


def _identity(conn):
    row = conn.execute("SELECT product_type, os_version FROM devices WHERE udid = ?", (UDID,)).fetchone()
    return row["product_type"], row["os_version"]


def _name(conn):
    return conn.execute("SELECT name FROM devices WHERE udid = ?", (UDID,)).fetchone()["name"]


def test_backup_values_fill_an_empty_row_and_missing_values_keep_known_ones(tmp_path):
    with closing(_conn(tmp_path)) as conn:
        fill_device_identity(conn, UDID, "iPad13,1", "26.3.1")
        assert _identity(conn) == ("iPad13,1", "26.3.1")
        fill_device_identity(conn, UDID, None, "")
        assert _identity(conn) == ("iPad13,1", "26.3.1")


def test_a_scan_fills_the_added_device(tmp_path):
    with closing(_conn(tmp_path)) as conn:
        seen = DeviceSeen(UDID, Transport.WIFI, "Test iPad", "iPad13,1", "26.5", True)
        refresh_seen_devices(conn, [seen])
        assert _identity(conn) == ("iPad13,1", "26.5")


def test_name_stays_in_sync_while_not_customized(tmp_path):
    """devices.name_custom defaults to 0 (db.py), so a scan or backup keeps devices.name synced
    with what the device itself reports, until the owner renames it (app.py's
    device_settings_submit sets name_custom once the saved name differs from the stored one)."""
    with closing(_conn(tmp_path)) as conn:
        fill_device_identity(conn, UDID, "iPad13,1", "26.3.1", "New Name From Device")
        assert _name(conn) == "New Name From Device"
        # Missing name (e.g. a backup's Info.plist without one) never overwrites a known one.
        fill_device_identity(conn, UDID, "iPad13,1", "26.3.1", None)
        assert _name(conn) == "New Name From Device"


def test_name_sync_stops_once_the_owner_renames_the_device(tmp_path):
    with closing(_conn(tmp_path)) as conn:
        conn.execute("UPDATE devices SET name_custom = 1 WHERE udid = ?", (UDID,))
        fill_device_identity(conn, UDID, "iPad13,1", "26.3.1", "Name From Device")
        assert _name(conn) == "Test iPad"  # unchanged: the custom name wins


def test_a_scan_syncs_the_name_too(tmp_path):
    with closing(_conn(tmp_path)) as conn:
        seen = DeviceSeen(UDID, Transport.WIFI, "Scanned Name", "iPad13,1", "26.5", True)
        refresh_seen_devices(conn, [seen])
        assert _name(conn) == "Scanned Name"


def _meta(product_type, os_version):
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    env.filters["ago"] = str
    template = env.from_string('{% from "_macros.html" import device_meta %}{{ device_meta(p, o) }}')
    return template.render(p=product_type, o=os_version).strip()


def test_device_meta_names_ipados_and_explains_the_empty_case():
    assert _meta("iPad13,1", "26.3.1") == "iPad13,1 · iPadOS 26.3.1"
    assert _meta("iPhone15,2", "26.5") == "iPhone15,2 · iOS 26.5"
    assert "Unknown" not in _meta(None, None)
    assert _meta(None, None) == "Model and iOS version appear after the first scan or backup"
