# SPDX-License-Identifier: GPL-3.0-or-later
"""Taking a device out of bioseasy again.

Until 1.0.1 there was no way to: a device that got stuck half set up stayed on the dashboard for
good, and its pair record - a credential for that device - stayed in the data volume with it.

Two rules decide the shape of this. The pair record must go, because leaving a device credential
behind for something bioseasy no longer shows anywhere is the worst outcome available. The backups
must stay, because they are the point of the product and an accidental click must not end a year
of them.
"""

from __future__ import annotations

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, pairing
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
UDID = "00008110-000A1B2C3D4E5F60"
RECORD = {
    "HostID": "host",
    "SystemBUID": "buid",
    "HostCertificate": b"cert",
    "HostPrivateKey": b"key",
    "RootCertificate": b"root",
    "WiFiMACAddress": "aa:bb:cc:dd:ee:ff",
    "EscrowBag": b"escrow",
}


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


def sign_in(client, username="admin", password=PASSWORD):
    token = csrf(client, "/login")
    assert client.post("/login", data={"csrf": token, "username": username, "password": password}).status_code == 303


def a_device(settings, *, owner: int, name: str = "Anna's iPhone") -> None:
    """A device as a real one arrives: a row, a pair record, and some history hanging off it."""
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, owner_id, paired_at) VALUES (?, ?, ?, '2026-09-20T10:00:00Z')",
            (UDID, name, owner),
        )
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status) "
            "VALUES (?, 'manual', '2026-09-20T10:05:00Z', 'succeeded')",
            (UDID,),
        )
        conn.execute(
            "INSERT INTO sightings (udid, seen_at, transport) VALUES (?, '2026-09-20T10:04:00Z', 'wifi')", (UDID,)
        )
        conn.execute(
            "INSERT INTO seen_devices (udid, name, transport, paired, last_seen_at) "
            "VALUES (?, ?, 'wifi', 1, '2026-09-20T10:04:00Z')",
            (UDID, name),
        )
        conn.commit()
    pairing.store(settings.data_dir / "pair-records", UDID, RECORD)
    backups = settings.backup_root / UDID
    backups.mkdir(parents=True)
    (backups / "Manifest.plist").write_bytes(b"not a real backup, but a real file")


def test_removing_a_device_takes_its_rows_and_its_pair_record_but_never_its_backups(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    sign_in(client)
    records = settings.data_dir / "pair-records"
    assert pairing.load(records, UDID) is not None

    response = client.post(
        f"/devices/{UDID}/remove",
        data={"csrf": csrf(client, f"/devices/{UDID}/settings"), "confirm_name": "Anna's iPhone"},
    )

    assert response.status_code == 303
    with conn_for(settings) as conn:
        for table in ("devices", "runs", "sightings", "seen_devices"):
            assert conn.execute(f"SELECT count(*) FROM {table} WHERE udid = ?", (UDID,)).fetchone()[0] == 0, table  # noqa: S608
    assert pairing.load(records, UDID) is None
    # The one thing that must survive.
    assert (settings.backup_root / UDID / "Manifest.plist").read_bytes() == b"not a real backup, but a real file"


def test_a_wrong_confirmation_removes_nothing(env):
    """The name has to be typed: a device is removed on purpose or not at all."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    sign_in(client)

    response = client.post(
        f"/devices/{UDID}/remove",
        data={"csrf": csrf(client, f"/devices/{UDID}/settings"), "confirm_name": "the wrong name"},
    )

    assert response.status_code == 400
    assert "type its name exactly" in response.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT count(*) FROM devices WHERE udid = ?", (UDID,)).fetchone()[0] == 1
    assert pairing.load(settings.data_dir / "pair-records", UDID) is not None


def test_a_device_being_backed_up_right_now_is_not_removed(env):
    """The run would go on writing into a device nothing in the UI knows about any more."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status) "
            "VALUES (?, 'manual', '2026-09-20T11:00:00Z', 'running')",
            (UDID,),
        )
        conn.commit()
    sign_in(client)

    response = client.post(
        f"/devices/{UDID}/remove",
        data={"csrf": csrf(client, f"/devices/{UDID}/settings"), "confirm_name": "Anna's iPhone"},
    )

    assert response.status_code == 409
    assert "A backup is running" in response.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT count(*) FROM devices WHERE udid = ?", (UDID,)).fetchone()[0] == 1


def test_a_member_cannot_remove_someone_elses_device(env):
    """404, not 403: a foreign device stays indistinguishable from one that does not exist."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        auth.create_user(conn, "member", PASSWORD, "member", "member@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    sign_in(client, "member")

    response = client.post(
        f"/devices/{UDID}/remove", data={"csrf": csrf(client, "/settings"), "confirm_name": "Anna's iPhone"}
    )

    assert response.status_code == 404
    with conn_for(settings) as conn:
        assert conn.execute("SELECT count(*) FROM devices WHERE udid = ?", (UDID,)).fetchone()[0] == 1
    assert pairing.load(settings.data_dir / "pair-records", UDID) is not None


def test_the_settings_page_offers_the_removal_and_names_where_the_backups_stay(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    sign_in(client)

    page = client.get(f"/devices/{UDID}/settings").text

    assert f'action="/devices/{UDID}/remove"' in page
    assert str(settings.backup_root / UDID) in page
    assert "not</strong> deleted" in page


def test_removal_clears_the_udid_a_spent_pairing_code_recorded(env):
    """A used code keeps the device it was spent on in `pairing_codes.consumed_udid`. "Its pairing
    goes" has to include that, or a removed device's identifier stays in the database for good -
    while the code itself must stay spent, so the row is cleared rather than deleted."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        conn.commit()
    a_device(settings, owner=admin.id)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO pairing_codes (code_hash, created_by, created_at, expires_at, used_at, consumed_udid) "
            "VALUES ('not-a-real-hash', ?, '2026-09-20T09:00:00Z', '2026-09-20T09:10:00Z',"
            " '2026-09-20T09:05:00Z', ?)",
            (admin.id, UDID),
        )
        conn.commit()
    sign_in(client)

    client.post(
        f"/devices/{UDID}/remove",
        data={"csrf": csrf(client, f"/devices/{UDID}/settings"), "confirm_name": "Anna's iPhone"},
    )

    with conn_for(settings) as conn:
        rows = conn.execute("SELECT used_at, consumed_udid FROM pairing_codes").fetchall()
    assert len(rows) == 1, "the code itself stays on record"
    assert rows[0]["used_at"] is not None, "and stays spent"
    assert rows[0]["consumed_udid"] is None
