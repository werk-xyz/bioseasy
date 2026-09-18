# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the backup-password check: the pyiosbackup wrapper and the route.

`write_encrypted_manifest` below builds a real, working encrypted `Manifest.plist` -- the same
TLV struct, PBKDF2 derivation and AES key-wrap that `pyiosbackup.keybag.Keybag.from_manifest`
itself parses and unwraps (pyiosbackup/keybag.py:50-73). The correct/wrong tests exercise that
exact code path end to end, including the AES key-wrap integrity check that
`cryptography.hazmat.primitives.keywrap.aes_key_unwrap` raises `InvalidUnwrap` for on a wrong
password. This is the real cryptographic path, not a monkeypatch: the installed pyiosbackup
0.2.4 package ships no tests/ directory and no keybag builder of its own (checked under
.venv/lib/python3.12/site-packages/pyiosbackup), so the fixture was built directly from
pyiosbackup/keybag.py's own struct and algorithm rather than from anything pyiosbackup exposes.
"""

from __future__ import annotations

import hashlib
import logging
import plistlib
import re
from contextlib import closing

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from fastapi.testclient import TestClient
from fixtures import BACKUP_PASSWORD  # one marked demo credential, defined in one place
from pyiosbackup.keybag import keybag_struct

from bioseasy import auth, db, password_check
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine, write_backup

PHONE = DEMO_DEVICES[0]
PASSWORD = "correct horse battery"  # bioseasy login password used by these tests

WRONG_BACKUP_PASSWORD = "definitely not it"  # noqa: S105


def write_encrypted_manifest(path, password: str, *, iterations: int = 1000) -> None:
    """Overwrite `path/Manifest.plist` with a real, working encrypted keybag for `password`.

    Product version 9.0 skips pyiosbackup's PBKDF2-SHA256 "DPSL/DPIC" pre-hash step (only
    applied above iOS 10.2), keeping the fixture to the minimum shape Keybag.from_manifest
    actually needs: one PBKDF2-SHA1 round over SALT/ITER, one AES key-wrap class.
    """
    salt = b"S" * 20
    decryption_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, iterations, 32)
    class_key = b"K" * 32
    wrapped_class_key = aes_key_wrap(decryption_key, class_key)

    keybag_bytes = keybag_struct.build(
        [
            {"tag": b"SALT", "size": len(salt), "data": salt},
            {"tag": b"ITER", "size": 4, "data": iterations},
            {"tag": b"CLAS", "size": 4, "data": 1},
            {"tag": b"WRAP", "size": 4, "data": 2},
            {"tag": b"WPKY", "size": len(wrapped_class_key), "data": wrapped_class_key},
            {"tag": b"KTYP", "size": 4, "data": 0},
            {"tag": b"PBKY", "size": 32, "data": b"P" * 32},
        ]
    )
    manifest = {
        "IsEncrypted": True,
        "BackupKeyBag": keybag_bytes,
        "ManifestKey": b"M" * 32,
        "Lockdown": {"ProductVersion": "9.0"},
    }
    path.mkdir(parents=True, exist_ok=True)
    with (path / "Manifest.plist").open("wb") as fh:
        plistlib.dump(manifest, fh)


def write_unencrypted_manifest(path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with (path / "Manifest.plist").open("wb") as fh:
        plistlib.dump({"IsEncrypted": False, "Lockdown": {"ProductVersion": "18.6"}}, fh)


# ---- password_check.check(): the wrapper and the real cryptographic path -------------------


def test_check_correct_password_against_a_real_keybag(tmp_path):
    write_encrypted_manifest(tmp_path, BACKUP_PASSWORD)
    result = password_check.check(tmp_path, BACKUP_PASSWORD)
    assert result.outcome == "correct"


def test_check_wrong_password_against_a_real_keybag(tmp_path):
    write_encrypted_manifest(tmp_path, BACKUP_PASSWORD)
    result = password_check.check(tmp_path, WRONG_BACKUP_PASSWORD)
    assert result.outcome == "wrong"
    assert WRONG_BACKUP_PASSWORD not in result.message
    assert BACKUP_PASSWORD not in result.message


def test_check_not_encrypted_backup(tmp_path):
    write_unencrypted_manifest(tmp_path)
    result = password_check.check(tmp_path, "anything")
    assert result.outcome == "not_encrypted"


def test_check_missing_manifest(tmp_path):
    result = password_check.check(tmp_path, "anything")
    assert result.outcome == "unreadable"


def test_check_corrupted_manifest(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "Manifest.plist").write_bytes(b"not a plist at all")
    result = password_check.check(tmp_path, "anything")
    assert result.outcome == "unreadable"


def test_check_encrypted_but_keybag_is_garbage(tmp_path):
    """IsEncrypted true but a keybag blob that cannot be parsed at all (corrupted or foreign
    Manifest.plist) must read as 'unreadable', never raise out of check(), and never hang."""
    tmp_path.mkdir(exist_ok=True)
    manifest = {
        "IsEncrypted": True,
        "BackupKeyBag": b"not a real keybag",
        "ManifestKey": b"M" * 32,
        "Lockdown": {"ProductVersion": "9.0"},
    }
    with (tmp_path / "Manifest.plist").open("wb") as fh:
        plistlib.dump(manifest, fh)
    result = password_check.check(tmp_path, "anything")
    assert result.outcome == "unreadable"


def test_check_never_logs_the_password(tmp_path, caplog):
    write_encrypted_manifest(tmp_path, BACKUP_PASSWORD)
    with caplog.at_level(logging.DEBUG):
        password_check.check(tmp_path, WRONG_BACKUP_PASSWORD)
        password_check.check(tmp_path, BACKUP_PASSWORD)
    for record in caplog.records:
        assert BACKUP_PASSWORD not in record.getMessage()
        assert WRONG_BACKUP_PASSWORD not in record.getMessage()


# ---- the route --------------------------------------------------------------------------------


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
        # The Add page reads seen_devices instead of calling engine.discover() itself;
        # seed it here the way a completed scan would, since PHONE is
        # already paired in DEMO_DEVICES and this helper only needs the fast "Add" path.
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    login(client, "admin")
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303


def seed_encrypted_backup(settings):
    """A full-shaped demo backup (Info/Status/Manifest.db) with a real, working keybag."""
    path = settings.backup_root / PHONE.udid
    write_backup(path, PHONE, encrypted=True)
    write_encrypted_manifest(path, BACKUP_PASSWORD)
    return path


def test_password_check_route_correct_password_persists_and_confirms(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": BACKUP_PASSWORD})
    assert r.status_code == 200
    assert "correct" in r.text.lower()
    assert BACKUP_PASSWORD not in r.text

    with conn_for(settings) as conn:
        row = conn.execute(
            "SELECT password_checked_at, password_check_result FROM devices WHERE udid = ?", (PHONE.udid,)
        ).fetchone()
    assert row["password_check_result"] == "correct"
    assert row["password_checked_at"] is not None

    # Confirmed within 90 days: the device page shows the confirmation, not the form again.
    page = client.get(url).text
    assert "Confirmed" in page
    assert 'name="password"' not in page


def test_password_check_route_wrong_password_does_not_confirm(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": WRONG_BACKUP_PASSWORD})
    assert r.status_code == 200
    assert "does not unlock" in r.text.lower()

    with conn_for(settings) as conn:
        row = conn.execute("SELECT password_check_result FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["password_check_result"] == "wrong"

    # Still not confirmed: the form stays on the page for another attempt.
    page = client.get(url).text
    assert 'name="password"' in page


def test_password_check_htmx_request_returns_the_swapped_section(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(
        f"{url}/password-check",
        data={"csrf": token, "password": BACKUP_PASSWORD},
        headers={"hx-request": "true"},
    )
    assert r.status_code == 200
    assert '<section id="password-check"' in r.text


def test_password_check_not_encrypted_backup(env):
    client, settings = env
    make_admin_with_device(client, settings)
    path = settings.backup_root / PHONE.udid
    write_backup(path, PHONE, encrypted=False)
    write_unencrypted_manifest(path)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": "anything"})
    assert r.status_code == 200
    assert "not encrypted" in r.text.lower()
    # not_encrypted is not one of the values the schema's CHECK constraint allows to be stored.
    with conn_for(settings) as conn:
        row = conn.execute("SELECT password_check_result FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["password_check_result"] is None


def test_password_check_missing_backup(env):
    client, settings = env
    make_admin_with_device(client, settings)
    # No backup directory at all yet for this device.

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": "anything"})
    assert r.status_code == 200
    assert "could not be read" in r.text.lower()


def test_password_check_password_never_appears_in_response_or_logs(env, caplog):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    with caplog.at_level(logging.DEBUG):
        token = csrf(client, url)
        r1 = client.post(f"{url}/password-check", data={"csrf": token, "password": WRONG_BACKUP_PASSWORD})
        token = csrf(client, url)
        r2 = client.post(f"{url}/password-check", data={"csrf": token, "password": BACKUP_PASSWORD})
        page = client.get(url).text

    for body in (r1.text, r2.text, page):
        assert BACKUP_PASSWORD not in body
        assert WRONG_BACKUP_PASSWORD not in body
    for record in caplog.records:
        assert BACKUP_PASSWORD not in record.getMessage()
        assert WRONG_BACKUP_PASSWORD not in record.getMessage()

    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert BACKUP_PASSWORD not in str(dict(row))
    assert WRONG_BACKUP_PASSWORD not in str(dict(row))


def test_password_check_rate_limited_after_free_attempts(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    # auth.LoginThrottle's default is 5 free attempts per key before backing off.
    for _ in range(5):
        token = csrf(client, url)
        r = client.post(f"{url}/password-check", data={"csrf": token, "password": WRONG_BACKUP_PASSWORD})
        assert r.status_code == 200
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": WRONG_BACKUP_PASSWORD})
    assert r.status_code == 429


def test_password_check_member_cannot_check_a_foreign_device(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")

    token = csrf(client, "/")
    r = client.post(f"/devices/{PHONE.udid}/password-check", data={"csrf": token, "password": BACKUP_PASSWORD})
    assert r.status_code == 404


def test_password_check_without_csrf_is_403(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    r = client.post(f"/devices/{PHONE.udid}/password-check", data={"password": BACKUP_PASSWORD})
    assert r.status_code == 403
    with conn_for(settings) as conn:
        row = conn.execute("SELECT password_check_result FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["password_check_result"] is None  # the missing-csrf request never reached the check


def test_password_check_oversized_password_is_rejected_before_the_key_derivation(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_encrypted_backup(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/password-check", data={"csrf": token, "password": "x" * 1025})
    assert r.status_code == 400
    assert "too long" in r.text.lower()


def test_keybag_error_text_never_reaches_the_log(tmp_path, caplog, monkeypatch):
    """An unexpected keybag error whose message echoes the password is logged by class only."""
    write_encrypted_manifest(tmp_path, BACKUP_PASSWORD)

    def echoing_keybag(manifest, password):
        raise RuntimeError(f"parse failed near {password}")

    monkeypatch.setattr(password_check.Keybag, "from_manifest", echoing_keybag)
    with caplog.at_level(logging.DEBUG):
        result = password_check.check(tmp_path, BACKUP_PASSWORD)
    assert result.outcome == "unreadable"
    assert BACKUP_PASSWORD not in caplog.text


def test_unexpected_manifest_error_logs_neither_message_nor_traceback(tmp_path, caplog, monkeypatch):
    """An error that escapes _unwrap reaches check(): only its class may be logged, because the
    message and traceback of a parse error can carry manifest fields such as the serial."""
    write_encrypted_manifest(tmp_path, BACKUP_PASSWORD)

    def failing_reader(path):
        raise RuntimeError("serial DEMO-SERIAL-123 in Lockdown dict")

    monkeypatch.setattr(password_check.ManifestPlist, "from_path", failing_reader)
    with caplog.at_level(logging.DEBUG):
        result = password_check.check(tmp_path, BACKUP_PASSWORD)
    assert result.outcome == "unreadable"
    assert "DEMO-SERIAL-123" not in caplog.text
    assert BACKUP_PASSWORD not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_an_unencrypted_backup_is_not_asked_for_a_password_it_does_not_have(env):
    """The device page offered a password check for a backup with no password, under the sentence
    "without this password the backup cannot be restored" - the opposite of true for that backup.
    The route still answers a posted check; only the offer is gone."""
    client, settings = env
    make_admin_with_device(client, settings)
    path = settings.backup_root / PHONE.udid
    write_backup(path, PHONE, encrypted=False)
    write_unencrypted_manifest(path)

    page = client.get(f"/devices/{PHONE.udid}").text

    assert "Encrypted</dt><dd>No" in page.replace(" ", "").replace("\n", "") or "Encrypted" in page
    assert "Check that you still know the backup password." not in page
    assert "Without this password the backup cannot be restored" not in page


def test_an_encrypted_backup_still_offers_the_check(env):
    """The other direction, so hiding the section cannot quietly hide it everywhere."""
    client, settings = env
    make_admin_with_device(client, settings)
    write_backup(settings.backup_root / PHONE.udid, PHONE, encrypted=True)

    page = client.get(f"/devices/{PHONE.udid}").text

    assert "Check that you still know the backup password." in page
