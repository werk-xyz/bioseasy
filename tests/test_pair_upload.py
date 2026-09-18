# SPDX-License-Identifier: GPL-3.0-or-later
import datetime
import plistlib
import re
import stat
from contextlib import closing

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

UDID = "00008110-000A1B2C3D4E5F60"
PASSWORD = "correct horse battery"


def record_bytes(escrow=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    record = {
        "HostID": "H",
        "SystemBUID": "B",
        "HostCertificate": pem,
        "RootCertificate": pem,
        "HostPrivateKey": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "WiFiMACAddress": "aa:bb:cc:dd:ee:ff",
    }
    if escrow:
        record["EscrowBag"] = b"e"
    return plistlib.dumps(record)


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        with closing(db.connect(data / "bioseasy.db")) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
            auth.create_user(conn, "member", PASSWORD, "member")
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client, username):
    client.post("/login", data={"csrf": csrf(client, "/login"), "username": username, "password": PASSWORD})


def upload(client, data, udid=UDID, token=None):
    return client.post(
        "/add/pair-record",
        data={"csrf": token if token is not None else csrf(client, "/add"), "udid": udid},
        files={"record": ("device.plist", data, "application/xml")},
    )


def test_valid_record_is_stored_privately_and_the_device_added(env):
    client, settings = env
    login(client, "admin")
    r = upload(client, record_bytes())
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{UDID}/setup"
    path = settings.data_dir / "pair-records" / f"{UDID}.plist"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_pasted_udid_with_whitespace_is_stripped_on_upload(env):
    # The stored file name (and devices.udid) must match the directory mobilebackup2 writes,
    # target_root/<UniqueDeviceID>; surrounding whitespace from a paste is removed, the case is
    # kept as given (pairing.normalize_udid explains why).
    client, settings = env
    login(client, "admin")
    r = upload(client, record_bytes(), udid=f"  {UDID}  ")
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{UDID}/setup"
    assert (settings.data_dir / "pair-records" / f"{UDID}.plist").is_file()


def test_record_without_an_escrow_bag_is_refused(env):
    # mobilebackup2 always requires the escrow bag (pairing.require_escrow_bag); a record
    # missing one would otherwise fail deep inside pymobiledevice3 on the first backup attempt,
    # as a bare KeyError instead of a clear message, so the upload rejects it up front.
    client, settings = env
    login(client, "admin")
    r = upload(client, record_bytes(escrow=False))
    assert r.status_code == 400 and "EscrowBag" in r.text
    assert not (settings.data_dir / "pair-records").exists() or not any((settings.data_dir / "pair-records").iterdir())


@pytest.mark.parametrize(
    ("data", "udid", "message"),
    [
        (b"garbage", UDID, "not a property list"),
        (plistlib.dumps({"HostID": "x"}), UDID, "lacks"),
        (None, "../../etc", "Enter the device UDID"),
    ],
)
def test_bad_uploads_are_refused_with_400(env, data, udid, message):
    client, settings = env
    login(client, "admin")
    r = upload(client, data if data is not None else record_bytes(), udid=udid)
    assert r.status_code == 400 and message in r.text
    assert not (settings.data_dir / "pair-records").exists() or not any((settings.data_dir / "pair-records").iterdir())


def test_upload_needs_csrf_and_admin(env):
    client, _ = env
    login(client, "admin")
    assert upload(client, record_bytes(), token="wrong").status_code == 403
    client.cookies.clear()
    login(client, "member")
    assert upload(client, record_bytes(), token=csrf(client, "/")).status_code == 404
