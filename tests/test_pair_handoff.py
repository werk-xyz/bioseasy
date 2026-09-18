# SPDX-License-Identifier: GPL-3.0-or-later
import datetime
import plistlib
import re
from contextlib import closing

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from bioseasy import auth, db, handoff
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

UDID = "00008110-000A1B2C3D4E5F60"
PASSWORD = "correct horse battery"


def record_bytes():
    # Same shape as tests/test_pair_upload.py's fixture, kept local so this file has no
    # cross-test-module import.
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
        "EscrowBag": b"e",
    }
    return plistlib.dumps(record)


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(create_app(settings, DemoEngine(step_seconds=0)), follow_redirects=False) as client:
        with closing(db.connect(data / "bioseasy.db")) as conn:
            auth.create_user(conn, "admin", PASSWORD, "admin")
            auth.create_user(conn, "member", PASSWORD, "member")
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client, username):
    client.post("/login", data={"csrf": csrf(client, "/login"), "username": username, "password": PASSWORD})


def create_code(client) -> str:
    r = client.post("/add/pair-code", data={"csrf": csrf(client, "/add")})
    assert r.status_code == 303
    return r.headers["location"].rsplit("/", 1)[-1]


def hand_off(client, code, data=None, udid=UDID, name="Test iPhone"):
    headers = {}
    if udid is not None:
        headers["X-Bioseasy-UDID"] = udid
    if name is not None:
        headers["X-Bioseasy-Device-Name"] = name
    return client.post(f"/pair/{code}", content=data if data is not None else record_bytes(), headers=headers)


def test_admin_can_create_a_code_member_cannot(env):
    client, _ = env
    login(client, "admin")
    r = client.post("/add/pair-code", data={"csrf": csrf(client, "/add")})
    assert r.status_code == 303 and r.headers["location"].startswith("/add/pair-code/")
    client.cookies.clear()
    login(client, "member")
    r = client.post("/add/pair-code", data={"csrf": csrf(client, "/")})
    assert r.status_code == 404


def test_fourth_open_code_is_refused_from_the_web(env):
    client, _ = env
    login(client, "admin")
    for _ in range(handoff.MAX_OPEN_CODES_PER_USER):
        assert client.post("/add/pair-code", data={"csrf": csrf(client, "/add")}).status_code == 303
    r = client.post("/add/pair-code", data={"csrf": csrf(client, "/add")})
    assert r.status_code == 400
    assert "open pairing codes" in r.text


def test_plain_code_is_never_stored(env):
    client, settings = env
    login(client, "admin")
    code = create_code(client)
    with closing(db.connect(settings.data_dir / "bioseasy.db")) as conn:
        row = conn.execute("SELECT code_hash FROM pairing_codes").fetchone()
    assert code not in row["code_hash"]


def test_valid_record_creates_the_device_and_consumes_the_code(env):
    client, settings = env
    login(client, "admin")
    code = create_code(client)
    r = hand_off(client, code)
    assert r.status_code == 200
    assert "Paired Test iPhone" in r.text
    assert (settings.data_dir / "pair-records" / f"{UDID}.plist").is_file()
    # Single use: the same code cannot be redeemed twice.
    assert hand_off(client, code).status_code == 404
    # The status poll now redirects into the setup wizard.
    status = client.get(f"/add/pair-code/{code}/status")
    assert status.headers.get("hx-redirect") == f"/devices/{UDID}/setup"


def test_udid_header_is_stripped_and_keeps_its_case(env):
    # pairing.normalize_udid only strips; the case must match the directory mobilebackup2 writes.
    # (A case-changing assertion passed on macOS only because APFS ignores case.)
    client, settings = env
    login(client, "admin")
    code = create_code(client)
    r = hand_off(client, code, udid=f" {UDID} ")
    assert r.status_code == 200
    assert (settings.data_dir / "pair-records" / f"{UDID}.plist").is_file()


def test_script_endpoint_serves_only_while_the_code_is_open(env):
    client, _ = env
    login(client, "admin")
    code = create_code(client)
    r = client.get(f"/pair/{code}/bioseasy-pair.py")
    assert r.status_code == 200
    assert code in r.text
    assert "pymobiledevice3==11.12.5" in r.text
    hand_off(client, code)  # consumes it
    assert client.get(f"/pair/{code}/bioseasy-pair.py").status_code == 404


def test_script_endpoint_404s_for_an_unknown_code(env):
    client, _ = env
    assert client.get("/pair/ZZZZZZZZ/bioseasy-pair.py").status_code == 404


def test_wrong_code_is_rejected_with_generic_404(env):
    client, _ = env
    r = hand_off(client, "ZZZZZZZZ")
    assert r.status_code == 404
    assert r.text == "Not found"


def test_wrong_codes_are_rate_limited_per_ip(env):
    client, _ = env
    login(client, "admin")
    code = create_code(client)  # a real, still-open code, never guessed below
    for _ in range(10):
        hand_off(client, "ZZZZZZZZ")
    r = hand_off(client, "ZZZZZZZZ")
    assert r.status_code == 429
    # The throttle is keyed by IP, not by the specific wrong code, so even the real code is
    # blocked once too many wrong attempts came from this address.
    assert hand_off(client, code).status_code == 429


def test_wrong_codes_on_the_script_endpoint_are_rate_limited_per_ip(env):
    """Fetching the script must not be a cheaper
    way to guess a code than posting to it. Both share one per-IP counter."""
    client, _ = env
    login(client, "admin")
    code = create_code(client)  # a real, still-open code, never guessed below
    for _ in range(10):
        client.get("/pair/ZZZZZZZZ/bioseasy-pair.py")
    assert client.get("/pair/ZZZZZZZZ/bioseasy-pair.py").status_code == 429
    # Same counter as the POST endpoint, so a guesser cannot switch between the two to get more
    # free attempts, and the real code is blocked from this address too.
    assert client.get(f"/pair/{code}/bioseasy-pair.py").status_code == 429
    assert hand_off(client, code).status_code == 429


def test_invalid_record_is_rejected(env):
    client, _ = env
    login(client, "admin")
    code = create_code(client)
    r = hand_off(client, code, data=b"garbage")
    assert r.status_code == 404
    assert r.text == "Not found"


def test_record_without_an_escrow_bag_is_rejected(env):
    client, _ = env
    login(client, "admin")
    code = create_code(client)
    record = plistlib.loads(record_bytes())
    del record["EscrowBag"]
    r = hand_off(client, code, data=plistlib.dumps(record))
    assert r.status_code == 404
    assert r.text == "Not found"


def test_missing_udid_header_is_rejected(env):
    client, _ = env
    login(client, "admin")
    code = create_code(client)
    r = hand_off(client, code, udid=None)
    assert r.status_code == 404


def test_record_and_udid_never_appear_in_the_log(env, caplog):
    client, _ = env
    login(client, "admin")
    code = create_code(client)
    with caplog.at_level("INFO"):
        hand_off(client, code)
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert UDID not in log_text
    assert UDID[:8] in log_text
    assert "BEGIN" not in log_text  # no PEM key/certificate material either
