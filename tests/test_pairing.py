# SPDX-License-Identifier: GPL-3.0-or-later
import datetime
import plistlib
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bioseasy import pairing

UDID = "00008110-000A1B2C3D4E5F60"


def _key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test host")])
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
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


KEY, CERT = _key_and_cert()
OTHER_KEY, _ = _key_and_cert()
RECORD = {
    "HostID": "HOST",
    "SystemBUID": "BUID",
    "HostCertificate": CERT,
    "HostPrivateKey": KEY,
    "RootCertificate": CERT,
    "WiFiMACAddress": "aa:bb:cc:dd:ee:ff",
    "EscrowBag": b"escrow",
}


def test_valid_record_round_trips_with_private_permissions(tmp_path):
    folder = tmp_path / "records"
    record = pairing.parse(plistlib.dumps(RECORD))
    assert pairing.warnings(record) == []
    path = pairing.store(folder, UDID, record)
    assert path.name == f"{UDID}.plist"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert pairing.load(folder, UDID) == RECORD
    assert not list(folder.glob(".pair-*"))
    pairing.remove(folder, UDID)
    assert pairing.load(folder, UDID) is None


def test_missing_escrow_bag_is_a_warning_not_an_error():
    record = pairing.parse(plistlib.dumps({k: v for k, v in RECORD.items() if k != "EscrowBag"}))
    assert pairing.warnings(record) == ["No EscrowBag: backups will only run while the device is unlocked"]


def test_require_escrow_bag_accepts_a_complete_record():
    pairing.require_escrow_bag(RECORD)  # must not raise


def test_require_escrow_bag_rejects_a_record_without_one():
    record = {k: v for k, v in RECORD.items() if k != "EscrowBag"}
    with pytest.raises(pairing.PairRecordError, match="EscrowBag"):
        pairing.require_escrow_bag(record)


def test_normalize_udid_strips_but_keeps_the_case_the_device_reports():
    assert pairing.normalize_udid(f"  {UDID}\n") == UDID
    legacy = "a" * 40  # older 40-character UDIDs; a forced case would split it from its backup directory
    assert pairing.normalize_udid(legacy) == legacy


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"not a plist", "not a property list"),
        (plistlib.dumps(["a", "list"]), "not a pair record"),
        (plistlib.dumps({k: v for k, v in RECORD.items() if k != "WiFiMACAddress"}), "lacks WiFiMACAddress"),
        (plistlib.dumps({**RECORD, "HostPrivateKey": b""}), "lacks HostPrivateKey"),
        (plistlib.dumps({**RECORD, "HostPrivateKey": OTHER_KEY}), "does not belong"),
        (plistlib.dumps({**RECORD, "HostCertificate": b"garbage"}), "not readable"),
        (b"x" * (pairing.MAX_RECORD_BYTES + 1), "too large"),
    ],
)
def test_unusable_records_are_rejected_without_leaking_contents(data, message):
    with pytest.raises(pairing.PairRecordError, match=message) as exc:
        pairing.parse(data)
    assert "BEGIN" not in str(exc.value)


@pytest.mark.parametrize("udid", ["../etc/passwd", "", "00008110-000A1B2C3D4E5F6Z", "abc"])
def test_identifiers_cannot_escape_the_folder(tmp_path, udid):
    with pytest.raises(pairing.PairRecordError):
        pairing.store(tmp_path, udid, RECORD)


def test_both_udid_formats_are_accepted():
    assert pairing.valid_udid("00008110-000A1B2C3D4E5F60")
    assert pairing.valid_udid("a" * 40)
