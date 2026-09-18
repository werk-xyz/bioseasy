# SPDX-License-Identifier: GPL-3.0-or-later
"""Pair records: validation and storage.

A pair record lets a host talk to a device without a new "Trust" dialog, so it is as sensitive
as a password. Records live in the app data volume with mode 0600, one `<UDID>.plist` per
device, in the layout pymobiledevice3's Wi-Fi discovery reads (it matches devices by the
record's WiFiMACAddress and fails on records without it).

Records come from the USB pairing run on the server, or are uploaded when the server has no USB
(pairing done on another computer, see docs/pairing.md).
"""

from __future__ import annotations

import os
import plistlib
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Keys lockdown needs to open a session, plus the one Wi-Fi discovery matches on.
REQUIRED_KEYS = ("HostID", "SystemBUID", "HostCertificate", "HostPrivateKey", "RootCertificate", "WiFiMACAddress")
UDID_PATTERN = re.compile(r"^[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{16}$|^[0-9A-Fa-f]{40}$")
MAX_RECORD_BYTES = 64 * 1024


class PairRecordError(ValueError):
    """The record cannot be used; the message is safe to show and never contains key material."""


def valid_udid(udid: str) -> bool:
    return bool(UDID_PATTERN.fullmatch(udid))


def normalize_udid(udid: str) -> str:
    """Strips surrounding whitespace from a UDID that enters through a form, a header or a script.

    The case is deliberately left alone. mobilebackup2 writes a device's backup to
    target_root/<UniqueDeviceID> exactly as the device reports it, and the two UDID formats in use
    differ in case as far as we know: newer devices report "00008110-000A1B2C3D4E5F60" style
    values, older ones a 40-character hex string, commonly seen in lowercase. Forcing either case
    would split the database udid from the backup directory on a case-sensitive filesystem for
    one of the two. Not verified against a real device of each generation.
    """
    return udid.strip()


def parse(data: bytes) -> dict:
    if len(data) > MAX_RECORD_BYTES:
        raise PairRecordError("File is too large to be a pair record")
    try:
        record = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise PairRecordError("File is not a property list") from exc
    if not isinstance(record, dict):
        raise PairRecordError("File is not a pair record")
    missing = [key for key in REQUIRED_KEYS if not record.get(key)]
    if missing:
        raise PairRecordError("Pair record lacks " + ", ".join(missing))
    _check_key_pair(record["HostCertificate"], record["HostPrivateKey"])
    return record


def _check_key_pair(certificate: bytes, private_key: bytes) -> None:
    """The host certificate must belong to the host key, or every TLS session with the device fails."""
    try:
        cert = x509.load_pem_x509_certificate(certificate)
        key = serialization.load_pem_private_key(private_key, password=None)
    except (ValueError, TypeError) as exc:
        raise PairRecordError("Host certificate or host key is not readable") from exc
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise PairRecordError("Host certificate does not belong to the host key")


def warnings(record: dict) -> list[str]:
    """Usable but limited records: shown to the user, not rejected.

    A record can only reach here without an EscrowBag through the USB pairing flow
    (engine/pmd3.py's _pair, which stores whatever the device returned); require_escrow_bag
    below already rejects a record missing one at the two entrances that go through this
    module's own validation (upload and the pairing hand-off script).
    """
    found = []
    if not record.get("EscrowBag"):
        found.append("No EscrowBag: backups will only run while the device is unlocked")
    return found


def require_escrow_bag(record: dict) -> None:
    """Reject a record with no EscrowBag: mobilebackup2 always requests one
    (pymobiledevice3/services/mobilebackup2.py's Mobilebackup2Service.__init__ passes
    include_escrow_bag=True) and lockdown.py's get_service_connection_attributes then reads
    ``self.pair_record["EscrowBag"]`` directly - a plain KeyError, not a
    PyMobileDevice3Exception, for every operation that needs the backup service: get_will_encrypt,
    enable/change encryption and the backup itself. Without this check that KeyError would only
    surface once a backup or setup step is attempted, as an unexplained internal error.
    """
    if not record.get("EscrowBag"):
        raise PairRecordError("Pair record has no EscrowBag; pair again while the device is unlocked")


def _path(folder: Path, udid: str) -> Path:
    if not valid_udid(udid):
        raise PairRecordError("Not a valid device identifier")
    return folder / f"{udid}.plist"


def store(folder: Path, udid: str, record: dict) -> Path:
    target = _path(folder, udid)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = plistlib.dumps(record)
    # Write to a private temp file and rename, so a crash never leaves a half-written record
    # that Wi-Fi discovery would choke on.
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".pair-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def load(folder: Path, udid: str) -> dict | None:
    path = _path(folder, udid)
    if not path.is_file():
        return None
    return plistlib.loads(path.read_bytes())


def remove(folder: Path, udid: str) -> None:
    _path(folder, udid).unlink(missing_ok=True)
