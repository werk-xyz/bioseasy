# SPDX-License-Identifier: GPL-3.0-or-later
"""A realistic Finder/iTunes-format backup directory, written by hand.

Two callers: the test suite, which needs more than `engine.demo.write_backup`'s minimal shape,
and `demo_seed.py`, which fills a demo deployment with browsable demo generations. It lives in `src`
rather than in `tests` because the demo seed runs inside the shipped image; a second copy of the
encryption code would be the alternative, and one of the two would drift.

Layout and field names are checked against two sources:

- bioseasy's own reader, `inventory.py` (`Info.plist`, `Manifest.plist` with an `IsEncrypted`
  flag, `Status.plist` with `SnapshotState`/`IsFullBackup`/`Date`, `Manifest.db`).
- the installed pymobiledevice3 package (11.12.5, under
  .venv/lib/python3.12/site-packages/pymobiledevice3/services/mobilebackup2.py), which is the
  device-facing client for this exact format:
    * `Manifest.db`'s `Files` table: `SELECT fileID, domain, relativePath FROM Files`
      (mobilebackup2.py:886, also :761-789 for how a domain/relativePath pair is matched).
    * hashed files are stored two-hex-char-prefixed: `device_directory/<fileID[:2]>/<fileID>`
      (mobilebackup2.py:816-849, `allowed_prefixes = {file_id[:2] for file_id in
      allowed_file_ids}` and the iteration that walks `path.name` prefix directories).
    * `Manifest.db`, `Manifest.db-shm`, `Manifest.db-wal`, `Info.plist`, `Status.plist` are listed
      as `BACKUP_METADATA_FILES` (mobilebackup2.py:76-78) -- i.e. kept apart from the per-file
      hash-prefix directories.

The `flags` and `file` columns of `Files` are NOT verified against pymobiledevice3: the device
itself creates and populates Manifest.db during a real backup, so the client package only ever
*queries* three of the columns (fileID, domain, relativePath) and never creates the table. Their
names and general shape here follow the publicly documented iTunes/Finder backup format (used
throughout the open-source iOS-forensics tooling ecosystem); this generator does not depend on
their exact types being read anywhere in bioseasy, only on fileID/domain/relativePath and on the
row count when a test asserts against those.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import sqlite3
import struct
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from bpylist2 import archiver
from bpylist2.archive_types import NSMutableData
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from pyiosbackup.keybag import keybag_struct
from pyiosbackup.manifest_dbs.sqlite3 import MBFile

from bioseasy.engine.base import DeviceSeen

# The default backup encryption password an encrypted fixture is built for. Marked demo
# material: it protects nothing but the bytes this module writes into a tmp_path or into the
# sandbox, and nothing real ever joins it. Callers may pass their own; `demo_seed.py` does.
BACKUP_PASSWORD = "trubble w1th tribbles"  # noqa: S105

# One key class, the minimum Keybag.from_manifest accepts. The derivation follows the modern
# path, not the shortcut: above iOS 10.2 the password is first run through PBKDF2-SHA256 over
# DPSL/DPIC and only then through PBKDF2-SHA1 over SALT/ITER. tests/test_password_check.py's
# smaller fixture declares product version 9.0 to skip that first round; this one does not,
# because the devices bioseasy actually backs up are far above 10.2 and a fixture that avoids the
# real derivation would not prove the real path works.
_KEYBAG_CLASS = 1
_CLASS_KEY = b"K" * 32
_KEYBAG_ITERATIONS = 1000
_KEYBAG_DPIC = 1000
# Apple encrypts file payloads with AES-CBC under a zero IV, after unwrapping a per-file key with
# AES key wrap (pyiosbackup.keybag.aes_decrypt_wrapped). Payloads carry PKCS7 padding; Manifest.db
# does not - pyiosbackup decrypts it and unpads nothing, and a SQLite file is a whole number of
# pages, so it is already a multiple of the block size.
_ZERO_IV = b"\x00" * 16
_PAD_BITS = 128


def _replace(path: Path, data: bytes) -> None:
    """Write `data` at `path`, unlinking first.

    Writing in place would be wrong wherever this directory has already been snapshotted with
    `rsync --link-dest`: the old file and the snapshot's copy are then the same inode, and
    truncating it rewrites history. Unlinking breaks the link and leaves the snapshot alone. Only
    `demo_seed.py` writes the same directory more than once, but the trap belongs to the writer.
    """
    path.unlink(missing_ok=True)
    path.write_bytes(data)


def _wrapped_key(file_key: bytes) -> bytes:
    """The `EncryptionKey` shape a real MBFile carries: class number, then the wrapped key."""
    return struct.pack("<I", _KEYBAG_CLASS) + aes_key_wrap(_CLASS_KEY, file_key)


def _encrypt(data: bytes, file_key: bytes, *, pad: bool) -> bytes:
    if pad:
        padder = padding.PKCS7(_PAD_BITS).padder()
        data = padder.update(data) + padder.finalize()
    # CBC without authentication is Apple's backup format, not a choice: a reader that expects
    # anything else cannot open a real backup. Only this module's own demo bytes are written
    # with it. The reader in extract.py carries the same note.
    # nosemgrep: python.cryptography.security.mode-without-authentication.crypto-mode-without-authentication
    encryptor = Cipher(algorithms.AES(file_key), modes.CBC(_ZERO_IV)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _build_keybag(password: str) -> bytes:
    dpsl, salt = b"D" * 20, b"S" * 20
    pre_hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), dpsl, _KEYBAG_DPIC, 32)
    decryption_key = hashlib.pbkdf2_hmac("sha1", pre_hashed, salt, _KEYBAG_ITERATIONS, 32)
    wrapped_class_key = aes_key_wrap(decryption_key, _CLASS_KEY)
    # Root elements first (everything before the first CLAS tag), then the one class.
    return keybag_struct.build(
        [
            {"tag": b"DPSL", "size": len(dpsl), "data": dpsl},
            {"tag": b"DPIC", "size": 4, "data": _KEYBAG_DPIC},
            {"tag": b"SALT", "size": len(salt), "data": salt},
            {"tag": b"ITER", "size": 4, "data": _KEYBAG_ITERATIONS},
            {"tag": b"CLAS", "size": 4, "data": _KEYBAG_CLASS},
            {"tag": b"WRAP", "size": 4, "data": 2},
            {"tag": b"WPKY", "size": len(wrapped_class_key), "data": wrapped_class_key},
            {"tag": b"KTYP", "size": 4, "data": 0},
            {"tag": b"PBKY", "size": 32, "data": b"P" * 32},
        ]
    )


def _encode_mbfile(obj, archive) -> None:
    """bpylist2 encoder for MBFile. pyiosbackup only ships the decoder, so a fixture that wants to
    write the blob a real device writes has to supply this half itself."""
    archive.encode("RelativePath", obj.relative_path)
    archive.encode("LastModified", obj.last_modified)
    archive.encode("LastStatusChange", obj.last_status_change)
    archive.encode("Birth", obj.created)
    archive.encode("Size", obj.size)
    archive.encode("Mode", obj.mode)
    archive.encode("GroupID", obj.group_id)
    archive.encode("UserID", obj.user_id)
    if obj.encryption_key:
        archive.encode("EncryptionKey", NSMutableData(obj.encryption_key))


MBFile.encode_archive = staticmethod(_encode_mbfile)


def _mbfile_blob(backup_file, encryption_key: bytes) -> bytes:
    """The NSKeyedArchiver `file` blob a real Manifest.db row carries."""
    return archiver.archive(
        MBFile(
            relative_path=backup_file.relative_path,
            last_modified=1_700_000_000,
            last_status_change=1_700_000_000,
            created=1_700_000_000,
            size=len(backup_file.content),
            mode=0o40755 if backup_file.flags == 2 else 0o100644,
            group_id=501,
            user_id=501,
            encryption_key=encryption_key,
        )
    )


@dataclass(frozen=True)
class BackupFile:
    domain: str
    relative_path: str
    content: bytes = b""
    # 1 = regular file, 2 = domain directory entry (no payload of its own), 4 = symlink - the
    # real device-written format (see verify.py's DIRECTORY_FLAG). Regular file is the default;
    # verify.py's own tests pass 2 to build a directory-only row that must never be reported
    # missing even though it has no on-disk payload.
    flags: int = 1

    @property
    def file_id(self) -> str:
        # Real devices key each Files row by SHA1("Domain-RelativePath"); this is how
        # mobilebackup2.py's own prefix pruning (file_id[:2]) is meant to line up with the
        # two-hex-char storage directories it walks.
        # SHA1 is the format's own identifier for a row, not a signature, and a different hash
        # would simply not find the file a real device wrote.
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        return hashlib.sha1(f"{self.domain}-{self.relative_path}".encode(), usedforsecurity=False).hexdigest()


DEFAULT_FILES = (
    BackupFile("HomeDomain", "Library/SMS/sms.db", b"sms-db-contents"),
    BackupFile("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", b"contacts-contents"),
    BackupFile("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG", b"jpeg-bytes"),
)


@dataclass(frozen=True)
class RealisticBackup:
    path: Path
    device: DeviceSeen
    files: tuple[BackupFile, ...]

    def hashed_file_path(self, backup_file: BackupFile) -> Path:
        return self.path / backup_file.file_id[:2] / backup_file.file_id


# nosemgrep: python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument
def write_realistic_backup(
    path: Path,
    device: DeviceSeen,
    *,
    encrypted: bool = False,
    snapshot_state: str = "finished",
    is_full_backup: bool = False,
    files: tuple[BackupFile, ...] = DEFAULT_FILES,
    password: str = BACKUP_PASSWORD,  # the marked demo credential above, never a real one
    serial: str = "REALISTICFIXTURE01",
    write_manifest_db: bool = True,
    write_hashed_files: bool = True,
    now: datetime | None = None,
) -> RealisticBackup:
    """Write a structurally real Finder-format backup directory at `path`.

    `path`'s name is expected to be the device UDID, matching what `inventory.read_backup`
    requires and what a real Finder backup root looks like (one directory per device, named after
    its UDID).
    """
    path.mkdir(parents=True, exist_ok=True)
    now = (now or datetime.now(UTC)).replace(tzinfo=None)

    info = {
        "Device Name": device.name,
        "Display Name": device.name,
        "Product Type": device.product_type,
        "Product Version": device.os_version,
        "Serial Number": serial,
        "Unique Identifier": device.udid,
        "Target Identifier": device.udid,
        "Last Backup Date": now,
    }
    manifest = {
        "IsEncrypted": encrypted,
        "Version": "10.0",
        "Lockdown": {
            "UniqueDeviceID": device.udid,
            "ProductVersion": device.os_version,
            "ProductType": device.product_type,
            "DeviceName": device.name,
        },
        "Applications": {},
        "WasPasscodeSet": True,
    }
    status = {
        "SnapshotState": snapshot_state,
        "IsFullBackup": is_full_backup,
        "Date": now,
        "Version": "3.3",
        "UUID": str(uuid.uuid4()).upper(),
    }
    # One random key per payload plus one for Manifest.db, each wrapped under the class key - the
    # same shape a device writes. Kept here because both the blob in Manifest.db and the payload
    # on disk need the same key.
    file_keys = {bf.file_id: os.urandom(32) for bf in files} if encrypted else {}
    manifest_key = os.urandom(32) if encrypted else b""
    if encrypted:
        manifest["BackupKeyBag"] = _build_keybag(password)
        manifest["ManifestKey"] = _wrapped_key(manifest_key)

    for name, data in (("Info.plist", info), ("Manifest.plist", manifest), ("Status.plist", status)):
        _replace(path / name, plistlib.dumps(data))

    if write_manifest_db:
        db_path = path / "Manifest.db"
        db_path.unlink(missing_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)"
            )
            for backup_file in files:
                # flags=1 is the real device's marker for "regular file" (2 is "directory", 4 is
                # "symlink") in the public format; verify.py is the first bioseasy code path that
                # reads it back.
                conn.execute(
                    "INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?, ?, ?, ?, ?)",
                    (
                        backup_file.file_id,
                        backup_file.domain,
                        backup_file.relative_path,
                        backup_file.flags,
                        # The NSKeyedArchiver blob a real row carries: size, mode, and - on an
                        # encrypted backup - the wrapped per-file key that decryption needs.
                        _mbfile_blob(backup_file, _wrapped_key(file_keys[backup_file.file_id]) if encrypted else b""),
                    ),
                )
            conn.commit()
        if encrypted:
            # No PKCS7 here: pyiosbackup decrypts Manifest.db and unpads nothing, and a SQLite
            # file is a whole number of pages, so it is already a multiple of the block size.
            _replace(db_path, _encrypt(db_path.read_bytes(), manifest_key, pad=False))

    if write_hashed_files:
        for backup_file in files:
            if backup_file.flags == 2:
                continue  # a domain directory entry has no payload file to write
            hashed_path = path / backup_file.file_id[:2] / backup_file.file_id
            hashed_path.parent.mkdir(parents=True, exist_ok=True)
            content = backup_file.content
            if encrypted:
                content = _encrypt(content, file_keys[backup_file.file_id], pad=True)
            _replace(hashed_path, content)

    # Date every file to the backup's own time. Without it, a caller that writes several
    # generations into the same directory in quick succession (demo_seed.py does) leaves them all
    # with the same size and the same mtime-to-the-second, and rsync's quick check then treats the
    # next snapshot as unchanged and hard-links it to the previous one - so a generation written
    # as encrypted ends up sharing the plaintext Manifest.db of the one before it.
    stamp = now.replace(tzinfo=UTC).timestamp()
    for child in path.rglob("*"):
        if child.is_file():
            os.utime(child, (stamp, stamp))

    return RealisticBackup(path=path, device=device, files=files)
