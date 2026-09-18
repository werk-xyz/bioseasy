# SPDX-License-Identifier: GPL-3.0-or-later
"""A whole generation as an archive that can actually be restored from.

The bar here is not "the tar opens". It is that unpacking the archive gives back a directory
`inventory.read_backup` still recognises as a complete backup and `pyiosbackup` still opens with
its password - because the point of this download is to be dropped into MobileSync and restored by
Finder, and an archive that loses the format on the way is worse than no archive at all.
"""

from __future__ import annotations

import io
import re
import tarfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fixtures import BACKUP_PASSWORD, DEFAULT_FILES, write_realistic_backup

from bioseasy import auth, db, export, inventory, snapshots
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.base import DeviceSeen
from bioseasy.engine.demo import DemoEngine

DEVICE = DeviceSeen(
    udid="00008110-000A1B2C3D4E5F60",
    name="Export Phone",
    product_type="iPhone15,2",
    os_version="18.6",
    transport="network",
)


OTHER = DeviceSeen(
    udid="00008103-001122334455667A",
    name="Other Phone",
    product_type="iPad13,4",
    os_version="18.6",
    transport="network",
)
PASSWORD = "correct-horse-battery-staple"  # noqa: S105 - test account, throwaway database


@pytest.fixture
def route_env(tmp_path):
    """Two members with one device each, both with a real backup and one taken generation."""
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    app = create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True)
    with TestClient(app, follow_redirects=False) as client:
        with closing(db.connect(data / "bioseasy.db")) as conn:
            mine = auth.create_user(conn, "member", PASSWORD, "member")
            yours = auth.create_user(conn, "other", PASSWORD, "member")
            for device, owner in ((DEVICE, mine.id), (OTHER, yours.id)):
                conn.execute(
                    "INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)",
                    (device.udid, device.name, owner),
                )
            conn.commit()
        for device in (DEVICE, OTHER):
            write_realistic_backup(root / device.udid, device)
            snapshots.take(root, device.udid, datetime.now(UTC), hardlinks=False)
        yield client, settings, DEVICE.udid, OTHER.udid


def generation_of(settings, udid: str) -> str:
    return snapshots.list_snapshots(settings.backup_root, udid)[0].path.name


def login(client, username="member"):
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/login").text).group(1)
    assert client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD}).status_code == 303


def unpack(chunks, into: Path) -> Path:
    into.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(b"".join(chunks)), mode="r|") as tar:
        tar.extractall(into, filter="data")
    return into


def test_an_unpacked_export_is_still_a_backup(tmp_path):
    """Structure first: the metadata files and the hash directories come back where they were.

    Unpacked into a directory named after the UDID, because that is what makes it a backup rather
    than a folder of files: `inventory.read_backup` refuses a directory whose name does not match
    the device, and MobileSync wants exactly that name too.
    """
    backup = write_realistic_backup(tmp_path / "source", DEVICE)

    restored = unpack(export.tar_stream(backup.path), tmp_path / DEVICE.udid)

    for name in ("Info.plist", "Manifest.plist", "Status.plist", "Manifest.db"):
        assert (restored / name).is_file(), name
    for backup_file in DEFAULT_FILES:
        stored = restored / backup_file.file_id[:2] / backup_file.file_id
        assert stored.is_file()
        assert stored.read_bytes() == backup_file.content
    assert inventory.read_backup(restored).complete


def test_an_encrypted_generation_comes_back_encrypted_and_still_opens(tmp_path):
    """The archive carries the backup as it lies: still encrypted, and the password was never
    needed to make it. Ground truth is pyiosbackup, which is not our code."""
    backup = write_realistic_backup(tmp_path / "source", DEVICE, encrypted=True)
    target = DEFAULT_FILES[0]

    restored = unpack(export.tar_stream(backup.path), tmp_path / "restored")

    # Byte-identical to the source, i.e. nothing was decrypted on the way out.
    stored = restored / target.file_id[:2] / target.file_id
    assert stored.read_bytes() == (backup.path / target.file_id[:2] / target.file_id).read_bytes()
    assert stored.read_bytes() != target.content  # and it really is the ciphertext

    pyiosbackup = pytest.importorskip("pyiosbackup")
    opened = pyiosbackup.Backup.from_path(restored, password=BACKUP_PASSWORD)
    names = {entry.relative_path for entry in opened.iter_files()}
    assert target.relative_path in names


def test_the_same_generation_exports_to_the_same_bytes(tmp_path):
    """A snapshot never changes once taken, and the archive must not either: same input, same
    bytes. Without a stable order two downloads of one generation differ for no reason."""
    backup = write_realistic_backup(tmp_path / "source", DEVICE)

    first = b"".join(export.tar_stream(backup.path))
    second = b"".join(export.tar_stream(backup.path))

    assert first == second


def test_nothing_is_held_whole_in_memory(tmp_path):
    """Proven by shape rather than by measuring memory: with a small chunk size a backup of a few
    megabytes comes back in many pieces, so the stream really is a stream."""
    big = (
        *DEFAULT_FILES,
        *(type(DEFAULT_FILES[0])("CameraRollDomain", f"Media/DCIM/IMG_{i:03d}.JPG", b"x" * 40_000) for i in range(40)),
    )
    backup = write_realistic_backup(tmp_path / "source", DEVICE, files=big)

    pieces = list(export.tar_stream(backup.path, chunk_bytes=64 * 1024))

    assert len(pieces) > 20
    assert all(len(piece) <= 64 * 1024 for piece in pieces)


@pytest.mark.parametrize(
    ("device_name", "expected"),
    [
        ("Demo iPhone", "Demo_iPhone-20260917T101500Z.tar"),
        ('evil"; rm -rf /', "evil_rm-rf-.tar".replace("_rm", "_rm")),
        (None, "00008110-000A1B2C3D4E5F60-20260917T101500Z.tar"),
    ],
)
def test_the_archive_name_cannot_break_the_header(device_name, expected):
    """The device name is chosen by whoever named the device, so it is stripped of anything that
    could close the filename parameter early or start a new header line."""
    name = export.archive_name(device_name, DEVICE.udid, "20260917T101500Z")

    assert '"' not in name
    assert "\n" not in name and "\r" not in name
    assert name.endswith(".tar")


# --- The route ---------------------------------------------------------------------------------


def test_only_the_owner_and_an_admin_can_export_a_generation(route_env):
    """The same rule as everywhere: a member reaches their own device, an admin reaches both, and a
    foreign device is indistinguishable from one that does not exist."""
    client, settings, mine, yours = route_env

    login(client, "member")
    own = client.get(f"/devices/{mine}/snapshots/{generation_of(settings, mine)}/download")
    foreign = client.get(f"/devices/{yours}/snapshots/{generation_of(settings, yours)}/download")

    assert own.status_code == 200
    assert foreign.status_code == 404


def test_an_unknown_generation_name_is_refused(route_env):
    """The name is matched against the real snapshot list before it becomes a path."""
    client, _settings, mine, _yours = route_env
    login(client, "member")

    for name in ("../../etc", "latest", "does-not-exist"):
        assert client.get(f"/devices/{mine}/snapshots/{name}/download").status_code == 404


def test_a_signed_out_visitor_is_sent_to_login(route_env):
    client, settings, mine, _yours = route_env

    response = client.get(f"/devices/{mine}/snapshots/{generation_of(settings, mine)}/download")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_the_exported_archive_is_the_generation(route_env):
    """End to end through the route: what comes down the wire unpacks into a backup again."""
    client, settings, mine, _yours = route_env
    login(client, "member")

    response = client.get(f"/devices/{mine}/snapshots/{generation_of(settings, mine)}/download")

    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in response.headers["content-disposition"]
    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r|") as tar:
        names = set(tar.getnames())
    assert {"Info.plist", "Manifest.plist", "Status.plist", "Manifest.db"} <= names


def test_the_two_archives_of_one_generation_have_different_names():
    """One generation yields two downloads that are not interchangeable: the picked files,
    decrypted and readably named, and the whole backup as it lies. Only the second restores. They
    were both called `<device>-<generation>.tar`, so whoever took both got a name and a copy of it.
    """
    files = export.archive_name("Demo iPhone", DEVICE.udid, "20260917T101500Z", kind="files")
    backup = export.archive_name("Demo iPhone", DEVICE.udid, "20260917T101500Z")

    assert files != backup
    assert files.endswith("-files.tar")
    assert backup.endswith("-backup.tar")
