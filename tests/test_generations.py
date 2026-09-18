# SPDX-License-Identifier: GPL-3.0-or-later
import re
import time
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, snapshots
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine, write_backup

PHONE = DEMO_DEVICES[0]
PASSWORD = "correct horse battery"


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


def _seed_generations(settings, count=2):
    """A live backup plus `count` hard-linked snapshots, as the demo engine and jobs.py produce."""
    write_backup(settings.backup_root / PHONE.udid, PHONE)
    names = []
    for _ in range(count):
        snap = snapshots.take(settings.backup_root, PHONE.udid, datetime.now(UTC), hardlinks=True)
        names.append(snap.name)
        time.sleep(1.1)  # timestamps are second-resolution; force distinct names
    return names


def test_generations_section_lists_snapshots_with_sizes(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=2)

    page = client.get(f"/devices/{PHONE.udid}").text
    assert "Generations" in page
    assert "Total space used" in page
    for name in names:
        assert name in page  # used in the pin form's action URL
    # A shape check on the size column rather than an exact byte count: the demo backup's exact
    # size is an implementation detail of write_backup, not part of this contract.
    assert re.search(r"\d+(\.\d+)?\s*(Bytes|kB|KB|MB)", page)
    assert "Not pinned" in page
    assert "Kept by" in page
    assert "latest" in page  # both generations fall under the default keep_last rule


def test_pin_unpin_survives_retention(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=3)
    oldest = names[0]

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/snapshots/{oldest}/pin", data={"csrf": token, "pinned": "1"})
    assert r.status_code == 303
    assert r.headers["location"] == url

    snaps = {s.path.name: s.pinned for s in snapshots.list_snapshots(settings.backup_root, PHONE.udid)}
    assert snaps[oldest] is True

    # Retention with keep_last=1 would normally drop everything but the newest; the pin must save it.
    policy = snapshots.RetentionPolicy(keep_last=1)
    removed = snapshots.apply_retention(settings.backup_root, PHONE.udid, policy, UTC, datetime.now(UTC))
    remaining = {s.path.name for s in snapshots.list_snapshots(settings.backup_root, PHONE.udid)}
    assert oldest in remaining
    assert oldest not in {p.name for p in removed}

    # Unpin it again through the same route.
    token = csrf(client, url)
    r = client.post(f"{url}/snapshots/{oldest}/pin", data={"csrf": token, "pinned": "0"})
    assert r.status_code == 303
    snaps = {s.path.name: s.pinned for s in snapshots.list_snapshots(settings.backup_root, PHONE.udid)}
    assert snaps[oldest] is False


def test_pin_htmx_request_returns_the_swapped_section(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(
        f"{url}/snapshots/{names[0]}/pin", data={"csrf": token, "pinned": "1"}, headers={"hx-request": "true"}
    )
    assert r.status_code == 200
    assert '<section id="generations"' in r.text
    assert "Pinned" in r.text


def test_pin_unknown_snapshot_name_is_404(env):
    client, settings = env
    make_admin_with_device(client, settings)
    _seed_generations(settings, count=1)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/snapshots/20200101T000000Z/pin", data={"csrf": token, "pinned": "1"})
    assert r.status_code == 404


@pytest.mark.parametrize(
    "raw_name",
    [
        "..%2F..",
        "..%2f..%2f..%2fetc%2fpasswd",
        "{name}.pinned",  # targets the pin marker file directly, never a real snapshot directory
        "{name}.partial",
    ],
)
def test_pin_path_traversal_attempts_are_404_and_create_nothing(env, raw_name):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)
    name = raw_name.format(name=names[0])

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    before = sorted(p.name for p in (settings.backup_root / ".bioseasy" / "snapshots" / PHONE.udid).iterdir())

    r = client.post(f"{url}/snapshots/{name}/pin", data={"csrf": token, "pinned": "1"})
    assert r.status_code == 404

    after = sorted(p.name for p in (settings.backup_root / ".bioseasy" / "snapshots" / PHONE.udid).iterdir())
    assert after == before  # no marker, partial or directory was created by the attempt

    # Nothing escaped the snapshots directory either.
    assert not (settings.backup_root / "etc" / "passwd").exists()


def test_member_cannot_pin_or_open_restore_page_of_a_foreign_device(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")

    assert client.get(f"/devices/{PHONE.udid}/restore").status_code == 404

    token = csrf(client, "/")
    r = client.post(f"/devices/{PHONE.udid}/snapshots/{names[0]}/pin", data={"csrf": token, "pinned": "1"})
    assert r.status_code == 404


def test_pin_without_csrf_is_403(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)

    r = client.post(f"/devices/{PHONE.udid}/snapshots/{names[0]}/pin", data={"pinned": "1"})
    assert r.status_code == 403
    snaps = {s.path.name: s.pinned for s in snapshots.list_snapshots(settings.backup_root, PHONE.udid)}
    assert snaps[names[0]] is False  # the missing-csrf request never reached the pin logic


def test_restore_guide_lists_live_backup_and_snapshots_with_container_paths(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=2)

    page = client.get(f"/devices/{PHONE.udid}/restore")
    assert page.status_code == 200
    text = page.text
    assert "Restoring overwrites the device" in text
    assert str(settings.backup_root / PHONE.udid) in text
    for name in names:
        assert str(settings.backup_root / ".bioseasy" / "snapshots" / PHONE.udid / name) in text
    assert "pymobiledevice3 backup2 restore" in text
    assert "MobileSync" in text
    assert "not verified" in text  # the unverified Windows subfolder is called out, not guessed


def test_restore_guide_is_linked_from_the_device_page(env):
    client, settings = env
    make_admin_with_device(client, settings)
    _seed_generations(settings, count=1)

    page = client.get(f"/devices/{PHONE.udid}").text
    assert f"/devices/{PHONE.udid}/restore" in page


def test_restore_guide_for_a_chosen_generation_shows_only_that_snapshot_path(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=2)

    page = client.get(f"/devices/{PHONE.udid}/restore?snapshot={names[0]}")
    assert page.status_code == 200
    text = page.text
    chosen = settings.backup_root / ".bioseasy" / "snapshots" / PHONE.udid / names[0]
    other = settings.backup_root / ".bioseasy" / "snapshots" / PHONE.udid / names[1]
    live = settings.backup_root / PHONE.udid
    assert str(chosen) in text
    assert str(other) not in text  # only the chosen generation's path is shown, not every one
    assert str(live) not in text  # nor the live backup, once a specific generation is chosen
    assert "hard-linked" in text  # copy, not move, warning
    assert "iMazing" in text


def test_restore_guide_404s_on_an_unknown_snapshot_name(env):
    client, settings = env
    make_admin_with_device(client, settings)
    _seed_generations(settings, count=1)

    assert client.get(f"/devices/{PHONE.udid}/restore?snapshot=not-a-real-generation").status_code == 404


def test_restore_guide_404s_on_a_path_traversal_attempt(env):
    client, settings = env
    make_admin_with_device(client, settings)
    _seed_generations(settings, count=1)

    r = client.get(f"/devices/{PHONE.udid}/restore", params={"snapshot": "../../etc/passwd"})
    assert r.status_code == 404
    # Nothing escaped the snapshots directory: the traversal string was only ever compared
    # against the real list of names, never turned into a path.
    assert not (settings.backup_root / "etc" / "passwd").exists()


def test_restore_guide_generation_link_is_in_the_generations_table(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)

    page = client.get(f"/devices/{PHONE.udid}").text
    assert f"/devices/{PHONE.udid}/restore?snapshot={names[0]}" in page


def test_member_gets_404_for_a_chosen_generation_on_a_foreign_device(env):
    client, settings = env
    make_admin_with_device(client, settings)
    names = _seed_generations(settings, count=1)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")

    assert client.get(f"/devices/{PHONE.udid}/restore?snapshot={names[0]}").status_code == 404
