# SPDX-License-Identifier: GPL-3.0-or-later
"""GET /devices/{udid}/files and .../files/download: browsing one backup and downloading one file.

tests/test_extract.py covers the reading itself. This file covers the two things that only exist
at the HTTP boundary: that a member reaches their own devices and nothing else, and that a file
the server never produced is handed out in a way that cannot execute in the browser.
"""

from __future__ import annotations

import io
import re
import tarfile
import threading
import time
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from fixtures import BACKUP_PASSWORD, DEFAULT_FILES, BackupFile, write_realistic_backup

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.base import DeviceSeen, Transport
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
MINE = DeviceSeen(
    udid="00008110-000A1B2C3D4E5F60",
    name="My iPhone",
    product_type="iPhone15,2",
    os_version="18.6",
    transport=Transport.WIFI,
)
YOURS = DeviceSeen(
    udid="00008103-001122334455667A",
    name="Their iPad",
    product_type="iPad13,4",
    os_version="18.6",
    transport=Transport.WIFI,
)


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


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username):
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/login").text).group(1)
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303


def seed(settings, *, encrypted=False, files=DEFAULT_FILES):
    """Two members, one device each, with a real backup directory on disk for both."""
    with conn_for(settings) as conn:
        mine = auth.create_user(conn, "member", PASSWORD, "member")
        yours = auth.create_user(conn, "other", PASSWORD, "member")
        for device, owner in ((MINE, mine.id), (YOURS, yours.id)):
            conn.execute(
                "INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)",
                (device.udid, device.name, owner),
            )
        conn.commit()
    for device in (MINE, YOURS):
        write_realistic_backup(settings.backup_root / device.udid, device, encrypted=encrypted, files=files)


# --- Browsing ---------------------------------------------------------------------------------


def test_a_member_browses_their_own_backup(env):
    client, settings = env
    seed(settings)
    login(client, "member")

    areas = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    assert "HomeDomain" in areas
    assert "CameraRollDomain" in areas

    inside = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "HomeDomain", "path": "Library/SMS"},
    ).text
    assert "sms.db" in inside


def test_a_member_cannot_browse_another_owners_backup(env):
    """404, not 403: a foreign device must be indistinguishable from one that does not exist."""
    client, settings = env
    seed(settings)
    login(client, "member")

    assert client.get(f"/devices/{YOURS.udid}/files").status_code == 404
    response = client.get(
        f"/devices/{YOURS.udid}/files/download", params={"file_id": DEFAULT_FILES[0].file_id, "snapshot": "latest"}
    )
    assert response.status_code == 404


def test_choosing_an_area_lists_it_at_once(env):
    """No Search press in between: picking an area opens its contents."""
    client, settings = env
    seed(settings)
    login(client, "member")

    only_camera = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
    ).text
    assert "IMG_0001.JPG" in only_camera
    # The full path, not the bare name: the search box carries "sms.db" as its placeholder, so the
    # name alone is on every rendering of this page.
    assert "Library/SMS/sms.db" not in only_camera

    searched = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "AddressBook"}).text
    assert "AddressBook.sqlitedb" in searched

    narrowed = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "q": "AddressBook", "scope": "domain"},
    ).text
    assert "No files match" in narrowed  # the contacts database is not in the camera roll


def test_an_unknown_generation_name_is_refused(env):
    """The snapshot name is matched against the real list before it becomes a path."""
    client, settings = env
    seed(settings)
    login(client, "member")

    for name in ("../../etc", "does-not-exist", "2026-01-01T00-00-00Z"):
        assert client.get(f"/devices/{MINE.udid}/files", params={"snapshot": name}).status_code == 404


def test_an_encrypted_backup_asks_for_the_password_instead_of_showing_an_empty_list(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    assert "encrypted" in page.lower()
    assert 'name="backup_password"' in page
    # Not an empty listing, which would read as "this backup has no files".
    assert "No files match this filter." not in page
    assert "Library/SMS/sms.db" not in page


def csrf_of(client, udid, snapshot="latest"):
    page = client.get(f"/devices/{udid}/files", params={"snapshot": snapshot}).text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def unlock(client, udid, password, snapshot="latest"):
    token = csrf_of(client, udid, snapshot)
    return client.post(
        f"/devices/{udid}/files/unlock",
        params={"snapshot": snapshot},
        data={"csrf": token, "backup_password": password},
    )


def test_the_right_backup_password_unlocks_the_listing(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    response = unlock(client, MINE.udid, BACKUP_PASSWORD)
    assert response.status_code == 303

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    assert "HomeDomain" in page  # the areas of the unlocked generation
    assert 'name="backup_password"' not in page
    assert "Lock now" in page


def test_a_wrong_backup_password_is_reported_and_not_kept(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    page = unlock(client, MINE.udid, "definitely not it").text
    assert "does not open this generation" in page
    assert "CameraRollDomain" not in page

    # And nothing was remembered: the next visit still asks.
    assert 'name="backup_password"' in client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text


def test_downloading_from_an_encrypted_backup_returns_the_decrypted_bytes(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)
    target = next(f for f in DEFAULT_FILES if f.relative_path.endswith("IMG_0001.JPG"))

    response = client.get(
        f"/devices/{MINE.udid}/files/download", params={"file_id": target.file_id, "snapshot": "latest"}
    )

    assert response.status_code == 200
    assert response.content == target.content
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("attachment")


def test_an_encrypted_file_cannot_be_downloaded_without_unlocking(env):
    """Not the ciphertext, and not an error that names which of several reasons applied."""
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    response = client.get(
        f"/devices/{MINE.udid}/files/download", params={"file_id": DEFAULT_FILES[0].file_id, "snapshot": "latest"}
    )

    assert response.status_code == 404


def test_locking_again_forgets_the_password(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)

    token = re.search(
        r'name="csrf" value="([^"]+)"', client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    ).group(1)
    assert client.post(f"/devices/{MINE.udid}/files/lock", data={"csrf": token}).status_code == 303

    assert 'name="backup_password"' in client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text


def test_an_unlock_belongs_to_one_session_only(env):
    """The password is held against an opaque per-session handle, not against the account.

    A second sign-in - the same user in another browser - starts locked, or an unlock on a shared
    computer would silently follow the account everywhere.
    """
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)
    assert "HomeDomain" in client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text

    other = TestClient(client.app, follow_redirects=False)
    login(other, "member")

    assert 'name="backup_password"' in other.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text


def test_signing_out_drops_the_backup_password(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)

    token = re.search(
        r'name="csrf" value="([^"]+)"', client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    ).group(1)
    client.post("/logout", data={"csrf": token})
    login(client, "member")

    assert 'name="backup_password"' in client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text


def test_a_member_cannot_unlock_another_owners_backup(env):
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    token = re.search(
        r'name="csrf" value="([^"]+)"', client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text
    ).group(1)
    response = client.post(
        f"/devices/{YOURS.udid}/files/unlock", data={"csrf": token, "backup_password": BACKUP_PASSWORD}
    )

    assert response.status_code == 404


# --- Downloading ------------------------------------------------------------------------------


def test_downloading_a_file_returns_its_stored_bytes(env):
    client, settings = env
    seed(settings)
    login(client, "member")
    target = next(f for f in DEFAULT_FILES if f.relative_path.endswith("IMG_0001.JPG"))

    response = client.get(
        f"/devices/{MINE.udid}/files/download", params={"file_id": target.file_id, "snapshot": "latest"}
    )

    assert response.status_code == 200
    assert response.content == target.content


def test_a_download_can_never_execute_in_the_browser(env):
    """The decisive property of this feature.

    A backup holds arbitrary files the server never produced. Served with their real type from
    this origin, an HTML file among them would be stored cross-site scripting against the
    signed-in user. So: always octet-stream, always an attachment, always nosniff.
    """
    client, settings = env
    seed(
        settings,
        files=(BackupFile("HomeDomain", "Library/evil.html", b"<script>alert(1)</script>"),),
    )
    login(client, "member")
    file_id = BackupFile("HomeDomain", "Library/evil.html", b"").file_id

    response = client.get(f"/devices/{MINE.udid}/files/download", params={"file_id": file_id, "snapshot": "latest"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("attachment")


def test_a_hostile_file_name_cannot_break_the_download_header(env):
    """The name comes from the backed-up path, which the server never chose - a newline in it
    would be header injection, not a cosmetic problem."""
    client, settings = env
    nasty = 'Library/one"two\nthree.txt'
    seed(settings, files=(BackupFile("HomeDomain", nasty, b"payload"),))
    login(client, "member")
    file_id = BackupFile("HomeDomain", nasty, b"").file_id

    response = client.get(f"/devices/{MINE.udid}/files/download", params={"file_id": file_id, "snapshot": "latest"})

    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert "\n" not in disposition and "\r" not in disposition
    assert response.content == b"payload"


def test_downloading_an_unknown_file_is_refused(env):
    client, settings = env
    seed(settings)
    login(client, "member")

    for bad in ("0" * 40, "../../../../etc/passwd", "not-a-hash", ""):
        response = client.get(f"/devices/{MINE.udid}/files/download", params={"file_id": bad, "snapshot": "latest"})
        assert response.status_code in (404, 422), bad


def test_signed_out_visitors_are_sent_to_login(env):
    client, settings = env
    seed(settings)

    response = client.get(f"/devices/{MINE.udid}/files")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# --- The three-step flow, the timeline and several files at once -------------------------------


def test_the_landing_page_offers_generations_rather_than_a_dead_search_box(env):
    """The complaint that started the redesign: a search box above a locked backup is a control
    that cannot work, with the way to unlock hidden below it."""
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files").text

    assert "Pick a generation" in page
    assert "Latest backup" in page
    assert 'name="q"' not in page
    assert 'name="backup_password"' not in page


def test_an_open_generation_keeps_the_others_one_click_away(env):
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text

    assert 'aria-label="Generations"' in page
    assert 'aria-current="page"' in page


def test_a_password_already_held_is_tried_on_another_generation_first(env):
    """Generations usually share one password, so switching must not ask again.

    Both generations here are encrypted with the same password; unlocking one has to be enough.
    """
    client, settings = env
    seed(settings, encrypted=True)
    with conn_for(settings) as conn:
        conn.commit()
    # A second generation of the same device, same password.
    from bioseasy import snapshots

    taken = snapshots.take(settings.backup_root, MINE.udid, datetime.now(UTC), hardlinks=False)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": taken.name}).text

    assert 'name="backup_password"' not in page
    assert "HomeDomain" in page


def test_several_files_come_back_as_one_tar(env):
    client, settings = env
    seed(settings)
    login(client, "member")
    wanted = [f for f in DEFAULT_FILES if f.flags == 1]

    token = csrf_of(client, MINE.udid)
    response = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        # The shape a browser sends for repeated checkboxes: one key, several values. (httpx
        # encodes a list of (key, value) tuples differently and the CSRF field is lost in it.)
        data={"csrf": token, "file_id": [f.file_id for f in wanted]},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    with tarfile.open(fileobj=io.BytesIO(response.content)) as tar:
        names = set(tar.getnames())
        assert names == {f"{f.domain}/{f.relative_path}" for f in wanted}
        for f in wanted:
            assert tar.extractfile(f"{f.domain}/{f.relative_path}").read() == f.content


def test_selecting_nothing_just_returns_to_the_list(env):
    client, settings = env
    seed(settings)
    login(client, "member")

    token = csrf_of(client, MINE.udid)
    response = client.post(f"/devices/{MINE.udid}/files/download", params={"snapshot": "latest"}, data={"csrf": token})

    assert response.status_code == 303


def test_a_member_cannot_pull_a_tar_out_of_another_owners_backup(env):
    """The scope guard on the newest route, checked in both directions.

    A read confinement without the matching write confinement is the failure this project keeps
    watching for, and `POST .../files/download` was the one route of the pair that no test had
    driven with a foreign UDID.
    """
    client, settings = env
    seed(settings)
    login(client, "member")
    wanted = [f.file_id for f in DEFAULT_FILES if f.flags == 1]
    token = csrf_of(client, MINE.udid)

    foreign = client.post(
        f"/devices/{YOURS.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": token, "file_id": wanted},
    )
    own = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": token, "file_id": wanted},
    )

    assert foreign.status_code == 404  # never 403: a foreign device looks like a missing one
    assert own.status_code == 200  # and the guard does not lock the owner out of their own


def test_an_admin_reaches_a_members_backup(env):
    """The other half of the same guard: `visible_device` widens for an admin instead of only
    narrowing for a member, so an admin can download from a device they do not own."""
    client, settings = env
    seed(settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "boss", PASSWORD, "admin")
        conn.commit()
    login(client, "boss")

    response = client.get(
        f"/devices/{YOURS.udid}/files/download",
        params={"file_id": DEFAULT_FILES[0].file_id, "snapshot": "latest"},
    )

    assert response.status_code == 200
    assert response.content == DEFAULT_FILES[0].content


def start_a_run(settings, udid):
    """A running row for this device, the way jobs.py's start() leaves one behind."""
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase) "
            "VALUES (?, 'manual', ?, 'running', 'transferring')",
            (udid, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        conn.commit()


def test_the_live_backup_is_not_browsable_while_a_backup_writes_it(env):
    """The engine rewrites the live directory in place, so while a run is on, its index and its
    payloads are both moving. Generations are untouched by this and stay open."""
    client, settings = env
    seed(settings)
    login(client, "member")
    start_a_run(settings, MINE.udid)

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text

    assert "A backup is running" in page
    assert "sms.db" not in page  # the file list of a directory being rewritten is never shown


def test_a_download_from_the_live_backup_is_refused_while_it_is_written(env):
    """409 rather than a file: half of the old payload and half of the new one would look like a
    perfectly ordinary download and only turn out broken when someone opens it."""
    client, settings = env
    seed(settings)
    login(client, "member")
    start_a_run(settings, MINE.udid)
    wanted = [f for f in DEFAULT_FILES if f.flags == 1]

    single = client.get(
        f"/devices/{MINE.udid}/files/download",
        params={"file_id": wanted[0].file_id, "snapshot": "latest"},
    )
    many = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": csrf_of(client, MINE.udid), "file_id": [f.file_id for f in wanted]},
    )

    assert single.status_code == 409
    assert many.status_code == 409


def test_a_run_on_one_device_does_not_close_another_ones_files(env):
    """The check is per device, not global - one phone backing up must not lock everyone out."""
    client, settings = env
    seed(settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "boss", PASSWORD, "admin")
        conn.commit()
    login(client, "boss")
    start_a_run(settings, YOURS.udid)

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest"}).text

    assert "HomeDomain" in page


def test_an_expired_password_leaves_memory_without_anyone_asking(env):
    """The store is swept on a timer, not only when something reads it.

    Sweeping on access alone kept the promise the interface makes - a reader coming back hours
    later is asked again, because a read sweeps before it looks anything up - but left the
    plaintext in the process heap in the meantime. Fifteen minutes has to hold for the memory too.
    """
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    token = csrf_of(client, MINE.udid)
    client.post(
        f"/devices/{MINE.udid}/files/unlock",
        params={"snapshot": "latest"},
        data={"csrf": token, "backup_password": BACKUP_PASSWORD},
    )
    store = client.app.state.backup_passwords
    assert len(store) == 1

    # Age the one entry past its deadline, then sweep as the thread does - no request involved.
    key, (password, _expires) = next(iter(store.items()))
    store[key] = (password, time.monotonic() - 1)
    dropped = client.app.state.sweep_backup_passwords()

    assert dropped == 1
    assert store == {}


def test_the_web_process_runs_a_password_sweeper(env):
    """The wiring, separately from the logic: without the thread the sweep above never happens on
    an idle server, and nothing else would notice."""
    client, _settings = env
    names = [t.name for t in threading.enumerate()]
    assert "backup-password-sweep" in names


# --- Selecting by path ---------------------------------------------------------------------


def select(client, udid, domain, path, on=True, **params):
    return client.post(
        f"/devices/{udid}/files/select",
        params={"snapshot": "latest", **params},
        data={
            "csrf": csrf_of(client, udid),
            "target_domain": domain,
            "target_path": path,
            "on": "1" if on else "0",
        },
    )


def test_a_whole_area_is_selected_as_one_entry(env):
    """The point of storing paths instead of file ids: one tick covers everything below it."""
    client, settings = env
    seed(settings)
    login(client, "member")

    page = select(client, MINE.udid, "CameraRollDomain", "").text
    assert "whole area" in page

    archive = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": csrf_of(client, MINE.udid)},
    )
    with tarfile.open(fileobj=io.BytesIO(archive.content)) as tar:
        names = set(tar.getnames())
    camera = {f"{f.domain}/{f.relative_path}" for f in DEFAULT_FILES if f.domain == "CameraRollDomain" and f.flags == 1}
    assert names == camera


def test_a_selection_survives_walking_into_another_folder(env):
    """It lives on the server, not in the form - otherwise every step of a column browser would
    throw away what was ticked in the column before."""
    client, settings = env
    seed(settings)
    login(client, "member")
    select(client, MINE.udid, "HomeDomain", "Library/SMS/sms.db")

    elsewhere = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
    ).text

    assert "Library/SMS/sms.db" in elsewhere  # still listed in the selection bar
    assert "Download 1 selected" in elsewhere


def test_a_file_inside_a_selected_folder_cannot_be_unticked_on_its_own(env):
    """Subtracting one file from a selected folder would mean storing the other 4,999 by hand, so
    the row says what covers it instead of pretending otherwise."""
    client, settings = env
    seed(settings)
    login(client, "member")
    select(client, MINE.udid, "CameraRollDomain", "Media/DCIM")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
    ).text

    assert "Already included by Media/DCIM" in page
    assert "disabled" in page


def test_clearing_the_selection_empties_it(env):
    client, settings = env
    seed(settings)
    login(client, "member")
    select(client, MINE.udid, "HomeDomain", "")

    cleared = client.post(
        f"/devices/{MINE.udid}/files/select",
        params={"snapshot": "latest"},
        data={"csrf": csrf_of(client, MINE.udid), "clear": "1"},
    ).text

    assert "Download 1 selected" not in cleared


def test_a_folder_of_five_thousand_files_stays_one_page_and_one_tick(env):
    """The case this view was rebuilt for.

    A column shows a bounded number of rows however large the folder is, says how many there are,
    and selecting all of them is a single entry that never needs a row on screen.
    """
    client, settings = env
    many = tuple(BackupFile("CameraRollDomain", f"Media/DCIM/100APPLE/IMG_{i:04d}.JPG", b"x") for i in range(5000))
    seed(settings, files=many)
    login(client, "member")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
    ).text
    rendered = page.count("IMG_")
    assert rendered < 5000  # a bounded column, not five thousand rows
    assert "of 5000" in page  # and it says how many are really there

    select(client, MINE.udid, "CameraRollDomain", "Media/DCIM/100APPLE")
    archive = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": csrf_of(client, MINE.udid)},
    )
    with tarfile.open(fileobj=io.BytesIO(archive.content)) as tar:
        assert len(tar.getnames()) == 5000


def test_a_column_offers_to_select_everything_in_it(env):
    """Ticking the folder's own row one column to the left does the same thing, but nobody finds
    that while standing in the folder they actually want."""
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
    ).text
    assert "Select all 1" in page

    chosen = client.post(
        f"/devices/{MINE.udid}/files/select",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE"},
        data={
            "csrf": csrf_of(client, MINE.udid),
            "target_domain": "CameraRollDomain",
            "target_path": "Media/DCIM/100APPLE",
            "on": "1",
        },
    ).text

    assert "Download 1 selected" in chosen
    assert "Deselect all" in chosen  # and the same control turns it off again


def test_the_lock_countdown_is_refreshed_by_a_selection(env):
    """The countdown has to sit in the block htmx swaps, or it tells the reader the opposite of
    what the server is doing.

    Every request pushes the deadline out again - the limit is fifteen idle minutes - so a reader
    ticking files is extending it with every click. The counter used to live outside the swapped
    block, keep counting the old deadline down, and reload the page at zero on a session that had
    just been extended.
    """
    client, settings = env
    seed(settings, encrypted=True)
    login(client, "member")
    unlock(client, MINE.udid, BACKUP_PASSWORD)

    after_select = client.post(
        f"/devices/{MINE.udid}/files/select",
        params={"snapshot": "latest"},
        data={
            "csrf": csrf_of(client, MINE.udid),
            "target_domain": "HomeDomain",
            "target_path": "",
            "on": "1",
        },
    ).text

    # The fragment htmx takes from this response is #browser, so the countdown must be inside it.
    browser_block = after_select.split('<div id="browser">', 1)[1]
    assert 'id="lock-countdown"' in browser_block
    assert 'data-seconds="900"' in browser_block  # and the deadline came back full


# --- Search as a column --------------------------------------------------------------------


def strip_of(page):
    """The Finder strip itself, so a test can tell a column inside it from a block below it."""
    assert '<div class="finder">' in page
    assert "\n</div>\n</div>" in page
    return page.split('<div class="finder">', 1)[1].split("\n</div>\n</div>", 1)[0]


def test_search_results_are_a_column_and_not_a_table_under_the_browser(env):
    """One way of picking a file on the page: hits are rows in the last column, like everything else.

    The folder columns stay where they were, so the trail the reader is standing on is still
    there to walk back.
    """
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "HomeDomain", "path": "Library/SMS", "q": "AddressBook"},
    ).text

    strip = strip_of(page)
    assert '<section class="fcol fcol-hits"' in strip  # a column of the strip, at its right end
    assert "AddressBook.sqlitedb" in strip
    assert "<table" not in page  # the old results table is gone, not merely moved
    assert "sms.db" in strip  # and the folder that was open is still a column of its own
    assert strip.index("sms.db") < strip.index("AddressBook.sqlitedb")


def test_a_hit_is_ticked_by_the_same_route_as_any_other_row(env):
    """No second mechanism: the checkbox in a hit posts the same (domain, path) pair."""
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "AddressBook"}).text
    assert 'value="Library/AddressBook/AddressBook.sqlitedb"' in page

    chosen = select(client, MINE.udid, "HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", q="AddressBook").text
    assert "Download 1 selected" in chosen

    archive = client.post(
        f"/devices/{MINE.udid}/files/download",
        params={"snapshot": "latest"},
        data={"csrf": csrf_of(client, MINE.udid)},
    )
    with tarfile.open(fileobj=io.BytesIO(archive.content)) as tar:
        assert tar.getnames() == ["HomeDomain/Library/AddressBook/AddressBook.sqlitedb"]


def test_the_hit_column_grows_instead_of_turning_a_page(env):
    """Show more, like every other column, rather than the Previous/Next it used to carry.

    A page that replaces the one before it takes away the matches the reader has already read
    past - and the row they ticked two screens up with it.
    """
    client, settings = env
    many = tuple(BackupFile("CameraRollDomain", f"Media/DCIM/100APPLE/IMG_{i:04d}.JPG", b"x") for i in range(250))
    seed(settings, files=many)
    login(client, "member")

    first = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "IMG_"}).text
    assert "Show more (100 of 250)" in first
    assert "Next" not in strip_of(first)

    more = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "IMG_", "hits": 2}).text
    assert "Show more (200 of 250)" in more
    assert "IMG_0000.JPG" in more  # grown, not replaced: the first match is still on screen
    assert "IMG_0199.JPG" in more


def test_ticking_a_row_does_not_collapse_a_grown_column(env):
    """Every checkbox posts back to where the reader is standing, paging included.

    Without that the form action drops `page` and `hits`, the server re-renders the first page of
    both columns, and the row that was just ticked is no longer on screen.
    """
    client, settings = env
    many = tuple(BackupFile("CameraRollDomain", f"Media/DCIM/100APPLE/IMG_{i:04d}.JPG", b"x") for i in range(250))
    seed(settings, files=many)
    login(client, "member")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={
            "snapshot": "latest",
            "domain": "CameraRollDomain",
            "path": "Media/DCIM/100APPLE",
            "q": "IMG_",
            "page": 2,
            "hits": 2,
        },
    ).text

    actions = re.findall(r'action="(/devices/[^"]*/files/select[^"]*)"', page)
    assert actions, "no select form on the page"
    assert all("page=2" in action and "hits=2" in action for action in actions)

    # And the round trip itself: posting to one of those actions comes back with the hits column
    # still grown to the 200 rows the reader was looking at.
    posted = client.post(
        actions[0].replace("&amp;", "&"),
        data={
            "csrf": csrf_of(client, MINE.udid),
            "target_domain": "CameraRollDomain",
            "target_path": "Media/DCIM/100APPLE/IMG_0000.JPG",
            "on": "1",
        },
    ).text
    assert "Show more (200 of 250)" in posted


def test_the_hit_column_offers_no_select_all(env):
    """A selection is a set of paths, and a result list is not a path.

    "Select all 250" there would be 250 stored entries wearing one button, so the column says
    what it found and leaves the bulk control to the folder columns, where a path does exist.
    """
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(
        f"/devices/{MINE.udid}/files",
        params={"snapshot": "latest", "domain": "CameraRollDomain", "path": "Media/DCIM/100APPLE", "q": "IMG_"},
    ).text

    hits = page.split('<section class="fcol fcol-hits"', 1)[1]
    assert "Select all" not in hits
    assert "1 found" in hits
    assert "Select all 1" in page  # the folder column next to it still has one


def test_walking_into_a_folder_keeps_the_search(env):
    """The hits are a column now, so the link that opens a folder must not empty it."""
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "sms"}).text
    into = re.findall(r'href="(/devices/[^"]*domain=HomeDomain[^"]*)"', page)
    assert into, "no link into an area on the page"
    assert all("q=sms" in link for link in into)


def test_a_search_that_finds_nothing_says_so_in_the_column(env):
    client, settings = env
    seed(settings)
    login(client, "member")

    page = client.get(f"/devices/{MINE.udid}/files", params={"snapshot": "latest", "q": "nothing-like-this"}).text
    assert "No files match" in strip_of(page)
