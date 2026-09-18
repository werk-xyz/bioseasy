# SPDX-License-Identifier: GPL-3.0-or-later
import re
from contextlib import closing
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from fixtures import DEFAULT_FILES, BackupFile, write_realistic_backup

from bioseasy import auth, db, snapshots, verify
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine
from bioseasy.storage import StorageCheck
from bioseasy.ticker import Ticker

PHONE = DEMO_DEVICES[0]
PASSWORD = "correct horse battery"


# --- verify_snapshot: pure module tests ------------------------------------------------------


def test_complete_unencrypted_snapshot_is_verified(tmp_path):
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False)
    result = verify.verify_snapshot(backup.path)
    assert result.outcome == "verified"
    assert result.listed == len(DEFAULT_FILES)
    assert result.present == len(DEFAULT_FILES)
    assert result.missing == 0
    assert result.missing_fileids == ()


def test_one_deleted_payload_file_is_reported_missing_with_its_fileid(tmp_path):
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False)
    victim = backup.files[0]
    backup.hashed_file_path(victim).unlink()

    result = verify.verify_snapshot(backup.path)
    assert result.outcome == "missing"
    assert result.listed == len(DEFAULT_FILES)
    assert result.present == len(DEFAULT_FILES) - 1
    assert result.missing == 1
    assert result.missing_fileids == (victim.file_id,)


def test_encrypted_snapshot_is_not_checked_and_never_counted_as_ok(tmp_path):
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=True)
    result = verify.verify_snapshot(backup.path)
    assert result.outcome == "not_checked"
    assert "encrypted" in result.detail
    assert "needs the backup password" in result.detail
    # Still reports what can be checked without the password.
    assert "payload file(s) on disk" in result.detail
    assert result.outcome != "verified"


def test_directory_entry_has_no_payload_and_is_never_reported_missing(tmp_path):
    files = (
        *DEFAULT_FILES,
        BackupFile("HomeDomain", "Library/SMS", flags=2),  # a domain directory, no payload file
    )
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False, files=files)
    result = verify.verify_snapshot(backup.path)
    assert result.outcome == "verified"
    assert result.listed == len(DEFAULT_FILES)  # the directory row is not counted as listed


def test_missing_manifest_db_is_not_checked(tmp_path):
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False, write_manifest_db=False)
    result = verify.verify_snapshot(backup.path)
    assert result.outcome == "not_checked"
    assert "Manifest.db" in result.detail


def test_time_budget_stops_the_walk_and_is_reported_as_not_checked(tmp_path, monkeypatch):
    """No file is missing, but the deadline is hit after the first row - never reported as
    'verified' for a walk that did not finish, and the detail line says how far it got."""
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False)
    # verify_snapshot checks the deadline once per row, before processing it: the first call (for
    # row 0) is still before the deadline so that row is checked; the second (for row 1) is past
    # it, so the walk stops there having checked exactly one row.
    calls = iter([0.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr(verify.time, "monotonic", lambda: next(calls))

    result = verify.verify_snapshot(backup.path, deadline=50.0)

    assert result.outcome == "not_checked"
    assert result.missing == 0
    assert "stopped after the time budget" in result.detail
    assert "1 of about" in result.detail
    assert "none missing so far" in result.detail


def test_time_budget_stop_still_reports_a_file_already_found_missing(tmp_path, monkeypatch):
    """A file confirmed missing before the deadline is real evidence and must survive the cutoff,
    even though the overall walk never finished."""
    backup = write_realistic_backup(tmp_path / PHONE.udid, PHONE, encrypted=False)
    victim = backup.files[0]
    backup.hashed_file_path(victim).unlink()
    calls = iter([0.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr(verify.time, "monotonic", lambda: next(calls))

    result = verify.verify_snapshot(backup.path, deadline=50.0)

    assert result.outcome == "missing"
    assert result.missing == 1
    assert result.missing_fileids == (victim.file_id,)
    assert "stopped after the time budget" in result.detail
    assert "1 missing so far" in result.detail


def test_run_and_save_passes_a_deadline_so_a_huge_backup_cannot_run_forever(tmp_path, monkeypatch):
    """run_and_save itself must apply VERIFY_TIME_BUDGET, not just verify_snapshot when called
    with one explicitly - a deadline far in the past forces an immediate stop."""

    def connect():
        conn = db.connect(tmp_path / "app.db")
        return conn

    with closing(connect()) as conn:
        db.migrate(conn)
        conn.execute(
            "INSERT INTO devices (udid, name, created_at) VALUES (?, ?, ?)",
            (PHONE.udid, PHONE.name, "2026-09-01T00:00:00Z"),
        )
    backup = write_realistic_backup(tmp_path / "backups" / PHONE.udid, PHONE, encrypted=False)

    # time.monotonic() is called once by run_and_save to build the deadline (VERIFY_TIME_BUDGET
    # past whatever it returns first) and then once per row inside verify_snapshot; jumping far
    # ahead on every later call makes the deadline already past by the time the first row is
    # checked, regardless of how generous the real budget constant is.
    calls = iter([0.0])

    def fake_monotonic():
        try:
            return next(calls)
        except StopIteration:
            return 1_000_000.0

    monkeypatch.setattr(verify.time, "monotonic", fake_monotonic)

    result = verify.run_and_save(connect, backup.path, PHONE.udid, "20260901T000000Z")

    assert result.outcome != "verified"
    assert "stopped after the time budget" in result.detail


def test_save_and_load_result_round_trips(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        conn.execute(
            "INSERT INTO devices (udid, name, created_at) VALUES (?, ?, ?)",
            (PHONE.udid, PHONE.name, "2026-09-01T00:00:00Z"),
        )
        result = verify.VerifyResult("missing", listed=5, present=4, missing=1, missing_fileids=("abc123",))
        verify.save_result(conn, PHONE.udid, "20260901T000000Z", result, datetime(2026, 9, 15, tzinfo=UTC))
        loaded = verify.load_results(conn, PHONE.udid)
        assert loaded["20260901T000000Z"]["outcome"] == "missing"
        assert loaded["20260901T000000Z"]["missing"] == 1
        assert loaded["20260901T000000Z"]["checked_at"] == "2026-09-15T00:00:00Z"


# --- schedule: oldest-unverified first, at most weekly ---------------------------------------


class _FakeSnap:
    """Stands in for snapshots.Snapshot: pick_snapshot reads `.path.name` and, for a snapshot with
    no stored result, `.taken_at`."""

    def __init__(self, name, taken_at=None):
        from pathlib import Path

        self.path = Path(f"/does/not/matter/{name}")
        self.taken_at = taken_at or datetime.strptime(name, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


class _Row(dict):
    """Stands in for a sqlite3.Row: pick_snapshot only ever reads `row["checked_at"]`."""

    def __getitem__(self, key):
        return dict.__getitem__(self, key)


def test_pick_snapshot_prefers_never_checked_over_stale_results():
    checked = _FakeSnap("20260101T000000Z")
    never_checked = _FakeSnap("20260201T000000Z")
    results = {"20260101T000000Z": _Row(checked_at="2026-01-05T00:00:00Z")}
    assert verify.pick_snapshot([checked, never_checked], results) is never_checked


def test_pick_snapshot_prefers_oldest_checked_at_among_checked_ones():
    newer = _FakeSnap("20260201T000000Z")
    older = _FakeSnap("20260101T000000Z")
    results = {
        "20260201T000000Z": _Row(checked_at="2026-09-10T00:00:00Z"),
        "20260101T000000Z": _Row(checked_at="2026-09-01T00:00:00Z"),
    }
    assert verify.pick_snapshot([newer, older], results) is older


@pytest.fixture
def connect(tmp_path):
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    return lambda: db.connect(path)


def _add_device(connect, udid=PHONE.udid):
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO devices (udid, name, created_at) VALUES (?, ?, ?)",
            (udid, "Demo iPhone", "2026-09-01T00:00:00Z"),
        )


class FakeJobs:
    def running(self):
        return {}

    def start(self, udid, trigger):
        pass


def _synchronous_verify_enqueue(connect, root):
    """Stands in for tasks.py's verify_snapshot Huey task, run synchronously in-process instead
    of through Huey: ticker.py no longer calls
    verify.run_and_save itself, only ever `self.enqueue_verify(udid, name)` - these pacing/skip
    tests care about that decision logic, not about Huey's own machinery (see test_tasks.py for a
    test going through the real queue). Mirrors tasks.build's verify_snapshot task body exactly:
    resolve the snapshot path from the current on-disk list, then run_and_save.
    """

    def enqueue(udid: str, name: str) -> None:
        for snap in snapshots.list_snapshots(root, udid):
            if snap.path.name == name:
                verify.run_and_save(connect, snap.path, udid, name)
                return

    return enqueue


def test_tick_deep_verifies_oldest_unverified_generation(tmp_path, connect):
    _add_device(connect)
    root = tmp_path / "backups"
    write_realistic_backup(root / PHONE.udid, PHONE, encrypted=False)
    older = snapshots.take(root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)
    newer = snapshots.take(root, PHONE.udid, datetime(2026, 9, 10, tzinfo=UTC), hardlinks=False)
    del newer

    ticker = Ticker(
        connect,
        DemoEngine(step_seconds=0),
        FakeJobs(),
        lambda *a: None,
        UTC,
        backup_root=root,
        storage_check=lambda: StorageCheck(root, ()),
        enqueue_verify=_synchronous_verify_enqueue(connect, root),
    )
    ticker.tick(datetime(2026, 9, 15, tzinfo=UTC))

    with closing(connect()) as conn:
        results = verify.load_results(conn, PHONE.udid)
    # Only the oldest of the two generations was picked - never both in one tick.
    assert set(results) == {older.name}
    assert results[older.name]["outcome"] == "verified"


def test_tick_does_not_verify_again_inside_a_week(tmp_path, connect):
    _add_device(connect)
    root = tmp_path / "backups"
    write_realistic_backup(root / PHONE.udid, PHONE, encrypted=False)
    snap = snapshots.take(root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)

    with closing(connect()) as conn:
        verify.save_result(
            conn, PHONE.udid, snap.name, verify.VerifyResult("verified", 3, 3, 0), datetime(2026, 9, 10, tzinfo=UTC)
        )

    ticker = Ticker(
        connect,
        DemoEngine(step_seconds=0),
        FakeJobs(),
        lambda *a: None,
        UTC,
        backup_root=root,
        storage_check=lambda: StorageCheck(root, ()),
        enqueue_verify=_synchronous_verify_enqueue(connect, root),
    )
    # Only 4 days after the stored check: still inside the weekly interval.
    ticker.tick(datetime(2026, 9, 14, tzinfo=UTC))

    with closing(connect()) as conn:
        results = verify.load_results(conn, PHONE.udid)
    assert results[snap.name]["checked_at"] == "2026-09-10T00:00:00Z"  # unchanged: not re-run


def test_tick_skips_deep_verification_when_storage_check_fails(tmp_path, connect):
    _add_device(connect)
    root = tmp_path / "backups"
    write_realistic_backup(root / PHONE.udid, PHONE, encrypted=False)
    snapshots.take(root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)

    ticker = Ticker(
        connect,
        DemoEngine(step_seconds=0),
        FakeJobs(),
        lambda *a: None,
        UTC,
        backup_root=root,
        storage_check=lambda: StorageCheck(root, ("Less than 5 GiB free",)),
        enqueue_verify=_synchronous_verify_enqueue(connect, root),
    )
    ticker.tick(datetime(2026, 9, 15, tzinfo=UTC))

    with closing(connect()) as conn:
        results = verify.load_results(conn, PHONE.udid)
    assert results == {}


def test_second_tick_does_not_enqueue_again_while_a_verification_is_still_running(tmp_path, connect):
    """The guard (ticker.py's activity.is_running check): a verification enqueued but not yet
    finished must not cause the next tick to pick the same never-checked generation again. The
    stub `enqueue_verify` below simulates a Huey task that has started but not finished by
    registering itself in the activities table exactly as verify.run_and_save's own
    activity.track does, and deliberately never finishes it (no outcome written) - the same shape
    a real, still-running worker task would leave behind between two ticks.
    """
    _add_device(connect)
    root = tmp_path / "backups"
    write_realistic_backup(root / PHONE.udid, PHONE, encrypted=False)
    snapshots.take(root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)

    calls = []

    def enqueue(udid: str, name: str) -> None:
        calls.append((udid, name))
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO activities (id, kind, udid, started_at, heartbeat_at) VALUES (?, 'verify', ?, ?, ?)",
                (f"test-{len(calls)}", udid, "2026-09-15T02:59:00Z", "2026-09-15T02:59:00Z"),
            )

    ticker = Ticker(
        connect,
        DemoEngine(step_seconds=0),
        FakeJobs(),
        lambda *a: None,
        UTC,
        backup_root=root,
        storage_check=lambda: StorageCheck(root, ()),
        enqueue_verify=enqueue,
    )
    now = datetime(2026, 9, 15, 3, 0, tzinfo=UTC)
    ticker.tick(now)
    ticker.tick(now)

    assert len(calls) == 1
    with closing(connect()) as conn:
        # Never finished by this test on purpose: nothing was ever saved either.
        assert verify.load_results(conn, PHONE.udid) == {}


# --- web route: on-demand trigger, member cannot reach a foreign device ----------------------


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
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    login(client, "admin")
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303


def _seed_generation(settings):
    from bioseasy.engine.demo import write_backup

    write_backup(settings.backup_root / PHONE.udid, PHONE)
    snap = snapshots.take(settings.backup_root, PHONE.udid, datetime.now(UTC), hardlinks=True)
    return snap.name


def test_generations_table_shows_running_state_for_the_right_generation_only(env):
    """A running verification must be visible on the row of the generation it is actually
    checking (app.py's generations_context + activity.running_snapshot_names), not just as the
    header's activity indicator, and not on any other generation's row."""
    client, settings = env
    make_admin_with_device(client, settings)
    write_realistic_backup(settings.backup_root / PHONE.udid, PHONE, encrypted=False)
    older = snapshots.take(settings.backup_root, PHONE.udid, datetime(2026, 9, 1, tzinfo=UTC), hardlinks=False)
    newer = snapshots.take(settings.backup_root, PHONE.udid, datetime(2026, 9, 10, tzinfo=UTC), hardlinks=False)

    # generations_context reads the wall clock (no injectable `now`), so the heartbeat must be
    # fresh by real time, not by the fixture dates above - activity.STALE_AFTER is only 60s.
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with conn_for(settings) as conn:
        # Simulates a Huey "verify" task that has started but not finished, exactly as
        # verify.run_and_save's own activity.track registers it - the same trick
        # test_second_tick_does_not_enqueue_again_while_a_verification_is_still_running uses.
        conn.execute(
            "INSERT INTO activities (id, kind, udid, snapshot_name, started_at, heartbeat_at) "
            "VALUES ('test-running', 'verify', ?, ?, ?, ?)",
            (PHONE.udid, newer.name, now, now),
        )

    r = client.get(f"/devices/{PHONE.udid}")
    assert r.status_code == 200
    rows = re.findall(r"<tr>.*?</tr>", r.text, re.S)
    verifying_rows = [row for row in rows if "Verifying" in row]
    assert len(verifying_rows) == 1
    assert newer.name in verifying_rows[0]
    assert older.name not in verifying_rows[0]


def test_verify_button_enqueues_and_result_shows_on_the_device_page(env):
    client, settings = env
    make_admin_with_device(client, settings)
    name = _seed_generation(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/snapshots/{name}/verify", data={"csrf": token}, headers={"hx-request": "true"})
    assert r.status_code == 200
    assert '<section id="generations"' in r.text
    # huey_immediate=True: the task already ran synchronously by the time this response rendered.
    assert "Verified" in r.text or "Not checked" in r.text


def test_verify_unknown_snapshot_name_is_404(env):
    client, settings = env
    make_admin_with_device(client, settings)
    _seed_generation(settings)

    url = f"/devices/{PHONE.udid}"
    token = csrf(client, url)
    r = client.post(f"{url}/snapshots/20200101T000000Z/verify", data={"csrf": token})
    assert r.status_code == 404


def test_member_cannot_trigger_verification_on_a_foreign_device(env):
    client, settings = env
    make_admin_with_device(client, settings)
    name = _seed_generation(settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")

    token = csrf(client, "/")
    r = client.post(f"/devices/{PHONE.udid}/snapshots/{name}/verify", data={"csrf": token})
    assert r.status_code == 404
    with conn_for(settings) as conn:
        assert verify.load_results(conn, PHONE.udid) == {}  # the foreign-device attempt never ran


def test_verify_without_csrf_is_403(env):
    client, settings = env
    make_admin_with_device(client, settings)
    name = _seed_generation(settings)

    r = client.post(f"/devices/{PHONE.udid}/snapshots/{name}/verify", data={})
    assert r.status_code == 403
    with conn_for(settings) as conn:
        assert verify.load_results(conn, PHONE.udid) == {}
