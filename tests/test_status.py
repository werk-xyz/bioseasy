# SPDX-License-Identifier: GPL-3.0-or-later
import json
import plistlib
from datetime import UTC, datetime, timedelta

import pytest

from bioseasy import auth, db, status
from bioseasy.engine.demo import DEMO_DEVICES, write_backup

PHONE, PAD = DEMO_DEVICES
PASSWORD = "correct horse battery"
PUBLIC_KEYS = {
    "udid", "name", "model", "os_version", "state", "last_success_at", "next_due_at",
    "last_run_status", "last_run_at", "progress_percent", "backup_complete", "encrypted",
    "pair_days_unused",
}  # fmt: skip


def _add_device(conn, device, owner_id, udid=None):
    conn.execute(
        "INSERT INTO devices (udid, name, product_type, os_version, owner_id, interval_hours, overdue_days) "
        "VALUES (?, ?, ?, ?, ?, 24, 3)",
        (udid or device.udid, device.name, device.product_type, device.os_version, owner_id),
    )


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    alice = auth.create_user(conn, "alice", PASSWORD, "member")
    bob = auth.create_user(conn, "bob", PASSWORD, "member")
    _add_device(conn, PHONE, alice.id)
    _add_device(conn, PAD, bob.id)
    yield conn, root, alice, bob
    conn.close()


def _phone(conn, root, now):
    return next(s for s in status.for_admin(conn, root, now) if s.udid == PHONE.udid)


def test_owner_scope_is_applied_in_the_query(env):
    conn, root, alice, bob = env
    now = datetime.now(UTC)
    assert [s.udid for s in status.for_owner(conn, root, now, alice.id)] == [PHONE.udid]
    assert [s.udid for s in status.for_owner(conn, root, now, bob.id)] == [PAD.udid]
    assert status.for_owner(conn, root, now, 9999) == []
    assert {s.udid for s in status.for_admin(conn, root, now)} == {PHONE.udid, PAD.udid}


def test_statement_count_does_not_grow_with_the_number_of_devices(env):
    conn, root, alice, _ = env
    now = datetime.now(UTC)
    statements = []
    conn.set_trace_callback(statements.append)
    status.for_admin(conn, root, now)
    with_two = len(statements)
    for n in range(5):
        _add_device(conn, PHONE, alice.id, udid=f"00008110-00000000000000{n:02d}")
    statements.clear()
    assert len(status.for_admin(conn, root, now)) == 7
    conn.set_trace_callback(None)
    assert len(statements) == with_two


def test_never_running_and_waiting_states(env):
    conn, root, _, _ = env
    now = datetime.now(UTC)
    assert _phone(conn, root, now).state == "never"
    conn.execute(
        "INSERT INTO runs (udid, trigger, started_at, status, phase, percent) VALUES (?, 'manual', ?, 'running', ?, ?)",
        (PHONE.udid, now.strftime("%Y-%m-%dT%H:%M:%SZ"), "transferring", 40.0),
    )
    running = _phone(conn, root, now)
    assert (running.state, running.progress_percent) == ("running", 40.0)
    conn.execute("UPDATE runs SET phase = 'waiting_for_passcode', percent = NULL WHERE udid = ?", (PHONE.udid,))
    waiting = _phone(conn, root, now)
    assert (waiting.state, waiting.progress_percent) == ("waiting_for_passcode", None)


def test_incomplete_backup(env):
    conn, root, _, _ = env
    write_backup(root / PHONE.udid, PHONE, state="new")
    assert _phone(conn, root, datetime.now(UTC)).state == "incomplete"


def test_ok_due_and_overdue_follow_interval_and_overdue_days(env):
    conn, root, _, _ = env
    write_backup(root / PHONE.udid, PHONE)
    fresh = _phone(conn, root, datetime.now(UTC))
    assert fresh.state == "ok"
    taken = fresh.last_success_at
    assert fresh.next_due_at == taken + timedelta(hours=24)
    assert _phone(conn, root, taken + timedelta(hours=25)).state == "due"
    assert _phone(conn, root, taken + timedelta(days=4)).state == "overdue"


def test_complete_backup_without_a_date_is_due_not_overdue(env):
    conn, root, _, _ = env
    backup = root / PHONE.udid
    write_backup(backup, PHONE)
    for name, key in (("Status.plist", "Date"), ("Info.plist", "Last Backup Date")):
        data = plistlib.loads((backup / name).read_bytes())
        data.pop(key)
        (backup / name).write_bytes(plistlib.dumps(data))
    undated = _phone(conn, root, datetime.now(UTC) + timedelta(days=30))
    assert (undated.state, undated.last_success_at, undated.backup_complete) == ("due", None, True)


def test_public_shape_is_json_without_owner_or_location(env):
    conn, root, _, _ = env
    write_backup(root / PHONE.udid, PHONE)
    public = status.to_public(_phone(conn, root, datetime.now(UTC)))
    assert set(public) == PUBLIC_KEYS
    text = json.dumps(public)
    assert str(root) not in text
    assert public["last_success_at"].endswith("Z")
    # The pair record itself, and where it lives, never leave the process (module docstring).
    assert "pairing" not in text.lower() and "record" not in text.lower()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_pair_days_unused_is_none_before_pairing(env):
    conn, root, _, _ = env
    assert _phone(conn, root, datetime.now(UTC)).pair_days_unused is None


@pytest.mark.parametrize("days,expected", [(0, 0), (20, 20), (21, 21), (29, 29), (30, 30), (45, 45)])
def test_pair_days_unused_counts_from_pair_used_at(env, days, expected):
    conn, root, _, _ = env
    now = datetime.now(UTC)
    used = now - timedelta(days=days)
    conn.execute(
        "UPDATE devices SET paired_at = ?, pair_used_at = ? WHERE udid = ?", (_iso(used), _iso(used), PHONE.udid)
    )
    assert _phone(conn, root, now).pair_days_unused == expected


def test_pair_days_unused_falls_back_to_paired_at_when_never_used(env):
    conn, root, _, _ = env
    now = datetime.now(UTC)
    paired = now - timedelta(days=25)
    conn.execute("UPDATE devices SET paired_at = ?, pair_used_at = NULL WHERE udid = ?", (_iso(paired), PHONE.udid))
    assert _phone(conn, root, now).pair_days_unused == 25


@pytest.mark.parametrize(
    "days,warns,expired,phrase",
    [
        (20, False, False, None),
        (21, True, False, "After 30 days"),
        (29, True, False, "After 30 days"),
        (30, True, True, "needs pairing again"),
        (45, True, True, "needs pairing again"),
    ],
)
def test_pair_warning_thresholds(days, warns, expired, phrase):
    text = status.pair_warning(days)
    assert (text is not None) == warns
    if warns:
        assert f"{days} days" in text
        assert phrase in text
    assert (days is not None and days >= status.PAIR_EXPIRED_DAYS) == expired


def test_pair_warning_is_none_when_never_paired():
    assert status.pair_warning(None) is None
