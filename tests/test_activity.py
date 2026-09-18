# SPDX-License-Identifier: GPL-3.0-or-later
"""The cross-process activity registry (src/bioseasy/activity.py): register, list, and a stale
(crashed) entry aging out of for_owner/for_admin without being deleted by the read itself."""

from contextlib import closing
from datetime import UTC, datetime, timedelta

from bioseasy import activity, auth, db


def make_conn(tmp_path):
    conn = db.connect(tmp_path / "bioseasy.db")
    db.migrate(conn)
    return conn


def make_device(conn, udid, owner_id):
    conn.execute(
        "INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)",
        (udid, f"device-{udid}", owner_id),
    )


def test_track_registers_and_removes_the_row(tmp_path):
    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    with activity.track(connect, "discovery"):
        with closing(connect()) as conn:
            rows = activity.for_admin(conn)
        assert len(rows) == 1
        assert rows[0]["kind"] == "discovery"

    with closing(connect()) as conn:
        assert activity.for_admin(conn) == []


def test_track_removes_the_row_even_when_the_block_raises(tmp_path):
    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    class Boom(Exception):
        pass

    try:
        with activity.track(connect, "backup"):
            raise Boom
    except Boom:
        pass

    with closing(connect()) as conn:
        assert activity.for_admin(conn) == []


def test_set_phase_updates_the_row(tmp_path):
    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    with activity.track(connect, "backup") as set_phase:
        set_phase("Transferring")
        with closing(connect()) as conn:
            rows = activity.for_admin(conn)
        assert rows[0]["phase"] == "Transferring"


def test_stale_entry_is_excluded_from_listings_but_not_deleted_by_them(tmp_path):
    conn = make_conn(tmp_path)
    old = (datetime.now(UTC) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) VALUES (?, ?, NULL, NULL, ?, ?)",
        ("stale-1", "discovery", old, old),
    )
    assert activity.for_admin(conn) == []
    # The row is still there: for_admin/for_owner filter by heartbeat, they never delete.
    assert conn.execute("SELECT 1 FROM activities WHERE id = 'stale-1'").fetchone() is not None
    assert activity.sweep_stale(conn) == 1
    assert conn.execute("SELECT 1 FROM activities WHERE id = 'stale-1'").fetchone() is None


def test_for_owner_sees_only_their_own_device_activity(tmp_path):
    conn = make_conn(tmp_path)
    owner_a = auth.create_user(conn, "alice", "correct horse battery", "member")
    owner_b = auth.create_user(conn, "bob", "correct horse battery", "member")
    make_device(conn, "AAA", owner_a.id)
    make_device(conn, "BBB", owner_b.id)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for activity_id, udid in (("a1", "AAA"), ("b1", "BBB")):
        conn.execute(
            "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) "
            "VALUES (?, 'backup', ?, NULL, ?, ?)",
            (activity_id, udid, now, now),
        )
    rows_a = activity.for_owner(conn, owner_a.id)
    assert [r["udid"] for r in rows_a] == ["AAA"]
    rows_b = activity.for_owner(conn, owner_b.id)
    assert [r["udid"] for r in rows_b] == ["BBB"]
    assert {r["udid"] for r in activity.for_admin(conn)} == {"AAA", "BBB"}


def test_for_owner_never_sees_a_deviceless_activity(tmp_path):
    """Discovery scans and storage-size recalculation are admin-only actions with no udid; a
    member must never see them, the same rule status.py applies to devices themselves."""
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "carol", "correct horse battery", "member")
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) "
        "VALUES ('d1', 'discovery', NULL, NULL, ?, ?)",
        (now, now),
    )
    assert activity.for_owner(conn, member.id) == []
    assert len(activity.for_admin(conn)) == 1


def test_running_for_shapes_rows_for_the_popover(tmp_path):
    conn = make_conn(tmp_path)
    started = datetime.now(UTC) - timedelta(seconds=90)
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) VALUES "
        "('x1', 'backup', NULL, 'Transferring', ?, ?)",
        (started.strftime("%Y-%m-%dT%H:%M:%SZ"), datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
    )
    shaped = activity.running_for(activity.for_admin(conn))
    assert shaped[0]["label"] == "Backup"
    assert shaped[0]["phase"] == "Transferring"
    assert shaped[0]["running_for_seconds"] >= 89


def test_track_records_succeeded_outcome_on_normal_exit(tmp_path):
    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    with activity.track(connect, "discovery"):
        pass

    with closing(connect()) as conn:
        # A row that just finished is never shown by the *running* query.
        assert activity.for_admin(conn) == []
        finished = activity.finished_for(activity.for_admin_finished(conn))
    assert len(finished) == 1
    assert finished[0]["outcome"] == "succeeded"
    assert finished[0]["detail"] is None


def test_track_records_failed_outcome_when_the_block_raises(tmp_path):
    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    class Boom(Exception):
        pass

    try:
        with activity.track(connect, "backup"):
            raise Boom("engine unreachable")
    except Boom:
        pass

    with closing(connect()) as conn:
        finished = activity.finished_for(activity.for_admin_finished(conn))
    assert finished[0]["outcome"] == "failed"
    assert finished[0]["detail"] == "engine unreachable"


def test_set_outcome_overrides_the_default_even_on_a_normal_exit(tmp_path):
    """jobs.py's backup run: the block returns normally (no exception) even when the backup
    failed or was not confirmed, so it must be able to say so explicitly."""

    def connect():
        return db.connect(tmp_path / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)

    with activity.track(connect, "backup") as set_phase:
        set_phase.set_outcome("not_confirmed", "no acknowledgement from the device")

    with closing(connect()) as conn:
        finished = activity.finished_for(activity.for_admin_finished(conn))
    assert finished[0]["outcome"] == "not_confirmed"
    assert finished[0]["detail"] == "no acknowledgement from the device"


def test_finished_entry_is_dropped_after_the_retention_window(tmp_path):
    conn = make_conn(tmp_path)
    old = datetime.now(UTC) - activity.FINISHED_RETENTION - timedelta(seconds=1)
    old_str = old.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at, outcome, detail, finished_at) "
        "VALUES (?, ?, NULL, NULL, ?, ?, 'succeeded', NULL, ?)",
        ("old-finished", "discovery", old_str, old_str, old_str),
    )
    assert activity.for_admin_finished(conn) == []
    # Still there until swept - the read itself never deletes.
    assert conn.execute("SELECT 1 FROM activities WHERE id = 'old-finished'").fetchone() is not None
    assert activity.sweep_stale(conn) == 1
    assert conn.execute("SELECT 1 FROM activities WHERE id = 'old-finished'").fetchone() is None


def test_finished_entry_within_the_window_is_kept_and_shaped(tmp_path):
    conn = make_conn(tmp_path)
    finished = datetime.now(UTC) - timedelta(minutes=2)
    finished_str = finished.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at, outcome, detail, finished_at) "
        "VALUES (?, ?, NULL, NULL, ?, ?, 'failed', 'Storage check failed', ?)",
        ("recent-finished", "backup", finished_str, finished_str, finished_str),
    )
    shaped = activity.finished_for(activity.for_admin_finished(conn))
    assert shaped[0]["outcome"] == "failed"
    assert shaped[0]["outcome_label"] == "failed"
    assert shaped[0]["detail"] == "Storage check failed"
    assert shaped[0]["finished_ago_seconds"] >= 119
    # sweep_stale must not remove it: it is well inside FINISHED_RETENTION.
    assert activity.sweep_stale(conn) == 0
    assert conn.execute("SELECT 1 FROM activities WHERE id = 'recent-finished'").fetchone() is not None


def test_for_owner_finished_scopes_like_for_owner(tmp_path):
    """The same visibility rule as running activity: a member never sees another owner's
    finished device activity (INNER JOIN against devices, as for_owner already does)."""
    conn = make_conn(tmp_path)
    owner_a = auth.create_user(conn, "alice", "correct horse battery", "member")
    owner_b = auth.create_user(conn, "bob", "correct horse battery", "member")
    make_device(conn, "AAA", owner_a.id)
    make_device(conn, "BBB", owner_b.id)
    finished_str = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for activity_id, udid in (("a1", "AAA"), ("b1", "BBB")):
        conn.execute(
            "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at, outcome, detail, finished_at) "
            "VALUES (?, 'backup', ?, NULL, ?, ?, 'succeeded', NULL, ?)",
            (activity_id, udid, finished_str, finished_str, finished_str),
        )
    rows_a = activity.for_owner_finished(conn, owner_a.id)
    assert [r["udid"] for r in rows_a] == ["AAA"]
    rows_b = activity.for_owner_finished(conn, owner_b.id)
    assert [r["udid"] for r in rows_b] == ["BBB"]
    assert {r["udid"] for r in activity.for_admin_finished(conn)} == {"AAA", "BBB"}


def test_latest_event_prefers_the_most_recent_of_running_and_finished(tmp_path):
    conn = make_conn(tmp_path)
    started = (datetime.now(UTC) - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    finished = (datetime.now(UTC) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) VALUES "
        "('r1', 'discovery', NULL, NULL, ?, ?)",
        (started, started),
    )
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at, outcome, detail, finished_at) "
        "VALUES ('f1', 'storage_size', NULL, NULL, ?, ?, 'succeeded', NULL, ?)",
        (started, started, finished),
    )
    event = activity.latest_event(activity.for_admin(conn), activity.for_admin_finished(conn))
    assert event is not None
    assert "Calculating storage size" in event["text"]
    assert "finished" in event["text"]


def test_latest_event_is_none_when_nothing_is_visible(tmp_path):
    conn = make_conn(tmp_path)
    assert activity.latest_event(activity.for_admin(conn), activity.for_admin_finished(conn)) is None
