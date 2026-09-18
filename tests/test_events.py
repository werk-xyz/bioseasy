# SPDX-License-Identifier: GPL-3.0-or-later
"""The device event feed (src/bioseasy/events.py) and, above all, its scope.

The condition for having a user-visible log at all was that a member must
not be able to see information about another user's devices or connections. That condition is
what most of this file tests, from several directions rather than once: the plain feed, the
device filter, a device with no owner, and the free-text log table the feed must never touch.
"""

from datetime import UTC, datetime, timedelta

from bioseasy import auth, db, events


def make_conn(tmp_path):
    conn = db.connect(tmp_path / "bioseasy.db")
    db.migrate(conn)
    return conn


def make_device(conn, udid, owner_id):
    conn.execute(
        "INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)",
        (udid, f"device-{udid}", owner_id),
    )


def iso(offset_minutes: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_run(conn, udid, status="succeeded", *, message="", trigger="schedule", minutes_ago=1):
    conn.execute(
        "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) VALUES (?, ?, ?, ?, ?, ?)",
        (udid, trigger, iso(minutes_ago + 1), iso(minutes_ago), status, message),
    )


def add_verification(conn, udid, snapshot_name="2026-09-16", outcome="verified", *, minutes_ago=1):
    conn.execute(
        "INSERT INTO snapshot_verifications (udid, snapshot_name, outcome, checked_at) VALUES (?, ?, ?, ?)",
        (udid, snapshot_name, outcome, iso(minutes_ago)),
    )


def two_owners(conn):
    alice = auth.create_user(conn, "alice", "correct horse battery", "member")
    bob = auth.create_user(conn, "bob", "correct horse battery", "member")
    make_device(conn, "AAA", alice.id)
    make_device(conn, "BBB", bob.id)
    return alice, bob


def test_member_sees_only_their_own_devices(tmp_path):
    conn = make_conn(tmp_path)
    alice, bob = two_owners(conn)
    add_run(conn, "AAA")
    add_run(conn, "BBB")
    add_verification(conn, "AAA")
    add_verification(conn, "BBB")

    assert {r["udid"] for r in events.list_events(conn, owner_id=alice.id).rows} == {"AAA"}
    assert {r["udid"] for r in events.list_events(conn, owner_id=bob.id).rows} == {"BBB"}


def test_admin_scope_sees_every_device(tmp_path):
    conn = make_conn(tmp_path)
    two_owners(conn)
    add_run(conn, "AAA")
    add_run(conn, "BBB")

    assert {r["udid"] for r in events.list_events(conn, owner_id=None).rows} == {"AAA", "BBB"}


def test_the_device_filter_cannot_leave_the_members_scope(tmp_path):
    """The filter narrows within the scope, it never replaces it.

    This is the failure that would make the whole feature unsafe: a member typing another
    owner's device into `?device=` must get nothing back, not that device's events. The owner
    clause and the filter sit in the same query, so the filter cannot widen it.
    """
    conn = make_conn(tmp_path)
    alice, _bob = two_owners(conn)
    add_run(conn, "BBB", status="failed", message="something went wrong on bob's device")

    page = events.list_events(conn, owner_id=alice.id, udid="BBB")
    assert page.rows == []
    assert page.total == 0


def test_a_device_with_no_owner_never_reaches_a_member(tmp_path):
    """An unowned device is admin business, the same rule activity.for_owner applies with its
    INNER join: it must not fall into some member's feed just because nobody claimed it."""
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "carol", "correct horse battery", "member")
    make_device(conn, "CCC", None)
    add_run(conn, "CCC", status="failed", message="unowned device failed")

    assert events.list_events(conn, owner_id=member.id).rows == []
    assert len(events.list_events(conn, owner_id=None).rows) == 1


def test_the_feed_never_reads_the_free_text_log(tmp_path):
    """`log_entries` is not a source here, by construction.

    Its `udid` is filled by a best-effort regex over the message text (logview._extract_udid,
    whose own docstring says it is "never for anything security-relevant"), so it cannot carry a
    trustworthy boundary. A row in it - even one carrying this member's own shortened UDID -
    must not appear in the feed at all.
    """
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "dave", "correct horse battery", "member")
    make_device(conn, "DDD", member.id)
    conn.execute(
        "INSERT INTO log_entries (ts, process, logger, level, message, udid) "
        "VALUES (?, 'worker', 'bioseasy', 'ERROR', 'something about DDD', 'DDD')",
        (iso(),),
    )

    page = events.list_events(conn, owner_id=member.id)
    assert page.rows == []
    assert "something about DDD" not in str([dict(r) for r in page.rows])


def test_a_running_backup_is_not_an_event_yet(tmp_path):
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "erin", "correct horse battery", "member")
    make_device(conn, "EEE", member.id)
    conn.execute(
        "INSERT INTO runs (udid, trigger, started_at, status) VALUES ('EEE', 'manual', ?, 'running')",
        (iso(),),
    )

    assert events.list_events(conn, owner_id=member.id).rows == []

    add_run(conn, "EEE", status="succeeded")
    assert len(events.list_events(conn, owner_id=member.id).rows) == 1


def test_both_sources_appear_newest_first(tmp_path):
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "frank", "correct horse battery", "member")
    make_device(conn, "FFF", member.id)
    add_run(conn, "FFF", status="succeeded", minutes_ago=30)
    add_verification(conn, "FFF", "2026-09-10", "verified", minutes_ago=20)
    add_run(conn, "FFF", status="failed", message="disk full", minutes_ago=10)

    rows = events.list_events(conn, owner_id=member.id).rows
    assert [r["kind"] for r in rows] == ["backup", "verification", "backup"]
    assert [r["outcome"] for r in rows] == ["failed", "verified", "succeeded"]


def test_kind_filter_narrows_to_one_source(tmp_path):
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "gina", "correct horse battery", "member")
    make_device(conn, "GGG", member.id)
    add_run(conn, "GGG")
    add_verification(conn, "GGG")

    assert [r["kind"] for r in events.list_events(conn, owner_id=member.id, kind="backup").rows] == ["backup"]
    assert [r["kind"] for r in events.list_events(conn, owner_id=member.id, kind="verification").rows] == [
        "verification"
    ]
    # An unknown kind is ignored rather than returning nothing: the same shape logview's own
    # allowlisting of level/process uses, so a hand-edited query string cannot blank the page.
    assert len(events.list_events(conn, owner_id=member.id, kind="nonsense").rows) == 2


def test_paging_reports_the_total_of_the_scope_only(tmp_path):
    """`total` drives the pager, so it must be the scoped count - an unscoped total would tell a
    member how many events exist on devices they cannot see."""
    conn = make_conn(tmp_path)
    alice, _bob = two_owners(conn)
    for i in range(7):
        add_run(conn, "AAA", minutes_ago=i + 1)
    for i in range(4):
        add_run(conn, "BBB", minutes_ago=i + 1)

    page = events.list_events(conn, owner_id=alice.id, page=1, page_size=5)
    assert page.total == 7
    assert len(page.rows) == 5
    assert page.has_more

    second = events.list_events(conn, owner_id=alice.id, page=2, page_size=5)
    assert len(second.rows) == 2
    assert not second.has_more


def test_devices_in_scope_never_offers_a_foreign_device(tmp_path):
    """The filter dropdown is built from the same scope as the feed. If it were not, a member
    would learn that another owner's device exists simply by opening the select."""
    conn = make_conn(tmp_path)
    alice, _bob = two_owners(conn)

    assert [r["udid"] for r in events.devices_in_scope(conn, alice.id)] == ["AAA"]
    assert [r["udid"] for r in events.devices_in_scope(conn, None)] == ["AAA", "BBB"]


def test_shape_keeps_an_unknown_outcome_visible(tmp_path):
    """A status this module has no label for is shown as itself with a neutral pill, never
    relabelled into a known one - "unknown" stays visible."""
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "hana", "correct horse battery", "member")
    make_device(conn, "HHH", member.id)
    add_verification(conn, "HHH", "2026-09-16", "not_checked")

    shaped = events.shape(events.list_events(conn, owner_id=member.id).rows)
    assert shaped[0]["outcome_word"] == "Not checked"
    assert shaped[0]["outcome_class"] == "warn"
    assert shaped[0]["label"] == "Generation check"
    assert shaped[0]["snapshot_name"] == "2026-09-16"


def test_shape_carries_the_device_name_and_the_trigger(tmp_path):
    conn = make_conn(tmp_path)
    member = auth.create_user(conn, "ivan", "correct horse battery", "member")
    make_device(conn, "III", member.id)
    add_run(conn, "III", status="succeeded", trigger="manual")

    shaped = events.shape(events.list_events(conn, owner_id=member.id).rows)
    assert shaped[0]["device_name"] == "device-III"
    assert shaped[0]["trigger"] == "started by hand"
    assert shaped[0]["outcome_class"] == "ok"
