# SPDX-License-Identifier: GPL-3.0-or-later
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bioseasy import snapshots

UDID = "00008110-TESTUDID000000"


def _write_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _live(root: Path) -> Path:
    return root / UDID


def _seed_live(root: Path) -> Path:
    live = _live(root)
    _write_file(live / "Info.plist", b"info-v1")
    _write_file(live / "Manifest.db", b"manifest-v1")
    return live


@pytest.fixture
def root(tmp_path):
    return tmp_path / "backups"


def test_snapshot_matches_live_contents(root):
    live = _seed_live(root)
    snap = snapshots.take(root, UDID, datetime.now(UTC), hardlinks=True)
    assert (snap / "Info.plist").read_bytes() == (live / "Info.plist").read_bytes()
    assert (snap / "Manifest.db").read_bytes() == (live / "Manifest.db").read_bytes()
    assert len(snap.name) == 16 and snap.name.endswith("Z")  # YYYYMMDDTHHMMSSZ


def test_second_snapshot_shares_inodes_with_first_but_never_with_live(root):
    live = _seed_live(root)
    first = snapshots.take(root, UDID, datetime.now(UTC), hardlinks=True)
    second = snapshots.take(root, UDID, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    first_stat = (first / "Info.plist").stat()
    second_stat = (second / "Info.plist").stat()
    live_stat = (live / "Info.plist").stat()

    assert (first_stat.st_dev, first_stat.st_ino) == (second_stat.st_dev, second_stat.st_ino)
    assert (first_stat.st_dev, first_stat.st_ino) != (live_stat.st_dev, live_stat.st_ino)


def test_changing_live_file_does_not_change_older_snapshot(root):
    live = _seed_live(root)
    first = snapshots.take(root, UDID, datetime.now(UTC), hardlinks=True)
    # Mirrors the engine: open(path, "wb") truncates and rewrites, it does not edit in place.
    with (live / "Info.plist").open("wb") as fh:
        fh.write(b"info-v2")
    snapshots.take(root, UDID, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    assert (first / "Info.plist").read_bytes() == b"info-v1"
    assert (live / "Info.plist").read_bytes() == b"info-v2"


def test_retention_keeps_pinned_and_latest(root, caplog):
    caplog.set_level("INFO", logger="bioseasy.snapshots")
    _seed_live(root)
    names = [
        snapshots.take(root, UDID, datetime.now(UTC) + timedelta(seconds=i), hardlinks=True).name for i in range(5)
    ]
    # names[0] is oldest, names[4] is newest. Pin the second-oldest so keep_last=2 would otherwise drop it.
    snapshots.pin(root, UDID, names[1], True)

    policy = snapshots.RetentionPolicy(keep_last=2)
    removed = snapshots.apply_retention(root, UDID, policy, UTC, datetime.now(UTC))

    remaining = {s.path.name for s in snapshots.list_snapshots(root, UDID)}
    assert remaining == {names[1], names[3], names[4]}
    assert {p.name for p in removed} == {names[0], names[2]}
    # A removed generation must be visible in the container log, not only as a missing directory.
    for name in (names[0], names[2]):
        assert f"retention removed snapshot {name} of {UDID[:8]}" in caplog.text
    assert "keep_last=2" in caplog.text


def test_retention_always_keeps_newest_even_with_every_rule_zero(root):
    _seed_live(root)
    older = snapshots.take(root, UDID, datetime.now(UTC) - timedelta(days=1), hardlinks=True)
    newest = snapshots.take(root, UDID, datetime.now(UTC), hardlinks=True)

    # An all-zero policy is a configuration error at the call sites (config.py, app.py both
    # reject it via retention_error) but apply_retention/plan_retention are pure and still must
    # never silently delete every generation - the newest one is always kept as a last resort.
    removed = snapshots.apply_retention(root, UDID, snapshots.RetentionPolicy(), UTC, datetime.now(UTC))

    assert older in removed
    assert newest not in removed
    assert [s.path for s in snapshots.list_snapshots(root, UDID)] == [newest]


def _snap(name: str, taken_at: datetime, pinned: bool = False) -> snapshots.Snapshot:
    """Builds a snapshots.Snapshot without touching the filesystem, for plan_retention's pure
    table-case tests below - apply_retention's own filesystem behaviour is covered above."""
    return snapshots.Snapshot(Path(name), taken_at, pinned)


def _reasons_by_name(planned: list[tuple[snapshots.Snapshot, list[str]]]) -> dict[str, list[str]]:
    return {snap.path.name: reasons for snap, reasons in planned}


def test_plan_retention_daily_counts_only_days_that_have_a_snapshot():
    # Ten calendar days, but snapshots only on 6 of them (a gap on day -3 and -7): keep_daily=3
    # must count the 3 most recent *populated* days, not the 3 most recent calendar days.
    base = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    populated_days_ago = [0, 1, 2, 4, 5, 9]  # 3 and 7 skipped on purpose
    snaps = [_snap(f"d{d}", base - timedelta(days=d)) for d in populated_days_ago]
    snaps.sort(key=lambda s: s.taken_at, reverse=True)

    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_daily=3), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["d0"] == ["daily"]
    assert reasons["d1"] == ["daily"]
    assert reasons["d2"] == ["daily"]
    assert reasons["d4"] == []  # 4th most recent populated day, beyond keep_daily=3
    assert reasons["d5"] == []
    assert reasons["d9"] == []


def test_plan_retention_keeps_only_the_most_recent_snapshot_per_day():
    base = datetime(2026, 9, 15, 8, 0, tzinfo=UTC)
    morning = _snap("morning", base)
    evening = _snap("evening", base + timedelta(hours=10))  # same calendar day, later
    snaps = [evening, morning]  # newest first, as list_snapshots returns

    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_daily=5), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["evening"] == ["daily"]
    assert reasons["morning"] == []  # same day as "evening", which is newer


def test_plan_retention_week_boundary():
    # 2026-09-14 is a Monday: two hours later than "sun" but a fresh ISO week (Mon 00:00-Sun
    # 23:59), so the two must land in different weekly buckets despite being close in time.
    sunday_end_of_week = datetime(2026, 9, 13, 23, 0, tzinfo=UTC)
    monday_new_week = datetime(2026, 9, 14, 1, 0, tzinfo=UTC)
    snaps = sorted(
        [_snap("sun", sunday_end_of_week), _snap("mon", monday_new_week)], key=lambda s: s.taken_at, reverse=True
    )

    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_weekly=4), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["mon"] == ["weekly"]
    assert reasons["sun"] == ["weekly"]  # a different ISO week from "mon", both counted


def test_plan_retention_month_boundary():
    # end_of_august and start_of_september are two hours apart but different calendar months.
    end_of_august = datetime(2026, 8, 31, 23, 0, tzinfo=UTC)
    start_of_september = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
    snaps = sorted(
        [_snap("aug", end_of_august), _snap("sep", start_of_september)], key=lambda s: s.taken_at, reverse=True
    )

    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_monthly=4), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["sep"] == ["monthly"]
    assert reasons["aug"] == ["monthly"]  # a different month from "sep", both counted


def test_plan_retention_timezone_bucketing_moves_the_day_boundary():
    # 23:30 UTC on 2026-09-14 is already 2026-09-15 in a UTC+2 timezone; keep_daily=1 must bucket
    # by the given tz, not by UTC, or this would wrongly look like two different days versus one.
    from zoneinfo import ZoneInfo

    late_utc = datetime(2026, 9, 14, 23, 30, tzinfo=UTC)
    next_morning_utc = datetime(2026, 9, 15, 1, 0, tzinfo=UTC)  # 03:00 in UTC+2, same local day
    snaps = sorted(
        [_snap("late", late_utc), _snap("morning", next_morning_utc)], key=lambda s: s.taken_at, reverse=True
    )

    tz = ZoneInfo("Europe/Berlin")  # UTC+2 in September (CEST)
    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_daily=5), tz)

    reasons = _reasons_by_name(planned)
    assert reasons["morning"] == ["daily"]
    assert reasons["late"] == []  # same local day as "morning", which is newer


def test_plan_retention_reasons_are_unioned_when_several_rules_keep_the_same_snapshot():
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    newest = _snap("newest", now)
    snaps = [newest]

    policy = snapshots.RetentionPolicy(keep_last=1, keep_daily=1, keep_weekly=1, keep_monthly=1, keep_yearly=1)
    planned = snapshots.plan_retention(snaps, policy, UTC)

    reasons = _reasons_by_name(planned)
    assert set(reasons["newest"]) == {"latest", "daily", "weekly", "monthly", "yearly"}


def test_plan_retention_pinned_and_newest_are_always_kept_outside_every_rule():
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    newest = _snap("newest", now)
    pinned_but_old = _snap("pinned_old", now - timedelta(days=400), pinned=True)
    dropped = _snap("dropped", now - timedelta(days=200))
    snaps = sorted([newest, pinned_but_old, dropped], key=lambda s: s.taken_at, reverse=True)

    # keep_last=1 already covers "newest"; every period rule is 0 so nothing else is kept by a
    # rule, yet the pinned one must survive regardless.
    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(keep_last=1), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["newest"] == ["latest"]
    assert reasons["pinned_old"] == ["pinned"]
    assert reasons["dropped"] == []


def test_plan_retention_zero_rules_keeps_only_the_newest():
    now = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
    snaps = sorted(
        [_snap("a", now), _snap("b", now - timedelta(days=1)), _snap("c", now - timedelta(days=2))],
        key=lambda s: s.taken_at,
        reverse=True,
    )

    planned = snapshots.plan_retention(snaps, snapshots.RetentionPolicy(), UTC)

    reasons = _reasons_by_name(planned)
    assert reasons["a"] == ["newest"]
    assert reasons["b"] == []
    assert reasons["c"] == []


def test_plan_retention_empty_snapshot_list():
    assert snapshots.plan_retention([], snapshots.RetentionPolicy(keep_last=3), UTC) == []


def test_resolve_policy_layers_device_overrides_over_server_defaults():
    defaults = snapshots.RetentionPolicy(keep_last=3, keep_daily=7, keep_weekly=4, keep_monthly=6, keep_yearly=0)
    overrides = {"keep_last": 10, "keep_daily": None, "keep_weekly": None, "keep_monthly": None, "keep_yearly": 2}

    resolved = snapshots.resolve_policy(overrides, defaults)

    assert resolved == snapshots.RetentionPolicy(
        keep_last=10, keep_daily=7, keep_weekly=4, keep_monthly=6, keep_yearly=2
    )


def test_retention_error_requires_at_least_one_rule_above_zero():
    assert snapshots.retention_error(snapshots.RetentionPolicy()) is not None
    assert snapshots.retention_error(snapshots.RetentionPolicy(keep_yearly=1)) is None


def test_disk_usage_counts_linked_files_once(root):
    _seed_live(root)
    first = snapshots.take(root, UDID, datetime.now(UTC), hardlinks=True)
    second = snapshots.take(root, UDID, datetime.now(UTC) + timedelta(seconds=1), hardlinks=True)

    single = snapshots.disk_usage([first])
    total = snapshots.disk_usage([first, second])
    assert total == single  # every file in `second` is hard-linked to `first`


def test_partial_dir_removed_on_rsync_failure(root):
    # Live directory does not exist, so rsync's source is missing and the run fails.
    with pytest.raises(snapshots.SnapshotError):
        snapshots.take(root, UDID, datetime.now(UTC), hardlinks=False)

    snapshots_dir = root / ".bioseasy" / "snapshots" / UDID
    assert list(snapshots_dir.glob("*.partial")) == []
