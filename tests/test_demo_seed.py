# SPDX-License-Identifier: GPL-3.0-or-later
import time
from contextlib import closing
from datetime import UTC

import pytest

from bioseasy import auth, db, demo_files, demo_seed, extract, inventory, snapshots, storage
from bioseasy.engine.demo import DEMO_DEVICES


def test_seed_makes_a_usable_demo_once(tmp_path):
    path, root = tmp_path / "app.db", tmp_path / "backups"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)

    def connect():
        return db.connect(path)

    assert demo_seed.seed(connect, root) is True
    assert demo_seed.seed(connect, root) is False
    with closing(connect()) as conn:
        assert auth.authenticate(conn, demo_seed.DEMO_USER, demo_seed.DEMO_PASSWORD) is not None
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 10  # 7 phone + 3 iPad
        root_id = db.get_setting(conn, "backup_root_id")
    assert storage.check(root, root_id, 0).ok
    assert inventory.read_backup(root / DEMO_DEVICES[0].udid).complete
    generations = snapshots.list_snapshots(root, DEMO_DEVICES[0].udid)
    assert len(generations) == 7  # demo_seed.generation_days_ago
    assert [g.pinned for g in generations] == [False, False, False, False, False, False, True]  # oldest pinned

    # The default retention policy (defaults.py: keep_last=3, keep_daily=7, keep_weekly=4,
    # keep_monthly=6) keeps every one of these dated generations - none would be pruned on the
    # next backup - and shows daily, weekly and monthly reasons, not just "latest" throughout.
    from bioseasy import defaults as backup_defaults

    policy = snapshots.RetentionPolicy(
        keep_last=backup_defaults.DEFAULT_KEEP_LAST,
        keep_daily=backup_defaults.DEFAULT_KEEP_DAILY,
        keep_weekly=backup_defaults.DEFAULT_KEEP_WEEKLY,
        keep_monthly=backup_defaults.DEFAULT_KEEP_MONTHLY,
        keep_yearly=backup_defaults.DEFAULT_KEEP_YEARLY,
    )
    planned = snapshots.plan_retention(generations, policy, UTC)
    reasons = {reason for _, reasons in planned for reason in reasons}
    assert {"latest", "daily", "weekly", "monthly", "pinned"} <= reasons
    assert all(reasons for _, reasons in planned)  # nothing would be silently dropped


def test_every_seeded_generation_can_be_browsed_and_restored(tmp_path):
    """The demo data is only worth seeding if the file browser actually opens it.

    Both halves are checked, because the seed deliberately writes the older generations without
    encryption and the newer ones with it: an unencrypted one must open with no password at all,
    an encrypted one only with the demo password. The file count has to grow from generation to
    generation as well - when it does not, the snapshots were hard-linked to each other instead of
    written fresh, which is how this seed silently produced seven copies of one generation.
    """
    path, root = tmp_path / "app.db", tmp_path / "backups"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    assert demo_seed.seed(lambda: db.connect(path), root) is True

    udid = DEMO_DEVICES[0].udid
    generations = sorted(snapshots.list_snapshots(root, udid), key=lambda g: g.taken_at)
    encrypted = [extract.is_encrypted(g.path) for g in generations]
    assert encrypted == [False] * demo_seed.DEMO_ENCRYPTED_FROM + [True] * (
        len(generations) - demo_seed.DEMO_ENCRYPTED_FROM
    )

    counts = []
    for generation, is_encrypted in zip(generations, encrypted, strict=True):
        password = demo_seed.DEMO_BACKUP_PASSWORD if is_encrypted else None
        counts.append(extract.list_entries(generation.path, password=password).total)
    assert counts == sorted(counts) and counts[0] < counts[-1]

    newest = generations[-1]
    with pytest.raises(extract.WrongPassword):
        extract.list_entries(newest.path, password="not the demo password")

    # One file out of the newest, encrypted generation, byte for byte what the seed put in.
    wanted = {f.relative_path: f.content for f in demo_files.for_generation(len(generations) - 1, bulk=True)}
    rows = extract.list_entries(newest.path, query="IMG_0001", password=demo_seed.DEMO_BACKUP_PASSWORD).rows
    entry, chunks = extract.stream_file(newest.path, rows[0].file_id, demo_seed.DEMO_BACKUP_PASSWORD)
    assert b"".join(chunks) == wanted[entry.relative_path]


def test_ipad_gets_its_own_unencrypted_backup(tmp_path):
    """The iPad has no backup on disk before this change: it must now have a few
    unencrypted generations of its own, non-overlapping file set - not a copy of the phone's."""
    path, root = tmp_path / "app.db", tmp_path / "backups"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    assert demo_seed.seed(lambda: db.connect(path), root) is True

    phone_udid, pad_udid = (d.udid for d in DEMO_DEVICES)
    generations = sorted(snapshots.list_snapshots(root, pad_udid), key=lambda g: g.taken_at)
    assert len(generations) == 3  # a few generations, per demo_seed.ipad_days_ago
    assert all(not extract.is_encrypted(g.path) for g in generations)

    # Every generation really has its own content: byte-different Manifest.db files, not the same
    # snapshot hard-linked forward (the exact trap demo_backup.write_realistic_backup's docstring
    # warns about when several generations are written in the same second).
    manifest_paths = (root / ".bioseasy" / "snapshots" / pad_udid / g.path.name / "Manifest.db" for g in generations)
    manifest_inodes = {p.stat().st_ino for p in manifest_paths}
    assert len(manifest_inodes) == len(generations)

    counts = [extract.list_entries(g.path).total for g in generations]
    assert counts == sorted(counts) and counts[0] < counts[-1]

    # "Own file set" means own (domain, path) pairs - HomeDomain legitimately exists on both real
    # devices, but nothing inside it should be identical, and neither device's set is a subset of
    # the other's.
    pad_paths = {(f.domain, f.relative_path) for f in demo_files.for_ipad_generation(2)}
    phone_paths = {(f.domain, f.relative_path) for f in demo_files.for_generation(6, bulk=True)}
    assert pad_paths, "the iPad's newest generation has no files at all"
    assert pad_paths.isdisjoint(phone_paths), (
        f"iPad and phone share files {pad_paths & phone_paths} - the iPad file set is not its own"
    )


def test_bulk_folder_makes_pagination_visible(tmp_path):
    """The file browser pages a folder at extract.CHILD_PAGE_SIZE (200) rows and only
    shows "Show more"/"Select all N" once a folder exceeds that - with the old seven-file demo
    folders that state was never reachable in a demo deployment. One folder now must cross it."""
    path, root = tmp_path / "app.db", tmp_path / "backups"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    assert demo_seed.seed(lambda: db.connect(path), root) is True

    phone_udid = DEMO_DEVICES[0].udid
    # The live backup directory (not a snapshot) is left holding the newest generation's content,
    # which is the one seeded with the bulk folder - and it is what the file browser opens by
    # default (app.py's LIVE = "latest").
    live = root / phone_udid
    password = demo_seed.DEMO_BACKUP_PASSWORD
    page = extract.children(live, "MediaDomain", "Library/SMS/Attachments/inbox", password=password)
    assert page.total == demo_files.BULK_FILE_COUNT
    assert page.total > extract.CHILD_PAGE_SIZE, "folder must exceed the page size for 'Show more' to appear"
    assert len(page.rows) == extract.CHILD_PAGE_SIZE, "first page must actually be capped at the page size"
    assert page.has_more


def test_seed_duration_and_disk_stay_bounded(tmp_path):
    """The bulk folder's size is chosen deliberately, with seed time and disk use
    measured and named rather than assumed. Generous bounds: this only guards against someone
    later turning demo_files.BULK_FILE_COUNT into something that makes every demo deployment slow
    or the demo volume large, not a performance benchmark."""
    path, root = tmp_path / "app.db", tmp_path / "backups"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)

    started = time.perf_counter()
    assert demo_seed.seed(lambda: db.connect(path), root) is True
    elapsed = time.perf_counter() - started

    disk_bytes = sum(f.stat().st_size for f in root.rglob("*") if f.is_file())

    # Printed so a real CI run shows the actual, current numbers, not just a pass/fail.
    print(f"demo_seed.seed: {elapsed:.2f}s, {disk_bytes / 1_000_000:.2f} MB under {root}")
    assert elapsed < 30, f"demo seed took {elapsed:.2f}s, expected well under 30s"
    assert disk_bytes < 50_000_000, f"demo seed used {disk_bytes / 1_000_000:.2f} MB, expected well under 50 MB"
