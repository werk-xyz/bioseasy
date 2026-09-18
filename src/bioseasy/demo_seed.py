# SPDX-License-Identifier: GPL-3.0-or-later
"""Demo content for throwaway environments, so a fresh deploy is usable at once.

DEMO CREDENTIALS, NOT A SECRET: username `demo`, password `demo-password-not-secret`. They exist
only when BIOSEASY_ENGINE=demo and BIOSEASY_DEMO_SEED=true, and nothing real may ever use them.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import auth, db, demo_files, snapshots, storage
from .demo_backup import write_realistic_backup
from .engine.demo import DEMO_DEVICES

log = logging.getLogger(__name__)
DEMO_USER = "demo"
DEMO_PASSWORD = "demo-password-not-secret"  # noqa: S105 - marked demo credential, see module docstring
# The backup encryption password the demo generations are written with. Short on purpose: it is
# typed into the unlock form by anyone trying the file browser, and the files page prints it
# next to the form while the demo engine is running.
DEMO_BACKUP_PASSWORD = "demo"  # noqa: S105 - marked demo credential, see module docstring
# The generation from which the demo device has backup encryption switched on, so the timeline
# carries both kinds: older generations open without a password, newer ones ask for one.
DEMO_ENCRYPTED_FROM = 3


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed(
    connect: Callable[[], sqlite3.Connection],
    backup_root: Path,
    now: datetime | None = None,
    data_dir: Path | None = None,
) -> bool:
    """Idempotent: does nothing once any user exists. Returns whether it seeded."""
    now = now or datetime.now(UTC)
    with closing(connect()) as conn:
        if auth.has_users(conn):
            return False
        if data_dir is not None:
            # Both demo devices are added below, so both must count as paired for the demo engine
            # too; otherwise the iPad's setup wizard shows "Paired: Done" and then refuses the
            # Wi-Fi step with "Pair the device first".
            # The iPad now also gets finished, unencrypted backup generations below (so a demo
            # deployment shows the encrypted/unencrypted contrast on two devices, not only across
            # generations of one), which only makes sense if those backups could actually have
            # happened - so the iPad counts as Wi-Fi-enabled too, same as the phone. Encryption
            # stays off for the iPad on purpose: its setup wizard still has that one step open,
            # matching docs/setup.md's "Adding a device again" story (device already did things,
            # the fresh devices row does not know it yet) for both devices instead of only the
            # phone.
            phone_udid, pad_udid = (d.udid for d in DEMO_DEVICES)
            state = {
                "paired": [d.udid for d in DEMO_DEVICES],
                "wifi": [phone_udid, pad_udid],
                "encrypted": [phone_udid],
            }
            (data_dir / "demo-engine-state.json").write_text(json.dumps(state))
        # An address, because single sign-on matches on one and a demo deployment should not show
        # its own demo account as the one thing that cannot be signed in with it. example.org
        # is reserved for documentation (RFC 2606), so it can never reach anybody.
        admin = auth.create_user(conn, DEMO_USER, DEMO_PASSWORD, "admin", email="demo@example.org")
        backup_root.mkdir(parents=True, exist_ok=True)
        db.set_setting(conn, "backup_root_id", storage.initialise(backup_root))
        phone, pad = DEMO_DEVICES
        for device in (phone, pad):
            # wifi_enabled_at and encryption_enabled_at are left NULL here for both devices, on
            # purpose: DemoEngine's own starting state already has the phone's Wi-Fi and
            # encryption "on" and the iPad's Wi-Fi "on" (see the state file above), and both
            # already have finished backups below - exactly the re-added-after-a-recreated-
            # database situation docs/setup.md ("Adding a device again") describes. Opening a
            # device's setup page runs real detection (runtime.run_setup_detect) against the demo
            # engine and fills the columns in from there, so a demo deployment demonstrates the
            # detected-state wizard end to end instead of only ever showing pre-seeded timestamps.
            # For the iPad, detection confirms Wi-Fi but not encryption (still off in the demo
            # engine), so its wizard correctly stops on that one open step - not because nothing
            # was ever done, but because that step genuinely has not happened yet.
            conn.execute(
                "INSERT INTO devices (udid, name, product_type, os_version, owner_id, paired_at, window_start, "
                "window_end) VALUES (?, ?, ?, ?, ?, ?, '01:00', '06:00')",
                (device.udid, device.name, device.product_type, device.os_version, admin.id, _iso(now)),
            )
        # A week of history for the phone, so the generation strip shows every state it can show.
        history = ["succeeded", "succeeded", "not_confirmed", "succeeded", "failed", "succeeded", "succeeded"]
        for days_ago, status in enumerate(history):
            started = now - timedelta(days=days_ago, hours=1)
            message = {"failed": "Connection to the device was lost", "not_confirmed": "Nobody confirmed"}.get(status)
            conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) VALUES (?, ?, ?, ?, ?, ?)",
                (phone.udid, "schedule", _iso(started), _iso(started + timedelta(minutes=12)), status, message),
            )
        # Spread across recent days, distinct ISO weeks and distinct months, so the "Kept by"
        # column shows every rule of the default retention policy (keep_last=3, keep_daily=7,
        # keep_weekly=4, keep_monthly=6) at least once, not just "latest" on everything. Taken
        # oldest first, as jobs.py always would, so --link-dest always points at the snapshot
        # right before it.
        generation_days_ago = [100, 45, 16, 9, 2, 1, 0]
        for index, days_ago in enumerate(generation_days_ago):
            taken_at = now - timedelta(days=days_ago)
            # Rewritten before every snapshot, the way a real run leaves a changed live backup
            # behind: each generation then holds one screenshot more than the one before it, and
            # the file browser shows a real difference when the timeline switches between them.
            # The large attachments folder (demo_files.BULK_ATTACHMENTS) only goes into the
            # newest generation - it is also the one left in the live backup directory afterwards,
            # so it is what the file browser opens to by default - rather than into all seven,
            # which would multiply both the seed's write time and its disk use sevenfold for no
            # extra demonstration value.
            write_realistic_backup(
                backup_root / phone.udid,
                phone,
                encrypted=index >= DEMO_ENCRYPTED_FROM,
                password=DEMO_BACKUP_PASSWORD,
                files=demo_files.for_generation(index, bulk=index == len(generation_days_ago) - 1),
                serial="DEMO000000",
                now=taken_at,
            )
            snapshots.take(backup_root, phone.udid, taken_at, hardlinks=True)
        # The oldest generation pinned, so the Generations section also shows that state.
        oldest = snapshots.list_snapshots(backup_root, phone.udid)[-1]
        snapshots.pin(backup_root, phone.udid, oldest.path.name, True)

        # The iPad had no backup on disk at all before this: its Generations section was always
        # empty, so the encrypted/unencrypted contrast the phone alone shows across its own
        # generations was never visible across two *devices*. A few unencrypted generations of the
        # iPad's own file set (demo_files.for_ipad_generation - different domains and files than
        # the phone's, an iPad does not carry SMS or a phone dialler) makes that comparison
        # visible without touching the phone's already-established encrypted-from-generation-3
        # story.
        ipad_days_ago = [10, 3, 0]
        for days_ago in ipad_days_ago:
            started = now - timedelta(days=days_ago, hours=1)
            conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) VALUES (?, ?, ?, ?, ?, ?)",
                (pad.udid, "schedule", _iso(started), _iso(started + timedelta(minutes=12)), "succeeded", None),
            )
        for index, days_ago in enumerate(ipad_days_ago):
            taken_at = now - timedelta(days=days_ago)
            write_realistic_backup(
                backup_root / pad.udid,
                pad,
                encrypted=False,
                files=demo_files.for_ipad_generation(index),
                serial="DEMOPAD0001",
                now=taken_at,
            )
            snapshots.take(backup_root, pad.udid, taken_at, hardlinks=True)
    # DEMO_PASSWORD is the marked demo credential from the module docstring, not a secret.
    log.warning(  # nosemgrep: python-logger-credential-disclosure
        "Demo content seeded. DEMO CREDENTIALS: %s / %s", DEMO_USER, DEMO_PASSWORD
    )
    return True
