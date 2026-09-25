# SPDX-License-Identifier: GPL-3.0-or-later
"""Removing a device from bioseasy.

Two things a device leaves behind are treated very differently here.

Its **pair record is a device credential**: whoever holds it can back the device up and read an
unencrypted backup (docs/pairing.md). Removing the device without deleting the record would leave
that credential in the data volume for a device bioseasy no longer shows anywhere, which is the
one outcome this must not produce.

Its **backups are the point of the whole product** and are never touched. They stay where they
are, under `<backup root>/<udid>`, and the caller tells the user so. Someone who wants them gone
deletes that folder deliberately; a button that says "remove device" must not decide that for
them, and an accidental click must not be the end of a year of backups.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from . import pairing

# Tables keyed by udid that SQLite will not clear on its own: the device tables declare
# `REFERENCES devices(udid) ON DELETE CASCADE` and go with the row, these do not.
# `activities` is the live registry behind the header indicator, `seen_devices` the USB scan
# result, `pairings` the state of a pairing attempt, and `pairing_codes.consumed_udid` records
# which device a one-time code was spent on - the last one in its own column, which is why it is
# cleared rather than deleted: the code itself stays spent.
#
# One udid does outlive this on purpose: `log_entries` keeps the first 8 characters of a device
# id in service log lines, and rewriting the log to hide that a device was ever here would be
# falsifying a record. Those lines age out with the log itself.
_WITHOUT_CASCADE = ("activities", "seen_devices", "pairings")


def backup_folder(backup_root: Path, udid: str) -> Path:
    return backup_root / udid


def remove(conn: sqlite3.Connection, records_dir: Path, udid: str) -> None:
    """Forget the device: its row, everything keyed to it, and its pair record.

    Leaves every backup on disk untouched. Safe to call for a device that is already half gone -
    a pairing attempt that never produced a device row, for instance - so a stuck state can always
    be cleared.
    """
    with conn:  # one transaction: a half-removed device is worse than none removed
        for table in _WITHOUT_CASCADE:
            conn.execute(f"DELETE FROM {table} WHERE udid = ?", (udid,))  # noqa: S608 - fixed names above
        conn.execute("DELETE FROM devices WHERE udid = ?", (udid,))
        conn.execute("UPDATE pairing_codes SET consumed_udid = NULL WHERE consumed_udid = ?", (udid,))
    pairing.remove(records_dir, udid)
