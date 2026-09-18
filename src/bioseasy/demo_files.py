# SPDX-License-Identifier: GPL-3.0-or-later
"""The file set a demo deployment's demo backups carry, so browsing and restoring can be tried out.

Every payload here is a real file of its type - the databases open in sqlite3, the screenshots
open in an image viewer, the plists parse. A restored demo file that turns out to be a placeholder
would teach the wrong thing about the feature it demonstrates.
"""

from __future__ import annotations

import plistlib
import sqlite3
import struct
import tempfile
import zlib
from pathlib import Path

from .demo_backup import BackupFile


def _png(red: int, green: int, blue: int, side: int = 48) -> bytes:
    """A real PNG of one solid colour. Hand-built because Pillow is not a dependency and a
    screenshot that does not open is not a demonstration of a restored screenshot."""

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))

    header = struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0)  # 8-bit truecolour, no interlace
    raw = b"".join(b"\x00" + bytes((red, green, blue)) * side for _ in range(side))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def _sqlite(schema: str, rows: list[tuple[str, list[tuple]]]) -> bytes:
    """A real SQLite file, built in a temporary directory and read back as bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "demo.db"
        with sqlite3.connect(path) as conn:
            conn.executescript(schema)
            for table, values in rows:
                placeholders = ", ".join("?" * len(values[0]))
                conn.executemany(f"INSERT INTO {table} VALUES ({placeholders})", values)  # noqa: S608 - fixed literals
            conn.commit()
        return path.read_bytes()


_MESSAGES = _sqlite(
    "CREATE TABLE message (rowid INTEGER PRIMARY KEY, handle TEXT, text TEXT, sent_at TEXT)",
    [
        (
            "message",
            [
                (1, "+49 30 000000", "Are we still on for Thursday?", "2026-06-02T18:04:00Z"),
                (2, "+49 30 000000", "Yes - I will bring the cable.", "2026-06-02T18:06:00Z"),
                (3, "demo@example.org", "Photos from the weekend are in the shared album.", "2026-06-09T09:20:00Z"),
            ],
        )
    ],
)

_CONTACTS = _sqlite(
    "CREATE TABLE ABPerson (rowid INTEGER PRIMARY KEY, first TEXT, last TEXT, organization TEXT)",
    [
        (
            "ABPerson",
            [
                (1, "Ada", "Demo", "bioseasy demo"),
                (2, "Grace", "Example", "bioseasy demo"),
                (3, "Alan", "Sample", None),
            ],
        )
    ],
)

_NOTES = _sqlite(
    "CREATE TABLE note (rowid INTEGER PRIMARY KEY, title TEXT, body TEXT, edited_at TEXT)",
    [
        (
            "note",
            [
                (1, "Packing list", "charger, adapter, passport", "2026-05-30T21:10:00Z"),
                (2, "Wifi at the office", "network: bioseasy-demo", "2026-06-01T08:00:00Z"),
            ],
        )
    ],
)

_PHONE_PREFS = plistlib.dumps({"DialAssist": False, "LastKnownCarrier": "Demo Mobile", "SilenceUnknownCallers": True})
_ACCESSIBILITY_PREFS = plistlib.dumps({"TextSize": 3, "ReduceMotion": True, "BoldText": False})

# The part of the set that is in every generation. Kept small enough to stay readable in the file
# browser and varied enough that a search over domain, path and extension has something to find.
_STABLE = (
    BackupFile("HomeDomain", "Library/SMS/sms.db", _MESSAGES),
    BackupFile("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", _CONTACTS),
    BackupFile("HomeDomain", "Library/Preferences/com.apple.mobilephone.plist", _PHONE_PREFS),
    BackupFile("HomeDomain", "Library/Preferences/com.apple.Accessibility.plist", _ACCESSIBILITY_PREFS),
    BackupFile("AppDomain-com.example.notes", "Documents/notes.sqlite", _NOTES),
    BackupFile(
        "AppDomain-com.example.notes",
        "Documents/shopping-list.txt",
        b"oat milk\nbatteries (AA)\nbirthday card for Grace\n",
    ),
    BackupFile("RootDomain", "Library/Caches/locationd/consolidated.db", b"demo cache, deliberately tiny\n"),
)

# Screenshots accumulate over time, so two generations of the same device differ in the file
# browser rather than looking identical apart from their timestamp.
_SCREENSHOTS = (
    ("IMG_0001.PNG", (198, 112, 88)),
    ("IMG_0002.PNG", (72, 128, 164)),
    ("IMG_0003.PNG", (94, 156, 110)),
    ("IMG_0004.PNG", (188, 168, 92)),
    ("IMG_0005.PNG", (132, 104, 172)),
    ("IMG_0006.PNG", (206, 140, 152)),
    ("IMG_0007.PNG", (96, 160, 168)),
)


# --- the iPad's own file set -----------------------------------------------------------------
# An iPad backs up different domains and different apps than a phone: no SMS, no phone/carrier
# preferences, no address book in this demo story. Safari bookmarks and two document-style apps
# stand in instead, so the two devices' file browsers show genuinely different content rather than
# the same fixture copied under a second UDID.

_BOOKMARKS = _sqlite(
    "CREATE TABLE bookmark (rowid INTEGER PRIMARY KEY, title TEXT, url TEXT, added_at TEXT)",
    [
        (
            "bookmark",
            [
                (1, "bioseasy docs", "https://bioseasy.example.net/guide", "2026-06-01T10:00:00Z"),
                (2, "Weather", "https://example.org/weather", "2026-06-03T07:30:00Z"),
            ],
        )
    ],
)

_SAFARI_PREFS = plistlib.dumps({"HomepageURL": "https://example.org/start", "OpenLinksInBackground": True})

_READING_LIBRARY = _sqlite(
    "CREATE TABLE book (rowid INTEGER PRIMARY KEY, title TEXT, author TEXT, progress_percent INTEGER)",
    [("book", [(1, "Sample Handbook", "A. Author", 42), (2, "Field Notes", "B. Writer", 5)])],
)

_SKETCH_LIBRARY = _sqlite(
    "CREATE TABLE sketch (rowid INTEGER PRIMARY KEY, title TEXT, created_at TEXT)",
    [("sketch", [(1, "Kitchen layout", "2026-06-04T12:00:00Z")])],
)

_IPAD_STABLE = (
    BackupFile("HomeDomain", "Library/Safari/Bookmarks.db", _BOOKMARKS),
    BackupFile("HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist", _SAFARI_PREFS),
    BackupFile("AppDomain-com.example.reader", "Documents/library.sqlite", _READING_LIBRARY),
    BackupFile("AppDomain-com.example.sketchpad", "Documents/canvas.sqlite", _SKETCH_LIBRARY),
)

# A sketch added per generation, same idea as the phone's screenshots: two generations of the same
# device should differ in the file browser, not just in their timestamp.
_SKETCHES = (
    ("sketch-01.PNG", (210, 180, 90)),
    ("sketch-02.PNG", (90, 150, 210)),
    ("sketch-03.PNG", (150, 90, 180)),
)


def for_ipad_generation(index: int) -> tuple[BackupFile, ...]:
    """The iPad's file set as it stood at generation `index`, oldest being 0."""
    sketches = tuple(
        BackupFile("AppDomain-com.example.sketchpad", f"Documents/Canvases/{name}", _png(*colour))
        for name, colour in _SKETCHES[: index + 1]
    )
    return _IPAD_STABLE + sketches


def for_generation(index: int, *, bulk: bool = False) -> tuple[BackupFile, ...]:
    """The set as it stood at generation `index`, oldest being 0: the stable files plus one more
    screenshot per generation.

    `bulk` adds a large, single-folder attachment set (see `BULK_ATTACHMENTS`) on top - only the
    newest generation carries it (demo_seed.py), so the seed pays its write cost once rather than
    once per generation.
    """
    shots = tuple(
        BackupFile("CameraRollDomain", f"Media/DCIM/100APPLE/{name}", _png(*colour))
        for name, colour in _SCREENSHOTS[: index + 1]
    )
    return _STABLE + shots + (BULK_ATTACHMENTS if bulk else ())


# The column view (device_files.html) pages a folder at extract.CHILD_PAGE_SIZE (200) rows and
# only then shows "Show more (200 of N)" and "Select all N" - with the seven-file folders above,
# neither ever appears in a demo deployment. 240 is the smallest round number past 200 that exercises
# both: a first page of 200, a second page of the remaining 40, and a "Select all 240" whose count
# a reader can actually check against the "Show more" counter. Kept to one folder, in the newest
# generation only (see `bulk` above), so the extra disk and seed time stay bounded - measured in
# tests/test_demo_seed.py::test_seed_duration_and_disk_stay_bounded.
BULK_FILE_COUNT = 240
# A handful of distinct, cheap colours so the 240 attachments are not 240 byte-identical files -
# still real, tiny PNGs (see `_png`), just not hand-picked individually like `_SCREENSHOTS`.
_BULK_COLOURS = ((198, 112, 88), (72, 128, 164), (94, 156, 110), (188, 168, 92), (132, 104, 172))
BULK_ATTACHMENTS = tuple(
    BackupFile(
        "MediaDomain",
        f"Library/SMS/Attachments/inbox/IMG_{i:04d}.PNG",
        _png(*_BULK_COLOURS[i % len(_BULK_COLOURS)], side=8),
    )
    for i in range(BULK_FILE_COUNT)
)
