# SPDX-License-Identifier: GPL-3.0-or-later
"""Browsing one backup generation and reading a single file out of it (src/bioseasy/extract.py).

Everything here runs against `write_realistic_backup`, the structurally real Finder-format fixture
the verification tests already use: a real `Manifest.db` with a `Files` table, and payloads stored
under `<fileID[:2]>/<fileID>`. No device and no mocking of the module under test.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest
from fixtures import BACKUP_PASSWORD, DEFAULT_FILES, BackupFile, write_realistic_backup

from bioseasy import extract
from bioseasy.engine.base import DeviceSeen, Transport

DEVICE = DeviceSeen(
    udid="00008110-000A1B2C3D4E5F60",
    name="Demo iPhone",
    product_type="iPhone15,2",
    os_version="18.6",
    transport=Transport.WIFI,
)


def make_backup(tmp_path, **kwargs):
    return write_realistic_backup(tmp_path / DEVICE.udid, DEVICE, **kwargs)


# --- Listing ----------------------------------------------------------------------------------


def test_lists_every_regular_file_in_the_backup(tmp_path):
    backup = make_backup(tmp_path)
    page = extract.list_entries(backup.path)

    assert page.total == len(DEFAULT_FILES)
    assert {(e.domain, e.relative_path) for e in page.rows} == {(f.domain, f.relative_path) for f in DEFAULT_FILES}


def test_entry_carries_the_file_name_and_the_size_from_disk(tmp_path):
    backup = make_backup(tmp_path)
    rows = {e.relative_path: e for e in extract.list_entries(backup.path).rows}

    sms = rows["Library/SMS/sms.db"]
    assert sms.name == "sms.db"
    assert sms.is_file
    # The fixture writes no MBFile blob, so the size comes from the stored payload - which is the
    # honest fallback, not a guess.
    assert sms.size == len(b"sms-db-contents")


def test_domains_are_listed_with_their_file_counts(tmp_path):
    backup = make_backup(tmp_path)

    assert extract.domains(backup.path) == [("HomeDomain", 2), ("CameraRollDomain", 1)]


def test_listing_can_be_narrowed_to_one_domain(tmp_path):
    backup = make_backup(tmp_path)
    page = extract.list_entries(backup.path, domain="CameraRollDomain")

    assert page.total == 1
    assert page.rows[0].relative_path == "Media/DCIM/100APPLE/IMG_0001.JPG"


def test_search_matches_part_of_a_path(tmp_path):
    backup = make_backup(tmp_path)
    page = extract.list_entries(backup.path, query="AddressBook")

    assert [e.name for e in page.rows] == ["AddressBook.sqlitedb"]


def test_search_treats_wildcards_as_literal_characters(tmp_path):
    """A search for "%" must not match every file.

    LIKE gives "%" and "_" their own meaning; passing a user's term straight through turns a
    search box into a "show me everything" button and makes "_" match any character.
    """
    backup = make_backup(
        tmp_path,
        files=(
            BackupFile("HomeDomain", "Library/notes.txt", b"plain"),
            BackupFile("HomeDomain", "Library/100%-done.txt", b"percent"),
        ),
    )

    assert [e.name for e in extract.list_entries(backup.path, query="%").rows] == ["100%-done.txt"]
    assert extract.list_entries(backup.path, query="%").total == 1


def test_paging_is_stable_and_reports_the_total(tmp_path):
    files = tuple(BackupFile("HomeDomain", f"Library/file-{i:03}.txt", f"content {i}".encode()) for i in range(25))
    backup = make_backup(tmp_path, files=files)

    first = extract.list_entries(backup.path, page=1, page_size=10)
    second = extract.list_entries(backup.path, page=2, page_size=10)
    third = extract.list_entries(backup.path, page=3, page_size=10)

    assert first.total == 25
    assert first.has_more and second.has_more and not third.has_more
    assert len(third.rows) == 5
    # No file appears on two pages: the query is ordered, so paging cannot shuffle underneath.
    seen = [e.file_id for e in first.rows + second.rows + third.rows]
    assert len(seen) == len(set(seen)) == 25


def test_directory_entries_are_not_listed_as_files(tmp_path):
    backup = make_backup(
        tmp_path,
        files=(
            BackupFile("HomeDomain", "Library", b"", flags=2),
            BackupFile("HomeDomain", "Library/notes.txt", b"plain"),
        ),
    )
    page = extract.list_entries(backup.path)

    assert [e.name for e in page.rows] == ["notes.txt"]


def test_the_backups_own_bookkeeping_is_never_offered(tmp_path):
    """Manifest.db and friends are the backup's own metadata, not the user's files."""
    backup = make_backup(
        tmp_path,
        files=(
            BackupFile("HomeDomain", "Library/notes.txt", b"plain"),
            BackupFile("RootDomain", "Manifest.db", b"not-user-data"),
        ),
    )
    page = extract.list_entries(backup.path)

    assert [e.name for e in page.rows] == ["notes.txt"]


# --- Reading one file -------------------------------------------------------------------------


def test_reads_the_stored_bytes_of_one_file(tmp_path):
    backup = make_backup(tmp_path)
    target = next(f for f in DEFAULT_FILES if f.relative_path.endswith("IMG_0001.JPG"))

    entry, path = extract.open_file(backup.path, target.file_id)

    assert entry.name == "IMG_0001.JPG"
    assert path.read_bytes() == target.content


def test_reading_an_unknown_file_id_is_refused(tmp_path):
    backup = make_backup(tmp_path)

    with pytest.raises(extract.ExtractError):
        extract.open_file(backup.path, "0" * 40)


def test_a_listed_file_whose_payload_is_gone_is_named_as_such(tmp_path):
    backup = make_backup(tmp_path, write_hashed_files=False)
    target = DEFAULT_FILES[0]

    with pytest.raises(extract.ExtractError, match="contents are missing"):
        extract.open_file(backup.path, target.file_id)


def test_a_directory_entry_cannot_be_downloaded(tmp_path):
    backup = make_backup(tmp_path, files=(BackupFile("HomeDomain", "Library", b"", flags=2),))
    file_id = BackupFile("HomeDomain", "Library", b"", flags=2).file_id

    with pytest.raises(extract.ExtractError, match="folder"):
        extract.open_file(backup.path, file_id)


# --- The file id is the whole boundary --------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "../../../../etc/passwd",
        "..",
        "aa/../../etc/passwd",
        "0" * 39,
        "0" * 41,
        "ZZZZ" + "0" * 36,
        "0123456789ABCDEF0123456789abcdef01234567",  # upper case is not the stored form
        "",
        "' OR 1=1 --",
    ],
)
def test_a_file_id_that_is_not_a_sha1_digest_is_refused(tmp_path, bad):
    """The file id arrives from a URL, so it is the one value an attacker controls here.

    It is checked against a SHA-1 hex pattern before it is used as a path component or reaches
    SQL - and everything that does reach SQL is a bound parameter, never interpolated. Both halves
    matter: pyiosbackup's own manifest reader builds this exact lookup by f-string.
    """
    backup = make_backup(tmp_path)

    with pytest.raises(extract.ExtractError):
        extract.stored_path(backup.path, bad)
    with pytest.raises(extract.ExtractError):
        extract.open_file(backup.path, bad)


def test_a_quote_in_a_search_term_cannot_break_the_query(tmp_path):
    backup = make_backup(tmp_path)

    page = extract.list_entries(backup.path, query="' OR 1=1 --")

    assert page.total == 0
    assert page.rows == []


# --- Encrypted backups: refused, not faked ----------------------------------------------------


def test_an_encrypted_backup_asks_for_the_password_instead_of_listing(tmp_path):
    """Without the password there is genuinely nothing to read - an encrypted backup's Manifest.db
    is itself encrypted - and an empty list would read as "this backup has no files"."""
    backup = make_backup(tmp_path, encrypted=True)

    for call in (
        lambda: extract.list_entries(backup.path),
        lambda: extract.domains(backup.path),
        lambda: extract.get_entry(backup.path, DEFAULT_FILES[0].file_id),
    ):
        with pytest.raises(extract.PasswordRequired):
            call()


def test_a_wrong_password_is_told_apart_from_a_missing_one(tmp_path):
    """Two different answers, because they need two different reactions from the reader."""
    backup = make_backup(tmp_path, encrypted=True)

    with pytest.raises(extract.WrongPassword):
        extract.list_entries(backup.path, password="definitely not it")
    with pytest.raises(extract.PasswordRequired):
        extract.list_entries(backup.path, password="")


def test_the_right_password_lists_an_encrypted_backup(tmp_path):
    backup = make_backup(tmp_path, encrypted=True)

    page = extract.list_entries(backup.path, password=BACKUP_PASSWORD)

    assert page.total == len(DEFAULT_FILES)
    assert {(e.domain, e.relative_path) for e in page.rows} == {(f.domain, f.relative_path) for f in DEFAULT_FILES}
    assert extract.domains(backup.path, BACKUP_PASSWORD) == [("HomeDomain", 2), ("CameraRollDomain", 1)]


def test_sizes_come_from_the_index_not_from_the_padded_payload(tmp_path):
    """An encrypted payload on disk is padded to the block size, so the stored file is larger than
    the real one. The size shown has to be the one recorded in the index, or every file would read
    as a few bytes bigger than it is."""
    backup = make_backup(tmp_path, encrypted=True)
    rows = {e.name: e for e in extract.list_entries(backup.path, password=BACKUP_PASSWORD).rows}

    sms = rows["sms.db"]
    on_disk = (backup.path / sms.file_id[:2] / sms.file_id).stat().st_size
    assert sms.size == len(b"sms-db-contents")
    assert on_disk > sms.size


def test_streaming_an_encrypted_file_yields_exactly_its_plaintext(tmp_path):
    backup = make_backup(tmp_path, encrypted=True)

    for wanted in DEFAULT_FILES:
        entry, chunks = extract.stream_file(backup.path, wanted.file_id, BACKUP_PASSWORD)
        assert b"".join(chunks) == wanted.content, entry.name


def test_a_large_file_is_decrypted_in_pieces_not_in_one_go(tmp_path):
    """The point of streaming: memory stays flat whatever the file size.

    Proven by the shape of the output rather than by measuring memory - a whole-file
    implementation would hand back one piece no matter how small the chunk size is.
    """
    big = BackupFile("HomeDomain", "Media/big.bin", b"X" * (3 * 1024 * 1024 + 7))
    backup = make_backup(tmp_path, encrypted=True, files=(big,))

    # A false positive, not a credential: the generic-api-key rule sees the word PASSWORD followed
    # by an "=" and takes the chunk size for a secret. Allowlisted in .gitleaks.toml, not with an
    # inline marker - the scan runs over the whole history, where this line already exists.
    _entry, chunks = extract.stream_file(backup.path, big.file_id, BACKUP_PASSWORD, chunk_bytes=64 * 1024)
    pieces = list(chunks)

    assert len(pieces) > 40
    assert b"".join(pieces) == big.content


def test_streaming_works_for_an_unencrypted_backup_too(tmp_path):
    backup = make_backup(tmp_path)
    wanted = DEFAULT_FILES[0]

    _entry, chunks = extract.stream_file(backup.path, wanted.file_id)

    assert b"".join(chunks) == wanted.content


def test_open_file_refuses_an_encrypted_backup_even_with_the_password(tmp_path):
    """The bytes at that path are ciphertext. Handing the path to a file response would serve
    unusable data that looks like a successful download, so this asks for `stream_file` instead."""
    backup = make_backup(tmp_path, encrypted=True)

    with pytest.raises(extract.PasswordRequired):
        extract.open_file(backup.path, DEFAULT_FILES[0].file_id, BACKUP_PASSWORD)


def test_the_decrypted_index_never_becomes_a_file(tmp_path):
    """The reason this module does not use pyiosbackup's reader.

    Its manifest reader writes the decrypted Manifest.db to a temp file it never removes. Here the
    plaintext index only ever exists in memory, so nothing new appears anywhere on disk while an
    encrypted backup is browsed.
    """
    backup = make_backup(tmp_path, encrypted=True)
    before = {p for p in tmp_path.rglob("*") if p.is_file()}
    temp_before = set(Path(tempfile.gettempdir()).glob("*sqlite3*"))

    extract.list_entries(backup.path, password=BACKUP_PASSWORD)

    assert {p for p in tmp_path.rglob("*") if p.is_file()} == before
    assert set(Path(tempfile.gettempdir()).glob("*sqlite3*")) == temp_before


def test_a_backup_whose_manifest_cannot_be_read_counts_as_encrypted(tmp_path):
    """Refusing is the safe answer when we cannot establish that a backup is in the clear."""
    backup = make_backup(tmp_path)
    (backup.path / "Manifest.plist").write_bytes(b"not a plist")

    assert extract.is_encrypted(backup.path) is True


def test_a_generation_without_a_file_index_says_so(tmp_path):
    backup = make_backup(tmp_path, write_manifest_db=False)

    with pytest.raises(extract.ExtractError, match="no file index"):
        extract.list_entries(backup.path)


def test_the_manifest_is_opened_read_only(tmp_path):
    """A backup may be hard-linked into several snapshots, so a stray write would alter every
    generation sharing that file. Proven by trying to write through the module's own connection."""
    backup = make_backup(tmp_path)

    conn = extract._manifest_connection(backup.path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM Files")
    finally:
        conn.close()


# --- Column browsing ---------------------------------------------------------------------------


def test_children_derives_folders_from_flat_paths(tmp_path):
    """A backup has no directory tree on disk; the levels come out of the paths themselves."""
    backup = write_realistic_backup(tmp_path / "u", DEVICE)

    top = extract.children(backup.path, "HomeDomain")
    assert [(c.name, c.is_folder) for c in top.rows] == [("Library", True)]

    library = extract.children(backup.path, "HomeDomain", "Library")
    assert sorted((c.name, c.is_folder, c.count) for c in library.rows) == [
        ("AddressBook", True, 1),
        ("SMS", True, 1),
    ]

    sms = extract.children(backup.path, "HomeDomain", "Library/SMS")
    assert [(c.name, c.is_folder, c.size) for c in sms.rows] == [("sms.db", False, len(b"sms-db-contents"))]


def test_a_column_is_paged_however_large_the_folder(tmp_path):
    many = tuple(BackupFile("CameraRollDomain", f"Media/{i:04d}.JPG", b"x") for i in range(500))
    backup = write_realistic_backup(tmp_path / "u", DEVICE, files=many)

    first = extract.children(backup.path, "CameraRollDomain", "Media", page=1, page_size=100)
    second = extract.children(backup.path, "CameraRollDomain", "Media", page=2, page_size=100)

    assert first.total == 500
    assert len(first.rows) == 100
    assert first.has_more
    assert {c.name for c in first.rows}.isdisjoint({c.name for c in second.rows})


def test_a_selection_of_paths_expands_into_files(tmp_path):
    backup = write_realistic_backup(tmp_path / "u", DEVICE)
    by_path = {f.relative_path: f.file_id for f in DEFAULT_FILES if f.flags == 1}

    whole_area = extract.selection_file_ids(backup.path, [("HomeDomain", "")])
    one_folder = extract.selection_file_ids(backup.path, [("HomeDomain", "Library/SMS")])
    one_file = extract.selection_file_ids(backup.path, [("HomeDomain", "Library/SMS/sms.db")])
    nothing = extract.selection_file_ids(backup.path, [])

    assert set(whole_area) == {v for k, v in by_path.items() if k.startswith("Library")}
    assert one_folder == [by_path["Library/SMS/sms.db"]]
    assert one_file == one_folder
    assert nothing == []


def test_a_selected_path_cannot_reach_another_area(tmp_path):
    """The path is a value in a query against this backup's own index, never a filesystem path -
    so a crafted one selects nothing rather than escaping the generation."""
    backup = write_realistic_backup(tmp_path / "u", DEVICE)

    escaped = extract.selection_file_ids(backup.path, [("HomeDomain", "../CameraRollDomain")])
    wildcard = extract.selection_file_ids(backup.path, [("HomeDomain", "%")])

    assert escaped == []
    assert wildcard == []  # the LIKE wildcard is escaped, so "%" is a literal folder name
