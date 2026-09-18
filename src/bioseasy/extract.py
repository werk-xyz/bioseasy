# SPDX-License-Identifier: GPL-3.0-or-later
"""Browse one backup generation and read a single file out of it.

A Finder-format backup is flat on disk: every file is stored as `<fileID[:2]>/<fileID>`, and
`Manifest.db`'s `Files` table maps `(domain, relativePath)` to that `fileID`. Browsing is
therefore a database question, not a filesystem walk - there are no directories to descend.

Why this does not simply call pyiosbackup
-----------------------------------------
pyiosbackup is a dependency already (password_check.py uses its `Keybag`), and its `Backup` class
can list and extract. Two things in it make it unsuitable as the front door for a *server*:

- `ManifestDbSqlite3.get_metadata_by_id` builds its SQL by f-string:
  `... WHERE fileID='{file_id}'`. Our file ids come out of a URL, so that is an injection waiting
  for a caller who forgets to validate. Everything here uses bound parameters.
- `ManifestDbSqlite3.from_path` decrypts an encrypted `Manifest.db` into
  `tempfile.NamedTemporaryFile(delete=False)` and never removes it. On a long-running server that
  accumulates decrypted manifests - the very data the backup password protects - in the system
  temp directory.

So this module does its own SQL and its own file handling, and borrows from pyiosbackup only the
two pieces that encode Apple's format: the `Keybag` and the `MBFile` archive shape.

Encrypted backups
-----------------
Both halves are here, and neither writes plaintext to disk:

- **The file index** is decrypted in memory and handed to SQLite through
  `Connection.deserialize`, so the decrypted `Manifest.db` never becomes a file. That is the whole
  reason this module does not use pyiosbackup's reader, which writes it to a temp file it never
  removes.
- **A file payload** is decrypted while it streams. Apple encrypts payloads with AES-CBC under a
  zero IV after unwrapping a per-file key, and pads with PKCS7 - all three of those are streamable,
  so a multi-gigabyte video is decrypted a megabyte at a time instead of being held in memory or
  staged on disk.

The backup password is never stored here; it is passed in per call. Where it is held between
calls is `app.py`'s decision (in memory, bound to the session, with a short expiry).
"""

from __future__ import annotations

import plistlib
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

# A backup's own bookkeeping, not user data: never offered for download or shown in a listing.
# Same set verify.py excludes, for the same reason.
META_FILES = frozenset(
    {"Manifest.db", "Manifest.db-shm", "Manifest.db-wal", "Info.plist", "Status.plist", "Manifest.plist"}
)

# Files rows carry flags: 1 a regular file, 2 a domain directory entry (no payload of its own),
# 4 a symlink. Only regular files have something to download.
FILE_FLAG = 1
DIRECTORY_FLAG = 2

# A fileID is a SHA-1 hex digest. Validated before it reaches SQL or a path, so a crafted value
# can neither escape the snapshot directory nor reach the database as anything but a parameter.
_FILE_ID_RE = re.compile(r"^[0-9a-f]{40}$")

PAGE_SIZE = 100

# A decrypted file index is held in memory rather than written to disk, so it needs a ceiling. A
# manifest for a phone with a hundred thousand files is tens of megabytes; this is generous, and
# the alternative - staging it on disk - is the thing this module exists to avoid.
MAX_MANIFEST_BYTES = 512 * 1024 * 1024

# How much of an encrypted payload is decrypted at a time. Large enough that a big file is not
# thousands of round trips, small enough that memory stays flat whatever the file size.
CHUNK_BYTES = 1024 * 1024


class ExtractError(Exception):
    """Browsing or reading failed; the message is safe to show and names no absolute path."""


class PasswordRequired(ExtractError):
    """The backup is encrypted. Listing and reading both need the backup password."""


class WrongPassword(ExtractError):
    """The backup is encrypted and the password given does not open it."""


@dataclass(frozen=True)
class Entry:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    # None where the size is genuinely unknown rather than zero: a `file` blob we could not
    # decode and no payload on disk. Shown as "unknown", never as 0 bytes.
    size: int | None

    @property
    def is_file(self) -> bool:
        return self.flags == FILE_FLAG

    @property
    def name(self) -> str:
        return self.relative_path.rsplit("/", 1)[-1] or self.relative_path


@dataclass(frozen=True)
class EntryPage:
    rows: list[Entry]
    total: int
    page: int
    page_size: int

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total


def is_encrypted(snapshot_dir: Path) -> bool:
    """Whether this backup's `Manifest.plist` declares encryption.

    A missing or unreadable Manifest.plist reads as encrypted: refusing to browse is the safe
    answer when we cannot establish that a backup is in the clear.
    """
    try:
        data = plistlib.loads((snapshot_dir / "Manifest.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return True
    return bool(data.get("IsEncrypted", True))


def _keybag(snapshot_dir: Path, password: str):
    """The unwrapped keybag for an encrypted backup, or a typed error.

    A wrong password fails as an AES key-unwrap integrity error, which is exactly what should be
    reported as "wrong password" - the unwrap is the check. Anything else is a broken or foreign
    keybag and says so by exception class only, never by echoing manifest content.
    """
    from cryptography.hazmat.primitives.keywrap import InvalidUnwrap  # noqa: PLC0415
    from pyiosbackup.keybag import Keybag  # noqa: PLC0415
    from pyiosbackup.manifest_plist import ManifestPlist  # noqa: PLC0415

    try:
        manifest = ManifestPlist.from_path(snapshot_dir / "Manifest.plist")
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        raise ExtractError("This backup's manifest could not be read.") from exc
    try:
        return Keybag.from_manifest(manifest, password), manifest
    except InvalidUnwrap as exc:
        raise WrongPassword("That password does not open this backup.") from exc
    except Exception as exc:  # noqa: BLE001 - class name only; a keybag can hold key material
        raise ExtractError(f"This backup's keybag could not be read ({exc.__class__.__name__}).") from exc


def _manifest_connection(snapshot_dir: Path, password: str | None = None) -> sqlite3.Connection:
    """A connection to this snapshot's file index.

    Unencrypted: read-only at the driver level (`mode=ro`), not by convention - this module has no
    reason to write to a backup, and a backup being browsed may be hard-linked into several
    snapshots, so a stray write would alter every generation sharing that file.

    Encrypted: decrypted in memory and handed to SQLite with `deserialize`, so the plaintext index
    never becomes a file. An in-memory database is writable, which is harmless - it is a private
    copy, and the backup on disk is never touched.
    """
    db_path = snapshot_dir / "Manifest.db"
    if not db_path.is_file():
        raise ExtractError("This generation has no file index (Manifest.db is missing).")

    if not is_encrypted(snapshot_dir):
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    if not password:
        raise PasswordRequired("This backup is encrypted.")
    if db_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ExtractError("This backup's file index is too large to open.")

    keybag, manifest = _keybag(snapshot_dir, password)
    try:
        plain = keybag.decrypt(db_path.read_bytes(), manifest.manifest_key)
    except Exception as exc:  # noqa: BLE001 - class name only
        raise ExtractError(f"The file index could not be decrypted ({exc.__class__.__name__}).") from exc

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        conn.deserialize(plain)
    except sqlite3.Error as exc:
        conn.close()
        raise ExtractError("The file index did not decrypt into a readable database.") from exc
    return conn


def _decoded_mbfile(blob: bytes | None):
    """A row's decoded `file` blob, or None when it cannot be read.

    Real devices store an NSKeyedArchiver-encoded `MBFile` there, carrying the size, the mode and -
    on an encrypted backup - the wrapped per-file key. pyiosbackup registers the class map for it,
    so decoding is a library call; a backup written by another tool simply has nothing to give, and
    that is reported as unknown rather than guessed.
    """
    if not blob:
        return None
    try:
        import pyiosbackup.manifest_dbs.sqlite3  # noqa: F401, PLC0415 - registers MBFile in the class map
        from bpylist2 import archiver  # noqa: PLC0415 - optional path, keeps import cost off startup

        return archiver.unarchive(blob)
    except Exception:  # noqa: BLE001 - any decoding failure means "unknown", never a crash
        return None


def _decoded_size(blob: bytes | None) -> int | None:
    decoded = _decoded_mbfile(blob)
    size = getattr(decoded, "size", None)
    return size if isinstance(size, int) and size >= 0 else None


def _on_disk_size(snapshot_dir: Path, file_id: str) -> int | None:
    path = stored_path(snapshot_dir, file_id)
    try:
        return path.stat().st_size
    except OSError:
        return None


def stored_path(snapshot_dir: Path, file_id: str) -> Path:
    """Where a file id is stored inside the snapshot: `<fileID[:2]>/<fileID>`.

    `file_id` is validated as a SHA-1 hex digest first, so the result can never leave
    `snapshot_dir` - there is no separator and no `..` that survives that pattern.
    """
    if not _FILE_ID_RE.match(file_id):
        raise ExtractError("Not a valid file id.")
    return snapshot_dir / file_id[:2] / file_id


def domains(snapshot_dir: Path, password: str | None = None) -> list[tuple[str, int]]:
    """Every domain in this backup with how many regular files it holds, most files first.

    The domain is the only grouping a Finder backup actually has; there is no directory tree to
    offer, so this is what a browse view can open with.
    """
    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        rows = conn.execute(
            "SELECT domain, COUNT(*) AS n FROM Files WHERE flags = ? AND domain IS NOT NULL "
            "GROUP BY domain ORDER BY n DESC, domain",
            (FILE_FLAG,),
        ).fetchall()
    return [(row["domain"], row["n"]) for row in rows]


def list_entries(
    snapshot_dir: Path,
    *,
    domain: str | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = PAGE_SIZE,
    password: str | None = None,
) -> EntryPage:
    """One page of regular files, optionally narrowed to a domain and a path substring.

    Ordered by domain and path so that paging is stable: without an ORDER BY, SQLite may return
    rows in a different order between two queries and a reader would see files twice or not at
    all while paging.
    """
    where = ["flags = ?"]
    params: list[object] = [FILE_FLAG]
    if domain:
        where.append("domain = ?")
        params.append(domain)
    if query:
        where.append("relativePath LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(query)}%")
    clause = " AND ".join(where)
    page = max(1, page)

    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM Files WHERE {clause}", params).fetchone()[0]  # noqa: S608
        rows = conn.execute(
            f"SELECT fileID, domain, relativePath, flags, file FROM Files WHERE {clause} "  # noqa: S608
            "ORDER BY domain, relativePath LIMIT ? OFFSET ?",
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()

    entries = []
    for row in rows:
        if row["relativePath"] in META_FILES:
            continue
        size = _decoded_size(row["file"])
        if size is None:
            size = _on_disk_size(snapshot_dir, row["fileID"])
        entries.append(
            Entry(
                file_id=row["fileID"],
                domain=row["domain"] or "",
                relative_path=row["relativePath"] or "",
                flags=row["flags"],
                size=size,
            )
        )
    return EntryPage(rows=entries, total=total, page=page, page_size=page_size)


def _escape_like(text: str) -> str:
    """Neutralise LIKE wildcards in a user's search term.

    Without this, a search for "100%" matches everything from "100" on, and "_" matches any
    character - surprising rather than dangerous, but wrong either way.
    """
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_entry(snapshot_dir: Path, file_id: str, password: str | None = None) -> Entry:
    """One entry by file id, or an error if this backup does not list it."""
    if not _FILE_ID_RE.match(file_id):
        raise ExtractError("Not a valid file id.")
    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        row = conn.execute(
            "SELECT fileID, domain, relativePath, flags, file FROM Files WHERE fileID = ?",
            (file_id,),
        ).fetchone()
    if row is None or row["relativePath"] in META_FILES:
        raise ExtractError("This generation does not contain that file.")
    size = _decoded_size(row["file"])
    if size is None:
        size = _on_disk_size(snapshot_dir, file_id)
    return Entry(
        file_id=row["fileID"],
        domain=row["domain"] or "",
        relative_path=row["relativePath"] or "",
        flags=row["flags"],
        size=size,
    )


def download_name(entry: Entry) -> str:
    """A safe filename for the download header.

    The name comes from the backed-up file's own path, which the server never chose - it can hold
    quotes, newlines or separators, and a newline in a response header is a header-injection bug
    rather than a cosmetic one. Reduced to the last path segment with anything awkward replaced,
    and never empty.
    """
    raw = entry.name or entry.file_id
    cleaned = "".join(ch if ch.isprintable() and ch not in '"\\/\r\n\t' else "_" for ch in raw)
    cleaned = cleaned.strip(" .") or entry.file_id
    return cleaned[:120]


def _locate(snapshot_dir: Path, file_id: str, password: str | None) -> tuple[Entry, Path, bytes | None]:
    """The entry, the path holding its stored bytes, and its wrapped key if there is one.

    The wrapped key is read here rather than carried on `Entry`, so key material never rides along
    in a listing that a template will render.
    """
    if not _FILE_ID_RE.match(file_id):
        raise ExtractError("Not a valid file id.")
    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        row = conn.execute(
            "SELECT fileID, domain, relativePath, flags, file FROM Files WHERE fileID = ?",
            (file_id,),
        ).fetchone()
    if row is None or row["relativePath"] in META_FILES:
        raise ExtractError("This generation does not contain that file.")

    decoded = _decoded_mbfile(row["file"])
    size = getattr(decoded, "size", None)
    if not isinstance(size, int) or size < 0:
        size = _on_disk_size(snapshot_dir, file_id)
    entry = Entry(
        file_id=row["fileID"],
        domain=row["domain"] or "",
        relative_path=row["relativePath"] or "",
        flags=row["flags"],
        size=size,
    )
    if not entry.is_file:
        raise ExtractError("That entry is a folder, not a file.")
    path = stored_path(snapshot_dir, file_id)
    if not path.is_file():
        raise ExtractError("The file is listed in this generation but its contents are missing.")

    wrapped = getattr(decoded, "encryption_key", b"") or None
    return entry, path, wrapped


def open_file(snapshot_dir: Path, file_id: str, password: str | None = None) -> tuple[Entry, Path]:
    """The entry and the path its plaintext bytes are stored at.

    Only for a backup that is not encrypted: on an encrypted one the bytes at that path are
    ciphertext, so handing the path to a file response would serve unusable data that looks like a
    successful download. Use `stream_file` instead, which covers both cases.
    """
    if is_encrypted(snapshot_dir):
        raise PasswordRequired("This backup is encrypted; its stored bytes are not the file.")
    entry, path, _wrapped = _locate(snapshot_dir, file_id, password)
    return entry, path


def _decrypting_chunks(path: Path, keybag, wrapped_key: bytes, chunk_bytes: int):
    """Yield the plaintext of an encrypted payload, a chunk at a time.

    Apple encrypts a payload with AES-CBC under a zero IV, using a per-file key wrapped under the
    class key, and pads it with PKCS7. All three steps are streamable, so nothing here holds the
    whole file: the decryptor and the unpadder each keep only the block they need, and a
    multi-gigabyte video costs the same memory as a text file.
    """
    from cryptography.hazmat.primitives import padding  # noqa: PLC0415
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: PLC0415
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap  # noqa: PLC0415
    from pyiosbackup.keybag import encryption_key_struct  # noqa: PLC0415

    parsed = encryption_key_struct.parse(wrapped_key)
    file_key = aes_key_unwrap(keybag.get_key(parsed.class_), parsed.key)
    # CBC without authentication is Apple's choice, not ours: this decrypts what iOS wrote, and no
    # reader gets to pick the mode a backup was encrypted with years ago. Nothing here encrypts.
    # The marker goes on the line before the finding, not after it: a trailing one pushes the call
    # past the line limit, the formatter wraps it, and semgrep then reports the first line while
    # the marker sits on the last.
    # nosemgrep: crypto-mode-without-authentication
    cbc = modes.CBC(b"\x00" * 16)
    decryptor = Cipher(algorithms.AES(file_key), cbc).decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk_bytes)
            if not block:
                break
            out = unpadder.update(decryptor.update(block))
            if out:
                yield out
    tail = unpadder.update(decryptor.finalize())
    if tail:
        yield tail
    last = unpadder.finalize()
    if last:
        yield last


def _plain_chunks(path: Path, chunk_bytes: int):
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk_bytes)
            if not block:
                break
            yield block


def stream_file(snapshot_dir: Path, file_id: str, password: str | None = None, *, chunk_bytes: int = CHUNK_BYTES):
    """The entry and an iterator over its plaintext bytes, encrypted or not.

    Nothing is staged on disk and nothing is held whole in memory, which is what makes this safe
    for the large files a phone backup is mostly made of.
    """
    entry, path, wrapped = _locate(snapshot_dir, file_id, password)
    if not is_encrypted(snapshot_dir):
        return entry, _plain_chunks(path, chunk_bytes)
    if not wrapped:
        raise ExtractError("This file carries no key in the backup's index and cannot be decrypted.")
    keybag, _manifest = _keybag(snapshot_dir, password or "")
    return entry, _decrypting_chunks(path, keybag, wrapped, chunk_bytes)


def tar_stream(
    snapshot_dir: Path,
    file_ids: list[str],
    password: str | None = None,
    *,
    chunk_bytes: int = CHUNK_BYTES,
):
    """Several files as one streamed tar archive.

    tar rather than zip, deliberately. A zip's central directory sits at the end and its local
    headers carry each entry's size up front, so writing one without seeking means either buffering
    every file or hand-rolling data descriptors; `tarfile` streams natively (mode "w|") into a
    non-seekable sink. The cost is that Windows Explorer does not open .tar on its own - macOS and
    Linux do - and the gain is that a selection of several gigabytes never lands in memory or on
    disk. A single file is still offered as itself, not as an archive, so the common case is
    unaffected.

    Entries are named `<domain>/<relative path>`, which is the only structure a Finder backup
    has - there is no directory tree on disk to preserve.
    """
    import tarfile  # noqa: PLC0415 - only needed on this path

    class _Sink:
        """Collects what tarfile writes and hands it to the generator below."""

        def __init__(self) -> None:
            self.parts: list[bytes] = []

        def write(self, data: bytes) -> int:
            self.parts.append(data)
            return len(data)

        def drain(self) -> bytes:
            data = b"".join(self.parts)
            self.parts.clear()
            return data

    sink = _Sink()
    tar = tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT)
    try:
        for file_id in file_ids:
            entry, chunks = stream_file(snapshot_dir, file_id, password, chunk_bytes=chunk_bytes)
            # tarfile needs the size in the header before the body, and the plaintext size is what
            # the index records - the padded file on disk is longer.
            if entry.size is None:
                continue
            info = tarfile.TarInfo(name=f"{entry.domain}/{entry.relative_path}".lstrip("/"))
            info.size = entry.size
            info.mtime = 0
            tar.addfile(info, _ChunkReader(chunks))
            if out := sink.drain():
                yield out
    finally:
        tar.close()
    if out := sink.drain():
        yield out


class _ChunkReader:
    """A minimal read()-only file object over an iterator of byte chunks, for tarfile.addfile."""

    def __init__(self, chunks) -> None:
        self._chunks = iter(chunks)
        self._buffer = b""

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            rest = self._buffer + b"".join(self._chunks)
            self._buffer = b""
            return rest
        while len(self._buffer) < size:
            try:
                self._buffer += next(self._chunks)
            except StopIteration:
                break
        out, self._buffer = self._buffer[:size], self._buffer[size:]
        return out


# --- Column browsing ---------------------------------------------------------------------------
# A Finder backup has no directory tree on disk: every file lies flat under <fileID[:2]>/<fileID>,
# and the only structure is the `domain` plus `relativePath` pair in Manifest.db. The levels a
# column browser needs are therefore derived from the paths themselves rather than walked. Doing it
# in SQL keeps a folder with five thousand photos to one grouped query instead of fifty thousand
# rows crossing into Python: measured on a 50,000-row manifest, 2 to 50 ms per level. An index on
# (domain, relativePath) was measured too and made the deepest query slower, so there is none.

CHILD_PAGE_SIZE = 200

_CHILDREN_SQL = """
WITH rest AS (
  SELECT substr(relativePath, ? + 1) AS r, fileID, flags, file
  FROM Files
  WHERE domain = ? AND flags IN (?, ?) AND (? = '' OR relativePath LIKE ? ESCAPE '\\')
)
SELECT
  CASE WHEN instr(r, '/') > 0 THEN substr(r, 1, instr(r, '/') - 1) ELSE r END AS name,
  MAX(instr(r, '/') > 0) AS is_folder,
  COUNT(*) AS n,
  MIN(fileID) AS file_id,
  MIN(file) AS blob
FROM rest
WHERE r <> ''
GROUP BY name
"""


@dataclass(frozen=True)
class Child:
    """One row of a column: either a folder (derived from the paths below it) or a file."""

    name: str
    is_folder: bool
    # For a folder, how many files lie anywhere below it; for a file, always 1.
    count: int
    # Only set for a file. A folder has no payload and nothing to download on its own - it is
    # selected by path and expanded when the archive is built.
    file_id: str | None
    size: int | None


@dataclass(frozen=True)
class ChildPage:
    rows: list[Child]
    total: int
    page: int
    page_size: int

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total


def _prefix_params(prefix: str) -> tuple[int, str, str]:
    """The three shapes the children query needs: the length to cut off, the literal prefix, and
    the same prefix escaped for LIKE."""
    p = f"{prefix.strip('/')}/" if prefix.strip("/") else ""
    return len(p), p, _escape_like(p) + "%"


def children(
    snapshot_dir: Path,
    domain: str,
    prefix: str = "",
    *,
    page: int = 1,
    page_size: int = CHILD_PAGE_SIZE,
    password: str | None = None,
) -> ChildPage:
    """One column: what lies directly under `domain`/`prefix`, folders first then files."""
    length, literal, like = _prefix_params(prefix)
    page = max(1, page)
    params = [length, domain, FILE_FLAG, DIRECTORY_FLAG, literal, like]
    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM ({_CHILDREN_SQL})", params).fetchone()[0]  # noqa: S608
        rows = conn.execute(
            f"{_CHILDREN_SQL} ORDER BY is_folder DESC, name LIMIT ? OFFSET ?",  # noqa: S608
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()

    out = []
    for row in rows:
        is_folder = bool(row["is_folder"])
        full = f"{literal}{row['name']}"
        if not is_folder and full in META_FILES:
            continue
        size = None
        if not is_folder:
            size = _decoded_size(row["blob"])
            if size is None:
                size = _on_disk_size(snapshot_dir, row["file_id"])
        out.append(
            Child(
                name=row["name"],
                is_folder=is_folder,
                count=row["n"],
                file_id=None if is_folder else row["file_id"],
                size=size,
            )
        )
    return ChildPage(rows=out, total=total, page=page, page_size=page_size)


def selection_file_ids(
    snapshot_dir: Path,
    selections: list[tuple[str, str]],
    password: str | None = None,
    *,
    limit: int | None = None,
) -> list[str]:
    """Every file id a selection covers, in a stable order.

    A selection entry is a `(domain, path)` pair: an empty path means the whole domain, a path that
    names a folder means everything below it, and a path that names a file means that one file.
    This is what keeps "select all five thousand photos" a single stored value and a single form
    field instead of five thousand - the expansion happens here, against the index, at the moment
    the archive is built.
    """
    if not selections:
        return []
    where, params = [], []
    for domain, path in selections:
        cleaned = path.strip("/")
        if not cleaned:
            where.append("(domain = ?)")
            params.append(domain)
        else:
            # Either the file itself, or anything below it as a folder. A file and a folder can
            # share a name, and covering both is what the caller means by "this row".
            where.append("(domain = ? AND (relativePath = ? OR relativePath LIKE ? ESCAPE '\\'))")
            params.extend([domain, cleaned, _escape_like(cleaned) + "/%"])
    clause = " OR ".join(where)
    sql = f"SELECT fileID, relativePath FROM Files WHERE flags = ? AND ({clause}) ORDER BY domain, relativePath"  # noqa: S608
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    with closing(_manifest_connection(snapshot_dir, password)) as conn:
        rows = conn.execute(sql, [FILE_FLAG, *params]).fetchall()
    return [row["fileID"] for row in rows if row["relativePath"] not in META_FILES]
