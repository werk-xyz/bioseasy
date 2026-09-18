# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded log storage for the admin `/logs` page.

A `logging.Handler` installed in both processes (web: `app.create_app`; worker:
`bioseasy.__init__._worker`) writes WARNING and above, plus the one INFO line jobs.py logs when a
backup finishes ("backup of ... ended succeeded"), into the `log_entries` table (db.py's SCHEMA).
Everything the handler stores passes through `redact` first - the same rule as the container log
(backup passwords and pair records are never stored in the queue, logged or rendered back; logs
carry a shortened UDID at most), applied again here as defence in depth, not because
any known call site logs a secret.

A DB failure inside the handler must never raise into the application, and must never recurse
back into logging (the default `Handler.handleError` calls `logging.error`, which re-enters a
handler attached to the root or an ancestor logger) - `emit` below catches everything itself and
writes nothing on failure, silently.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import traceback
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass

# Bounds: last MAX_ROWS rows, at most MAX_AGE_DAYS old, whichever is smaller. Pruned on every
# write rather than on a schedule - the expected volume (WARNING and above, plus one INFO line
# per finished backup) is low enough that this stays cheap; both DELETEs use the ts index or a
# small LIMIT scan, never a full table scan.
MAX_ROWS = 2000
MAX_AGE_DAYS = 14

PROCESSES = ("web", "worker")
LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")

# UDID shapes: the old 40-hex format and the current 8-4/16-hex format (pairing.py's
# UDID_PATTERN documents both), matched loosely here since this runs against free-text log
# messages, not a validated field - a run bordered by non-hex characters on both sides.
_FULL_UDID_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{16}(?![0-9A-Fa-f])"
    r"|(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])"
)
# A bare 8-hex-character token, the shortened form the rest of the codebase already logs
# (`udid[:8]`, see jobs.py/runtime.py/app.py). Matched only where the full pattern above did not
# already match and replace, so a full UDID is never double-counted as its own shortened prefix.
_SHORT_UDID_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?![0-9A-Fa-f])")

_SECRET_FIELD_RE = re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*\S+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")

# The exact format string jobs.py logs on a successful backup (jobs.py's `_run`); matched against
# the record's raw `msg`, before `%`-substitution, so this does not depend on the udid or the
# other formatted values. INFO records that are not this one are dropped by the handler: the log
# page wants this one INFO line, not every INFO record either process happens to emit.
_BACKUP_SUCCEEDED_MSG = "backup of %s ended succeeded"


def redact(text: str | None) -> str | None:
    """Shorten any UDID-shaped run to its first 8 characters, and drop anything that looks like
    a secret field (`password=`, `token: ...`, `Bearer <token>`). Defence in depth: every call
    site already avoids logging secrets or full UDIDs; this is a second, independent guard
    against a message that slips through anyway."""
    if not text:
        return text
    text = _FULL_UDID_RE.sub(lambda m: m.group(0)[:8], text)
    text = _SECRET_FIELD_RE.sub(lambda m: f"{m.group(1)}=[redacted]", text)
    text = _BEARER_RE.sub("Bearer [redacted]", text)
    return text


def _extract_udid(original_text: str) -> str | None:
    """Best-effort shortened UDID for the `udid` filter column, read from the message before
    redaction. Not authoritative - a message that happens to carry an unrelated 8-hex-character
    token is stored as if it were a UDID - so this is only ever used for filtering the log view,
    never for anything security-relevant."""
    match = _FULL_UDID_RE.search(original_text) or _SHORT_UDID_RE.search(original_text)
    return match.group(0)[:8] if match else None


class DBLogHandler(logging.Handler):
    """Stores WARNING+ records (and the one allow-listed INFO line) into `log_entries`.

    `connect` is called once per record, the same short-lived-connection pattern every other
    module in this codebase uses (see db.connect / runtime.Runtime.connect) - a handler held open
    across a long-lived process should not itself hold a connection open across it.
    """

    def __init__(self, connect: Callable[[], sqlite3.Connection], process: str) -> None:
        super().__init__(level=logging.INFO)
        if process not in PROCESSES:
            raise ValueError(f"process must be one of {PROCESSES}, got {process!r}")
        self._connect = connect
        self._process = process

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < logging.WARNING and not (
                isinstance(record.msg, str) and record.msg.startswith(_BACKUP_SUCCEEDED_MSG)
            ):
                return
            raw_message = record.getMessage()
            udid = _extract_udid(raw_message)
            message = redact(raw_message)
            tb = None
            if record.exc_info:
                tb = redact("".join(traceback.format_exception(*record.exc_info)))
            with closing(self._connect()) as conn:
                conn.execute(
                    "INSERT INTO log_entries (ts, process, logger, level, message, udid, traceback) "
                    "VALUES (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?, ?, ?, ?, ?, ?)",
                    (self._process, record.name, record.levelname, message, udid, tb),
                )
                _prune(conn)
        except Exception:  # noqa: BLE001, S110 - a handler must never raise into the application
            # Not self.handleError(record): its default implementation writes to stderr through
            # `traceback.print_exc` and, in older stdlib versions, can end up calling back into
            # logging - safest is to swallow it completely here. A DB that is genuinely broken
            # shows up in the container's own stderr from whatever else touches it, not from
            # this handler going silent, and nothing here may call `log.*` without risking the
            # same recursion this whole guard exists to avoid.
            return


def install(connect: Callable[[], sqlite3.Connection], process: str, logger_name: str = "bioseasy") -> DBLogHandler:
    """Attach a `DBLogHandler` to `logger_name`, replacing any handler this function previously
    installed on it. Idempotent so that calling it again - `create_app()` runs once per test, not
    once per process - never accumulates handlers bound to a stale, already-closed `connect`."""
    logger = logging.getLogger(logger_name)
    for existing in list(logger.handlers):
        if isinstance(existing, DBLogHandler):
            logger.removeHandler(existing)
    handler = DBLogHandler(connect, process)
    logger.addHandler(handler)
    return handler


def _prune(conn: sqlite3.Connection) -> None:
    conn.execute(
        "DELETE FROM log_entries WHERE ts < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
        (f"-{MAX_AGE_DAYS} days",),
    )
    conn.execute(
        "DELETE FROM log_entries WHERE id NOT IN (SELECT id FROM log_entries ORDER BY ts DESC, id DESC LIMIT ?)",
        (MAX_ROWS,),
    )


@dataclass(frozen=True)
class LogPage:
    rows: list[sqlite3.Row]
    total: int
    page: int
    page_size: int

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total


def list_entries(
    conn: sqlite3.Connection,
    *,
    level: str | None = None,
    process: str | None = None,
    udid: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> LogPage:
    """Newest-first, optionally filtered by level, process and (shortened) device UDID."""
    where, params = [], []
    if level:
        where.append("level = ?")
        params.append(level)
    if process:
        where.append("process = ?")
        params.append(process)
    if udid:
        where.append("udid = ?")
        params.append(udid)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM log_entries {clause}", params).fetchone()[0]  # noqa: S608
    page = max(1, page)
    rows = conn.execute(
        f"SELECT * FROM log_entries {clause} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",  # noqa: S608
        [*params, page_size, (page - 1) * page_size],
    ).fetchall()
    return LogPage(rows=rows, total=total, page=page, page_size=page_size)
