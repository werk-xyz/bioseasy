# SPDX-License-Identifier: GPL-3.0-or-later
"""logview.py: redaction, the bounded log_entries store, and the handler's own failure mode."""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass

import pytest

from bioseasy import db, logview


@dataclass
class Env:
    path: object
    conn: sqlite3.Connection  # a long-lived connection, for the test's own reads/writes

    def connect(self) -> sqlite3.Connection:
        # A fresh connection per call, the same as every real caller (db.connect, rt.connect):
        # the handler always closes what `connect()` gives it (logview.DBLogHandler.emit's
        # `closing(self._connect())`), so reusing one connection object here would close it out
        # from under the test after the first log call.
        return db.connect(self.path)


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "bioseasy.db"
    with closing(db.connect(path)) as c:
        db.migrate(c)
        yield Env(path=path, conn=c)


def rows(env):
    return env.conn.execute("SELECT * FROM log_entries ORDER BY id").fetchall()


# --- redact() -----------------------------------------------------------------------------


def test_redact_shortens_new_style_udid():
    text = "pairing of 00008103-001122334455667A failed: timeout"
    assert logview.redact(text) == "pairing of 00008103 failed: timeout"


def test_redact_shortens_old_style_forty_hex_udid():
    udid40 = "a" * 40
    assert logview.redact(f"device {udid40} disconnected") == "device aaaaaaaa disconnected"


def test_redact_drops_password_field():
    assert logview.redact("backup failed: password=hunter2 wrong") == "backup failed: password=[redacted] wrong"


def test_redact_drops_token_and_secret_and_api_key_fields():
    assert "abc123" not in logview.redact("token=abc123")
    assert "abc123" not in logview.redact("secret: abc123")
    assert "abc123" not in logview.redact("api_key=abc123")


def test_redact_drops_bearer_token():
    text = logview.redact("request failed with Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert "eyJhbGciOiJIUzI1NiJ9" not in text
    assert "Bearer [redacted]" in text


def test_redact_leaves_ordinary_text_alone():
    assert logview.redact("storage check failed: disk full") == "storage check failed: disk full"


def test_redact_handles_none_and_empty():
    assert logview.redact(None) is None
    assert logview.redact("") == ""


# --- DBLogHandler ---------------------------------------------------------------------------


def _logger(name="bioseasy.test_logview"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    return logger


def test_handler_stores_warning_with_shortened_udid(env):
    logger = _logger()
    handler = logview.DBLogHandler(env.connect, "worker")
    logger.addHandler(handler)
    try:
        logger.warning("pairing of %s failed: timed out", "00008103-001122334455667A")
    finally:
        logger.removeHandler(handler)
    stored = rows(env)
    assert len(stored) == 1
    assert stored[0]["level"] == "WARNING"
    assert stored[0]["process"] == "worker"
    assert stored[0]["udid"] == "00008103"
    assert "001122334455667A" not in stored[0]["message"]
    assert stored[0]["message"] == "pairing of 00008103 failed: timed out"


def test_handler_ignores_ordinary_info_lines(env):
    logger = _logger()
    handler = logview.DBLogHandler(env.connect, "web")
    logger.addHandler(handler)
    try:
        logger.info("server started")
    finally:
        logger.removeHandler(handler)
    assert rows(env) == []


def test_handler_stores_the_backup_succeeded_info_line(env):
    logger = _logger()
    handler = logview.DBLogHandler(env.connect, "worker")
    logger.addHandler(handler)
    try:
        logger.info("backup of %s ended succeeded: encrypted=%s, %s iOS %s", "00008103", True, "iPhone14,5", "17.4")
    finally:
        logger.removeHandler(handler)
    stored = rows(env)
    assert len(stored) == 1
    assert stored[0]["level"] == "INFO"
    assert "ended succeeded" in stored[0]["message"]


def test_handler_records_traceback(env):
    logger = _logger()
    handler = logview.DBLogHandler(env.connect, "worker")
    logger.addHandler(handler)
    try:
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("something broke")
    finally:
        logger.removeHandler(handler)
    stored = rows(env)
    assert len(stored) == 1
    assert "ValueError: boom" in stored[0]["traceback"]


def test_handler_swallows_a_db_error(env, caplog):
    def broken_connect():
        raise sqlite3.OperationalError("disk I/O error")

    logger = _logger()
    handler = logview.DBLogHandler(broken_connect, "worker")
    logger.addHandler(handler)
    try:
        with caplog.at_level(logging.WARNING):
            logger.warning("this must not raise even though storage is broken")
    finally:
        logger.removeHandler(handler)
    # No exception escaped emit() (pytest would otherwise fail the test on an unhandled error in
    # a logging call), and nothing was stored, and the handler did not log about its own failure
    # (that would recurse back into the very handler that just failed).
    assert rows(env) == []
    assert not any(
        r.name == "bioseasy.test_logview" and "storage is broken" not in r.getMessage() for r in caplog.records
    )


def test_install_is_idempotent(env):
    logger_name = "bioseasy.test_logview_install"
    logview.install(env.connect, "web", logger_name=logger_name)
    logview.install(env.connect, "web", logger_name=logger_name)
    logger = logging.getLogger(logger_name)
    handlers = [h for h in logger.handlers if isinstance(h, logview.DBLogHandler)]
    assert len(handlers) == 1
    logger.handlers.clear()


def test_handler_rejects_unknown_process(env):
    with pytest.raises(ValueError):
        logview.DBLogHandler(env.connect, "gremlin")


# --- pruning ----------------------------------------------------------------------------


def test_prune_keeps_at_most_max_rows(env, monkeypatch):
    monkeypatch.setattr(logview, "MAX_ROWS", 5)
    logger = _logger()
    handler = logview.DBLogHandler(env.connect, "worker")
    logger.addHandler(handler)
    try:
        for i in range(12):
            logger.warning("warning number %d", i)
    finally:
        logger.removeHandler(handler)
    stored = rows(env)
    assert len(stored) == 5
    # Newest survive: the highest-numbered warnings, not the earliest ones.
    assert {r["message"] for r in stored} == {f"warning number {i}" for i in range(7, 12)}


def test_prune_drops_rows_older_than_max_age(env):
    env.conn.execute(
        "INSERT INTO log_entries (ts, process, logger, level, message) VALUES "
        "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days'), 'worker', 'x', 'WARNING', 'old')"
    )
    logview._prune(env.conn)
    assert rows(env) == []


# --- list_entries() ---------------------------------------------------------------------


def test_list_entries_filters_and_pages(env):
    for i in range(3):
        env.conn.execute(
            "INSERT INTO log_entries (ts, process, logger, level, message, udid) VALUES "
            "(strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ? || ' seconds'), ?, 'x', ?, ?, ?)",
            (i, "worker" if i % 2 == 0 else "web", "ERROR" if i == 0 else "WARNING", f"m{i}", "00008103"),
        )
    all_rows = logview.list_entries(env.conn, page_size=10)
    assert all_rows.total == 3
    only_worker = logview.list_entries(env.conn, process="worker", page_size=10)
    assert only_worker.total == 2
    only_errors = logview.list_entries(env.conn, level="ERROR", page_size=10)
    assert only_errors.total == 1
    by_device = logview.list_entries(env.conn, udid="00008103", page_size=10)
    assert by_device.total == 3
    page1 = logview.list_entries(env.conn, page=1, page_size=2)
    assert len(page1.rows) == 2
    assert page1.has_more is True
    page2 = logview.list_entries(env.conn, page=2, page_size=2)
    assert len(page2.rows) == 1
    assert page2.has_more is False
