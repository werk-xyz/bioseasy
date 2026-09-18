# SPDX-License-Identifier: GPL-3.0-or-later
"""The schema must survive two processes starting at once: the web service and the worker both
migrate on startup, and in a demo deployment they do so on a fresh database on every deploy.

Also covers forward migration from an old database that is migrated forward rather than
recreated, starting at schema 8 (tests/fixtures/schema_v8.sql): every SCHEMA_VERSION bump needs
a step in db.MIGRATIONS, and this module has to stay green."""

import re
import sqlite3
import threading
import traceback
from contextlib import closing
from pathlib import Path

import pytest

from bioseasy import db

FIXTURES = Path(__file__).parent / "fixtures"


def _schema(path):
    with closing(sqlite3.connect(path)) as conn:
        return sorted(conn.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("CREATE TABLE a (id INTEGER); CREATE TABLE b (id INTEGER);", 2),
        ("INSERT INTO t VALUES ('a;b'); SELECT 1;", 2),
        ("-- head\nCREATE TABLE c (id INTEGER);\n-- trailing comment only\n", 1),
    ],
)
def test_statement_split_handles_lines_strings_and_comments(sql, expected):
    parts = db._statements(sql)
    assert len(parts) == expected
    assert all(sqlite3.complete_statement(p) for p in parts)


def test_statement_split_builds_the_same_schema_as_executescript(tmp_path):
    via_split = tmp_path / "split.db"
    with closing(db.connect(via_split)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
    via_script = tmp_path / "script.db"
    with closing(sqlite3.connect(via_script, isolation_level=None)) as conn:
        conn.executescript(f"BEGIN; {db.SCHEMA}; PRAGMA user_version = {db.SCHEMA_VERSION}; COMMIT;")
    assert _schema(via_split) == _schema(via_script)


def test_migrate_is_idempotent(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_failed_schema_rolls_back_and_keeps_the_version(tmp_path, monkeypatch):
    path = tmp_path / "app.db"
    monkeypatch.setattr(db, "SCHEMA", db.SCHEMA + "\nSELECT * FROM missing_table;")
    with closing(db.connect(path)) as conn:
        with pytest.raises(sqlite3.OperationalError):
            db.migrate(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'devices'").fetchone() is None


def test_too_old_database_fails_startup_with_a_clear_message(tmp_path):
    """A database older than BASELINE_VERSION predates automatic migrations entirely (there is no
    fixture, no migration step, nothing to apply from) and must still fail loudly rather than
    silently applying a schema that does not match what is already there."""
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(f"PRAGMA user_version = {db.BASELINE_VERSION - 1}")
        conn.execute("COMMIT")
    with closing(db.connect(path)) as conn:
        with pytest.raises(SystemExit, match="no migration path|does not match"):
            db.migrate(conn)


def test_newer_database_fails_startup_as_a_refused_downgrade(tmp_path):
    """A user_version above SCHEMA_VERSION means the database was migrated by a newer release
    than the one currently running (a downgrade) - refused clearly instead of guessed at."""
    path = tmp_path / "app.db"
    with closing(db.connect(path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
        conn.execute("COMMIT")
    with closing(db.connect(path)) as conn:
        with pytest.raises(SystemExit, match="newer|downgrad"):
            db.migrate(conn)


@pytest.mark.parametrize("attempt", range(15))
def test_two_processes_open_and_migrate_a_fresh_database_at_once(tmp_path, attempt):
    """Both threads open the connection behind the same barrier, like two containers starting."""
    path = tmp_path / f"race-{attempt}.db"
    barrier = threading.Barrier(2)
    errors, results = [], []

    def start():
        try:
            barrier.wait(timeout=10)
            with closing(db.connect(path)) as conn:
                results.append(db.migrate(conn))
        except Exception:  # the full traceback, so a failure says where it happened
            errors.append(traceback.format_exc())

    threads = [threading.Thread(target=start, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=40)
    assert not any(t.is_alive() for t in threads), "a migrating thread hung"
    assert errors == []
    assert results == [db.SCHEMA_VERSION] * 2
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


@pytest.mark.parametrize("attempt", range(5))
def test_two_processes_migrate_an_old_database_at_once(tmp_path, attempt):
    """The same two-processes-at-once guarantee, but starting from the v8 baseline instead of a
    fresh database, so the forward-migration path (backup copy, multi-step apply) is exercised
    under the same race as the fresh-database case above."""
    path = tmp_path / f"race-old-{attempt}.db"
    _load_v8_fixture(path)
    barrier = threading.Barrier(2)
    errors, results = [], []

    def start():
        try:
            barrier.wait(timeout=10)
            with closing(db.connect(path)) as conn:
                results.append(db.migrate(conn))
        except Exception:
            errors.append(traceback.format_exc())

    threads = [threading.Thread(target=start, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=40)
    assert not any(t.is_alive() for t in threads), "a migrating thread hung"
    assert errors == []
    assert results == [db.SCHEMA_VERSION] * 2
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_every_version_above_baseline_has_a_migration_step():
    """Guards against a bumped SCHEMA_VERSION with no matching entry in MIGRATIONS: without this,
    migrate() would raise a bare KeyError deep inside a transaction instead of a clear failure,
    and a deployed database would never reach the new schema."""
    expected = set(range(db.BASELINE_VERSION + 1, db.SCHEMA_VERSION + 1))
    assert set(db.MIGRATIONS.keys()) == expected


# --- Forward migration from the v8 baseline (automatic database migrations from schema 8 on) ---


def _load_v8_fixture(path: Path) -> None:
    fixture_sql = (FIXTURES / "schema_v8.sql").read_text()
    with closing(sqlite3.connect(path, isolation_level=None)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(fixture_sql)
        conn.execute("PRAGMA user_version = 8")


def _seed_v8_rows(conn: sqlite3.Connection) -> None:
    """One representative row (at least) in every v8 table, covering an admin and a member user,
    a device with per-device overrides, two runs (one finished, one still running), an API token,
    a notification connector, activities and a netcheck run - the shapes a real database
    actually holds."""
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, session_version, created_at) VALUES "
        "(1, 'admin', 'hash-admin', 'admin', 1, '2026-01-01T00:00:00Z'), "
        "(2, 'member', 'hash-member', 'member', 1, '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO devices (udid, name, product_type, os_version, owner_id, owner_label, host, "
        "interval_hours, keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly, "
        "window_start, window_end, only_when_charging, overdue_days, last_nudge_at, "
        "last_window_notice_at, name_custom, password_checked_at, password_check_result, "
        "wifi_enabled_at, encryption_enabled_at, paired_at, pair_used_at, created_at) VALUES "
        "('AAAA1111', 'Test iPad', 'iPad13,1', '17.5', 2, 'Members iPad', '192.168.1.50', "
        "12, 5, 7, 4, 6, 2, '20:00', '23:00', 1, 3, '2026-09-01T00:00:00Z', "
        "'2026-09-01T00:00:00Z', 1, '2026-09-01T00:00:00Z', 'correct', '2026-09-01T00:00:00Z', "
        "'2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', "
        "'2026-09-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO runs (id, udid, trigger, started_at, finished_at, status, message, phase, "
        "percent, progress_message, worker_id, heartbeat_at) VALUES "
        "(1, 'AAAA1111', 'schedule', '2026-09-10T20:00:00Z', '2026-09-10T20:20:00Z', "
        "'succeeded', NULL, NULL, 100.0, NULL, NULL, NULL), "
        "(2, 'AAAA1111', 'manual', '2026-09-14T10:00:00Z', NULL, 'running', NULL, "
        "'transferring', 42.0, 'copying files', 'huey-worker', '2026-09-15T10:00:00Z')"
    )
    conn.execute("INSERT INTO sightings (udid, seen_at, transport) VALUES ('AAAA1111', '2026-09-14T09:59:00Z', 'wifi')")
    conn.execute("INSERT INTO ticks (tick_at) VALUES ('2026-09-15T10:00:00Z')")
    conn.execute("INSERT INTO settings (key, value) VALUES ('schedule_window_start', '20:00')")
    conn.execute(
        "INSERT INTO oidc_links (user_id, issuer, subject, created_at) VALUES "
        "(2, 'https://idp.example', 'sub-123', '2026-09-01T00:00:00Z')"
    )
    conn.execute("INSERT INTO workers (id, heartbeat_at) VALUES ('huey-worker', '2026-09-15T10:00:00Z')")
    conn.execute(
        "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
        "VALUES ('AAAA1111', 'Test iPad', 'iPad13,1', '17.5', 'wifi', 1, '2026-09-15T09:59:00Z')"
    )
    conn.execute(
        "INSERT INTO pairings (udid, state, message, updated_at) VALUES "
        "('AAAA1111', 'done', NULL, '2026-09-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO setup_actions (udid, step, state, message, updated_at) VALUES "
        "('AAAA1111', 'wifi', 'done', NULL, '2026-09-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO api_tokens (id, user_id, name, prefix, secret_hash, created_at, last_used_at, revoked_at) "
        "VALUES (1, 2, 'Shortcuts token', 'bsy_ab12', 'hash-of-secret', '2026-09-01T00:00:00Z', "
        "'2026-09-10T00:00:00Z', NULL)"
    )
    conn.execute(
        "INSERT INTO notification_connectors (id, scope, udid, kind, label, settings_json, "
        "secret_ciphertext, enabled, created_at, updated_at) VALUES "
        "(1, 'device', 'AAAA1111', 'email', 'My email', '{\"host\":\"smtp.example\"}', NULL, 1, "
        "'2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO pairing_codes (id, code_hash, created_by, created_at, expires_at, used_at, consumed_udid) "
        "VALUES (1, 'codehash1', 1, '2026-09-01T00:00:00Z', '2026-09-01T00:10:00Z', "
        "'2026-09-01T00:05:00Z', 'AAAA1111')"
    )
    conn.execute(
        "INSERT INTO netcheck_runs (udid, state, steps_json, started_at, updated_at) VALUES "
        '(\'AAAA1111\', \'done\', \'[{"name":"dns","ok":true,"detail":""}]\', '
        "'2026-09-14T00:00:00Z', '2026-09-14T00:01:00Z')"
    )
    conn.execute(
        "INSERT INTO dir_sizes (path, bytes, files, computed_at, state) VALUES "
        "('', 123456, 42, '2026-09-14T00:00:00Z', 'done')"
    )
    conn.execute(
        "INSERT INTO activities (id, kind, udid, phase, started_at, heartbeat_at) VALUES "
        "('act-1', 'backup', 'AAAA1111', 'transferring', '2026-09-14T10:00:00Z', '2026-09-15T10:00:00Z')"
    )


# Every v8 table, so the row-survival check below iterates all of them rather than a sample.
V8_TABLES = [
    "users",
    "devices",
    "runs",
    "sightings",
    "ticks",
    "settings",
    "oidc_links",
    "workers",
    "seen_devices",
    "pairings",
    "setup_actions",
    "api_tokens",
    "notification_connectors",
    "pairing_codes",
    "netcheck_runs",
    "dir_sizes",
    "activities",
]


def _rows_by_columns(conn: sqlite3.Connection, table: str, columns: list[str]) -> list[tuple]:
    cols = ", ".join(columns)
    return sorted(
        tuple(row)
        for row in conn.execute(f"SELECT {cols} FROM {table} ORDER BY rowid")  # noqa: S608 - fixed test constants, not user input
    )


def _user_table_names(conn: sqlite3.Connection) -> list[str]:
    return sorted(
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    )


def _table_info(conn: sqlite3.Connection, table: str) -> frozenset[tuple]:
    """(name, type, notnull, default, pk) per column, unordered: ALTER TABLE ADD COLUMN (used for
    api_tokens.scope, MIGRATIONS[9]) always appends at the end of the stored column list, while a
    fresh database built from SCHEMA has it in the position written there - a real difference in
    column order that a rebuild could avoid but does not matter here, since every row in this
    codebase is read through sqlite3.Row (db.connect sets row_factory), never by position."""
    return frozenset((r[1], r[2], r[3], r[4], r[5]) for r in conn.execute(f"PRAGMA table_info({table})"))


def _foreign_key_list(conn: sqlite3.Connection, table: str) -> list[tuple]:
    return sorted((r[2], r[3], r[4], r[5], r[6], r[7]) for r in conn.execute(f"PRAGMA foreign_key_list({table})"))


def _index_signature(conn: sqlite3.Connection, table: str) -> dict[str, tuple]:
    """{index name: (unique, column tuple, normalized partial-WHERE clause or None)}; excludes
    sqlite's own implicit autoindexes (unnamed, backing UNIQUE/PK constraints), which are covered
    by table_info's pk flags and the UNIQUE columns themselves instead."""
    signature = {}
    for row in conn.execute(f"PRAGMA index_list({table})"):
        _seq, name, unique, origin, _partial = row
        if origin == "pk" and name.startswith("sqlite_autoindex_"):
            continue
        columns = tuple(r[2] for r in conn.execute(f"PRAGMA index_info({name})"))
        create_sql = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", (name,)).fetchone()
        where_clause = None
        if create_sql and create_sql[0]:
            match = re.search(r"\bWHERE\b(.*)$", create_sql[0], re.IGNORECASE | re.DOTALL)
            if match:
                where_clause = " ".join(match.group(1).split())
        signature[name] = (bool(unique), columns, where_clause)
    return signature


def _check_clauses(conn: sqlite3.Connection, table: str) -> list[str]:
    """Every CHECK (...) clause in the table's stored CREATE TABLE SQL, whitespace-normalized -
    the only way to see CHECK constraints at all, since no PRAGMA exposes them. Scans for
    balanced parentheses instead of a non-greedy regex, since a CHECK can itself contain
    parenthesized value lists (e.g. CHECK (x IN ('a', 'b')))."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    text = "\n".join(line for line in row[0].splitlines() if not line.strip().startswith("--"))
    clauses = []
    pos = 0
    while True:
        idx = text.find("CHECK", pos)
        if idx == -1:
            break
        start = text.find("(", idx)
        depth, j = 0, start
        while j < len(text):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        clauses.append(" ".join(text[start : j + 1].split()))
        pos = j + 1
    return sorted(clauses)


def _schema_signature(conn: sqlite3.Connection) -> dict[str, dict]:
    return {
        table: {
            "table_info": _table_info(conn, table),
            "foreign_keys": _foreign_key_list(conn, table),
            "indexes": _index_signature(conn, table),
            "checks": _check_clauses(conn, table),
        }
        for table in _user_table_names(conn)
    }


def test_a_finished_migration_says_so_in_the_log(tmp_path, caplog):
    """A finished migration could not be told from one that died halfway: the log
    announced the start and never the end. The completion line names the version reached."""
    path = tmp_path / "bioseasy.db"
    _load_v8_fixture(path)
    with caplog.at_level("INFO", logger="bioseasy"), closing(db.connect(path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
    assert f"database schema migrated to version {db.SCHEMA_VERSION}" in caplog.text


def test_migrating_the_v8_baseline_preserves_rows_and_reaches_the_current_schema(tmp_path):
    """The guard against a broken migration: build a database from the frozen v8 fixture (a
    real baseline), seed every table with a representative row, migrate it,
    and check what actually matters - no data lost, and the result is exactly what
    a fresh install would get."""
    old_path = tmp_path / "old.db"
    _load_v8_fixture(old_path)
    with closing(sqlite3.connect(old_path, isolation_level=None)) as seed_conn:
        seed_conn.execute("PRAGMA foreign_keys = ON")
        _seed_v8_rows(seed_conn)
        before = {table: _rows_by_columns(seed_conn, table, _columns(seed_conn, table)) for table in V8_TABLES}

    with closing(db.connect(old_path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION

        # (b) every row survived with its values. api_tokens gained a `scope` column (default
        # 'read') and activities gained outcome/detail/finished_at (all NULL for a pre-existing
        # row): both compared separately below, on top of their original columns unchanged.
        new_columns = {
            "api_tokens": {"scope"},
            "activities": {"outcome", "detail", "finished_at", "snapshot_name"},
            "users": {"last_sign_in_at", "last_push_ok", "last_push_error", "last_push_at", "email"},
            "devices": {"last_overdue_alert_at", "last_alert_ok", "last_alert_error", "last_alert_at"},
        }
        for table in V8_TABLES:
            after_columns = [c for c in _columns(conn, table) if c not in new_columns.get(table, set())]
            after = _rows_by_columns(conn, table, after_columns)
            assert after == before[table], f"row mismatch in {table}"
        scopes = [r[0] for r in conn.execute("SELECT scope FROM api_tokens ORDER BY id")]
        assert scopes == ["read"], "existing api token must default to the original read-only scope"
        outcomes = [tuple(r) for r in conn.execute("SELECT outcome, detail, finished_at FROM activities ORDER BY id")]
        assert outcomes == [(None, None, None)], "a pre-existing activity row must read as still-running, not finished"

        # (c) the resulting schema equals a fresh database built straight from SCHEMA.
        fresh_path = tmp_path / "fresh.db"
        with closing(db.connect(fresh_path)) as fresh_conn:
            assert db.migrate(fresh_conn) == db.SCHEMA_VERSION
            assert _schema_signature(conn) == _schema_signature(fresh_conn)


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def test_schema_signature_catches_a_broken_migration_step(tmp_path, monkeypatch):
    """The guard above is only worth having if it actually goes red on a broken migration -
    checked here once on purpose by dropping a column a step is supposed to add, then reverting
    via monkeypatch's own teardown."""

    def _broken_8_to_9(conn: sqlite3.Connection) -> None:
        # Same as the real step, minus the scope column: api_tokens keeps its v8 shape.
        conn.execute(
            """
            CREATE TABLE runs__migrate_9 (
                id INTEGER PRIMARY KEY,
                udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
                trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'device', 'api')),
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'not_confirmed', 'cancelled')),
                message TEXT,
                phase TEXT,
                percent REAL,
                progress_message TEXT,
                worker_id TEXT,
                heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO runs__migrate_9 (id, udid, trigger, started_at, finished_at, status, "
            "message, phase, percent, progress_message, worker_id, heartbeat_at) "
            "SELECT id, udid, trigger, started_at, finished_at, status, message, phase, percent, "
            "progress_message, worker_id, heartbeat_at FROM runs"
        )
        conn.execute("DROP TABLE runs")
        conn.execute("ALTER TABLE runs__migrate_9 RENAME TO runs")
        conn.execute("CREATE INDEX runs_by_device ON runs (udid, started_at DESC)")
        conn.execute("CREATE UNIQUE INDEX runs_one_running ON runs(udid) WHERE status = 'running'")

    monkeypatch.setitem(db.MIGRATIONS, 9, _broken_8_to_9)
    old_path = tmp_path / "old.db"
    _load_v8_fixture(old_path)
    with closing(sqlite3.connect(old_path, isolation_level=None)) as seed_conn:
        seed_conn.execute("PRAGMA foreign_keys = ON")
        _seed_v8_rows(seed_conn)

    with closing(db.connect(old_path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        fresh_path = tmp_path / "fresh.db"
        with closing(db.connect(fresh_path)) as fresh_conn:
            assert db.migrate(fresh_conn) == db.SCHEMA_VERSION
            assert _schema_signature(conn) != _schema_signature(fresh_conn), (
                "the schema-equivalence guard did not notice a migration step that skips a column"
            )


# --- SCHEMA_VERSION 20: one account per email address ------------------------------------------


def _as_v19(path: Path, emails: list[str | None]) -> None:
    """A database in the state SCHEMA_VERSION 19 left it in: users.email exists, nothing stops two
    accounts from sharing an address, and there is no unique index yet."""
    with closing(db.connect(path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        conn.execute("DROP INDEX users_email_unique")
        for n, email in enumerate(emails):
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email) VALUES (?, 'x', 'member', ?)",
                (f"user{n}", email),
            )
        conn.execute("PRAGMA user_version = 19")
        conn.commit()


def _has_email_index(path: Path) -> bool:
    with closing(sqlite3.connect(path)) as conn:
        return (
            conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'users_email_unique'").fetchone()
            is not None
        )


def test_migrating_to_20_adds_the_unique_index_and_keeps_addressless_accounts(tmp_path):
    """The point of the step: the rule "one account per address" is enforced from now on, while
    the rows that predate any address requirement keep their NULL - no address exists for them and
    none may be invented, which is exactly why users.email is not NOT NULL."""
    path = tmp_path / "v19.db"
    _as_v19(path, [None, None, "alice@example.test"])

    with closing(db.connect(path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert [r[0] for r in conn.execute("SELECT email FROM users ORDER BY username")] == [
            None,
            None,
            "alice@example.test",
        ]
        # Two rows without an address stay allowed; a second row with the same address does not.
        conn.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('x', 'x', 'member', NULL)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email) "
                "VALUES ('y', 'x', 'member', 'ALICE@example.test')"
            )
    assert _has_email_index(path)


def test_a_database_that_already_shares_an_address_still_migrates_and_says_so(tmp_path, caplog):
    """A database that already holds the duplicate cannot get the index, and refusing to start
    over it would be far worse than living without it: it migrates, the log names the count, and
    the ambiguity is caught at sign-in instead (oidc.find_user_by_email, tests/test_auth.py)."""
    path = tmp_path / "dupes.db"
    _as_v19(path, ["shared@example.test", "SHARED@example.test", "alice@example.test"])

    with caplog.at_level("WARNING", logger="bioseasy"), closing(db.connect(path)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3  # nothing dropped, nothing rewritten

    assert "shared by more than one account" in caplog.text
    assert not _has_email_index(path)
