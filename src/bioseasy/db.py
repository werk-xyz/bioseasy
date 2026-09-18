# SPDX-License-Identifier: GPL-3.0-or-later
"""SQLite app state: one schema, applied once or migrated forward, tracked in PRAGMA user_version.

Automatic migrations from schema 8 on, reversing the earlier "no migrations and no legacy
compatibility before 1.0" stance: an existing deployment can hold real data at schema 8
and must upgrade in place rather than start over. SCHEMA is still the full schema a
fresh database gets in one pass; MIGRATIONS
holds one forward-only step per version above BASELINE_VERSION, applied in order by migrate().
A database older than BASELINE_VERSION has no migration path and is still rejected with a
message telling the operator to recreate the data volume.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

log = logging.getLogger("bioseasy")

SCHEMA_VERSION = 20

# The oldest user_version migrate() knows how to bring forward, taken from a live database
# (tests/fixtures/schema_v8.sql). A database older
# than this predates automatic migrations entirely and is still refused, the same message as
# before this feature existed.
BASELINE_VERSION = 8

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    session_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Set on every successful sign-in (password or OIDC; auth.record_sign_in), never on session
    -- resumption from the cookie - so the admin-only Users page (SCHEMA_VERSION 13) shows when an
    -- account was last actually used, not merely browsed with. NULL for a user who has never
    -- signed in since this column existed.
    last_sign_in_at TEXT,
    -- Outcome of the most recent browser push delivery attempt to this user (webpush.py's
    -- send_to_users), recorded the same honest way as devices.last_alert_ok for the Apprise
    -- path -- a timestamp that means "the user was told" is only written when the telling
    -- actually happened -- but kept as its own state here, not folded into that
    -- column, because push is scoped to the user, not to a device: a subscription lives on the
    -- Settings page (webpush.py's module docstring) and is not tied to any one device the user
    -- may or may not own. Separate state also lets the Settings page name the channel that is
    -- actually broken instead of a device page pointing an owner at "check the connectors" for
    -- a push failure connectors.py has nothing to do with. NULL until a push has been attempted
    -- for this user, or whenever the user currently has no subscriptions at all -- "nothing to
    -- deliver to" is never recorded as a failure (SCHEMA_VERSION 18).
    last_push_ok INTEGER CHECK (last_push_ok IN (0, 1)),
    -- Always this module's own fixed, secret-free text when last_push_ok = 0, never a push
    -- service's response body verbatim (webpush.py's _PUSH_FAILURE_MESSAGE). NULL otherwise.
    last_push_error TEXT,
    -- When last_push_ok/last_push_error were last written.
    last_push_at TEXT,
    -- Contact address for this account (SCHEMA_VERSION 19) and, since SCHEMA_VERSION 20, the
    -- claim an OIDC sign-in is matched against. Required for
    -- every account created through the setup wizard, the admin Users page or single sign-on
    -- self-registration (auth.register_user / auth.create_sso_user), but still declared NULL-able
    -- on purpose: accounts created before this column existed have no address, none can be
    -- invented for them, and a NOT NULL column would make the migration of any existing
    -- database impossible.
    -- The admin Users page lists those accounts and asks for the missing address; until one is
    -- set, such an account simply cannot be reached by an SSO sign-in.
    email TEXT
);
-- One account per address, so the email-to-account match of an SSO sign-in can never be
-- ambiguous. Case-insensitive, because providers do not agree on the case of the local part, and
-- partial, because the rows without an address (above) must stay allowed and there may be many.
CREATE UNIQUE INDEX users_email_unique ON users (email COLLATE NOCASE) WHERE email IS NOT NULL;
CREATE TABLE devices (
    udid TEXT PRIMARY KEY,
    name TEXT,
    product_type TEXT,
    os_version TEXT,
    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    owner_label TEXT,
    -- Optional fixed address: bypasses mDNS where the device sits in another VLAN.
    host TEXT,
    -- Every column in this block is a per-device override of a global default the admin sets on
    -- the Settings page (src/bioseasy/defaults.py DEFAULT_*, stored in the settings table); NULL
    -- means "use the global default" for that field. defaults.resolve_device is the one function
    -- that layers a device row onto the global defaults - scheduler.py, status.py and jobs.py
    -- (retention) all call it, never re-implementing the NULL-means-inherit rule themselves.
    interval_hours INTEGER,
    -- Retention overrides, resolved by snapshots.resolve_policy through defaults.resolve_device.
    keep_last INTEGER,
    keep_daily INTEGER,
    keep_weekly INTEGER,
    keep_monthly INTEGER,
    keep_yearly INTEGER,
    -- Local time window for scheduled starts, 'HH:MM'. Both NULL means "use the global default
    -- window"; the web UI only ever writes both together (see app.py's validate_device_settings).
    window_start TEXT,
    window_end TEXT,
    only_when_charging INTEGER,
    overdue_days INTEGER,
    -- When the last due (nudge) reminder went out, so each interval nudges at most once.
    last_nudge_at TEXT,
    -- When the last overdue alert went out, measured against its own _OVERDUE_ALERT_COOLDOWN
    -- (scheduler.py) - kept separate from last_nudge_at (SCHEMA_VERSION 15) because the two
    -- cooldowns run on different clocks (interval_hours vs. a fixed 24h): sharing one column let
    -- a nudge sent every few hours keep resetting it and silently starve the overdue alert
    -- forever. NULL until the first overdue alert for this device.
    last_overdue_alert_at TEXT,
    -- Identifies the scheduling-window occurrence (its own start instant, not "when this was
    -- written") for which the pre-attempt notice has already gone out, so scheduler.decide can
    -- compare by identity instead of staleness and never send a second notice for the same
    -- window; see scheduler.py's window-occurrence helpers.
    last_window_notice_at TEXT,
    -- Outcome of the most recent alert send attempt (nudge, overdue or upcoming-window notice)
    -- for this device, recorded from notify.send()'s actual result rather than assumed at the
    -- moment the send was handed off -- a timestamp that means "the user was told" is only
    -- written when the telling actually happened (SCHEMA_VERSION 17). NULL means
    -- no alert has been attempted yet. last_nudge_at/last_overdue_alert_at/last_window_notice_at
    -- above stay attempt timestamps only - they gate the retry cooldown in scheduler.py and are
    -- written unconditionally, the same as before this column existed; they never claimed
    -- delivery succeeded and still do not.
    last_alert_ok INTEGER CHECK (last_alert_ok IN (0, 1)),
    -- Short, secret-free reason from notify.NotifyResult.error when last_alert_ok = 0. NULL
    -- otherwise.
    last_alert_error TEXT,
    -- When last_alert_ok/last_alert_error were last written, i.e. when delivery of the most
    -- recent alert was actually confirmed or refuted - independent of, and normally later than,
    -- the matching last_*_at attempt timestamp above.
    last_alert_at TEXT,
    -- Set once the device settings page saves a name that differs from the last name bioseasy
    -- itself discovered (lockdown DeviceName on scan, or Info.plist "Device Name" after a
    -- backup, see discovery.fill_device_identity). While this is 0, a scan or a finished backup
    -- keeps devices.name in sync with what the device itself reports; once the owner renames it
    -- here, that sync stops for this device.
    name_custom INTEGER NOT NULL DEFAULT 0,
    -- Time and outcome of the most recent backup-password check. Never the password itself:
    -- see src/bioseasy/password_check.py.
    password_checked_at TEXT,
    password_check_result TEXT CHECK (password_check_result IN ('correct', 'wrong')),
    -- The assisted setup wizard (docs/setup.md): each column is set once bioseasy itself has
    -- turned the step on, so a device added with either already on elsewhere (Finder, iTunes,
    -- a previous manual pairing) still has to walk through the wizard once, which is
    -- deliberate - see src/bioseasy/app.py's setup routes.
    wifi_enabled_at TEXT,
    encryption_enabled_at TEXT,
    paired_at TEXT,
    -- Last time a lockdown session using this device's stored pair record succeeded (a backup
    -- start, Wi-Fi enable, encryption check, or a discovery reconnect over Wi-Fi; see
    -- engine/pmd3.py and runtime.py). "On devices with iOS 11 and iPadOS 13.1, or later, if a
    -- pairing record hasn't been used for more than 30 days, it expires." (Apple Support,
    -- "Physical pairing model security for iPad and iPhone",
    -- https://support.apple.com/guide/security/pairing-model-security-secadb5b6434/web,
    -- retrieved 2026-09-15).
    -- status.py warns once this gets old. NULL until the first successful use after pairing.
    pair_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
    -- manual: web UI; schedule: due and inside the window; device: started from the device
    -- itself; api: POST /api/v1/devices/{udid}/backup, e.g. an iOS Shortcuts automation
    -- (SCHEMA_VERSION 9)
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'device', 'api')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    -- not_confirmed: nobody entered the passcode in time; not a failure of the backup itself
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'not_confirmed', 'cancelled')),
    message TEXT,
    -- Progress persisted to the row itself, so any process (not only the one running the
    -- backup) can read it back; needed once backups can run in a separate worker process.
    phase TEXT,
    percent REAL,
    progress_message TEXT,
    -- Which process is running this backup, and when it last proved it is still alive; see
    -- src/bioseasy/jobs.py and the workers table below.
    worker_id TEXT,
    heartbeat_at TEXT
);
CREATE TABLE sightings (
    udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
    seen_at TEXT NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('usb', 'wifi'))
);
CREATE INDEX sightings_by_device ON sightings (udid, seen_at DESC);
-- One row per completed schedule tick (ticker.py), so reachability.py can report an exact
-- "N of M checks" per day instead of estimating M from settings.schedule_minutes - wrong
-- whenever the interval changed mid-window or a tick was skipped outright (a worker restart, a
-- missed tick_lease). Pruned after 30 days like sightings (ticker.SIGHTINGS_KEPT/TICKS_KEPT).
CREATE TABLE ticks (
    tick_at TEXT NOT NULL
);
CREATE INDEX ticks_by_time ON ticks (tick_at);
CREATE INDEX runs_by_device ON runs (udid, started_at DESC);
-- The real guard against two concurrent backups for one device: a partial unique index, not
-- only JobManager's in-memory dict, which does not exist across processes.
CREATE UNIQUE INDEX runs_one_running ON runs(udid) WHERE status = 'running';
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Links a local account to an OIDC identity. The key is (issuer, subject), never email, because
-- a provider's email claim is not guaranteed stable, unique or verified.
CREATE TABLE oidc_links (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX oidc_links_by_user ON oidc_links (user_id);
CREATE TABLE workers (
    id TEXT PRIMARY KEY,
    heartbeat_at TEXT NOT NULL
);
-- Devices seen by the last discovery scan (tick or an explicit "Scan now"), regardless of
-- whether they are paired or already added: the Add page reads this table instead of ever
-- calling engine.discover() itself, which can block for seconds against real hardware and, for
-- pairing, up to 120s.
CREATE TABLE seen_devices (
    udid TEXT PRIMARY KEY,
    name TEXT,
    product_type TEXT,
    os_version TEXT,
    transport TEXT NOT NULL CHECK (transport IN ('usb', 'wifi')),
    paired INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT NOT NULL
);
-- One row per device pairing attempt started from the Add page; the pairing itself runs off the
-- request in the worker process (tasks.pair_device), and the page polls this state with htmx
-- instead of the request blocking on the device's Trust dialog.
CREATE TABLE pairings (
    udid TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'done', 'failed')),
    message TEXT,
    updated_at TEXT NOT NULL
);
-- Transient state for the setup-wizard actions that run off the request (enable_wifi,
-- enable_encryption) and the device settings page's own backup-password change, one row per
-- (udid, step), the same shape as the `pairings` table above and for the same reason: the web
-- page polls this with htmx instead of the request blocking on the device. Never holds a
-- password; see src/bioseasy/runtime.py.
CREATE TABLE setup_actions (
    udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
    step TEXT NOT NULL CHECK (step IN ('wifi', 'encryption', 'password_change')),
    state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed')),
    message TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (udid, step)
);
-- Personal API tokens for the status API. Only a hash of the secret is stored
-- (src/bioseasy/tokens.py); the full token is shown once at creation and never again, never
-- logged. scope='read' (default) is the original read-only behaviour; scope='backup' additionally
-- allows POST /api/v1/devices/{udid}/backup for the devices owned by that token's user (SCHEMA_VERSION 9).
CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'read',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at TEXT,
    revoked_at TEXT
);
CREATE INDEX api_tokens_by_user ON api_tokens (user_id);
-- Browser push subscriptions (docs/notifications.md, "Browser popups and push"). One row per
-- browser/device the user opted in from,
-- created by POST /settings/notifications/push/subscribe (webpush.py, settings_notifications.html). endpoint
-- is unique across all users: the push service assigns it per browser subscription, and the
-- same value can never legitimately belong to two rows. p256dh and auth are the subscription's
-- own public key and auth secret (RFC 8291), not a bioseasy secret, and are not encrypted at
-- rest for that reason -- unlike an SMTP password or bot token, they are only ever useful
-- together with a still-valid endpoint at the push service, and are worthless once that
-- subscription expires or is revoked (SCHEMA_VERSION 14).
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at TEXT
);
CREATE INDEX push_subscriptions_by_user ON push_subscriptions (user_id);
-- Notification connectors: proper forms (email over SMTP, Telegram) replace pasting a raw
-- Apprise URL; kind='apprise' keeps the raw-URL path for advanced use. scope='device' rows are
-- alerts for the user who owns that device; scope='admin' rows are global alert targets, sent for every
-- device in addition to that device's own connectors. See src/bioseasy/connectors.py.
CREATE TABLE notification_connectors (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('device', 'admin')),
    udid TEXT REFERENCES devices(udid) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('email', 'telegram', 'apprise')),
    label TEXT NOT NULL,
    -- Non-secret fields only (host, port, chat id, and the like); the one secret part per
    -- connector (an SMTP password, a bot token, or a whole raw Apprise URL) lives encrypted in
    -- secret_ciphertext instead.
    settings_json TEXT NOT NULL DEFAULT '{}',
    secret_ciphertext BLOB,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- A device-scope row always names its device; an admin-scope row never does.
    CHECK ((scope = 'device') = (udid IS NOT NULL))
);
CREATE INDEX notification_connectors_by_device ON notification_connectors (udid) WHERE scope = 'device';
CREATE INDEX notification_connectors_by_scope ON notification_connectors (scope) WHERE scope = 'admin';
-- MIGRATIONS: pair hand-off codes (docs/pairing.md, "Pair from my computer"). An admin creates a
-- short-lived, single-use code on the Add page; a small script the user runs on their own
-- computer trades it for the pair record it just created over USB. Only the SHA-256 hash of the
-- code is stored (src/bioseasy/handoff.py), the same trade-off as api_tokens above: the code is
-- shown once, never read back, and a stolen row is useless without the plaintext code.
CREATE TABLE pairing_codes (
    id INTEGER PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    -- Set together with used_at once the hand-off endpoint has stored a record and added or
    -- matched a device from it, so the Add page's poll knows where to send the admin next.
    consumed_udid TEXT
);
CREATE INDEX pairing_codes_open_by_creator ON pairing_codes (created_by) WHERE used_at IS NULL;

-- One row per device holding the most recent connectivity check (engine.netcheck), started from
-- the setup wizard or the device settings page and run in the worker like every other device
-- operation; the web page polls this with htmx, the same shape as `setup_actions` above.
-- steps_json is a JSON array of {name, ok, detail} objects built by the engine to be safe to
-- show (src/bioseasy/engine/base.py's NetcheckStep) - this table, like pair records and
-- passwords, never holds a pair record, a password or any other secret.
CREATE TABLE netcheck_runs (
    udid TEXT PRIMARY KEY REFERENCES devices(udid) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('running', 'done')),
    steps_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Cached recursive size of one directory under the backup root, for the storage browse view
-- (src/bioseasy/browse.py). Computed in the background by a Huey task, never inline in a
-- request: walking a whole snapshot tree can take a while. path is relative to the backup root
-- ("" for the root itself); bytes/files/computed_at are NULL while state = 'calculating' (no
-- result yet, not a zero-byte directory) and filled in once the task finishes.
CREATE TABLE dir_sizes (
    path TEXT PRIMARY KEY,
    bytes INTEGER,
    files INTEGER,
    computed_at TEXT,
    state TEXT NOT NULL DEFAULT 'done' CHECK (state IN ('calculating', 'done'))
);
-- Cross-process registry of running background activity (backup, discovery scan, pairing,
-- storage size calculation, snapshot/retention cleanup, password check, the setup wizard's Wi-Fi
-- and encryption steps, a backup password change, the connectivity check, the update check, and
-- - still unbuilt - a restore, for the header's activity indicator. Web and worker are
-- separate processes (Huey worker), so this table is the only place either can see what the
-- other is doing right now; see src/bioseasy/activity.py's `track` context manager, the one way
-- either process is meant to write to it. heartbeat_at ages a crashed entry out the same way
-- workers.heartbeat_at ages out an orphaned run (jobs.sweep_orphan_runs). udid is NULL for an
-- activity with no single device (a discovery scan, a storage-root size recalculation); both are
-- admin-only actions, so activity.for_owner's INNER JOIN never shows them to a member. Not a
-- foreign key against devices(udid): pairing tracks a udid before any devices row for it exists
-- (a device is only added once pairing has finished) - activity.py joins to devices for a name
-- and simply gets none for a udid that is not there (yet, or any more).
-- outcome/detail/finished_at (SCHEMA_VERSION 12): a finished activity is kept around for a short
-- while instead of being deleted immediately, so the header can show "it just finished".
-- NULL outcome means still running (or, for a row from before this
-- version, "no finished state recorded" - the same as still running to activity.py's queries,
-- which is the safe reading either way). phase keeps meaning only the running phase text.
-- snapshot_name (SCHEMA_VERSION 16): which backup generation this activity is about, for a
-- "verify" row - the generations table (app.py's generations_context) reads it to mark the one
-- row actually being verified right now, not just the device as a whole (the header's activity
-- indicator already covers that). NULL for every activity kind that is not about one generation.
CREATE TABLE activities (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    udid TEXT,
    phase TEXT,
    snapshot_name TEXT,
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    outcome TEXT CHECK (outcome IN ('succeeded', 'failed', 'not_confirmed')),
    detail TEXT,
    finished_at TEXT
);
CREATE INDEX activities_by_heartbeat ON activities (heartbeat_at);
-- WARNING+ log records from both processes, plus the one INFO line jobs.py logs when a backup
-- finishes, for the admin-only /logs page; written by logview.DBLogHandler, installed on the
-- "bioseasy" logger in both app.py's
-- create_app (process='web') and __init__.py's _worker (process='worker'). message and traceback
-- have already passed through logview.redact before they reach here - the same rule as the
-- container log itself: no passwords, no pair record content, only a shortened UDID. Bounded by
-- both row count and age (logview.MAX_ROWS/MAX_AGE_DAYS), pruned on every write. udid is NULL
-- for a record that did not carry one (logview._extract_udid is best-effort, only used to filter
-- the page, never for anything security-relevant).
CREATE TABLE log_entries (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    process TEXT NOT NULL CHECK (process IN ('web', 'worker')),
    logger TEXT NOT NULL,
    level TEXT NOT NULL CHECK (level IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    message TEXT NOT NULL,
    udid TEXT,
    traceback TEXT
);
CREATE INDEX log_entries_by_ts ON log_entries (ts DESC, id DESC);
CREATE INDEX log_entries_by_udid ON log_entries (udid) WHERE udid IS NOT NULL;

-- Deep verification result for one backup generation (src/bioseasy/verify.py): does every file
-- listed in that snapshot's Manifest.db actually exist on disk. Status.plist's SnapshotState
-- alone (inventory.py) never proves this - it is written by the device once it believes the
-- transfer finished. One row per (udid, snapshot_name), overwritten on each re-check; outcome is
-- 'verified', 'missing' or 'not_checked' (an encrypted backup without its password, or a
-- Manifest.db that could not be read) - never folded into 'verified'. missing_fileids_json holds
-- at most verify.MAX_MISSING_EXAMPLES fileIDs, not the full list.
CREATE TABLE snapshot_verifications (
    udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
    snapshot_name TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('verified', 'missing', 'not_checked')),
    listed INTEGER NOT NULL DEFAULT 0,
    present INTEGER NOT NULL DEFAULT 0,
    missing INTEGER NOT NULL DEFAULT 0,
    missing_fileids_json TEXT NOT NULL DEFAULT '[]',
    detail TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL,
    PRIMARY KEY (udid, snapshot_name)
);
CREATE INDEX snapshot_verifications_by_device ON snapshot_verifications (udid, checked_at);
-- A single row the tick lease UPDATE always targets (see migrate()'s note on WAL: UPDATE cannot
-- create a row, so the first lease acquisition needs one to already exist). The far-past value
-- means the very first tick, from whichever worker gets there first, always acquires it.
INSERT INTO settings (key, value) VALUES ('tick_lease', '1970-01-01T00:00:00Z');
"""


# Switching a new database file to WAL needs an exclusive lock, and SQLite answered two
# connections doing it at the same moment with "database is locked" at once, without using the
# busy handler (measured with tests/test_db_migrate.py: the failing test run took
# 0.11 s). WAL is stored in the file, so the first opener's switch serves everyone; the others
# only have to wait for it.
WAL_SWITCH_ATTEMPTS = 100
WAL_SWITCH_PAUSE_SECONDS = 0.05


def _enable_wal(conn: sqlite3.Connection) -> None:
    for attempt in range(WAL_SWITCH_ATTEMPTS):
        try:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or attempt == WAL_SWITCH_ATTEMPTS - 1:
                raise
            time.sleep(WAL_SWITCH_PAUSE_SECONDS)


def connect(path: Path) -> sqlite3.Connection:
    # timeout= installs the busy handler when the connection opens. It covers ordinary write
    # contention between the web service and the worker (keep write transactions short, 10 s is
    # generous); the switch to WAL is not covered by it and has its own retry above.
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA foreign_keys = ON")
    _enable_wal(conn)
    return conn


def _statements(sql: str) -> list[str]:
    """Split a schema into single statements; conn.execute runs only one at a time.

    The text is cut at every semicolon and pieces are joined until sqlite3.complete_statement
    agrees a statement has really ended, so several statements on one line and semicolons inside
    string literals or trigger bodies both come out right without hand-written SQL parsing.
    Comment-only leftovers are dropped.
    """
    statements, buffer = [], ""
    for piece in sql.split(";"):
        buffer += piece + ";"
        if sqlite3.complete_statement(buffer):
            text = buffer.strip()
            # Comment lines removed, is there SQL left beyond the semicolon this loop appended?
            code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--")).strip()
            if code and code != ";":
                statements.append(text)
            buffer = ""
    return statements


def _migrate_8_to_9(conn: sqlite3.Connection) -> None:
    """api_tokens gets a scope column, and runs.trigger's CHECK gains the 'api' value,
    so an API token's scope can allow starting a backup for iOS Shortcuts automation.

    ALTER TABLE ADD COLUMN with a DEFAULT covers api_tokens.scope on its own: SQLite backfills
    every existing row with 'read', the original read-only behaviour, without a separate UPDATE.

    A CHECK constraint cannot be changed by ALTER TABLE at all, so runs is rebuilt following
    SQLite's documented procedure for schema changes ALTER TABLE cannot make
    (sqlite.org/lang_altertable.html, "Making Other Kinds Of Table Schema Changes"): new table,
    copy, drop old, rename, recreate indexes, then PRAGMA foreign_key_check. That procedure's
    PRAGMA foreign_keys=OFF/ON bracket is skipped here on purpose: SQLite documents (and this was
    measured against sqlite3 directly while building this migration) that PRAGMA foreign_keys is
    a no-op inside an already-open transaction, which migrate() always has open at this point for
    the two-processes-starting-at-once guarantee below - so the pragma would silently not take
    effect anyway. It is not needed for this rebuild regardless: no table has a foreign key
    pointing at runs (checked: no "REFERENCES runs" anywhere in SCHEMA), only runs' own outgoing
    reference to devices, which stays satisfied throughout since devices is never touched here.
    foreign_key_check runs anyway, as real proof rather than a skipped assumption.
    """
    conn.execute("ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'read'")
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
    problems = conn.execute("PRAGMA foreign_key_check(runs)").fetchall()
    if problems:
        raise sqlite3.IntegrityError(f"foreign_key_check failed after rebuilding runs: {problems}")


def _migrate_9_to_10(conn: sqlite3.Connection) -> None:
    """New log_entries table for the admin /logs page.

    A plain CREATE TABLE plus indexes: no existing table changes shape, so no rebuild is needed.
    """
    conn.execute(
        """
        CREATE TABLE log_entries (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            process TEXT NOT NULL CHECK (process IN ('web', 'worker')),
            logger TEXT NOT NULL,
            level TEXT NOT NULL CHECK (level IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
            message TEXT NOT NULL,
            udid TEXT,
            traceback TEXT
        )
        """
    )
    conn.execute("CREATE INDEX log_entries_by_ts ON log_entries (ts DESC, id DESC)")
    conn.execute("CREATE INDEX log_entries_by_udid ON log_entries (udid) WHERE udid IS NOT NULL")


def _migrate_10_to_11(conn: sqlite3.Connection) -> None:
    """New snapshot_verifications table for the deep Manifest.db check.

    A plain CREATE TABLE plus index: no existing table changes shape, so no rebuild is needed.
    """
    conn.execute(
        """
        CREATE TABLE snapshot_verifications (
            udid TEXT NOT NULL REFERENCES devices(udid) ON DELETE CASCADE,
            snapshot_name TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('verified', 'missing', 'not_checked')),
            listed INTEGER NOT NULL DEFAULT 0,
            present INTEGER NOT NULL DEFAULT 0,
            missing INTEGER NOT NULL DEFAULT 0,
            missing_fileids_json TEXT NOT NULL DEFAULT '[]',
            detail TEXT NOT NULL DEFAULT '',
            checked_at TEXT NOT NULL,
            PRIMARY KEY (udid, snapshot_name)
        )
        """
    )
    conn.execute("CREATE INDEX snapshot_verifications_by_device ON snapshot_verifications (udid, checked_at)")


def _migrate_11_to_12(conn: sqlite3.Connection) -> None:
    """New outcome/detail/finished_at columns on activities, for the header's "recently
    finished" list (activity.py's ActivityHandle.set_outcome).

    A plain three-column ADD COLUMN: no existing column changes shape, and a single-column CHECK
    on a newly added column is supported directly (SQLite ALTER TABLE ADD COLUMN, since 3.25.0),
    so no table rebuild is needed here the way runs required in _migrate_8_to_9. Every existing
    row gets NULL in all three, read the same as "still running" by activity.py's queries.
    """
    conn.execute(
        "ALTER TABLE activities ADD COLUMN outcome TEXT CHECK (outcome IN ('succeeded', 'failed', 'not_confirmed'))"
    )
    conn.execute("ALTER TABLE activities ADD COLUMN detail TEXT")
    conn.execute("ALTER TABLE activities ADD COLUMN finished_at TEXT")


def _migrate_12_to_13(conn: sqlite3.Connection) -> None:
    """New users.last_sign_in_at, for the admin-only local user management page.

    A plain single-column ADD COLUMN, no CHECK on it: no existing column changes shape, so no
    table rebuild is needed the way runs required in _migrate_8_to_9. Every existing row gets
    NULL, read the same as "never signed in since this column existed" everywhere it is shown.
    """
    conn.execute("ALTER TABLE users ADD COLUMN last_sign_in_at TEXT")


def _migrate_13_to_14(conn: sqlite3.Connection) -> None:
    """New push_subscriptions table for browser Web Push (src/bioseasy/webpush.py).

    A plain CREATE TABLE plus index: no existing table changes shape, so no rebuild is needed the
    way runs required in _migrate_8_to_9. An existing database simply gets zero rows until a user
    opts in from the Settings page.
    """
    conn.execute(
        """
        CREATE TABLE push_subscriptions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            last_used_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX push_subscriptions_by_user ON push_subscriptions (user_id)")


def _migrate_14_to_15(conn: sqlite3.Connection) -> None:
    """New devices.last_overdue_alert_at, splitting the overdue-alert cooldown off
    last_nudge_at: one column serving two cooldowns caused one to starve the other.

    A plain single-column ADD COLUMN, no CHECK on it: no existing column changes shape, so no
    table rebuild is needed the way runs required in _migrate_8_to_9. Left NULL for every
    existing row on purpose, never backfilled from last_nudge_at: a device that is actually
    overdue right now is owed its first overdue alert immediately, not made to wait out a
    cooldown that started for an unrelated nudge.
    """
    conn.execute("ALTER TABLE devices ADD COLUMN last_overdue_alert_at TEXT")


def _migrate_15_to_16(conn: sqlite3.Connection) -> None:
    """New activities.snapshot_name, so a running deep verification can be shown on the row of
    the generation it is actually checking, not only as the header's activity indicator.

    A plain single-column ADD COLUMN, no CHECK on it: no existing column changes shape, so no
    table rebuild is needed the way runs required in _migrate_8_to_9. NULL for every existing row
    and for every activity kind that is not about one snapshot.
    """
    conn.execute("ALTER TABLE activities ADD COLUMN snapshot_name TEXT")


def _migrate_16_to_17(conn: sqlite3.Connection) -> None:
    """New devices.last_alert_ok/last_alert_error/last_alert_at, so a failed or timed-out alert
    send is recorded as failed instead of looking exactly like a successful one -- a timestamp
    that means "the user was told" is only written when the telling actually happened.

    Three plain ADD COLUMNs, no table rebuild needed. NULL for every existing row: nothing is
    backfilled, since no past send outcome is known for rows written under the old, timestamp-only
    behaviour.
    """
    conn.execute("ALTER TABLE devices ADD COLUMN last_alert_ok INTEGER CHECK (last_alert_ok IN (0, 1))")
    conn.execute("ALTER TABLE devices ADD COLUMN last_alert_error TEXT")
    conn.execute("ALTER TABLE devices ADD COLUMN last_alert_at TEXT")


def _migrate_17_to_18(conn: sqlite3.Connection) -> None:
    """New users.last_push_ok/last_push_error/last_push_at, closing the same gap for browser push
    that _migrate_16_to_17 closed for the Apprise path: webpush.send_to_users used to swallow every
    delivery failure with nothing recorded anywhere but the container log, so a user whose browser
    notifications had been failing for days saw nothing on any page. Browser
    push delivery is now recorded the same honest way as Apprise, kept as its own state.

    Three plain ADD COLUMNs on users, no table rebuild needed. NULL for every existing row:
    nothing is backfilled, since no past send outcome is known for rows written before this
    column existed.
    """
    conn.execute("ALTER TABLE users ADD COLUMN last_push_ok INTEGER CHECK (last_push_ok IN (0, 1))")
    conn.execute("ALTER TABLE users ADD COLUMN last_push_error TEXT")
    conn.execute("ALTER TABLE users ADD COLUMN last_push_at TEXT")


def _migrate_18_to_19(conn: sqlite3.Connection) -> None:
    """New users.email, so an admin creating an account can have an invitation sent to it and
    later per-user email notifications have somewhere to go.

    One plain ADD COLUMN, no table rebuild: the column is nullable by design rather than by
    migration convenience - an address is never required for a local account, and nothing is
    backfilled, since no address is known for a row written before this column existed.
    """
    conn.execute("ALTER TABLE users ADD COLUMN email TEXT")


def _migrate_19_to_20(conn: sqlite3.Connection) -> None:
    """The unique index behind "one account per address", for matching an SSO sign-in by email.

    What this step deliberately does NOT do is make users.email NOT NULL. The rule "every account
    has an address" cannot be applied backwards: accounts created before this release have no
    address, no address may be invented for them, and a NOT NULL column would need a table rebuild
    that every one of those rows would fail. The requirement therefore lives at every entrance
    that creates an account from now on (auth.register_user, auth.create_sso_user), while old rows
    keep their NULL and are listed on the admin Users page until somebody fills the address in.

    The index is partial for exactly that reason - many rows may have no address - and
    case-insensitive because a provider may report the same address in a different case than the
    admin typed it.

    A database that already holds two accounts with the same address (possible until now: nothing
    ever checked) cannot get the index, and refusing to start over it would be a far worse outcome
    than living without it. Such a database is migrated without the index and says so in the log;
    the ambiguity is then caught where it matters instead, in oidc.find_user_by_email, which
    refuses to sign anybody in for an address that matches more than one account.
    """
    duplicates = conn.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM users WHERE email IS NOT NULL "
        "GROUP BY email COLLATE NOCASE HAVING COUNT(*) > 1)"
    ).fetchone()[0]
    if duplicates:
        log.warning(
            "%d email address(es) are shared by more than one account, so the unique index on "
            "users.email was not created; single sign-on will refuse to match those addresses "
            "until each account has its own. Fix them on the admin Users page.",
            duplicates,
        )
        return
    conn.execute("CREATE UNIQUE INDEX users_email_unique ON users (email COLLATE NOCASE) WHERE email IS NOT NULL")


# One forward-only step per version above BASELINE_VERSION, keyed by the version it produces.
# migrate() applies MIGRATIONS[v] to go from v - 1 to v. A version bump in SCHEMA_VERSION without
# a matching entry here is caught by test_db_migrate.py's
# test_every_version_above_baseline_has_a_migration_step.
MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    9: _migrate_8_to_9,
    10: _migrate_9_to_10,
    11: _migrate_10_to_11,
    12: _migrate_11_to_12,
    13: _migrate_12_to_13,
    14: _migrate_13_to_14,
    15: _migrate_14_to_15,
    16: _migrate_15_to_16,
    17: _migrate_16_to_17,
    18: _migrate_17_to_18,
    19: _migrate_18_to_19,
    20: _migrate_19_to_20,
}


def _db_path(conn: sqlite3.Connection) -> Path:
    """The on-disk path of a connection's main database (PRAGMA database_list's row 0)."""
    return Path(conn.execute("PRAGMA database_list").fetchone()[2])


def _write_backup_copy(conn: sqlite3.Connection, backup_path: Path) -> None:
    """A consistent snapshot of conn's database, taken with the sqlite3 backup API.

    Must run with no transaction open on conn: the backup API deadlocks against a BEGIN IMMEDIATE
    already open on the same connection (measured while building this migration - it simply never
    returns, since the busy handler waits on a lock the same connection is holding). migrate()
    only ever calls this after rolling back its version-probing transaction, before starting the
    one that actually migrates.
    """
    with closing(sqlite3.connect(backup_path)) as dst:
        conn.backup(dst)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply SCHEMA to a fresh database, or MIGRATIONS forward from an older one; safe when
    several processes start at the same time.

    The web service and the worker both migrate on startup. Reading user_version before taking
    the write lock let two processes on a fresh database both try to create the schema, and the
    second failed with "table already exists". This first transaction reads the version under
    the lock, so a waiting process sees the other's work and skips it. executescript cannot be
    used here: it commits any open transaction before it runs.

    A database at BASELINE_VERSION..SCHEMA_VERSION - 1 is migrated forward one step at a time
    (see _migrate_forward). A database above SCHEMA_VERSION (a downgrade) or below
    BASELINE_VERSION (older than any migration step covers) is refused with a clear message
    instead of guessing.
    """
    conn.execute("BEGIN IMMEDIATE")
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current == SCHEMA_VERSION:
        conn.execute("COMMIT")
        return SCHEMA_VERSION
    if current == 0:
        try:
            for statement in _statements(SCHEMA):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.execute("COMMIT")
            return SCHEMA_VERSION
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    if current > SCHEMA_VERSION:
        conn.execute("ROLLBACK")
        raise SystemExit(
            f"Database schema version {current} is newer than this version of bioseasy expects "
            f"({SCHEMA_VERSION}): this database was migrated by a newer release. Downgrading "
            "bioseasy is not supported; start the newer release again, or stop the container "
            "and delete the data volume to start with a fresh database."
        )
    if current < BASELINE_VERSION:
        conn.execute("ROLLBACK")
        raise SystemExit(
            f"Database schema version {current} does not match this version of bioseasy "
            f"(expects {SCHEMA_VERSION}). There is no migration path from before schema "
            f"{BASELINE_VERSION}: stop the container and delete the data "
            "volume to start with a fresh database."
        )
    # BASELINE_VERSION <= current < SCHEMA_VERSION: forward migration needed. Release this
    # probing transaction first - the backup copy below must run without one open (see
    # _write_backup_copy) - and let _migrate_forward re-acquire the lock and re-read the version,
    # in case another process (web or worker, starting at the same moment) finishes migrating
    # while this one is still writing the backup copy.
    conn.execute("ROLLBACK")
    return _migrate_forward(conn, current)


def _migrate_forward(conn: sqlite3.Connection, probed_version: int) -> int:
    path = _db_path(conn)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_path = path.with_name(f"{path.name}.before-v{probed_version + 1}-{timestamp}")
    _write_backup_copy(conn, backup_path)
    log.warning(
        "migrating database schema from %d towards %d; backup copy of the pre-migration database written to %s",
        probed_version,
        SCHEMA_VERSION,
        backup_path,
    )
    conn.execute("BEGIN IMMEDIATE")
    version = probed_version
    try:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current == SCHEMA_VERSION:
            conn.execute("COMMIT")
            return SCHEMA_VERSION
        steps = list(range(current + 1, SCHEMA_VERSION + 1))
        started = time.monotonic()
        for version in steps:
            MIGRATIONS[version](conn)
            conn.execute(f"PRAGMA user_version = {version}")
        conn.execute("COMMIT")
        # Without this line the log only ever announced a migration and never its end, so a
        # finished run and one that died halfway looked the same.
        log.info(
            "database schema migrated to version %d in %d step(s), %.1fs",
            SCHEMA_VERSION,
            len(steps),
            time.monotonic() - started,
        )
        return SCHEMA_VERSION
    except BaseException as exc:
        conn.execute("ROLLBACK")
        raise SystemExit(
            f"Database migration step to schema version {version} failed: {exc}. Startup "
            "stopped; the database on disk is unchanged (rolled back), and the backup copy "
            f"taken before migrating is still at {backup_path}."
        ) from exc


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
