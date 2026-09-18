# SPDX-License-Identifier: GPL-3.0-or-later
"""Builds the pieces that carry out backups, ticks, discovery and pairing, from Settings.

The worker process (`bioseasy worker`: see tasks.py) is the one that actually runs jobs and
ticks, using this module's engine, JobManager and Ticker; the web process (app.py) builds the
same Runtime too, but only to enqueue Huey tasks and to run the setup wizard's encryption step
(the one exception that never goes through Huey, see run_encryption_enable). Building the wiring
in one place means a change reaches both processes instead of the two drifting apart.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import activity, auth, connectors, db, mqtt, notify, status, storage, webpush
from . import defaults as backup_defaults
from .config import Settings
from .engine.base import Engine, EngineError, Transport
from .jobs import JobManager
from .ticker import Ticker

log = logging.getLogger("bioseasy")
# At most one "backup storage problem" admin alert per volume per day, so a tick or a run of
# manual attempts that all hit the same low-space volume does not spam admin connectors; keyed by
# the backup root path in the settings table (one row is enough since bioseasy has one volume).
STORAGE_ALERT_COOLDOWN = timedelta(hours=24)
# Re-detection (run_setup_detect) is skipped for a device within this long of its last attempt,
# successful or not, so polling the setup page (every 2s while a step is running) never turns
# into hammering the device with lockdown sessions. See setup_detect_due.
SETUP_DETECT_COOLDOWN = timedelta(minutes=10)
# A 'running' state older than this is treated as abandoned rather than in flight, so a worker
# killed between mark_setup_detect_running and run_setup_detect's own terminal write (OOM,
# container restart) does not leave setup_detect_due returning False forever - with no manual
# override in the UI, that would need a direct database edit to ever clear. Every real device
# round trip inside detect_setup_state finishes in seconds (NETCHECK_TIMEOUT and
# HEARTBEAT_FIRST_MARCO_TIMEOUT are both 5s in engine/pmd3.py); this is comfortably above any
# real run while still far below a day, so a genuinely stuck state clears on the next poll.
SETUP_DETECT_STUCK_AFTER = timedelta(hours=1)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_engine(settings: Settings, fixed_hosts: Callable[[], dict[str, str]] | None = None) -> Engine:
    if settings.engine == "demo":
        from .engine.demo import DemoEngine

        return DemoEngine(fixed_hosts=fixed_hosts, data_dir=settings.data_dir)
    if settings.engine == "pymobiledevice3":
        from .engine.pmd3 import Pmd3Engine

        return Pmd3Engine(settings.data_dir / "pair-records", backup_root=settings.backup_root, fixed_hosts=fixed_hosts)
    raise SystemExit(f"Unknown engine {settings.engine!r}; use pymobiledevice3 or demo")


@dataclass
class Runtime:
    settings: Settings
    connect: Callable[[], sqlite3.Connection]
    engine: Engine
    jobs: JobManager
    ticker: Ticker
    notify_event: Callable[[str, str, str], None]
    notify_targets: Callable[[sqlite3.Connection, sqlite3.Row], list[str]]
    notify_storage_failed: Callable[[str], None]
    storage_check: Callable[[], storage.StorageCheck]
    global_defaults: Callable[[], backup_defaults.GlobalDefaults]
    tz: tzinfo
    # Persists devices.pair_used_at (db.py) whenever a lockdown session with the device's stored
    # pair record succeeds; passed as the engine's on_pair_used callback from jobs.py (backup),
    # ticker.py and discovery.py (discover), and used directly by run_wifi_enable below.
    mark_pair_used: Callable[[str], None]


def build(settings: Settings, engine: Engine | None = None, *, worker_id: str | None = None) -> Runtime:
    """Construct one process's copy of the shared runtime.

    `worker_id` identifies this process in the workers table (jobs.sweep_orphan_runs); pass it
    explicitly for the worker process so it is stable across the process's own lifetime, or leave
    it to JobManager's default (a random id per instance) for ad hoc use such as tests.
    """
    db_path = settings.data_dir / "bioseasy.db"

    def connect() -> sqlite3.Connection:
        return db.connect(db_path)

    def fixed_hosts() -> dict[str, str]:
        with closing(connect()) as conn:
            rows = conn.execute("SELECT udid, host FROM devices WHERE host IS NOT NULL AND host != ''")
            return {row["udid"]: row["host"] for row in rows}

    engine = engine or make_engine(settings, fixed_hosts)

    def global_defaults() -> backup_defaults.GlobalDefaults:
        with closing(connect()) as conn:
            return backup_defaults.get_global_defaults(conn)

    def storage_check() -> storage.StorageCheck:
        with closing(connect()) as conn:
            root_id = db.get_setting(conn, "backup_root_id")
            threshold = backup_defaults.get_global_defaults(conn).free_space_threshold_bytes
        return storage.check(settings.backup_root, root_id, threshold)

    def notify_targets(conn: sqlite3.Connection, device: sqlite3.Row) -> list[str]:
        admin_urls = connectors.apprise_urls_for(conn, settings.data_dir, "admin")
        device_urls = connectors.apprise_urls_for(conn, settings.data_dir, "device", device["udid"])
        seen = set(device_urls)
        return device_urls + [u for u in admin_urls if u not in seen]

    def push_targets(conn: sqlite3.Connection, device: sqlite3.Row | None) -> set[int]:
        """Which users' browser subscriptions an event reaches: every admin (same reach as an
        admin-scope Apprise connector) plus the device's own owner, if it has one -- the same
        pairing notify_targets uses for email/Telegram, just addressed by user id instead of a
        built URL, since a push subscription lives on the Settings page, not per device.
        """
        admin_ids = {row["id"] for row in auth.list_users(conn) if row["role"] == "admin"}
        if device is not None and device["owner_id"] is not None:
            admin_ids.add(device["owner_id"])
        return admin_ids

    def send_push(conn: sqlite3.Connection, user_ids: set[int], title: str, body: str, context: str) -> None:
        # Never allowed to block or fail the caller: webpush.send_to_users already swallows every
        # per-subscription failure, this is the outer safety net for anything it does not (a
        # crashed VAPID load, an unexpected exception from the library itself).
        try:
            webpush.send_to_users(conn, settings.data_dir, user_ids, title, body)
        except Exception:
            log.warning("push notification (%s) failed", context, exc_info=True)

    alert_locks: dict[str, threading.Lock] = {}
    alert_locks_guard = threading.Lock()

    def alert_lock(udid: str) -> threading.Lock:
        """One lock per device, so alerts for the same device never send concurrently.

        Bounded by the number of devices, which is small and already bounded by the devices
        table, so the dictionary cannot grow without limit.
        """
        with alert_locks_guard:
            return alert_locks.setdefault(udid, threading.Lock())

    def notify_event(event: str, udid: str, message: str) -> None:
        # Runs off the calling thread (the backup worker, or ticker.py's tick) so a slow SMTP
        # server, webhook or push service can never delay or block a backup or a tick.
        def send_it() -> None:
            with closing(connect()) as conn:
                device = conn.execute("SELECT * FROM devices WHERE udid = ?", (udid,)).fetchone()
                if device is None:
                    return
                urls = notify_targets(conn, device)
                push_user_ids = push_targets(conn, device)
                title, body = notify.message_for(
                    event, device["name"] or device["udid"], message, device["product_type"]
                )
                if urls:
                    # Serialised per device, because two alerts for the same device can overlap
                    # (ticker.py raising an overdue alert while jobs.py reports a backup outcome),
                    # and each thread writes its own verdict when its own send returns. Run
                    # concurrently, the slower one lands last: a stale failure then overwrites the
                    # newer success and the device page reports a failed delivery for an alert
                    # that did arrive. Serialising makes "most recently written" and "most recent
                    # send" the same statement. The wait is bounded by notify.send's own timeout,
                    # and this is a background thread, so no tick or backup waits on it.
                    # The write belongs inside the lock, not merely the send: serialising the send
                    # alone still lets both threads race to write afterwards, which is the very
                    # defect this guards against.
                    with alert_lock(udid):
                        result = notify.send(urls, title, body)
                        if not result.ok:
                            log.warning("notification for device %s (%s) failed: %s", udid, event, result.error)
                        # Recorded only now, after the send actually returned - never at the moment
                        # the alert was merely handed off - so devices.last_alert_ok reflects what
                        # was observed to happen, not what was hoped for. A timestamp that means
                        # "the user was told" is only written when the telling actually happened.
                        # Covers every notify_event caller (ticker.py's
                        # nudge/overdue/upcoming alerts and jobs.py's run-outcome notifications
                        # alike), since all of them share this one send path and the same honesty
                        # requirement applies to each.
                        conn.execute(
                            "UPDATE devices SET last_alert_ok = ?, last_alert_error = ?, "
                            "last_alert_at = ? WHERE udid = ?",
                            (1 if result.ok else 0, None if result.ok else result.error, _now(), udid),
                        )
                if push_user_ids:
                    send_push(conn, push_user_ids, title, body, f"device {udid} ({event})")

        threading.Thread(target=send_it, name=f"notify-{udid}", daemon=True).start()
        # Every device's state, not just this one: simplest way to keep the MQTT payload built
        # from one shared query (status.for_admin), the same rule the API follows. Only for a run
        # actually finishing - "waiting_for_passcode", "overdue" and "due" fire notify_event too,
        # but republishing on those would not change anything MQTT hasn't already published on
        # the next tick.
        if event in ("succeeded", "failed", "not_confirmed"):
            threading.Thread(target=mqtt_publish_all, name="mqtt-publish", daemon=True).start()

    def mqtt_publish_all() -> None:
        # A broker that is down, unreachable or misconfigured must never break a backup or a
        # tick (see mqtt.py's module docstring): every failure is caught here, and only the
        # exception's class name is logged, never its text, which could echo the broker host or
        # an auth error built from the password.
        try:
            with closing(connect()) as conn:
                cfg = mqtt.load_config(conn, settings.data_dir)
                if cfg is None or not cfg.enabled:
                    return
                now = datetime.now(UTC)
                statuses = [status.to_public(s) for s in status.for_admin(conn, settings.backup_root, now)]
            mqtt.publish_all(cfg, statuses, now)
        except Exception as exc:
            log.warning("mqtt publish failed: %s", type(exc).__name__)

    def notify_storage_failed(message: str) -> None:
        """A backup could not start because the volume is below its free-space threshold.

        Runs off the calling thread, same reason as notify_event above. Volume-wide, not
        per-device, and throttled to at most one admin alert per STORAGE_ALERT_COOLDOWN: every
        device whose scheduled or manual backup hits the same low-space volume would otherwise
        each trigger their own alert. The last-sent timestamp is a settings row keyed by the
        backup root path, so a changed BIOSEASY_BACKUP_ROOT starts its own cooldown.
        """

        def send_it() -> None:
            key = f"storage_alert_sent_at:{settings.backup_root}"
            now = datetime.now(UTC)
            with closing(connect()) as conn:
                last = db.get_setting(conn, key)
                if last is not None:
                    last_dt = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                    if now - last_dt < STORAGE_ALERT_COOLDOWN:
                        return
                urls = connectors.apprise_urls_for(conn, settings.data_dir, "admin")
                push_user_ids = push_targets(conn, None)
                if not urls and not push_user_ids:
                    return
                title, body = notify.message_for("storage_failed", "the backup volume", message)
                sent = False
                if urls:
                    result = notify.send(urls, title, body)
                    if result.ok:
                        sent = True
                    else:
                        log.warning("storage alert notification failed: %s", result.error)
                if push_user_ids:
                    send_push(conn, push_user_ids, title, body, "storage_failed")
                    sent = True
                if sent:
                    db.set_setting(conn, key, now.strftime("%Y-%m-%dT%H:%M:%SZ"))

        threading.Thread(target=send_it, name="notify-storage", daemon=True).start()

    def mark_pair_used(udid: str) -> None:
        with closing(connect()) as conn:
            conn.execute("UPDATE devices SET pair_used_at = ? WHERE udid = ?", (_now(), udid))

    def mark_setup_confirmed(udid: str, transport: Transport | None, encrypted: bool) -> None:
        mark_setup_confirmed_from_backup(connect, udid, transport, encrypted)

    try:
        tz = ZoneInfo(settings.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        log.warning("unknown time zone %r, using UTC", settings.timezone)
        tz = UTC
    jobs = JobManager(
        connect,
        engine,
        settings.backup_root,
        storage_check,
        global_defaults,
        tz,
        on_event=notify_event,
        worker_id=worker_id,
        mark_pair_used=mark_pair_used,
        notify_storage_failed=notify_storage_failed,
        mark_setup_confirmed=mark_setup_confirmed,
    )

    def on_tick() -> None:
        threading.Thread(target=mqtt_publish_all, name="mqtt-publish-tick", daemon=True).start()

    ticker = Ticker(
        connect,
        engine,
        jobs,
        notify_event,
        tz,
        settings.backup_root,
        storage_check,
        mark_pair_used=mark_pair_used,
        on_tick=on_tick,
    )
    return Runtime(
        settings=settings,
        connect=connect,
        engine=engine,
        jobs=jobs,
        ticker=ticker,
        notify_event=notify_event,
        notify_targets=notify_targets,
        notify_storage_failed=notify_storage_failed,
        storage_check=storage_check,
        global_defaults=global_defaults,
        tz=tz,
        mark_pair_used=mark_pair_used,
    )


def run_pairing(rt: Runtime, udid: str) -> None:
    """Runs engine.pair(udid) off the request and records the outcome in the pairings row.

    Shared by the web process's Huey
    pair_device task (runner=huey, tasks.py): pairing can block for up to 120s waiting on the
    device's own Trust dialog, so it must never run on a request thread.

    Deliberately does not touch the devices table: it only owns the pairing itself, so it needs
    no owner_id (tasks.pair_device's signature is pair_device(udid), nothing more). The web
    route that polls this state (app.py's /add/pairing/{udid}/status) does the actual add, with
    the requesting admin as owner, once it observes state == 'done'.
    """
    with closing(rt.connect()) as conn:
        conn.execute("UPDATE pairings SET state = 'running', updated_at = ? WHERE udid = ?", (_now(), udid))
    with activity.track(rt.connect, "pairing", udid=udid):
        try:
            rt.engine.pair(udid)
        except EngineError as exc:
            log.warning("pairing of %s failed: %s", udid[:8], exc)
            with closing(rt.connect()) as conn:
                conn.execute(
                    "UPDATE pairings SET state = 'failed', message = ?, updated_at = ? WHERE udid = ?",
                    (str(exc), _now(), udid),
                )
            return
        except Exception:  # a crash must end as a recorded failure, never as a stuck 'running'
            log.exception("pairing of %s crashed", udid)
            with closing(rt.connect()) as conn:
                conn.execute(
                    "UPDATE pairings SET state = 'failed', message = ?, updated_at = ? WHERE udid = ?",
                    ("Internal error, see the container log", _now(), udid),
                )
            return
        with closing(rt.connect()) as conn:
            conn.execute(
                "UPDATE pairings SET state = 'done', message = NULL, updated_at = ? WHERE udid = ?", (_now(), udid)
            )


def mark_setup_action_running(rt: Runtime, udid: str, step: str) -> None:
    """Written by the request handler itself (app.py), synchronously, before it starts the
    background thread or Huey task - the same shape as add_pair_start's own INSERT into
    `pairings` before it hands off to run_pairing. Writing this here rather than at the top of
    run_wifi_enable/run_encryption_enable closes the small race where the page polls
    /devices/{udid}/setup/status before the background call has run its first statement and
    would otherwise still see the previous, stale state.
    """
    with closing(rt.connect()) as conn:
        conn.execute(
            "INSERT INTO setup_actions (udid, step, state, message, updated_at) VALUES (?, ?, 'running', NULL, ?) "
            "ON CONFLICT(udid, step) DO UPDATE SET state = 'running', message = NULL, updated_at = excluded.updated_at",
            (udid, step, _now()),
        )


def _setup_action_failed(rt: Runtime, udid: str, step: str, message: str) -> None:
    # The message is the one the UI shows (EngineError text), never a password or record content.
    log.warning("setup step %s failed for device %s: %s", step, udid[:8], message)
    with closing(rt.connect()) as conn:
        conn.execute(
            "UPDATE setup_actions SET state = 'failed', message = ?, updated_at = ? WHERE udid = ? AND step = ?",
            (message, _now(), udid, step),
        )


def _setup_action_done(rt: Runtime, udid: str, step: str, device_column: str) -> None:
    with closing(rt.connect()) as conn:
        conn.execute(
            "UPDATE setup_actions SET state = 'done', message = NULL, updated_at = ? WHERE udid = ? AND step = ?",
            (_now(), udid, step),
        )
        conn.execute(f"UPDATE devices SET {device_column} = ? WHERE udid = ?", (_now(), udid))  # noqa: S608


def run_wifi_enable(rt: Runtime, udid: str) -> None:
    """Runs engine.enable_wifi(udid) off the request and records the outcome in the
    setup_actions row that /devices/{udid}/setup polls with htmx (app.py).

    Shared by the web process's Huey
    enable_wifi_step task (runner=huey, tasks.py) - the same "existing background path" pairing
    already uses (docs/concept.md, "Pairing"), just one row per (udid, 'wifi') instead of per
    udid.
    """
    with activity.track(rt.connect, "wifi_enable", udid=udid):
        try:
            rt.engine.enable_wifi(udid, on_pair_used=rt.mark_pair_used)
        except EngineError as exc:
            _setup_action_failed(rt, udid, "wifi", str(exc))
            return
        except Exception:  # a crash must end as a recorded failure, never as a stuck 'running'
            log.exception("enabling Wi-Fi backups for %s crashed", udid)
            _setup_action_failed(rt, udid, "wifi", "Internal error, see the container log")
            return
        _setup_action_done(rt, udid, "wifi", "wifi_enabled_at")


def run_encryption_enable(rt: Runtime, udid: str, password: str) -> None:
    """Runs engine.enable_encryption(udid, password) off the request.

    Unlike every other background device operation in this module, this one is never allowed to
    run through Huey: Huey's SqliteHuey storage persists task arguments to queue.db, and the
    backup password must never be written to disk. app.py therefore always starts this as a plain
    threading.Thread in the web process, as the one deliberate exception to that rule.
    `password` lives only in this call's local scope (and the engine call's), and is
    deleted from it as soon as it is no longer needed, on every exit path.
    """
    with activity.track(rt.connect, "encryption_enable", udid=udid):
        try:
            try:
                rt.engine.enable_encryption(udid, password)
            finally:
                del password
        except EngineError as exc:
            _setup_action_failed(rt, udid, "encryption", str(exc))
            return
        except Exception:  # a crash must end as a recorded failure, never as a stuck 'running'
            log.exception("enabling backup encryption for %s crashed", udid)
            _setup_action_failed(rt, udid, "encryption", "Internal error, see the container log")
            return
        _setup_action_done(rt, udid, "encryption", "encryption_enabled_at")


def run_password_change(rt: Runtime, udid: str, old: str, new: str) -> None:
    """Runs engine.change_encryption_password(udid, old, new) off the request.

    Started from the device settings page ("Backup password" section), never through Huey, for
    the exact reason run_encryption_enable above never is: Huey's SqliteHuey storage persists
    task arguments to queue.db, and both passwords must never touch disk. app.py always starts
    this as a plain threading.Thread in the web process. `old` and `new` live only in this call's local
    scope (and the engine call's), deleted from it on every exit path.

    On success this also clears devices.password_checked_at and password_check_result: the
    reminder the device page shows is about the *current* password, and it just changed, so a
    check against the old one is no longer meaningful.
    """
    with activity.track(rt.connect, "password_change", udid=udid):
        try:
            try:
                rt.engine.change_encryption_password(udid, old, new)
            finally:
                del old, new
        except EngineError as exc:
            _setup_action_failed(rt, udid, "password_change", str(exc))
            return
        except Exception:  # a crash must end as a recorded failure, never as a stuck 'running'
            log.exception("backup encryption change for %s crashed", udid)
            _setup_action_failed(rt, udid, "password_change", "Internal error, see the container log")
            return
        with closing(rt.connect()) as conn:
            conn.execute(
                "UPDATE setup_actions SET state = 'done', message = NULL, updated_at = ? WHERE udid = ? AND step = ?",
                (_now(), udid, "password_change"),
            )
            conn.execute(
                "UPDATE devices SET password_checked_at = NULL, password_check_result = NULL WHERE udid = ?",
                (udid,),
            )


def mark_netcheck_running(rt: Runtime, udid: str) -> None:
    """Written by the request handler itself (app.py), synchronously, before it enqueues the
    Huey task - the same reason mark_setup_action_running is written before its background call
    starts: it closes the race where the page's first poll would otherwise still see the
    previous run's result."""
    with closing(rt.connect()) as conn:
        conn.execute(
            "INSERT INTO netcheck_runs (udid, state, steps_json, started_at, updated_at) "
            "VALUES (?, 'running', '[]', ?, ?) "
            "ON CONFLICT(udid) DO UPDATE SET state = 'running', steps_json = '[]', "
            "started_at = excluded.started_at, updated_at = excluded.updated_at",
            (udid, _now(), _now()),
        )


def run_netcheck(rt: Runtime, udid: str) -> None:
    """Runs engine.netcheck(udid) in the worker (tasks.py's netcheck_step) and records the
    result in netcheck_runs (db.py), polled with htmx by /devices/{udid}/netcheck/status
    (app.py). Every NetcheckStep.detail is built by the engine to be safe to store and show
    (engine/base.py); this function never touches a pair record or a password itself, so unlike
    run_encryption_enable and run_password_change it is allowed to run as a plain Huey task.

    Registered with the activity tracker like every other device operation: a connectivity check
    runs in the worker and takes a while, and was previously the one such operation that
    never appeared in the header's "what is running" popover, although `activity.KINDS` had
    listed `connectivity_check` all along."""
    with activity.track(rt.connect, "connectivity_check", udid=udid) as handle:
        try:
            steps = rt.engine.netcheck(udid, on_pair_used=rt.mark_pair_used)
        except Exception:  # a crash must end as a recorded result, never as a stuck 'running'
            log.exception("connectivity check for %s crashed", udid)
            steps_json = json.dumps([{"name": "Internal error", "ok": False, "detail": "See the container log"}])
            # The `with` block returns normally here, so `track` alone would record a success.
            # Saying so explicitly is the difference between "checked, found nothing" and "crashed".
            handle.set_outcome("failed", "Internal error")
        else:
            steps_json = json.dumps([{"name": s.name, "ok": s.ok, "detail": s.detail} for s in steps])
            # A check that ran is a success even when a step reports a problem: the failure it
            # found belongs on the device page, not in the activity popover.
            handle.set_outcome("succeeded")
        with closing(rt.connect()) as conn:
            conn.execute(
                "UPDATE netcheck_runs SET state = 'done', steps_json = ?, updated_at = ? WHERE udid = ?",
                (steps_json, _now(), udid),
            )


def mark_setup_confirmed_from_backup(
    connect: Callable[[], sqlite3.Connection], udid: str, transport: Transport | None, encrypted: bool
) -> None:
    """A succeeded backup is itself evidence for the setup wizard's Wi-Fi and encryption steps
    (docs/setup.md): a run that actually transferred data over Wi-Fi proves Wi-Fi connections
    are on, and a finished backup whose Manifest.plist reads IsEncrypted=True (inventory.py's
    BackupInfo.encrypted) proves backup encryption is on - real outcomes, stronger evidence than
    either engine.detect_setup_state's own read or the wizard's own buttons.

    `transport` is only ever Transport.WIFI here when the engine itself reported the connection
    used Wi-Fi (engine/pmd3.py's _backup, wired through jobs.py's on_transport): a device
    plugged into the bioseasy host by USB is still found first by _connect, so a successful
    backup is not by itself proof of a Wi-Fi connection and must never be treated as one just
    because bioseasy's purpose is Wi-Fi backups - see engine/base.py's TransportCallback.

    Called from jobs.py's JobManager only for a run about to be recorded 'succeeded'. Only ever
    sets a column that is still NULL (COALESCE), the same "never unset" rule run_setup_detect
    follows - a run's own evidence is never used to blank out a state bioseasy already recorded.
    """
    if transport is not Transport.WIFI and not encrypted:
        return
    with closing(connect()) as conn:
        if transport is Transport.WIFI:
            conn.execute(
                "UPDATE devices SET wifi_enabled_at = COALESCE(wifi_enabled_at, ?) WHERE udid = ?", (_now(), udid)
            )
        if encrypted:
            conn.execute(
                "UPDATE devices SET encryption_enabled_at = COALESCE(encryption_enabled_at, ?) WHERE udid = ?",
                (_now(), udid),
            )


def _setup_detect_key(udid: str) -> str:
    return f"setup_detect:{udid}"


def setup_detect_state(rt: Runtime, udid: str) -> dict | None:
    """The most recent setup-detection run for `udid`: {"state": "running"|"done"|"failed",
    "message": str | None, "updated_at": str}, or None if detection has never run for it.

    Stored in the generic `settings` table (db.py) rather than a new column or a new
    setup_actions step, so this feature needs no schema change (a schema change before the
    migration mechanism landed meant an operator had to recreate the data volume, which this
    detection feature exists to make unnecessary for exactly this kind of re-add).
    """
    with closing(rt.connect()) as conn:
        raw = db.get_setting(conn, _setup_detect_key(udid))
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def setup_detect_due(rt: Runtime, udid: str) -> bool:
    """Whether run_setup_detect should be enqueued for `udid` right now.

    False while a previous run is still 'running' (it would otherwise be re-enqueued on every
    2s poll of the setup page while it is itself still in flight), and False again for
    SETUP_DETECT_COOLDOWN after the last attempt finished, successful or not - the whole point
    of this check is to keep polling the setup page from hammering the device with lockdown
    sessions. True the first time (no state recorded yet), which is also what makes every "add a
    device" path enqueue detection unconditionally.

    A 'running' state also stops blocking once it is older than SETUP_DETECT_STUCK_AFTER: with no
    button that lets an operator force a re-check, a run that never reached its own 'done'/'failed'
    write (the worker process was killed, not merely slow) would otherwise leave this device stuck
    forever, since nothing else ever moves the state out of 'running'.
    """
    state = setup_detect_state(rt, udid)
    if state is None:
        return True
    updated_at = state.get("updated_at")
    updated_dt: datetime | None
    if isinstance(updated_at, str):
        try:
            updated_dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        except ValueError:
            updated_dt = None
    else:
        updated_dt = None
    if state.get("state") == "running":
        if updated_dt is None:
            return False
        return datetime.now(UTC) - updated_dt >= SETUP_DETECT_STUCK_AFTER
    if updated_dt is None:
        return True
    return datetime.now(UTC) - updated_dt >= SETUP_DETECT_COOLDOWN


def mark_setup_detect_running(rt: Runtime, udid: str) -> None:
    """Written by the request handler itself (app.py), synchronously, before the detection task
    is enqueued - the same race-closing shape as mark_setup_action_running and
    mark_netcheck_running above: without it, a poll landing before the background call's first
    statement would still see the previous (or absent) state and could enqueue a second run."""
    with closing(rt.connect()) as conn:
        db.set_setting(
            conn, _setup_detect_key(udid), json.dumps({"state": "running", "message": None, "updated_at": _now()})
        )


def run_setup_detect(rt: Runtime, udid: str) -> None:
    """Runs engine.detect_setup_state(udid) off the request and records what it found.

    Enqueued by the setup wizard's own task (tasks.detect_setup_step) when a device is
    (re-)added or its setup page is opened with an open step (app.py) - see
    engine.detect_setup_state's docstring for why: a pair record can survive a recreated
    database while the device itself already has Wi-Fi and encryption on.

    Only ever moves devices.wifi_enabled_at / encryption_enabled_at from NULL to now, on a
    confirmed True (SetupState field is True); a confirmed False or an unreadable field (None)
    changes nothing - never an assumption, and never unset once bioseasy has recorded either.
    """
    with activity.track(rt.connect, "setup_detect", udid=udid):
        try:
            found = rt.engine.detect_setup_state(udid, on_pair_used=rt.mark_pair_used)
        except Exception:  # a crash must end as a recorded failure, never as a stuck 'running'
            log.exception("setup detection for %s crashed", udid)
            with closing(rt.connect()) as conn:
                db.set_setting(
                    conn,
                    _setup_detect_key(udid),
                    json.dumps(
                        {"state": "failed", "message": "Internal error, see the container log", "updated_at": _now()}
                    ),
                )
            return
        with closing(rt.connect()) as conn:
            # Only a confirmed True (never a False, and never a failed/unknown read) ever
            # writes a column, and only once - see the docstring above.
            if found.wifi_enabled:
                conn.execute(
                    "UPDATE devices SET wifi_enabled_at = COALESCE(wifi_enabled_at, ?) WHERE udid = ?", (_now(), udid)
                )
            if found.encryption_enabled:
                conn.execute(
                    "UPDATE devices SET encryption_enabled_at = COALESCE(encryption_enabled_at, ?) WHERE udid = ?",
                    (_now(), udid),
                )
            message = None
            if found.wifi_enabled is None and found.encryption_enabled is None:
                message = "Could not reach the device to check its current state."
            db.set_setting(
                conn, _setup_detect_key(udid), json.dumps({"state": "done", "message": message, "updated_at": _now()})
            )


def mark_backup_starting(rt: Runtime, udid: str, trigger: str) -> int | None:
    """Inserts the running `runs` row synchronously, before the backup task is enqueued, so the
    request's own response already shows the running state - "Back up now" otherwise looked
    unchanged until the worker process got around to dequeuing the task and JobManager.start
    inserted the row itself, several seconds later on a busy queue and confusingly indefinitely
    if Huey's consumer was ever down.

    Returns the new run's id (to pass through to tasks.backup_device, then jobs.py's
    JobManager.start(..., run_id=...), which claims this row instead of inserting its own), or
    None if a backup was already running for this device (runs_one_running, db.py) - the caller
    reports that as a refusal instead of enqueueing a task that would find nothing to do.

    worker_id is left NULL: this runs in the web process, which never runs backups itself; the
    actual worker process stamps it once JobManager.start claims the row.
    """
    with closing(rt.connect()) as conn:
        try:
            cur = conn.execute(
                "INSERT INTO runs (udid, trigger, started_at, status, phase, heartbeat_at) "
                "VALUES (?, ?, ?, 'running', 'starting', ?)",
                (udid, trigger, _now(), _now()),
            )
        except sqlite3.IntegrityError:
            return None
        return cur.lastrowid
