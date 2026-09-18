# SPDX-License-Identifier: GPL-3.0-or-later
"""bioseasy: self-hosted Wi-Fi backups for iPhone and iPad."""

import argparse
import logging
import os
import sys

log = logging.getLogger("bioseasy")


def main() -> None:
    parser = argparse.ArgumentParser(prog="bioseasy")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the web server (default when no command is given)")
    sub.add_parser("worker", help="Run the Huey consumer that executes background tasks")
    diagnose = sub.add_parser("diagnose", help="Print a report safe to paste into a public bug report")
    diagnose.add_argument("--no-discover", action="store_true", help="Skip live device discovery")
    diagnose.add_argument("--json", action="store_true", help="Print the report as JSON instead of text")
    args = parser.parse_args()

    if args.command == "diagnose":
        sys.exit(_diagnose(discover=not args.no_discover, as_json=args.json))
    if args.command == "worker":
        _worker()
        return
    _serve()


def _tls_arguments() -> dict:
    """The certificate and key to serve with, or nothing at all.

    Off by default, because the documented setup puts a reverse proxy in front and that proxy
    should own TLS. `BIOSEASY_TLS=self-signed` is for an installation with no proxy: the container
    makes its own certificate on first start and renews it before it expires. The names it is made
    for have to be said out loud - a certificate for a name nobody uses matches nothing, and a
    browser cannot be told to trust it either.

    Read from the environment here rather than through Settings, the same way host, port and the
    forwarded-header setting are: this runs before the application is built.
    """
    mode = os.environ.get("BIOSEASY_TLS", "").strip().lower()
    if mode in ("", "off", "false", "none"):
        return {}

    certfile, keyfile = os.environ.get("BIOSEASY_TLS_CERT"), os.environ.get("BIOSEASY_TLS_KEY")
    if certfile and keyfile:
        return {"ssl_certfile": certfile, "ssl_keyfile": keyfile}

    if mode != "self-signed":
        raise SystemExit(
            f"BIOSEASY_TLS={mode!r} is not a setting. Use 'self-signed', or give "
            "BIOSEASY_TLS_CERT and BIOSEASY_TLS_KEY to serve a certificate you already have."
        )

    from pathlib import Path as _Path  # noqa: PLC0415 - only needed on this path

    from . import tlscert  # noqa: PLC0415

    names = tlscert.parse_names(os.environ.get("BIOSEASY_TLS_NAMES", ""))
    if not names:
        raise SystemExit(
            "BIOSEASY_TLS=self-signed needs BIOSEASY_TLS_NAMES: the host names and IP addresses "
            "bioseasy is opened at, comma separated, for example "
            "'backup.lan,192.168.1.10'. A certificate that carries none of the names in use is "
            "rejected by every browser, so there is nothing sensible to generate without them."
        )
    directory = _Path(os.environ.get("BIOSEASY_TLS_DIR") or os.environ.get("BIOSEASY_DATA_DIR", "/data")) / "tls"
    certfile, keyfile = tlscert.ensure(directory, names)
    return {"ssl_certfile": str(certfile), "ssl_keyfile": str(keyfile)}


def _serve() -> None:
    import uvicorn

    uvicorn.run(
        "bioseasy.app:asgi",
        factory=True,
        # All interfaces by default: the container is reached from the LAN; BIOSEASY_HOST narrows it.
        host=os.environ.get("BIOSEASY_HOST", "0.0.0.0"),  # noqa: S104
        port=int(os.environ.get("BIOSEASY_PORT", "8080")),
        proxy_headers=True,
        **_tls_arguments(),
        # X-Forwarded-Proto/-For are honoured only from these addresses. uvicorn's default is
        # 127.0.0.1, so a reverse proxy on another host (or a container network gateway) made
        # HTTPS requests look like plain HTTP. Comma-separated IPs, or "*" when only the proxy can
        # reach the port.
        forwarded_allow_ips=os.environ.get("BIOSEASY_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )


def _worker() -> None:
    """Run the Huey consumer programmatically (no shell wrapper): builds the Runtime and its
    Huey/tasks from Settings (runtime.py, tasks.py), migrates and sweeps orphaned runs the same
    way the web process's lifespan does on startup (app.py), then blocks running tasks until a
    signal stops it (huey.consumer.Consumer.run, called via Huey.create_consumer).
    """
    from contextlib import closing

    from . import activity, db, logview, runtime, tasks
    from .config import load
    from .jobs import sweep_orphan_runs

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load()
    rt = runtime.build(settings, worker_id="huey-worker")
    built = tasks.build(rt)
    with closing(rt.connect()) as conn:
        db.migrate(conn)
        swept = sweep_orphan_runs(conn)
        if swept:
            log.warning("worker startup: failed %d run(s) left running by a worker that did not come back", swept)
        activity.sweep_stale(conn)
    # After migrate: log_entries only exists from here on; any WARNING logged during startup
    # above (load(), runtime.build()) is not lost, only not captured in the log view - it still
    # reached the container log through basicConfig.
    logview.install(rt.connect, "worker")
    rt.jobs.start_heartbeat()
    try:
        # Single thread worker: JobManager already runs each backup in its own daemon thread
        # regardless of which huey worker thread called jobs.start(), so there is nothing to
        # gain from more Huey workers here, only more concurrent tasks contending for the same
        # SQLite connections.
        consumer = built.huey.create_consumer(workers=1, worker_type="thread")
        consumer.run()
    finally:
        rt.jobs.stop_heartbeat()


def _diagnose(discover: bool, as_json: bool) -> int:
    import json

    from . import diagnostics
    from .config import load
    from .runtime import make_engine

    settings = load()
    connect = diagnostics.readonly_connector(settings.data_dir / "bioseasy.db")
    # Building the real engine can touch the host's USB or network stack; only do it when the
    # caller actually asked for discovery.
    engine = make_engine(settings, fixed_hosts=lambda: {}) if discover else None
    report = diagnostics.collect(settings, connect, engine, discover=discover)

    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(diagnostics.render_text(report))

    return 0 if report["storage"]["ok"] else 1
