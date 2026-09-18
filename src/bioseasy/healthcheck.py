# SPDX-License-Identifier: GPL-3.0-or-later
"""Container health probes.

Web service: exits 0 when /healthz answers on the configured port.
Worker service (`--worker`): exits 0 when the newest worker heartbeat is recent. Only the worker
writes heartbeats, so the web service cannot make it pass.
"""

import os
import sqlite3
import ssl
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Three missed heartbeats (jobs.HEARTBEAT_INTERVAL is 10 s) before the worker counts as down.
WORKER_STALE_AFTER = timedelta(seconds=30)


def _probe_host() -> str:
    """Where the web server can be reached from inside its own container.

    A wildcard bind (the default 0.0.0.0, or ::) answers on loopback. A specific BIOSEASY_HOST
    does not: bound to a network address, 127.0.0.1 is refused, the web container never turns
    healthy and the worker, which waits for it, never starts.
    """
    host = os.environ.get("BIOSEASY_HOST", "0.0.0.0")  # noqa: S104 - compared, never bound here
    if host in ("", "0.0.0.0", "::"):  # noqa: S104
        return "127.0.0.1"
    return f"[{host}]" if ":" in host else host


def _serves_tls() -> bool:
    """Whether the web server speaks HTTPS, by the same settings that switch it on (__init__.py)."""
    return bool(os.environ.get("BIOSEASY_TLS", "").strip())


def web() -> int:
    # With BIOSEASY_TLS set the server answers only HTTPS, so a plain-HTTP probe gets its connection
    # closed, the web container never turns healthy, and the worker - which waits for it - never
    # starts at all.
    scheme = "https" if _serves_tls() else "http"
    url = f"{scheme}://{_probe_host()}:{os.environ.get('BIOSEASY_PORT', '8080')}/healthz"
    # The probe asks the server it runs next to whether it is up. The certificate is made for the
    # names the server is opened at, never for the loopback address the probe uses, and verifying
    # it here would prove nothing about liveness - so this one local request skips verification.
    context = ssl._create_unverified_context() if scheme == "https" else None  # noqa: S323  nosemgrep
    try:
        with urllib.request.urlopen(url, timeout=3, context=context) as response:  # noqa: S310 - fixed local URL  nosemgrep: dynamic-urllib-use-detected
            return 0 if response.status == 200 else 1
    except OSError as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1


def worker(data_dir: Path | None = None, now: datetime | None = None) -> int:
    data_dir = data_dir or Path(os.environ.get("BIOSEASY_DATA_DIR", "/data"))
    db_path = data_dir / "bioseasy.db"
    if not db_path.is_file():
        print(f"healthcheck failed: no database at {db_path}", file=sys.stderr)
        return 1
    try:
        # mode=ro: a probe must never create or change the database it inspects.
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3)
        try:
            row = conn.execute("SELECT max(heartbeat_at) FROM workers").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        print(f"healthcheck failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    if not row or not row[0]:
        print("healthcheck failed: no worker heartbeat yet", file=sys.stderr)
        return 1
    beat = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
    age = (now or datetime.now(UTC)) - beat
    if age > WORKER_STALE_AFTER:
        print(f"healthcheck failed: last worker heartbeat {int(age.total_seconds())} s ago", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    return worker() if args[:1] == ["--worker"] else web()


if __name__ == "__main__":
    sys.exit(main())
