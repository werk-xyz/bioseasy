# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import closing
from datetime import UTC, datetime, timedelta

from bioseasy import db, healthcheck

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def _beat(data_dir, when):
    with closing(db.connect(data_dir / "bioseasy.db")) as conn:
        db.migrate(conn)
        conn.execute(
            "INSERT INTO workers (id, heartbeat_at) VALUES ('w1', ?) "
            "ON CONFLICT(id) DO UPDATE SET heartbeat_at = excluded.heartbeat_at",
            (when.strftime("%Y-%m-%dT%H:%M:%SZ"),),
        )


def test_worker_is_healthy_only_with_a_recent_heartbeat(tmp_path):
    _beat(tmp_path, NOW - timedelta(seconds=5))
    assert healthcheck.worker(tmp_path, now=NOW) == 0
    _beat(tmp_path, NOW - timedelta(seconds=45))
    assert healthcheck.worker(tmp_path, now=NOW) == 1


def test_worker_without_any_heartbeat_is_unhealthy(tmp_path):
    with closing(db.connect(tmp_path / "bioseasy.db")) as conn:
        db.migrate(conn)
    assert healthcheck.worker(tmp_path, now=NOW) == 1


def test_probe_never_creates_a_missing_database(tmp_path):
    assert healthcheck.worker(tmp_path, now=NOW) == 1
    assert not (tmp_path / "bioseasy.db").exists()


def test_main_dispatches_on_the_worker_flag(monkeypatch):
    monkeypatch.setattr(healthcheck, "worker", lambda *a, **k: 7)
    monkeypatch.setattr(healthcheck, "web", lambda: 3)
    assert healthcheck.main(["--worker"]) == 7
    assert healthcheck.main([]) == 3


def test_web_probe_follows_a_specific_bind_address(monkeypatch):
    seen = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout, context=None):
        seen.append(url)
        return Response()

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("BIOSEASY_PORT", "8080")
    cases = (
        ("0.0.0.0", "127.0.0.1"),  # noqa: S104 - a bind value under test, nothing is bound
        ("::", "127.0.0.1"),
        ("192.0.2.4", "192.0.2.4"),
        ("fd00::4", "[fd00::4]"),
    )
    for host, expected in cases:
        monkeypatch.setenv("BIOSEASY_HOST", host)
        assert healthcheck.web() == 0
        assert seen[-1] == f"http://{expected}:8080/healthz"


def test_web_probe_speaks_https_when_the_server_does(tmp_path, monkeypatch):
    """Against a real TLS server with a self-signed certificate made for other names: the probe must
    answer healthy. With plain HTTP here the web service never turned healthy under BIOSEASY_TLS,
    and the worker, which waits for it, never started."""
    import http.server
    import ssl
    import threading

    from bioseasy import tlscert

    cert, key = tlscert.generate(tmp_path / "tls", ["backup.example.net"])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/healthz" else 404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("BIOSEASY_HOST", "0.0.0.0")  # noqa: S104 - a bind value under test
        monkeypatch.setenv("BIOSEASY_PORT", str(server.server_address[1]))
        monkeypatch.setenv("BIOSEASY_TLS", "self-signed")
        assert healthcheck.web() == 0
        monkeypatch.delenv("BIOSEASY_TLS")
        assert healthcheck.web() == 1  # plain HTTP against the same server: the old failure
    finally:
        server.shutdown()
