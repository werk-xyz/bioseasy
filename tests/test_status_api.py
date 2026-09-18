# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import logging
import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import api, auth, db, tokens
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

# tokens.py:_parse() cannot be re-derived with a naive str.split("_") here: the random prefix
# and secret both come from the base64url alphabet, which includes "_", so either one can
# contain it. Splitting the full token in tests uses the same fixed lengths tokens.py itself
# relies on (and asserts at import time), not a search for the separator character.
_PREFIX_LEN, _SECRET_LEN = tokens._PREFIX_LEN, tokens._SECRET_LEN

PHONE, TABLET = DEMO_DEVICES
PASSWORD = "correct horse battery"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def add_device(conn, device, owner_id):
    conn.execute(
        "INSERT INTO devices (udid, name, product_type, os_version, owner_id, interval_hours, overdue_days) "
        "VALUES (?, ?, ?, ?, ?, 24, 3)",
        (device.udid, device.name, device.product_type, device.os_version, owner_id),
    )


def issue_token(settings, username: str, scope: str = tokens.SCOPE_READ) -> str:
    """Creates a token for `username` directly in the database, bypassing the web UI. Used by
    tests that only care about the API's own behaviour, not the account page flow."""
    with conn_for(settings) as conn:
        user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        issued = tokens.create(conn, user_id, "test token", scope)
    return issued.token


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def split_token(full_token: str) -> tuple[str, str]:
    body = full_token[len("bse_") :]
    return body[:_PREFIX_LEN], body[_PREFIX_LEN + 1 :]


def test_migration_creates_the_api_tokens_table(tmp_path):
    conn = db.connect(tmp_path / "app.db")
    db.migrate(conn)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(api_tokens)")}
    assert columns == {
        "id",
        "user_id",
        "name",
        "prefix",
        "secret_hash",
        "scope",
        "created_at",
        "last_used_at",
        "revoked_at",
    }
    conn.close()


def test_health_needs_no_auth(env):
    client, _ = env
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_openapi_schema_is_served_for_the_api_only(env):
    client, _ = env
    r = client.get("/api/v1/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/devices" in paths and "/devices/{udid}" in paths
    # The main app keeps interactive docs off, as before.
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_token_hash_is_stored_never_the_secret(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    full_token = issue_token(settings, "alice")
    _, secret = split_token(full_token)

    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM api_tokens").fetchone()
    assert row["secret_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in row["secret_hash"]
    assert full_token not in row["secret_hash"]


def test_token_is_shown_once_on_the_account_page(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "alice")

    r = client.post("/settings/tokens", data={"csrf": csrf(client, "/settings"), "name": "Home Assistant"})
    assert r.status_code == 200
    match = re.search(r"bse_[A-Za-z0-9_-]+", r.text)
    assert match, "the created token must appear once, right after creation"
    full_token = match.group(0)

    # A second load of the same page must not carry it again: only the hash is ever stored.
    again = client.get("/settings/tokens").text
    assert full_token not in again
    assert "Home Assistant" in again  # the token's name (not the secret) is listed permanently


def test_token_create_rejects_empty_name(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "alice")
    r = client.post("/settings/tokens", data={"csrf": csrf(client, "/settings"), "name": "  "})
    assert r.status_code == 400
    assert "1 to 64 characters" in r.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM api_tokens").fetchone() is None


def test_member_token_lists_only_their_own_device(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
        add_device(conn, TABLET, bob.id)
    alice_token = issue_token(settings, "alice")

    r = client.get("/api/v1/devices", headers=bearer(alice_token))
    assert r.status_code == 200
    assert [d["udid"] for d in r.json()] == [PHONE.udid]

    r = client.get(f"/api/v1/devices/{PHONE.udid}", headers=bearer(alice_token))
    assert r.status_code == 200
    assert r.json()["udid"] == PHONE.udid


def test_pair_days_unused_is_in_the_api_json_and_scoped_like_everything_else(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
        add_device(conn, TABLET, bob.id)
        conn.execute(
            "UPDATE devices SET paired_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-25 days') WHERE udid = ?",
            (PHONE.udid,),
        )
    alice_token = issue_token(settings, "alice")

    own = client.get(f"/api/v1/devices/{PHONE.udid}", headers=bearer(alice_token))
    assert own.status_code == 200
    assert own.json()["pair_days_unused"] == 25

    # A member cannot see a foreign device's state at all - same 404 body as a udid that does
    # not exist, so pair_days_unused (or anything else) never leaks through a different status
    # code or response shape (app.py's visible_device / status.for_owner).
    foreign = client.get(f"/api/v1/devices/{TABLET.udid}", headers=bearer(alice_token))
    missing = client.get("/api/v1/devices/does-not-exist", headers=bearer(alice_token))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    assert "pair_days_unused" not in foreign.text


def test_member_gets_404_for_a_foreign_device_and_for_a_nonexistent_one_with_the_same_body(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
        add_device(conn, TABLET, bob.id)
    alice_token = issue_token(settings, "alice")

    foreign = client.get(f"/api/v1/devices/{TABLET.udid}", headers=bearer(alice_token))
    missing = client.get("/api/v1/devices/does-not-exist", headers=bearer(alice_token))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_admin_token_lists_every_device(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        member = auth.create_user(conn, "member", PASSWORD, "member")
        add_device(conn, PHONE, admin.id)
        add_device(conn, TABLET, member.id)
    admin_token = issue_token(settings, "admin")

    r = client.get("/api/v1/devices", headers=bearer(admin_token))
    assert r.status_code == 200
    assert {d["udid"] for d in r.json()} == {PHONE.udid, TABLET.udid}


def test_revoked_token_is_refused(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice")
    assert client.get("/api/v1/devices", headers=bearer(token)).status_code == 200

    with conn_for(settings) as conn:
        row = conn.execute("SELECT id FROM api_tokens").fetchone()
        assert tokens.revoke(conn, alice.id, row["id"])

    r = client.get("/api/v1/devices", headers=bearer(token))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer bse_not_a_real_token"},
        {"Authorization": "Bearer " + "x" * 500},
    ],
)
def test_malformed_or_missing_header_is_401(env, headers):
    client, _ = env
    r = client.get("/api/v1/devices", headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_unknown_token_gets_the_same_body_as_a_malformed_one(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    real = issue_token(settings, "alice")
    _, secret = split_token(real)
    unknown = f"bse_{'z' * _PREFIX_LEN}_{secret}"  # well-formed, but no such prefix is issued

    malformed_body = client.get("/api/v1/devices", headers=bearer("garbage")).json()
    unknown_body = client.get("/api/v1/devices", headers=bearer(unknown)).json()
    assert malformed_body == unknown_body


def test_session_cookie_without_a_bearer_token_is_401(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")  # the client now carries a valid session cookie
    r = client.get("/api/v1/devices")  # no Authorization header at all
    assert r.status_code == 401


def _freeze_limiter_clock(monkeypatch):
    # The limiter counts in whole-minute windows of time.monotonic(); 61 real requests that cross
    # a minute boundary start a fresh window and the 61st passes. That made CI red once on a slow
    # runner, so the clock stands still inside one window for these tests.
    monkeypatch.setattr(api, "_clock", lambda: 1_000_020.0)


def test_rate_limit_returns_429_with_retry_after(env, monkeypatch):
    _freeze_limiter_clock(monkeypatch)
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice")

    statuses = [client.get("/api/v1/devices", headers=bearer(token)).status_code for _ in range(60)]
    assert statuses == [200] * 60

    r = client.get("/api/v1/devices", headers=bearer(token))
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0


def test_unauthenticated_flood_is_rate_limited_too(env, monkeypatch):
    _freeze_limiter_clock(monkeypatch)
    client, _ = env
    statuses = [client.get("/api/v1/devices", headers=bearer("garbage")).status_code for _ in range(60)]
    assert statuses == [401] * 60
    r = client.get("/api/v1/devices", headers=bearer("garbage"))
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "BeArEr"])
def test_bearer_scheme_name_is_case_insensitive(env, scheme):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice")
    r = client.get("/api/v1/devices", headers={"Authorization": f"{scheme} {token}"})
    assert r.status_code == 200


def test_revoke_of_another_users_token_is_404(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
        auth.create_user(conn, "bob", PASSWORD, "member")
    with conn_for(settings) as conn:
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        alice_token_row = tokens.create(conn, alice_id, "alice's token")

    client.cookies.clear()
    login(client, "bob")
    r = client.post(f"/settings/tokens/{alice_token_row.id}/revoke", data={"csrf": csrf(client, "/settings")})
    assert r.status_code == 404
    with conn_for(settings) as conn:
        row = conn.execute("SELECT revoked_at FROM api_tokens WHERE id = ?", (alice_token_row.id,)).fetchone()
    assert row["revoked_at"] is None


def test_revoke_of_own_token_redirects_and_takes_effect(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "alice")
    client.post("/settings/tokens", data={"csrf": csrf(client, "/settings"), "name": "to revoke"})
    with conn_for(settings) as conn:
        token_id = conn.execute("SELECT id FROM api_tokens").fetchone()["id"]

    r = client.post(f"/settings/tokens/{token_id}/revoke", data={"csrf": csrf(client, "/settings")})
    assert r.status_code == 303
    # Back to the page the token was revoked from, not to the password page.
    assert r.headers["location"] == "/settings/tokens"
    with conn_for(settings) as conn:
        row = conn.execute("SELECT revoked_at FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
    assert row["revoked_at"] is not None


def test_token_never_appears_in_captured_logs(env, caplog):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    login(client, "alice")

    with caplog.at_level(logging.DEBUG):
        r = client.post("/settings/tokens", data={"csrf": csrf(client, "/settings"), "name": "logged?"})
        full_token = re.search(r"bse_[A-Za-z0-9_-]+", r.text).group(0)
        _, secret = split_token(full_token)
        client.get("/settings")
        client.get("/api/v1/devices", headers=bearer(full_token))
        with conn_for(settings) as conn:
            token_id = conn.execute("SELECT id FROM api_tokens").fetchone()["id"]
        client.post(f"/settings/tokens/{token_id}/revoke", data={"csrf": csrf(client, "/settings")})
        client.get("/api/v1/devices", headers=bearer(full_token))

    for record in caplog.records:
        text = record.getMessage()
        assert full_token not in text
        assert secret not in text


# --- POST /api/v1/devices/{udid}/backup (start a backup from iOS Shortcuts) ---------------------


def test_read_only_token_cannot_start_a_backup(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice", tokens.SCOPE_READ)

    r = client.post(f"/api/v1/devices/{PHONE.udid}/backup", headers=bearer(token))
    assert r.status_code == 403
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM runs WHERE udid = ?", (PHONE.udid,)).fetchone() is None


def test_backup_scope_token_starts_a_backup_and_it_is_really_enqueued(env, monkeypatch):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice", tokens.SCOPE_BACKUP)

    enqueued = []
    original_enqueue = client.app.state.huey.enqueue

    def spy(task):
        enqueued.append(task)
        return original_enqueue(task)

    monkeypatch.setattr(client.app.state.huey, "enqueue", spy)

    r = client.post(f"/api/v1/devices/{PHONE.udid}/backup", headers=bearer(token))
    assert r.status_code == 202
    assert r.json()["udid"] == PHONE.udid
    assert len(enqueued) == 1  # the API route really goes through Huey, same as "Back up now"
    with conn_for(settings) as conn:
        row = conn.execute("SELECT trigger FROM runs WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["trigger"] == "api"


def test_backup_scope_token_gets_404_for_a_foreign_device(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        add_device(conn, TABLET, bob.id)
    token = issue_token(settings, "alice", tokens.SCOPE_BACKUP)

    r = client.post(f"/api/v1/devices/{TABLET.udid}/backup", headers=bearer(token))
    assert r.status_code == 404
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM runs WHERE udid = ?", (TABLET.udid,)).fetchone() is None


def test_backup_scope_token_gets_409_when_a_backup_is_already_running(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase, percent) "
            "VALUES (?, 'manual', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'running', 'copying', 10.0)",
            (PHONE.udid,),
        )
    token = issue_token(settings, "alice", tokens.SCOPE_BACKUP)

    r = client.post(f"/api/v1/devices/{PHONE.udid}/backup", headers=bearer(token))
    assert r.status_code == 409
    with conn_for(settings) as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM runs WHERE udid = ?", (PHONE.udid,)).fetchone()["n"]
    assert count == 1  # no second run was started on top of the running one


def test_session_cookie_without_a_bearer_token_cannot_start_a_backup(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        add_device(conn, PHONE, admin.id)
    login(client, "admin")  # the client now carries a valid session cookie, no bearer token
    r = client.post(f"/api/v1/devices/{PHONE.udid}/backup")
    assert r.status_code == 401
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM runs WHERE udid = ?", (PHONE.udid,)).fetchone() is None


def test_start_backup_is_rate_limited_like_the_other_api_routes(env, monkeypatch):
    _freeze_limiter_clock(monkeypatch)
    client, settings = env
    with conn_for(settings) as conn:
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        add_device(conn, PHONE, alice.id)
    token = issue_token(settings, "alice", tokens.SCOPE_BACKUP)

    # 60 plain reads plus this route share the same per-token limiter (60/minute), so the 61st
    # request total already trips it.
    for _ in range(60):
        assert client.get("/api/v1/devices", headers=bearer(token)).status_code == 200
    r = client.post(f"/api/v1/devices/{PHONE.udid}/backup", headers=bearer(token))
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
