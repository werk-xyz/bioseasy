# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser push notifications - the Web Push half.

No real network call anywhere here: pywebpush.webpush is monkeypatched wherever a send is
exercised, and no real browser or push service is contacted. Follows the env/csrf/login fixture
shape test_user_management.py and test_connectors.py already use.
"""

import re
import stat
from contextlib import closing
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pywebpush import WebPushException

from bioseasy import auth, db, webpush
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600, schedule_minutes=0)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username, password=PASSWORD):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": password})
    assert r.status_code == 303 and r.headers["location"] == "/"


def logout(client):
    client.post("/logout", data={"csrf": csrf(client, "/settings")})


def _sub(n=1):
    return webpush.Subscription(endpoint=f"https://push.example/ep{n}", p256dh=f"p256dh{n}", auth=f"auth{n}")


# --- VAPID key file ------------------------------------------------------------------------------


def test_key_file_created_with_owner_only_permissions(tmp_path):
    assert webpush.vapid_status(tmp_path) is True
    mode = stat.S_IMODE((tmp_path / "vapid_key.pem").stat().st_mode)
    assert mode == 0o600


def test_key_is_reused_across_calls(tmp_path):
    webpush.vapid_status(tmp_path)
    first = (tmp_path / "vapid_key.pem").read_bytes()
    webpush.vapid_status(tmp_path)
    assert (tmp_path / "vapid_key.pem").read_bytes() == first


def test_public_key_is_a_url_safe_uncompressed_point(tmp_path):
    key = webpush.public_key_b64url(tmp_path)
    assert key is not None
    assert "+" not in key and "/" not in key  # base64url, not base64


def test_missing_key_file_disables_the_feature_instead_of_crashing(tmp_path):
    """No key file, and it cannot be created (tmp_path itself removed): vapid_status and
    public_key_b64url both read as "disabled", not an exception -- the same contract
    connectors.decrypt_secret documents for a missing connector.key, applied the other way
    (webpush never raises here; it is fine for a feature nobody set up correctly to just be off).
    """
    unwritable = tmp_path / "does-not-exist"
    assert webpush.vapid_status(unwritable) is False
    assert webpush.public_key_b64url(unwritable) is None


def test_corrupt_key_file_disables_the_feature_instead_of_crashing(tmp_path):
    (tmp_path / "vapid_key.pem").write_bytes(b"not a key")
    assert webpush.vapid_status(tmp_path) is False


# --- sending: no crash, no-op when nothing is set up ----------------------------------------------


def test_sending_with_no_vapid_key_is_a_silent_no_op(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        auth.create_user(conn, "admin", PASSWORD, "admin")
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path / "missing", {1}, "title", "body")
    mock_send.assert_not_called()


def test_sending_with_no_subscriptions_is_a_silent_no_op(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        auth.create_user(conn, "admin", PASSWORD, "admin")
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path, {1}, "title", "body")
    mock_send.assert_not_called()


def test_sending_to_no_users_is_a_silent_no_op(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path, set(), "title", "body")
    mock_send.assert_not_called()


# --- sending: failures never propagate ------------------------------------------------------------


def test_a_send_exception_never_propagates(tmp_path):
    """A broken third-party push service must never fail the caller -- the guarantee
    runtime.py's notify_event relies on to never let a notification delay or fail a backup."""
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        with patch("bioseasy.webpush.webpush", side_effect=RuntimeError("boom")):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")  # must not raise
        # the broken subscription is not touched (only 404/410 removes it), so it is still there
        assert len(webpush.list_for_user(conn, user_id)) == 1


def test_410_gone_removes_the_subscription(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("gone", response=_FakeResponse(410))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert webpush.list_for_user(conn, user_id) == []


def test_404_also_removes_the_subscription(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("not found", response=_FakeResponse(404))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert webpush.list_for_user(conn, user_id) == []


def test_other_status_codes_keep_the_subscription(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("server error", response=_FakeResponse(500))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert len(webpush.list_for_user(conn, user_id)) == 1


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code
        self.text = ""


# --- delivery outcome is recorded honestly, per user (users.last_push_ok/error/at) ----------------


def test_no_subscriptions_is_not_recorded_as_a_failure(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        mock_send.assert_not_called()
        status = webpush.push_delivery_status(conn, user_id)
    assert status["last_push_ok"] is None
    assert status["last_push_error"] is None


def test_a_gone_subscription_is_removed_without_being_reported_as_a_failure(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("gone", response=_FakeResponse(410))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert webpush.list_for_user(conn, user_id) == []
        status = webpush.push_delivery_status(conn, user_id)
    assert status["last_push_ok"] is None  # not touched: a removed subscription is not a failure


def test_every_subscription_failing_is_recorded_as_a_failure(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub(1))
        webpush.save_subscription(conn, user_id, _sub(2))
        exc = WebPushException("server error", response=_FakeResponse(500))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        status = webpush.push_delivery_status(conn, user_id)
    assert status["last_push_ok"] == 0
    assert status["last_push_error"] == webpush._PUSH_FAILURE_MESSAGE
    assert "server error" not in status["last_push_error"]  # never the push service's own text
    assert status["last_push_at"] is not None


def test_at_least_one_subscription_reached_is_recorded_as_ok(tmp_path):
    """A user with two browsers, one broken and one working: reaching either one counts as
    delivered, the same "any target reached" shape notify.send already gives Apprise's several
    URLs."""
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub(1))
        webpush.save_subscription(conn, user_id, _sub(2))
        exc = WebPushException("server error", response=_FakeResponse(500))
        with patch("bioseasy.webpush.webpush", side_effect=[exc, None]):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        status = webpush.push_delivery_status(conn, user_id)
    assert status["last_push_ok"] == 1
    assert status["last_push_error"] is None


def test_a_successful_send_clears_a_previous_failure(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("server error", response=_FakeResponse(500))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert webpush.push_delivery_status(conn, user_id)["last_push_ok"] == 0
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path, {user_id}, "title", "body")
        assert mock_send.call_count == 1
        status = webpush.push_delivery_status(conn, user_id)
    assert status["last_push_ok"] == 1
    assert status["last_push_error"] is None


def test_account_page_shows_a_notice_only_for_a_confirmed_failure(env):
    client, settings = env
    with conn_for(settings) as conn:
        user_id = auth.create_user(conn, "alice", PASSWORD, "admin").id
    login(client, "alice")
    notifications = "/settings/notifications"  # its own page
    assert "could not be delivered" not in client.get(notifications).text  # nothing attempted yet

    with conn_for(settings) as conn:
        webpush.save_subscription(conn, user_id, _sub())
        exc = WebPushException("server error", response=_FakeResponse(500))
        with patch("bioseasy.webpush.webpush", side_effect=exc):
            webpush.send_to_users(conn, settings.data_dir, {user_id}, "title", "body")
    page = client.get(notifications).text
    assert "could not be delivered" in page
    assert "server error" not in page  # never the push service's own response text
    assert "https://push.example" not in page  # never the endpoint


def test_a_successful_send_reaches_pywebpush_with_the_stored_keys(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        webpush.save_subscription(conn, user_id, _sub())
        with patch("bioseasy.webpush.webpush") as mock_send:
            webpush.send_to_users(conn, tmp_path, {user_id}, "Backup failed", "detail text")
        assert mock_send.call_count == 1
        kwargs = mock_send.call_args.kwargs
        assert kwargs["subscription_info"]["endpoint"] == "https://push.example/ep1"
        assert kwargs["subscription_info"]["keys"] == {"p256dh": "p256dh1", "auth": "auth1"}
        assert "Backup failed" in kwargs["data"]


# --- save_subscription: an endpoint cannot be rebound to a different user ------------------------


def test_resubscribe_by_the_same_user_refreshes_keys_and_label(tmp_path):
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        user_id = auth.create_user(conn, "alice", PASSWORD, "member").id
        webpush.save_subscription(conn, user_id, _sub(), "Old label")
        refreshed = webpush.Subscription(endpoint=_sub().endpoint, p256dh="new-p256dh", auth="new-auth")
        webpush.save_subscription(conn, user_id, refreshed, "New label")
        rows = webpush.list_for_user(conn, user_id)
    assert len(rows) == 1
    assert rows[0]["p256dh"] == "new-p256dh"
    assert rows[0]["auth"] == "new-auth"
    assert rows[0]["label"] == "New label"


def test_save_subscription_refuses_to_rebind_another_users_endpoint(tmp_path):
    """A signed-in user who knows another user's push endpoint URL must not be able to take it
    over by posting it as their own."""
    with closing(db.connect(tmp_path / "app.db")) as conn:
        db.migrate(conn)
        alice_id = auth.create_user(conn, "alice", PASSWORD, "member").id
        bob_id = auth.create_user(conn, "bob", PASSWORD, "member").id
        webpush.save_subscription(conn, alice_id, _sub())
        with pytest.raises(webpush.ForeignSubscriptionError):
            webpush.save_subscription(conn, bob_id, _sub())
        # Alice's subscription is untouched: still hers, still with the original keys.
        rows = webpush.list_for_user(conn, alice_id)
    assert len(rows) == 1
    assert rows[0]["p256dh"] == "p256dh1"


# --- account.html routes: opt-in, list, revoke, scoped per user ----------------------------------


def test_subscribe_stores_a_subscription_for_the_signed_in_user(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "admin")
    login(client, "alice")
    token = csrf(client, "/settings")
    data = {"csrf": token, "endpoint": "https://push.example/e1", "p256dh": "k1", "auth": "a1", "label": "Test browser"}
    r = client.post("/settings/notifications/push/subscribe", data=data)
    assert r.status_code == 200
    assert "Test browser" in r.text
    with conn_for(settings) as conn:
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        rows = webpush.list_for_user(conn, alice_id)
    assert len(rows) == 1
    assert rows[0]["endpoint"] == "https://push.example/e1"


def test_subscribe_route_lets_the_same_user_resubscribe(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "alice")
    data = {"csrf": csrf(client, "/settings"), "endpoint": "https://push.example/e1", "p256dh": "k1", "auth": "a1"}
    r1 = client.post("/settings/notifications/push/subscribe", data=data)
    assert r1.status_code == 200
    data2 = {"csrf": csrf(client, "/settings"), "endpoint": "https://push.example/e1", "p256dh": "k2", "auth": "a2"}
    r2 = client.post("/settings/notifications/push/subscribe", data=data2)
    assert r2.status_code == 200
    with conn_for(settings) as conn:
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        rows = webpush.list_for_user(conn, alice_id)
    assert len(rows) == 1
    assert rows[0]["p256dh"] == "k2"


def test_subscribe_route_refuses_to_take_over_another_users_endpoint(env):
    client, settings = env
    with conn_for(settings) as conn:
        alice_id = auth.create_user(conn, "alice", PASSWORD, "member").id
        auth.create_user(conn, "bob", PASSWORD, "member")
        webpush.save_subscription(conn, alice_id, webpush.Subscription("https://push.example/shared", "k1", "a1"))

    login(client, "bob")
    data = {"csrf": csrf(client, "/settings"), "endpoint": "https://push.example/shared", "p256dh": "k9", "auth": "a9"}
    r = client.post("/settings/notifications/push/subscribe", data=data)
    assert r.status_code == 409

    with conn_for(settings) as conn:
        rows = webpush.list_for_user(conn, alice_id)
        bob_id = conn.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()["id"]
        assert webpush.list_for_user(conn, bob_id) == []
    assert len(rows) == 1
    assert rows[0]["p256dh"] == "k1"  # alice's subscription is untouched


def test_subscribe_with_missing_fields_is_400(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "admin")
    login(client, "alice")
    token = csrf(client, "/settings")
    r = client.post(
        "/settings/notifications/push/subscribe", data={"csrf": token, "endpoint": "https://push.example/e1"}
    )
    assert r.status_code == 400


def test_a_member_can_never_see_another_users_subscription(env):
    """Per-user scoping: subscriptions are listed only for the signed-in user's own account,
    exactly like API tokens (tokens.list_for_user) -- two real users, not a monkeypatched check."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
        auth.create_user(conn, "bob", PASSWORD, "member")
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        webpush.save_subscription(conn, alice_id, _sub(), "Alice test phone")

    # Both halves move together, or this would stop proving anything: the point is that Bob does
    # not see Alice's subscription on the page where subscriptions are actually listed.
    login(client, "bob")
    assert "Alice test phone" not in client.get("/settings/notifications").text
    logout(client)

    login(client, "alice")
    assert "Alice test phone" in client.get("/settings/notifications").text


def test_a_member_cannot_revoke_another_users_subscription(env):
    """Revoke must be scoped to webpush.revoke(conn, user.id, subscription_id), the same shape as
    tokens.revoke: without the user_id filter a member could revoke another user's subscription."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
        auth.create_user(conn, "bob", PASSWORD, "member")
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        webpush.save_subscription(conn, alice_id, _sub())
        sub_id = webpush.list_for_user(conn, alice_id)[0]["id"]

    login(client, "bob")
    token = csrf(client, "/settings")
    r = client.post(f"/settings/notifications/push/{sub_id}/revoke", data={"csrf": token})
    assert r.status_code == 404

    with conn_for(settings) as conn:
        assert len(webpush.list_for_user(conn, alice_id)) == 1  # still there, bob did not touch it


def test_owner_can_revoke_their_own_subscription(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
        webpush.save_subscription(conn, alice_id, _sub())
        sub_id = webpush.list_for_user(conn, alice_id)[0]["id"]

    login(client, "alice")
    token = csrf(client, "/settings")
    r = client.post(f"/settings/notifications/push/{sub_id}/revoke", data={"csrf": token})
    assert r.status_code == 303

    with conn_for(settings) as conn:
        assert webpush.list_for_user(conn, alice_id) == []


def test_revoking_an_unknown_id_is_404(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "alice")
    token = csrf(client, "/settings")
    r = client.post("/settings/notifications/push/99999/revoke", data={"csrf": token})
    assert r.status_code == 404


# --- runtime.py wiring: an event reaches the device owner and every admin -------------------------


def test_notify_event_sends_push_to_device_owner_and_admins(env):
    from bioseasy.runtime import build as build_runtime

    client, settings = env
    with conn_for(settings) as conn:
        admin_id = auth.create_user(conn, "admin", PASSWORD, "admin").id
        owner_id = auth.create_user(conn, "owner", PASSWORD, "member").id
        webpush.save_subscription(conn, admin_id, _sub(1))
        webpush.save_subscription(conn, owner_id, _sub(2))
        udid = "00008030-000000000000000E"
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES (?, ?, ?)", (udid, "Test iPhone", owner_id))

    runtime = build_runtime(settings, DemoEngine(step_seconds=0))
    with patch("bioseasy.webpush.webpush") as mock_send:
        runtime.notify_event("failed", udid, "boom")
        for t in __import__("threading").enumerate():
            if t.name == f"notify-{udid}":
                t.join(timeout=5)
    endpoints = {c.kwargs["subscription_info"]["endpoint"] for c in mock_send.call_args_list}
    assert endpoints == {"https://push.example/ep1", "https://push.example/ep2"}
