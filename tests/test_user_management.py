# SPDX-License-Identifier: GPL-3.0-or-later
"""Admin-only local user management: /users (list, create, role
change, remove) and the device owner reassignment select on /devices/{udid}/settings/owner.

Follows the same env/csrf/login fixture shape as tests/test_account_password.py and
tests/test_header.py.
"""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
OTHER_PASSWORD = "another correct horse battery"


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


EMAIL_SETTINGS = {
    "label": "Admin mail",
    "host": "smtp.example.com",
    "port": 587,
    "security": "starttls",
    "username": "bioseasy",
    "from_addr": "bioseasy@example.com",
    "to": ["admin@example.com"],
}


def _email_connector(conn, data_dir):
    from bioseasy import connectors

    connectors.create_connector(
        conn,
        scope="admin",
        udid=None,
        kind="email",
        label="Admin mail",
        settings=EMAIL_SETTINGS,
        secret_ciphertext=connectors.encrypt_secret(data_dir, "smtp-password"),
    )


def test_an_account_can_be_created_with_an_email_address(env):
    """The address is optional and never an identity - the account is still addressed by its
    username (SCHEMA_VERSION 19)."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    token = csrf(client, "/admin/users")
    r = client.post(
        "/admin/users",
        data={
            "csrf": token,
            "username": "bob",
            "role": "member",
            "password": OTHER_PASSWORD,
            "email": "bob@example.com",
        },
    )
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT email FROM users WHERE username = 'bob'").fetchone()
    assert row["email"] == "bob@example.com"


def test_an_account_without_an_email_address_is_refused(env):
    """The reverse of what this test asserted before the address became
    mandatory for every account: it is now what a single sign-on identity is matched against, so
    an account without one cannot be reached by single sign-on at all."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    token = csrf(client, "/admin/users")
    r = client.post(
        "/admin/users", data={"csrf": token, "username": "carol", "role": "member", "password": OTHER_PASSWORD}
    )
    assert r.status_code == 400
    assert "email address is required" in r.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM users WHERE username = 'carol'").fetchone() is None


def test_a_malformed_email_is_refused_and_the_form_keeps_what_was_typed(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    token = csrf(client, "/admin/users")
    r = client.post(
        "/admin/users",
        data={
            "csrf": token,
            "username": "dave",
            "role": "member",
            "password": OTHER_PASSWORD,
            "email": "not-an-address",
        },
    )
    assert r.status_code == 400
    assert "valid email address" in r.text
    assert 'value="dave"' in r.text and "not-an-address" in r.text
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM users WHERE username = 'dave'").fetchone() is None


def test_no_invitation_is_built_without_an_email_connector(env):
    """Creating an account never depends on mail being configured: with no connector there is
    simply no URL to send to, and the account is created all the same."""
    from bioseasy import connectors

    client, settings = env
    with conn_for(settings) as conn:
        assert connectors.email_invite_url(conn, settings.data_dir, "bob@example.com") is None


def test_the_invitation_goes_to_the_new_address_not_the_connector_s_own(env):
    """The one place bioseasy mails an address that is in no stored configuration: the connector's
    server and credentials are reused, only the recipient is replaced. The connector's own
    recipients must not receive it."""
    from bioseasy import connectors

    client, settings = env
    with conn_for(settings) as conn:
        _email_connector(conn, settings.data_dir)
        url = connectors.email_invite_url(conn, settings.data_dir, "bob@example.com")

    assert url is not None
    assert "bob%40example.com" in url or "bob@example.com" in url
    assert "admin%40example.com" not in url and "admin@example.com" not in url
    assert "smtp.example.com" in url  # same server as the connector


def login(client, username, password=PASSWORD):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": password})
    assert r.status_code == 303 and r.headers["location"] == "/"


def flash_bad(page_text):
    """The action_error/create_error flash paragraph only - never the per-row "cannot be
    demoted"/"Last remaining admin" helper text users.html always shows next to the last admin's
    own row (class="meta", not "flash bad"), which would otherwise make a loose substring check
    pass even when the route's own guard is broken."""
    match = re.search(r'<p class="flash bad"[^>]*>(.*?)</p>', page_text, re.DOTALL)
    return match.group(1) if match else ""


def logout(client):
    client.post("/logout", data={"csrf": csrf(client, "/settings")})


# --- Guards: admin-only, 404 for members -------------------------------------------------------


def test_users_page_is_404_for_a_member(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    assert client.get("/admin/users").status_code == 404


def test_users_page_and_link_are_reachable_for_an_admin(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    header = re.search(r"<header\b.*?</header>", client.get("/").text, re.DOTALL).group(0)
    # Users sits in the Admin section nav, not in the header itself - what has to
    # hold is that an admin still gets there in two clicks and that the page answers.
    assert re.search(r'href="/admin"[^>]*>Admin<', header)
    assert 'href="/admin/users"' in client.get("/admin").text
    assert client.get("/admin/users").status_code == 200


def test_member_never_sees_the_users_link_in_the_header(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    header = re.search(r"<header\b.*?</header>", client.get("/").text, re.DOTALL).group(0)
    assert "/admin/users" not in header


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/admin/users", {"username": "new", "role": "member", "password": OTHER_PASSWORD}),
        ("/admin/users/1/role", {"role": "member"}),
        ("/admin/users/1/remove", {}),
    ],
)
def test_users_post_routes_are_404_for_a_member(env, path, data):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    # A member has no CSRF token for a page it cannot even load; the guard must still be a 404,
    # never a 403 (csrf_form would 403 first on a forged token, which would leak that the route
    # exists at all - see visible_device's own note on this shape).
    token = csrf(client, "/settings")
    r = client.post(path, data={"csrf": token, **data})
    assert r.status_code == 404


def test_device_owner_reassignment_is_404_for_a_member(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        owner = auth.create_user(conn, "member", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAAA', 'iPhone', ?)", (owner.id,))
    login(client, "member")
    token = csrf(client, "/settings")
    r = client.post("/devices/AAAA/settings/owner", data={"csrf": token, "owner_id": ""})
    assert r.status_code == 404
    # The reassignment section itself must not even render on the member's own device settings page.
    page = client.get("/devices/AAAA/settings").text
    assert "Owner</h2>" not in page
    assert 'name="owner_id"' not in page


# --- List content --------------------------------------------------------------------------


def test_list_shows_username_role_created_and_device_count(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAAA', 'iPhone', ?)", (alice.id,))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('BBBB', 'iPad', ?)", (alice.id,))
    login(client, "admin")
    page = client.get("/admin/users").text
    assert "alice" in page
    assert "Member" in page
    assert "never" in page  # alice has not signed in yet in this test
    row = re.search(r"<tr>\s*<td>alice.*?</tr>", page, re.DOTALL).group(0)
    assert ">2<" in row  # device_count


def test_last_sign_in_is_recorded_on_login_not_on_session_resumption(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "admin")
    page = client.get("/admin/users").text
    row = re.search(r"<tr>\s*<td>alice.*?</tr>", page, re.DOTALL).group(0)
    assert ">never<" in row

    other = TestClient(client.app, follow_redirects=False)
    login(other, "alice")
    other.get("/settings")  # session resumption from the cookie must not bump last_sign_in_at again

    page = client.get("/admin/users").text
    row = re.search(r"<tr>\s*<td>alice.*?</tr>", page, re.DOTALL).group(0)
    assert ">never<" not in row


def test_users_page_names_what_it_can_and_cannot_do_for_sso_users(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/admin/users").text
    # The three facts this page owes an admin looking at an SSO account: it manages roles, it has
    # no password to manage, and where linking actually happens. Asserted on the facts rather than
    # on one phrasing - the previous version demanded the words "Account page", which stopped
    # existing when Account became Settings and survived only because the old
    # sentence happened to still contain them.
    assert "role" in page.lower()
    assert "no password here" in page.lower()
    assert "Settings page" in page


# --- Create ---------------------------------------------------------------------------------


def test_admin_creates_a_member_with_the_password_policy_enforced(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(
        "/admin/users",
        data={"csrf": token, "username": "bob", "role": "member", "password": "short", "email": "bob@example.test"},
    )
    assert r.status_code == 400
    assert "at least" in r.text
    with conn_for(settings) as conn:
        assert auth.authenticate(conn, "bob", "short") is None

    token = csrf(client, "/admin/users")
    r = client.post(
        "/admin/users",
        data={
            "csrf": token,
            "username": "bob",
            "role": "member",
            "password": OTHER_PASSWORD,
            "email": "bob@example.test",
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/admin/users?saved=1"
    with conn_for(settings) as conn:
        bob = auth.authenticate(conn, "bob", OTHER_PASSWORD)
        assert bob is not None and bob.role == "member"


def test_new_user_password_is_never_logged(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/users")
    secret_password = "a very secret onboarding password"
    client.post(
        "/admin/users", data={"csrf": token, "username": "carol", "role": "member", "password": secret_password}
    )
    with conn_for(settings) as conn:
        messages = [r["message"] for r in conn.execute("SELECT message FROM log_entries")]
    assert not any(secret_password in m for m in messages)


# --- Role change: safety rule + session invalidation -----------------------------------------


def test_role_change_ends_the_users_sessions_but_not_the_acting_admins(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "alice", PASSWORD, "member")
    login(client, "admin")

    other = TestClient(client.app, follow_redirects=False)
    login(other, "alice")
    assert other.get("/settings").status_code == 200

    with conn_for(settings) as conn:
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{alice_id}/role", data={"csrf": token, "role": "admin"})
    assert r.status_code == 303 and r.headers["location"] == "/admin/users?saved=1"

    # Alice's existing session is now rejected...
    r_other = other.get("/settings")
    assert r_other.status_code == 303 and r_other.headers["location"] == "/login"
    # ...but the acting admin stays signed in.
    assert client.get("/admin/users").status_code == 200
    with conn_for(settings) as conn:
        assert auth.get_user(conn, alice_id).role == "admin"


def test_the_last_remaining_admin_cannot_be_demoted(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{admin.id}/role", data={"csrf": token, "role": "member"})
    assert r.status_code == 400
    # flash_bad, not a loose page-wide substring: the role column always shows the same "cannot
    # be demoted" sentence as static helper text next to the last admin's row regardless of
    # whether this POST's own guard fired, which would otherwise mask a broken guard as green.
    assert "last remaining admin" in flash_bad(r.text).lower()
    with conn_for(settings) as conn:
        assert auth.get_user(conn, admin.id).role == "admin"


def test_demoting_one_of_two_admins_is_allowed(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        second = auth.create_user(conn, "second", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{second.id}/role", data={"csrf": token, "role": "member"})
    assert r.status_code == 303
    with conn_for(settings) as conn:
        assert auth.get_user(conn, second.id).role == "member"


# --- Removal: safety rules -------------------------------------------------------------------


def test_the_last_remaining_admin_cannot_be_removed(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{admin.id}/remove", data={"csrf": token})
    assert r.status_code == 400
    assert "last remaining admin" in flash_bad(r.text).lower()
    with conn_for(settings) as conn:
        assert auth.get_user(conn, admin.id) is not None


def test_an_admin_cannot_remove_their_own_account_from_this_page(env):
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "second", PASSWORD, "admin")  # so "last admin" is not the blocker here
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{admin.id}/remove", data={"csrf": token})
    assert r.status_code == 400
    assert "own account" in flash_bad(r.text).lower()
    with conn_for(settings) as conn:
        assert auth.get_user(conn, admin.id) is not None


def test_removing_a_user_who_owns_devices_is_refused_with_the_count_then_succeeds_after_reassignment(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAAA', 'iPhone', ?)", (alice.id,))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('BBBB', 'iPad', ?)", (alice.id,))
    login(client, "admin")
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{alice.id}/remove", data={"csrf": token})
    assert r.status_code == 400
    assert "2 devices" in flash_bad(r.text)
    with conn_for(settings) as conn:
        assert auth.get_user(conn, alice.id) is not None

    # Reassign both devices away from alice first, as the error message directs.
    token = csrf(client, "/devices/AAAA/settings")
    r = client.post("/devices/AAAA/settings/owner", data={"csrf": token, "owner_id": ""})
    assert r.status_code == 303
    token = csrf(client, "/devices/BBBB/settings")
    r = client.post("/devices/BBBB/settings/owner", data={"csrf": token, "owner_id": ""})
    assert r.status_code == 303

    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{alice.id}/remove", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == "/admin/users?saved=1"
    with conn_for(settings) as conn:
        assert auth.get_user(conn, alice.id) is None


def test_demoting_an_admin_ends_their_sessions_immediately(env):
    """A demoted admin is signed out, not merely reduced to member rights.

    Two mechanisms overlap here and only one of them was guarded before the other. The role is
    re-read from the database on every request (`auth.session_user` -> `get_user`), never taken
    from the cookie, so a demotion removes admin rights immediately even if nothing else happened.
    On top of that `auth.set_role` bumps `session_version`, which ends the session outright - the
    difference this test pins down: without the bump the demoted admin stays signed in and gets
    404 on an admin page, with it they are sent back to /login.

    `POST /admin/users/{user_id}/role` changes a role, so the session consequence is real and
    needs a guard.
    """
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "carol", PASSWORD, "admin")
    login(client, "admin")

    other = TestClient(client.app, follow_redirects=False)
    login(other, "carol")
    assert other.get("/admin/users").status_code == 200

    with conn_for(settings) as conn:
        carol_id = conn.execute("SELECT id FROM users WHERE username = 'carol'").fetchone()["id"]
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{carol_id}/role", data={"csrf": token, "role": "member"})
    assert r.status_code == 303

    r_other = other.get("/admin/users")
    assert r_other.status_code == 303 and r_other.headers["location"] == "/login"
    # And the session is gone for every page, not only the admin-only one.
    assert other.get("/settings").status_code == 303


def test_removing_a_user_ends_their_sessions_via_cascade(env):
    """Removal deletes the row outright rather than merely bumping session_version, so the
    session lookup fails the same way as any other deleted account (auth.session_user 404s once
    get_user returns None) - proven end to end rather than only at the auth.py unit level."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "bob", PASSWORD, "member")
    login(client, "admin")

    other = TestClient(client.app, follow_redirects=False)
    login(other, "bob")
    assert other.get("/settings").status_code == 200

    with conn_for(settings) as conn:
        bob_id = conn.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()["id"]
    token = csrf(client, "/admin/users")
    client.post(f"/admin/users/{bob_id}/remove", data={"csrf": token})

    r_other = other.get("/settings")
    assert r_other.status_code == 303 and r_other.headers["location"] == "/login"


# --- Device owner reassignment ----------------------------------------------------------------


def test_admin_reassigns_a_device_owner_and_scoping_follows_immediately(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        bob = auth.create_user(conn, "bob", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAAA', 'iPhone', ?)", (alice.id,))
    login(client, "admin")
    page = client.get("/devices/AAAA/settings").text
    assert 'name="owner_id"' in page
    assert f'value="{bob.id}"' in page

    token = csrf(client, "/devices/AAAA/settings")
    r = client.post("/devices/AAAA/settings/owner", data={"csrf": token, "owner_id": str(bob.id)})
    assert r.status_code == 303 and r.headers["location"] == "/devices/AAAA/settings?saved=1"

    login(client, "bob")
    assert "iPhone" in client.get("/").text
    logout(client)
    login(client, "alice")
    assert "iPhone" not in client.get("/").text


def test_an_admin_fills_in_the_address_of_an_account_that_predates_the_requirement(env):
    """The only way an account created before the address became mandatory ever gets one - and
    the page says which accounts are still missing one, since nothing else will ever fill them
    in."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        old = auth.create_user(conn, "carol", OTHER_PASSWORD, "member")  # no address, as before
    login(client, "admin")

    page = client.get("/admin/users").text
    assert "have no email address" in page and "carol" in page

    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{old.id}/email", data={"csrf": token, "email": "carol@example.test"})
    assert r.status_code == 303
    with conn_for(settings) as conn:
        assert auth.get_user(conn, old.id).email == "carol@example.test"
        assert auth.users_without_email(conn) == []

    # And the address of one account cannot be handed to another.
    token = csrf(client, "/admin/users")
    r = client.post(f"/admin/users/{old.id}/email", data={"csrf": token, "email": "admin@example.test"})
    assert r.status_code == 400
    assert "already uses that email address" in r.text
    with conn_for(settings) as conn:
        assert auth.get_user(conn, old.id).email == "carol@example.test"


def test_only_an_admin_may_set_an_address(env):
    """A member setting their own would be able to claim an address the provider is about to hand
    to somebody else, which is the whole account-takeover shape this feature has to avoid."""
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin", "admin@example.test")
        member = auth.create_user(conn, "carol", OTHER_PASSWORD, "member", "carol@example.test")
    login(client, "carol", OTHER_PASSWORD)

    r = client.post(f"/admin/users/{member.id}/email", data={"csrf": csrf(client, "/"), "email": "boss@example.test"})
    assert r.status_code == 404  # a member must not even learn the route exists
    with conn_for(settings) as conn:
        assert auth.get_user(conn, member.id).email == "carol@example.test"
