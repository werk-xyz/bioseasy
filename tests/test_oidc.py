# SPDX-License-Identifier: GPL-3.0-or-later
"""OIDC sign-in and linking.

The identity provider is never contacted: authorize_redirect and authorize_access_token are
monkeypatched on app.state.oidc_client, the same Authlib client instance the routes call.
"""

import re
from contextlib import closing

import pytest
from authlib.integrations.starlette_client import OAuthError
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
ISSUER = "https://idp.example.test"


@pytest.fixture
def env(tmp_path):
    """OIDC configured: issuer, client id and base_url are all set."""
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(
        data,
        root,
        "demo",
        "test-secret",
        False,
        3600,
        oidc_issuer=ISSUER,
        oidc_client_id="bioseasy",
        oidc_client_secret="s3cr3t",
        oidc_name="Acme SSO",
        base_url="https://bioseasy.example.test",
    )
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


@pytest.fixture
def unconfigured_env(tmp_path):
    """No OIDC env vars set: the Settings defaults leave it disabled."""
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


def make_user(settings, username, role="admin"):
    with conn_for(settings) as conn:
        return auth.create_user(conn, username, PASSWORD, role)


async def fake_authorize_redirect(request, redirect_uri=None, **kwargs):
    # A real redirect would leave the app; the routes only need something with a 302 status
    # back, since what matters for the tests is the session flag set before this is called.
    return RedirectResponse("https://idp.example.test/authorize", status_code=302)


def patch_identity(monkeypatch, client, iss, sub, **claims):
    """The provider always returns this (iss, sub) from the next token exchange.

    Extra claims (email, email_verified, groups) are passed through, since what an identity is
    allowed to do here now depends on them. The protocol half of all this runs for real in
    tests/test_oidc_real_provider.py; this file stays about what bioseasy does with the claims.
    """

    async def fake_authorize_access_token(request, **kwargs):
        return {"access_token": "x", "userinfo": {"iss": iss, "sub": sub, **claims}}

    monkeypatch.setattr(client.app.state.oidc_client, "authorize_access_token", fake_authorize_access_token)


def patch_failure(monkeypatch, client):
    async def fake_authorize_access_token(request, **kwargs):
        raise OAuthError(error="invalid_state", description="mismatching state")

    monkeypatch.setattr(client.app.state.oidc_client, "authorize_access_token", fake_authorize_access_token)


# --- configuration gating -----------------------------------------------------------------


def test_button_hidden_and_routes_404_when_not_configured(unconfigured_env):
    client, settings = unconfigured_env
    assert "Sign in with" not in client.get("/login").text

    assert client.get("/login/oidc").status_code == 404
    assert client.get("/login/oidc/callback").status_code == 404

    make_user(settings, "admin")
    login(client, "admin")
    assert "/settings/sso/link" not in client.get("/settings").text
    assert client.post("/settings/sso/link", data={"csrf": csrf(client, "/settings")}).status_code == 404


def test_button_shown_when_configured(env):
    client, settings = env
    make_user(settings, "admin")
    assert "Sign in with Acme SSO" in client.get("/login").text


# --- sign-in with an unlinked identity -----------------------------------------------------


def test_unknown_identity_is_refused_and_starts_no_session(env, monkeypatch):
    """A verified address nobody here uses, with self-registration off: refused, and the sentence
    says which of the checks refused it."""
    client, settings = env
    make_user(settings, "admin")
    patch_identity(monkeypatch, client, ISSUER, "someone-not-linked", email="nobody@example.test", email_verified=True)

    r = client.get("/login/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 403
    assert "No account here uses that email address" in r.text

    # No session was started: the dashboard still redirects to login.
    assert "Sign out" not in client.get("/").text


# --- linking and signing in --------------------------------------------------------------


def test_link_then_sign_in_with_that_identity_works(env, monkeypatch):
    client, settings = env
    make_user(settings, "admin")
    login(client, "admin")
    monkeypatch.setattr(client.app.state.oidc_client, "authorize_redirect", fake_authorize_redirect)
    patch_identity(monkeypatch, client, ISSUER, "admin-subject")

    r = client.post("/settings/sso/link", data={"csrf": csrf(client, "/settings")})
    assert r.status_code == 302  # to the (faked) provider

    r = client.get("/login/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 303 and r.headers["location"] == "/settings"
    # The linked identity is listed on the Single sign-on page, its own page.
    assert ISSUER in client.get("/settings/sso").text

    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM oidc_links WHERE issuer = ? AND subject = ?", (ISSUER, "admin-subject"))
        assert row.fetchone() is not None

    # Sign out, then sign in again purely through the linked identity.
    client.post("/logout", data={"csrf": csrf(client, "/")})
    assert "Sign out" not in client.get("/").text

    r = client.get("/login/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/").status_code == 200


# --- an identity cannot switch owners ------------------------------------------------------


def test_identity_linked_to_one_user_cannot_be_linked_to_another(env, monkeypatch):
    client, settings = env
    make_user(settings, "alice")
    make_user(settings, "bob")
    monkeypatch.setattr(client.app.state.oidc_client, "authorize_redirect", fake_authorize_redirect)
    patch_identity(monkeypatch, client, ISSUER, "shared-subject")

    login(client, "alice")
    client.post("/settings/sso/link", data={"csrf": csrf(client, "/settings")})
    client.get("/login/oidc/callback?code=abc&state=xyz")
    with conn_for(settings) as conn:
        alice_id = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]

    client.cookies.clear()
    login(client, "bob")
    client.post("/settings/sso/link", data={"csrf": csrf(client, "/settings")})
    r = client.get("/login/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 409

    with conn_for(settings) as conn:
        rows = conn.execute(
            "SELECT user_id FROM oidc_links WHERE issuer = ? AND subject = ?", (ISSUER, "shared-subject")
        ).fetchall()
    assert [r["user_id"] for r in rows] == [alice_id]  # still only Alice's


# --- unlinking -----------------------------------------------------------------------------


def test_unlink_removes_only_the_callers_own_link(env, monkeypatch):
    client, settings = env
    make_user(settings, "alice")
    make_user(settings, "bob")
    monkeypatch.setattr(client.app.state.oidc_client, "authorize_redirect", fake_authorize_redirect)
    patch_identity(monkeypatch, client, ISSUER, "alice-subject")

    login(client, "alice")
    client.post("/settings/sso/link", data={"csrf": csrf(client, "/settings")})
    client.get("/login/oidc/callback?code=abc&state=xyz")
    with conn_for(settings) as conn:
        link_id = conn.execute("SELECT rowid FROM oidc_links WHERE subject = 'alice-subject'").fetchone()["rowid"]

    client.cookies.clear()
    login(client, "bob")
    assert client.post(f"/settings/sso/{link_id}/unlink", data={"csrf": csrf(client, "/settings")}).status_code == 404
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM oidc_links WHERE rowid = ?", (link_id,)).fetchone() is not None

    client.cookies.clear()
    login(client, "alice")
    r = client.post(f"/settings/sso/{link_id}/unlink", data={"csrf": csrf(client, "/settings")})
    assert r.status_code == 303
    with conn_for(settings) as conn:
        assert conn.execute("SELECT 1 FROM oidc_links WHERE rowid = ?", (link_id,)).fetchone() is None


# --- provider or browser error --------------------------------------------------------------


def test_callback_error_from_the_provider_is_a_400_not_a_500(env, monkeypatch):
    client, settings = env
    make_user(settings, "admin")
    patch_failure(monkeypatch, client)

    r = client.get("/login/oidc/callback?error=access_denied")
    assert r.status_code == 400


# --- schema ------------------------------------------------------------------------------------


def test_schema_creates_the_oidc_links_table(tmp_path):
    fresh = tmp_path / "fresh.db"
    with closing(db.connect(fresh)) as conn:
        assert db.migrate(conn) == db.SCHEMA_VERSION
        conn.execute("SELECT * FROM oidc_links")  # table exists, no OperationalError
