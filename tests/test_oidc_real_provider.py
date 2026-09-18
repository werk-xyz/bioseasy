# SPDX-License-Identifier: GPL-3.0-or-later
"""The OIDC flow against a provider that really answers, rather than against a patched client.

`tests/test_oidc.py` covers what bioseasy does with an identity once it has one - who may link it,
who may not, what happens to an unknown subject. It gets that identity by replacing Authlib's
`authorize_access_token`, so the protocol half has never run in a test: discovery, the redirect and
its state, PKCE, the code exchange, fetching the signing keys, and checking the signature, issuer,
audience and nonce. This file runs that half against `tests/dummy_oidc.py`, a real provider on a
real port that signs real RS256 tokens.

The browser is played by hand - the test client will not follow a redirect to another host - which
is also what makes each hop visible enough to assert on.
"""

from __future__ import annotations

import re
from contextlib import closing
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from dummy_oidc import CLIENT_ID, CLIENT_SECRET, claims_of, running_provider
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct-horse-battery-staple"  # noqa: S105 - test account, throwaway database


@pytest.fixture
def provider():
    with running_provider(subject="alice-at-the-idp") as p:
        yield p


@pytest.fixture
def make_env(tmp_path, provider):
    """A client and its settings, with the OIDC options a test wants to vary.

    A factory rather than a plain fixture because the interesting cases here are configuration:
    self-registration on or off, a required group, whether a verified address is insisted on.
    """
    started = []

    def build(**options):
        data, root = tmp_path / f"data{len(started)}", tmp_path / f"backups{len(started)}"
        data.mkdir()
        root.mkdir()
        settings = Settings(
            data,
            root,
            "demo",
            "test-secret",
            False,
            3600,
            base_url="http://testserver",
            oidc_issuer=provider.issuer,
            oidc_client_id=CLIENT_ID,
            oidc_client_secret=CLIENT_SECRET,
            **options,
        )
        client = TestClient(
            create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
        )
        started.append(client.__enter__())
        return client, settings

    try:
        yield build
    finally:
        for client in started:
            client.__exit__(None, None, None)


@pytest.fixture
def env(make_env):
    return make_env()


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def create_admin(settings, username="admin", email=None):
    with conn_for(settings) as conn:
        user = auth.create_user(conn, username, PASSWORD, "admin", email)
        conn.commit()
        return user


def sign_in(client, username="admin"):
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/login").text).group(1)
    assert client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD}).status_code == 303


def walk_the_provider(client, start_path, *, method="GET", data=None):
    """Play the browser: follow bioseasy to the provider, and the provider back to bioseasy.

    Returns bioseasy's own response to the callback. The test client keeps the session cookie
    across the hop, which is what carries the state, the nonce and the PKCE verifier. Linking
    starts with a POST because it changes something and therefore carries a CSRF token; a plain
    sign-in is a GET.
    """
    to_provider = client.post(start_path, data=data) if method == "POST" else client.get(start_path)
    assert to_provider.status_code in (302, 303, 307), to_provider.status_code
    authorize_url = to_provider.headers["location"]

    # The provider is a different host, so this hop is a real HTTP request.
    back = httpx.get(authorize_url, follow_redirects=False)
    assert back.status_code == 302, back.status_code
    callback = urlparse(back.headers["location"])
    return client.get(f"{callback.path}?{callback.query}")


def test_the_whole_exchange_works_against_a_provider_that_really_answers(env, provider):
    """Discovery, redirect, code exchange, signature check and sign-in, end to end.

    Nothing in this test is patched: the id_token is signed by a key the client fetches from the
    provider's own JWKS endpoint and verifies for itself.
    """
    client, settings = env
    admin = create_admin(settings)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO oidc_links (user_id, issuer, subject) VALUES (?, ?, ?)",
            (admin.id, provider.issuer, "alice-at-the-idp"),
        )
        conn.commit()

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    # And the session really is signed in, not merely redirected.
    assert client.get("/").status_code == 200


def test_the_request_to_the_provider_carries_pkce_and_a_state(env, provider):
    """What bioseasy sends, not only what it does with the answer.

    Without the challenge an intercepted code could be exchanged by someone else, and without the
    state the callback would accept a request the user never started - neither would be visible
    from the outcome alone, because the flow succeeds either way.
    """
    client, _settings = env

    client.get("/login/oidc")
    # The redirect alone does not reach the provider; follow it so it records the parameters.
    to_provider = client.get("/login/oidc")
    httpx.get(to_provider.headers["location"], follow_redirects=False)
    params = provider.last_authorize_params

    assert params["code_challenge_method"] == "S256"
    assert params["code_challenge"]
    assert params["state"]
    assert params["nonce"]
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == "http://testserver/login/oidc/callback"
    assert "openid" in params["scope"]


def test_an_identity_the_provider_vouches_for_but_nobody_here_uses_is_refused(env):
    """Without self-registration bioseasy still creates no account by itself: a perfectly valid
    token whose verified address belongs to no account here signs nobody in."""
    client, settings = env
    create_admin(settings)  # exists, but carries no address, so nothing can match

    response = walk_the_provider(client, "/login/oidc")

    # 403 with a reason, which is the deliberate answer here: the exchange itself was fine, the
    # identity simply matches no account, and saying so is what tells an admin what to do next. A
    # 404 would be right for a resource that must stay invisible; this is not one.
    assert response.status_code == 403
    assert "No account here uses that email address" in response.text
    assert "Sign out" not in client.get("/").text  # and no session was started


def test_a_second_visit_to_the_callback_with_the_same_code_fails(env, provider):
    """The provider drops a code once it is exchanged, so a replayed callback has nothing to trade
    and must be a 400 rather than a second sign-in."""
    client, settings = env
    admin = create_admin(settings)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO oidc_links (user_id, issuer, subject) VALUES (?, ?, ?)",
            (admin.id, provider.issuer, "alice-at-the-idp"),
        )
        conn.commit()

    to_provider = client.get("/login/oidc")
    back = httpx.get(to_provider.headers["location"], follow_redirects=False)
    callback = urlparse(back.headers["location"])
    query = parse_qs(callback.query)

    first = client.get(f"{callback.path}?{callback.query}")
    assert first.status_code == 303

    client.cookies.clear()
    sign_in(client)  # a fresh session, no state for that code any more
    replay = client.get(f"{callback.path}?code={query['code'][0]}&state={query['state'][0]}")
    assert replay.status_code == 400


def test_linking_from_the_settings_page_uses_the_same_real_exchange(env, provider):
    """The other entry point, since it carries an extra session value the plain sign-in must not."""
    client, settings = env
    create_admin(settings)
    sign_in(client)
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/settings").text).group(1)

    response = walk_the_provider(client, "/settings/sso/link", method="POST", data={"csrf": token})
    assert response.status_code in (303, 307)

    # Measured where it is stored, not only where it is drawn.
    with conn_for(settings) as conn:
        stored = conn.execute("SELECT issuer, subject FROM oidc_links").fetchall()
    assert [(r["issuer"], r["subject"]) for r in stored] == [(provider.issuer, "alice-at-the-idp")]

    page = client.get("/settings/sso").text
    assert provider.issuer in page
    assert "alice-at-the-idp" in page  # which identity, not only which provider


def test_the_provider_signs_what_it_says_it_signs(provider):
    """A check on the test's own instrument: a dummy that issued unsigned or differently-addressed
    tokens would make every assertion above meaningless."""
    token = provider.id_token("someone", nonce="n-1")
    claims = claims_of(token)

    assert len(token.split(".")) == 3  # header.payload.signature, not an unsigned token
    assert claims["iss"] == provider.issuer
    assert claims["aud"] == CLIENT_ID
    assert claims["nonce"] == "n-1"


def _link(settings, provider, subject="alice-at-the-idp"):
    admin = create_admin(settings)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO oidc_links (user_id, issuer, subject) VALUES (?, ?, ?)",
            (admin.id, provider.issuer, subject),
        )
        conn.commit()
    return admin


def test_a_token_signed_by_the_wrong_key_is_rejected(env, provider):
    """The proof that the signature is really checked.

    Everything else about this exchange is identical to the one that succeeds - same issuer, same
    audience, same subject, same nonce, a linked account waiting - and the only difference is a key
    the JWKS endpoint does not publish. If this signed the user in, every other test in this file
    would be checking nothing.
    """
    client, settings = env
    _link(settings, provider)
    provider.sign_with_a_foreign_key = True

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 400
    assert "Sign out" not in client.get("/").text


def test_a_token_claiming_another_issuer_is_rejected(env, provider):
    """The same again for the issuer claim: a valid signature from this provider does not make it
    the provider it says it is, and the link key is (issuer, subject)."""
    client, settings = env
    _link(settings, provider)
    provider.claim_to_be = "https://somebody-else.example"

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 400
    assert "Sign out" not in client.get("/").text


# --- matching by email, and the (issuer, subject) binding that follows it ----------------------


def users_in(settings):
    with conn_for(settings) as conn:
        return {r["username"]: (r["role"], r["email"]) for r in conn.execute("SELECT username, role, email FROM users")}


def links_in(settings):
    with conn_for(settings) as conn:
        return [(r["issuer"], r["subject"], r["user_id"]) for r in conn.execute("SELECT * FROM oidc_links")]


def test_a_verified_address_signs_in_the_account_that_carries_it_and_binds_the_identity(env, provider):
    """End to end against a provider that really signs: the
    account is found by its address, and the same sign-in records (issuer, subject) so that every
    later one no longer depends on the address at all."""
    client, settings = env
    admin = create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 303
    assert client.get("/").status_code == 200
    assert links_in(settings) == [(provider.issuer, "alice-at-the-idp", admin.id)]


def test_once_bound_a_changed_address_at_the_provider_still_signs_the_same_account_in(env, provider):
    """Why the binding is worth having. OIDC Core 5.7 lets an address change and lets a provider
    hand it to somebody else; the link is the stable identifier, so after the first match the
    address is never consulted again."""
    client, settings = env
    admin = create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    assert walk_the_provider(client, "/login/oidc").status_code == 303
    client.cookies.clear()

    provider.email = "alice.renamed@example.test"  # same subject, new address, matching no account
    assert walk_the_provider(client, "/login/oidc").status_code == 303
    assert client.get("/").status_code == 200
    assert links_in(settings) == [(provider.issuer, "alice-at-the-idp", admin.id)]


def test_a_second_identity_with_the_same_address_does_not_take_the_account_over(env, provider):
    """The other half of the binding: an account already bound to one subject at this issuer is
    not handed to a second one that merely presents the same address - the case OIDC Core 5.7
    warns about, where an issuer re-uses an address for a different person."""
    client, settings = env
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    assert walk_the_provider(client, "/login/oidc").status_code == 303
    client.cookies.clear()

    provider.subject = "somebody-else-entirely"
    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 403
    assert "already linked to a different identity" in response.text
    assert len(links_in(settings)) == 1
    assert "Sign out" not in client.get("/").text


def test_an_address_the_provider_will_not_call_verified_is_refused(make_env, provider):
    """email_verified is read strictly. authentik reports false by default since 2025.10, so this
    is the shape a real provider arrives in, not a hypothetical one."""
    client, settings = make_env()
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.email_verified = False

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 403
    assert "did not confirm this email address as verified" in response.text
    assert "Sign out" not in client.get("/").text


def test_a_missing_email_verified_claim_counts_as_unverified_unless_the_check_is_switched_off(make_env, provider):
    """No claim is no guarantee. The escape hatch exists for a provider that never sends one, and
    switching it on is then that installation's own decision, not a silent default."""
    strict_client, strict_settings = make_env()
    create_admin(strict_settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.email_verified = None  # the claim is left out entirely

    assert walk_the_provider(strict_client, "/login/oidc").status_code == 403

    relaxed_client, relaxed_settings = make_env(oidc_require_verified_email=False)
    create_admin(relaxed_settings, email="alice@example.test")
    assert walk_the_provider(relaxed_client, "/login/oidc").status_code == 303
    assert relaxed_client.get("/").status_code == 200


# --- self-registration -------------------------------------------------------------------------


def test_self_registration_creates_a_member_account_for_an_unknown_identity(make_env, provider):
    """An identity that matches no account gets one, as a member."""
    client, settings = make_env(oidc_allow_registration=True)
    create_admin(settings, email="admin@example.test")
    provider.email = "newcomer@example.test"
    provider.preferred_username = "newcomer"

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 303
    assert client.get("/").status_code == 200
    assert users_in(settings)["newcomer"] == ("member", "newcomer@example.test")
    assert links_in(settings) == [(provider.issuer, "alice-at-the-idp", 2)]


def test_the_settings_page_names_the_local_account_a_single_sign_on_identity_landed_on(make_env, provider):
    """A single sign-on user never typed a username here, so the settings page has to say which
    local account their identity maps to. Here the provider suggests a username that is already
    taken, so the account gets a different one: exactly the case where the user could not have
    guessed it."""
    client, settings = make_env(oidc_allow_registration=True)
    create_admin(settings, email="admin@example.test")  # holds the username "admin"
    provider.email = "newcomer@example.test"
    provider.preferred_username = "admin"

    assert walk_the_provider(client, "/login/oidc").status_code == 303
    landed_on = next(name for name, (_role, email) in users_in(settings).items() if email == "newcomer@example.test")
    assert landed_on != "admin"

    page = client.get("/settings").text
    account = page[page.index("<h2>Account</h2>") : page.index("<h2>Email address</h2>")]
    assert f"<code>{landed_on}</code>" in account
    assert "Member" in account
    assert "sign-in is linked to this account" in account


def test_a_self_registered_account_has_no_local_password_and_is_never_an_admin(make_env, provider):
    """The role is not the provider's to choose: whatever it sends, a registration is a member.
    And the account carries no password_hash, so nobody can sign into it with a guessed password
    either - it exists only for the identity that created it."""
    client, settings = make_env(oidc_allow_registration=True)
    create_admin(settings, email="admin@example.test")
    provider.email = "newcomer@example.test"
    provider.preferred_username = "newcomer"
    provider.groups = ["administrators", "superuser", "admin"]  # nothing the provider says grants it

    assert walk_the_provider(client, "/login/oidc").status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT role, password_hash FROM users WHERE username = 'newcomer'").fetchone()
    assert row["role"] == "member"
    assert row["password_hash"] is None
    with conn_for(settings) as conn:
        assert auth.admin_count(conn) == 1  # the one created by hand, and no second one


def test_a_registered_username_that_is_taken_gets_a_free_one_instead_of_failing(make_env, provider):
    """The username is a label here, not an identity (OIDC Core 5.7 says as much about
    preferred_username as about email), so a collision is counted past rather than refused."""
    client, settings = make_env(oidc_allow_registration=True)
    create_admin(settings, username="newcomer", email="admin@example.test")
    provider.email = "newcomer@example.test"
    provider.preferred_username = "newcomer"

    assert walk_the_provider(client, "/login/oidc").status_code == 303
    assert sorted(users_in(settings)) == ["newcomer", "newcomer-2"]
    assert users_in(settings)["newcomer-2"] == ("member", "newcomer@example.test")


def test_registration_stays_off_until_it_is_switched_on(make_env, provider):
    """The same identity, the same provider, one setting apart - which is the only honest way to
    show that the switch is what decides, rather than something else in the flow."""
    off_client, off_settings = make_env()
    create_admin(off_settings, email="admin@example.test")
    provider.email = "newcomer@example.test"
    assert walk_the_provider(off_client, "/login/oidc").status_code == 403
    assert list(users_in(off_settings)) == ["admin"]

    on_client, on_settings = make_env(oidc_allow_registration=True)
    create_admin(on_settings, email="admin@example.test")
    assert walk_the_provider(on_client, "/login/oidc").status_code == 303
    assert len(users_in(on_settings)) == 2


# --- the required group ------------------------------------------------------------------------


def test_a_group_served_only_by_the_userinfo_endpoint_is_found(make_env, provider):
    """authentik's shape: group membership comes with the default `profile` scope but is not in
    the id_token unless the provider is told to include it. The claim is fetched from userinfo
    only when the token cannot answer, which is what this covers."""
    client, settings = make_env(oidc_required_group="bioseasy-users", oidc_allow_registration=True)
    create_admin(settings, email="admin@example.test")
    provider.email = "newcomer@example.test"
    provider.groups = ["bioseasy-users", "other"]
    provider.groups_in_id_token = False

    assert walk_the_provider(client, "/login/oidc").status_code == 303
    assert client.get("/").status_code == 200


def test_a_group_inside_the_id_token_is_found_without_asking_userinfo(make_env, provider):
    """Keycloak's and Entra ID's shape, where the claim rides in the token itself."""
    client, settings = make_env(oidc_required_group="BIOSEASY-Users", oidc_allow_registration=True)
    create_admin(settings, email="admin@example.test")
    provider.email = "newcomer@example.test"
    provider.groups = ["bioseasy-users"]  # compared case-insensitively
    provider.groups_in_id_token = True

    assert walk_the_provider(client, "/login/oidc").status_code == 303


def test_without_the_required_group_neither_sign_in_nor_registration_happens(make_env, provider):
    """The gate has to hold for an account that already exists as well as for a new one, or it
    would only ever have gated the first visit."""
    client, settings = make_env(oidc_required_group="bioseasy-users", oidc_allow_registration=True)
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.groups = ["everyone-else"]

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 403
    assert "not a member of the group required" in response.text
    assert links_in(settings) == []
    assert list(users_in(settings)) == ["admin"]
    assert "Sign out" not in client.get("/").text


def test_an_identity_that_was_already_bound_loses_access_when_it_loses_the_group(make_env, provider):
    """The check runs on every sign-in, not only on the one that created the link."""
    client, settings = make_env(oidc_required_group="bioseasy-users")
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.groups = ["bioseasy-users"]
    assert walk_the_provider(client, "/login/oidc").status_code == 303
    client.cookies.clear()

    provider.groups = []
    assert walk_the_provider(client, "/login/oidc").status_code == 403
    assert "Sign out" not in client.get("/").text


def test_a_provider_that_sends_no_group_claim_at_all_is_refused_not_waved_through(make_env, provider):
    """The dangerous default: a misconfigured scope or claim name means no claim arrives, and
    "no claim" must never read as "no objection"."""
    client, settings = make_env(oidc_required_group="bioseasy-users", oidc_groups_claim="not-the-claim-name")
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.groups = ["bioseasy-users"]

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 403
    assert "could not be checked" in response.text


def test_entra_ids_group_overage_is_refused_rather_than_ignored(make_env, provider):
    """Above 200 groups in a JWT, Entra ID sends no `groups` claim at all, only a pointer to
    Microsoft Graph. bioseasy does not follow it, so the sign-in is refused and the message says
    what to change (access-token-claims-reference, retrieved 2026-09-17)."""
    client, settings = make_env(oidc_required_group="bioseasy-users")
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.group_overage = True

    response = walk_the_provider(client, "/login/oidc")

    assert response.status_code == 403
    assert "too many groups" in response.text


def test_no_group_requirement_means_no_group_claim_is_needed(env, provider):
    """The default installation: nothing configured, nothing demanded."""
    client, settings = env
    create_admin(settings, email="alice@example.test")
    provider.email = "alice@example.test"
    provider.groups = None

    assert walk_the_provider(client, "/login/oidc").status_code == 303
