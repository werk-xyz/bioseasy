# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional OIDC sign-in, for users who already run Authentik, Keycloak, Entra ID and the like.

An identity is matched to a local account by its email address. That is a deliberate reversal of
what this module's first version did - it insisted on an explicit link and refused to look at the
email claim at all - and it is worth writing down why that version argued the way it did, because
the risk it named is real and is now carried by the safeguards below.

OpenID Connect Core 1.0, section 5.7 (retrieved 2026-09-17,
https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability) is explicit: "the only
guaranteed unique identifier for a given End-User is the combination of the `iss` Claim and the
`sub` Claim", while "other Claims such as `email` ... MUST NOT be used as unique identifiers".
A provider may re-use an address for a different person, and a person's address may change.

So the email decides who a sign-in belongs to exactly once, and three things guard that moment:

* The provider must say the address is verified. `email_verified` means "the OP took affirmative
  steps to ensure that this e-mail address was controlled by the End-User" (Core 5.1); an address
  the provider will not vouch for is one anybody could have typed into their own profile. A claim
  that is missing counts as not verified - authentik, for one, reports `email_verified` as false
  by default since 2025.10 - and the requirement can be turned off for a provider that never sends
  the claim (settings.oidc_require_verified_email), which is then that installation's decision.
* One address belongs to at most one account (the users_email_unique index, SCHEMA_VERSION 20).
  An address that still matches several accounts - only possible in a database migrated from
  before that index - signs nobody in.
* The first successful match writes the (issuer, subject) link, and every later sign-in of that
  identity is found through the link, not through the email. From then on the account follows the
  stable identifier: a renamed address at the provider keeps working, and an address handed to
  somebody else does not take the account with it. This is the safeguard the previous design was
  built around, kept as a second layer under the email-matching rule rather than instead of it.

Self-registration (settings.oidc_allow_registration, off by default) creates an account for an
identity that matches none, always as a member, never as an admin: a provider that can mint
identities must not be able to mint administrators of this installation.

A required group or scope (settings.oidc_required_group) gates both sign-in and registration.
Where that membership arrives differs per provider, which is why both the claim name and the
scopes are configurable and why this module falls back to the userinfo endpoint:
* authentik puts group membership in the default `profile` scope, but includes the claims in the
  id_token only when "Include claims in id_token" is switched on - otherwise they are only at the
  userinfo endpoint (https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/,
  retrieved 2026-09-17). The claim is named `groups`.
* Keycloak has no group claim by default. Its `roles` client scope puts realm roles into
  `realm_access.roles` and, by default, into the access token only - a mapper has to be told to
  add them to the id_token (https://www.keycloak.org/docs/latest/server_admin/, retrieved
  2026-09-17). Hence dotted claim names are supported: `realm_access.roles`.
* Entra ID sends `groups` as a JSON array of GUIDs, not names, and above 200 groups in a JWT it
  sends none at all, only a `_claim_names`/`_claim_sources` pointer to Microsoft Graph
  (https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference,
  retrieved 2026-09-17). bioseasy does not call Graph: such a sign-in is refused rather than
  waved through, and the group filter in the Entra app registration is the way out.
"""

from __future__ import annotations

import sqlite3

from authlib.integrations.starlette_client import OAuth

from .config import Settings


class Refused(Exception):
    """A sign-in the provider got right and bioseasy will not accept: no verified address, no
    required group, an ambiguous address, nobody to sign in as. Carries the sentence the user is
    shown, which says what is wrong without saying which accounts exist here."""


def build_oauth(settings: Settings) -> OAuth:
    """Registers the "oidc" client from discovery. Call only when settings.oidc_enabled."""
    oauth = OAuth()
    oauth.register(
        name="oidc",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
        # code_challenge_method turns on PKCE (Authlib generates and stores the verifier in the
        # session); the openid scope makes Authlib generate and check a nonce the same way.
        client_kwargs={"scope": settings.oidc_scopes, "code_challenge_method": "S256"},
    )
    return oauth


def redirect_uri(settings: Settings) -> str:
    return f"{settings.base_url.rstrip('/')}/login/oidc/callback"


def find_linked_user(conn: sqlite3.Connection, issuer: str, subject: str) -> int | None:
    row = conn.execute("SELECT user_id FROM oidc_links WHERE issuer = ? AND subject = ?", (issuer, subject)).fetchone()
    return row["user_id"] if row else None


def link(conn: sqlite3.Connection, user_id: int, issuer: str, subject: str) -> None:
    """Links an identity to a user. Raises ValueError if it is already linked to someone else."""
    existing = find_linked_user(conn, issuer, subject)
    if existing == user_id:
        return  # already linked to this same account: linking again is a no-op
    if existing is not None:
        raise ValueError("This identity is already linked to another account")
    conn.execute("INSERT INTO oidc_links (user_id, issuer, subject) VALUES (?, ?, ?)", (user_id, issuer, subject))


def list_links(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT rowid AS link_id, issuer, subject, created_at FROM oidc_links WHERE user_id = ? ORDER BY created_at",
        (user_id,),
    ).fetchall()


def unlink(conn: sqlite3.Connection, user_id: int, link_id: int) -> bool:
    """Removes one link, but only if it belongs to user_id. Returns whether a row was removed."""
    cur = conn.execute("DELETE FROM oidc_links WHERE rowid = ? AND user_id = ?", (link_id, user_id))
    return cur.rowcount > 0


# --- what the provider told us about this identity ---------------------------------------------


def claimed_email(claims: dict, *, require_verified: bool) -> str:
    """The address this sign-in may be matched by, or a Refused saying why there is none.

    `email_verified` is read strictly: present and true, or nothing. A provider that sends no such
    claim sends no guarantee either, and "no guarantee" is the case the pre-hijacking work asks an
    RP to refuse - Sudhodanan and Paverd, USENIX Security 2022, 6.2.1 (arxiv.org/abs/2205.10174,
    retrieved 2026-09-17): a service relying on the IdP for verification "should require a strong
    guarantee from the IdP that this verification has been performed". An installation whose
    provider never sends the claim can lift the requirement, deliberately and in one place.
    """
    email = str(claims.get("email") or "").strip()
    if not email:
        raise Refused("The provider did not send an email address, so this sign-in cannot be matched to an account.")
    if require_verified and claims.get("email_verified") is not True:
        raise Refused(
            "The provider did not confirm this email address as verified, so it cannot be used to sign in here."
        )
    return email


def claim_path(claims: dict, path: str):
    """A claim by name, or by a dotted path for a provider that nests it (Keycloak's
    `realm_access.roles`). Returns None where any step is missing or is not an object."""
    value = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def groups_of(claims: dict, claim: str) -> list[str] | None:
    """The group/role values of a token, or None if the claim is absent - which is not the same as
    an empty list and must not be treated as one: absent means "ask the userinfo endpoint", empty
    means "this user is in none of them".

    A string is accepted as a single value, because a provider that sends one group may send it
    unwrapped; everything else is stringified, since Entra ID sends GUIDs and others send names.
    """
    value = claim_path(claims, claim)
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def has_overage_pointer(claims: dict, claim: str) -> bool:
    """Entra ID's way of saying "too many groups to list": no `groups` claim, but a `_claim_names`
    entry pointing at Microsoft Graph. bioseasy does not follow that pointer, so this is a refusal
    rather than a silent pass."""
    names = claims.get("_claim_names")
    return isinstance(names, dict) and claim.split(".")[0] in names


def check_group(claims: dict, userinfo: dict | None, settings: Settings) -> None:
    """Raises Refused unless the required group is among the claims. Does nothing if none is set.

    `userinfo` is the answer of the userinfo endpoint, fetched by the caller only when the
    id_token has no such claim - authentik is the reason it is looked for in both places.
    """
    required = settings.oidc_required_group
    if not required:
        return
    claim = settings.oidc_groups_claim
    for source in (claims, userinfo or {}):
        if has_overage_pointer(source, claim):
            raise Refused(
                "The provider reported too many groups to list in the token, so membership of the "
                "required group could not be checked. Restrict the groups the provider sends."
            )
    groups = groups_of(claims, claim)
    if groups is None:
        groups = groups_of(userinfo or {}, claim)
    if groups is None:
        raise Refused(
            f"The provider sent no {claim!r} claim, so the required group could not be checked. "
            "Check the scopes and the claim name configured for single sign-on."
        )
    if not any(g.casefold() == required.casefold() for g in groups):
        raise Refused("Your account is not a member of the group required to sign in here.")


# --- matching an identity to a local account ---------------------------------------------------


def find_user_by_email(conn: sqlite3.Connection, email: str) -> int | None:
    """The single account with this address, or None. Raises Refused where more than one account
    carries it: only reachable in a database migrated from before users_email_unique existed
    (db._migrate_19_to_20), and picking one of them would be a coin toss over who gets signed in.
    """
    rows = conn.execute(
        "SELECT id FROM users WHERE email IS NOT NULL AND email = ? COLLATE NOCASE", (email,)
    ).fetchall()
    if len(rows) > 1:
        raise Refused(
            "More than one account here uses that email address, so this sign-in cannot be matched "
            "to one of them. An administrator has to give each account its own address."
        )
    return rows[0]["id"] if rows else None


def username_for(conn: sqlite3.Connection, claims: dict, email: str) -> str:
    """A free username for a self-registered account: the provider's `preferred_username`, else
    the local part of the address, else with a number appended. It names the account in this
    installation and is not an identity - OIDC Core 5.7 says as much about preferred_username as
    it says about email - so a collision is resolved by counting up rather than by refusing."""
    base = str(claims.get("preferred_username") or "").strip() or email.split("@")[0].strip()
    base = base[:56] or "user"
    candidate, n = base, 1
    while conn.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (candidate,)).fetchone():
        n += 1
        candidate = f"{base}-{n}"
    return candidate


def bind(conn: sqlite3.Connection, user_id: int, issuer: str, subject: str) -> None:
    """Record (issuer, subject) for an account that was matched by its email address.

    From here on that identity is found by its link and the address is never consulted again, so
    the account follows the one identifier OIDC Core 5.7 calls stable. The refusal below is the
    other half of that: an account that already carries a different subject at the same issuer has
    already been bound once, and a second subject arriving with the same address is either a
    re-registration at the provider or somebody else who was handed the address. Both need a human
    to look, so neither silently takes the account over.
    """
    others = conn.execute(
        "SELECT subject FROM oidc_links WHERE user_id = ? AND issuer = ? AND subject != ?", (user_id, issuer, subject)
    ).fetchall()
    if others:
        raise Refused(
            "That account is already linked to a different identity at this provider. An "
            "administrator has to remove the old link before this one can be used."
        )
    link(conn, user_id, issuer, subject)
