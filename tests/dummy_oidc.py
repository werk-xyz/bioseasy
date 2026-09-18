# SPDX-License-Identifier: GPL-3.0-or-later
"""A real, if minimal, OpenID Connect provider, served on a real port for the duration of a test.

Why not another mock: every other OIDC test in this repository replaces Authlib's
`authorize_access_token`, which means the half that actually talks to a provider - discovery,
the redirect and its state, PKCE, the code exchange, fetching the signing keys and checking the
signature, the issuer, the audience and the nonce - has never run. A provider that answers over
HTTP with tokens it really signed is the only way to see that half work.

It implements exactly what Authlib asks of a provider in this flow and nothing else. It is not a
security product and must never be reachable outside a test: it hands a token to anyone who asks.

DEMO CREDENTIALS, NOT SECRETS: the client id and secret below exist only in this file and in the
test that starts it.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from contextlib import closing, contextmanager
from urllib.parse import urlencode

import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

CLIENT_ID = "bioseasy-test"
CLIENT_SECRET = "not-a-secret-test-value"  # noqa: S105 - marked demo credential, see module docstring
KEY_ID = "test-key-1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DummyProvider:
    """Holds the signing key and whatever the last authorize call was told."""

    def __init__(self, issuer: str, subject: str = "test-subject") -> None:
        self.issuer = issuer
        self.subject = subject
        # What this provider says about the person behind the subject. Settable per test, because
        # the whole email-matching, verification and group story is decided by these three claims
        # and by where they are served from.
        self.email: str | None = f"{subject}@example.test"
        self.email_verified: bool | None = True
        self.preferred_username: str | None = None
        self.groups: list[str] | None = None
        # authentik's default: group membership is at the userinfo endpoint and NOT in the
        # id_token unless the provider is configured to include it. Flipping this is how a test
        # covers the Keycloak/Entra shape instead.
        self.groups_in_id_token = False
        # Entra ID above 200 groups: no groups claim anywhere, only a pointer to Microsoft Graph.
        self.group_overage = False
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes: dict[str, dict] = {}
        # Two ways to make the provider misbehave on purpose, so the checks on the client side can
        # be seen failing. A verifier that has never rejected anything is indistinguishable from
        # one that accepts everything.
        self.sign_with_a_foreign_key = False
        self.claim_to_be: str | None = None
        self.foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # What the client sent us, so a test can assert on the request itself rather than only on
        # its outcome - a missing PKCE challenge would otherwise pass unnoticed.
        self.last_authorize_params: dict[str, str] = {}

    # --- endpoints ---------------------------------------------------------------------------

    def discovery(self, _request) -> JSONResponse:
        return JSONResponse(
            {
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
                "userinfo_endpoint": f"{self.issuer}/userinfo",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "profile", "email"],
                "code_challenge_methods_supported": ["S256"],
            }
        )

    def jwks(self, _request) -> JSONResponse:
        numbers = self.private_key.public_key().public_numbers()
        return JSONResponse(
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": KEY_ID,
                        "use": "sig",
                        "alg": "RS256",
                        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                        "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                    }
                ]
            }
        )

    def authorize(self, request) -> RedirectResponse:
        params = dict(request.query_params)
        self.last_authorize_params = params
        code = f"code-{len(self.codes) + 1}"
        self.codes[code] = {"nonce": params.get("nonce"), "subject": self.subject}
        back = {"code": code}
        if "state" in params:
            back["state"] = params["state"]
        return RedirectResponse(f"{params['redirect_uri']}?{urlencode(back)}", status_code=302)

    async def token(self, request) -> JSONResponse:
        form = await request.form()
        issued = self.codes.pop(str(form.get("code")), None)
        if issued is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return JSONResponse(
            {
                "access_token": "test-access-token",  # noqa: S106 - marked demo credential
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": self.id_token(issued["subject"], issued["nonce"]),
            }
        )

    def userinfo(self, _request) -> JSONResponse:
        """What a provider answers at the userinfo endpoint. Deliberately not authenticated: this
        is a test double that hands a token to anyone (module docstring), and what matters here is
        that the claims can live here instead of in the id_token, the way authentik serves them.
        """
        claims = {"sub": self.subject}
        if self.email is not None:
            claims["email"] = self.email
        if self.email_verified is not None:
            claims["email_verified"] = self.email_verified
        claims.update(self.group_claims())
        return JSONResponse(claims)

    def group_claims(self) -> dict:
        """The group claim as this provider currently serves it, or Entra's overage pointer."""
        if self.group_overage:
            return {"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "https://graph"}}}
        return {} if self.groups is None else {"groups": list(self.groups)}

    # --- token signing -----------------------------------------------------------------------

    def id_token(self, subject: str, nonce: str | None, *, issuer: str | None = None) -> str:
        """A real RS256 id_token, signed with the key the JWKS endpoint publishes.

        Unless the provider has been told to misbehave: `sign_with_a_foreign_key` signs with a key
        nobody can fetch, and `claim_to_be` puts another issuer in the claims. Both exist so the
        client's own checks can be watched rejecting something.
        """
        from authlib.jose import jwt  # noqa: PLC0415 - kept out of import time for a test helper

        now = int(time.time())
        claims = {
            "iss": issuer or self.claim_to_be or self.issuer,
            "sub": subject,
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
        }
        if self.email is not None:
            claims["email"] = self.email
        if self.email_verified is not None:
            claims["email_verified"] = self.email_verified
        if self.preferred_username is not None:
            claims["preferred_username"] = self.preferred_username
        if self.groups_in_id_token or self.group_overage:
            claims.update(self.group_claims())
        if nonce:
            claims["nonce"] = nonce
        key = self.foreign_key if self.sign_with_a_foreign_key else self.private_key
        return jwt.encode({"alg": "RS256", "kid": KEY_ID}, claims, key).decode()

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/.well-known/openid-configuration", self.discovery),
                Route("/authorize", self.authorize),
                Route("/token", self.token, methods=["POST"]),
                Route("/jwks", self.jwks),
                Route("/userinfo", self.userinfo),
            ]
        )


@contextmanager
def running_provider(subject: str = "test-subject"):
    """Serve the provider on a free port until the block ends.

    A real socket, not an in-process transport: Authlib fetches the discovery document and the
    signing keys with its own HTTP client, and swapping that out would put us back to testing a
    mock instead of the protocol.
    """
    port = free_port()
    provider = DummyProvider(f"http://127.0.0.1:{port}", subject)
    config = uvicorn.Config(provider.app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="dummy-oidc", daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        raise RuntimeError("the dummy provider did not start")
    try:
        yield provider
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def claims_of(id_token: str) -> dict:
    """The claims of a token, without verifying it - for assertions about what was issued."""
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
