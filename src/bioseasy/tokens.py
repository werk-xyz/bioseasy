# SPDX-License-Identifier: GPL-3.0-or-later
"""Personal API tokens for the status API (read-only by default, optionally scoped to start
backups too, see SCOPE_READ / SCOPE_BACKUP below).

Format: `bse_<prefix>_<secret>`. The prefix is looked up directly (indexed, unique); the secret
is compared with `hmac.compare_digest` against a stored hash, never against the plaintext. Only
`hashlib.sha256` of the secret is stored, never the secret itself, and the full token is handed
back exactly once, at creation, by `create()` -- nothing later reads it back out of the database
because nothing later stores it.

sha256 is adequate here even though it is a fast hash: the secret is 32 random bytes from
`secrets.token_urlsafe`, so it carries 256 bits of entropy. Unlike a human-chosen password there
is no realistic low-entropy search space for an attacker to speed through offline; the slow KDFs
used for passwords (see `auth.py`, argon2) exist to blunt exactly that search, and buy nothing
against a token that is already unguessable.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass

_SCHEME = "bse"
_PREFIX_BYTES = 6
_SECRET_BYTES = 32
# secrets.token_urlsafe(n) always returns a base64url string of this length once padding is
# stripped: ceil(4n/3) characters. Asserted below against a real call so a future change to that
# stdlib behaviour would fail loudly at import time instead of silently breaking token parsing.
_PREFIX_LEN = 8
_SECRET_LEN = 43
assert len(secrets.token_urlsafe(_PREFIX_BYTES)) == _PREFIX_LEN
assert len(secrets.token_urlsafe(_SECRET_BYTES)) == _SECRET_LEN

_MAX_CREATE_ATTEMPTS = 5

# 'read' (default) is the original read-only behaviour; 'backup' additionally allows starting a
# backup of the devices owned by the token's user through the API (POST /api/v1/devices/{udid}/backup).
SCOPE_READ = "read"
SCOPE_BACKUP = "backup"
SCOPES = (SCOPE_READ, SCOPE_BACKUP)


@dataclass(frozen=True)
class IssuedToken:
    id: int
    name: str
    prefix: str
    scope: str
    token: str  # the full, secret-bearing token; exists only on the value returned by create()


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _parse(raw: str) -> tuple[str, str] | None:
    """Splits `raw` into (prefix, secret) by fixed length, never by searching for "_": both the
    prefix and the secret are drawn from the same base64url alphabet, which includes "_", so a
    literal split would misparse whenever one of them happens to contain it.
    """
    head = f"{_SCHEME}_"
    body_len = _PREFIX_LEN + 1 + _SECRET_LEN
    if len(raw) != len(head) + body_len or not raw.startswith(head):
        return None
    body = raw[len(head) :]
    if body[_PREFIX_LEN] != "_":
        return None
    return body[:_PREFIX_LEN], body[_PREFIX_LEN + 1 :]


def create(conn: sqlite3.Connection, user_id: int, name: str, scope: str = SCOPE_READ) -> IssuedToken:
    name = name.strip()
    if not (1 <= len(name) <= 64):
        raise ValueError("Name must be 1 to 64 characters")
    if scope not in SCOPES:
        raise ValueError("Scope must be 'read' or 'backup'")
    for _ in range(_MAX_CREATE_ATTEMPTS):
        prefix = secrets.token_urlsafe(_PREFIX_BYTES)
        secret = secrets.token_urlsafe(_SECRET_BYTES)
        try:
            cur = conn.execute(
                "INSERT INTO api_tokens (user_id, name, prefix, secret_hash, scope) VALUES (?, ?, ?, ?, ?)",
                (user_id, name, prefix, _hash(secret), scope),
            )
        except sqlite3.IntegrityError:
            continue  # prefix collision at 48 random bits: vanishingly unlikely, just retry
        return IssuedToken(
            id=cur.lastrowid, name=name, prefix=prefix, scope=scope, token=f"{_SCHEME}_{prefix}_{secret}"
        )
    raise RuntimeError("Could not generate a unique token prefix")


def authenticate(conn: sqlite3.Connection, header_token: str) -> sqlite3.Row | None:
    """Looks up and verifies a bearer token. Returns the api_tokens row, or None for anything
    that is not a currently valid, unrevoked token of ours -- missing, malformed, unknown and
    revoked are deliberately indistinguishable to the caller (api.py turns None into one generic
    401, never leaking which case applied).
    """
    parsed = _parse(header_token)
    if parsed is None:
        return None
    prefix, secret = parsed
    row = conn.execute("SELECT * FROM api_tokens WHERE prefix = ?", (prefix,)).fetchone()
    if row is None or row["revoked_at"] is not None:
        return None
    if not hmac.compare_digest(_hash(secret), row["secret_hash"]):
        return None
    return row


def touch_last_used(conn: sqlite3.Connection, token_id: int) -> None:
    """Updates last_used_at, but at most once per minute per token, so a busy caller does not
    turn every single request into a write.
    """
    conn.execute(
        "UPDATE api_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ? "
        "AND (last_used_at IS NULL OR last_used_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 minute'))",
        (token_id,),
    )


def list_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()


def revoke(conn: sqlite3.Connection, user_id: int, token_id: int) -> bool:
    """Revokes one token, but only if it belongs to user_id. Returns whether a matching row
    exists, so app.py can turn "no" into a 404 that does not distinguish "not yours" from "does
    not exist" -- the same shape as visible_device in app.py and oidc.unlink.

    Idempotent: revoking an already-revoked token of your own still matches (COALESCE keeps the
    original revoked_at) and returns True, rather than looking like a 404 on a second click.
    """
    cur = conn.execute(
        "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) "
        "WHERE id = ? AND user_id = ?",
        (token_id, user_id),
    )
    return cur.rowcount > 0
