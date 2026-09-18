# SPDX-License-Identifier: GPL-3.0-or-later
"""Local accounts, sessions and the first-run setup token.

Sessions live in a signed cookie that carries the user id and a session_version. Bumping
users.session_version (password or role change) invalidates every existing session of that user.
"""

from __future__ import annotations

import hmac
import re
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()
# Verifying against a dummy hash for unknown users keeps login timing independent of whether the
# username exists.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12


@dataclass(frozen=True)
class User:
    id: int
    username: str
    role: str
    session_version: int
    # The address a single sign-on identity is matched by (oidc.py). None only for accounts
    # created before this field existed; every entrance that creates one now refuses to leave it
    # empty.
    email: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _row_to_user(row: sqlite3.Row | None) -> User | None:
    if row is None:
        return None
    return User(row["id"], row["username"], row["role"], row["session_version"], row["email"])


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def admin_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every local user for the admin-only /users page: role, timestamps and how many devices
    each one owns, in one statement rather than N+1 queries. Never selects password_hash - a
    route rendering this straight into a template must not even have the column in reach."""
    return conn.execute(
        "SELECT u.id, u.username, u.role, u.session_version, u.email, u.created_at, u.last_sign_in_at, "
        "(SELECT COUNT(*) FROM devices d WHERE d.owner_id = u.id) AS device_count, "
        "(SELECT COUNT(*) FROM oidc_links o WHERE o.user_id = u.id) AS oidc_link_count, "
        "(u.password_hash IS NOT NULL) AS has_password "
        "FROM users u ORDER BY u.username COLLATE NOCASE"
    ).fetchall()


def record_sign_in(conn: sqlite3.Connection, user_id: int) -> None:
    """Called once per successful sign-in (password or OIDC), never on session resumption from
    the cookie - see users.last_sign_in_at's column comment in db.py."""
    conn.execute("UPDATE users SET last_sign_in_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?", (user_id,))


def set_role(conn: sqlite3.Connection, user_id: int, role: str) -> None:
    """Admin-only role change. Ends every existing session of that user immediately, the same
    session_version mechanism change_password already relies on (module docstring) - never
    reimplemented here. The "last remaining admin" and "not my own account" rules are the
    caller's business logic (app.py), not this module's: this function only performs the change
    once a caller has already decided it is allowed.
    """
    if role not in ("admin", "member"):
        raise ValueError("Unknown role")
    conn.execute("UPDATE users SET role = ?, session_version = session_version + 1 WHERE id = ?", (role, user_id))


def remove_user(conn: sqlite3.Connection, user_id: int) -> None:
    """Admin-only removal. Like set_role, the safety rules (last admin, not-yourself, no devices
    still owned) are the caller's responsibility; this only deletes the row. api_tokens and
    oidc_links cascade (ON DELETE CASCADE); devices.owner_id is ON DELETE SET NULL as a backstop,
    though the caller is expected to refuse removal while any device is still owned."""
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# Deliberately loose, like connectors.py's: enough to catch a typo, never a claim that the address
# exists. Whether mail actually arrives is answered by the invitation being sent, not by a regex.
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def validate_email(value: str | None) -> str:
    """The one place an address is normalised and checked. Raises ValueError on anything else.

    An address is what a single sign-on identity is matched against (oidc.py), so
    every entrance that creates or changes an account goes through here rather than trimming a
    string itself.
    """
    email = (value or "").strip()
    if not email:
        raise ValueError("An email address is required")
    if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
        raise ValueError("Not a valid email address")
    return email


def register_user(conn: sqlite3.Connection, username: str, password: str, role: str, email: str | None) -> User:
    """Create an account the way a human creates one: with a password and an address, both
    required. Every entrance a person reaches - the setup wizard and the admin Users page - goes
    through this rather than through create_user, which still exists for the programmatic callers
    (demo seed, tests) that predate the address being required and for whom no address exists.
    tests/test_auth.py keeps that list of callers honest.
    """
    return create_user(conn, username, password, role, validate_email(email))


def create_sso_user(conn: sqlite3.Connection, username: str, email: str, role: str = "member") -> User:
    """Create an account for a single sign-on identity that matched none: no local password at
    all (password_hash NULL, which authenticate() already treats as "no local password"), and the
    address the provider vouched for.

    The role is a member's and the caller is not allowed to choose otherwise: a provider that can
    create identities must not be able to create administrators of this installation. An admin
    promotes the account afterwards on the Users page, which is a decision a person makes here.
    """
    username = username.strip()
    if role != "member":
        raise ValueError("A self-registered account is always a member")
    email = validate_email(email)
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, NULL, ?, ?)",
            (username, role, email),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError("Username or email address is taken") from exc
    return get_user(conn, cur.lastrowid)  # type: ignore[return-value]


def set_email(conn: sqlite3.Connection, user_id: int, email: str | None) -> None:
    """Admin-only. Deliberately not something a user may do for themselves: the address decides
    which account a single sign-on identity lands on, so anyone able to set their own could claim
    an address their provider is about to hand somebody else."""
    address = validate_email(email)
    # Checked here as well as by the unique index, because a database migrated from before that
    # index may not have it at all (db._migrate_19_to_20): the duplicate the index would have
    # refused must not be creatable through this form either.
    taken = conn.execute(
        "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?", (address, user_id)
    ).fetchone()
    if taken:
        raise ValueError("Another account already uses that email address")
    try:
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (address, user_id))
    except sqlite3.IntegrityError as exc:
        raise ValueError("Another account already uses that email address") from exc


def users_without_email(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Accounts from before the address was required. They are listed on the admin Users page
    because an address cannot be invented for them and nothing else will ever fill it in."""
    return conn.execute(
        "SELECT id, username FROM users WHERE email IS NULL ORDER BY username COLLATE NOCASE"
    ).fetchall()


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str, email: str | None = None) -> User:
    """Create a local account. Prefer register_user: an address is required for
    every account a person creates, and this function still accepts None only for the programmatic
    callers that have no address to give (demo seed, tests)."""
    username = username.strip()
    if not username or len(username) > 64:
        raise ValueError("Username must be 1 to 64 characters")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if role not in ("admin", "member"):
        raise ValueError("Unknown role")
    email = validate_email(email) if (email or "").strip() else None
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, _hasher.hash(password), role, email),
        )
    except sqlite3.IntegrityError as exc:
        # One message for both unique constraints on purpose: which of the two was hit is exactly
        # the kind of "does this address have an account here" answer an unauthenticated form must
        # not give away. The admin Users page is authenticated and says which (app.py).
        raise ValueError("Username or email address is taken") from exc
    return get_user(conn, cur.lastrowid)  # type: ignore[return-value]


def get_user(conn: sqlite3.Connection, user_id: int) -> User | None:
    return _row_to_user(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def has_password(conn: sqlite3.Connection, user_id: int) -> bool:
    """False for an OIDC-only user: created without a local password (password_hash NULL), or one
    whose password was cleared - neither exists yet in this codebase, but authenticate() already
    treats a NULL hash as "no local password" via _DUMMY_HASH, so the settings page's password
    section has to agree instead of showing a form that can never succeed."""
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row and row["password_hash"])


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> User | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    stored = row["password_hash"] if row and row["password_hash"] else _DUMMY_HASH
    try:
        _hasher.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return None
    if row is None:
        return None
    if _hasher.check_needs_rehash(stored):
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_hasher.hash(password), row["id"]))
    return _row_to_user(row)


def change_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    conn.execute(
        "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
        (_hasher.hash(password), user_id),
    )


def session_user(conn: sqlite3.Connection, session: dict) -> User | None:
    user_id, version = session.get("uid"), session.get("sv")
    if not isinstance(user_id, int) or not isinstance(version, int):
        return None
    user = get_user(conn, user_id)
    if user is None or user.session_version != version:
        return None
    return user


def start_session(session: dict, user: User) -> None:
    session.clear()
    session["uid"] = user.id
    session["sv"] = user.session_version
    session["csrf"] = secrets.token_urlsafe(24)


class LoginThrottle:
    """Slows down password guessing: after `free` failures per key, each attempt must wait.

    In memory on purpose: a restart resets it, which is acceptable for a single home server and
    keeps the database free of attacker-controlled rows.
    """

    def __init__(self, free: int = 5, base_seconds: float = 2.0, max_seconds: float = 300.0):
        self._free, self._base, self._max = free, base_seconds, max_seconds
        self._failures: dict[str, tuple[int, float]] = {}

    def wait_seconds(self, key: str, now: float) -> float:
        count, last = self._failures.get(key, (0, 0.0))
        if count < self._free:
            return 0.0
        delay = min(self._max, self._base * 2 ** (count - self._free))
        return max(0.0, last + delay - now)

    def failed(self, key: str, now: float) -> None:
        count, _ = self._failures.get(key, (0, 0.0))
        self._failures[key] = (count + 1, now)

    def succeeded(self, key: str) -> None:
        self._failures.pop(key, None)


def setup_token(data_dir: Path) -> str:
    """One-time token for creating the first admin; printed to the log, deleted once used."""
    path = data_dir / "setup_token"
    if path.is_file():
        return path.read_text().strip()
    token = secrets.token_urlsafe(18)
    path.touch(mode=0o600)
    path.write_text(token)
    return token


def check_setup_token(data_dir: Path, given: str) -> bool:
    path = data_dir / "setup_token"
    return path.is_file() and hmac.compare_digest(path.read_text().strip(), given.strip())


def consume_setup_token(data_dir: Path) -> None:
    (data_dir / "setup_token").unlink(missing_ok=True)
