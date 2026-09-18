# SPDX-License-Identifier: GPL-3.0-or-later
"""Notification connectors: forms for email and Telegram, plus a raw Apprise URL for advanced use.

Non-secret fields (SMTP host and port, a Telegram chat id, and the like) live as JSON in
notification_connectors.settings_json. The one secret part per connector - an SMTP password, a
Telegram bot token, or a whole raw Apprise URL - is encrypted at rest with Fernet (`cryptography`,
already a dependency) under a key file `<data_dir>/connector.key`, created on first use with mode
0600, kept apart from the database file (db.py's notification_connectors table).

Honest limit, worth restating in the UI and docs: this protects a copied or shared database file
(a backup, a support attachment) by making the secret columns unreadable without the key file
too. It does NOT protect an attacker who can already read the whole data volume, since the key
sits right next to the database there.

Secrets are write-only in the UI: `connector_public()` never includes secret_ciphertext or a
decrypted secret, only whether one is set (`secret_set`). A save with a blank secret field keeps
the stored value; a filled field replaces it (app.py's connector routes implement that rule,
since only they know whether the field was left blank versus explicitly cleared). Apprise URLs
are built only at send time (`build_apprise_url`), never stored ready-made, and nothing here logs
or renders a secret or a built URL.

Apprise URL syntax verified against the installed apprise 1.13.1 package sources (never the
network, so no token or password ever needs to be typed into a search):
- Email (`mailto://`): apprise/plugins/email/base.py - templates include
  `{schema}://{host}:{port}` and `{schema}://{user}:{password}@{host}:{port}/{targets}`;
  `common.py` defines SECURE_MODES as insecure/starttls/ssl, taken from the `mode=` query arg
  (`template_args["mode"]`); `from=`, `to=`, `user=` and the `pass=` alias for `password=` are
  documented query args (`URL_TOKEN_ALIASES` in apprise/url.py maps `pass` to `password`), which
  is how a password containing `@`, `:`, `/` or `#` reaches Apprise without needing to be
  percent-encoded into the URL's userinfo part - it never goes there at all, it goes into a query
  value which urlencode() escapes safely.
- Telegram (`tgram://`): apprise/plugins/telegram.py - templates are `{schema}://{bot_token}` and
  `{schema}://{bot_token}/{targets}`; `IS_CHAT_ID_RE` accepts a signed integer or `@name`/`name`,
  optionally followed by `:<topic>`; `parse_url()` also reads a `topic=` (or `thread=`) query arg
  into the same field, which is the form used here instead of the colon suffix.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, InvalidToken

from . import notify

log = logging.getLogger("bioseasy")

KINDS = ("email", "telegram", "apprise")
SCOPES = ("device", "admin")

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_TELEGRAM_TOKEN_RE = re.compile(r"^\d+:[A-Za-z0-9_-]+$")
_TELEGRAM_NUMERIC_CHAT_RE = re.compile(r"^-?\d{1,32}$")
_TELEGRAM_CHANNEL_RE = re.compile(r"^@[A-Za-z0-9_]{5,32}$")
# mailto's own vocabulary (insecure/starttls/ssl) is more Apprise jargon than a form should ask
# a user to know; the form offers the plain names a mail client would use instead.
SECURITY_MODES = {"none": "insecure", "starttls": "starttls", "tls": "ssl"}


class ConnectorSecretError(Exception):
    """A stored secret could not be decrypted (wrong or missing key file, corrupted row)."""


# --- secrets at rest --------------------------------------------------------------------------


def _key_path(data_dir: Path) -> Path:
    return data_dir / "connector.key"


def _load_key(data_dir: Path, create: bool = True) -> bytes:
    """Returns the connector key, creating it only when `create` is set.

    The web service and the worker share /data and can both reach this on first use. The key is
    written completely to a private temp file and then hard-linked into place: the link fails if
    another process got there first, and a reader never sees a half-written key file.
    """
    path = _key_path(data_dir)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        if not create:
            raise
    fd, tmp_name = tempfile.mkstemp(dir=data_dir, prefix=".connector.key.")  # mode 0600
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(Fernet.generate_key())
        try:
            os.link(tmp_name, path)
        except FileExistsError:
            pass  # the other process won; its key is the one everybody uses
    finally:
        os.unlink(tmp_name)
    return path.read_bytes()


def encrypt_secret(data_dir: Path, plaintext: str) -> bytes:
    return Fernet(_load_key(data_dir)).encrypt(plaintext.encode())


def decrypt_secret(data_dir: Path, ciphertext: bytes) -> str:
    # Never creates a key: a fresh key cannot read old ciphertext, and a missing key file must
    # stay visible as an error instead of being silently replaced.
    try:
        return Fernet(_load_key(data_dir, create=False)).decrypt(ciphertext).decode()
    except (InvalidToken, FileNotFoundError) as exc:
        raise ConnectorSecretError("Stored secret could not be read") from exc


# --- form validation ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorForm:
    """Result of validating one connector form.

    `secret` is the secret field exactly as typed, including an empty string when it was left
    blank - callers (app.py) decide what a blank field means: "no secret" on first creation,
    "keep the one already stored" on an edit. `errors` is field-level, readable, and never
    includes a secret's value.
    """

    label: str
    settings: dict
    secret: str
    errors: list[str] = field(default_factory=list)


def _int_in_range(raw: str, low: int, high: int, label: str) -> tuple[int | None, str | None]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, f"{label} must be a whole number"
    if not (low <= value <= high):
        return None, f"{label} must be between {low} and {high}"
    return value, None


def _clean_label(form: dict) -> tuple[str, str | None]:
    label = (form.get("label") or "").strip()
    if not (1 <= len(label) <= 64):
        return "", "Label must be 1 to 64 characters"
    return label, None


def validate_email_form(form: dict) -> ConnectorForm:
    errors: list[str] = []
    label, err = _clean_label(form)
    if err:
        errors.append(err)

    host = (form.get("host") or "").strip()
    if not (1 <= len(host) <= 255) or re.search(r"\s", host):
        errors.append("SMTP host is required")

    port, err = _int_in_range(form.get("port", ""), 1, 65535, "SMTP port")
    if err:
        errors.append(err)

    security = form.get("security", "")
    if security not in SECURITY_MODES:
        errors.append("Security must be None, STARTTLS or TLS")

    username = (form.get("username") or "").strip()
    if len(username) > 254:
        errors.append("SMTP username is too long")

    from_addr = (form.get("from_addr") or "").strip()
    if not _EMAIL_RE.fullmatch(from_addr):
        errors.append("From address must be a valid email address")

    to_raw = form.get("to") or ""
    to = [line.strip() for line in to_raw.splitlines() if line.strip()]
    if not to:
        errors.append("At least one recipient address is required")
    else:
        for addr in to:
            if not _EMAIL_RE.fullmatch(addr):
                errors.append(f"Not a valid recipient address: {addr}")

    password = form.get("password") or ""
    if len(password) > 512:
        errors.append("SMTP password is too long")

    settings: dict = {}
    if not errors:
        settings = {
            "host": host,
            "port": port,
            "security": security,
            "username": username or None,
            "from_addr": from_addr,
            "to": to,
        }
    return ConnectorForm(label=label, settings=settings, secret=password, errors=errors)


def validate_telegram_form(form: dict) -> ConnectorForm:
    errors: list[str] = []
    label, err = _clean_label(form)
    if err:
        errors.append(err)

    bot_token = (form.get("bot_token") or "").strip()
    if bot_token and not _TELEGRAM_TOKEN_RE.fullmatch(bot_token):
        errors.append("Bot token must look like 123456789:AA-your-token")

    chat_id = (form.get("chat_id") or "").strip()
    if not (_TELEGRAM_NUMERIC_CHAT_RE.fullmatch(chat_id) or _TELEGRAM_CHANNEL_RE.fullmatch(chat_id)):
        errors.append("Chat id must be numeric or an @channel name")

    topic_raw = (form.get("topic_id") or "").strip()
    topic_id = None
    if topic_raw:
        topic_id, err = _int_in_range(topic_raw, 1, 2_147_483_647, "Topic id")
        if err:
            errors.append(err)

    settings: dict = {}
    if not errors:
        settings = {"chat_id": chat_id, "topic_id": topic_id}
    return ConnectorForm(label=label, settings=settings, secret=bot_token, errors=errors)


def validate_apprise_form(form: dict) -> ConnectorForm:
    errors: list[str] = []
    label, err = _clean_label(form)
    if err:
        errors.append(err)

    url = (form.get("url") or "").strip()
    if url:
        errors.extend(notify.validate_urls([url]))

    return ConnectorForm(label=label, settings={}, secret=url, errors=errors)


VALIDATORS = {
    "email": validate_email_form,
    "telegram": validate_telegram_form,
    "apprise": validate_apprise_form,
}

# A blank secret field on first creation is only ever "keep the existing secret" once a
# connector already exists; on a brand-new connector it means the required secret is missing.
# Email has no such rule - an SMTP password is genuinely optional (anonymous relay).
REQUIRED_SECRET_LABEL = {"telegram": "Bot token is required", "apprise": "Apprise URL is required"}


def form_defaults(kind: str, label: str, settings: dict) -> dict:
    """The stored settings of one connector, reshaped into the same flat string fields its form
    uses - so a template can feed either a freshly submitted form or a saved connector into the
    same field macro."""
    if kind == "email":
        return {
            "label": label,
            "host": settings.get("host", ""),
            "port": str(settings.get("port") or ""),
            "security": settings.get("security", "starttls"),
            "username": settings.get("username") or "",
            "from_addr": settings.get("from_addr", ""),
            "to": "\n".join(settings.get("to") or []),
        }
    if kind == "telegram":
        return {
            "label": label,
            "chat_id": settings.get("chat_id", ""),
            "topic_id": str(settings.get("topic_id") or ""),
        }
    return {"label": label}


# --- building the Apprise URL at send time ------------------------------------------------------


def build_email_url(settings: dict, password: str | None) -> str:
    mode = SECURITY_MODES[settings["security"]]
    query: dict[str, str] = {
        "mode": mode,
        "from": settings["from_addr"],
        "to": ",".join(settings["to"]),
    }
    if settings.get("username"):
        query["user"] = settings["username"]
    if password:
        query["pass"] = password
    host = quote(settings["host"], safe="")
    return f"mailto://{host}:{settings['port']}?{urlencode(query, quote_via=quote)}"


def build_telegram_url(settings: dict, bot_token: str) -> str:
    query: dict[str, str] = {}
    if settings.get("topic_id"):
        query["topic"] = str(settings["topic_id"])
    qs = f"?{urlencode(query, quote_via=quote)}" if query else ""
    chat_id = quote(str(settings["chat_id"]), safe="@")
    return f"tgram://{quote(bot_token, safe='')}/{chat_id}{qs}"


def build_apprise_url(kind: str, settings: dict, secret: str | None) -> str:
    if kind == "email":
        return build_email_url(settings, secret)
    if kind == "telegram":
        if not secret:
            raise ValueError("Telegram connector is missing its bot token")
        return build_telegram_url(settings, secret)
    if kind == "apprise":
        if not secret:
            raise ValueError("Apprise connector is missing its URL")
        return secret
    raise ValueError(f"Unknown connector kind: {kind!r}")


# --- storage -------------------------------------------------------------------------------------


def list_connectors(conn: sqlite3.Connection, scope: str, udid: str | None = None) -> list[sqlite3.Row]:
    if scope == "device":
        return conn.execute(
            "SELECT * FROM notification_connectors WHERE scope = 'device' AND udid = ? ORDER BY created_at, id",
            (udid,),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM notification_connectors WHERE scope = 'admin' ORDER BY created_at, id"
    ).fetchall()


def get_connector(conn: sqlite3.Connection, connector_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM notification_connectors WHERE id = ?", (connector_id,)).fetchone()


def create_connector(
    conn: sqlite3.Connection,
    *,
    scope: str,
    udid: str | None,
    kind: str,
    label: str,
    settings: dict,
    secret_ciphertext: bytes | None,
) -> int:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute(
        "INSERT INTO notification_connectors "
        "(scope, udid, kind, label, settings_json, secret_ciphertext, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (scope, udid, kind, label, json.dumps(settings), secret_ciphertext, now, now),
    )
    return cur.lastrowid


def update_connector(
    conn: sqlite3.Connection,
    connector_id: int,
    *,
    label: str,
    settings: dict,
    secret_ciphertext: bytes | None,
    enabled: bool,
) -> None:
    conn.execute(
        "UPDATE notification_connectors SET label = ?, settings_json = ?, secret_ciphertext = ?, "
        "enabled = ?, updated_at = ? WHERE id = ?",
        (
            label,
            json.dumps(settings),
            secret_ciphertext,
            1 if enabled else 0,
            datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            connector_id,
        ),
    )


def delete_connector(conn: sqlite3.Connection, connector_id: int) -> None:
    conn.execute("DELETE FROM notification_connectors WHERE id = ?", (connector_id,))


def connector_public(row: sqlite3.Row) -> dict:
    """Everything about a connector that is safe to put in a template context: never the
    ciphertext, never a decrypted secret, only whether one is set."""
    kind = row["kind"]
    label = row["label"]
    settings = json.loads(row["settings_json"])
    return {
        "id": row["id"],
        "kind": kind,
        "label": label,
        "enabled": bool(row["enabled"]),
        "settings": settings,
        "secret_set": row["secret_ciphertext"] is not None,
        "updated_at": row["updated_at"],
        "form": form_defaults(kind, label, settings),
    }


def email_invite_url(conn: sqlite3.Connection, data_dir: Path, recipient: str) -> str | None:
    """A one-off mailto:// URL to `recipient`, built from the first enabled admin email connector.

    Server, port, security mode, login and sender come from that connector; only the recipient is
    replaced, and nothing about the connector is changed on the way. None when no usable email
    connector exists - the caller then simply does not send, which is why creating an account never
    depends on mail being configured.

    This is the one place where bioseasy sends to an address that is not in any stored
    configuration, so it stays narrow on purpose: one recipient, admin scope only, email kind only.
    """
    for row in list_connectors(conn, "admin"):
        if row["kind"] != "email" or not row["enabled"]:
            continue
        secret = None
        if row["secret_ciphertext"] is not None:
            try:
                secret = decrypt_secret(data_dir, row["secret_ciphertext"])
            except ConnectorSecretError:
                # Connector id only, never the settings, the secret or the recipient's address.
                log.warning("connector %s: secret could not be decrypted, no invitation sent", row["id"])
                continue
        settings = json.loads(row["settings_json"])
        try:
            return build_email_url({**settings, "to": [recipient]}, secret)
        except (KeyError, ValueError) as exc:
            log.warning("connector %s: could not build an invitation URL (%s)", row["id"], type(exc).__name__)
    return None


def apprise_urls_for(conn: sqlite3.Connection, data_dir: Path, scope: str, udid: str | None = None) -> list[str]:
    """Enabled connectors of one scope, built into Apprise URLs ready to hand to notify.send().

    A connector that cannot be turned into a URL (a secret that fails to decrypt, an internal
    inconsistency) is skipped rather than failing the whole notification for every other target;
    it is logged by connector id only, never with the settings or the secret.
    """
    urls = []
    for row in list_connectors(conn, scope, udid):
        if not row["enabled"]:
            continue
        settings = json.loads(row["settings_json"])
        secret = None
        if row["secret_ciphertext"] is not None:
            try:
                secret = decrypt_secret(data_dir, row["secret_ciphertext"])
            except ConnectorSecretError:
                log.warning("connector %s: secret could not be decrypted, skipping", row["id"])
                continue
        try:
            urls.append(build_apprise_url(row["kind"], settings, secret))
        except ValueError as exc:
            log.warning("connector %s: could not build a notification URL (%s), skipping", row["id"], exc)
    return urls
