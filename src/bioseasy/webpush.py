# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser push notifications (Web Push), the second half of the notifications feature -- the
first half, an in-page toast for an open tab, is already built (activity.py, base.html's toast
script).

What a user needs to know is in docs/notifications.md, "Browser popups and push". Short version:
iOS and iPadOS Safari can only deliver Web Push to a web app the user has added to the Home
Screen (WebKit, "Web Push for Web Apps on iOS and iPadOS", 2023-03-16, still the documented
model as of WebKit's 2025 Declarative Web Push post); a plain Safari tab cannot subscribe. macOS
Safari, desktop Chrome and Firefox, and Android Chrome need no such install step. That is a
well known, stable constraint, and it is stated plainly wherever the feature is offered.

VAPID keys identify this bioseasy install to the push services it sends through (RFC 8292); they
are not a per-user or per-device secret and never leave the server. The private key lives at
`<data_dir>/vapid_key.pem`, created on first use with mode 0600, the same race-safe
tempfile-then-hardlink pattern connectors.py uses for connector.key, and is never logged or
rendered. A missing or unreadable key file disables the feature (`vapid_status`) rather than
crashing anything that calls into this module.

A push subscription's own endpoint, p256dh and auth (RFC 8291) are not a bioseasy secret --
useless without a live endpoint at the push service -- so unlike connector secrets they are
stored in the clear in push_subscriptions (db.py, SCHEMA_VERSION 14).

Sending never raises: `send_to_users` swallows every per-subscription failure, removes a
subscription the push service reports as gone (404 or 410, the standard "this endpoint no longer
exists" response), and is always safe to call from the same off-thread path runtime.py already
uses for Apprise sends, so a broken or slow push service can never delay or fail a backup.

`send_to_users` also records what actually happened, the same honesty rule runtime.py's
notify_event follows for the Apprise path -- a timestamp that means "the user was told" is only
written when the telling actually happened: users.last_push_ok/
last_push_error/last_push_at are written once the sends for that call are done, per user, not per
subscription -- a user can own several browsers. Three cases:

- A user with no subscriptions at all is never touched: "nothing to deliver to" is not a
  delivery failure and must never read as one.
- A subscription the push service reports as gone (404/410) is removed, same as before this
  feature existed -- normal housekeeping, not a delivery failure, and never counted as one.
- Otherwise: if at least one of a user's subscriptions was reached, that user's state is 1 (ok);
  if every one of them failed (and at least one was actually attempted, i.e. not only removed
  ones), it is 0 (failed) with a fixed, secret-free reason -- never the push service's own
  response text, which is not vetted for that.

This is separate state from devices.last_alert_ok, on purpose: push is scoped to the user (a
subscription lives on the Settings page, see above), not to any one device, so it gets its own
columns on users rather than being folded into a device-scoped column that would either miss
admins with no owned device or misattribute a shared failure to one device's owner.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from py_vapid import Vapid01
from py_vapid.utils import b64urlencode
from pywebpush import WebPushException, webpush

log = logging.getLogger("bioseasy")

# Not a real mailbox: RFC 8292 only requires vapid_claims["sub"] to be a "mailto:" or "https:"
# contact URI a push service could reach out to about this application server; it need not
# resolve. A fixed placeholder is standard practice and keeps no operator email in the image.
_VAPID_SUB = "mailto:webpush@bioseasy.invalid"
_SEND_TIMEOUT = 10.0
# Stored and shown verbatim when a user's push delivery failed (users.last_push_error) -- always
# this fixed text, never a push service's own response body: unlike notify.NotifyResult.error,
# which notify.py already keeps secret-free, pywebpush hands back whatever the push service
# wrote (exc.message), which is not vetted for that and stays log-only (see the except block in
# send_to_users below).
_PUSH_FAILURE_MESSAGE = "One or more browser push deliveries failed"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_path(data_dir: Path) -> Path:
    return data_dir / "vapid_key.pem"


def _write_new_key(data_dir: Path) -> None:
    """Generates a fresh VAPID key pair and writes it to the key file, mode 0600, without ever
    exposing a half-written file to another reader -- same race-safe pattern as
    connectors.py's _load_key: write to a private temp file, then hard-link into place, letting
    whichever process gets there first win.
    """
    vapid = Vapid01()
    vapid.generate_keys()
    fd, tmp_name = tempfile.mkstemp(dir=data_dir, prefix=".vapid_key.")  # mode 0600
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(vapid.private_pem())
        try:
            os.link(tmp_name, _key_path(data_dir))
        except FileExistsError:
            pass  # another process (web or worker) won; its key is the one everybody uses
    finally:
        os.unlink(tmp_name)


def _load_vapid(data_dir: Path) -> Vapid01 | None:
    """Returns the VAPID key pair, generating one on first use. None (never an exception) for a
    key file that exists but cannot be read or parsed, so callers can turn that into "feature
    disabled" instead of a crash -- deliberately different from connectors.py's decrypt_secret,
    which does raise, because a broken connector secret is a stored value the user needs to know
    about, while a broken VAPID key file just means push was never set up correctly here.
    """
    path = _key_path(data_dir)
    if not path.exists():
        try:
            _write_new_key(data_dir)
        except OSError:
            log.warning("could not write VAPID key file at %s", path)
            return None
    try:
        pem = path.read_bytes()
    except OSError:
        log.warning("could not read VAPID key file at %s", path)
        return None
    try:
        return Vapid01.from_pem(pem)
    except Exception:
        log.warning("VAPID key file at %s is not a usable key", path)
        return None


def vapid_status(data_dir: Path) -> bool:
    """Whether browser push can be offered at all right now. account.html and the subscribe route
    both call this instead of duplicating the missing/unreadable check."""
    return _load_vapid(data_dir) is not None


def public_key_b64url(data_dir: Path) -> str | None:
    """The VAPID public key as the base64url-encoded uncompressed EC point the browser's
    `PushManager.subscribe({applicationServerKey: ...})` expects. None if push is disabled."""
    vapid = _load_vapid(data_dir)
    if vapid is None:
        return None
    raw = vapid.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return b64urlencode(raw)


# --- subscriptions -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Subscription:
    endpoint: str
    p256dh: str
    auth: str


class ForeignSubscriptionError(Exception):
    """Raised by save_subscription when the endpoint already belongs to a different user.

    Deliberately carries no detail about who the owner is -- the same reasoning app.py already
    applies to visible_device and oidc.unlink (404, not 403): a caller must not be able to learn
    anything about another user's account from the response.
    """


def save_subscription(conn: sqlite3.Connection, user_id: int, sub: Subscription, label: str = "") -> None:
    """Stores or refreshes one subscription for user_id.

    A browser that resubscribes (a rotated key, a reinstalled service worker) reuses the same
    endpoint or gets a new one from the push service; either way this never produces a duplicate
    row for the same endpoint, and refreshing today's keys/label for a subscription this same
    user already owns is exactly what a legitimate resubscribe means.

    endpoint comes straight from the client (POST /settings/notifications/push/subscribe takes it from the
    subscribe form), so a signed-in user could otherwise post another user's real push endpoint
    and silently take over their subscription -- send_to_users would then deliver that user's
    notifications to the caller instead, with nothing shown to either side. Guarded here, not
    only in the route, so every caller gets it: an existing row for a different user_id is
    refused outright rather than rebound.
    """
    existing = conn.execute("SELECT user_id FROM push_subscriptions WHERE endpoint = ?", (sub.endpoint,)).fetchone()
    if existing is not None and existing["user_id"] != user_id:
        raise ForeignSubscriptionError()
    conn.execute(
        "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, label) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, "
        "auth = excluded.auth, label = excluded.label",
        (user_id, sub.endpoint, sub.p256dh, sub.auth, label),
    )


def list_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM push_subscriptions WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()


def revoke(conn: sqlite3.Connection, user_id: int, subscription_id: int) -> bool:
    """Removes one subscription, but only if it belongs to user_id. Returns whether a matching row
    existed, the same shape as tokens.revoke and oidc.unlink, so app.py can turn "no" into a 404
    that does not distinguish "not yours" from "does not exist".
    """
    cur = conn.execute("DELETE FROM push_subscriptions WHERE id = ? AND user_id = ?", (subscription_id, user_id))
    return cur.rowcount > 0


def _remove_by_endpoint(conn: sqlite3.Connection, endpoint: str) -> None:
    conn.execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (endpoint,))


# --- sending ---------------------------------------------------------------------------------


def send_to_users(conn: sqlite3.Connection, data_dir: Path, user_ids: set[int], title: str, body: str) -> None:
    """Sends one push message to every subscription of every user in user_ids. Never raises: a
    disabled feature (no VAPID key), an empty subscription list, or a broken push service are all
    silently absorbed here, the same guarantee notify.send gives its callers for Apprise. A
    subscription the push service reports as gone (410 Gone, or 404 for a push service that reuses
    that code the same way) is deleted; every other failure is logged and otherwise ignored, one
    subscription at a time, so one broken subscription never stops the rest from being tried.
    """
    if not user_ids:
        return
    vapid = _load_vapid(data_dir)
    if vapid is None:
        return
    private_pem = vapid.private_pem().decode()
    # user_ids never comes from a request body here (runtime.py builds it from owner_id/role
    # columns), only the placeholder count is interpolated, never a value.
    placeholders = ",".join("?" * len(user_ids))
    rows = conn.execute(
        f"SELECT * FROM push_subscriptions WHERE user_id IN ({placeholders})",  # noqa: S608
        tuple(user_ids),
    ).fetchall()
    if not rows:
        return
    payload = _payload(title, body)
    # Per user who has at least one non-gone subscription in this batch: True once any send to
    # them succeeds, False as long as every attempt so far has failed outright. A user who only
    # ever gets 404/410 responses (subscriptions removed, not failed) never gets an entry here --
    # see _record_outcomes.
    outcomes: dict[int, bool] = {}
    for row in rows:
        user_id = row["user_id"]
        subscription_info = {
            "endpoint": row["endpoint"],
            "keys": {"p256dh": row["p256dh"], "auth": row["auth"]},
        }
        try:
            webpush(
                subscription_info=subscription_info,
                data=payload,
                vapid_private_key=private_pem,
                vapid_claims={"sub": _VAPID_SUB},
                timeout=_SEND_TIMEOUT,
            )
        except WebPushException as exc:
            if exc.status_code in (404, 410):
                _remove_by_endpoint(conn, row["endpoint"])
                continue  # normal housekeeping, never counted as a delivery failure
            log.warning("push send failed (status %s): %s", exc.status_code, exc.message)
            outcomes.setdefault(user_id, False)
        except Exception:  # a broken third-party push service must never crash the caller
            log.warning("push send failed", exc_info=True)
            outcomes.setdefault(user_id, False)
        else:
            outcomes[user_id] = True
    _record_outcomes(conn, outcomes)


def _record_outcomes(conn: sqlite3.Connection, outcomes: dict[int, bool]) -> None:
    """Writes users.last_push_ok/last_push_error/last_push_at for every user send_to_users
    actually tried to reach this call. A user absent from `outcomes` -- no subscriptions at all,
    or every one of them merely removed as gone -- is left untouched, so "nothing to deliver to"
    never overwrites a real prior result with a fabricated one."""
    if not outcomes:
        return
    now = _now()
    for user_id, ok in outcomes.items():
        conn.execute(
            "UPDATE users SET last_push_ok = ?, last_push_error = ?, last_push_at = ? WHERE id = ?",
            (1 if ok else 0, None if ok else _PUSH_FAILURE_MESSAGE, now, user_id),
        )


def push_delivery_status(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    """The most recent push delivery outcome for user_id, for the Settings page (app.py's
    account_context) -- last_push_ok is NULL when no push has ever been attempted for this user,
    or when they currently have no subscriptions, so the page only ever shows a notice for a
    confirmed failure, never for "nothing set up yet"."""
    return conn.execute(
        "SELECT last_push_ok, last_push_error, last_push_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def _payload(title: str, body: str) -> str:
    return json.dumps({"title": title, "body": body})
