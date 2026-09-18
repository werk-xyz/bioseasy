# SPDX-License-Identifier: GPL-3.0-or-later
"""Pairing codes for the code hand-off onboarding path.

The preferred way to trust a device with bioseasy (docs/pairing.md, "Pair from my computer"): an
admin creates a short-lived, single-use code on the Add page; a small script the user runs on
their own computer (see `build_script` below) pairs the device over USB and trades the code for
the pair record it just created, by POSTing it to `/pair/{code}` (src/bioseasy/app.py). This
module only creates and validates the codes; the record itself is handled exactly like the
manual upload path (pairing.py).

Only the SHA-256 hash of a code is ever stored, the same trade-off as tokens.py: the code is
shown once, on the admin's own screen, and nothing later needs to read it back.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta

# No 0/O/1/I/L: characters that are easy to misread or mistype from a screen.
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LENGTH = 8
CODE_TTL_MINUTES = 10
MAX_OPEN_CODES_PER_USER = 3
_MAX_CREATE_ATTEMPTS = 5


class TooManyOpenCodesError(ValueError):
    """Raised when the creating user already has MAX_OPEN_CODES_PER_USER unexpired, unused codes."""


def _generate_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def open_code_count(conn: sqlite3.Connection, user_id: int, now: datetime) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM pairing_codes WHERE created_by = ? AND used_at IS NULL AND expires_at > ?",
        (user_id, _iso(now)),
    ).fetchone()[0]


def create_code(conn: sqlite3.Connection, user_id: int, now: datetime) -> tuple[str, str]:
    """Creates a new pairing code for `user_id`. Returns (plaintext_code, expires_at_iso).

    Raises TooManyOpenCodesError if the user already has MAX_OPEN_CODES_PER_USER open codes.
    """
    if open_code_count(conn, user_id, now) >= MAX_OPEN_CODES_PER_USER:
        raise TooManyOpenCodesError(
            f"You already have {MAX_OPEN_CODES_PER_USER} open pairing codes. "
            "Wait for one to expire or finish one first."
        )
    expires_at = _iso(now + timedelta(minutes=CODE_TTL_MINUTES))
    for _ in range(_MAX_CREATE_ATTEMPTS):
        code = _generate_code()
        try:
            conn.execute(
                "INSERT INTO pairing_codes (code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (_hash(code), user_id, _iso(now), expires_at),
            )
        except sqlite3.IntegrityError:
            continue  # hash collision at 8 chars from a 31-letter alphabet: vanishingly unlikely, just retry
        return code, expires_at
    raise RuntimeError("Could not generate a unique pairing code")


def get_code(conn: sqlite3.Connection, user_id: int, code: str) -> sqlite3.Row | None:
    """For the Add page only: the creating admin looking up their own code to show its state.

    Returns the row regardless of expiry or use, so the page can say "expired" or redirect to
    the finished device instead of a bare 404; None if the code is unknown or belongs to someone
    else (a member never reaches this at all, admin_user already guards every route that calls
    this, and one admin must not be able to watch or steal another admin's open code).
    """
    row = conn.execute("SELECT * FROM pairing_codes WHERE code_hash = ?", (_hash(code),)).fetchone()
    if row is None or row["created_by"] != user_id:
        return None
    return row


def consume(conn: sqlite3.Connection, code: str, now: datetime) -> sqlite3.Row | None:
    """For the hand-off endpoint (`POST /pair/{code}`, no session, no admin check).

    The submitted code is hashed before it ever reaches a comparison, so lookup is a single
    indexed equality check on the hash, never a character-by-character comparison against a
    plaintext code held in memory. Returns the still-open row, or None for anything wrong -
    unknown code, already used, or expired - so the caller can turn every one of those into the
    same generic response; telling them apart would let an attacker learn which reason they hit.
    """
    row = conn.execute("SELECT * FROM pairing_codes WHERE code_hash = ?", (_hash(code),)).fetchone()
    if row is None or row["used_at"] is not None:
        return None
    if _parse(row["expires_at"]) <= now:
        return None
    return row


def mark_consumed(conn: sqlite3.Connection, code_id: int, udid: str, now: datetime) -> None:
    conn.execute(
        "UPDATE pairing_codes SET used_at = ?, consumed_udid = ? WHERE id = ?",
        (_iso(now), udid, code_id),
    )


def build_script(base_url: str, code: str, pymobiledevice3_version: str) -> str:
    """The PEP 723 script served at GET /pair/{code}/bioseasy-pair.py, one per code.

    Pairs the connected device over USB, turns on Wi-Fi connections and reads back the pair
    record, using the same pymobiledevice3 11.12.5 API as src/bioseasy/engine/pmd3.py's own
    _pair() (checked against the installed package under .venv):
      - usbmux.list_devices() (usbmux.py:456) to find a connected USB device
      - lockdown.create_using_usbmux(serial=..., autopair=False) (lockdown.py:1370) to connect
      - LockdownClient.pair(timeout=120) (lockdown.py:631) to run the Trust dialog
      - LockdownClient.set_enable_wifi_connections(True) (lockdown.py:510)
      - LockdownClient.pair_record / .wifi_mac_address (lockdown.py:299) to read the record back

    The record's own bytes carry no UDID or device name (see pairing.py's REQUIRED_KEYS), so
    those travel as two request headers alongside the raw plist body, which is exactly what
    /pair/{code} expects and never logs beyond a shortened UDID.
    """
    return f'''# /// script
# requires-python = ">=3.9"
# dependencies = ["pymobiledevice3=={pymobiledevice3_version}"]
# ///
"""bioseasy pair hand-off: pairs this computer's connected iPhone or iPad over USB, then sends
the resulting pair record to bioseasy so Wi-Fi backups can start. Generated for one pairing code
only; the code stops working after {CODE_TTL_MINUTES} minutes or after its first successful use.
"""
import asyncio
import plistlib
import sys
import urllib.error
import urllib.request

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_usbmux

BASE_URL = {base_url!r}
CODE = {code!r}


async def main() -> int:
    devices = [d for d in await usbmux.list_devices() if d.connection_type == "USB"]
    if not devices:
        print("No iPhone or iPad found over USB. Connect it, unlock it, and run this again.")
        return 1
    if len(devices) > 1:
        print("Several devices are connected; pairing the first one found.")
    lockdown = await create_using_usbmux(serial=devices[0].serial, autopair=False)
    try:
        print('Unlock the device and tap "Trust" if it asks. Waiting up to two minutes...')
        try:
            await lockdown.pair(timeout=120)
        except PyMobileDevice3Exception as exc:
            print(f"Pairing failed: {{exc.__class__.__name__}}")
            return 1
        await lockdown.set_enable_wifi_connections(True)
        record = dict(lockdown.pair_record or {{}})
        record.setdefault("WiFiMACAddress", lockdown.wifi_mac_address)
        udid = lockdown.udid
        name = (lockdown.all_values or {{}}).get("DeviceName", "")
    finally:
        await lockdown.close()

    request = urllib.request.Request(
        f"{{BASE_URL}}/pair/{{CODE}}",
        data=plistlib.dumps(record),
        method="POST",
        headers={{
            "Content-Type": "application/octet-stream",
            "X-Bioseasy-UDID": udid,
            "X-Bioseasy-Device-Name": name,
        }},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        print(f"bioseasy did not accept the pairing: HTTP {{exc.code}}")
        return 1
    except urllib.error.URLError as exc:
        print(f"Could not reach bioseasy at {{BASE_URL}}: {{exc.reason}}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
'''
