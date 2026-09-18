# SPDX-License-Identifier: GPL-3.0-or-later
"""Thin wrapper around Apprise: sending alerts, parsing and validating URLs, and message text.

Notify URLs carry secrets (bot tokens, SMTP passwords). Never log or return a URL itself; only
its scheme may appear in user-facing text.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

import apprise

# Apprise's own per-plugin defaults are not a bound we control or have verified for every
# scheme an admin can configure (a raw Apprise URL can name any installed plugin): email uses
# smtplib with a 15s connect timeout that then persists for the whole SMTP conversation, most
# requests-based plugins default to 4s connect / 4s read, and some plugins set neither. Measured
# by hand against a local listener that accepts a connection and never answers (never a real
# host): a mailto:// URL to it took about 17s to give up. This is our own ceiling on top of
# whatever Apprise does internally, so a misbehaving or merely slow target can never hold up the
# caller (a backup worker thread or a web request handling the "send test" button) longer than
# this, regardless of scheme or Apprise version.
_SEND_TIMEOUT = 20.0


@dataclass(frozen=True)
class NotifyResult:
    ok: bool
    error: str = ""


def _scheme(url: str) -> str:
    return urlsplit(url).scheme or "unknown"


def validate_urls(urls: list[str]) -> list[str]:
    """Readable problems for URLs Apprise cannot parse.

    Uses Apprise's own parsing (add() returns False for a URL it does not recognise) instead of
    reimplementing it. Never echoes a full URL, only its scheme, since the rest may carry a token
    or password.
    """
    problems = []
    for url in urls:
        if not apprise.Apprise().add(url):
            problems.append(f"Not a valid notification URL (scheme: {_scheme(url)})")
    return problems


def send(urls: list[str], title: str, body: str) -> NotifyResult:
    """Send one message to every URL. Never logs or returns the URLs themselves.

    Bounded by _SEND_TIMEOUT no matter what Apprise or the target does: service.notify() runs in
    a helper thread and the caller only ever waits up to _SEND_TIMEOUT for it. If the target is
    still hanging by then, this returns a timeout NotifyResult and leaves the helper thread to
    finish (or stay stuck) on its own, daemonised so it can never keep the process alive. Same
    "never raises, never blocks the caller past a fixed bound" guarantee webpush.send_to_users
    already gives its callers via pywebpush's own timeout=.
    """
    if not urls:
        return NotifyResult(ok=False, error="No notification URLs configured")
    service = apprise.Apprise()
    for url in urls:
        service.add(url)

    outcome: list[NotifyResult] = []

    def run() -> None:
        try:
            ok = service.notify(title=title, body=body)
        except Exception:  # a broken third-party service must not crash the caller
            outcome.append(NotifyResult(ok=False, error="Sending the notification failed"))
            return
        if not ok:
            outcome.append(NotifyResult(ok=False, error="One or more notification services rejected the message"))
            return
        outcome.append(NotifyResult(ok=True))

    worker = threading.Thread(target=run, name="notify-send", daemon=True)
    worker.start()
    worker.join(_SEND_TIMEOUT)
    if not outcome:
        return NotifyResult(ok=False, error="Sending the notification timed out")
    return outcome[0]


def _kind(product_type: str | None) -> str:
    """ "iPhone" or "iPad" - the same distinction app.py's device_kind() draws for the setup
    wizard and device page, duplicated here as one line rather than importing app.py (which
    imports this module, so that would be a cycle)."""
    return "iPad" if product_type and product_type.startswith("iPad") else "iPhone"


def message_for(event: str, device_name: str, detail: str = "", product_type: str | None = None) -> tuple[str, str]:
    """Sober, short title and body for one notification event.

    `product_type` is only used by the "upcoming" event, to pick "iPhone" or "iPad" wording;
    every other event ignores it.
    """
    name = device_name or "the device"
    if event == "upcoming":
        kind = _kind(product_type)
        minutes = detail or "a few"
        return (
            f"Backup of {name} starts soon",
            f"Backup of {name} starts in {minutes} minutes: put the {kind} on the charger, "
            "unlock it and wait for the passcode prompt.",
        )
    if event == "waiting_for_passcode":
        return f"Confirm the backup on {name}", "Unlock the device and enter its passcode to start the backup."
    if event == "due":
        return (
            f"Backup of {name} is due",
            detail or "Open bioseasy on the device and tap Back up now, then enter the passcode.",
        )
    if event == "succeeded":
        return f"Backup of {name} succeeded", "The backup finished and reads as complete on disk."
    if event == "failed":
        return f"Backup of {name} failed", detail or "The backup did not finish. See the device page for details."
    if event == "not_confirmed":
        return (
            f"Backup of {name} not confirmed",
            "Nobody entered the passcode in time, so the backup did not run.",
        )
    if event == "overdue":
        return (
            f"{name} is overdue for a backup",
            detail or "No complete backup has finished within the configured period.",
        )
    if event == "storage_failed":
        return "Backup storage problem", detail or "The backup storage is not ready. See the storage page."
    raise ValueError(f"Unknown notification event: {event!r}")
