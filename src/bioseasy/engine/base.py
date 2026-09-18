# SPDX-License-Identifier: GPL-3.0-or-later
"""The boundary between the web app and whatever talks to the device.

Everything iOS-specific sits behind this protocol, so the app, its tests and a demo deployment
run against the demo engine, and the real engine can be swapped without touching the UI.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class Transport(StrEnum):
    USB = "usb"
    WIFI = "wifi"


class PairingRoute(StrEnum):
    """How a pairing was established, and which entrances a device offers.

    LOCKDOWN is everything bioseasy does today: a lockdown pair record, made by the helper app,
    the command line, USB at the host, or an upload. REMOTE_PAIRING is the iOS 27 wireless
    pairing, which yields a different artefact in a different place (engine/ios27.py).

    The two live side by side deliberately: a device that can pair wirelessly still offers the
    lockdown entrance, and nothing about an iOS 18 device changes.
    """

    LOCKDOWN = "lockdown"
    REMOTE_PAIRING = "remote_pairing"


@dataclass(frozen=True)
class DeviceSeen:
    udid: str
    transport: Transport
    name: str | None = None
    product_type: str | None = None
    os_version: str | None = None
    paired: bool = False


class Phase(StrEnum):
    WAITING_FOR_PASSCODE = "waiting_for_passcode"
    TRANSFERRING = "transferring"
    FINISHING = "finishing"


@dataclass(frozen=True)
class Progress:
    phase: Phase
    percent: float | None = None
    message: str = ""


ProgressCallback = Callable[[Progress], None]


class EngineError(RuntimeError):
    """A device operation failed; the message is safe to show to the user."""


# Called with a udid whenever a lockdown session authenticated with that device's *stored* pair
# record succeeds - a backup start, Wi-Fi enable, encryption check, or a Wi-Fi discovery
# reconnect (engine/pmd3.py). The caller (runtime.py, jobs.py, ticker.py, discovery.py) persists
# this as devices.pair_used_at (db.py); the engine itself never touches the database.
PairUsedCallback = Callable[[str], None]

# Called at most once per backup(), as soon as the engine knows which transport the connection
# actually used - USB or Wi-Fi (engine/pmd3.py's _connect tries USB first, then a fixed host,
# then Bonjour, so a call cannot be assumed to have gone over Wi-Fi just because bioseasy is a
# Wi-Fi-backup product: a device plugged into the host by USB is still found first). jobs.py uses
# this, together with the finished backup's own encrypted flag, as real-world evidence for the
# setup wizard's Wi-Fi and encryption steps (see Engine.backup below).
TransportCallback = Callable[[Transport], None]


@dataclass(frozen=True)
class SetupState:
    """What the device itself already reports for the assisted setup wizard (docs/setup.md),
    read without changing anything on the device. `None` means "could not be confirmed" - an
    unreachable device, a missing pairing, or a read the installed pymobiledevice3 does not
    support - and must never be treated as "off"; see Engine.detect_setup_state."""

    wifi_enabled: bool | None
    encryption_enabled: bool | None


class Engine(Protocol):
    name: str

    def discover(self, on_pair_used: PairUsedCallback | None = None) -> list[DeviceSeen]:
        """Devices reachable right now, over USB or Wi-Fi."""

    def pair(self, udid: str) -> None:
        """Start pairing; the user confirms "Trust" and enters the passcode on the device."""

    def enable_wifi(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> None:
        """Make a paired device reachable over Wi-Fi from now on."""

    def encryption_enabled(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool:
        """Whether the device is currently set to encrypt its own backups."""

    def charging_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool | None:
        """Whether the device is currently charging, or None when this cannot be determined
        right now (unreachable, or the device did not answer). Used only to gate a scheduled
        start's "only while charging" requirement (scheduler.py); an unknown state does not
        satisfy that requirement, the same as a False would."""

    def enable_encryption(self, udid: str, password: str) -> None:
        """Turn on backup encryption with `password`. The device asks for its passcode, so this
        can take a while. `password` must never be stored, logged or returned; the caller is
        responsible for holding it only in memory."""

    def change_encryption_password(self, udid: str, old: str, new: str) -> None:
        """Change the backup password of a device that already has encryption on, from `old` to
        `new`. Raises EngineError if `old` is wrong, if distinguishable from other failures (see
        engine/pmd3.py for what pymobiledevice3 actually lets us tell apart). Neither password is
        ever stored, logged or returned; the caller is responsible for holding them only in
        memory, the same rule as enable_encryption."""

    def backup(
        self,
        udid: str,
        target_root: Path,
        on_progress: ProgressCallback,
        on_pair_used: PairUsedCallback | None = None,
        on_transport: TransportCallback | None = None,
    ) -> None:
        """Write or update the backup in target_root/<udid>. Raises EngineError on failure.

        `on_transport`, if given, is called once the connection's actual transport is known -
        see TransportCallback above."""

    def detect_setup_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> SetupState:
        """Read-only: what the device itself already reports for the setup wizard's Wi-Fi and
        encryption steps, without changing anything on the device or starting a new pairing.

        Used when a device is (re-)added or its setup page is opened with open steps
        (docs/setup.md, "Adding a device again"): a pair record can survive a recreated
        database while the device itself already has both on, and this is how bioseasy notices
        without the owner walking through the wizard again. Never raises for an unreachable
        device or a partial read; each field is None where it could not be confirmed (see
        SetupState). The caller (runtime.run_setup_detect) only ever sets a devices.*_at column
        forward, from None to now, and never clears one because a read came back False or
        unknown."""

    def netcheck(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> list[NetcheckStep]:
        """Read-only connectivity check against the device's already-stored pairing, run from
        the server's own position (never from a computer the device trusts over USB).

        Never starts a new pairing and never triggers a Trust prompt: a missing or rejected pair
        record is reported as a failed step, not repaired. Steps run in order and stop at the
        first failure, since a later step could not succeed without an earlier one; each
        returned step's `detail` is safe to show and to persist (see NetcheckStep)."""


class NotConfirmedError(EngineError):
    """Nobody entered the passcode on the device in time. Not a failure of the backup itself."""


@dataclass(frozen=True)
class NetcheckStep:
    """One step of a connectivity check (engine.netcheck). `detail` is built by the engine to be
    safe to show and store: never a pair record, a password, or other secret (see
    engine/pmd3.py's netcheck implementation)."""

    name: str
    ok: bool
    detail: str


# Called once with the six-digit code the user has to type on the device during a wireless
# pairing. The code is short-lived and only meaningful while the pairing is running, but it is
# still a pairing secret: show it, never log or store it.
PairingCodeCallback = Callable[[str], None]


class WirelessPairingEngine(Protocol):
    """The iOS 27 wireless entrance, as a protocol of its own next to `Engine`.

    Deliberately not part of `Engine`: the wireless path is added, never substituted, so an
    engine that only speaks lockdown (Pmd3Engine today) stays a complete `Engine` and nothing
    about an iOS 18 device changes. Callers ask
    `isinstance(engine, WirelessPairingEngine)` - or simply `hasattr` - before offering the
    fourth entrance.
    """

    def pairing_routes(self, udid: str) -> tuple[PairingRoute, ...]:
        """Which entrances this device offers, lockdown always included (engine/ios27.py)."""

    def pair_wireless(self, udid: str, on_code: PairingCodeCallback) -> None:
        """Pair without a cable: advertise as a pairable host, hand the user a six-digit code
        through `on_code`, and wait for the device to complete the pairing.

        Raises EngineError when the device cannot use this entrance (an OS version below
        iOS 27, or one that could not be read - an unknown version is never assumed to be new).
        """
