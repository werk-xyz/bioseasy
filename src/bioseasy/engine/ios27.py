# SPDX-License-Identifier: GPL-3.0-or-later
"""Which pairing entrances a device offers, and what the installed pymobiledevice3 can do.

iOS 27 added a device-initiated wireless pairing (Apple, "Managing your simulated and physical
devices in Device Hub": "Upgrade your iPhone or iPad to iOS or iPadOS 27 or later to wirelessly
pair it; otherwise, use a cable", retrieved 2026-09-17). It produces a *RemotePairing* record,
not the lockdown record every existing path in bioseasy uses.

This module holds only what can be decided without touching a device: parsing an OS version,
deriving the available entrances from it, locating the RemotePairing record, and asking the
installed pymobiledevice3 which parts of the wireless chain it actually ships. It never connects
to anything.

Wireless pairing is deliberately an *addition* to the route model. Every device keeps the
lockdown entrance, whatever its OS version, so `routes_for` always contains
`PairingRoute.LOCKDOWN` and an unparsable version can never take it away.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from .base import PairingRoute

#: First iOS/iPadOS major version whose devices can pair without a cable. Apple's Device Hub
#: documentation (retrieved 2026-09-17), not inferred from a library.
WIRELESS_PAIRING_MIN_MAJOR = 27

#: The lockdown service name mobilebackup2 uses over an RSD tunnel. Asserted against the
#: installed library in tests/test_ios27.py so an upstream rename is noticed here and not in the
#: middle of a backup (pymobiledevice3 services/mobilebackup2.py:189).
MOBILEBACKUP2_RSD_SERVICE = "com.apple.mobilebackup2.shim.remote"


def parse_major(os_version: str | None) -> int | None:
    """Major version of an OS string such as "26.3.1", or None when it cannot be read.

    None means "unknown" and must never be treated as "old" or "new" - the same rule
    SetupState follows for its unknown fields (engine/base.py).
    """
    if not os_version:
        return None
    head = os_version.strip().split(".", 1)[0]
    if not head.isdigit():
        return None
    return int(head)


def supports_wireless_pairing(os_version: str | None) -> bool | None:
    """True / False / None (unknown), from the device's reported OS version alone."""
    major = parse_major(os_version)
    if major is None:
        return None
    return major >= WIRELESS_PAIRING_MIN_MAJOR


def routes_for(os_version: str | None) -> tuple[PairingRoute, ...]:
    """The pairing entrances a device with this OS version offers, lockdown always first.

    Lockdown is unconditional: it is what every device supports today and what iOS 27 keeps
    (Apple's own wireless-pairing section still names the cable as the path for everything else).
    RemotePairing is added only where the version is known *and* at least
    WIRELESS_PAIRING_MIN_MAJOR - an unknown version offers the lockdown entrance alone, which is
    exactly today's behaviour.
    """
    if supports_wireless_pairing(os_version):
        return (PairingRoute.LOCKDOWN, PairingRoute.REMOTE_PAIRING)
    return (PairingRoute.LOCKDOWN,)


def remote_record_path(folder: Path, udid: str) -> Path:
    """Where pymobiledevice3 keeps the RemotePairing record for this device.

    The name is taken from pymobiledevice3 itself rather than spelled out here, so a change in
    its scheme cannot silently leave us reading a file that no longer exists
    (pair_records.get_remote_pairing_record_filename, pair_records.PAIRING_RECORD_EXT).
    """
    from pymobiledevice3.pair_records import PAIRING_RECORD_EXT, get_remote_pairing_record_filename

    return folder / f"{get_remote_pairing_record_filename(udid)}.{PAIRING_RECORD_EXT}"


def has_remote_unlock_key(record: dict | None) -> bool:
    """Whether a RemotePairing record carries the host key mobilebackup2 needs.

    Over an RSD tunnel the escrow bag for the check-in is
    `base64.b64decode(record["remote_unlock_host_key"])`
    (pymobiledevice3 remote/remote_service_discovery.py:421-429). A record written by the
    device-initiated flow sets that field to the empty string unconditionally
    (remote/tunnel_service.py:1881), so this returns False for it. What the device then does with
    an empty escrow bag is not established and needs an iOS 27 device to test against.

    This is the RemotePairing counterpart of Pmd3Engine._require_escrow_bag, which refuses a
    lockdown record without an EscrowBag before a connection is ever opened.
    """
    if not record:
        return False
    return bool(record.get("remote_unlock_host_key"))


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def capabilities() -> dict[str, bool]:
    """What the *installed* pymobiledevice3 offers for the wireless path, as plain facts.

    Read from the package that is actually installed, so a version bump that drops a piece shows
    up as a False here instead of an exception inside a backup. Keys:

    - ``pairable_host``: the device-initiated pairing responder exists
      (remote.tunnel_service.serve_pairable_host / PairableHostInfo).
    - ``mobilebackup2_over_rsd``: Mobilebackup2Service still names an RSD shim service.
    - ``tcp_tunnel``: the tunnel can speak TCP. QUIC is the default below Python 3.13
      (remote/common.py:15) and is gone from the device side ("iOS 18.2+ removed QUIC protocol
      support", remote/tunnel_service.py:706), so on our Python 3.12 this depends on sslpsk_pmd3
      being installed (remote/tunnel_service.py:738-743).
    - ``kernel_tunnel``: pytun_pmd3 is present - the default tunnel device, which needs root.
    - ``userspace_tunnel``: pmd_pytcp is present - the no-root stack. Note it has no public
      Wi-Fi-only entry point in 11.12.5.
    """
    try:
        from pymobiledevice3.remote.tunnel_service import PairableHostInfo, serve_pairable_host

        pairable_host = callable(serve_pairable_host) and PairableHostInfo is not None
    except ImportError:
        pairable_host = False
    try:
        from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

        mobilebackup2_over_rsd = Mobilebackup2Service.RSD_SERVICE_NAME == MOBILEBACKUP2_RSD_SERVICE
    except (ImportError, AttributeError):
        mobilebackup2_over_rsd = False
    return {
        "pairable_host": pairable_host,
        "mobilebackup2_over_rsd": mobilebackup2_over_rsd,
        "tcp_tunnel": sys.version_info >= (3, 13) or _module_available("sslpsk_pmd3"),
        "kernel_tunnel": _module_available("pytun_pmd3"),
        "userspace_tunnel": _module_available("pmd_pytcp"),
    }
