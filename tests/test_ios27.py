# SPDX-License-Identifier: GPL-3.0-or-later
"""engine/ios27.py: the route model, and the facts it asserts about the installed
pymobiledevice3.

The capability tests are deliberately written against the real installed package rather than a
stub: their job is to go red when a pymobiledevice3 bump moves the wireless path out from under
us, which a stub could never notice. Nothing here contacts a device.
"""

import plistlib

import pytest
from pymobiledevice3.pair_records import get_remote_pairing_record_filename
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

from bioseasy.engine import ios27
from bioseasy.engine.base import PairingRoute

# --- version parsing --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("os_version", "expected"),
    [
        ("18.6", 18),
        ("26.3.1", 26),  # a real iPad running this version
        ("27.0", 27),
        ("27", 27),
        (" 27.1 ", 27),
        ("unknown", None),  # DemoEngine uses this literal for a device it cannot read
        ("", None),
        (None, None),
        ("beta", None),
    ],
)
def test_parse_major_reads_a_version_or_says_it_cannot(os_version, expected):
    assert ios27.parse_major(os_version) == expected


def test_an_unreadable_version_is_unknown_and_not_false():
    """None and False are different answers, and the difference decides whether a device is
    offered an entrance it cannot use or denied one it could (engine/base.py SetupState has the
    same rule)."""
    assert ios27.supports_wireless_pairing("nonsense") is None
    assert ios27.supports_wireless_pairing("18.6") is False
    assert ios27.supports_wireless_pairing("27.0") is True


# --- the route model --------------------------------------------------------------------------


def test_an_ios_18_device_keeps_exactly_the_lockdown_entrance():
    """The constraint in one assertion: nothing about an older device
    changes, and it is never offered a path it cannot walk."""
    assert ios27.routes_for("18.6") == (PairingRoute.LOCKDOWN,)


def test_an_ios_27_device_gains_the_wireless_entrance_without_losing_lockdown():
    assert ios27.routes_for("27.0") == (PairingRoute.LOCKDOWN, PairingRoute.REMOTE_PAIRING)


def test_a_version_we_cannot_read_falls_back_to_lockdown_alone():
    assert ios27.routes_for(None) == (PairingRoute.LOCKDOWN,)
    assert ios27.routes_for("unknown") == (PairingRoute.LOCKDOWN,)


def test_lockdown_is_the_first_route_for_every_version():
    for version in ("18.6", "26.3.1", "27.0", "99.0", "unknown", None):
        assert ios27.routes_for(version)[0] is PairingRoute.LOCKDOWN


# --- the RemotePairing record -------------------------------------------------------------------


def test_remote_record_path_follows_pymobiledevice3s_own_naming(tmp_path):
    """Cross-checked against the upstream function that invents the name, not against a string we
    also wrote ourselves (pair_records.get_remote_pairing_record_filename)."""
    udid = "00008110-000A1B2C3D4E5F60"
    path = ios27.remote_record_path(tmp_path, udid)
    assert path.parent == tmp_path
    assert path.name == f"{get_remote_pairing_record_filename(udid)}.plist"
    assert path.name == f"remote_{udid}.plist"


def test_a_device_initiated_record_has_no_unlock_key(tmp_path):
    """The record `serve_pairable_host` writes sets remote_unlock_host_key to the empty string
    (pymobiledevice3 remote/tunnel_service.py:1881), and that field is what becomes the escrow
    bag for the mobilebackup2 check-in (remote/remote_service_discovery.py:429). Whether
    mobilebackup2 then works at all, works only while the device is unlocked, or refuses is not
    established without a real iOS 27 device; this is pinned as a test so a future
    pymobiledevice3 that starts filling the field in is noticed."""
    record = {"public_key": b"\x01", "private_key": b"\x02", "remote_unlock_host_key": ""}
    path = ios27.remote_record_path(tmp_path, "UDID")
    path.write_bytes(plistlib.dumps(record))
    assert ios27.has_remote_unlock_key(plistlib.loads(path.read_bytes())) is False


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (None, False),
        ({}, False),
        ({"remote_unlock_host_key": ""}, False),
        ({"public_key": b"x"}, False),
        ({"remote_unlock_host_key": "aGVsbG8="}, True),
    ],
)
def test_has_remote_unlock_key(record, expected):
    assert ios27.has_remote_unlock_key(record) is expected


# --- what the installed pymobiledevice3 offers ---------------------------------------------------


def test_mobilebackup2_still_names_the_rsd_shim_we_expect():
    """Over an RSD tunnel Mobilebackup2Service picks RSD_SERVICE_NAME instead of the classic one
    (services/mobilebackup2.py:189-195). A rename upstream would make our second transport talk
    to nothing, so it is asserted here rather than discovered during a backup."""
    assert Mobilebackup2Service.RSD_SERVICE_NAME == ios27.MOBILEBACKUP2_RSD_SERVICE


def test_capabilities_reports_every_piece_of_the_wireless_chain():
    caps = ios27.capabilities()
    assert sorted(caps) == [
        "kernel_tunnel",
        "mobilebackup2_over_rsd",
        "pairable_host",
        "tcp_tunnel",
        "userspace_tunnel",
    ]
    assert all(isinstance(value, bool) for value in caps.values())


def test_the_installed_pymobiledevice3_can_do_the_wireless_pairing_and_the_tcp_tunnel():
    """Facts about the pinned pymobiledevice3 11.12.5 in pyproject.toml, not a wish: the
    pairable-host responder exists, mobilebackup2 has its RSD shim, and the TCP tunnel is
    reachable on our Python 3.12 because sslpsk_pmd3 is installed (QUIC, the default below 3.13,
    is gone from iOS 18.2+ - remote/tunnel_service.py:706). If a bump breaks one of these, the
    plan for wireless pairing as a fourth entrance changes."""
    caps = ios27.capabilities()
    assert caps["pairable_host"]
    assert caps["mobilebackup2_over_rsd"]
    assert caps["tcp_tunnel"]
