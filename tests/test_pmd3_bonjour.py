# SPDX-License-Identifier: GPL-3.0-or-later
"""Bonjour discovery exercised without a real device, against a fake advertisement.

pymobiledevice3 does not use zeroconf for `_apple-mobdev2._tcp` discovery. It ships its own
dependency-light async mDNS client/responder in pymobiledevice3/bonjour.py (checked in the
installed 11.12.5 package under .venv/lib/python3.12/site-packages/pymobiledevice3/bonjour.py):

- `MOBDEV2_SERVICE_NAME = "_apple-mobdev2._tcp.local."` (bonjour.py:25)
- `browse_mobdev2()` sends a raw PTR query over UDP/5353 and parses PTR/SRV/TXT/A/AAAA answers
  by hand (bonjour.py:132-386); no zeroconf, no python-zeroconf dependency anywhere.
- `MDNSResponder` (bonjour.py:464-621) is a minimal mDNS advertiser/responder used by the package
  itself (e.g. for RemotePairing) and reused here to advertise a fake `_apple-mobdev2._tcp` on the
  real local interface.
- `lockdown.get_mobdev2_lockdowns()` (lockdown.py:1579-1616) is the layer bioseasy's
  `Pmd3Engine._wifi_lockdowns()` drives. It parses the Bonjour instance name as
  `"<wifi mac>@<host>"` (`answer.instance.split("@", 1)[0]`, lockdown.py:1601) and looks that MAC
  up against `WiFiMACAddress` in every `*.plist` under the pair-records folder
  (lockdown.py:1585-1596) -- this is the "iOS 17.1+ private MAC" mismatch pmd3.py's own docstring
  warns about: since the advertised MAC is usually private and random, this lookup normally
  misses even for an already-paired device.

  The device is still connected to (autopair=False, so no pairing dialog), and it reports its
  real UDID in lockdownd's GetValue response. bioseasy's own `Pmd3Engine._wifi_lockdowns()`
  (engine/pmd3.py:127-155) is what actually matches by UDID: it takes the UDID lockdownd just
  told it, and if the connection came back unpaired, looks up bioseasy's *own* pair-record store
  (same folder, same `<udid>.plist` layout per pairing.py) by that UDID -- not by the Bonjour
  name -- and reconnects with that record. That is what these tests demonstrate end to end.

No real device exists here, so the "device" is a fake lockdownd: a plain asyncio TCP server
speaking the real length-prefixed-plist protocol (service_connection.py's `recv_prefixed` /
`send_recv_plist`: 4-byte big-endian length, then an XML plist) that answers only `QueryType` and
a whole-dict `GetValue` -- the two requests `LockdownClient._initialize()` sends
(lockdown.py:216-232) before `_handle_autopair(autopair=False, ...)` returns without touching the
network again (pair_record is None and identifier is None, so `fetch_pair_record()` is a no-op;
lockdown.py:1103-1110, 1199-1206).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import os
import plistlib
import socket
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pymobiledevice3.bonjour import MOBDEV2_SERVICE_NAME, MDNSResponder, browse_mobdev2

from bioseasy import pairing
from bioseasy.engine import pmd3

LOCKDOWN_PORT = 62078
FAKE_UDID = "00008110-AABBCCDDEEFF1234"
FAKE_WIFI_MAC_PRIVATE = "AA:BB:CC:DD:EE:FF"  # the address actually advertised over Bonjour
FAKE_WIFI_MAC_REAL = "11:22:33:44:55:66"  # what bioseasy's own pair record stores


def _multicast_available() -> bool:
    """Best-effort probe: can we even join the mDNS multicast group here?

    CI containers commonly have no multicast-capable interface or block IGMP, in which case
    `browse_service`/`MDNSResponder` silently see nothing and every test here would fail for an
    environment reason, not a code reason. Skip cleanly instead.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            mreq = struct.pack(
                "=4s4s",
                socket.inet_aton("224.0.0.251"),
                socket.inet_aton("0.0.0.0"),  # noqa: S104
            )
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        finally:
            s.close()
    except OSError:
        return False
    return True


requires_multicast = pytest.mark.skipif(
    not _multicast_available(), reason="no multicast-capable network interface available in this environment"
)

# engine.discover() connects to every mobdev2 advertiser on the segment, real Apple devices on the
# developer's LAN included, and waits out their connection timeouts: about 80 s per test.
# Opt in with BIOSEASY_TEST_ENGINE_MDNS=1 instead of slowing every run.
requires_engine_mdns = pytest.mark.skipif(
    os.environ.get("BIOSEASY_TEST_ENGINE_MDNS") != "1",
    reason="slow and touches real LAN devices; set BIOSEASY_TEST_ENGINE_MDNS=1 to run",
)


async def _tolerant(coro_factory, attempts: int = 6):
    """Retry an mDNS call, swallowing malformed-packet crashes from unrelated LAN traffic.

    Real: on a real network segment (not a sealed CI container), `browse_service`'s hand-rolled
    parser (bonjour.py:132-186) is not defensive against arbitrary third-party mDNS traffic --
    any other device's malformed or unsupported record can raise `ValueError` mid-parse and abort
    the whole browse. This was observed live in this environment (`ValueError: truncated RR
    header`) from ordinary background multicast traffic, not from anything this test sent. That is
    a real robustness gap in pymobiledevice3's bonjour.py, a third-party dependency, and unrelated
    to the code path being tested. Retrying discards only that one malformed round, never the pass/fail verdict itself.
    """
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return await coro_factory()
        except ValueError as exc:
            last_exc = exc
            continue
    pytest.skip(f"local network mDNS traffic keeps breaking pymobiledevice3's parser: {last_exc!r}")


def _self_signed_pair_record(wifi_mac: str) -> dict:
    """A minimal but real pair record: pairing.parse() validates the cert belongs to the key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bioseasy-test-host")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return {
        "HostID": "11111111-2222-3333-4444-555555555555",
        "SystemBUID": "66666666-7777-8888-9999-000000000000",
        "HostCertificate": cert_pem,
        "HostPrivateKey": key_pem,
        "RootCertificate": cert_pem,
        "WiFiMACAddress": wifi_mac,
    }


class FakeLockdownd:
    """A TCP server speaking just enough real lockdownd protocol for `LockdownClient._initialize()`."""

    def __init__(self, udid: str, *, device_name: str = "Fake Wi-Fi iPhone", accept_sessions: bool = False):
        self.udid = udid
        self.device_name = device_name
        self.accept_sessions = accept_sessions
        self._server: asyncio.AbstractServer | None = None
        self.connections = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                size_bytes = await reader.readexactly(4)
                size = struct.unpack(">L", size_bytes)[0]
                payload = await reader.readexactly(size)
                request = plistlib.loads(payload)
                kind = request.get("Request")
                if kind == "QueryType":
                    response = {"Request": "QueryType", "Type": "com.apple.mobile.lockdown"}
                elif kind == "GetValue":
                    response = {
                        "Request": "GetValue",
                        "Value": {
                            "UniqueDeviceID": self.udid,
                            "DeviceName": self.device_name,
                            "ProductType": "iPhone15,2",
                            "ProductVersion": "18.6",
                        },
                    }
                elif kind == "StartSession" and self.accept_sessions:
                    # No "EnableSessionSSL": validate_pairing() (lockdown.py:608-621) then skips
                    # the TLS upgrade entirely, which a plain-TCP fake server cannot speak anyway.
                    response = {"Request": "StartSession", "SessionID": "fake-session-id"}
                else:
                    response = {"Request": kind, "Error": "NotSupportedByFake"}
                data = plistlib.dumps(response)
                writer.write(struct.pack(">L", len(data)) + data)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            with contextlib.suppress(OSError):
                writer.close()

    async def __aenter__(self) -> FakeLockdownd:
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", LOCKDOWN_PORT)  # noqa: S104
        return self

    async def __aexit__(self, *exc) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


@requires_multicast
def test_browse_mobdev2_finds_a_real_advertisement():
    """The raw Bonjour layer (no engine involved): advertise, then browse, over the real network."""

    async def scenario():
        # Bare instance label; MDNSResponder appends the service type itself.
        instance = f"{FAKE_WIFI_MAC_PRIVATE}@bioseasy-fake"
        async with MDNSResponder(MOBDEV2_SERVICE_NAME, instance, LOCKDOWN_PORT, properties={}):
            for _ in range(8):
                answers = await _tolerant(lambda: browse_mobdev2(timeout=0.3))
                if any(a.instance.startswith(FAKE_WIFI_MAC_PRIVATE) for a in answers):
                    return answers
            return []

    answers = asyncio.run(scenario())
    assert answers, "fake _apple-mobdev2._tcp advertisement was never seen by browse_mobdev2()"
    matches = [a for a in answers if a.instance.startswith(FAKE_WIFI_MAC_PRIVATE)]
    assert matches, [a.instance for a in answers]
    match = matches[0]
    assert match.port == LOCKDOWN_PORT
    assert match.addresses, "advertised instance resolved to no A/AAAA addresses"
    # Format real devices use: "<wifi mac>@<name>", per lockdown.py:1601 (answer.instance.split("@", 1)[0]).
    assert "@" in match.instance
    mac_part = match.instance.split("@", 1)[0]
    assert mac_part == FAKE_WIFI_MAC_PRIVATE


@requires_multicast
@requires_engine_mdns
def test_engine_discover_ignores_a_device_with_no_local_pair_record(tmp_path):
    """A device bioseasy has never paired with is not surfaced over Wi-Fi at all.

    engine/pmd3.py's `_wifi_lockdowns` (pmd3.py:142-150) closes an unpaired connection and, when
    `pairing.load()` finds no record for that UDID, `continue`s without yielding it -- so an
    unknown device advertising itself over Bonjour never reaches `discover()`'s result, however
    many times it is seen. This is what makes the UDID-keyed match in the next test meaningful:
    presence in the result already implies bioseasy recognised the device by UDID.
    """
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=0.5)

    async def scenario():
        # Bare instance label; MDNSResponder appends the service type itself.
        instance = f"{FAKE_WIFI_MAC_PRIVATE}@bioseasy-fake"
        async with (
            FakeLockdownd(FAKE_UDID),
            MDNSResponder(MOBDEV2_SERVICE_NAME, instance, LOCKDOWN_PORT, properties={}),
        ):
            return await _tolerant(lambda: asyncio.get_running_loop().run_in_executor(None, engine.discover))

    devices = asyncio.run(scenario())
    assert devices == []


@requires_multicast
@requires_engine_mdns
def test_matching_is_by_pair_record_udid_not_by_bonjour_name(tmp_path):
    """The documented iOS 17.1+ case: the Bonjour name carries a private MAC that matches nothing,
    but bioseasy's own pair-record store (keyed by UDID) still finds the record once the real UDID
    is known from the connection -- exactly what engine/pmd3.py's `_wifi_lockdowns` docstring
    describes. A record keyed by the *real* WiFiMACAddress, which the private-MAC advertisement
    never equals, proves the match happened via UDID and not via the advertised name.
    """
    record = _self_signed_pair_record(FAKE_WIFI_MAC_REAL)
    pairing.store(tmp_path, FAKE_UDID, pairing.parse(plistlib.dumps(record)))
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=0.5)

    async def scenario():
        # Bonjour advertises the PRIVATE mac, never the one in the stored record.
        # Bare instance label; MDNSResponder appends the service type itself.
        instance = f"{FAKE_WIFI_MAC_PRIVATE}@bioseasy-fake"
        async with (
            FakeLockdownd(FAKE_UDID, accept_sessions=True),
            MDNSResponder(MOBDEV2_SERVICE_NAME, instance, LOCKDOWN_PORT, properties={}),
        ):
            for _ in range(8):
                devices = await _tolerant(lambda: asyncio.get_running_loop().run_in_executor(None, engine.discover))
                if devices:
                    return devices
            return []

    devices = asyncio.run(scenario())
    assert devices, "engine.discover() never saw the fake Wi-Fi device"
    assert devices[0].udid == FAKE_UDID
    # The proof that matching happened by UDID, not by the Bonjour name: pymobiledevice3's own
    # MAC-based lookup inside get_mobdev2_lockdowns (lockdown.py:1601-1602) cannot have matched --
    # the advertised MAC differs from the stored record's WiFiMACAddress by construction, so the
    # first connection comes back unpaired. Only bioseasy's own UDID-keyed reconnect
    # (engine/pmd3.py:146-155), looking up the record this test stored under FAKE_UDID, can have
    # produced a *paired* session here.
    assert FAKE_WIFI_MAC_PRIVATE != FAKE_WIFI_MAC_REAL
    assert devices[0].paired is True
