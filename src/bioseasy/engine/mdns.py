# SPDX-License-Identifier: GPL-3.0-or-later
"""Routed-safe `_apple-mobdev2._tcp` browse: the reason bioseasy has its own mDNS browse at all.

With bioseasy on host networking in
one subnet and a paired iPad in another, reached through the gateway's mDNS proxy, "Scan now"
and an address-less backup both failed with "Device not found on the network" even though the
proxy correctly mirrored the PTR/SRV/A answers. Cause, read from the installed
pymobiledevice3==11.12.5 source: `bonjour.py`'s `browse_service._record_addr` calls
`_Adapters.pick_iface_for_ip`, and `if iface is None: return` - every A/AAAA record whose address
is not on a locally-attached subnet is silently dropped before it ever reaches
`ServiceInstance.addresses`, so `lockdown.get_mobdev2_lockdowns` (which `engine/pmd3.py`'s
`_wifi_lockdowns` used to call directly) has nothing to connect to. Routing, not local adapter
membership, decides whether the address is reachable, so an IPv4 answer must be kept regardless
of `pick_iface_for_ip`'s verdict; a link-local IPv6 answer still needs its interface (its address
is only meaningful with a scope), so that half of pymobiledevice3's rule is kept as-is.

pymobiledevice3 is foreign software (GPL, vendored into .venv) and is never patched or
monkeypatched. This module
does not re-implement mDNS wire parsing: it reuses pymobiledevice3's own `build_query` /
`parse_mdns_message` (the same functions `bonjour.browse_service` calls), the QTYPE_*
constants, and `MDNS_MCAST_V4` / `MDNS_PORT`. Only the socket setup and the address-keeping rule
below are bioseasy's own, because `browse_service` (and the private functions it is built from)
apply the drop rule before any caller can see the raw records.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from pymobiledevice3.bonjour import (
    MDNS_MCAST_V4,
    MDNS_PORT,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_PTR,
    QTYPE_SRV,
    build_query,
    parse_mdns_message,
)

MOBDEV2_SERVICE_NAME = "_apple-mobdev2._tcp.local."


@dataclass(slots=True)
class Address:
    ip: str
    iface: str | None  # local interface name for a link-local IPv6 address; always None for IPv4

    @property
    def full_ip(self) -> str:
        """Same shape pymobiledevice3's own `bonjour.Address.full_ip` produces, so this is a
        drop-in `hostname=` value for `create_using_tcp`."""
        if self.iface and self.ip.lower().startswith("fe80:"):
            return f"{self.ip}%{self.iface}"
        return self.ip


@dataclass(slots=True)
class ServiceInstance:
    instance: str  # "<Instance Name>._type._proto.local."
    host: str | None
    port: int
    addresses: list[Address] = field(default_factory=list)


def _iface_for_scope(scopeid: int | None) -> str | None:
    """Interface name for an IPv6 scope id, the same source pymobiledevice3's own
    `_Adapters.pick_iface_for_ip` prefers for a link-local address (bonjour.py: "Prefer scope id
    for IPv6 link-local")."""
    if not scopeid:
        return None
    try:
        return socket.if_indextoname(scopeid)
    except OSError:
        return None


def assemble_instances(datagrams: list[tuple[bytes, Any]]) -> list[ServiceInstance]:
    """Turn received mDNS response datagrams into `ServiceInstance`s, keeping every IPv4 address
    unconditionally and every link-local IPv6 address that resolves to a local interface.

    Split out from `browse_mobdev2_routed` so the assembly rule - the actual fix - is testable
    with crafted packets and no real socket or network (`tests/test_engine_mdns.py`); the network
    half only has to collect `(data, pkt_addr)` pairs the way `browse_mobdev2_routed` does.
    """
    ptr_targets: set[str] = set()
    srv_map: dict[str, list[dict[str, Any]]] = {}
    host_addrs: dict[str, list[Address]] = {}

    def record_addr(rr_name: str, ip_str: str, pkt_addr: Any) -> None:
        existing = host_addrs.setdefault(rr_name, [])
        if any(a.ip == ip_str for a in existing):
            return
        if ":" in ip_str:
            if not ip_str.lower().startswith("fe80:"):
                return  # only link-local IPv6 carries a meaningful scope; anything else is skipped
            scopeid = pkt_addr[3] if isinstance(pkt_addr, tuple) and len(pkt_addr) == 4 else None
            iface = _iface_for_scope(scopeid)
            if iface is None:
                return
            existing.append(Address(ip=ip_str, iface=iface))
        else:
            # The fix: kept unconditionally, no local-interface check. Once the packet has
            # arrived (possibly via an mDNS proxy), routing decides reachability, not adapter
            # membership.
            existing.append(Address(ip=ip_str, iface=None))

    for data, pkt_addr in datagrams:
        for rr in parse_mdns_message(data):
            rtype = rr.get("type")
            if rtype == QTYPE_PTR and rr.get("name") == MOBDEV2_SERVICE_NAME:
                ptr_targets.add(rr.get("ptrdname"))
            elif rtype == QTYPE_SRV:
                srv_map.setdefault(rr["name"], []).append({"target": rr.get("target"), "port": rr.get("port")})
            elif rtype in (QTYPE_A, QTYPE_AAAA) and rr.get("address"):
                record_addr(rr["name"], rr["address"], pkt_addr)

    results: list[ServiceInstance] = []
    for instance in sorted(ptr_targets):
        for srv in srv_map.get(instance, []):
            port = srv.get("port")
            if port is None:
                continue  # SRV records always carry a port; skip a malformed/unresolved entry
            target = srv.get("target")
            host = (target[:-1] if target and target.endswith(".") else target) or None
            addresses = host_addrs.get(target, []) if target else []
            results.append(ServiceInstance(instance=instance, host=host, port=port, addresses=addresses))
    return results


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[tuple[bytes, Any]]):
        self._queue = queue

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._queue.put_nowait((data, addr))


async def _open_ipv4_socket() -> tuple[asyncio.DatagramTransport, socket.socket, asyncio.Queue]:
    queue: asyncio.Queue[tuple[bytes, Any]] = asyncio.Queue()
    # Receiving mDNS answers means listening on UDP 5353 on every interface (RFC 6762); the socket
    # only reads multicast replies to our own query and never serves anything.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # nosemgrep: avoid-bind-to-all-interfaces
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", MDNS_PORT))  # noqa: S104 - mDNS itself is inherently all-interfaces
    mreq = struct.pack("=4s4s", socket.inet_aton(MDNS_MCAST_V4), socket.inet_aton("0.0.0.0"))  # noqa: S104
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _DatagramProtocol(queue), sock=sock)
    return transport, sock, queue


async def browse_mobdev2_routed(timeout: float) -> list[ServiceInstance]:
    """Send one `_apple-mobdev2._tcp` PTR query over IPv4 multicast and collect answers for
    `timeout` seconds, keeping routed IPv4 addresses `bonjour.browse_service` would drop.

    IPv4 only: the bug this exists for is a routed IPv4 address from an mDNS proxy;
    pymobiledevice3's own IPv6 handling
    (`_bind_ipv6_all_ifaces`/`browse_service`) is unaffected by the bug (a link-local address
    always resolves through its packet's scope id, never through subnet membership), so there is
    nothing to fix there and no reason to duplicate that socket setup. The mDNS socket is opened
    fresh for this call and always closed before returning, success or not.
    """
    transport, sock, queue = await _open_ipv4_socket()
    datagrams: list[tuple[bytes, Any]] = []
    try:
        transport.sendto(build_query(MOBDEV2_SERVICE_NAME, QTYPE_PTR), (MDNS_MCAST_V4, MDNS_PORT))
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while True:
            remaining = end - loop.time()
            if remaining <= 0:
                break
            try:
                datagrams.append(await asyncio.wait_for(queue.get(), timeout=remaining))
            except TimeoutError:
                break
    finally:
        transport.close()
        with contextlib.suppress(OSError):
            sock.close()
    return assemble_instances(datagrams)
