# SPDX-License-Identifier: GPL-3.0-or-later
"""`engine/mdns.py`'s address-assembly rule, proven with crafted mDNS packets - no real socket,
no real network, no pymobiledevice3 device. This is the fix itself: `assemble_instances` must
keep a routed IPv4 address even when no local interface matches its subnet, unlike
pymobiledevice3's own `bonjour.browse_service` (see mdns.py's module docstring)."""

from __future__ import annotations

import socket
import struct

from pymobiledevice3.bonjour import QTYPE_A, QTYPE_AAAA, QTYPE_PTR, QTYPE_SRV, encode_name

from bioseasy.engine import mdns

INSTANCE = "AA:BB:CC:DD:EE:FF@bioseasy-fake._apple-mobdev2._tcp.local."
HOST = "iPad.local."


def _rr(name: str, rtype: int, rdata: bytes) -> bytes:
    return encode_name(name) + struct.pack("!HHIH", rtype, 0x0001, 120, len(rdata)) + rdata


def _srv_rdata(target: str, port: int) -> bytes:
    return struct.pack("!HHH", 0, 0, port) + encode_name(target)


def _message(answers: list[bytes]) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, len(answers), 0, 0)
    return header + b"".join(answers)


def _ptr_srv(target: str, port: int) -> list[bytes]:
    return [
        _rr(mdns.MOBDEV2_SERVICE_NAME, QTYPE_PTR, encode_name(INSTANCE)),
        _rr(INSTANCE, QTYPE_SRV, _srv_rdata(target, port)),
    ]


def test_routed_ipv4_survives_with_no_local_interface_match():
    """The actual bug: 192.0.2.12 is not on any interface of the machine running the test
    (there is no such adapter here), yet the fix must keep it - routing handles delivery, not
    local subnet membership."""
    routed_ip = "192.0.2.12"
    a_record = _rr(HOST, QTYPE_A, socket.inet_aton(routed_ip))
    packet = _message([*_ptr_srv(HOST, 32498), a_record])

    instances = mdns.assemble_instances([(packet, ("192.0.2.1", 5353))])

    assert len(instances) == 1
    instance = instances[0]
    assert instance.instance == INSTANCE
    assert instance.port == 32498
    assert [a.ip for a in instance.addresses] == [routed_ip]
    assert instance.addresses[0].iface is None
    assert instance.addresses[0].full_ip == routed_ip


def test_link_local_ipv6_keeps_its_interface():
    """A link-local IPv6 answer is only meaningful with its scope, so it keeps pymobiledevice3's
    own rule: kept only when the packet's scope id resolves to a real local interface. Loopback
    (index 1, "lo0" on macOS/BSD, "lo" on Linux) is used as a real, always-present interface so
    the test needs no network access."""
    link_local_ip = "fe80::1234:5678:9abc:def0"
    ifindex, ifname = socket.if_nameindex()[0]
    aaaa_record = _rr(HOST, QTYPE_AAAA, socket.inet_pton(socket.AF_INET6, link_local_ip))
    packet = _message([*_ptr_srv(HOST, 32498), aaaa_record])

    instances = mdns.assemble_instances([(packet, (link_local_ip, 5353, 0, ifindex))])

    assert len(instances) == 1
    address = instances[0].addresses[0]
    assert address.ip == link_local_ip
    assert address.iface == ifname
    assert address.full_ip == f"{link_local_ip}%{ifname}"


def test_link_local_ipv6_without_a_resolvable_scope_is_dropped():
    link_local_ip = "fe80::dead:beef"
    aaaa_record = _rr(HOST, QTYPE_AAAA, socket.inet_pton(socket.AF_INET6, link_local_ip))
    packet = _message([*_ptr_srv(HOST, 32498), aaaa_record])

    instances = mdns.assemble_instances([(packet, (link_local_ip, 5353, 0, 0))])

    assert instances[0].addresses == []


def test_non_link_local_ipv6_is_dropped():
    """Out of scope for this fix (the bug is IPv4-only, per mdns.py's module docstring): a
    routable, non-link-local IPv6 address carries no scope id to rely on, so it is dropped rather
    than guessed at."""
    global_ip = "2001:db8::1"
    aaaa_record = _rr(HOST, QTYPE_AAAA, socket.inet_pton(socket.AF_INET6, global_ip))
    packet = _message([*_ptr_srv(HOST, 32498), aaaa_record])

    instances = mdns.assemble_instances([(packet, (global_ip, 5353, 0, 1))])

    assert instances[0].addresses == []


def test_srv_without_a_matching_ptr_produces_no_instance():
    a_record = _rr(HOST, QTYPE_A, socket.inet_aton("192.0.2.12"))
    packet = _message([_rr(HOST, QTYPE_SRV, _srv_rdata(HOST, 32498)), a_record])

    assert mdns.assemble_instances([(packet, ("192.0.2.1", 5353))]) == []
