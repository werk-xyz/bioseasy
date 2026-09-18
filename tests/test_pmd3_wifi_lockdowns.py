# SPDX-License-Identifier: GPL-3.0-or-later
"""`Pmd3Engine._wifi_lockdowns` with `mdns.browse_mobdev2_routed` and `create_using_tcp` both
faked: proves the MAC-matching and unpaired-reconnect loop that replaced the direct call to
pymobiledevice3's `lockdown.get_mobdev2_lockdowns` (see pmd3.py's module and method docstrings,
and engine/mdns.py). No network, no real device."""

from __future__ import annotations

import asyncio
import plistlib

from bioseasy import pairing
from bioseasy.engine import mdns, pmd3

UDID = "00008110-000A1B2C3D4E5F60"
OTHER_UDID = "00008110-AAAAAAAAAAAAAAAA"
MAC = "AA:BB:CC:DD:EE:FF"
INSTANCE = f"{MAC}@bioseasy-fake._apple-mobdev2._tcp.local."
ADDRESS = mdns.Address(ip="192.0.2.12", iface=None)


def _instance(instance_name: str = INSTANCE, addresses=(ADDRESS,)) -> mdns.ServiceInstance:
    return mdns.ServiceInstance(instance=instance_name, host="iPad.local", port=32498, addresses=list(addresses))


class FakeLockdown:
    def __init__(self, udid: str | None, *, paired: bool):
        self.udid = udid
        self.paired = paired
        self.closed = False

    async def close(self):
        self.closed = True


def _store_record(records_dir, udid: str, mac: str) -> dict:
    """A minimal dict written straight to disk, bypassing pairing.store's certificate validation
    (irrelevant here - only WiFiMACAddress and the udid<->file mapping matter to this loop)."""
    record = {"WiFiMACAddress": mac, "HostID": "host", "marker": udid}
    (records_dir / f"{udid}.plist").write_bytes(plistlib.dumps(record))
    return record


async def _collect(engine, **kwargs):
    result = []
    async for address, lockdown in engine._wifi_lockdowns(**kwargs):
        result.append((address, lockdown))
    return result


def test_matches_a_pair_record_by_wifi_mac_and_yields_the_already_paired_lockdown(tmp_path, monkeypatch):
    _store_record(tmp_path, UDID, MAC)
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    seen_records = []

    async def fake_browse(timeout):
        assert timeout == 1.0
        return [_instance()]

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        assert hostname == ADDRESS.full_ip
        assert autopair is False
        assert keep_alive is False
        seen_records.append(pair_record)
        return FakeLockdown(UDID, paired=True)

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)

    pair_used = []
    results = asyncio.run(_collect(engine, on_pair_used=pair_used.append))

    assert [lockdown.udid for _, lockdown in results] == [UDID]
    assert results[0][0] == ADDRESS.full_ip
    assert pair_used == [UDID]
    assert seen_records[0]["WiFiMACAddress"] == MAC


def test_no_mac_match_still_reconnects_using_the_udid_the_device_itself_reports(tmp_path, monkeypatch):
    """The iOS 17.1+ private-MAC case (pmd3.py's `_wifi_lockdowns` docstring): the Bonjour name
    matches no stored record, so the first connect goes out with pair_record=None and comes back
    unpaired; bioseasy then looks up its own record by the UDID that connection reported and
    reconnects with it."""
    own_record = _store_record(tmp_path, UDID, "11:22:33:44:55:66")  # different MAC than advertised
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    calls = []

    async def fake_browse(timeout):
        return [_instance()]  # instance MAC matches nothing in the records folder

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        calls.append(pair_record)
        if len(calls) == 1:
            assert pair_record is None
            return FakeLockdown(UDID, paired=False)
        assert pair_record["marker"] == UDID
        return FakeLockdown(UDID, paired=True)

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3.pairing, "load", lambda folder, udid: own_record if udid == UDID else None)

    pair_used = []
    results = asyncio.run(_collect(engine, on_pair_used=pair_used.append))

    assert len(calls) == 2
    assert [ld.udid for _, ld in results] == [UDID]
    assert pair_used == [UDID]  # only the successful reconnect fires on_pair_used, not the failed first attempt


def test_unpaired_reconnect_with_no_stored_record_is_skipped_without_crashing(tmp_path, monkeypatch):
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    async def fake_browse(timeout):
        return [_instance()]

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return FakeLockdown(UDID, paired=False)

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3.pairing, "load", lambda folder, udid: None)

    assert asyncio.run(_collect(engine)) == []


def test_wanted_udid_filters_out_every_other_device(tmp_path, monkeypatch):
    _store_record(tmp_path, UDID, MAC)
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    async def fake_browse(timeout):
        return [_instance()]

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return FakeLockdown(OTHER_UDID, paired=True)

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)

    assert asyncio.run(_collect(engine, wanted=UDID)) == []


def test_wanted_device_rejecting_the_stored_pairing_raises(tmp_path, monkeypatch):
    own_record = _store_record(tmp_path, UDID, "11:22:33:44:55:66")
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    async def fake_browse(timeout):
        return [_instance()]

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return FakeLockdown(UDID, paired=False)  # every attempt comes back unpaired

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3.pairing, "load", lambda folder, udid: own_record if udid == UDID else None)

    try:
        asyncio.run(_collect(engine, wanted=UDID))
    except pmd3.EngineError as exc:
        assert "rejected the stored pairing" in str(exc)
    else:
        raise AssertionError("expected EngineError")


def test_records_folder_ignores_remote_pairing_files_and_files_without_a_wifi_mac(tmp_path, monkeypatch):
    """`_pair_records_by_wifi_mac` must not crash on a `remote_*` RemotePairing file (a different
    record shape, deliberately skipped, matching pymobiledevice3's own get_mobdev2_lockdowns) or
    on a plist with no WiFiMACAddress key."""
    (tmp_path / "remote_something.plist").write_bytes(plistlib.dumps({"WiFiMACAddress": "should:not:match"}))
    (tmp_path / "no-mac.plist").write_bytes(plistlib.dumps({"HostID": "x"}))
    _store_record(tmp_path, UDID, MAC)
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    records = engine._pair_records_by_wifi_mac()

    assert set(records) == {MAC}


def test_matches_pairing_load_error_is_treated_as_no_record(tmp_path, monkeypatch):
    """A record file that fails pairing.load's own validation (PairRecordError) must be treated
    the same as no record at all, not raise out of the discovery loop."""
    engine = pmd3.Pmd3Engine(tmp_path, bonjour_timeout=1.0)

    async def fake_browse(timeout):
        return [_instance()]

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return FakeLockdown(UDID, paired=False)

    def raising_load(folder, udid):
        raise pairing.PairRecordError("broken")

    monkeypatch.setattr(mdns, "browse_mobdev2_routed", fake_browse)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3.pairing, "load", raising_load)

    assert asyncio.run(_collect(engine)) == []
