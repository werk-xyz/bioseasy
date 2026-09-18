# SPDX-License-Identifier: GPL-3.0-or-later
"""DemoEngine's own small behaviours that are not covered by the JobManager-level tests in
test_jobs_storage.py."""

import pytest

from bioseasy.engine.base import EngineError, PairingRoute, Phase
from bioseasy.engine.demo import DEMO_DEVICES, DEMO_PAIRING_CODE, DemoEngine

PHONE = DEMO_DEVICES[0]
TABLET = DEMO_DEVICES[1]  # starts unpaired


def test_backup_mentions_the_configured_fixed_address(tmp_path):
    """runtime.make_engine wires devices.host into DemoEngine the same way as Pmd3Engine
    (engine/pmd3.py); this is the demo side of that wiring actually being used."""
    engine = DemoEngine(step_seconds=0, fixed_hosts=lambda: {PHONE.udid: "192.0.2.9"})
    engine.pair(PHONE.udid)
    seen = []
    engine.backup(PHONE.udid, tmp_path, seen.append)
    first = next(p for p in seen if p.phase == Phase.WAITING_FOR_PASSCODE)
    assert "192.0.2.9" in first.message


def test_backup_without_a_fixed_address_says_nothing_about_one(tmp_path):
    engine = DemoEngine(step_seconds=0)
    engine.pair(PHONE.udid)
    seen = []
    engine.backup(PHONE.udid, tmp_path, seen.append)
    first = next(p for p in seen if p.phase == Phase.WAITING_FOR_PASSCODE)
    assert "connecting to" not in first.message


# --- netcheck --------------------------------------------------------------------------------


def test_netcheck_without_a_fixed_address_reports_one_failed_step():
    engine = DemoEngine(step_seconds=0)
    engine.pair(PHONE.udid)
    steps = engine.netcheck(PHONE.udid)
    assert len(steps) == 1
    assert steps[0].name == "Fixed address configured"
    assert not steps[0].ok


def test_netcheck_requires_pairing_first():
    engine = DemoEngine(step_seconds=0, fixed_hosts=lambda: {TABLET.udid: "192.0.2.10"})
    steps = engine.netcheck(TABLET.udid)
    assert len(steps) == 1
    assert steps[0].name == "Stored pairing"
    assert not steps[0].ok


def test_netcheck_deterministic_success():
    """The default, deterministic success path used by the UI and its own tests."""
    engine = DemoEngine(step_seconds=0, fixed_hosts=lambda: {PHONE.udid: "192.0.2.9"})
    engine.pair(PHONE.udid)
    used = []
    steps = engine.netcheck(PHONE.udid, on_pair_used=used.append)
    names = [s.name for s in steps]
    assert names == [
        "Address reachable (TCP 62078)",
        "Stored pairing",
        "Secure session",
        "Heartbeat",
        "Backup service port reachable (optional)",
    ]
    assert all(s.ok for s in steps)
    assert used == [PHONE.udid]


def test_netcheck_deterministic_failure():
    """fail_udids (already used by DemoEngine.backup to simulate a dropped connection) doubles
    as the deterministic failure case here: the device is unreachable at its fixed address."""
    engine = DemoEngine(
        step_seconds=0, fixed_hosts=lambda: {PHONE.udid: "192.0.2.9"}, fail_udids=frozenset({PHONE.udid})
    )
    engine.pair(PHONE.udid)
    steps = engine.netcheck(PHONE.udid)
    assert len(steps) == 1
    assert steps[0].name == "Address reachable (TCP 62078)"
    assert not steps[0].ok
    assert "192.0.2.9" in steps[0].detail


def test_charging_state_defaults_to_true_for_a_paired_device():
    # Every paired demo device charges by default so the default only_when_charging=on policy
    # does not block the demo/sandbox schedule end to end (see defaults.py, engine/demo.py).
    engine = DemoEngine(step_seconds=0)
    assert engine.charging_state(PHONE.udid) is True


def test_charging_state_is_none_for_an_unpaired_device():
    unpaired = DEMO_DEVICES[1]
    engine = DemoEngine(step_seconds=0)
    assert engine.charging_state(unpaired.udid) is None


def test_charging_state_honours_not_charging_udids():
    engine = DemoEngine(step_seconds=0, not_charging_udids=frozenset({PHONE.udid}))
    assert engine.charging_state(PHONE.udid) is False


def test_charging_state_fires_on_pair_used_for_a_paired_device():
    engine = DemoEngine(step_seconds=0)
    seen = []
    engine.charging_state(PHONE.udid, on_pair_used=seen.append)
    assert seen == [PHONE.udid]


# --- the iOS 27 wireless entrance --------------------------------------------------------------


def test_demo_devices_still_run_ios_below_27_by_default():
    """The demo story is unchanged by the iOS 27 work: both devices keep the single lockdown
    entrance unless a test or a demo deployment deliberately puts one on a newer version."""
    engine = DemoEngine(step_seconds=0)
    for device in DEMO_DEVICES:
        assert engine.pairing_routes(device.udid) == (PairingRoute.LOCKDOWN,)


def test_an_ios_27_demo_device_offers_both_entrances():
    engine = DemoEngine(step_seconds=0, os_versions={TABLET.udid: "27.0"})
    assert engine.pairing_routes(TABLET.udid) == (PairingRoute.LOCKDOWN, PairingRoute.REMOTE_PAIRING)
    # The other device is untouched by the override.
    assert engine.pairing_routes(PHONE.udid) == (PairingRoute.LOCKDOWN,)


def test_pair_wireless_hands_out_a_code_and_pairs_the_device():
    engine = DemoEngine(step_seconds=0, os_versions={TABLET.udid: "27.0"})
    codes = []
    engine.pair_wireless(TABLET.udid, codes.append)
    assert codes == [DEMO_PAIRING_CODE]
    assert len(codes[0]) == 6 and codes[0].isdigit()
    assert engine.pairing_route(TABLET.udid) is PairingRoute.REMOTE_PAIRING


def test_pair_wireless_refuses_a_device_below_ios_27():
    engine = DemoEngine(step_seconds=0)
    with pytest.raises(EngineError) as excinfo:
        engine.pair_wireless(TABLET.udid, lambda code: None)
    assert "27" in str(excinfo.value)
    assert engine.pairing_route(TABLET.udid) is None


def test_pair_wireless_refuses_a_device_whose_version_cannot_be_read():
    """An unknown version is never treated as new enough (engine/ios27.py)."""
    engine = DemoEngine(step_seconds=0, os_versions={TABLET.udid: "unknown"})
    with pytest.raises(EngineError):
        engine.pair_wireless(TABLET.udid, lambda code: None)


def test_a_device_paired_the_old_way_still_reports_the_lockdown_route():
    engine = DemoEngine(step_seconds=0)
    engine.pair(TABLET.udid)
    assert engine.pairing_route(TABLET.udid) is PairingRoute.LOCKDOWN


def test_a_wirelessly_paired_device_backs_up_exactly_like_any_other(tmp_path):
    """The fourth entrance changes how a device is paired, nothing after it."""
    engine = DemoEngine(step_seconds=0, os_versions={TABLET.udid: "27.0"})
    engine.pair_wireless(TABLET.udid, lambda code: None)
    engine.enable_encryption(TABLET.udid, "demo-password")
    seen = []
    engine.backup(TABLET.udid, tmp_path, seen.append)
    assert [p.phase for p in seen][-1] is Phase.FINISHING
    assert (tmp_path / TABLET.udid / "Manifest.plist").is_file()
