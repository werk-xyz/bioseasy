# SPDX-License-Identifier: GPL-3.0-or-later
"""A demo deployment runs one demo engine in the web process and one in the worker. A real device
paired through the code hand-off must walk the whole setup wizard there, with each step seen by
both."""

from bioseasy import pairing
from bioseasy.engine.demo import DemoEngine

REAL_UDID = "00008120-001A2B3C4D5E6F70"


def test_a_handed_off_record_counts_as_paired_and_state_is_shared_between_processes(tmp_path):
    pairing.store(tmp_path / "pair-records", REAL_UDID, {"HostID": "handed-off"})
    web = DemoEngine(step_seconds=0, data_dir=tmp_path)
    worker = DemoEngine(step_seconds=0, data_dir=tmp_path)

    worker.enable_wifi(REAL_UDID)  # the Wi-Fi step runs in the worker
    web.enable_encryption(REAL_UDID, "correct horse battery")  # the encryption step in the web process
    assert worker.encryption_enabled(REAL_UDID)

    seen = []
    worker.backup(REAL_UDID, tmp_path / "backups", seen.append)
    assert (tmp_path / "backups" / REAL_UDID / "Status.plist").is_file()
    assert "correct horse battery" not in (tmp_path / "demo-engine-state.json").read_text()


def test_without_a_record_an_unknown_device_is_still_refused(tmp_path):
    engine = DemoEngine(step_seconds=0, data_dir=tmp_path)
    try:
        engine.enable_wifi(REAL_UDID)
    except Exception as exc:  # EngineError
        assert "Pair the device first" in str(exc)
    else:
        raise AssertionError("an unpaired device must be refused")
