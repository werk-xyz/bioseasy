# SPDX-License-Identifier: GPL-3.0-or-later
"""A demo deployment seeds both demo devices as added; the demo engine must agree that both are
paired, or the iPad's setup wizard refuses its Wi-Fi step with "Pair the device first"."""

from contextlib import closing

from bioseasy import db, demo_seed
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE, PAD = DEMO_DEVICES


def test_seeded_ipad_can_walk_the_setup_wizard(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()

    def connect():
        return db.connect(data / "bioseasy.db")

    with closing(connect()) as conn:
        db.migrate(conn)
    assert demo_seed.seed(connect, root, data_dir=data)

    engine = DemoEngine(step_seconds=0, data_dir=data)
    engine.enable_wifi(PAD.udid)  # raised "Pair the device first" before the seed wrote the state
    assert not engine.encryption_enabled(PAD.udid)  # the iPad still needs the encryption step
    assert engine.encryption_enabled(PHONE.udid)
