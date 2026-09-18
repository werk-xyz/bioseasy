# SPDX-License-Identifier: GPL-3.0-or-later
"""Failed device steps must reach the container log, not only the UI (first real-device test)."""

import logging
from contextlib import closing
from types import SimpleNamespace

from pymobiledevice3.exceptions import ConnectionTerminatedError

from bioseasy import db, runtime
from bioseasy.engine import pmd3


def test_wrapped_device_error_is_logged_with_its_class_and_traceback(caplog):
    try:
        raise ConnectionTerminatedError()
    except ConnectionTerminatedError as exc:
        with caplog.at_level(logging.WARNING):
            wrapped = pmd3._wrap_device_error("Could not turn on backup encryption", exc)
    assert "ConnectionTerminatedError" in str(wrapped)
    record = next(r for r in caplog.records if "Could not turn on backup encryption" in r.getMessage())
    assert record.levelno == logging.WARNING
    assert record.exc_info is not None


def test_failed_setup_step_is_logged_without_secrets(tmp_path, caplog):
    path = tmp_path / "bioseasy.db"
    with closing(db.connect(path)) as conn:
        db.migrate(conn)
    rt = SimpleNamespace(connect=lambda: db.connect(path))
    with caplog.at_level(logging.WARNING):
        runtime._setup_action_failed(
            rt, "00008103-001122334455667A", "encryption", "Could not turn on backup encryption: X"
        )
    text = caplog.text
    assert "setup step encryption failed for device 00008103" in text
    assert "001122334455667A" not in text  # only a shortened UDID
