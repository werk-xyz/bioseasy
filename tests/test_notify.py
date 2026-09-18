# SPDX-License-Identifier: GPL-3.0-or-later
import threading
import time

import apprise
import pytest

from bioseasy import notify


def test_validate_urls_accepts_offline_parseable_urls():
    assert notify.validate_urls(["json://localhost", "mailto://user:pass@example.com"]) == []


def test_validate_urls_rejects_bad_urls_without_leaking_them():
    secret_url = "mailto://alice:super-secret-password@example.com"
    problems = notify.validate_urls(["not a url at all", secret_url.replace("mailto", "bogus-scheme")])
    assert len(problems) == 2
    for problem in problems:
        assert "super-secret-password" not in problem
        assert "example.com" not in problem


def test_send_with_no_urls_fails_without_talking_to_apprise():
    result = notify.send([], "title", "body")
    assert result.ok is False
    assert "No notification" in result.error


def test_send_reports_ok_without_sending_a_real_notification(monkeypatch):
    monkeypatch.setattr(apprise.Apprise, "notify", lambda self, **kwargs: True)
    result = notify.send(["json://localhost"], "title", "body")
    assert result.ok is True
    assert result.error == ""


def test_send_reports_failure_without_sending_a_real_notification(monkeypatch):
    monkeypatch.setattr(apprise.Apprise, "notify", lambda self, **kwargs: False)
    result = notify.send(["json://localhost"], "title", "body")
    assert result.ok is False
    assert result.error


def test_send_turns_a_crash_into_a_safe_result(monkeypatch):
    def boom(self, **kwargs):
        raise RuntimeError("network is unreachable")

    monkeypatch.setattr(apprise.Apprise, "notify", boom)
    result = notify.send(["json://localhost"], "title", "body")
    assert result.ok is False
    assert "network is unreachable" not in result.error


@pytest.mark.parametrize(
    "event",
    ["waiting_for_passcode", "succeeded", "failed", "not_confirmed", "overdue", "storage_failed", "upcoming"],
)
def test_message_for_covers_every_event(event):
    title, body = notify.message_for(event, "Anna's iPhone", "some detail")
    assert title and body
    assert "\n" not in title


def test_message_for_unknown_event_raises():
    with pytest.raises(ValueError):
        notify.message_for("no-such-event", "device")


def test_send_does_not_block_the_caller_past_send_timeout(monkeypatch):
    """A fake (no real socket) that never returns from notify() -- standing in for a target that
    accepts the connection and then never answers, or dribbles bytes slowly enough to keep
    resetting Apprise's own per-operation timeout. send() must still hand control back to the
    caller within _SEND_TIMEOUT, not hang forever."""
    monkeypatch.setattr(notify, "_SEND_TIMEOUT", 0.2)
    release = threading.Event()

    def hang(self, **kwargs):
        release.wait(timeout=5)  # released after the test asserts, so the thread can exit cleanly
        return True

    monkeypatch.setattr(apprise.Apprise, "notify", hang)

    start = time.monotonic()
    result = notify.send(["json://localhost"], "title", "body")
    elapsed = time.monotonic() - start

    assert elapsed < 1.0, f"send() blocked for {elapsed}s, past its own _SEND_TIMEOUT"
    assert result.ok is False
    assert "timed out" in result.error
    release.set()


def test_send_timeout_error_never_carries_the_url_or_a_secret(monkeypatch):
    monkeypatch.setattr(notify, "_SEND_TIMEOUT", 0.1)
    release = threading.Event()
    monkeypatch.setattr(apprise.Apprise, "notify", lambda self, **kwargs: release.wait(timeout=5))

    secret_url = "mailto://alice:super-secret-password@example.com"
    result = notify.send([secret_url], "title", "body")

    assert "super-secret-password" not in result.error
    assert "example.com" not in result.error
    release.set()


def test_message_for_upcoming_names_minutes_and_iphone_or_ipad():
    _, body_phone = notify.message_for("upcoming", "Anna's iPhone", "5", "iPhone14,5")
    assert "starts in 5 minutes" in body_phone
    assert "iPhone" in body_phone
    assert "charger" in body_phone
    assert "passcode prompt" in body_phone

    _, body_pad = notify.message_for("upcoming", "Anna's iPad", "5", "iPad13,1")
    assert "iPad" in body_pad
