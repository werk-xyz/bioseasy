# SPDX-License-Identifier: GPL-3.0-or-later
"""Engine control flow with pymobiledevice3 replaced by fakes; the device protocol itself needs a
real device and is not covered here."""

import asyncio
import time

import pytest
from pymobiledevice3.exceptions import NotEnoughDiskSpaceError, PyMobileDevice3Exception

from bioseasy.engine import mdns, pmd3
from bioseasy.engine.base import EngineError, NotConfirmedError, Phase

UDID = "00008110-000A1B2C3D4E5F60"


class FakeLockdown:
    closed = False
    paired = True

    async def close(self):
        FakeLockdown.closed = True


class FakeTcpLockdown(pmd3.TcpLockdownClient):
    """Stands in for a real Wi-Fi (TCP) lockdown connection so isinstance(lockdown,
    TcpLockdownClient) in _wifi_heartbeat recognizes it; __init__ is overridden so the real
    TcpLockdownClient.__init__ (which needs an actual ServiceConnection) never runs."""

    def __init__(self, hostname="192.0.2.9", pair_record=None):
        self.hostname = hostname
        self.pair_record = pair_record or {"fake": "record"}
        self.paired = True
        self.closed = False

    async def close(self):
        self.closed = True


class FakeHeartbeatConnection(pmd3.TcpLockdownClient):
    """The extra TCP lockdown connection _wifi_heartbeat opens for itself. Subclasses
    TcpLockdownClient (like FakeTcpLockdown) so HeartbeatService picks the plain lockdown
    heartbeat service name rather than the RSD/tunnel variant."""

    def __init__(self, service):
        self.hostname = "192.0.2.9"
        self.pair_record = {"fake": "record"}
        self.closed = False
        self.service = service
        self.requested_service_names = []

    async def start_lockdown_service(self, name):
        self.requested_service_names.append(name)
        return self.service

    async def close(self):
        self.closed = True


class FakeHeartbeatService:
    """Fake heartbeat service connection: yields `marcos` Marco messages, replying with Polo
    for each, then hangs (like a real device between Marcos) until cancelled."""

    def __init__(self, marcos=1):
        self._marcos = marcos
        self._sent_count = 0
        self.sent = []
        self.closed = False

    async def recv_plist(self):
        if self._sent_count >= self._marcos:
            await asyncio.sleep(3600)
        return {"Command": "Marco"}

    async def send_plist(self, plist):
        self.sent.append(plist)
        self._sent_count += 1

    async def close(self):
        self.closed = True


def fake_service(
    *,
    encrypt=True,
    steps=(50.0, 100.0),
    hang=False,
    stall_after_first=False,
    change_password_calls=None,
    change_password_hangs=False,
):
    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            return encrypt

        async def backup(self, full, backup_directory, progress_callback):
            if hang:
                await asyncio.sleep(3600)
            if stall_after_first:
                progress_callback(steps[0])
                await asyncio.sleep(3600)
            for pct in steps:
                progress_callback(pct)

        async def change_password(self, backup_directory=".", old="", new=""):
            if change_password_hangs:
                await asyncio.sleep(3600)
            if change_password_calls is not None:
                change_password_calls.append((backup_directory, old, new))

    return Service


@pytest.fixture
def engine(tmp_path, monkeypatch):
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.2)

    async def connect(udid, on_pair_used=None):
        if on_pair_used:
            on_pair_used(udid)
        return FakeLockdown()

    monkeypatch.setattr(e, "_connect", connect)
    FakeLockdown.closed = False
    return e


def test_backup_reports_phases_in_order(engine, monkeypatch, tmp_path):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service())
    seen = []
    engine.backup(UDID, tmp_path, lambda p: seen.append((p.phase, p.percent)))
    assert seen == [
        (Phase.WAITING_FOR_PASSCODE, None),
        (Phase.TRANSFERRING, 50.0),
        (Phase.TRANSFERRING, 100.0),
        (Phase.FINISHING, None),
    ]
    assert FakeLockdown.closed


def test_unconfirmed_backup_times_out_as_not_confirmed(engine, monkeypatch, tmp_path):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(hang=True))
    with pytest.raises(NotConfirmedError):
        engine.backup(UDID, tmp_path, lambda p: None)
    assert FakeLockdown.closed


def test_backup_without_an_escrow_bag_is_refused_before_connecting(tmp_path, monkeypatch):
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.2)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})  # no EscrowBag key

    async def fail_if_called(udid, on_pair_used=None):
        raise AssertionError("_connect must not be called when the record has no escrow bag")

    monkeypatch.setattr(e, "_connect", fail_if_called)
    with pytest.raises(EngineError, match="escrow bag"):
        e.backup(UDID, tmp_path, lambda p: None)


def test_stalled_backup_is_cancelled_after_no_progress(monkeypatch, tmp_path):
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=5.0, stall_timeout=0.2)

    async def connect(udid, on_pair_used=None):
        return FakeLockdown()

    monkeypatch.setattr(e, "_connect", connect)
    FakeLockdown.closed = False
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(stall_after_first=True))

    with pytest.raises(EngineError, match="No data from the device"):
        e.backup(UDID, tmp_path, lambda p: None)
    assert FakeLockdown.closed


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (NotEnoughDiskSpaceError("needs 512 more bytes"), "needs 512 more bytes"),
        (PyMobileDevice3Exception("Device link error: some device text"), "Device link error: some device text"),
        (PyMobileDevice3Exception("SomeOtherFailure"), "PyMobileDevice3Exception"),
    ],
)
def test_wrap_device_error_passes_through_only_safe_messages(exc, expected):
    err = pmd3._wrap_device_error("Backup failed", exc)
    assert str(err) == f"Backup failed: {expected}"


def test_backup_reports_a_device_link_error_with_its_own_text(engine, monkeypatch, tmp_path):
    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            return True

        async def backup(self, full, backup_directory, progress_callback):
            raise PyMobileDevice3Exception("Device link error: disk full on device")

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    with pytest.raises(EngineError, match="Device link error: disk full on device"):
        engine.backup(UDID, tmp_path, lambda p: None)


def test_backup_reports_an_assertion_from_the_backup_protocol(engine, monkeypatch, tmp_path):
    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            return True

        async def backup(self, full, backup_directory, progress_callback):
            assert False, "unreachable"  # noqa: B011, PT015 - simulates device_link.py's own bare assert

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    with pytest.raises(EngineError, match="the device closed the connection"):
        engine.backup(UDID, tmp_path, lambda p: None)


def test_unencrypted_device_is_refused(engine, monkeypatch, tmp_path):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=False))
    with pytest.raises(EngineError, match="encryption is off"):
        engine.backup(UDID, tmp_path, lambda p: None)


def test_unpaired_device_without_usb_is_reported(tmp_path, monkeypatch):
    e = pmd3.Pmd3Engine(tmp_path)

    async def no_usb():
        return []

    monkeypatch.setattr(e, "_usb_serials", no_usb)
    with pytest.raises(EngineError, match="not paired"):
        asyncio.run(e._connect(UDID))


def _paired_no_usb(e, monkeypatch):
    """No USB devices, and a pair record already on file, so _connect falls through to the
    fixed address (or, without one, to Bonjour)."""

    async def no_usb():
        return []

    monkeypatch.setattr(e, "_usb_serials", no_usb)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})


def test_discover_reports_a_fixed_address_device_over_wifi(tmp_path, monkeypatch):
    """A device in another subnet is never found by USB or Bonjour; _discover must still probe
    its configured fixed address so the scheduler and ticker see it as reachable."""

    class PairedLockdown(FakeLockdown):
        udid = UDID
        all_values = {"DeviceName": "iPad", "ProductType": "iPad1,1", "ProductVersion": "18.0"}

    async def no_usb():
        return []

    async def no_bonjour(wanted=None, on_pair_used=None):
        for _ in ():
            yield _

    async def fake_create_using_tcp(*, hostname, autopair, pair_record):
        return PairedLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    monkeypatch.setattr(e, "_usb_serials", no_usb)
    monkeypatch.setattr(e, "_wifi_lockdowns", no_bonjour)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    seen = asyncio.run(e._discover())

    assert [d.udid for d in seen] == [UDID]
    assert seen[0].transport == pmd3.Transport.WIFI
    assert FakeLockdown.closed


def test_discover_skips_an_unpaired_fixed_address_device(tmp_path, monkeypatch):
    class UnpairedLockdown(FakeLockdown):
        paired = False

    async def no_usb():
        return []

    async def no_bonjour(wanted=None, on_pair_used=None):
        for _ in ():
            yield _

    async def fake_create_using_tcp(*, hostname, autopair, pair_record):
        return UnpairedLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    monkeypatch.setattr(e, "_usb_serials", no_usb)
    monkeypatch.setattr(e, "_wifi_lockdowns", no_bonjour)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    assert asyncio.run(e._discover()) == []
    assert FakeLockdown.closed


def test_connect_uses_the_configured_fixed_address(tmp_path, monkeypatch):
    calls = []

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=False):
        calls.append(hostname)
        return FakeLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    _paired_no_usb(e, monkeypatch)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    lockdown = asyncio.run(e._connect(UDID))

    assert calls == ["192.0.2.9"]
    assert isinstance(lockdown, FakeLockdown)


def test_connect_reports_a_rejected_pair_record_at_a_fixed_address(tmp_path, monkeypatch):
    """create_using_tcp(autopair=False) does not raise for a rejected record (InvalidHostID, an
    expired or wrong record, an SSL failure) - it returns a client with paired == False
    (pymobiledevice3/lockdown.py's _handle_autopair). _connect must turn that into a clear error
    instead of handing back an unauthenticated session that would later look like "encryption
    is off"."""

    class UnpairedLockdown(FakeLockdown):
        paired = False

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=False):
        return UnpairedLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    _paired_no_usb(e, monkeypatch)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    with pytest.raises(EngineError, match="rejected the stored pairing"):
        asyncio.run(e._connect(UDID))
    assert FakeLockdown.closed


def test_connect_retries_a_fixed_address_before_giving_up(tmp_path, monkeypatch):
    calls = []

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=False):
        calls.append(hostname)
        if len(calls) < pmd3.FIXED_HOST_RETRIES:
            raise OSError("timed out")
        return FakeLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    _paired_no_usb(e, monkeypatch)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3, "FIXED_HOST_RETRY_DELAY", 0.0)
    FakeLockdown.closed = False

    lockdown = asyncio.run(e._connect(UDID))

    assert len(calls) == pmd3.FIXED_HOST_RETRIES
    assert isinstance(lockdown, FakeLockdown)


def test_connect_reports_an_unreachable_fixed_address(tmp_path, monkeypatch):
    calls = []

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=False):
        calls.append(hostname)
        raise OSError("no route to host")

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    _paired_no_usb(e, monkeypatch)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3, "FIXED_HOST_RETRY_DELAY", 0.0)

    with pytest.raises(EngineError, match="192.0.2.9.*TCP 62078"):
        asyncio.run(e._connect(UDID))
    assert len(calls) == pmd3.FIXED_HOST_RETRIES


def test_connect_without_a_fixed_address_falls_through_to_bonjour(tmp_path, monkeypatch):
    """No fixed address configured for this device: _connect must not even try create_using_tcp,
    and instead reaches _wifi_lockdowns (here made to find nothing, for a clean, specific error)."""

    async def no_bonjour(wanted=None, on_pair_used=None):
        for _ in ():  # an async generator that yields nothing
            yield _

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {})
    _paired_no_usb(e, monkeypatch)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("create_using_tcp must not be called without a configured address")

    monkeypatch.setattr(pmd3, "create_using_tcp", fail_if_called)
    monkeypatch.setattr(e, "_wifi_lockdowns", no_bonjour)

    with pytest.raises(EngineError, match="not found on the network"):
        asyncio.run(e._connect(UDID))


def test_encryption_enabled_reads_get_will_encrypt(engine, monkeypatch):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=False))
    assert engine.encryption_enabled(UDID) is False
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=True))
    assert engine.encryption_enabled(UDID) is True
    assert FakeLockdown.closed


def test_enable_encryption_turns_it_on_with_only_the_new_password(engine, monkeypatch):
    # change_password(old="", new=...) is how a device with encryption off is switched on
    # (pymobiledevice3/services/mobilebackup2.py:532); this must never send an "old" password,
    # since bioseasy never has one to send.
    calls = []
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=False, change_password_calls=calls))
    engine.enable_encryption(UDID, "correct horse battery")
    assert calls == [(str(engine._backup_root), "", "correct horse battery")]
    assert FakeLockdown.closed


def test_enable_encryption_skips_change_password_when_already_on(engine, monkeypatch):
    """WillEncrypt read before the call is already True: an earlier attempt may have gone
    through on the device even though bioseasy never saw a confirmation, or Finder/iTunes
    turned it on. change_password must not be sent again in that case."""
    calls = []
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=True, change_password_calls=calls))
    engine.enable_encryption(UDID, "correct horse battery")
    assert calls == []
    assert FakeLockdown.closed


def test_enable_encryption_times_out_if_nobody_confirms(engine, monkeypatch):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=False, change_password_hangs=True))
    with pytest.raises(EngineError, match="Nobody confirmed"):
        engine.enable_encryption(UDID, "correct horse battery")
    assert FakeLockdown.closed


def test_enable_encryption_gives_the_port_message_for_an_early_timeout(engine, monkeypatch):
    """A TimeoutError that fires almost instantly is the 1-second service-port connect deep
    inside pymobiledevice3 (service_connection.py's DEFAULT_TIMEOUT), not our own
    passcode-window wait_for - it must not be reported as "Nobody confirmed"."""

    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            return False

        async def change_password(self, backup_directory=".", old="", new=""):
            raise TimeoutError("connect timed out")

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    # The fixture's 0.2 s window makes "early" mean under 0.1 s, which a loaded full-suite run
    # overshot once; the instant TimeoutError is early against any real window.
    monkeypatch.setattr(engine, "_passcode_timeout", 60.0)
    with pytest.raises(EngineError, match="did not accept a connection"):
        engine.enable_encryption(UDID, "correct horse battery")
    assert FakeLockdown.closed


def test_enable_encryption_reports_success_when_terminated_but_now_on(engine, monkeypatch):
    """A ConnectionTerminatedError from change_password does not mean the device rejected the
    change - iOS can apply it and drop the connection anyway while showing the passcode
    prompt. A reconnect that finds WillEncrypt now True must be reported as success."""
    attempts = {"n": 0}

    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            # False on the pre-check, True on the post-failure re-read.
            attempts["n"] += 1
            return attempts["n"] > 1

        async def change_password(self, backup_directory=".", old="", new=""):
            raise pmd3.ConnectionTerminatedError()

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    engine.enable_encryption(UDID, "correct horse battery")  # must not raise
    assert FakeLockdown.closed


def test_enable_encryption_raises_the_hint_when_terminated_and_still_off(engine, monkeypatch):
    """The counterpart of the above: WillEncrypt is still False after the reconnect, so this
    must raise, naming the exception class and the recovery hint, and never claim success."""

    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get_will_encrypt(self):
            return False

        async def change_password(self, backup_directory=".", old="", new=""):
            raise pmd3.ConnectionTerminatedError()

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    with pytest.raises(EngineError, match="ConnectionTerminatedError.*Keep the device unlocked"):
        engine.enable_encryption(UDID, "correct horse battery")
    assert FakeLockdown.closed


def test_change_encryption_password_times_out_if_nobody_confirms(engine, monkeypatch):
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(change_password_hangs=True))
    with pytest.raises(EngineError, match="Nobody confirmed"):
        engine.change_encryption_password(UDID, "old", "new")
    assert FakeLockdown.closed


def test_change_encryption_password_gives_the_port_message_for_an_early_timeout(engine, monkeypatch):
    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def change_password(self, backup_directory=".", old="", new=""):
            raise TimeoutError("connect timed out")

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    with pytest.raises(EngineError, match="did not accept a connection"):
        engine.change_encryption_password(UDID, "old", "new")
    assert FakeLockdown.closed


def test_change_encryption_password_reports_the_failure_plainly_when_terminated(engine, monkeypatch):
    """Unlike enable_encryption, a password change can never be confirmed by WillEncrypt (it
    reads True either way), so a ConnectionTerminatedError must always raise, never claim
    success, and still name the exception class and the recovery hint."""

    class Service:
        def __init__(self, lockdown):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def change_password(self, backup_directory=".", old="", new=""):
            raise pmd3.ConnectionTerminatedError()

    monkeypatch.setattr(pmd3, "Mobilebackup2Service", Service)
    with pytest.raises(EngineError, match="ConnectionTerminatedError.*Keep the device unlocked"):
        engine.change_encryption_password(UDID, "old", "new")
    assert FakeLockdown.closed


def test_connect_fixed_host_disables_keep_alive(tmp_path, monkeypatch):
    """osu/os_utils.py's TCP keep-alive defaults kill an idle socket after roughly 12 seconds
    (checked against the installed pymobiledevice3==11.12.5), and create_using_tcp's public
    keep_alive flag offers no gentler setting - this lockdown session is also what any later
    backup or encryption service connection reuses, so it must not opt into that."""
    calls = []

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=True):
        calls.append(keep_alive)
        return FakeLockdown()

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    _paired_no_usb(e, monkeypatch)
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    asyncio.run(e._connect(UDID))

    assert calls == [False]


def test_wifi_reconnect_disables_keep_alive(tmp_path, monkeypatch):
    """`_wifi_lockdowns` (engine/mdns.py's browse result fed into pmd3.py's own MAC/UDID match
    and reconnect loop, replacing pymobiledevice3's `get_mobdev2_lockdowns`) must pass
    keep_alive=False on every `create_using_tcp` call it makes itself - see the note above
    `_connect_fixed_host` for why: the OS default keep-alive kills the socket after roughly 12
    seconds, and this lockdown session is reused by later service connections."""

    class UnauthLockdown(FakeLockdown):
        udid = UDID
        paired = False

    calls = []
    attempts = []

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive=True):
        calls.append(keep_alive)
        attempts.append(pair_record)
        if len(attempts) == 1:
            return UnauthLockdown()
        return FakeLockdown()

    async def one_instance(timeout):
        return [
            mdns.ServiceInstance(
                instance="aa:bb:cc:dd:ee:ff@host._apple-mobdev2._tcp.local.",
                host="host.local",
                port=62078,
                addresses=[mdns.Address(ip="192.0.2.9", iface=None)],
            )
        ]

    e = pmd3.Pmd3Engine(tmp_path)
    monkeypatch.setattr(mdns, "browse_mobdev2_routed", one_instance)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})
    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    FakeLockdown.closed = False

    results = asyncio.run(_collect(e._wifi_lockdowns()))

    assert calls == [False, False]  # the first (unpaired) connect and the reconnect, both
    assert len(results) == 1


async def _collect(agen):
    return [item async for item in agen]


# -- Wi-Fi heartbeat (Marco/Polo) --------------------------------------------------------------


def test_wifi_heartbeat_runs_and_stops_around_a_wifi_backup(tmp_path, monkeypatch):
    """A Wi-Fi (TCP) lockdown connection gets its own heartbeat, started before the operation and
    stopped (task cancelled, its own connection closed) once the operation finishes."""
    monkeypatch.setattr(pmd3, "HEARTBEAT_FIRST_MARCO_TIMEOUT", 0.2)
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.2)
    tcp_lockdown = FakeTcpLockdown()

    async def connect(udid, on_pair_used=None):
        return tcp_lockdown

    monkeypatch.setattr(e, "_connect", connect)

    heartbeat_service = FakeHeartbeatService(marcos=1)
    heartbeat_conn = FakeHeartbeatConnection(heartbeat_service)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        assert hostname == tcp_lockdown.hostname
        assert pair_record == tcp_lockdown.pair_record
        assert keep_alive is False
        return heartbeat_conn

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service())

    e.backup(UDID, tmp_path, lambda p: None)

    assert heartbeat_conn.requested_service_names == ["com.apple.mobile.heartbeat"]
    assert heartbeat_service.sent == [{"Command": "Polo"}]  # replied to the one Marco it saw
    assert heartbeat_conn.closed
    assert tcp_lockdown.closed


def test_wifi_heartbeat_not_started_for_usb(tmp_path, monkeypatch):
    """A USB (usbmux) lockdown connection is not a TcpLockdownClient; _wifi_heartbeat must be a
    no-op for it, since the device only checks the heartbeat over Wi-Fi."""
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.2)

    async def connect(udid, on_pair_used=None):
        return FakeLockdown()

    monkeypatch.setattr(e, "_connect", connect)
    FakeLockdown.closed = False

    def fail_if_called(*args, **kwargs):
        raise AssertionError("create_using_tcp must not be called for a USB (non-TCP) lockdown")

    monkeypatch.setattr(pmd3, "create_using_tcp", fail_if_called)
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service())

    e.backup(UDID, tmp_path, lambda p: None)

    assert FakeLockdown.closed


def test_wifi_heartbeat_failure_does_not_mask_the_operations_own_error(tmp_path, monkeypatch):
    """The heartbeat's own connection fails outright (refused); the backup's own error - here,
    encryption being off on the device - must still be the one reported, not the heartbeat's."""
    monkeypatch.setattr(pmd3, "HEARTBEAT_FIRST_MARCO_TIMEOUT", 0.2)
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.2)
    tcp_lockdown = FakeTcpLockdown()

    async def connect(udid, on_pair_used=None):
        return tcp_lockdown

    monkeypatch.setattr(e, "_connect", connect)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        raise OSError("heartbeat connection refused")

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service(encrypt=False))

    with pytest.raises(EngineError, match="encryption is off"):
        e.backup(UDID, tmp_path, lambda p: None)
    assert tcp_lockdown.closed


def test_wifi_heartbeat_first_marco_wait_is_bounded(tmp_path, monkeypatch):
    """A device that never sends a Marco within the bound must not hang the operation - the wait
    for the first exchange gives up after HEARTBEAT_FIRST_MARCO_TIMEOUT and the operation, and the
    heartbeat loop underneath it, keep running."""
    monkeypatch.setattr(pmd3, "HEARTBEAT_FIRST_MARCO_TIMEOUT", 0.1)
    e = pmd3.Pmd3Engine(tmp_path, passcode_timeout=0.5)
    tcp_lockdown = FakeTcpLockdown()

    async def connect(udid, on_pair_used=None):
        return tcp_lockdown

    monkeypatch.setattr(e, "_connect", connect)

    heartbeat_service = FakeHeartbeatService(marcos=0)  # never sends a Marco
    heartbeat_conn = FakeHeartbeatConnection(heartbeat_service)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return heartbeat_conn

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)
    monkeypatch.setattr(pmd3, "Mobilebackup2Service", fake_service())

    start = time.monotonic()
    e.backup(UDID, tmp_path, lambda p: None)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0  # bounded by HEARTBEAT_FIRST_MARCO_TIMEOUT, not the fake's 3600s hang
    assert heartbeat_conn.closed


# --- netcheck --------------------------------------------------------------------------------


class FakeNetcheckLockdown(pmd3.TcpLockdownClient):
    """Stands in for the lockdown session netcheck opens directly (not through _connect): paired,
    closeable, and answering get_service_connection_attributes the way a real device would for
    Mobilebackup2Service's dynamic port."""

    def __init__(self, paired=True, port=49290):
        self.paired = paired
        self.closed = False
        self.port = port

    async def close(self):
        self.closed = True

    async def get_service_connection_attributes(self, name, include_escrow_bag=True):
        return {"Port": self.port}


class FakeNotificationProxy:
    def __init__(self, lockdown):
        self.lockdown = lockdown

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def _ok_heartbeat(lockdown, first_marco):
    first_marco.set()
    await asyncio.sleep(3600)


async def _silent_heartbeat(lockdown, first_marco):
    await asyncio.sleep(3600)


def _netcheck_engine(tmp_path, monkeypatch, *, host="192.0.2.9"):
    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: host} if host else {})
    monkeypatch.setattr(pmd3, "HEARTBEAT_FIRST_MARCO_TIMEOUT", 0.1)
    monkeypatch.setattr(pmd3, "NETCHECK_TIMEOUT", 0.5)
    monkeypatch.setattr(pmd3, "NotificationProxyService", FakeNotificationProxy)
    monkeypatch.setattr(pmd3, "_run_heartbeat", _ok_heartbeat)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})
    return e


def test_netcheck_without_a_fixed_address_reports_one_failed_step(tmp_path, monkeypatch):
    e = _netcheck_engine(tmp_path, monkeypatch, host=None)

    async def fail_if_called(*a, **kw):
        raise AssertionError("no probe should run without a configured address")

    monkeypatch.setattr(pmd3, "_tcp_probe", fail_if_called)
    steps = e.netcheck(UDID)
    assert len(steps) == 1
    assert steps[0].name == "Fixed address configured"
    assert not steps[0].ok
    assert "different network" in steps[0].detail


def test_netcheck_stops_when_the_port_is_unreachable(tmp_path, monkeypatch):
    e = _netcheck_engine(tmp_path, monkeypatch)

    async def unreachable(host, port, timeout):
        return False, f"Could not open a TCP connection to {host}:{port}"

    monkeypatch.setattr(pmd3, "_tcp_probe", unreachable)

    async def fail_if_called(**kw):
        raise AssertionError("must not try to open lockdown when the port itself is unreachable")

    monkeypatch.setattr(pmd3, "create_using_tcp", fail_if_called)

    steps = e.netcheck(UDID)
    assert len(steps) == 1
    assert steps[0].name == "Address reachable (TCP 62078)"
    assert not steps[0].ok


def test_netcheck_reports_no_stored_pairing_without_starting_one(tmp_path, monkeypatch):
    e = _netcheck_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(pmd3, "_tcp_probe", lambda host, port, timeout: _ok(True, "reachable"))
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: None)

    async def fail_if_called(**kw):
        raise AssertionError("no lockdown session without a stored record")

    monkeypatch.setattr(pmd3, "create_using_tcp", fail_if_called)

    steps = e.netcheck(UDID)
    assert steps[-1].name == "Stored pairing"
    assert not steps[-1].ok
    assert "not paired" in steps[-1].detail


def test_netcheck_reports_a_rejected_pairing_without_repairing(tmp_path, monkeypatch):
    """autopair=False must always be used: a rejected record is reported as a failed step, and
    lockdown.pair() (the Trust dialog) must never be called from netcheck."""
    e = _netcheck_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(pmd3, "_tcp_probe", lambda host, port, timeout: _ok(True, "reachable"))
    lockdown = FakeNetcheckLockdown(paired=False)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        assert autopair is False
        return lockdown

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)

    steps = e.netcheck(UDID)
    assert steps[-1].name == "Stored pairing"
    assert not steps[-1].ok
    assert "no new pairing" in steps[-1].detail
    assert lockdown.closed


def test_netcheck_full_success_path(tmp_path, monkeypatch):
    e = _netcheck_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(pmd3, "_tcp_probe", lambda host, port, timeout: _ok(True, f"TCP {port} at {host} ok"))
    lockdown = FakeNetcheckLockdown(paired=True, port=49290)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return lockdown

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)

    used = []
    steps = e.netcheck(UDID, on_pair_used=used.append)

    names = [s.name for s in steps]
    assert names == [
        "Address reachable (TCP 62078)",
        "Stored pairing",
        "Secure session",
        "Heartbeat",
        "Backup service port reachable (optional)",
    ]
    assert all(s.ok for s in steps)
    assert used == [UDID]
    assert lockdown.closed
    # The fake pair record's own content ({"fake": "record"}) never leaks into a detail string.
    assert all("fake" not in s.detail for s in steps)


def test_netcheck_heartbeat_timeout_still_runs_the_optional_service_port_step(tmp_path, monkeypatch):
    e = _netcheck_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(pmd3, "_run_heartbeat", _silent_heartbeat)
    monkeypatch.setattr(pmd3, "_tcp_probe", lambda host, port, timeout: _ok(True, "ok"))
    lockdown = FakeNetcheckLockdown(paired=True)

    async def fake_create_using_tcp(*, hostname, autopair, pair_record, keep_alive):
        return lockdown

    monkeypatch.setattr(pmd3, "create_using_tcp", fake_create_using_tcp)

    steps = e.netcheck(UDID)
    heartbeat_step = next(s for s in steps if s.name == "Heartbeat")
    assert not heartbeat_step.ok
    assert steps[-1].name == "Backup service port reachable (optional)"
    assert steps[-1].ok


async def _ok(value, detail):
    return value, detail


def test_enabling_wifi_without_a_cable_says_why_instead_of_trying(tmp_path, monkeypatch):
    """The switch being set is the one that lets the device accept Wi-Fi lockdown connections at
    all, so it can only be set over USB. Attempted over Wi-Fi, pymobiledevice3 11.12.5 does not
    fail cleanly: it answers a refused ValidatePair by reconnecting and validating again until
    Python raises RecursionError, and the user sees "Internal error, see the container log"."""

    async def no_usb():
        return []

    async def must_not_connect(*args, **kwargs):
        raise AssertionError("no connection may be opened without USB")

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    monkeypatch.setattr(e, "_usb_serials", no_usb)
    monkeypatch.setattr(e, "_connect", must_not_connect)

    with pytest.raises(pmd3.EngineError, match="connected by cable"):
        asyncio.run(e._enable_wifi(UDID))


def test_a_device_that_keeps_refusing_the_pairing_over_wifi_gets_a_message_not_a_stack_overflow(tmp_path, monkeypatch):
    """pymobiledevice3's endless reconnect loop reaches Python's recursion limit. Whatever else
    that is, it is not something to show a user as "Internal error"."""

    async def no_usb():
        return []

    async def recursing(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    e = pmd3.Pmd3Engine(tmp_path, fixed_hosts=lambda: {UDID: "192.0.2.9"})
    monkeypatch.setattr(e, "_usb_serials", no_usb)
    monkeypatch.setattr(e, "_connect_fixed_host", recursing)
    monkeypatch.setattr(pmd3.pairing, "load", lambda records, udid: {"fake": "record"})

    with pytest.raises(pmd3.EngineError, match="kept refusing the stored pairing"):
        asyncio.run(e._connect(UDID))


def test_a_refused_wifi_switch_never_costs_the_pairing(tmp_path, monkeypatch):
    """The device asks a human to unlock it and tap Trust; that is the expensive part. When it
    then refuses to switch Wi-Fi connections on - lockdownd answers "SetProhibited" while the
    screen is locked - the pair record must already be stored, or the whole trip was wasted."""
    from pymobiledevice3.exceptions import SetProhibitedError

    stored = {}

    class RefusingLockdown(FakeLockdown):
        udid = UDID
        wifi_mac_address = "aa:bb:cc:dd:ee:ff"
        pair_record = {"HostID": "host"}

        async def pair(self, timeout=120):
            return None

        async def set_enable_wifi_connections(self, value):
            raise SetProhibitedError("SetProhibited", UDID, "18.0")

    async def fake_create_using_usbmux(**kwargs):
        return RefusingLockdown()

    async def one_usb():
        return [UDID]

    e = pmd3.Pmd3Engine(tmp_path)
    monkeypatch.setattr(e, "_usb_serials", one_usb)
    monkeypatch.setattr(pmd3, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(pmd3.pairing, "parse", lambda data: {"parsed": True})
    monkeypatch.setattr(pmd3.pairing, "store", lambda records, udid, record: stored.update({udid: record}))

    asyncio.run(e._pair(UDID))  # must not raise

    assert stored == {UDID: {"parsed": True}}
