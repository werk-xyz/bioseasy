# SPDX-License-Identifier: GPL-3.0-or-later
"""Real devices through pymobiledevice3.

pymobiledevice3 is async; the engine protocol is sync because backups run in worker threads.
Each call therefore runs its own event loop inside the calling thread, which keeps the web
server's loop free of long device sessions.

Connection order for a device: USB if it is plugged in, then a fixed address if one is set, then
Bonjour (mobdev2) discovery. Everything that touches the device before the first progress
callback counts as "waiting for passcode", because iOS asks for it before any data moves.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import plistlib
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    ConnectionTerminatedError,
    MuxException,
    NoDeviceConnectedError,
    NotEnoughDiskSpaceError,
    PairingDialogResponsePendingError,
    PasswordRequiredError,
    PyMobileDevice3Exception,
    UserDeniedPairingError,
)
from pymobiledevice3.lockdown import (
    SERVICE_PORT,
    LockdownClient,
    TcpLockdownClient,
    create_using_tcp,
    create_using_usbmux,
)
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.notification_proxy import NotificationProxyService

from .. import pairing
from . import mdns
from .base import (
    DeviceSeen,
    EngineError,
    NetcheckStep,
    NotConfirmedError,
    PairUsedCallback,
    Phase,
    Progress,
    ProgressCallback,
    SetupState,
    Transport,
    TransportCallback,
)

log = logging.getLogger(__name__)

# A missing or unreachable usbmuxd is the normal case on a server without USB access.
_NO_USB = (MuxException, ConnectionFailedError, NoDeviceConnectedError, OSError)

# service_connection.py's DEFAULT_TIMEOUT for a single TCP connect attempt is 1 second (checked
# against the installed pymobiledevice3==11.12.5), too short for a device across a router or a
# momentarily busy Wi-Fi radio to answer once. A fixed address is retried this many times, with
# this pause between attempts, before _connect gives up on it.
FIXED_HOST_RETRIES = 3
FIXED_HOST_RETRY_DELAY = 1.0

# Bounds one fixed-address probe during discovery, so a tick with several configured devices
# stays quick even when one of them does not answer; deliberately shorter and without the
# retries of _connect_fixed_host, which is for an on-demand operation the user is waiting on.
FIXED_HOST_DISCOVER_TIMEOUT = 5.0

# No progress callback from the device for this long during a backup cancels the run: without
# this, a device that stops sending data (dropped Wi-Fi, a device that fell asleep mid-transfer)
# would leave the run 'running' forever, blocking the next attempt through the runs_one_running
# index (jobs.py, db.py).
STALL_TIMEOUT = 600.0

# Shown together with a ConnectionTerminatedError or another OSError from change_password, once
# a fresh connection could not confirm the device applied it (or, for a password change, could
# never confirm it either way - see _change_encryption_password).
_ENCRYPTION_RECOVERY_HINT = (
    "Keep the device unlocked with its screen on and try again. If it keeps failing, turn on "
    "backup encryption once from a computer over USB (see docs/setup.md)."
)

# A TimeoutError out of change_password can come from two different places that pymobiledevice3
# does not distinguish by exception type: our own asyncio.wait_for(..., timeout=passcode_timeout)
# when nobody confirms on the device, or the 1-second connect on the *new* TCP connection that
# device_link() opens to the backup service's dynamic port (service_connection.py's
# DEFAULT_TIMEOUT, checked against the installed pymobiledevice3==11.12.5) - a plain builtin
# TimeoutError that is never caught inside pymobiledevice3 itself. The two are told apart by how
# much of the passcode window had actually elapsed: a connect failure fires within a few seconds
# no matter how long passcode_timeout is, while "nobody confirmed" only fires once the whole
# window has passed. Anything under this fraction of the window is treated as the former.
_EARLY_TIMEOUT_FRACTION = 0.5


def _timeout_error(elapsed: float, passcode_timeout: float) -> EngineError:
    if elapsed < passcode_timeout * _EARLY_TIMEOUT_FRACTION:
        return EngineError(
            "The device did not accept a connection on its backup service port. Allow all TCP "
            "connections from the bioseasy host to the device, not only port 62078."
        )
    return EngineError("Nobody confirmed on the device in time")


def _same_udid(a: str, b: str) -> bool:
    return a.replace("-", "").lower() == b.replace("-", "").lower()


async def _require_paired(lockdown: LockdownClient) -> LockdownClient:
    """Close and reject a lockdown session whose pair record the device did not accept.

    ``create_using_tcp``/``create_using_usbmux`` with ``autopair=False`` never raise for a
    rejected pair record (InvalidHostID, an expired or wrong record, an SSL failure): they just
    return a client with ``paired == False`` (pymobiledevice3/lockdown.py's `_handle_autopair`,
    checked against the installed pymobiledevice3==11.12.5). Without this check the caller would
    go on to use that unauthenticated session, and `get_will_encrypt` would come back False,
    which used to be reported as "Backup encryption is off" - the device simply never accepted
    the stored pairing.
    """
    if not lockdown.paired:
        await lockdown.close()
        raise EngineError("The device rejected the stored pairing. Pair it again from the Add page.")
    return lockdown


def _wrap_device_error(prefix: str, exc: Exception) -> EngineError:
    """Turn a pymobiledevice3 failure into a message that is safe to show.

    NotEnoughDiskSpaceError's message already describes the shortfall in bytes, computed from
    the device's own response (device_link.py's `_insufficient_disk_space_error`) - no pair
    record content or password, safe to show whole. A "Device link error: ..." message
    (device_link.py's `dl_loop`, raised for every ChangePassword or backup ErrorCode other than
    insufficient disk space) is the device's own short protocol text, equally safe. Anything
    else keeps only the exception's class name, since pymobiledevice3 does not otherwise promise
    its message is free of internal detail.
    """
    # Log the traceback for the operator: without it a real-device test showed only
    # "ConnectionTerminatedError" in the UI and nothing in the container log. The
    # traceback carries frames and the exception text, never local variables, so no password or
    # pair record reaches the log; the device never echoes either back in an error.
    log.warning("%s: %s", prefix, exc.__class__.__name__, exc_info=(type(exc), exc, exc.__traceback__))
    if isinstance(exc, NotEnoughDiskSpaceError) or str(exc).startswith("Device link error:"):
        return EngineError(f"{prefix}: {exc}")
    return EngineError(f"{prefix}: {exc.__class__.__name__}")


# Bounds how long _wifi_heartbeat waits for the device's first Marco before it gives up
# waiting and lets the wrapped operation proceed anyway (the heartbeat task itself keeps running
# either way; a device is not obliged to send its first Marco within any particular window).
HEARTBEAT_FIRST_MARCO_TIMEOUT = 5.0


async def _run_heartbeat(lockdown: LockdownClient, first_marco: asyncio.Event) -> None:
    """Reply "Polo" to every device "Marco" on the heartbeat service, matching
    HeartbeatService.start()'s own loop (pymobiledevice3/services/heartbeat.py:44-51, checked
    against the installed pymobiledevice3==11.12.5) but setting `first_marco` once the first
    message arrives, so a caller can observe that without changing the loop's behaviour."""
    heartbeat = HeartbeatService(lockdown)
    service = await lockdown.start_lockdown_service(heartbeat.service_name)
    try:
        while True:
            await service.recv_plist()
            first_marco.set()
            await service.send_plist({"Command": "Polo"})
    finally:
        await service.close()


@contextlib.asynccontextmanager
async def _wifi_heartbeat(lockdown: LockdownClient) -> AsyncIterator[None]:
    """Run the lockdown heartbeat (Marco/Polo) concurrently for the lifetime of the wrapped
    Wi-Fi operation; a no-op for a USB (usbmux) connection.

    Evidence (real-device test, iPadOS 26.3.1, device paired, lockdown over Wi-Fi
    confirmed working): mobilebackup2 over Wi-Fi fails at the device link version
    exchange with ConnectionTerminatedError. The device log shows that on Wi-Fi only,
    BackupAgent2 checks com.apple.mobile.heartbeat, then logs "lockconn_disable_ssl" and "Error
    calling accept" (MBErrorDomain 100); over USB, where BackupAgent2 never checks the heartbeat,
    the same operation works. HeartbeatService (services/heartbeat.py:10-51) exists precisely to
    keep a lockdown connection alive by answering each device "Marco" with "Polo" on
    com.apple.mobile.heartbeat, so a Wi-Fi session that needs to stay open for a while (a backup,
    or waiting on a passcode prompt for ChangePassword) has to run it concurrently, for the whole
    operation.

    This uses its own, separate TCP lockdown connection rather than the operation's lockdown
    client, based on how pymobiledevice3 itself runs a heartbeat: AmfiService.enable_developer_mode
    (services/amfi.py:81) does `await HeartbeatService(self._lockdown).start()` on the *same*
    shared client, but only ever sequentially, after any other service call on that client has
    finished and before the next one starts - never concurrently with one. That matches what
    LockdownClient offers: `_request` (lockdown.py:982) writes a request and awaits its matching
    response on a single control connection with no multiplexing, and `start_lockdown_service`
    (lockdown.py:879-899) issues such a request before opening the actual service's own socket.
    Our case is different: the wrapped operation keeps using the same lockdown client
    concurrently with the heartbeat loop (Mobilebackup2Service opens NotificationProxyService and
    AfcService on `self.lockdown` while a backup or ChangePassword is in flight,
    mobilebackup2.py:258-259), so sharing one client risks interleaving requests and responses on
    one socket. A dedicated connection, opened the same way _connect_fixed_host does (same
    pair record, keep_alive=False), avoids that.

    A heartbeat failure - the extra connection is refused, or the loop errors out - is logged at
    WARNING (never at a level that could be read as the operation's own result) and otherwise
    swallowed: the wrapped operation's own error, if any, is what must reach the caller.
    """
    if not isinstance(lockdown, TcpLockdownClient):
        yield
        return
    try:
        heartbeat_lockdown = await create_using_tcp(
            hostname=lockdown.hostname, autopair=False, pair_record=lockdown.pair_record, keep_alive=False
        )
    except (PyMobileDevice3Exception, OSError) as exc:
        log.warning("Wi-Fi heartbeat: could not open its own connection: %s", exc.__class__.__name__)
        yield
        return
    first_marco = asyncio.Event()
    task = asyncio.create_task(_run_heartbeat(heartbeat_lockdown, first_marco))
    marco_waiter = asyncio.create_task(first_marco.wait())
    try:
        done, _pending = await asyncio.wait(
            {task, marco_waiter}, timeout=HEARTBEAT_FIRST_MARCO_TIMEOUT, return_when=asyncio.FIRST_COMPLETED
        )
        if marco_waiter in done:
            log.info("Wi-Fi heartbeat: first Marco/Polo exchange received")
        elif task in done:
            exc = task.exception()
            log.warning(
                "Wi-Fi heartbeat failed before its first exchange: %s",
                exc.__class__.__name__ if exc else "task ended",
            )
        else:
            log.info(
                "Wi-Fi heartbeat: no Marco/Polo exchange within %ss, continuing anyway",
                HEARTBEAT_FIRST_MARCO_TIMEOUT,
            )
        marco_waiter.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await marco_waiter
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 - a heartbeat failure must never mask the operation's own error
            log.warning("Wi-Fi heartbeat ended with an error: %s", exc.__class__.__name__)
        try:
            await heartbeat_lockdown.close()
        except Exception as exc:  # noqa: BLE001 - same: closing the extra connection must never raise here
            log.warning("Wi-Fi heartbeat: closing its connection failed: %s", exc.__class__.__name__)


# Timeout for each individual netcheck probe (a bare TCP connect, or one lockdown/service call).
# Deliberately short: netcheck is a diagnostic the owner is watching in the wizard or settings
# page, not an operation that waits out a passcode prompt, so a step that has not answered by
# now is reported as failed rather than left to hang.
NETCHECK_TIMEOUT = 5.0


async def _tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """A bare TCP connect-and-close, no lockdown or TLS involved: tells "nothing answers on this
    port" (firewall, wrong address, device asleep) apart from every later, protocol-level
    failure. Never raises."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        return False, (
            f"Could not open a TCP connection to {host}:{port} ({exc.__class__.__name__}). Check the address, "
            "and allow TCP from the bioseasy host to the device on this port."
        )
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return True, f"TCP {port} at {host} accepted a connection"


class Pmd3Engine:
    name = "pymobiledevice3"

    def __init__(
        self,
        pair_records: Path,
        *,
        backup_root: Path | None = None,
        bonjour_timeout: float = 5.0,
        passcode_timeout: float = 600.0,
        stall_timeout: float = STALL_TIMEOUT,
        fixed_hosts: Callable[[], dict[str, str]] | None = None,
    ):
        self._records = pair_records
        # Only used as the DeviceLink channel's working directory for enable_encryption (it
        # reports free disk space there even though ChangePassword itself transfers no backup
        # files); falls back to the pair records folder so the engine stays constructible
        # without it, e.g. in tests that never call enable_encryption.
        self._backup_root = backup_root or pair_records
        self._bonjour_timeout = bonjour_timeout
        self._passcode_timeout = passcode_timeout
        self._stall_timeout = stall_timeout
        self._fixed_hosts = fixed_hosts or dict

    @property
    def stall_timeout(self) -> float:
        """Seconds a running backup may go without a progress callback before the stall
        watchdog (`_backup` below) fails it. Public so the UI (app.py's device_summary) can
        quote the real configured value instead of a hard-coded number."""
        return self._stall_timeout

    # -- protocol ---------------------------------------------------------------------------

    def discover(self, on_pair_used: PairUsedCallback | None = None) -> list[DeviceSeen]:
        return asyncio.run(self._discover(on_pair_used))

    def pair(self, udid: str) -> None:
        asyncio.run(self._pair(udid))

    def enable_wifi(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> None:
        asyncio.run(self._enable_wifi(udid, on_pair_used))

    def backup(
        self,
        udid: str,
        target_root: Path,
        on_progress: ProgressCallback,
        on_pair_used: PairUsedCallback | None = None,
        on_transport: TransportCallback | None = None,
    ) -> None:
        asyncio.run(self._backup(udid, target_root, on_progress, on_pair_used, on_transport))

    def encryption_enabled(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool:
        return asyncio.run(self._encryption_enabled(udid, on_pair_used))

    def charging_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool | None:
        return asyncio.run(self._charging_state(udid, on_pair_used))

    def enable_encryption(self, udid: str, password: str) -> None:
        try:
            asyncio.run(self._enable_encryption(udid, password))
        finally:
            del password

    def change_encryption_password(self, udid: str, old: str, new: str) -> None:
        try:
            asyncio.run(self._change_encryption_password(udid, old, new))
        finally:
            del old, new

    def netcheck(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> list[NetcheckStep]:
        return asyncio.run(self._netcheck(udid, on_pair_used))

    def detect_setup_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> SetupState:
        return asyncio.run(self._detect_setup_state(udid, on_pair_used))

    # -- implementation -----------------------------------------------------------------------

    @staticmethod
    def _seen(lockdown: LockdownClient, transport: Transport) -> DeviceSeen:
        values = lockdown.all_values or {}
        return DeviceSeen(
            udid=lockdown.udid,
            transport=transport,
            name=values.get("DeviceName"),
            product_type=values.get("ProductType"),
            os_version=values.get("ProductVersion"),
            paired=bool(lockdown.paired),
        )

    async def _usb_serials(self) -> list[str]:
        with contextlib.suppress(*_NO_USB):
            return [d.serial for d in await usbmux.list_devices() if d.connection_type == "USB"]
        return []

    async def _discover(self, on_pair_used: PairUsedCallback | None = None) -> list[DeviceSeen]:
        found: dict[str, DeviceSeen] = {}
        for serial in await self._usb_serials():
            try:
                lockdown = await create_using_usbmux(
                    serial=serial, autopair=False, pairing_records_cache_folder=self._records
                )
            except PyMobileDevice3Exception as exc:
                log.info("USB device %s not usable: %s", serial, exc.__class__.__name__)
                continue
            try:
                found[lockdown.udid] = self._seen(lockdown, Transport.USB)
            finally:
                await lockdown.close()
        async for _address, lockdown in self._wifi_lockdowns(on_pair_used=on_pair_used):
            try:
                if lockdown.udid not in found:
                    found[lockdown.udid] = self._seen(lockdown, Transport.WIFI)
            finally:
                await lockdown.close()
        # A device on a fixed address (typically another subnet, so Bonjour never sees it) is
        # otherwise never 'reachable' for the scheduler and ticker (ticker.py's `seen` mapping),
        # even though _connect can reach it on demand. One short, single-attempt probe per
        # configured host not already found some other way, so a tick with fixed hosts stays
        # bounded in time.
        for udid, host in self._fixed_hosts().items():
            if udid in found:
                continue
            record = pairing.load(self._records, udid)
            if record is None:
                continue
            try:
                lockdown = await asyncio.wait_for(
                    create_using_tcp(hostname=host, autopair=False, pair_record=record),
                    timeout=FIXED_HOST_DISCOVER_TIMEOUT,
                )
            except (PyMobileDevice3Exception, OSError, TimeoutError):
                continue
            try:
                if lockdown.paired:
                    found[udid] = self._seen(lockdown, Transport.WIFI)
                    if on_pair_used:
                        on_pair_used(udid)
            finally:
                await lockdown.close()
        return list(found.values())

    def _pair_records_by_wifi_mac(self) -> dict[str, dict]:
        """MAC -> pair record, glob-loaded the same way pymobiledevice3's own
        `get_mobdev2_lockdowns` does (lockdown.py:1579-1596, checked against the installed
        pymobiledevice3==11.12.5): every `*.plist` under the records folder except a `remote_*`
        (RemotePairing) file. Unlike that original, a file that is not a usable plist, or one
        with no WiFiMACAddress, is skipped rather than raising - our own `pairing.store` always
        writes that key (pairing.py's REQUIRED_KEYS), but this folder is not guaranteed to hold
        only files this code wrote.
        """
        records: dict[str, dict] = {}
        for file in self._records.glob("*.plist"):
            if file.name.startswith("remote_"):
                continue
            try:
                record = plistlib.loads(file.read_bytes())
            except (plistlib.InvalidFileException, ValueError):
                continue
            mac = record.get("WiFiMACAddress")
            if not mac:
                continue
            records[mac] = record
        return records

    async def _wifi_lockdowns(
        self, wanted: str | None = None, on_pair_used: PairUsedCallback | None = None
    ) -> AsyncIterator[tuple[str, LockdownClient]]:
        """Devices found over Bonjour, each authenticated with the record stored under its UDID.

        Uses bioseasy's own `mdns.browse_mobdev2_routed` rather than pymobiledevice3's
        `lockdown.get_mobdev2_lockdowns`: the latter is built on `bonjour.browse_service`, which
        drops every IPv4 address for which `_Adapters.pick_iface_for_ip` finds no local interface
        in the same subnet - exactly the case of a device reached only through an mDNS proxy
        across subnets (see mdns.py's module docstring).
        `browse_mobdev2_routed` keeps those addresses; this method then reproduces
        `get_mobdev2_lockdowns`'s own MAC-based record lookup and connects on the fixed lockdown
        port (SERVICE_PORT), ignoring the SRV port the advertisement carries, exactly as the
        original did.

        pymobiledevice3 matches records by the Wi-Fi MAC in the Bonjour instance name. Since
        iOS 17.1 that is the private MAC, not the one in the record (netmuxd#56), so a paired
        device can come back unauthenticated. We read its UDID from that session and reconnect
        with our own record. Not verified yet: that an unauthenticated session reports the UDID.

        Every lockdown yielded here was authenticated from our own pair_records folder (either
        already, or by the explicit reconnect below), so on_pair_used fires for each - this is
        the "successful discovery connection" trigger for devices.pair_used_at (db.py).
        """
        records_by_mac = self._pair_records_by_wifi_mac()
        for instance in await mdns.browse_mobdev2_routed(timeout=self._bonjour_timeout):
            if "@" not in instance.instance:
                continue
            record = records_by_mac.get(instance.instance.split("@", 1)[0])
            for address in instance.addresses:
                try:
                    lockdown = await create_using_tcp(
                        hostname=address.full_ip, autopair=False, pair_record=record, keep_alive=False
                    )
                except (PyMobileDevice3Exception, OSError):
                    continue
                udid = lockdown.udid
                if not udid or (wanted is not None and not _same_udid(udid, wanted)):
                    await lockdown.close()
                    continue
                if lockdown.paired:
                    if on_pair_used:
                        on_pair_used(udid)
                    yield address.full_ip, lockdown
                    continue
                await lockdown.close()
                try:
                    own_record = pairing.load(self._records, udid)
                except pairing.PairRecordError:
                    own_record = None
                if own_record is None:
                    continue
                try:
                    # keep_alive=False: see the note above _connect_fixed_host - the OS default
                    # keep-alive here gives up after roughly 12 seconds of no ACK, and this
                    # lockdown session is also what any later service connection (backup,
                    # encryption) reuses (TcpLockdownClient.create_service_connection).
                    reconnected = await create_using_tcp(
                        hostname=address.full_ip, autopair=False, pair_record=own_record, keep_alive=False
                    )
                except (PyMobileDevice3Exception, OSError) as exc:
                    log.info(
                        "device %s at %s refused its pair record: %s",
                        udid,
                        address.full_ip,
                        exc.__class__.__name__,
                    )
                    continue
                if not reconnected.paired:
                    await reconnected.close()
                    if wanted is not None:
                        raise EngineError("The device rejected the stored pairing. Pair it again from the Add page.")
                    log.info("device %s at %s rejected the stored pairing", udid, address.full_ip)
                    continue
                if on_pair_used:
                    on_pair_used(udid)
                yield address.full_ip, reconnected

    async def _connect_fixed_host(self, host: str, record: dict) -> LockdownClient:
        """Connect to a device's fixed address, retrying a bare connect failure.

        A single TCP connect attempt only gets 1 second (service_connection.py's
        DEFAULT_TIMEOUT, checked against the installed pymobiledevice3==11.12.5) before it gives
        up - too short for a device on the far side of a router, or one whose Wi-Fi radio is
        momentarily busy, to answer even once. Retried up to FIXED_HOST_RETRIES times with a
        short pause; the final error names the address and port so it is obvious what was tried.

        keep_alive is deliberately False here. osu/os_utils.py's TCP keep-alive defaults
        (checked against the installed pymobiledevice3==11.12.5: DEFAULT_AFTER_IDLE_SEC,
        DEFAULT_INTERVAL_SEC, DEFAULT_MAX_FAILS all 3) kill a socket after roughly 3 + 3*3 = 12
        seconds without an ACK. create_using_tcp's public keep_alive flag has no way to ask for
        gentler values - service_connection.py's create_using_tcp calls
        OSUTIL.set_keepalive(sock) with no parameters, so True always means those same 12
        seconds. Worse, this lockdown session is not just used for the lockdown protocol: every
        later service connection it opens (Mobilebackup2Service for a backup or a ChangePassword
        call) reuses the same setting (TcpLockdownClient.create_service_connection ->
        self._keep_alive), so a device sitting with its screen off waiting for the passcode -
        exactly the situation this operation waits through - could have its socket killed by the
        OS before the human ever gets to it. The 10-minute backup stall watchdog (STALL_TIMEOUT)
        and the passcode timeout used for encryption already cover a connection that is actually
        dead; keep-alive would only add a false positive on a slow but live one.
        """
        last_exc: Exception | None = None
        for attempt in range(FIXED_HOST_RETRIES):
            try:
                return await create_using_tcp(hostname=host, autopair=False, pair_record=record, keep_alive=False)
            except (PyMobileDevice3Exception, OSError) as exc:
                last_exc = exc
                if attempt + 1 < FIXED_HOST_RETRIES:
                    await asyncio.sleep(FIXED_HOST_RETRY_DELAY)
        raise EngineError(f"Device did not answer at {host} on TCP {SERVICE_PORT}") from last_exc

    async def _connect(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> LockdownClient:
        record = pairing.load(self._records, udid)
        for serial in await self._usb_serials():
            if _same_udid(serial, udid):
                lockdown = await create_using_usbmux(
                    serial=serial, autopair=False, pair_record=record, pairing_records_cache_folder=self._records
                )
                if not lockdown.paired:
                    await lockdown.close()
                    if record is None:
                        raise EngineError("This device is not paired with bioseasy yet")
                    raise EngineError("The device rejected the stored pairing. Pair it again from the Add page.")
                if on_pair_used:
                    on_pair_used(udid)
                return lockdown
        if record is None:
            raise EngineError("This device is not paired with bioseasy yet")
        host = self._fixed_hosts().get(udid)
        if host:
            try:
                lockdown = await self._connect_fixed_host(host, record)
                await _require_paired(lockdown)
            except RecursionError as exc:
                # pymobiledevice3 11.12.5 answers a refused ValidatePair by reconnecting and
                # validating again, with no limit, so a device that will not accept this record
                # over Wi-Fi ends as a stack overflow rather than an error. Usually the device
                # has Wi-Fi lockdown connections switched off, which only a cable can change.
                raise EngineError(
                    "The device kept refusing the stored pairing over Wi-Fi. Connect it by cable "
                    "once and switch Wi-Fi backups on, or pair it again from the Add page."
                ) from exc
            if on_pair_used:
                on_pair_used(udid)
            return lockdown
        generator = self._wifi_lockdowns(wanted=udid, on_pair_used=on_pair_used)
        async with contextlib.aclosing(generator):
            async for _address, lockdown in generator:
                return lockdown
        raise EngineError(
            "Device not found on the network. Unlock it and check that it is on Wi-Fi. If bioseasy runs "
            "in a different network, enter the device's IP address as Fixed address in its settings."
        )

    async def _pair(self, udid: str) -> None:
        serials = [s for s in await self._usb_serials() if _same_udid(s, udid)]
        if not serials:
            raise EngineError("Connect the device to this server by USB to pair it")
        lockdown = await create_using_usbmux(
            serial=serials[0], autopair=False, pairing_records_cache_folder=self._records
        )
        try:
            await lockdown.pair(timeout=120)
            record = dict(lockdown.pair_record or {})
            record.setdefault("WiFiMACAddress", lockdown.wifi_mac_address)
            # Stored before Wi-Fi connections are switched on, and deliberately so: a device whose
            # screen locked in the meantime answers that request with lockdownd's "SetProhibited",
            # and losing the pairing that just succeeded - the part that needs a human at the
            # device - would be the worse outcome by far. The setup wizard has its own step for
            # Wi-Fi and reports its own error there.
            pairing.store(self._records, lockdown.udid, pairing.parse(plistlib.dumps(record)))
            try:
                await lockdown.set_enable_wifi_connections(True)
            except PyMobileDevice3Exception as exc:
                log.info("Paired, but the device refused to enable Wi-Fi connections: %s", exc.__class__.__name__)
        except PairingDialogResponsePendingError as exc:
            raise EngineError("Tap Trust on the device, enter the passcode, then try again") from exc
        except UserDeniedPairingError as exc:
            raise EngineError("Pairing was declined on the device") from exc
        except PasswordRequiredError as exc:
            raise EngineError("Unlock the device, then try again") from exc
        except pairing.PairRecordError as exc:
            raise EngineError(f"Pairing finished but the record is unusable: {exc}") from exc
        finally:
            await lockdown.close()

    async def _enable_wifi(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> None:
        # Only over USB, and that is not a limitation of this code: the switch being set here is
        # the one that lets a device accept lockdown connections over Wi-Fi at all. With it off,
        # the device refuses the very session that would turn it on. Tried anyway, the attempt
        # does not fail cleanly - pymobiledevice3 11.12.5 answers a refused ValidatePair by
        # reconnecting and validating again, without end, until Python stops it with a
        # RecursionError and the user sees "Internal error, see the container log".
        if not any(_same_udid(serial, udid) for serial in await self._usb_serials()):
            raise EngineError(
                "Wi-Fi backups can only be switched on while the device is connected by cable, "
                "because the device refuses Wi-Fi connections until it is. Either plug it into "
                "this server, or run the pairing app on your own computer again with the device "
                "unlocked - it switches Wi-Fi backups on while pairing."
            )
        lockdown = await self._connect(udid, on_pair_used)
        try:
            async with _wifi_heartbeat(lockdown):
                await lockdown.set_enable_wifi_connections(True)
        finally:
            await lockdown.close()

    def _require_escrow_bag(self, udid: str) -> None:
        """Fail fast, before ever opening a device connection, when the stored record has no
        EscrowBag: every Mobilebackup2Service call needs one (see pairing.require_escrow_bag) and
        otherwise fails deep inside pymobiledevice3 with a bare KeyError. A missing record is not
        this method's concern - _connect already raises its own clear error for that."""
        record = pairing.load(self._records, udid)
        if record is not None and not record.get("EscrowBag"):
            raise EngineError("This pairing has no escrow bag; pair again while the device is unlocked")

    async def _encryption_enabled(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool:
        self._require_escrow_bag(udid)
        lockdown = await self._connect(udid, on_pair_used)
        try:
            async with _wifi_heartbeat(lockdown), Mobilebackup2Service(lockdown) as service:
                return await service.get_will_encrypt()
        finally:
            await lockdown.close()

    async def _detect_setup_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> SetupState:
        """Read-only detection for the setup wizard (see Engine.detect_setup_state).

        Wi-Fi: LockdownClient.get_enable_wifi_connections() (pymobiledevice3/lockdown.py:519-524,
        checked against the installed pymobiledevice3==11.12.5) reads the same
        `EnableWifiConnections` key in the `com.apple.mobile.wireless_lockdown` domain that
        set_enable_wifi_connections (the setup wizard's own Wi-Fi step, above) writes - a plain
        lockdown get_value call, no service session needed.

        Encryption: Mobilebackup2Service.get_will_encrypt(), the same call
        `_encryption_enabled` already uses for the device settings page.

        Never raises: an unreachable device, a rejected pairing, a missing escrow bag or any
        pymobiledevice3/OS failure on either read leaves that field None ("could not confirm"),
        and the two reads are independent - a failed encryption read does not blank out a
        successful Wi-Fi read or vice versa. Wrapped in `_wifi_heartbeat` like every other
        Wi-Fi operation (see that function's docstring).
        """
        try:
            lockdown = await self._connect(udid, on_pair_used)
        except EngineError:
            return SetupState(wifi_enabled=None, encryption_enabled=None)
        try:
            async with _wifi_heartbeat(lockdown):
                wifi_enabled: bool | None
                try:
                    wifi_enabled = await lockdown.get_enable_wifi_connections()
                except (PyMobileDevice3Exception, OSError) as exc:
                    log.warning(
                        "setup detection: could not read Wi-Fi state for %s: %s", udid[:8], exc.__class__.__name__
                    )
                    wifi_enabled = None
                encryption_enabled: bool | None
                try:
                    self._require_escrow_bag(udid)
                    async with Mobilebackup2Service(lockdown) as service:
                        encryption_enabled = await service.get_will_encrypt()
                except (EngineError, PyMobileDevice3Exception, OSError) as exc:
                    log.warning(
                        "setup detection: could not read encryption state for %s: %s", udid[:8], exc.__class__.__name__
                    )
                    encryption_enabled = None
        finally:
            await lockdown.close()
        return SetupState(wifi_enabled=wifi_enabled, encryption_enabled=encryption_enabled)

    async def _charging_state(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> bool | None:
        """Whether the device is currently charging, read from its diagnostics_relay service.

        UNVERIFIED ON REAL HARDWARE (no full charging-state test against a
        real device yet): the installed pymobiledevice3==11.12.5 has no lockdown domain for
        battery state (there is no `com.apple.mobile.battery`, checked by grepping the package
        source); the only exposed battery information is DiagnosticsService.get_battery()
        (services/diagnostics.py:1090), a thin wrapper around an `IORegistry` request for the
        `IOPMPowerSource` entry over the `com.apple.mobile.diagnostics_relay` lockdown service -
        the same service the `pymobiledevice3 diagnostics battery` CLI command uses, whose
        `IsCharging` key is what this reads. DiagnosticsService is an ordinary LockdownService,
        opened with `lockdown.start_lockdown_service` exactly like Mobilebackup2Service and
        HeartbeatService, so nothing in the source marks it as USB-only; wrapped in
        `_wifi_heartbeat` for the same reason a backup is (see that function's docstring). A
        device that does not answer, or any battery entry missing "IsCharging", returns None
        (unknown) rather than raising - `scheduler.decide` already treats an unknown charging
        state as not satisfying "only while charging", the safer default.
        """
        try:
            lockdown = await self._connect(udid, on_pair_used)
        except EngineError:
            return None
        try:
            async with _wifi_heartbeat(lockdown), DiagnosticsService(lockdown) as service:
                info = await service.get_battery()
        except (PyMobileDevice3Exception, OSError):
            return None
        finally:
            await lockdown.close()
        if info is None or "IsCharging" not in info:
            return None
        return bool(info["IsCharging"])

    async def _will_encrypt_now(self, udid: str) -> bool:
        """Reconnect once and re-read WillEncrypt after a ChangePassword call that raised
        ConnectionTerminatedError, another OSError, or timed out.

        iOS can apply ChangePassword and then still drop the connection while it is busy
        showing the passcode prompt (the device end of device_link.py's dl_loop, or the
        TCP/SSL layer under it, closing first); the exception alone does not say whether the
        device went ahead. WillEncrypt is the device-side state (`get_will_encrypt`,
        mobilebackup2.py:204-212), so a fresh session reads what actually happened rather than
        what bioseasy's own now-dead connection did. Any failure while checking counts as "could
        not confirm" - this only ever turns a failure into a reported success, never the other
        way around, so a False (or an exception) here always still leads to an EngineError.
        """
        try:
            lockdown = await self._connect(udid)
        except EngineError:
            return False
        try:
            async with _wifi_heartbeat(lockdown), Mobilebackup2Service(lockdown) as service:
                return await service.get_will_encrypt()
        except (PyMobileDevice3Exception, OSError):
            return False
        finally:
            await lockdown.close()

    async def _enable_encryption(self, udid: str, password: str) -> None:
        """Turn on backup encryption with pymobiledevice3's own ChangePassword operation.

        Mobilebackup2Service.change_password(backup_directory, old="", new=...)
        (pymobiledevice3/services/mobilebackup2.py:532, checked against the installed
        pymobiledevice3==11.12.5) sends the same "ChangePassword" DeviceLink message Finder and
        iTunes use; omitting `old` is how a device with encryption currently off is switched on.
        The device link still needs a real, writable directory (it reports free disk space
        there even though this operation moves no backup files), so this uses the configured
        backup root, not a directory named after any particular device.

        WillEncrypt is checked twice around the actual call: before, so a device that already
        has encryption on (from an earlier attempt bioseasy never saw confirmed, or from Finder
        or iTunes) is reported done without sending another ChangePassword; after a
        ConnectionTerminatedError, another OSError, or a TimeoutError, so a device that in fact
        applied the change before dropping the connection is reported as the success it was -
        ConnectionTerminatedError about 2 seconds into the call is exactly what a
        real-device test hit. See _will_encrypt_now.
        """
        self._require_escrow_bag(udid)
        lockdown = await self._connect(udid)
        start: float | None = None
        try:
            async with _wifi_heartbeat(lockdown), Mobilebackup2Service(lockdown) as service:
                if await service.get_will_encrypt():
                    return
                start = time.monotonic()
                await asyncio.wait_for(
                    service.change_password(backup_directory=str(self._backup_root), new=password),
                    timeout=self._passcode_timeout,
                )
        except (TimeoutError, ConnectionTerminatedError, OSError) as exc:
            elapsed = time.monotonic() - start if start is not None else 0.0
            if await self._will_encrypt_now(udid):
                return
            if isinstance(exc, TimeoutError):
                raise _timeout_error(elapsed, self._passcode_timeout) from exc
            raise EngineError(
                f"Could not turn on backup encryption: {exc.__class__.__name__}. {_ENCRYPTION_RECOVERY_HINT}"
            ) from exc
        except PyMobileDevice3Exception as exc:
            # Most of the device's own error text is never shown: it can describe an old-
            # password mismatch (backup encryption already on with a password bioseasy never
            # captured, see docs/setup.md) but pymobiledevice3 does not expose a distinct
            # exception type for that case, so only the class name is safe to surface there.
            # _wrap_device_error passes the message through for the two cases where it is known
            # to carry no pair record content or password: insufficient disk space and a generic
            # device-link error.
            raise _wrap_device_error("Could not turn on backup encryption", exc) from exc
        finally:
            await lockdown.close()
            del password

    async def _change_encryption_password(self, udid: str, old: str, new: str) -> None:
        """Change the backup password with pymobiledevice3's own ChangePassword operation.

        Mobilebackup2Service.change_password(backup_directory, old=..., new=...)
        (pymobiledevice3/services/mobilebackup2.py:532, checked against the installed
        pymobiledevice3==11.12.5) sends the same "ChangePassword" DeviceLink message as
        enable_encryption above, this time with both OldPassword and NewPassword set.

        Whether a wrong `old` surfaces as a distinct error was unknown until
        checked against the source: it does not. change_password's own
        dl_loop (pymobiledevice3/services/device_link.py:141-168) only special-cases the
        insufficient-disk-space ErrorCode; every other nonzero ErrorCode, wrong old password
        included, raises the same generic `PyMobileDevice3Exception(f"Device link error:
        {message[1]}")` - a wrong old password cannot be told apart from any other
        ChangePassword failure by exception type alone, but that generic message (and a
        NotEnoughDiskSpaceError's) is safe to pass through as-is; see _wrap_device_error.
        """
        self._require_escrow_bag(udid)
        lockdown = await self._connect(udid)
        start = time.monotonic()
        try:
            async with _wifi_heartbeat(lockdown), Mobilebackup2Service(lockdown) as service:
                await asyncio.wait_for(
                    service.change_password(backup_directory=str(self._backup_root), old=old, new=new),
                    timeout=self._passcode_timeout,
                )
        except TimeoutError as exc:
            raise _timeout_error(time.monotonic() - start, self._passcode_timeout) from exc
        except (ConnectionTerminatedError, OSError) as exc:
            # Unlike _enable_encryption, WillEncrypt cannot confirm a password change either
            # way - it reads True whether the *old* or the *new* password is the one now in
            # effect - so there is nothing to re-read here; report the failure plainly instead
            # of guessing.
            raise EngineError(
                f"Could not change the backup password: {exc.__class__.__name__}. {_ENCRYPTION_RECOVERY_HINT}"
            ) from exc
        except PyMobileDevice3Exception as exc:
            raise _wrap_device_error("Could not change the backup password", exc) from exc
        finally:
            await lockdown.close()
            del old, new

    async def _backup(
        self,
        udid: str,
        target_root: Path,
        on_progress: ProgressCallback,
        on_pair_used: PairUsedCallback | None = None,
        on_transport: TransportCallback | None = None,
    ) -> None:
        self._require_escrow_bag(udid)
        first_progress = asyncio.Event()
        progress_since_check = asyncio.Event()

        def progress(percent: float) -> None:
            first_progress.set()
            progress_since_check.set()
            on_progress(Progress(Phase.TRANSFERRING, percent=float(percent)))

        async def run() -> None:
            lockdown = await self._connect(udid, on_pair_used)
            if on_transport:
                # _connect tries USB (usbmux) first, then a fixed host or Bonjour over Wi-Fi
                # (both TcpLockdownClient); a plugged-in device is found over USB even on a
                # server whose whole purpose is Wi-Fi backups, so the transport actually used
                # must be read off the connection, never assumed - see TransportCallback.
                on_transport(Transport.WIFI if isinstance(lockdown, TcpLockdownClient) else Transport.USB)
            try:
                async with _wifi_heartbeat(lockdown), Mobilebackup2Service(lockdown) as service:
                    if not await service.get_will_encrypt():
                        raise EngineError("Backup encryption is off on this device; turn it on before backing up")
                    await service.backup(full=False, backup_directory=str(target_root), progress_callback=progress)
            finally:
                await lockdown.close()

        on_progress(Progress(Phase.WAITING_FOR_PASSCODE, message="Unlock the device and enter its passcode"))
        task = asyncio.create_task(run())
        waiter = asyncio.create_task(first_progress.wait())
        done, _ = await asyncio.wait(
            {task, waiter}, timeout=self._passcode_timeout, return_when=asyncio.FIRST_COMPLETED
        )
        if not done:
            task.cancel()
            waiter.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            raise NotConfirmedError("Nobody confirmed the backup on the device in time")
        waiter.cancel()

        # Progress has started; now watch for a stall. asyncio.wait's timeout only tells us the
        # task did not finish within stall_timeout, not whether progress happened during that
        # window, so progress_since_check is cleared before each wait and checked after it - a
        # stall is only real if the whole window passed with no progress callback at all.
        while not task.done():
            progress_since_check.clear()
            await asyncio.wait({task}, timeout=self._stall_timeout)
            if not task.done() and not progress_since_check.is_set():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                minutes = int(self._stall_timeout // 60)
                raise EngineError(f"No data from the device for {minutes} minutes; the backup was stopped")

        try:
            await task
        except EngineError:
            raise
        except AssertionError as exc:
            # The backup protocol's own dl_loop asserts on a malformed device response
            # (device_link.py, e.g. "assert code == CODE_SUCCESS"); these carry no message, but
            # str(exc) is included on the rare chance one does - at most a short protocol
            # detail, never pair record content or a password.
            detail = f" ({exc})" if str(exc) else ""
            raise EngineError(f"Backup failed: the device closed the connection{detail}") from exc
        except (PyMobileDevice3Exception, OSError) as exc:
            raise _wrap_device_error("Backup failed", exc) from exc
        on_progress(Progress(Phase.FINISHING))

    async def _netcheck(self, udid: str, on_pair_used: PairUsedCallback | None = None) -> list[NetcheckStep]:
        """Read-only connectivity check against a device's stored pairing, run from the server's
        own position. This is the web-interface counterpart of the pairing helper's Diagnose mode
        (helper/bioseasy_pair_helper.py's run_diagnose): the helper cannot be imported here (its
        own docstring: it is a single-file script served over HTTP and must stay import-free of
        this package, "kept in sync ... BY HAND, not by import"), so this reimplements the same
        pymobiledevice3 11.12.5 calls (create_using_tcp, HeartbeatService's Marco/Polo loop via
        this module's own _run_heartbeat, NotificationProxyService as a second lockdown service,
        Mobilebackup2Service's dynamic service port) rather than the helper's fuller probe set
        (it also compares full-TLS against handshake-only SSL and captures a filtered device
        syslog - out of scope here: this check is meant to run unattended from the web UI, not
        interactively from a Mac with a USB cable).

        Only ever checks the configured fixed address (devices.host): that is the scenario this
        feature exists for - a device in another subnet is only reachable this way, since mDNS
        does not cross subnets. USB and
        the Bonjour fallback used by every other engine call are not probed here since the
        pairing helper already covers USB, and a Bonjour-only device does not have the "server
        cannot find it" problem this check diagnoses.

        Never starts a new pairing (autopair=False throughout) and never triggers a Trust prompt.
        Steps run in order and stop at the first failure. Every detail string is built here, not
        taken from the device or from pymobiledevice3's own exception message beyond the
        exception's class name (see _wrap_device_error for the same rule elsewhere in this
        module): none of it may ever carry pair record content.
        """
        steps: list[NetcheckStep] = []
        host = self._fixed_hosts().get(udid)
        if not host:
            steps.append(
                NetcheckStep(
                    "Fixed address configured",
                    False,
                    "No fixed address is set for this device. If it is in a different network "
                    "than bioseasy, set one in the setup wizard or under device settings.",
                )
            )
            return steps

        ok, detail = await _tcp_probe(host, SERVICE_PORT, NETCHECK_TIMEOUT)
        steps.append(NetcheckStep(f"Address reachable (TCP {SERVICE_PORT})", ok, detail))
        if not ok:
            return steps

        record = pairing.load(self._records, udid)
        if record is None:
            steps.append(NetcheckStep("Stored pairing", False, "This device is not paired with bioseasy yet."))
            return steps
        try:
            lockdown = await asyncio.wait_for(
                create_using_tcp(hostname=host, autopair=False, pair_record=record, keep_alive=False),
                timeout=NETCHECK_TIMEOUT,
            )
        except (PyMobileDevice3Exception, OSError, TimeoutError) as exc:
            steps.append(NetcheckStep("Stored pairing", False, f"Lockdown did not answer: {exc.__class__.__name__}"))
            return steps
        try:
            if not lockdown.paired:
                steps.append(
                    NetcheckStep(
                        "Stored pairing",
                        False,
                        "The device rejected the stored pairing (no new pairing was attempted). "
                        "Pair it again from the Add page.",
                    )
                )
                return steps
            steps.append(NetcheckStep("Stored pairing", True, "Lockdown accepted the stored pair record"))
            if on_pair_used:
                on_pair_used(udid)

            try:
                async with NotificationProxyService(lockdown):
                    pass
            except (PyMobileDevice3Exception, OSError, TimeoutError) as exc:
                steps.append(NetcheckStep("Secure session", False, f"{exc.__class__.__name__}"))
                return steps
            steps.append(NetcheckStep("Secure session", True, "The TLS session and a lockdown service both work"))

            first_marco = asyncio.Event()
            heartbeat_task = asyncio.create_task(_run_heartbeat(lockdown, first_marco))
            try:
                await asyncio.wait_for(first_marco.wait(), timeout=HEARTBEAT_FIRST_MARCO_TIMEOUT)
                steps.append(NetcheckStep("Heartbeat", True, "The device answered Marco/Polo"))
            except TimeoutError:
                steps.append(
                    NetcheckStep(
                        "Heartbeat",
                        False,
                        f"No heartbeat reply within {int(HEARTBEAT_FIRST_MARCO_TIMEOUT)}s. A backup can still fail "
                        "over Wi-Fi even though the checks above passed.",
                    )
                )
            finally:
                heartbeat_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await heartbeat_task

            try:
                attr = await asyncio.wait_for(
                    lockdown.get_service_connection_attributes(
                        Mobilebackup2Service.SERVICE_NAME, include_escrow_bag=True
                    ),
                    timeout=NETCHECK_TIMEOUT,
                )
                port = attr.get("Port")
            except (PyMobileDevice3Exception, OSError, TimeoutError) as exc:
                steps.append(
                    NetcheckStep("Backup service port reachable (optional)", False, f"{exc.__class__.__name__}")
                )
            else:
                if not port:
                    steps.append(
                        NetcheckStep(
                            "Backup service port reachable (optional)",
                            False,
                            "The device did not offer a dynamic port for the backup service.",
                        )
                    )
                else:
                    ok, detail = await _tcp_probe(host, port, NETCHECK_TIMEOUT)
                    steps.append(NetcheckStep("Backup service port reachable (optional)", ok, detail))
        finally:
            await lockdown.close()
        return steps
