# SPDX-License-Identifier: GPL-3.0-or-later
"""bioseasy pair helper: a self-contained desktop app for macOS, Windows and Linux that does exactly
what the served `bioseasy-pair.py` code hand-off script does (see src/bioseasy/handoff.py,
docs/pairing.md, "Pair from my computer"), packaged as a windowed app for anyone who does not want
to install uv or Python.

Kept in sync with handoff.py's build_script BY HAND, not by import: build_script emits a
single-file PEP 723 script served over plain HTTP and run with `uv run <url>`, so it cannot
import this module or any other local package - the served bytes have to be the whole program.
This file mirrors the same pymobiledevice3 11.12.5 API calls (usbmux.list_devices,
create_using_usbmux, LockdownClient.pair/set_enable_wifi_connections/pair_record) and the same
POST to `/pair/{code}` with the `X-Bioseasy-UDID` / `X-Bioseasy-Device-Name` headers and a raw
plist body. If one side changes how pairing or the upload works, the other must change too -
there is no test that catches drift between them, only this comment.

Never print or log the pair record: it is a full device credential (docs/pairing.md).
"""

from __future__ import annotations

import asyncio
import contextlib
import plistlib
import queue
import re
import ssl
import sys
import tempfile
import threading
import time
import tkinter as tk
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tkinter import scrolledtext, ttk

import certifi

APP_TITLE = "bioseasy pair helper"
REQUEST_TIMEOUT_SECONDS = 30
PAIR_TIMEOUT_SECONDS = 120


class PairingError(RuntimeError):
    """Something in the pairing flow failed; message is safe to show, never contains key material."""


@dataclass
class PairResult:
    udid: str
    device_name: str
    server_reply: str


def ssl_context() -> ssl.SSLContext:
    """TLS verification via certifi's bundle.

    A frozen app does not see the macOS keychain through urllib the way a normal Python
    install does, so we point at certifi's CA bundle explicitly. Never disable verification.
    """
    return ssl.create_default_context(cafile=certifi.where())


async def list_usb_devices_async():
    """Returns pymobiledevice3 usbmux entries whose connection_type is "USB".

    pymobiledevice3 11.12.5's usbmux and lockdown APIs are asyncio-based throughout (checked
    against the installed package under .venv); this and every function below mirror that.
    """
    from pymobiledevice3 import usbmux

    return [d for d in await usbmux.list_devices() if d.connection_type == "USB"]


def list_usb_devices():
    """Sync wrapper for list_usb_devices_async, for the self-test which has no running loop."""
    return asyncio.run(list_usb_devices_async())


async def pair_and_read_record(serial: str, on_status: Callable[[str], None]) -> tuple[dict, str, str]:
    """Pairs the device at `serial` over USB and reads back the pair record.

    Mirrors src/bioseasy/engine/pmd3.py's own _pair() and handoff.py's build_script:
      - lockdown.create_using_usbmux(serial=..., autopair=False) (lockdown.py:1370) to connect
      - LockdownClient.pair(timeout=120) (lockdown.py:631) to run the Trust dialog
      - LockdownClient.set_enable_wifi_connections(True) (lockdown.py:510)
      - LockdownClient.pair_record / .wifi_mac_address (lockdown.py:299) to read the record back

    Returns (record, udid, device_name). Never logs the record itself.
    """
    from pymobiledevice3.exceptions import PyMobileDevice3Exception
    from pymobiledevice3.lockdown import create_using_usbmux

    lockdown = await create_using_usbmux(serial=serial, autopair=False)
    try:
        on_status('Unlock the iPhone and tap "Trust" if it asks. Waiting up to two minutes...')
        try:
            await lockdown.pair(timeout=PAIR_TIMEOUT_SECONDS)
        except PyMobileDevice3Exception as exc:
            raise PairingError(f"Pairing failed: {exc.__class__.__name__}") from exc
        # The pairing is the part that needed a human at the device, so it is never thrown away
        # because of what comes after it: a locked screen makes lockdownd answer "SetProhibited"
        # here, and the record would have been lost with it.
        record = dict(lockdown.pair_record or {})
        record.setdefault("WiFiMACAddress", lockdown.wifi_mac_address)
        try:
            await lockdown.set_enable_wifi_connections(True)
        except Exception as exc:  # noqa: BLE001 - nothing here may cost the pairing
            on_status(
                f"The device refused to switch Wi-Fi backups on ({exc.__class__.__name__}). A locked"
                " screen is the usual reason - lockdownd only accepts this while the device is"
                " unlocked - and a Screen Time or MDM restriction can block it too. The pairing"
                " itself worked and is being sent; switch Wi-Fi backups on from the setup wizard"
                " in bioseasy with the device unlocked."
            )
        udid = lockdown.udid
        name = (lockdown.all_values or {}).get("DeviceName", "")
    finally:
        await lockdown.close()
    return record, udid, name


def checked_base_url(base_url: str) -> str:
    """The typed server address, accepted only as http or https.

    urllib would also open file:// and other schemes; the address is typed by the user, so
    anything but http(s) with a host is refused before any request is built.
    """
    parsed = urllib.parse.urlsplit(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise PairingError("Enter the bioseasy address starting with https:// (or http:// on your own network)")
    return base_url.strip().rstrip("/")


def send_pair_record(base_url: str, code: str, record: dict, udid: str, device_name: str) -> str:
    """POSTs the raw plist body to `<base_url>/pair/{code}` exactly like the served script.

    Returns the server's response text, or raises PairingError with a readable message.
    """
    request = urllib.request.Request(  # noqa: S310 - scheme checked in checked_base_url
        f"{checked_base_url(base_url)}/pair/{code}",
        data=plistlib.dumps(record),
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Bioseasy-UDID": udid,
            "X-Bioseasy-Device-Name": device_name,
        },
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 nosemgrep: dynamic-urllib-use-detected
            request, timeout=REQUEST_TIMEOUT_SECONDS, context=ssl_context()
        ) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # 404 is the server's one answer for every bad code - unknown, expired or already used -
        # so that guessing learns nothing from the reply. For someone holding a code that was
        # simply too old, that alone reads as "something broke", so the advice is added here,
        # where it costs the server nothing.
        if exc.code == 404:
            raise PairingError(
                "bioseasy did not accept this pairing code. A code is valid for ten minutes and"
                " for one device only. Open Add a device in bioseasy, start pairing again for a"
                " fresh code, and run this straight away. The device itself is paired already, so"
                " it will not ask you to trust this computer a second time."
            ) from exc
        raise PairingError(f"bioseasy did not accept the pairing: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise PairingError(f"Could not reach bioseasy at {base_url}: {exc.reason}") from exc


async def _run_pairing_async(base_url: str, code: str, on_status: Callable[[str], None]) -> PairResult:
    on_status("Waiting for a device on USB...")
    devices = await list_usb_devices_async()
    if not devices:
        raise PairingError("No iPhone or iPad found over USB. Connect it, unlock it, and try again.")
    if len(devices) > 1:
        on_status("Several devices are connected; pairing the first one found.")
    record, udid, name = await pair_and_read_record(devices[0].serial, on_status)
    on_status("Sending to bioseasy...")
    # The HTTP POST itself uses blocking urllib, same as the served script; pairing is the slow,
    # user-interactive part and that is what needs to stay async and off the GUI thread.
    reply = send_pair_record(base_url, code, record, udid, name)
    return PairResult(udid=udid, device_name=name, server_reply=reply)


def run_pairing(base_url: str, code: str, on_status: Callable[[str], None]) -> PairResult:
    """The full flow: find a USB device, pair it, send the record.

    Synchronous entry point (runs its own event loop with asyncio.run) so it can be called
    straight from a worker thread and keep the GUI responsive.
    """
    return asyncio.run(_run_pairing_async(base_url, code, on_status))


# --- diagnose (read-only, changes nothing on the device) -------------------------------------


@dataclass
class DiagnoseStep:
    name: str
    ok: bool
    detail: str
    elapsed_ms: int


def _short_udid(udid: str | None) -> str:
    """UDID shortened to 8 characters, the most a diagnose report is allowed to show."""
    if not udid:
        return "unknown"
    return udid.replace("-", "")[:8]


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


# No single awaited device call in the diagnose flow may hang silently: every one of them is
# wrapped in asyncio.wait_for with this per-step cap, on top of the overall _TOTAL_DIAGNOSE_
# TIMEOUT around the whole run (see run_diagnose). A step that times out is reported exactly
# like any other failure - TimeoutError is just another exception class in the report.
_STEP_TIMEOUT = 15.0
_TOTAL_DIAGNOSE_TIMEOUT = 90.0


async def _bounded(coro, timeout: float = _STEP_TIMEOUT):
    return await asyncio.wait_for(coro, timeout=timeout)


# Processes whose syslog lines are kept, matched case-insensitively against the basename of
# each entry's `filename` field (the process' main executable path - see cli/syslog.py's own
# process_name = posixpath.basename(filename), checked against the installed
# pymobiledevice3==11.12.5 source). This is how libimobiledevice#1648's stale-BackupAgent2/
# lockdownd-check-in failure and this project's own device_link refusal would show up;
# "heartbeat" was added after a real Wi-Fi capture showed BackupAgent2 opening
# com.apple.mobile.heartbeat right before failing.
_SYSLOG_PROCESSES = ("backupagent2", "backupagent", "lockdownd", "mobilebackup2", "heartbeat")
_SYSLOG_MAX_SECONDS = 15.0
_SYSLOG_MAX_LINES = 200

# Scrubbed from every kept log line before it is added to the report: an e-mail address, or
# any hex/dash token longer than 8 characters (a UDID is 25 or 40 hex characters, or a
# 36-character dashed UUID; ordinary log text essentially never matches this shape). Device
# syslog can carry personal data neither this app nor the report is allowed to keep.
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_LONG_TOKEN_RE = re.compile(r"\b[0-9A-Fa-f]{4,8}(?:-[0-9A-Fa-f]{2,12}){1,4}\b|\b[0-9A-Fa-f]{9,}\b")


def _scrub_log_line(text: str) -> str:
    text = _EMAIL_RE.sub("[redacted-email]", text)
    return _LONG_TOKEN_RE.sub(lambda m: f"{m.group(0)[:8]}...", text)


async def _capture_syslog(lockdown) -> tuple[list[str], str | None]:
    """Best-effort filtered device syslog, captured concurrently with the mobilebackup2 probes
    below, for up to _SYSLOG_MAX_SECONDS or _SYSLOG_MAX_LINES lines, whichever comes first.

    Uses OsTraceService(lockdown).syslog() (pymobiledevice3/services/os_trace.py:363-402,
    checked against the installed pymobiledevice3==11.12.5), the same live activity-stream API
    `pymobiledevice3 syslog live` and Console.app use - a read-only stream, no write to the
    device. Returns (kept lines, error message or None); never raises.
    """
    from pymobiledevice3.services.os_trace import OsTraceService

    lines: list[str] = []

    async def _collect() -> None:
        async with OsTraceService(lockdown) as service:
            async for entry in service.syslog():
                process_name = Path(entry.filename or "").name.lower()
                if not any(proc in process_name for proc in _SYSLOG_PROCESSES):
                    continue
                text = (
                    f"{entry.timestamp:%H:%M:%S} {Path(entry.filename or '').name}[{entry.pid}] "
                    f"{entry.level.name}: {entry.message}"
                )
                lines.append(_scrub_log_line(text))
                if len(lines) >= _SYSLOG_MAX_LINES:
                    return

    try:
        await asyncio.wait_for(_collect(), timeout=_SYSLOG_MAX_SECONDS)
    except TimeoutError:
        pass  # the 15-second cap is the expected way this capture ends, not a failure
    except Exception as exc:  # noqa: BLE001 - report, never let a log-capture failure hide the real result
        return lines, f"{exc.__class__.__name__}: {exc}"
    return lines, None


async def _open_mobilebackup2_service(lockdown, *, strip_ssl: bool):
    """Opens Mobilebackup2Service's own StartService/TLS connection directly instead of going
    through LockdownService.connect() (which always keeps TLS for the life of the stream), so
    a device that only uses SSL for the mobilebackup2 handshake and continues in plaintext
    afterwards can be told apart from a genuine TLS/mobilebackup2 refusal.

    Same pattern pymobiledevice3 already uses for pre-iOS 14 DTX services
    (DtxServiceProvider._open_dtx_connection, pymobiledevice3/dtx_service_provider.py:213-243,
    checked against the installed pymobiledevice3==11.12.5): StartService with the escrow bag
    (lockdown.py:846-875), open the raw connection, do a synchronous SSL handshake
    (ssl_start_sync), then detach the raw socket from the SSL wrapper and go non-blocking again
    - `strip_ssl=False` takes the normal always-TLS path instead, for the side-by-side
    comparison. The resulting Mobilebackup2Service is built by constructing it around this
    already-open connection (LockdownService.__init__'s own `service=` parameter,
    lockdown_service.py:56-73), which is the intended way to reuse an already-started
    ServiceConnection - LockdownService.connect() and Mobilebackup2Service.device_link() both
    no-op past the "already connected" check and use it as-is.
    """
    import socket as _socket

    from pymobiledevice3.services.lockdown_service import LockdownService
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

    attr = await lockdown.get_service_connection_attributes(Mobilebackup2Service.SERVICE_NAME, include_escrow_bag=True)
    connection = await lockdown.create_service_connection(attr["Port"])

    if attr.get("EnableServiceSSL", False):
        if strip_ssl:
            connection.setblocking(True)
            with lockdown.ssl_file() as certfile:
                connection.ssl_start_sync(certfile)
            if connection.socket is not None and hasattr(connection.socket, "_sslobj"):
                raw_socket = getattr(connection.socket, "_sock", None)
                if raw_socket is None:
                    raw_socket = _socket.socket(fileno=connection.socket.detach())
                else:
                    connection.socket._sslobj = None  # noqa: SLF001 - mirrors dtx_service_provider.py exactly
                connection.socket = raw_socket
            connection.setblocking(False)
        else:
            await connection._ensure_started()  # noqa: SLF001 - only way to force the handshake before use here
            with lockdown.ssl_file() as certfile:
                await connection.ssl_start(certfile)

    service = Mobilebackup2Service.__new__(Mobilebackup2Service)
    LockdownService.__init__(
        service, lockdown, Mobilebackup2Service.SERVICE_NAME, service=connection, include_escrow_bag=True
    )
    return service


async def _diagnose_device_link_variant(steps: list[DiagnoseStep], lockdown, label: str, *, strip_ssl: bool) -> None:
    """One "start Mobilebackup2Service + device link Hello" probe, opened directly via
    _open_mobilebackup2_service so the SSL handling can be varied; appends a single
    DiagnoseStep named f"Device link ({label})". Same read-only handshake-only scope as the
    full-TLS probe in _diagnose_service: version exchange + Hello, no MessageName sent."""
    start = time.monotonic()

    async def _run() -> None:
        service = await _open_mobilebackup2_service(lockdown, strip_ssl=strip_ssl)
        try:
            with tempfile.TemporaryDirectory(prefix="bioseasy-diagnose-") as scratch:
                async with service.device_link(Path(scratch)):
                    pass
        finally:
            await service.close()

    try:
        await _bounded(_run())
    except Exception as exc:  # noqa: BLE001
        steps.append(DiagnoseStep(f"Device link ({label})", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
    else:
        steps.append(DiagnoseStep(f"Device link ({label})", True, "ok", _ms(start)))


# How long the Wi-Fi-only heartbeat probe waits for the device's first Marco before giving up
# and running the device link probe anyway (the absence of a Marco within this window is
# itself useful information, reported as part of the step).
_HEARTBEAT_WAIT_SECONDS = 5.0


async def _run_heartbeat(lockdown, marco_event: asyncio.Event, first_marco_ms: list[int], start: float) -> None:
    """Keeps the device's com.apple.mobile.heartbeat service alive (Marco -> Polo) in the
    background, signalling `marco_event` the first time a Marco arrives.

    Mirrors HeartbeatService.start() (pymobiledevice3/services/heartbeat.py:31-49, checked
    against the installed pymobiledevice3==11.12.5) rather than calling it directly, because
    that method loops silently with no way to observe the first exchange from outside; the
    loop body (receive, then reply "Polo") is copied verbatim. HeartbeatService takes the same
    `lockdown` client it is given and opens its own service connection from it
    (`lockdown.start_lockdown_service`, checked against the source) - it shares the client,
    it does not need or open a second lockdown connection.

    Runs until cancelled by the caller; a connection failure ends the loop and is swallowed
    here since the device-link step that follows will surface its own connection failure if
    the same problem affects it.
    """
    from pymobiledevice3.services.heartbeat import HeartbeatService

    with contextlib.suppress(Exception):
        service = await lockdown.start_lockdown_service(HeartbeatService.SERVICE_NAME)
        try:
            while True:
                await service.recv_plist()
                if not marco_event.is_set():
                    first_marco_ms.append(_ms(start))
                    marco_event.set()
                await service.send_plist({"Command": "Polo"})
        finally:
            await service.close()


async def _diagnose_heartbeat_device_link(steps: list[DiagnoseStep], lockdown) -> None:
    """Wi-Fi-only probe: a real-device capture showed BackupAgent2
    opening com.apple.mobile.heartbeat right before the Wi-Fi-only device link failure,
    suggesting some devices expect a live heartbeat before they accept the backup connection
    over Wi-Fi (unlike over USB, where the plain full-TLS probe above already succeeds).

    Starts the heartbeat exchange in the background (_run_heartbeat), waits up to
    _HEARTBEAT_WAIT_SECONDS for the first Marco (reported either way), then runs the same
    full-TLS device link version-exchange-and-Hello probe as _diagnose_service while the
    heartbeat keeps running, then cancels it and closes. Appends two steps: "Heartbeat
    (Marco/Polo)" and "Device link (full TLS) with heartbeat".
    """
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

    marco_event = asyncio.Event()
    first_marco_ms: list[int] = []
    heartbeat_start = time.monotonic()
    heartbeat_task = asyncio.create_task(_run_heartbeat(lockdown, marco_event, first_marco_ms, heartbeat_start))

    try:
        await asyncio.wait_for(marco_event.wait(), timeout=_HEARTBEAT_WAIT_SECONDS)
    except TimeoutError:
        pass
    if marco_event.is_set():
        heartbeat_detail = f"Marco received after {first_marco_ms[0]}ms"
    else:
        heartbeat_detail = f"No Marco within {int(_HEARTBEAT_WAIT_SECONDS)}s"
    steps.append(DiagnoseStep("Heartbeat (Marco/Polo)", marco_event.is_set(), heartbeat_detail, _ms(heartbeat_start)))

    async def _run() -> None:
        service = Mobilebackup2Service(lockdown)
        try:
            await service.connect()
            with tempfile.TemporaryDirectory(prefix="bioseasy-diagnose-") as scratch:
                async with service.device_link(Path(scratch)):
                    pass
        finally:
            await service.close()

    start = time.monotonic()
    try:
        await _bounded(_run())
    except Exception as exc:  # noqa: BLE001
        steps.append(
            DiagnoseStep("Device link (full TLS) with heartbeat", False, f"{exc.__class__.__name__}: {exc}", _ms(start))
        )
    else:
        steps.append(DiagnoseStep("Device link (full TLS) with heartbeat", True, "ok", _ms(start)))

    heartbeat_task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await heartbeat_task


async def _diagnose_service(steps: list[DiagnoseStep], lockdown, *, include_heartbeat: bool = False) -> list[str]:
    """Read-only service probes against an already-connected, paired lockdown session.
    Appends one DiagnoseStep per probe; never raises. Returns the filtered device log lines
    captured while the mobilebackup2 probes ran (see _capture_syslog).

    - "Control service (NotificationProxyService)" starts a second, unrelated SSL lockdown
      service the same way (LockdownService.connect() -> StartService,
      pymobiledevice3/services/lockdown_service.py:114-136) to tell a transport/TLS problem
      shared by every service apart from a refusal specific to mobilebackup2.
    - "Start Mobilebackup2Service" opens the backup service the same way.
    - "get_will_encrypt" reads WillEncrypt (mobilebackup2.py:204-215), a plain lockdown
      get_value call, no device-link traffic.
    - "Device link (full TLS)" uses Mobilebackup2Service.device_link() on the connection
      LockdownService.connect() already opened (mobilebackup2.py:951-979): it opens the
      DeviceLink channel, runs DeviceLink's own version_exchange (device_link.py:215-221,
      protocol handshake only) and then Mobilebackup2Service.version_exchange
      (mobilebackup2.py:560-576, sends the "Hello" DLMessageProcessMessage and checks the
      reply), then disconnects (DLMessageDisconnect, device_link.py:553-554). No MessageName
      is ever sent, so no backup, restore, info or other operation runs - checked against the
      installed pymobiledevice3==11.12.5 source, there is no lower-level way to do the
      handshake without going through this context manager. The context manager's `root_path`
      is only touched if the device pushes files (DLMessageCreateDirectory/UploadFiles/...),
      which never happens here because no process message was sent; a throwaway temp
      directory is passed only to satisfy the constructor.
    - "Device link (handshake-only SSL)" repeats the same version-exchange-and-Hello probe on
      a separately opened connection where TLS is stripped back to plaintext right after the
      handshake (see _open_mobilebackup2_service) - some devices use SSL only to negotiate the
      mobilebackup2 service and expect plaintext DeviceLink traffic afterwards, which the
      always-TLS path above cannot detect on its own.
    - With `include_heartbeat=True` (Wi-Fi only): "Heartbeat (Marco/Polo)" and "Device link
      (full TLS) with heartbeat" (see _diagnose_heartbeat_device_link) - a real-device capture
      showed com.apple.mobile.heartbeat activity right before a Wi-Fi-only device link failure
      that USB does not show, so this repeats the full-TLS probe with a live heartbeat running
      in the background to see whether that changes the result.
    """
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    from pymobiledevice3.services.notification_proxy import NotificationProxyService

    async def _open_notification_proxy() -> None:
        async with NotificationProxyService(lockdown):
            pass

    start = time.monotonic()
    try:
        await _bounded(_open_notification_proxy())
    except Exception as exc:  # noqa: BLE001
        steps.append(
            DiagnoseStep(
                "Control service (NotificationProxyService)", False, f"{exc.__class__.__name__}: {exc}", _ms(start)
            )
        )
    else:
        steps.append(DiagnoseStep("Control service (NotificationProxyService)", True, "ok", _ms(start)))

    syslog_task = asyncio.create_task(_capture_syslog(lockdown))

    service = Mobilebackup2Service(lockdown)
    start = time.monotonic()
    try:
        await _bounded(service.connect())
    except Exception as exc:  # noqa: BLE001 - report every exception class, never crash the run
        steps.append(DiagnoseStep("Start Mobilebackup2Service", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
    else:
        steps.append(DiagnoseStep("Start Mobilebackup2Service", True, "ok", _ms(start)))

        start = time.monotonic()
        try:
            will_encrypt = await _bounded(service.get_will_encrypt())
        except Exception as exc:  # noqa: BLE001
            steps.append(DiagnoseStep("get_will_encrypt", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
        else:
            steps.append(DiagnoseStep("get_will_encrypt", True, f"WillEncrypt={will_encrypt}", _ms(start)))

        async def _hello(scratch: str) -> None:
            async with service.device_link(Path(scratch)):
                pass

        start = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(prefix="bioseasy-diagnose-") as scratch:
                await _bounded(_hello(scratch))
        except Exception as exc:  # noqa: BLE001
            steps.append(DiagnoseStep("Device link (full TLS)", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
        else:
            steps.append(DiagnoseStep("Device link (full TLS)", True, "ok", _ms(start)))

        await service.close()

        # A second, independent probe of the same handshake: this device may keep SSL only for
        # the initial negotiation and continue in plaintext afterwards (see
        # _open_mobilebackup2_service). Both results are kept side by side in the report.
        await _diagnose_device_link_variant(steps, lockdown, "handshake-only SSL", strip_ssl=True)

        if include_heartbeat:
            await _diagnose_heartbeat_device_link(steps, lockdown)

    try:
        log_lines, log_error = await _bounded(syslog_task, timeout=_SYSLOG_MAX_SECONDS + 5.0)
    except Exception as exc:  # noqa: BLE001 - the internal 15s cap should always beat this; belt and suspenders
        log_lines, log_error = [], f"{exc.__class__.__name__}: {exc}"
    detail = f"{len(log_lines)} line(s) kept" if log_error is None else f"{len(log_lines)} line(s) kept, {log_error}"
    steps.append(DiagnoseStep("Device log capture (BackupAgent2/BackupAgent/lockdownd/mobilebackup2)", True, detail, 0))
    return log_lines


async def _connect_detail(lockdown) -> str:
    """Builds the "Connect" step detail line: paired yes/no, product version, and whether the
    device allows Wi-Fi lockdown connections. Never raises; a failed sub-read is shown inline."""
    paired = "yes" if lockdown.paired else "no"
    version = lockdown.product_version or "unknown"
    try:
        wifi_enabled = "yes" if await _bounded(lockdown.get_enable_wifi_connections()) else "no"
    except Exception as exc:  # noqa: BLE001
        wifi_enabled = f"unknown ({exc.__class__.__name__})"
    return f"paired={paired} product_version={version} wifi_connections_enabled={wifi_enabled}"


async def _diagnose_usb(steps: list[DiagnoseStep]) -> tuple[str | None, dict | None, list[str]]:
    """USB diagnose sequence. Returns (udid, pair_record, log_lines); pair_record is set only
    on a paired connection, so the Wi-Fi sequence can reuse the very record pymobiledevice3 has
    stored for this device on this Mac. Mirrors pair_and_read_record's connect call above, but
    never pairs (autopair=False) and never writes anything - a diagnose run must change
    nothing."""
    from pymobiledevice3.lockdown import create_using_usbmux

    start = time.monotonic()
    try:
        devices = await _bounded(list_usb_devices_async())
        if not devices:
            steps.append(DiagnoseStep("Connect (USB)", False, "No iPhone or iPad found on USB", _ms(start)))
            return None, None, []
        lockdown = await _bounded(create_using_usbmux(serial=devices[0].serial, autopair=False))
    except Exception as exc:  # noqa: BLE001
        steps.append(DiagnoseStep("Connect (USB)", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
        return None, None, []

    detail = await _connect_detail(lockdown)
    udid = lockdown.udid
    paired = lockdown.paired
    steps.append(DiagnoseStep("Connect (USB)", True, f"{detail} udid={_short_udid(udid)}", _ms(start)))
    if not paired:
        await lockdown.close()
        return None, None, []
    record = dict(lockdown.pair_record or {})
    try:
        log_lines = await _diagnose_service(steps, lockdown)
    finally:
        await lockdown.close()
    return udid, (record or None), log_lines


async def _diagnose_wifi(steps: list[DiagnoseStep], ip: str, pair_record: dict) -> list[str]:
    """Wi-Fi diagnose sequence: the same probes as USB, over create_using_tcp with the pair
    record read back from the USB session, keep_alive False (see pmd3.py's
    _connect_fixed_host for why: the OS default kills the socket after ~12s with no ACK, and
    a diagnose run should not manufacture its own false timeout)."""
    from pymobiledevice3.lockdown import create_using_tcp

    start = time.monotonic()
    try:
        lockdown = await _bounded(
            create_using_tcp(hostname=ip, autopair=False, pair_record=pair_record, keep_alive=False)
        )
    except Exception as exc:  # noqa: BLE001
        steps.append(DiagnoseStep("Connect (Wi-Fi)", False, f"{exc.__class__.__name__}: {exc}", _ms(start)))
        return []

    detail = await _connect_detail(lockdown)
    paired = lockdown.paired
    steps.append(DiagnoseStep("Connect (Wi-Fi)", True, detail, _ms(start)))
    if not paired:
        steps.append(
            DiagnoseStep(
                "Start Mobilebackup2Service",
                False,
                "skipped: device rejected the stored pairing over Wi-Fi",
                0,
            )
        )
        await lockdown.close()
        return []
    try:
        return await _diagnose_service(steps, lockdown, include_heartbeat=True)
    finally:
        await lockdown.close()


# If diagnosing after an earlier failed attempt, a stale BackupAgent2 instance or a stuck
# lockdownd check-in can be the cause (libimobiledevice#1648) rather than anything bioseasy or
# this diagnose run did; a restart clears that state and costs one honest line in the report.
_RESTART_HINT = "If an earlier attempt already failed, try restarting the iPad once before diagnosing again."


def _render_diagnose_report(
    udid: str | None,
    sections: list[tuple[str, list[DiagnoseStep]]],
    log_sections: list[tuple[str, list[str]]],
) -> str:
    """Plain-text report. Never includes the pair record, keys or certificates - only step
    names, ok/exception-class-and-message, elapsed time, the 8-character short UDID, and
    already-scrubbed device log lines (see _scrub_log_line)."""
    lines = [f"{APP_TITLE} diagnose report", f"device: {_short_udid(udid)}", _RESTART_HINT]
    for title, steps in sections:
        lines.append("")
        lines.append(f"{title}:")
        if not steps:
            lines.append("  (not run)")
        for step in steps:
            status = "OK" if step.ok else "FAILED"
            lines.append(f"  [{status}] {step.name} ({step.elapsed_ms} ms): {step.detail}")

    lines.append("")
    lines.append("Device log (filtered - BackupAgent2, BackupAgent, lockdownd, mobilebackup2 only):")
    any_lines = False
    for title, log_lines in log_sections:
        if not log_lines:
            continue
        any_lines = True
        lines.append(f"  {title}:")
        lines.extend(f"    {line}" for line in log_lines)
    if not any_lines:
        lines.append("  (no matching lines captured)")
    return "\n".join(lines)


async def _run_diagnose_async(ip: str | None, on_status: Callable[[str], None]) -> str:
    on_status("Running USB diagnose...")
    steps_usb: list[DiagnoseStep] = []
    udid, record, log_lines_usb = await _diagnose_usb(steps_usb)
    sections: list[tuple[str, list[DiagnoseStep]]] = [("USB", steps_usb)]
    log_sections: list[tuple[str, list[str]]] = [("USB", log_lines_usb)]

    if ip:
        steps_wifi: list[DiagnoseStep] = []
        log_lines_wifi: list[str] = []
        if record is None:
            steps_wifi.append(
                DiagnoseStep(
                    "Connect (Wi-Fi)",
                    False,
                    "No pairing available: the USB step did not produce a paired connection and stored record",
                    0,
                )
            )
        else:
            on_status("Running Wi-Fi diagnose...")
            log_lines_wifi = await _diagnose_wifi(steps_wifi, ip, record)
        sections.append(("Wi-Fi", steps_wifi))
        log_sections.append(("Wi-Fi", log_lines_wifi))

    on_status("Diagnose finished.")
    return _render_diagnose_report(udid, sections, log_sections)


async def _run_diagnose_bounded(ip: str | None, on_status: Callable[[str], None]) -> str:
    """Caps the whole diagnose run at _TOTAL_DIAGNOSE_TIMEOUT, on top of the per-step caps in
    _bounded: a step timing out is reported and the run moves on, but a run must still never
    hang forever end-to-end (e.g. a task never noticing its own step timed out)."""
    try:
        return await asyncio.wait_for(_run_diagnose_async(ip, on_status), timeout=_TOTAL_DIAGNOSE_TIMEOUT)
    except TimeoutError:
        on_status("Diagnose timed out.")
        return (
            f"{APP_TITLE} diagnose report\n\n"
            f"Timed out after {int(_TOTAL_DIAGNOSE_TIMEOUT)}s without finishing; no individual step should take "
            "this long, so something hung outside the normal per-step timeouts. Try again, possibly after "
            "restarting the iPad."
        )


def run_diagnose(ip: str | None, on_status: Callable[[str], None]) -> str:
    """Synchronous entry point for the diagnose flow (own event loop, like run_pairing)."""
    return asyncio.run(_run_diagnose_bounded(ip, on_status))


# --- capture device log (read-only, USB only, no backup service started) ---------------------

CAPTURE_LOG_DEFAULT_SECONDS = 120.0
_CAPTURE_LOG_STATUS_INTERVAL = 10.0


async def _capture_log_async(
    duration: float,
    on_status: Callable[[str], None],
    on_count: Callable[[int], None],
    stop_event: threading.Event,
) -> tuple[list[str], str | None]:
    """Captures the filtered device log over USB for up to `duration` seconds, or until
    `stop_event` is set. Starts no backup service and sends no backup operation - only
    OsTraceService's read-only activity stream (see _capture_syslog above for the same API).

    Returns (kept lines, error message or None). A connection error mid-capture keeps
    whatever was captured so far and is reported as the error, never raised - the caller is
    usually watching a device the owner is exercising from elsewhere (e.g. bioseasy itself
    over Wi-Fi), so losing the lines already captured would defeat the point of capturing.
    """
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.os_trace import OsTraceService

    on_status("Connecting over USB...")
    try:
        devices = await _bounded(list_usb_devices_async())
    except Exception as exc:  # noqa: BLE001
        return [], f"{exc.__class__.__name__}: {exc}"
    if not devices:
        return [], "No iPhone or iPad found on USB"
    try:
        lockdown = await _bounded(create_using_usbmux(serial=devices[0].serial, autopair=False))
    except Exception as exc:  # noqa: BLE001
        return [], f"{exc.__class__.__name__}: {exc}"
    if not lockdown.paired:
        await lockdown.close()
        return [], "Device rejected the stored pairing. Pair it again first."

    on_status(
        f"Connected (udid={_short_udid(lockdown.udid)}). Capturing for up to {int(duration)}s; click Stop to end early."
    )
    lines: list[str] = []
    error: str | None = None
    start = time.monotonic()
    last_status_bucket = 0
    try:
        async with OsTraceService(lockdown) as service:
            generator = service.syslog()
            try:
                while True:
                    elapsed = time.monotonic() - start
                    remaining = duration - elapsed
                    if remaining <= 0 or stop_event.is_set():
                        break
                    bucket = int(elapsed // _CAPTURE_LOG_STATUS_INTERVAL)
                    if bucket != last_status_bucket:
                        last_status_bucket = bucket
                        on_status(f"Capturing... {int(remaining)}s remaining, {len(lines)} line(s) kept so far.")
                    # Poll stop_event/remaining every second rather than blocking indefinitely
                    # on the next log entry, which may never come if nothing loggable happens.
                    try:
                        entry = await asyncio.wait_for(generator.__anext__(), timeout=min(1.0, max(remaining, 0.01)))
                    except TimeoutError:
                        continue
                    except StopAsyncIteration:
                        break
                    process_name = Path(entry.filename or "").name.lower()
                    if not any(proc in process_name for proc in _SYSLOG_PROCESSES):
                        continue
                    text = (
                        f"{entry.timestamp:%H:%M:%S} {Path(entry.filename or '').name}[{entry.pid}] "
                        f"{entry.level.name}: {entry.message}"
                    )
                    lines.append(_scrub_log_line(text))
                    on_count(len(lines))
            finally:
                await generator.aclose()
    except Exception as exc:  # noqa: BLE001 - keep what was captured, report the error separately
        error = f"{exc.__class__.__name__}: {exc}"
    finally:
        await lockdown.close()
    return lines, error


def render_capture_log_report(lines: list[str], error: str | None, duration: float, stopped_early: bool) -> str:
    """Plain-text report, same privacy rules as the diagnose report: already-scrubbed lines
    only, never the pair record, keys or certificates."""
    header = [
        f"{APP_TITLE} device log capture",
        f"captured for up to {int(duration)}s over USB (BackupAgent2, BackupAgent, lockdownd, mobilebackup2 only)",
    ]
    if stopped_early:
        header.append("stopped early by request")
    if error:
        header.append(f"ended early: {error}")
    header.append(f"{len(lines)} line(s) kept")
    header.append("")
    if not lines:
        header.append("(no matching lines captured)")
        return "\n".join(header)
    return "\n".join(header + lines)


def run_capture_log(
    duration: float,
    on_status: Callable[[str], None],
    on_count: Callable[[int], None],
    stop_event: threading.Event,
) -> tuple[list[str], str | None]:
    """Synchronous entry point (own event loop, like run_pairing/run_diagnose)."""
    return asyncio.run(_capture_log_async(duration, on_status, on_count, stop_event))


# --- self-test (no device, no pairing) -------------------------------------------------------


def self_test(base_url: str) -> int:
    """Checks the pieces the GUI depends on, without touching a device or a pairing code.

    Prints one line per check and returns a process exit code (0 if every check passed).
    """
    ok = True

    try:
        import importlib.metadata

        import pymobiledevice3  # noqa: F401 - import itself is the check

        version = importlib.metadata.version("pymobiledevice3")
        print(f"pymobiledevice3 import: OK (version {version})")
    except Exception as exc:  # noqa: BLE001 - report, do not crash
        ok = False
        print(f"pymobiledevice3 import: FAILED ({exc!r})")

    try:
        devices = list_usb_devices()
        print(f"usbmux list_devices: OK ({len(devices)} USB device(s) found)")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"usbmux list_devices: FAILED ({exc!r})")

    try:
        path = certifi.where()
        print(f"certifi bundle: OK ({path})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"certifi bundle: FAILED ({exc!r})")

    health_url = f"{checked_base_url(base_url)}/healthz"
    try:
        request = urllib.request.Request(health_url, method="GET")  # noqa: S310 - scheme checked
        with urllib.request.urlopen(  # noqa: S310 nosemgrep: dynamic-urllib-use-detected
            request, timeout=REQUEST_TIMEOUT_SECONDS, context=ssl_context()
        ) as response:
            body = response.read().decode("utf-8", "replace")
            print(f"HTTPS GET {health_url}: OK (HTTP {response.status}, body: {body[:200]!r})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"HTTPS GET {health_url}: FAILED ({exc!r})")

    return 0 if ok else 1


# --- GUI ----------------------------------------------------------------------------------


DIAGNOSE_REPORT_PATH = Path.home() / "Desktop" / "bioseasy-diagnose.txt"
DEVICE_LOG_REPORT_PATH = Path.home() / "Desktop" / "bioseasy-device-log.txt"

# How often the main thread drains the worker->UI queue (see _poll_queue). Tk is not
# thread-safe: on macOS, calling widget methods or even root.after() from a worker thread can
# be silently dropped instead of raising, which is how an earlier build showed nothing at all
# in the status area on a real Mac while working fine here. Workers only ever put onto a
# queue.Queue (thread-safe by design); only the main-thread poller below touches widgets.
_QUEUE_POLL_MS = 100


class PairHelperApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry("560x460")
        root.minsize(480, 380)
        # Tk callback exceptions (e.g. inside a button command) otherwise print to a terminal
        # that a windowed .app has none of and simply vanish; route them into the status area.
        root.report_callback_exception = self._report_callback_exception

        padding = {"padx": 10, "pady": 6}

        frame = ttk.Frame(root)
        frame.pack(fill="x", **padding)

        ttk.Label(frame, text="bioseasy address").grid(row=0, column=0, sticky="w")
        self.address_var = tk.StringVar(value="https://")
        ttk.Entry(frame, textvariable=self.address_var, width=50).grid(row=0, column=1, sticky="ew", padx=(8, 0))

        ttk.Label(frame, text="Pairing code").grid(row=1, column=0, sticky="w")
        self.code_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.code_var, width=20).grid(
            row=1, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        ttk.Label(frame, text="iPad/iPhone IP (Wi-Fi, optional)").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.diagnose_ip_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.diagnose_ip_var, width=20).grid(
            row=2, column=1, sticky="w", padx=(8, 0), pady=(6, 0)
        )

        frame.columnconfigure(1, weight=1)

        button_row = ttk.Frame(root)
        button_row.pack(pady=(4, 8))
        self.pair_button = ttk.Button(button_row, text="Pair", command=self.on_pair_clicked)
        self.pair_button.pack(side="left", padx=4)
        self.diagnose_button = ttk.Button(button_row, text="Diagnose", command=self.on_diagnose_clicked)
        self.diagnose_button.pack(side="left", padx=4)
        self.capture_log_button = ttk.Button(button_row, text="Capture log", command=self.on_capture_log_clicked)
        self.capture_log_button.pack(side="left", padx=4)
        self.stop_capture_button = ttk.Button(
            button_row, text="Stop", command=self.on_stop_capture_clicked, state="disabled"
        )
        self.stop_capture_button.pack(side="left", padx=4)
        self.copy_report_button = ttk.Button(
            button_row, text="Copy report", command=self.on_copy_report_clicked, state="disabled"
        )
        self.copy_report_button.pack(side="left", padx=4)

        self.capture_count_var = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.capture_count_var).pack(anchor="w", padx=10)

        ttk.Label(root, text="Status").pack(anchor="w", padx=10)
        self.status_text = scrolledtext.ScrolledText(root, height=14, state="disabled", wrap="word")
        self.status_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._last_report = ""
        self._capture_stop_event: threading.Event | None = None
        # Worker threads only ever put tuples here; _poll_queue (main thread only) is the sole
        # reader and the sole thing that touches Tk widgets on behalf of a worker.
        self._ui_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.root.after(_QUEUE_POLL_MS, self._poll_queue)

    # -- main-thread only: widgets, the queue poller, and the callback-exception hook ---------

    def _report_callback_exception(self, exc_type, exc, tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        self._append_status_direct(f"Internal error:\n{text}")

    def _append_status_direct(self, line: str) -> None:
        self.status_text.configure(state="normal")
        self.status_text.insert("end", line + "\n")
        self.status_text.see("end")
        self.status_text.configure(state="disabled")

    def _clear_status_direct(self) -> None:
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", "end")
        self.status_text.configure(state="disabled")

    def _set_buttons_direct(self, in_progress: bool) -> None:
        state = "disabled" if in_progress else "normal"
        self.pair_button.configure(state=state)
        self.diagnose_button.configure(state=state)
        self.capture_log_button.configure(state=state)

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "line":
                    self._append_status_direct(str(payload))
                elif kind == "buttons":
                    self._set_buttons_direct(bool(payload))
                elif kind == "copy_enabled":
                    self.copy_report_button.configure(state="normal" if payload else "disabled")
                elif kind == "report":
                    self._last_report = str(payload)
                elif kind == "count":
                    self.capture_count_var.set(f"{payload} line(s) captured")
                elif kind == "stop_enabled":
                    self.stop_capture_button.configure(state="normal" if payload else "disabled")
        except queue.Empty:
            pass
        finally:
            self.root.after(_QUEUE_POLL_MS, self._poll_queue)

    # -- callable from a worker thread: queue only, never touch a widget directly -------------

    def append_status(self, line: str) -> None:
        self._ui_queue.put(("line", line))

    def set_pairing_in_progress(self, in_progress: bool) -> None:
        self._ui_queue.put(("buttons", in_progress))

    # -- Pair ----------------------------------------------------------------------------------

    def on_pair_clicked(self) -> None:
        base_url = self.address_var.get().strip()
        code = self.code_var.get().strip()
        if not base_url or not code:
            self._append_status_direct("Enter the bioseasy address and the pairing code first.")
            return

        self._clear_status_direct()
        self._append_status_direct("Pairing started...")
        self._set_buttons_direct(True)

        thread = threading.Thread(target=self._pair_worker, args=(base_url, code), daemon=True)
        thread.start()

    def _pair_worker(self, base_url: str, code: str) -> None:
        try:
            result = run_pairing(base_url, code, self.append_status)
        except PairingError as exc:
            self.append_status(str(exc))
        except Exception as exc:  # noqa: BLE001 - show something readable, never crash silently
            self.append_status(f"Unexpected error: {exc!r}")
        else:
            self.append_status(f"Paired {result.device_name or result.udid}.")
            self.append_status(result.server_reply)
        finally:
            self.set_pairing_in_progress(False)

    # -- Diagnose --------------------------------------------------------------------------------

    def on_diagnose_clicked(self) -> None:
        ip = self.diagnose_ip_var.get().strip()

        self._clear_status_direct()
        self._append_status_direct("Diagnose started...")
        self.copy_report_button.configure(state="disabled")
        self._last_report = ""
        self._set_buttons_direct(True)

        thread = threading.Thread(target=self._diagnose_worker, args=(ip,), daemon=True)
        thread.start()

    def _diagnose_worker(self, ip: str) -> None:
        try:
            report = run_diagnose(ip or None, self.append_status)
        except Exception as exc:  # noqa: BLE001 - show something readable, never crash silently
            self.append_status(f"Unexpected error: {exc!r}")
            return
        else:
            self.append_status("")
            self.append_status(report)
            self._ui_queue.put(("report", report))
            self._ui_queue.put(("copy_enabled", True))
        finally:
            self.set_pairing_in_progress(False)

        self._write_report_fallback(report, DIAGNOSE_REPORT_PATH)

    def _write_report_fallback(self, report: str, path: Path) -> None:
        """Writes the same report to Desktop, so it survives even if the status area failed to
        show it for some reason this app has not accounted for. Never raises into the worker."""
        try:
            path.write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            self.append_status(f"Could not write {path}: {exc.__class__.__name__}: {exc}")
        else:
            self.append_status(f"Report also saved to {path}")

    def on_copy_report_clicked(self) -> None:
        if not self._last_report:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._last_report)

    # -- Capture device log -----------------------------------------------------------------

    def on_capture_log_clicked(self) -> None:
        self._clear_status_direct()
        self._append_status_direct(
            f"Device log capture started (USB only, up to {int(CAPTURE_LOG_DEFAULT_SECONDS)}s)..."
        )
        self.copy_report_button.configure(state="disabled")
        self.capture_count_var.set("0 line(s) captured")
        self._last_report = ""
        self._set_buttons_direct(True)
        self.stop_capture_button.configure(state="normal")

        stop_event = threading.Event()
        self._capture_stop_event = stop_event
        thread = threading.Thread(
            target=self._capture_log_worker, args=(CAPTURE_LOG_DEFAULT_SECONDS, stop_event), daemon=True
        )
        thread.start()

    def on_stop_capture_clicked(self) -> None:
        if self._capture_stop_event is not None:
            self._capture_stop_event.set()
            self._append_status_direct("Stopping the capture...")

    def _capture_log_worker(self, duration: float, stop_event: threading.Event) -> None:
        def on_count(n: int) -> None:
            self._ui_queue.put(("count", n))

        lines: list[str] = []
        error: str | None = None
        try:
            lines, error = run_capture_log(duration, self.append_status, on_count, stop_event)
        except Exception as exc:  # noqa: BLE001 - show something readable, never crash silently
            self.append_status(f"Unexpected error: {exc!r}")
        finally:
            self._ui_queue.put(("stop_enabled", False))
            self.set_pairing_in_progress(False)

        report = render_capture_log_report(lines, error, duration, stop_event.is_set())
        self.append_status("")
        self.append_status(report)
        self._ui_queue.put(("report", report))
        self._ui_queue.put(("copy_enabled", True))
        self._write_report_fallback(report, DEVICE_LOG_REPORT_PATH)


def run_gui() -> None:
    root = tk.Tk()
    PairHelperApp(root)
    root.mainloop()


def main() -> int:
    if "--self-test" in sys.argv:
        base_url = "https://your-bioseasy-address.example"
        for arg in sys.argv[1:]:
            if arg.startswith("--base-url="):
                base_url = arg.split("=", 1)[1]
        return self_test(base_url)
    if "--diagnose" in sys.argv:
        ip = None
        for arg in sys.argv[1:]:
            if arg.startswith("--ip="):
                ip = arg.split("=", 1)[1].strip() or None
        report = run_diagnose(ip, lambda line: print(line, file=sys.stderr))
        print(report)
        return 0
    capture_log_arg = next(
        (arg for arg in sys.argv[1:] if arg == "--capture-log" or arg.startswith("--capture-log=")), None
    )
    if capture_log_arg is not None:
        duration = CAPTURE_LOG_DEFAULT_SECONDS
        if "=" in capture_log_arg:
            try:
                duration = float(capture_log_arg.split("=", 1)[1])
            except ValueError:
                print(f"Invalid --capture-log seconds: {capture_log_arg!r}", file=sys.stderr)
                return 1
        stop_event = threading.Event()
        lines, error = run_capture_log(duration, lambda line: print(line, file=sys.stderr), lambda n: None, stop_event)
        print(render_capture_log_report(lines, error, duration, stopped_early=False))
        return 0
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
