# Pairing a device

This page is for whoever is adding an iPhone or iPad to bioseasy: the one-time step of trusting
the device before it can be backed up at all.

iOS lets a computer back up a device only after the device has trusted that computer once, over
USB. There is no Wi-Fi-only pairing for iPhone or iPad today: it needs iOS 27 and Developer Mode
on the device, and bioseasy does not support that path yet. Several ways lead to a trusted
pairing instead.
All of them end with the same result: a pair record in bioseasy's data volume, after which the
device is backed up over Wi-Fi.

A pair record is a device credential: whoever holds it can back up the device (and read an
unencrypted backup). Treat the file like a password, delete copies after the upload, and never
put it on the backup share.

## 1. Pair from my computer (recommended)

Works whether or not the bioseasy server itself has a USB port. On the **Add a device** page,
click **Pair from my computer**. bioseasy shows an 8-character code, valid for 10 minutes and
usable once.

### No install: the pairing app

If a platform's URL setting is set, the code page offers a download for it first: a
self-contained app that needs no uv, Python or Homebrew (`helper/README.md`). Where each download
is hosted is up to the operator; no such URL is hard-coded anywhere in the application, each is
only ever set through its own environment variable. A platform without a configured URL shows
"Not available on this server" instead of a dead link.

| Platform            | Setting                  | Notes |
| ------------------- | ------------------------- | ----- |
| macOS (Apple Silicon) | `BIOSEASY_HELPER_URL_MACOS` | Unsigned, not notarized. macOS blocks it on first launch (Gatekeeper): right-click the app and choose Open, or allow it under System Settings > Privacy & Security. |
| Linux (x64)          | `BIOSEASY_HELPER_URL_LINUX` | Unsigned. Make it executable first (`chmod +x`). USB pairing needs `usbmuxd` installed (see pymobiledevice3's installation docs). |
| Windows (x64)        | `BIOSEASY_HELPER_URL_WINDOWS` | Unsigned. Windows SmartScreen warns on first launch: More info, then Run anyway. |

If none of the three is configured, the page instead points at building the app yourself from
`helper/`. The builds for all three platforms are attached to each `helper-v*` release; point the
settings at those files.

### One command (uv)

The code page also shows a one-line command for macOS/Linux and for Windows (PowerShell). Run it
on the computer the device is plugged into, not on the server:

```sh
uv run <your bioseasy address>/pair/<code>/bioseasy-pair.py
```

It needs [uv](https://docs.astral.sh/uv/) installed. Connect the device, unlock it, and run the
command; tap **Trust** and enter the passcode when asked. The script pairs the device over USB
with pymobiledevice3, turns on Wi-Fi backups, and sends the resulting pair record straight to
bioseasy. The Add page keeps polling and opens the setup wizard once it arrives.

pymobiledevice3 itself also caches the pair record locally on the computer that paired (its own
standard behaviour) - delete it there afterward if you do not want a second copy of this device
credential lying around.

If the page's address is plain HTTP and not clearly private to this network, it warns next to
the command: the record would travel unencrypted.

## 2. USB at the server

For a server where you can plug the device in. The container does not touch USB itself; it talks
to the `usbmuxd` daemon on the host through its socket, the same way Finder-like tools do on Linux.

1. Install and start `usbmuxd` on the host (`apt install usbmuxd` on Debian and Ubuntu; it starts
   when a device is plugged in).
2. Hand its socket to the worker, which is the service that pairs. Next to `docker-compose.yml`,
   create `docker-compose.override.yml`, which compose reads automatically:

   ```yaml
   services:
     worker:
       volumes:
         - /var/run/usbmuxd:/var/run/usbmuxd
   ```

   Compose adds this mount to the worker's existing ones.
3. `docker compose up -d`, plug the device in, unlock it, and on the **Add a device** page choose
   **Plugged into this server**, then **Scan now**. Tap **Trust** on the device when asked.

Once paired, the cable can go: backups run over Wi-Fi.

## 3. Pair on another computer and upload (fallback)

For a NAS in a cupboard, a VM without USB passthrough, or a server you cannot reach physically.
You need any computer with a USB port and [uv](https://docs.astral.sh/uv/):

- macOS: works as is
- Windows: install Apple Devices (Microsoft Store) or iTunes, which bring the USB driver
- Linux: install `usbmuxd` from your distribution

Connect the device, unlock it, then run:

```sh
uvx --from pymobiledevice3==11.12.5 pymobiledevice3 lockdown pair
uvx --from pymobiledevice3==11.12.5 pymobiledevice3 lockdown wifi-connections on
uvx --from pymobiledevice3==11.12.5 pymobiledevice3 usbmux list
uvx --from pymobiledevice3==11.12.5 pymobiledevice3 lockdown save-pair-record device.plist
```

Tap **Trust** and enter the passcode on the device when asked. `usbmux list` shows the device's
UDID. Upload `device.plist` in bioseasy under **Add device, Upload pair record**, then delete the
file from the computer.

### Without a terminal (third-party app)

[idevice_pair](https://github.com/jkcoxson/idevice_pair) is a desktop app for Windows, macOS and
Linux that creates the same kind of lockdown pairing file. Download it from its releases page,
create a "Lockdown" pairing file and upload it as above. Its files are not something we test
against; the upload tells you if a field is missing.

## 4. Reuse a Finder or iTunes pairing

If the device already syncs with a Mac or PC and "Show this iPhone when on Wi-Fi" is enabled in
Finder or iTunes, that computer holds a pair record:

- macOS: `/var/db/lockdown/<UDID>.plist` (readable with `sudo`)
- Windows: `C:\ProgramData\Apple\Lockdown\<UDID>.plist`

Upload that file the same way. The upload tells you which fields are missing if a record turns
out to be incomplete.

## What bioseasy checks on upload

- The file is a property list with `HostID`, `SystemBUID`, `HostCertificate`, `HostPrivateKey`,
  `RootCertificate` and `WiFiMACAddress`
- `HostCertificate` belongs to `HostPrivateKey`
- `EscrowBag` present; a record without one is rejected outright, both here and on the pairing
  hand-off script's upload. Every backup, and turning encryption on or off, goes through
  pymobiledevice3's mobilebackup2 service, which always requires the escrow bag from the pair
  record; a record missing it fails deep inside pymobiledevice3 with an unexplained internal
  error, not a clear message, so bioseasy checks for it up front instead
- The UDID is confirmed against the device on the first connection

## After pairing

Adding a device leads to the assisted setup wizard next: Wi-Fi backups, encryption and the
first backup. See `docs/setup.md`.

## Removing a device

Removing a device in bioseasy deletes its pair record. If the device is reachable at that moment,
bioseasy also asks it to forget the pairing; otherwise remove it on the device under
Settings, General, Transfer or Reset iPhone, Reset, Reset Location & Privacy.
