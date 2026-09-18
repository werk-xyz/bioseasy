# bioseasy pair helper

A self-contained app that does exactly what the served `bioseasy-pair.py` code hand-off script
does (`docs/pairing.md`, "Pair from my computer"; `src/bioseasy/handoff.py`), for anyone who
does not want to install uv or Python.

It pairs a connected iPhone or iPad over USB with pymobiledevice3, turns on Wi-Fi backups, and
sends the resulting pair record to your bioseasy server. A pair record is a full device
credential (docs/pairing.md); this app never prints or logs it, and it never disables TLS
certificate verification.

## Platforms

All three are built by `.github/workflows/helper.yml`, each on its own platform's runner -
PyInstaller cannot cross-build - and published together on a `helper-v*` release. None is signed.

| Platform | Download | First launch |
| --- | --- | --- |
| macOS (Apple Silicon) | `bioseasy-pair-macos-arm64.zip` | Gatekeeper blocks it: right-click the app and choose Open, or allow it under System Settings > Privacy & Security. |
| Windows (x64) | `bioseasy-pair-windows-x64.exe` | SmartScreen warns: More info, then Run anyway. |
| Linux (x64) | `bioseasy-pair-linux-x64` | Make it executable (`chmod +x`). USB pairing needs `usbmuxd` running. |

The bioseasy web UI offers a download once an operator sets the matching
`BIOSEASY_HELPER_URL_MACOS`, `BIOSEASY_HELPER_URL_LINUX` or `BIOSEASY_HELPER_URL_WINDOWS`
(`docs/configuration.md`).

## Using it

1. Download the app for your platform and unzip it if it came as a zip. On macOS you get
   `bioseasy-pair.app`; on Linux a single executable, `bioseasy-pair-linux-x64`.
2. Open it.
   - **macOS**: it blocks unsigned apps by default (this one is not notarized):
     - Right-click (or Control-click) `bioseasy-pair.app` and choose **Open**, then confirm in
       the dialog, **or**
     - If that dialog does not offer Open: **System Settings > Privacy & Security**, scroll to
       the "bioseasy-pair.app was blocked" notice near the bottom, and click **Open Anyway**.
       Then open the app again and confirm.
   - **Linux**: make it executable first, then run it: `chmod +x bioseasy-pair-linux-x64 &&
     ./bioseasy-pair-linux-x64`. USB pairing needs `usbmuxd` installed and running (see
     pymobiledevice3's installation docs for your distribution); without it no device is found.
3. Connect the iPhone or iPad over USB and unlock it.
4. In the app, enter your bioseasy address (e.g. `https://your-bioseasy-address.example`) and
   the pairing code shown on the bioseasy **Add a device** page, then click **Pair**.
5. Unlock the device and tap **Trust** when asked, and enter the passcode if prompted.
6. The status area shows the steps and then the server's reply. The bioseasy Add page keeps
   polling and opens the setup wizard once the record arrives.

## What this app stores on the Mac

pymobiledevice3 (bundled inside the app) caches a copy of the pair record itself, the same way
the served hand-off script and the manual `uvx pymobiledevice3` commands do; this is
pymobiledevice3's own standard behaviour, not something this app adds.

The exact location, traced in the installed pymobiledevice3 11.12.5 source
(`site-packages/pymobiledevice3/`):

- `lockdown.py:1421` resolves the cache folder via `create_pairing_records_cache_folder(None)`
  when pairing (called from `create_using_usbmux`, `lockdown.py:1370`).
- `pair_records.py:126-141` (`create_pairing_records_cache_folder`): when no folder is given, it
  uses `get_home_folder()`.
- `common.py:6-7`: `get_home_folder()` returns `get_os_utils().get_home_folder_path()`.
- `osu/posix_util.py:113-121` (`Darwin.get_home_folder_path`): if the legacy `~/.pymobiledevice3`
  directory already exists on the Mac, it is reused; otherwise the folder follows the XDG Base
  Directory spec, i.e. `$XDG_DATA_HOME/pymobiledevice3`, defaulting to
  `~/.local/share/pymobiledevice3`.
- `lockdown.py:1120`: the record is written to `<that folder>/<device UDID>.plist`.

So on a Mac that has never run pymobiledevice3 before, expect:

```
~/.local/share/pymobiledevice3/<UDID>.plist
```

On a Mac that already has an older pymobiledevice3 install (from a previous manual pairing, for
instance), it reuses:

```
~/.pymobiledevice3/<UDID>.plist
```

Check both if unsure which one your Mac used; only one will exist on a fresh machine.

## Deleting everything after testing

1. Delete `bioseasy-pair.app` (and the zip you downloaded it from).
2. Delete the cached pair record: `~/.local/share/pymobiledevice3/<UDID>.plist` or
   `~/.pymobiledevice3/<UDID>.plist`, whichever exists (see above). If you paired more than one
   device, delete each `<UDID>.plist` you no longer need, or remove the whole folder.
3. Optionally forget the pairing on the device itself: Settings, General, Transfer or Reset
   iPhone, Reset, Reset Location & Privacy (this also clears the trust relationship on the
   device's side, independent of the cache file above).
4. Remove the device from bioseasy if you added it only for this test (bioseasy's own pair
   record in its data volume is separate from the cache above and is deleted when you remove the
   device there).

## Rebuilding

### macOS (Apple Silicon)

Requires [uv](https://docs.astral.sh/uv/) (only on the machine that builds the app, not on the
machine that runs it). From this directory:

```sh
uv run --python 3.12 --group build pyinstaller \
  --name bioseasy-pair \
  --windowed \
  --clean \
  --noconfirm \
  --collect-all pymobiledevice3 \
  --collect-data certifi \
  --osx-bundle-identifier org.bioseasy.pairhelper \
  --target-architecture arm64 \
  bioseasy_pair_helper.py
```

This builds `dist/bioseasy-pair.app`. Zip it for distribution:

```sh
cd dist && ditto -c -k --sequesterRsrc --keepParent bioseasy-pair.app bioseasy-pair-macos-arm64.zip
```

`pyproject.toml` in this directory pins `pymobiledevice3==11.12.5`, matching the version in the
project's `uv.lock`; `uv run --python 3.12` uses uv's own managed Python 3.12, whose tkinter
works on macOS without anything installed system-wide. `uv sync --group build` (or the `pyinstaller` call
above, which resolves it on demand) pulls in PyInstaller itself; neither step touches the
Homebrew or macOS-provided Python.

### Linux (x64) and Windows (x64)

The same call as macOS without the three macOS-only flags (`--windowed` stays for Windows, where
it hides the console window), plus `--onefile`, since neither platform has an `.app` bundle:

```sh
uv run --python 3.12 --group build pyinstaller \
  --name bioseasy-pair --onefile --clean --noconfirm \
  --collect-all pymobiledevice3 --collect-data certifi \
  bioseasy_pair_helper.py
```

On Linux, tkinter needs the system's Tcl/Tk (`python3-tk`, `tk-dev` on Debian and Ubuntu). The CI
job installs both; `.github/workflows/helper.yml` is the exact recipe for all three platforms.

### Verifying a build without a device

The built binary supports a `--self-test` flag that needs no iPhone and does no pairing:

```sh
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --self-test
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --self-test --base-url=https://your-bioseasy-address
```

It imports pymobiledevice3, lists connected USB devices (without touching any), resolves the
certifi CA bundle, and does an HTTPS GET to `<base-url>/healthz` (default
`https://your-bioseasy-address.example`), printing one OK/FAILED line per check and exiting
non-zero if any failed.

## Diagnose

A read-only mode that changes nothing on the device, for telling apart "iOS refuses the backup
service" from "only the Wi-Fi path fails". Click **Diagnose** in the app (optionally entering the
device's IP address first to also test Wi-Fi), or run:

```sh
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --diagnose
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --diagnose --ip=192.168.1.50
```

It connects to the paired device over USB, reports whether it is paired, its product version,
and whether Wi-Fi lockdown connections are enabled, then starts a control service
(`NotificationProxyService`, unrelated to backups but opened the same TLS way) to tell a
transport/TLS problem apart from one specific to backups, starts `Mobilebackup2Service`, reads
`WillEncrypt`, and opens the backup device link far enough to complete the version exchange and
the "Hello" handshake - the same steps a real backup or an encryption change would need, minus
the operation itself. This runs twice: once the normal way (TLS kept for the whole
connection), and once with TLS stripped back to plaintext right after the handshake, the way
pymobiledevice3 already does for older DTX services - some devices only use SSL to negotiate
the mobilebackup2 service and expect plaintext afterwards, which shows up as a
`ConnectionTerminatedError` on the always-TLS path but succeeds on the stripped one. If an IP
address is given, the same sequence repeats over Wi-Fi, using the pair record read back from
the USB session, and adds one more probe: a real-device capture showed the device opening
`com.apple.mobile.heartbeat` right before a Wi-Fi-only device link failure that USB does not
show, so the Wi-Fi run also starts a background heartbeat (Marco/Polo) exchange, waits up to 5
seconds for the first Marco, and repeats the full-TLS device link probe while the heartbeat
keeps running. Each step is reported as ok, or as the exception class and message it failed
with, plus how long it took.

While the backup-service steps run, it also captures up to 15 seconds (200 lines) of the
device's own log, kept only for the processes `BackupAgent2`, `BackupAgent`, `lockdownd`,
`mobilebackup2` and anything with `heartbeat` in its name - the ones a refused backup service,
a stuck lockdownd check-in, or a missing heartbeat show up in.
Device logs can carry personal data: e-mail addresses and anything shaped like a UDID longer
than 8 characters are stripped before a line is kept, and the filtered lines are the only ones
that ever leave the device.

If an earlier attempt already failed, try restarting the iPad once before diagnosing again - a
stale `BackupAgent2` instance or a stuck lockdownd check-in on the device can cause a refusal
that has nothing to do with bioseasy or this diagnose run, and a restart clears it.

The report never contains the pair record, keys or certificates, and shows only the first 8
characters of the UDID; use **Copy report** to put it on the clipboard for sharing.

### Capture device log

A second read-only mode for when Diagnose already shows the general chain working but a
particular attempt (e.g. a real backup or an encryption change run from the bioseasy server
itself) still fails: click **Capture log** in the app, or run

```sh
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --capture-log
dist/bioseasy-pair.app/Contents/MacOS/bioseasy-pair --capture-log=60
```

It connects to the paired device over USB and streams its filtered log (the same
BackupAgent2/BackupAgent/lockdownd/mobilebackup2 filter and privacy scrubbing as Diagnose) for
up to 120 seconds by default (or the given number of seconds), while the owner triggers the
step to investigate from somewhere else, e.g. bioseasy over Wi-Fi. It never starts a backup
service itself. The GUI shows a live line count and a **Stop** button to end the capture early;
a connection error mid-capture keeps whatever was captured and says so. The result is shown in
the window and also written to `~/Desktop/bioseasy-device-log.txt`.

## Kept in sync with the served hand-off script by hand

`bioseasy_pair_helper.py` mirrors the pairing logic in `src/bioseasy/handoff.py`'s
`build_script` (same pymobiledevice3 calls, same `POST /pair/{code}` request), but the two are
not one shared implementation: `build_script` emits a single-file PEP 723 script served over
plain HTTP and run with `uv run <url>`, so it cannot import this module or any other local
package: the served bytes have to be the whole program. If the pairing flow or the upload
request changes, both files need the change; see the comment at the top of
`bioseasy_pair_helper.py`.

## License

GPL-3.0-or-later, same as the bioseasy project (`../LICENSE`). This app bundles pymobiledevice3,
itself GPL-3.0-or-later.
