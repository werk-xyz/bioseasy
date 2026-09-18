# The assisted setup wizard

Once a device is paired and added (`docs/pairing.md`), bioseasy walks the owner through the
remaining steps before backups actually happen: `/devices/<udid>/setup`. iPhone and iPad go
through the same four steps; only the wording says which one.

After the checklist, the wizard offers a **Device address** section: Bonjour (automatic
discovery) does not cross networks (a VLAN, a guest Wi-Fi, a router between the device and
bioseasy), so a device on a different network is only ever reachable at a fixed address. Entering
the device's IP address here saves the same `devices.host` setting the device settings page also
edits; set a DHCP reservation or a fixed IP for the device on the router first, so the address does
not change later. Below it, a **connectivity check** can be started here or
from the device settings page: it runs in the worker (`tasks.netcheck_step`, like every other
device operation), polls its result with htmx, and checks, in order, stopping at the first failure
- address reachable on TCP 62078, the stored pairing (never starts a new one, never triggers a
Trust prompt), a secure session, the Wi-Fi heartbeat, and the backup service's own dynamic port
(optional). Every step's text is safe to show: never a pair record or a password. The check needs
a fixed address configured; without one it says so instead of running. This is the same diagnostic
the pairing helper's Diagnose mode already offers over USB (`helper/README.md`), brought into the
web interface and run from the server's own position instead.

1. **Paired.** Always done by the time this page is reached: every route that adds a device
   (the fast "Add" path, a finished pairing, an uploaded pair record) only inserts it once a
   pair record exists.
2. **Wi-Fi connections enabled.** Calls `engine.enable_wifi()` off the request through the same
   Huey task path as everything else that can block on the device; the page polls the result
   with htmx. Recorded in `devices.wifi_enabled_at` once it succeeds.
3. **Backup encryption on.** The owner enters a password twice (minimum 8 characters); bioseasy
   never stores it. This step is the one exception to the background path above: it always runs
   as a plain thread in the web process, never through Huey, because Huey's queue is a file on
   disk and a backup password must never be written to one. The
   device asks for its passcode, so this can take a while. Recorded in
   `devices.encryption_enabled_at` once it succeeds.

   If the device already has encryption on from Finder, iTunes or an earlier pairing with a
   password bioseasy never saw, the step shows an explanation with Apple's own way to remove a
   forgotten backup password (Settings, General, Transfer or Reset, Reset, Reset All Settings).
   This does not erase the device's data and does not touch any backup already on disk, but that
   existing encrypted backup can no longer be restored once its password is gone.

   Keep the device unlocked with its screen on for this step: it can wait several minutes for the
   passcode prompt, and pymobiledevice3's connection to the device can be dropped while it waits
   (`engine/pmd3.py`'s `_will_encrypt_now`). bioseasy re-checks the device's own encryption state
   after such a drop and still reports success if the device applied the change before the
   connection ended; only a device that still reads "off" afterwards shows an error, with a hint
   to keep the screen on and try again.

   **USB fallback.** If the Wi-Fi step keeps failing, backup encryption can be turned on directly
   from a computer, over USB, instead:

   - **Finder** (macOS) or **iTunes** (Windows, or older macOS): connect the device, select it,
     and check "Encrypt local backup" under Backups. This sets the same device-side `WillEncrypt`
     flag pymobiledevice3 reads and writes (`Mobilebackup2Service.get_will_encrypt`), so bioseasy
     picks it up as "on" the next time it checks - no separate setting to reconcile.
   - The **pairing helper app** (`helper/README.md`) pairs the device and turns on Wi-Fi backups;
     it has no encryption step, so use one of the two above for that.
4. **First backup complete.** Links to "Back up now" (the same control as the device page) and
   is done once the on-disk backup reads as complete (`inventory.read_backup`), not merely once
   the engine call returns.

The dashboard and the device page mark a device "Setup incomplete" until all four steps are
done; the device page links back to the checklist while any step is open.

> Status: all four steps above have run against real devices. One detail
> stays unknown, and it is about the library rather than the device: whether pymobiledevice3's
> `ChangePassword` operation reports a distinct error for "wrong or missing old password". The
> setup page therefore cannot detect that case on its own and always shows the
> forgotten-password explanation alongside the encryption step.

## Adding a device again

A device's pair record (`/data/pair-records`) and its backups (`/backups`) both live outside
`bioseasy.db`, so either can survive a database that was recreated or migrated while the device
itself keeps whatever bioseasy already turned on. Re-adding such a device from the Scan list (the
fast "Add" path, `add_submit`) is intended - no new pairing happens, the stored record is simply
reused - but until it can compare notes with the device, the fresh row has neither
`wifi_enabled_at` nor `encryption_enabled_at`, and the setup wizard would otherwise walk the
owner through two steps the device does not need again.

Both the fast "Add" path and a finished pairing (`add_device_from_pairing`), the manual pair
record upload (`add_pair_record`), and opening the setup page itself while a step is still open,
therefore enqueue one worker task (`runtime.run_setup_detect`, `tasks.detect_setup_step`) that
reads the device's actual state through the engine:

- **Wi-Fi connections enabled**: `LockdownClient.get_enable_wifi_connections()`, which reads the
  `EnableWifiConnections` key in the `com.apple.mobile.wireless_lockdown` domain - the same key
  the wizard's own Wi-Fi step writes.
- **Backup encryption on**: `Mobilebackup2Service.get_will_encrypt()`, the same call the device
  settings page already uses to detect encryption bioseasy never turned on itself.

Either read that confirms "on" sets the matching `devices.*_at` column, once, if it was still
NULL; a confirmed "off" or a read that could not be completed (the device unreachable, no
answer, a rejected pairing) changes nothing - never an assumption, and never unset. Both reads
run over Wi-Fi like any other device operation, wrapped in the same `_wifi_heartbeat` as a
backup or the Wi-Fi step. The wizard shows a step found this way as "Already on (detected)" and,
while detection is still running, "Checking the device..." instead of looking stuck; if the
device could not be reached, the page says so and the manual buttons stay available. Detection
is rate-limited per device (`runtime.SETUP_DETECT_COOLDOWN`, 10 minutes), so polling the setup
page while a step is running never turns into hammering the device with connection attempts.

The setup page also says, up front, when it recognises this situation: "Already paired with this
server: no new pairing needed" whenever a stored pair record was found, and "Found existing
backups of this device: *N* generations, last one *…*" whenever a backup history already exists
on disk (`snapshots.list_snapshots`) - both were previously invisible in the UI.

Separately, a *succeeded* backup is itself treated as evidence, regardless of how it started: a
run that actually transferred data over Wi-Fi (not USB - a device plugged into the bioseasy host
is still found first) proves Wi-Fi connections are on, and a finished backup whose
`Manifest.plist` reads `IsEncrypted=True` proves backup encryption is on. `jobs.py`'s JobManager
sets either column the same way, once, if it was still NULL, right before recording the run
succeeded.

The first-backup step (4, above) already counted as done from an on-disk complete backup
(`inventory.read_backup`) before any of this; detection changes nothing about how that step is
judged; it only closes the gap for steps 2 and 3.

## Changing the backup password

Once encryption is on, the device settings page (`/devices/<udid>/settings`) has a "Backup
password" section: current password, new password twice. It runs exactly like step 3 above - a
web-process thread, never Huey, both passwords held only in memory - and calls
`Mobilebackup2Service.change_password(backup_directory, old=..., new=...)`. A wrong current
password does not surface as an error of its own: every ChangePassword failure other than
insufficient disk space raises the same generic exception, so bioseasy can only show a generic
"could not change the backup password" message, not "wrong current password" specifically.

Older backups and snapshots already on disk stay restorable with the *old* password after a
change; only the next backup on this device uses the new one. Each completed backup carries its
own keybag, frozen at the moment it was made, and a snapshot is a copy of a finished backup
directory, so every generation keeps the keybag it had. Only the live backup directory, which the
engine overwrites in place on the *next* run, gets a fresh keybag under the new password.

**Keep the old password as long as you keep generations made under it.**

## Start a backup from iOS Shortcuts

Every backup asks for the device's passcode, so the best moment to start one is when the owner is
at the device -- for example
when they get home or plug the charger in. A Personal Automation in the Shortcuts app can call
bioseasy at exactly that moment, using an API token scoped to start backups (created under
**Settings**, see `docs/api.md`).

1. Under **Settings -> API tokens**, create a token, choose **"Read and start backups"** as its scope, and copy
   the token shown once at creation.
2. In the Shortcuts app, add a **Personal Automation** with the trigger you want (for example
   "Charger" or "Arrive", under Home in your own automation): When Charger Connects, or When I
   Arrive Home. Turn off "Ask Before Running" so it fires on its own.
3. Add one action: **Get Contents of URL**.
   - URL: `https://your-bioseasy-server/api/v1/devices/<udid>/backup`
   - Method: `POST` (under Show More)
   - Headers: `Authorization` = `Bearer <token>`
4. Save. The device's UDID is shown on its device page in bioseasy.

The automation only starts the backup; it still asks for the device's passcode like every other
backup, and someone still has to unlock the device and enter it -- Shortcuts cannot do that part.
A 202 response means the backup was queued; 409 means one was already running; 403 means the
token's scope is read-only.

