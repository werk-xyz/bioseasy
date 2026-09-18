# bioseasy concept

What bioseasy is, what Apple's rules allow, and how the pieces fit together.

## Who it is for

People who want a **complete, restorable backup of their iPhone or iPad** without an iCloud
subscription and without plugging the device into their own computer. They run a home server or
NAS with Docker. Usually one device, sometimes a family's handful.

Not for: syncing photos or media as they are taken, iCloud, Android.

## What the platform allows

| Fact | Consequence |
|---|---|
| Since iOS/iPadOS 16.1 the device asks for its **passcode on every backup**, USB or Wi-Fi. | No tool runs unattended backups. bioseasy makes the confirmation cheap: the owner starts the backup from the phone in hand, or confirms a scheduled one. |
| The first pairing needs **USB** for iPhone and iPad. | One-time step: plug the device into the Docker host once. After that, Wi-Fi only. |
| `EnableWifiConnections` can be set from Linux after pairing (pymobiledevice3). | No Mac or Finder at any point. |
| pymobiledevice3 finds paired devices over Bonjour (`_apple-mobdev2._tcp`) and speaks mobilebackup2. | No netmuxd. usbmuxd only for the pairing run. |
| mDNS does not cross Docker's bridge network or VLANs. | `network_mode: host`; optional fixed address per device. |
| Backups use the Finder/iTunes format; complete means `Status.plist` `SnapshotState == "finished"`. | Restore works with Finder, iMazing or pymobiledevice3. |

**Verified against real devices**: the Wi-Fi handshake, and that a full and an incremental
encrypted backup both complete and ask for the passcode.

## Triggers and the passcode

1. **From the device:** the owner opens bioseasy on the phone (home screen bookmark), taps
   "Back up now", and enters the passcode on the same device.
2. **Scheduled:** only inside the device's time window, optionally only while charging. A stepped
   retry schedule tries again inside the same window if the previous attempt did not succeed:
   window start, then +30, +60 and +120 minutes; once the window ends without a success, the day
   ends `not_confirmed`, with one overdue nudge per period. A notice goes out
   before the window's first attempt (lead time a global default, 5 minutes unless the admin
   changes it under Admin -> Defaults), at most once per window per device and never once a
   successful backup already covers the current interval: "Backup of \<name\> starts in \<N\>
   minutes: put the \<iPhone/iPad\> on the charger, unlock it and wait for the passcode prompt."
3. **Due reminder:** at most one nudge per period with a link to the device page.

If nobody confirms within 10 minutes, the run ends as `not_confirmed`, not `failed`. After the
overdue threshold (default 7 days without a good backup) an alert goes out.

## Pairing

The Add page never calls `engine.discover()` or `engine.pair()` itself: both can be real I/O
against actual hardware, and pairing specifically can block for up to 120s on the device's own
Trust dialog. Discovery results land in a `seen_devices` table, refreshed by the scheduler tick
and by an explicit "Scan now"; the Add page only reads it. "Pair and add" creates a `pairings`
row and starts the pairing off the request through the `pair_device` Huey task, and the page
polls that row with htmx until it reads `done` (the device is then added, owned by the admin who
asked for it) or `failed` (the reason is shown, nothing is added).

## Encryption

Backups must be encrypted; only encrypted backups contain passwords, Health and similar data.
The wizard turns encryption on with a password the user chooses. **bioseasy never stores it.**
A password check proves the user still knows it by unwrapping the keybag in
`Manifest.plist`, without decrypting any file.

## Out of scope

Restore from the web UI, photo sync, iCloud, non-English UI, Kubernetes.

Browsing a backup and downloading single files out of it is built, see
[Restoring a backup](restore.md). Putting a whole backup back onto a device is still done with Finder, Apple Devices, iMazing or the
command line - bioseasy shows you the way, it does not perform the restore.
