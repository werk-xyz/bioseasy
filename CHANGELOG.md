# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.1] - 2026-09-25

### Added
- **A device can be removed again.** Its settings, history and pairing go; the backups on disk
  stay, and the page names the folder they stay in. The device's name has to be typed to confirm,
  and a device being backed up right now is not removed. Until now a device that got stuck half
  set up stayed for good, and its pair record - a credential for that device - stayed with it.

### Fixed
- **A pairing that worked is no longer thrown away** when the device refuses to switch Wi-Fi
  backups on afterwards. A locked screen makes the device answer that request with lockdownd's
  "SetProhibited", and the pair record - the part that needed somebody standing at the device -
  went with it. The record is stored and sent first now; the pairing app and the one-line command
  say what happened and what to do.
- **Switching Wi-Fi backups on without a cable says why** instead of failing as "Internal error".
  That switch is what lets a device accept Wi-Fi connections at all, so it can only be set over
  USB. Tried over Wi-Fi, pymobiledevice3 answers a refused pairing check by reconnecting and
  checking again without end, until Python stops it with a RecursionError. Both the attempt and
  the recursion now end in a sentence that names the cable.
- **A device that is removed leaves no identifier behind in a spent pairing code.** The code
  stays on record as used, as it must; only the device it was spent on is cleared with the device.
- **A rejected pairing code explains itself.** The server answers every bad code with a bare 404,
  deliberately, so guessing learns nothing - which left somebody holding a code that was simply
  too old with no idea. The pairing app and the command now say that a code lasts ten minutes and
  is good for one device.

## [1.0.0] - 2026-09-18

The first release. Everything below is new, so it is grouped by what it does for you rather than
by added, changed and fixed - those categories start meaning something with 1.0.1.

The public history starts here. What happened before it was development of software nobody had
yet, and listing it change by change would help no one.

### Backing up

- **Full and incremental encrypted backups of an iPhone or iPad over Wi-Fi**, to a server you run,
  in the format Finder and iTunes use - so anything that restores those restores these.
- **No cable after the first time.** One pairing over USB, then the device is found on the network
  and backed up over Wi-Fi. iOS asks for the device passcode at the start of every backup; that is
  Apple's rule, and bioseasy is built around it rather than pretending otherwise.
- **Generations with hard links**, so an unchanged file is stored once however many generations
  hold it. Retention by count and over time, a preview of what a rule would remove before it
  removes anything, and the ability to pin a generation so retention leaves it alone.
- **Deep verification** reads a generation back from disk on a schedule and reports what is really
  there, rather than trusting that a finished run left a complete backup.
- **A storage check** that notices an unmounted volume, a share that cannot hard-link, and free
  space running out - before a backup fails on it.

### Adding a device

- **Four ways to pair**, because the right one depends on where your cable is: a helper app you
  run on your own computer (macOS, Windows, Linux), a one-line command, a cable at the server
  itself, or uploading a pair record you already have.
- **A setup wizard per device**: pair, enable Wi-Fi backups, turn on encryption, first backup -
  with the device page saying which step is still open.
- **A warning when a pair record is going stale.** Apple expires them after 30 days of disuse;
  bioseasy says so at 21.
- **A fixed address per device** for networks where mDNS does not reach, and a reachability
  history counted from recorded sightings rather than estimated.

### Running it

- **Scheduled backups inside a window you choose**, optionally only while charging - and "Back up
  now" from the phone itself through the home-screen web app, which is the trigger that fits a
  backup needing a passcode.
- **Alerts** when a backup fails, falls behind, or storage goes wrong: email, Telegram, anything
  Apprise supports, browser notifications, and Home Assistant over MQTT with discovery.
- **A read-only status API with scoped tokens**, enough for a script, a cron job, or an iOS
  Shortcut that starts a backup when you get home.
- **Accounts with roles**, and optional single sign-on through any OIDC provider, matched by
  verified email address. The settings page names the local account an identity landed on.
- **The guide inside the web UI**, so the answer is where the question is.

### Getting data back

- **Browse a backup the way a file browser shows a disk**: generations, then areas, then one
  column per folder level. Pick single files, whole folders or whole areas and download them - a
  selection is a path, so restoring five thousand photos is one click, not five thousand.
- **Download a whole generation as one archive**, byte for byte as it lies on disk, for a restore
  through Finder, Apple Devices, iMazing or pymobiledevice3.
- **The backup password is asked for per generation and never stored**, and the unlocked state
  expires on its own.

### Security

- Every route carries an explicit ownership or admin check; a device that is not yours is
  indistinguishable from one that does not exist.
- Pair records live in the app volume with restrictive permissions and are never logged, rendered
  back, or written into a job queue.
- Secret scanning, static analysis, dependency advisories, Dockerfile linting and image scanning
  run in CI, all blocking, with a CycloneDX SBOM of what is shipped.
- The container runs unprivileged, read-only, with no capabilities.

### Installing it

- One image, two services, one compose file - with samples for an ordinary deployment, a
  throwaway demo with simulated devices, and a build from source.
- Optional HTTPS without a reverse proxy, with a self-signed certificate that is made and renewed
  on its own.
- Every setting documented in one reference, checked against the code so it cannot fall behind.
