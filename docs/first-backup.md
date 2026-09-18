# Your first backup

The whole path, from an empty server to a finished backup, in five steps. Each step links to the
page that has the detail - read those when a step does not go as described, not before.

Plan for **one computer with a USB cable** (step 3, once per device) and for **having the phone in
your hand** (step 5).

## 1. Run the server

Docker Compose, a volume for `/data`, a volume or network share for `/backups`, and a reverse
proxy in front of it. → [Installation](install.md)

Two things decided here are hard to change later: where the backups live, and that `/data` stays
on local disk.

## 2. Create your account

Open the server in a browser. On a fresh install it shows a setup page and the container log
prints a one-time token; paste it, pick a username and password. That account is an administrator.
→ [Installation, "First sign-in"](install.md#first-sign-in)

## 3. Pair the device

Pairing is the device saying "I trust this server". It needs a USB connection to a computer once -
the phone cannot do it alone, and no later step replaces it. The recommended way is the helper on
your own computer; there are three fallbacks. → [Pairing a device](pairing.md)

After this, everything else happens over Wi-Fi.

## 4. Turn on Wi-Fi backups and encryption

The setup wizard walks the device through the remaining switches and shows what is already on.
→ [Setup wizard](setup.md)

**Encryption deserves a moment.** An encrypted backup cannot be read, restored or repaired without
its password, and bioseasy deliberately does not store it. Write it down somewhere you will still
have it after the phone is gone - that is the situation you are preparing for. Older generations
keep the password they were made with.

## 5. Start the first backup

Press **Back up now** on the device page, then unlock the phone and confirm the passcode prompt.
iOS asks for it at the start of every backup, Wi-Fi included, and no tool can skip it. The first
run transfers everything, so it takes a while; later runs only move what changed.

## What happens from here

- **A schedule** runs inside a window you choose. It still waits for the passcode on the device,
  so pick a time somebody is actually holding the phone - see
  [Troubleshooting, "Not confirmed"](troubleshooting.md#a-run-ended-as-not-confirmed).
- **Generations** accumulate: each backup keeps a snapshot, older ones are thinned by a retention
  policy you can change per device.
- **Notifications** tell you when a run fails, so you are not relying on checking the page.
  → [Notifications](notifications.md)
- **Restoring** is done with Finder, Apple Devices, iMazing or the command line; bioseasy shows you
  the exact path per generation. → [Restoring a backup](restore.md)
