# Restoring a backup

This page is for a device owner who needs something back out of a bioseasy backup - either one
file, or the whole device.

## Getting one file back

If you only want a photo, a document or a database out of a backup, you do not need a restore at
all. On the device page, **Browse files** lists what a backup holds and lets you download a single
file. Nothing about the backup or the device changes.

- **While a backup is running, its latest backup cannot be opened.** The running backup rewrites
  that directory as it goes, so a file taken out of it now could be half the old version and half
  the new one. Pick a generation instead; a generation is a finished copy and is never touched by a
  later run.
- **Pick a generation first.** The page opens on the list of generations, the latest backup at the
  top, because each one holds the files as they were when it was taken.
- **Then, if that generation is encrypted, enter its backup password.** A password you already
  entered for another generation of the same device is tried first, so you usually type it once.
  When it does not fit, the page asks: each generation carries its own key material, and one made
  before a password change still needs the password it was made with.
- The password is kept in the server's memory, tied to your browser session, and the browse view
  shows how long is left. Fifteen minutes without activity locks it again, as does signing out or
  pressing **Lock now**. It is never written to disk, and a file is decrypted while it downloads.
- **Then browse in columns**, the way a file browser shows a disk: generations on the left, then
  the **areas** of the backup (`HomeDomain`, `CameraRollDomain` and so on), then one column per
  folder. Picking an area opens it straight away. On disk a backup has no folder tree at all -
  every file lies flat under a hash - so these folders are read out of the backup's own index.
- **Tick whatever you want back**: single files, whole folders, or a whole area. A folder is one
  tick however much is in it, so "all five thousand photos" is a single click and not five thousand.
  What you ticked stays ticked while you walk into other folders, and the bar at the top says how
  much is selected.
- A file inside a folder you already ticked is shown ticked and cannot be unticked on its own -
  untick the folder if you want to pick individually.
- **Search** as well, either across the whole backup or inside the open area. The matches arrive
  as one more column at the right-hand end, not as a list under the browser: the same rows, the
  same ticks, and each one says which area and path it came from. The folder columns stay where
  they were, so you can walk straight back into where you had got to, and the search stays set
  while you do. A long result list grows with **Show more** rather than turning pages, so nothing
  you have already ticked scrolls out of existence. There is no "select all matches": what gets
  selected is always a path - a file, a folder, an area - and a result list is not one. Tick the
  folder a match sits in if you want everything around it.
- **The download** is one `.tar` archive, built while it downloads, so the size of the selection
  does not matter. A single file comes back as itself.
- A downloaded file arrives exactly as the device stored it. Most of it is app data: an iOS
  backup keeps databases and container files, not the tidy folder names you see on the phone, so
  expect `sms.db` rather than "Messages".

What this does **not** do: put a file back onto the device. There is no supported way to write a
single file into an iOS backup and have the device accept it; that is what a full restore below is
for.

## Taking a whole generation off the server

If you cannot reach the backup volume yourself, download the generation instead. Every row of the
generations table on the device page has a **Download** link; it hands out that generation exactly
as it lies on disk, as one `.tar` archive.

- **Unpack it into a folder named after the device's UDID**, inside the MobileSync backup folder
  (`~/Library/Application Support/MobileSync/Backup/` on macOS). The name matters: Finder and
  bioseasy both identify a backup by that folder name.
- **It stays encrypted.** Nothing is decrypted on the way out and the backup password is never
  asked for here - Finder asks for it when you restore. That also means the archive is only as
  useful to a thief as the password is guessable.
- **This is not the same as the `.tar` from Browse files.** That one contains decrypted files with
  readable names, which is right for reading a photo and useless for restoring a device: a restore
  needs the backup's own layout, hashes and all.
- **Only finished generations, never the latest backup.** The live backup is rewritten in place by
  the next run, and a download of a full backup can easily take longer than the gap between two
  runs. Pick a generation.
- The download runs in one go. If the connection drops, it starts again from the beginning - worth
  knowing before starting one over a shaky link, since a phone backup can be tens of gigabytes.

Once it is unpacked in the right place, continue with the restore steps below.

## Putting a whole device back

Restoring replaces everything currently on the device with the chosen backup. There is no undo,
and a backup made with encryption on needs its password.

Each device's restore guide is at `/devices/<udid>/restore`; every row of the generations table on
the device page links to the guide for that one generation (`?snapshot=<name>`, validated against
the real snapshot list -- an unknown or invalid name is a 404, not a guess). The guide shows:

- the exact server-side path of the chosen generation (or, with no generation chosen, the live
  backup), inside the bioseasy container;
- that a snapshot is hard-linked against the previous generation and must be **copied**, never
  moved, or the generations still sharing its files lose them;
- step-by-step instructions for three restore paths, each honest about what it needs:
  - **Finder on a Mac, or Apple Devices/iTunes on Windows.** Copy the snapshot into the local
    MobileSync Backup folder under the device's UDID, then restore from there. The macOS path
    (`~/Library/Application Support/MobileSync/Backup/`) is verified against Apple's own support
    documentation; the exact Windows subfolder under `%USERPROFILE%` or `%AppData%` is not, and
    the guide says so instead of guessing one.
  - **iMazing** (third party, commercial; not bundled or configured by bioseasy): point it at the
    copied folder and restore from there.
  - **pymobiledevice3**, from a computer with the device on USB: `pymobiledevice3 backup2 restore
    --password <backup password> <folder>`, run against a folder that contains one subfolder named
    after the device UDID.

