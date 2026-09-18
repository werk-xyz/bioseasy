# Troubleshooting

> The fixes here are the ones that have actually come up.

Organised by what you see, not by which part of bioseasy is involved - you know the symptom, not
the subsystem. If your problem is not here, [collect a report](#collect-a-report-for-a-bug-report)
at the bottom of this page.

## A device does not appear

- **Phone and server must be on the same network segment.** mDNS/Bonjour traffic generally does
  not cross VLANs or separate Wi-Fi SSIDs and subnets. A phone on a guest VLAN or a separate IoT
  network will not be discovered there.
- **If mDNS is unreliable on your network** (some managed switches and access points filter
  multicast), or the device really is in another subnet, set a fixed address for the device on its
  Settings page - an IP address or a hostname. The firewall rules that path needs are in
  [Installation, "Ports and connections"](install.md#c-device-in-another-network-or-subnet).
- **Discovery runs in the `worker` service**, and it needs host networking. Confirm with:

  ```sh
  docker inspect $(docker compose ps -q worker) --format '{{.HostConfig.NetworkMode}}'
  ```

  It must print `host`.

## A backup asks for the passcode every time

That is the platform, not a setting. iOS and iPadOS have asked for the device passcode at the
start of every backup since 16.1, Wi-Fi backups included. No tool can skip it - see
[Concept](concept.md). Start a backup from the phone in hand when you can.

## A run ended as "Not confirmed"

Nobody entered the passcode within ten minutes, so the run was abandoned. This is deliberately
*not* reported as a failure: nothing went wrong with the backup, it simply never started. A
scheduled backup only starts inside its window and still waits for a confirmation on the device -
so a schedule that fires while everyone is asleep will collect "not confirmed" runs night after
night. Either move the window to a time somebody is holding the phone, or accept that the
scheduled run is a prompt rather than an unattended job.

## A run ended as "Failed"

Open the device page: the run's row carries the message the engine reported. The frequent ones:

- **The device left the network mid-transfer.** The next scheduled run picks up incrementally;
  nothing is lost.
- **No space on the backup volume.** Check the header's storage bar and
  [Storage](install.md#4-storage).
- **The pair record is no longer accepted.** The device page says so and offers to pair again; a
  pair record can be invalidated by a device reset, a restore, or by revoking trust on the device.

## The storage check fails

Almost always the host-side mount is not actually mounted - not a bioseasy misconfiguration. See
[the marker file check](install.md#the-marker-file-check).

## Where to look

**Your own log.** Every signed-in user has a **Log** entry in the header showing what happened to
their own devices: each finished backup and each generation check, newest first, with the outcome
and the same detail the device page shows. It never reaches past the devices you own.

**Admin → Logs**, for an administrator, has two views:

- **System log** - the web service's and the worker's own warnings and errors, filterable by
  level, process and device, with a traceback where one was captured. It holds the last 2000 rows
  or 14 days, whichever is smaller, redacted the same way as the container log: no passwords, no
  pair record content, only a shortened device id. `docker compose logs` remains the complete
  record; this page saves you a shell.
- **Application log** - the same per-device events users see on their own Log page, across every
  owner and with the owner named.

A member reaches neither: `/admin/logs` answers 404 for them rather than 403, so the page does not
announce its own existence.

## Collect a report for a bug report

Run inside the worker container, where discovery and backups happen. The report deliberately
excludes secrets, full device identifiers and device names, so it is safe to paste in public:

```sh
docker compose exec worker bioseasy diagnose
```

Add `--no-discover` to skip live device discovery (useful when discovery itself is what hangs) or
`--json` for machine-readable output. It covers versions, configuration, the storage check, pair
record counts and permissions, recent devices and runs, and optionally a discovery pass.
