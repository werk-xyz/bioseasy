# Installation

This guide covers a self-hosted install on a Linux server or NAS. It assumes you are comfortable
with a terminal, Docker Compose and editing an `fstab` file.

> Status: the compose file uses the real device engine (pymobiledevice3). Pairing, encrypted
> full and incremental Wi-Fi backups and a restore have been run against real devices.

## 1. Requirements

- **A Linux host** that runs Docker and Docker Compose. bioseasy is one image running as two
  services, a web service and a worker, and does not depend on a particular distribution.
- **Docker with host networking.** The compose file sets `network_mode: host` because devices
  are discovered over mDNS (Bonjour, `_apple-mobdev2._tcp`), and mDNS does not cross Docker's
  own bridge network (`docs/concept.md`). Host networking puts the container directly on the
  host's network namespace and interfaces, which is what makes multicast discovery work.
- **Not Docker Desktop on macOS or Windows.** Docker Desktop runs the Docker Engine inside a
  Linux VM and routes all container traffic through NAT and a backend process on the host
  (`com.docker.backend`), not through the host's own network interfaces. Docker's own
  documentation states this directly: even with Docker Desktop's host-networking feature enabled
  (version 4.34 and later, opt-in under Settings > Resources > Network), "processes inside the
  container cannot bind to the IP addresses of the host because the container has no direct
  access to the interfaces of the host", and the feature "works on layer 4" only. That is enough
  for a container to reach a service on the host or vice versa, but it does not put the container
  on the physical LAN segment the way `network_mode: host` does on Linux, so mDNS discovery of a
  phone on the LAN is not expected to work through Docker Desktop. Run bioseasy on a Linux host
  (bare metal, a VM, or a NAS with Docker support) instead.
- Enough disk space for backups, see [Storage](#4-storage) below.

**Docker Compose 2.24.4 or later** (`docker compose version`). The compose file marks `.env` as
optional, which needs 2.24.0, and the demo file replaces settings with `!override`, which needs
2.24.4 - both per Docker's own Compose file reference. Older distribution packages may lag; Docker's
own install instructions give a current one.

## 2. Ports and connections

What has to reach what, staged by where the device sits.

### (a) Device on USB at the Docker host

No network ports needed for pairing: pymobiledevice3 talks to the device over the USB
`usbmuxd` socket, which is why the runtime image installs `usbmuxd` (`Dockerfile`). Once paired,
the device still needs a Wi-Fi path for actual backups (bioseasy backs up over Wi-Fi, not USB);
see (b) or (c) below for that.

### (b) Device on the same Wi-Fi/LAN as the server

- **Discovery is mDNS/Bonjour** (`_apple-mobdev2._tcp`, standard multicast DNS, UDP port 5353;
  `docs/concept.md`, `engine/pmd3.py` `get_mobdev2_lockdowns`).
- **Docker network mode: `network_mode: host`.** `docker-compose.yml` sets this for both services
  because mDNS multicast does not cross Docker's own bridge network; a container on the bridge
  cannot see or send the multicast traffic a host-networked one can (`docs/concept.md`, "mDNS does
  not cross Docker's bridge network or VLANs"). This is also why Docker Desktop on macOS/Windows
  does not work for this case, see [Requirements](#1-requirements) above.
- **Backup and pairing traffic**: TCP 62078 (lockdown) plus a dynamic service port the device
  picks per session, same as (c) below; on the same LAN this needs no firewall rule because there
  is none between server and device.

### (c) Device in another network or subnet

Discovery over mDNS does not cross a network/VLAN boundary on its own. A backup only needs a
routed TCP connection from the server to the device, direction server to device only:

1. **Fixed address per device, plus a DHCP reservation.** Reserve an IP for the device in your
   router's DHCP settings, set the device's Private Wi-Fi Address for that network to fixed rather
   than rotating (otherwise the reservation does not match the device you keep seeing), and enter
   the address on the device's settings page in bioseasy; the engine then tries USB, then this
   address, then Bonjour.
2. **An mDNS reflector/repeater between the two networks** (a router or firewall feature that
   forwards multicast DNS across network segments; consult your own router's or firewall's
   documentation for the exact setting, since naming differs by vendor and none is cited here).
   Discovery then works without a fixed address: bioseasy keeps a device's routed IPv4 address
   from such a proxy's mirrored PTR/SRV/A records itself (`engine/mdns.py`), since the underlying
   pymobiledevice3 library otherwise drops those addresses on its own.
3. **A second interface of the Docker host in the client network.** Host networking then sees the
   Bonjour announcements directly on that interface; weigh that the server now has a leg in the
   client network.

Whichever discovery path you use, the actual backup connection needs this firewall rule set,
direction server to device only, nothing inbound to the device from anywhere else and nothing
inbound to the server except the web UI (see below):

- **TCP 62078** (lockdown session; pairing, discovery handshake and the start of every backup
  negotiate over this port).
- **TCP 49152-65535** (the IANA dynamic/private port range). A backup or a change to backup
  encryption opens a *second* TCP connection, to a port the device picks at random for that one
  session. The full range is not exhaustively confirmed, and a firewall rule that allows only
  62078 lets discovery and pairing through but breaks the backup and encryption steps with a
  connection error, not a clear "port blocked" message.

Keep the device unlocked with its screen on during setup steps (Wi-Fi enable, encryption, backup):
each one can take a while to reach the point where iOS actually asks for the passcode, and a
locked screen delays that prompt further.

Pairing needs the other direction too: the computer running the pairing helper (which may be a
different machine than the Docker host, see `docs/pairing.md`) must reach the bioseasy web port.
iOS accepts the backup session itself across subnets.

### Browser/helper app to the web UI

The browser (or the pairing helper app/script) only ever needs to reach the bioseasy web port
over HTTP or, behind a reverse proxy, HTTPS - see [HTTPS](#5-https) below. Behind a proxy, set:

- `BIOSEASY_BASE_URL` so pairing commands and the OIDC callback are built with the right public
  address instead of the proxy's internal one.
- `BIOSEASY_FORWARDED_ALLOW_IPS` to the proxy's address, so `X-Forwarded-Proto`/`X-Forwarded-For`
  are trusted only from it.

No inbound port is needed from the browser/helper to the device directly; that traffic goes
through bioseasy.

## 3. Install

### Where the image comes from

bioseasy is published as a container image on the GitHub Container Registry:

    ghcr.io/werk-xyz/bioseasy:latest

Built for `linux/amd64` and `linux/arm64`, so a NAS or a small arm64 box runs the same image as a
PC. Pulling needs no account. Pin a version instead of `latest` - `ghcr.io/werk-xyz/bioseasy:1.0.0`
or `:1.0` - if you would rather decide yourself when to upgrade.

To build it yourself instead, see [Building and releasing](building.md).

### Get the compose file

```sh
git clone https://github.com/werk-xyz/bioseasy.git
cd bioseasy
```

The repository carries the compose file and the environment sample; the image is pulled, not
built. If you prefer not to clone, copy `docker-compose.yml` and `.env.example` out of it - they
are the only two files you need.

### Configure

```sh
cp .env.example .env
```

Adjust `BACKUP_ROOT` (the host path for the backup share), `DATA_DIR` (app state and pair records
- keep this on local disk, never on the backup share) and `PUID`/`PGID` (the owner of both
directories on the host: `id -u`, `id -g`).

**Every setting bioseasy understands, with its default, is in
[Configuration](configuration.md)** - HTTPS without a proxy, single sign-on, session length,
timezone and the rest. It is not repeated here, so the two cannot disagree.

Backup windows, retention, notification targets and the free-space threshold are not environment
variables at all: an admin sets them in the web UI, and they are stored in the database so they
change without a restart. A device can override any of them on its own settings page.

### Start it

Create the two directories first, owned by the user in `PUID`/`PGID`. If they do not exist,
Docker creates them owned by root, and the container - which runs as `PUID`/`PGID` - cannot
write to them:

```sh
mkdir -p data backups          # or the paths set in DATA_DIR and BACKUP_ROOT
docker compose up -d
docker compose logs bioseasy
```

The log line on first start looks like this (search the log for `use this token`):

```
No admin account yet. Open /setup and use this token: <token>
```

The same token is stored in `setup_token` in the data directory (mode 0600) until the first admin
exists, in case the log has already rotated.

### First sign-in

Open `http://<server>:<BIOSEASY_PORT>/setup` (default port 8080), paste the token, choose a
username and password. This creates the one admin account; the token is consumed once used.
Sign-in afterwards happens at `/login`.

Over plain HTTP, set `BIOSEASY_SECURE_COOKIES=false` in `.env` before this step and restart. The
session cookie is marked secure by default, and a browser drops a secure cookie that arrives over
plain HTTP, so setup and sign-in would fail. The setup and sign-in pages say so when it applies.
Once HTTPS is in front ([HTTPS](#5-https)), set it back to `true`.

### More users

The admin who completed setup can create further accounts under **Admin -> Users** (admin-only):
a username, a role (admin or member) and an initial password, which the new user
should change from their own **Settings** page afterwards. A member's view is scoped to their own
devices everywhere in the app; an admin sees and manages everything, including this page. A role
change or removal ends that user's other sessions immediately. The last remaining admin can
neither be demoted nor removed, and an admin cannot remove their own account from Users. Removing a user who still owns devices is refused until those devices are
reassigned to someone else on each device's own settings page.

Every account needs an email address: it is what a single sign-on identity is matched against.
The address is set when the account is created and can be changed on this page, by an admin only -
a user cannot set their own, because that would let them claim an address the identity provider is
about to hand to somebody else. Accounts created before bioseasy required an address have none,
and none can be invented for them; the Users page lists them and asks for one. Until an account
has an address, single sign-on cannot reach it.

A user signed in through single sign-on (SSO/OIDC; see [Configuration](configuration.md)) still
has a role managed on this page; their password does not live here at all -
they sign in through the identity provider instead. An account created by single sign-on
self-registration is always a member; promote it here if it should be an admin.

### Storage initialisation

Open **Storage** and click **Use this backup root** once. Only then does bioseasy write a small
marker file under the configured backup root and remember its id; until you do, the page and
every backup report "Backup root is not initialised yet". From then on it checks, before every
backup, that the marker is still there and matches, so that a share which silently failed to
mount does not make bioseasy fill up the container's own disk instead. See
[Storage](#4-storage) for what to do if that check fails.

## 4. Storage

`BACKUP_ROOT` can point at:

- a local disk or partition on the Docker host,
- an NFS export, or
- an SMB/CIFS share,

mounted on the host and bind-mounted into the container through `BACKUP_ROOT` in `.env`. bioseasy
does not mount anything itself; the host must already have the share mounted at that path before
the container starts.

### The marker file check

`src/bioseasy/storage.py` writes `<backup root>/.bioseasy/root-id` once you confirm a backup
root in the UI, and checks it before every backup: if the path exists but the marker is missing,
storage reports "Marker file missing: is the volume mounted?" instead of silently backing up
into whatever local directory happened to exist at that path (for instance because the actual
NFS or SMB mount failed and the empty mount point directory was used instead). If you see that
message, check the host's mount first (`mount | grep <path>`, or `systemctl status
<mount-unit>`), not bioseasy's configuration.

### Hard links and snapshots

After a finished backup, bioseasy takes a snapshot generation with `rsync -a
--link-dest=<previous snapshot>`, so unchanged files are hard-linked rather than copied
(`docs/concept.md`). This needs a filesystem that supports hard links on the backup share. The
storage page shows whether the mount does ("Supported: older generations share unchanged files"
vs. "Not supported: every generation is a full copy") after you probe it once; bioseasy detects
this itself rather than assuming it from the filesystem type.

Local disks and NFS shares generally support hard links. SMB/CIFS is the case to watch: whether a
CIFS mount lets the client see and create hard links depends on the server and on whether the
so-called CIFS Unix Extensions are negotiated, which in turn needs `vers=1.0` (SMB1, generally
best avoided) or `vers=3.1.1` with a server that supports them; `man mount.cifs` warns that
without server inode support "you may not be able to detect hardlinks properly". In practice this
means: do not assume a SMB/CIFS-backed NAS share supports hard links, check what the storage page
reports after mounting it. If it does not, bioseasy falls back to one generation and the UI names
what more would cost.

### `/data` must stay on local disk

App state (the SQLite database) and pair records live in `/data`, mapped from `DATA_DIR`, and
must be on a local disk, never on the backup share. bioseasy's database uses SQLite's
write-ahead logging (WAL) mode, and SQLite's own documentation is explicit that this does not
work over a network filesystem:

> All processes using a database must be on the same host computer; WAL does not work over a
> network filesystem. This is because WAL requires all processes to share a small amount of
> memory and processes on separate host machines obviously cannot share memory with each other.

(sqlite.org, "Write-Ahead Logging", the "WAL" section). Pair records in the same directory are
also device credentials (see `docs/pairing.md`); keeping them off a network share limits who can
reach them to whoever has access to the Docker host.

### Mount examples (host side)

These are `/etc/fstab` entries for the host, not anything bioseasy configures. Point `BACKUP_ROOT`
at the resulting mount point. Options are as documented in `man 5 nfs` and `man 8 mount.cifs`;
verify them against those man pages on your own distribution before relying on them, since option
support can differ between kernel and cifs-utils versions.

NFS:

```
nas.local:/export/iphone-backups  /mnt/nas/iphone-backups  nfs  defaults,hard,timeo=600,retrans=2,vers=4.2  0 0
```

- `hard` (rather than `soft`): the client retries indefinitely instead of returning `EIO` to the
  application after a timeout, which is the safer choice for backup data (`man 5 nfs`, "MOUNT
  OPTIONS", `soft` / `softerr` / `hard`, and its warning that `soft` "can cause silent data
  corruption in certain cases").
- `timeo=600,retrans=2`: the client waits 60 seconds (600 deciseconds, the TCP default) before
  retrying, up to 2 retransmissions before it reports "server not responding" and continues
  retrying under `hard`.
- `vers=4.2`: pin the NFS version explicitly rather than letting the client negotiate; drop it if
  your NAS only serves NFSv3.

SMB/CIFS:

```
//nas.local/iphone-backups  /mnt/nas/iphone-backups  cifs  credentials=/etc/bioseasy-smb-credentials,uid=1000,gid=1000,file_mode=0660,dir_mode=0770,vers=3.1.1,_netdev  0 0
```

- `credentials=<file>`: keeps the username and password out of `/etc/fstab`
  (`username=value` / `password=value` / `domain=value` on separate lines in that file);
  `man 8 mount.cifs` recommends this over plaintext in `fstab`. Protect that file's permissions.
- `uid=`/`gid=`: match `PUID`/`PGID` from `.env` so the container can write to the mount.
- `vers=3.1.1`: the current SMB dialect; also a precondition (together with server support) for
  the Unix Extensions that make hard-link detection possible, see above.
- `_netdev`: a generic mount option telling the boot process this is a network filesystem, so it
  is mounted after networking is up.

## 5. HTTPS

Two ways, pick one:

- **A reverse proxy in front** (Caddy or nginx, below). Recommended when the machine has a real
  name: Caddy fetches a publicly trusted certificate by itself.
- **bioseasy serves HTTPS itself** with `BIOSEASY_TLS` - a self-signed certificate it makes and
  renews, or one you already have. See [Serving HTTPS without a proxy](#serving-https-without-a-proxy).

`BIOSEASY_SECURE_COOKIES` defaults to `true`, so session cookies carry the `Secure` flag and a
browser sends them over HTTPS only. If you deliberately run bioseasy over plain HTTP on the LAN,
set it to `false`: left at `true` on an HTTP-only installation, the browser refuses to store the
session cookie and the login form simply returns to itself with no error message - which looks
like a rejected password rather than a setting.

Because the container uses `network_mode: host`, the app listens directly on
`BIOSEASY_HOST:BIOSEASY_PORT` on the Docker host (default `0.0.0.0:8080`); point a reverse proxy
at `127.0.0.1:8080` (or whatever `BIOSEASY_PORT` is set to) on that same host.

### What a self-signed certificate does and does not affect

- **Backups are not affected at all.** A backup is a separate TLS session between bioseasy and the
  device, authenticated by the pair record's own certificates through pymobiledevice3's lockdown
  client (`engine/pmd3.py`, `TcpLockdownClient`/`create_using_usbmux`). It does not go through the
  web server and never sees its certificate. A self-signed web certificate cannot break a backup,
  and a certificate from a public authority does not make one more secure.
- **The web interface works**, once whoever uses it accepts the certificate in their browser.
- **`BIOSEASY_SECURE_COOKIES=true` keeps working**: the `Secure` flag asks for HTTPS, not for a
  particular kind of certificate.
- **Browser notifications and the home-screen web app need the certificate to be trusted**, not
  merely accepted. Both rest on a service worker (`web/static/push-subscribe.js` registers
  `/static/push-sw.js`), and a service worker only runs in what browsers call a secure context - a
  TLS connection they consider authenticated.

  Tested in Chrome: over plain `http://localhost` the service worker registers, and with a
  self-signed certificate Chrome shows its warning and loads nothing until somebody clicks through.
  Whether the service worker then works after clicking past the warning is untested, and Firefox
  and Safari were not tried. A certificate the client trusts - from an internal authority, or the
  self-signed one installed in the trust store - is the path known to work.

So: a certificate from a trusted authority is not needed for backups. It is the easy way to get
the browser features, and Caddy below gets one for nothing once the machine has a real name. If
the machine has no public name, an internal authority whose root you install on the devices that
use bioseasy does the same job as a public one.

### Serving HTTPS without a proxy

If there is no reverse proxy and none is wanted, bioseasy can serve HTTPS itself with a
certificate it makes on first start:

```
BIOSEASY_TLS=self-signed
BIOSEASY_TLS_NAMES=backup.lan,192.168.1.10
```

`BIOSEASY_TLS_NAMES` is not optional and takes every name and address the installation is opened
at, comma separated. A certificate is only ever accepted for the names written into it, so one
generated without them would match nothing and could not be trusted on a client either - bioseasy
refuses to start rather than write such a certificate. Names that parse as an IP address become IP
entries and everything else becomes a DNS entry, because a browser opening `https://192.168.1.10`
looks only at the former.

The certificate and its key land in `/data/tls` (key mode 0600, like the pair records), are kept
across restarts so nobody is warned twice about a new certificate, and are replaced automatically
when they are close to expiry or when `BIOSEASY_TLS_NAMES` gains an entry they do not cover. They
are valid for 820 days, deliberately under the 825-day limit Apple's platforms enforce on any TLS
certificate, self-signed ones included.

To serve a certificate you already have - from an internal authority, for instance - give the two
files instead and no certificate is generated:

```
BIOSEASY_TLS=on
BIOSEASY_TLS_CERT=/data/tls/your.crt
BIOSEASY_TLS_KEY=/data/tls/your.key
```

With TLS on, set `BIOSEASY_BASE_URL` to the `https://` address and leave
`BIOSEASY_SECURE_COOKIES` at `true`. `BIOSEASY_FORWARDED_ALLOW_IPS` is for a proxy and is not
needed here. The port does not change: it is still `BIOSEASY_PORT`, now speaking TLS, and plain
HTTP to that port gets no answer at all.

### Caddy

Caddy gets automatic HTTPS (via ACME) once you give it a real domain name, no manual certificate
handling needed:

```
backup.example.com

reverse_proxy 127.0.0.1:8080
```

Run `caddy run` from the directory holding that `Caddyfile`. Verified against Caddy's own
"Reverse proxy quick-start" (caddyserver.com/docs/quick-starts/reverse-proxy): it shows exactly
this two-line form for a domain-based proxy and notes that a plain domain name on the first line
gets Caddy to request a publicly trusted certificate automatically, provided DNS points at the
host and ports 80/443 are reachable.

### nginx

nginx needs an existing certificate; it does not fetch one itself. With a certificate already in
place (for example from Let's Encrypt via certbot):

```
server {
    listen 443 ssl;
    server_name backup.example.com;

    ssl_certificate     /etc/letsencrypt/live/backup.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/backup.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

`proxy_pass` and `proxy_set_header` are documented in nginx's "NGINX Reverse Proxy" admin guide
(docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/); `ssl_certificate` and
`ssl_certificate_key` are documented in the `ngx_http_ssl_module` reference
(nginx.org/en/docs/http/ngx_http_ssl_module.html). Redirecting plain port 80 to 443 is left out
here deliberately; add it once you have decided whether anything else on the host also needs port
80.

## 6. Updates and backups of bioseasy itself

To update, pull the new image and recreate the container:

```sh
docker compose pull
docker compose up -d
```

The schema is created automatically on first startup, and upgraded automatically on every later
one (`db.migrate(conn)` in the application's lifespan handler, before the app starts serving
requests; the worker does the same on its own startup). A data volume at schema 8 or later is
migrated forward one
step at a time, in one transaction; before the first step, a consistent copy of the database is
written next to it (`<name>.before-v<N>-<timestamp>` under `DATA_DIR`) in case anything needs to
be rolled back by hand. A data volume older than schema 8, or from a newer bioseasy than the one
you are running (a downgrade), still makes startup fail with a clear message instead of guessing:
stop the container and, for a database too old to migrate, delete the data volume (`/data`, or
the `DATA_DIR` you configured) to start with a fresh database - existing backups under
`BACKUP_ROOT` are untouched either way.

Back up `/data` (the `DATA_DIR` you configured) like any other important data: it holds the
SQLite database and the pair records directory. Pair records are device credentials, equivalent
to a password for backing up that device and reading an unencrypted backup of it
(`docs/pairing.md`); treat backups of `/data` with the same care you would treat a backup of a
password manager, and never let them land on the same share as `BACKUP_ROOT`.

## The worker service

The compose file starts two services from the same image:

- `bioseasy` serves the web UI and only queues background work.
- `worker` runs backups, device discovery, pairing and the schedule (`bioseasy worker`).

Both share `/data` and `/backups`. Background work always goes through Huey, with its own queue
file, `/data/queue.db`, so no database container is involved. Restarting the web UI does not stop
a running backup. A worker restart ends a running backup, which is then recorded as failed
("Worker restarted during the backup") instead of staying "running".

The worker starts once the web service is healthy. Its health check passes while its heartbeat in
the database is younger than 30 seconds:

```sh
docker compose ps
docker compose logs worker
```

## 7. When something does not work

Troubleshooting has its own page: a section at the end of the
installation guide is the one place nobody looks once the thing is installed.

→ **[Troubleshooting](troubleshooting.md)** - a device that does not appear, a failed or
unconfirmed run, storage check failures, where the logs are, and how to collect a report for a bug
report.
