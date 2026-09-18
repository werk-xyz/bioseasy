<p align="center"><img src="docs/assets/logo.svg" alt="" width="96"></p>

# bioseasy

Full, encrypted iPhone and iPad backups over Wi-Fi to your own server. No iCloud subscription,
no cable to your computer. The backups use the same format as Finder and iTunes, so you can
restore them with the tools you already know.

> Pairing, discovery across subnets, encryption, full and incremental encrypted Wi-Fi backups and
> a restore have been run against real devices. As with any backup tool you have just met: keep a
> second copy until you have restored from it yourself.

## How it works

- Runs with Docker Compose on a home server or NAS: one image, a web service and a worker.
- You plug your iPhone or iPad into the server **once** to pair it. From then on it is backed up
  over Wi-Fi.
- iOS asks for your passcode at the start of every backup. That is an Apple rule, and no tool
  can avoid it. bioseasy makes it quick: open bioseasy on the phone, tap **Back up now**, enter
  the passcode.
- The web UI shows every device, when it was last backed up, and whether that backup is
  complete. It keeps older generations, checks that a backup's files are really there, and lets
  you browse a backup and download a single file out of it without a full restore.
- Alerts when a backup fails or falls behind: email, Telegram, any service Apprise supports,
  browser notifications, and Home Assistant over MQTT.

## Try it without a device

Simulated devices, seeded content, nothing that touches a real iPhone:

```sh
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d
```

Open `http://<server>:8080`. `docker compose down -v` removes every trace.

## Install it for real

```sh
cp .env.example .env     # set BACKUP_ROOT, DATA_DIR, PUID/PGID - and see below for plain HTTP
mkdir -p data backups    # or the paths you set; owned by PUID/PGID
docker compose up -d
docker compose logs bioseasy | grep "use this token"
```

Without HTTPS in front yet, set `BIOSEASY_SECURE_COOKIES=false` in `.env` first: the session
cookie is marked secure by default, and a browser drops it over plain HTTP, so signing in would
fail. Open `http://<server>:8080/setup`, paste the token and create your admin account, then follow
[Your first backup](docs/first-backup.md). Requirements, storage and HTTPS are in
[Installation](docs/install.md); every setting is in [Configuration](docs/configuration.md).

**A Linux host is required** - devices are found over mDNS on the LAN, which needs
`network_mode: host`, and Docker Desktop on macOS or Windows cannot provide it.

## Development

```sh
uv sync
uv run ruff check src tests && uv run pytest
BIOSEASY_ENGINE=demo BIOSEASY_DATA_DIR=./data BIOSEASY_BACKUP_ROOT=./backups uv run bioseasy
```

Building the image, building the helper app and cutting a release:
[Building and releasing](docs/building.md).

## Single sign-on

bioseasy can accept sign-in from an OIDC provider you already run (authentik, Keycloak, Entra ID,
Pocket ID and the like). Accounts are matched by verified email address, and a sign-in that
matches nothing can create one if you allow it. The variables, and what each provider does
differently with group claims, are in [Configuration](docs/configuration.md).

## Documentation

[The docs](docs/README.md) are split by audience: running bioseasy, and working on it. They are
also rendered inside the web UI under **Guide**.

## Built on

[pymobiledevice3](https://github.com/doronz88/pymobiledevice3) (GPL-3.0-or-later),
[FastAPI](https://fastapi.tiangolo.com), [htmx](https://htmx.org),
[Apprise](https://github.com/caronc/apprise). Alternative stacks worth knowing:
[libimobiledevice](https://libimobiledevice.org) with
[netmuxd](https://github.com/jkcoxson/netmuxd).

bioseasy is not affiliated with Apple. iPhone, iPad, iTunes and Finder are trademarks of Apple Inc.

## License

[GPL-3.0-or-later](LICENSE). Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
