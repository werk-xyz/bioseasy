# Configuration

Everything bioseasy reads from the environment, in one place. These are the settings that have to
be known before the app starts; everything a user changes day to day - the backup window,
retention, notification targets, the free-space threshold - is set in the web UI and stored in the
database, so it changes without a restart.

Set them in `.env` next to `docker-compose.yml` (`cp .env.example .env`), or in the `environment:`
block of the compose file.

`tests/test_configuration_docs.py` fails if the code reads a `BIOSEASY_*` variable this page does
not list, so the table below cannot quietly fall behind the code.

## Paths and identity

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_DATA_DIR` | `/data` | Database, session key and pair records. Keep it on local disk and **off** the backup share: a pair record grants access to the device it belongs to. |
| `BIOSEASY_BACKUP_ROOT` | `/backups` | Where backups and their generations are written. This is the big one - a NAS share, usually. |
| `BIOSEASY_ENGINE` | `pymobiledevice3` | `pymobiledevice3` talks to real devices. `demo` simulates them and never touches a device; it is what the demo deployment and the test suite use. |
| `BIOSEASY_SECRET_KEY` | generated once | Signs session cookies. Left unset, a key is generated into `<data dir>/secret_key` (mode 0600) and reused, so sessions survive a restart. Set it only if you want to control the value yourself. |
| `BIOSEASY_TIMEZONE` | `TZ`, else `UTC` | The timezone backup windows and timestamps are interpreted in. |
| `BIOSEASY_SCHEDULE_MINUTES` | `5` | How often the worker's tick runs: it looks for devices that are due, reachable and inside their window. Lower means a scheduled backup starts sooner after the device appears, at the cost of more polling. |

## Web server

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_HOST` | `0.0.0.0` | Address to bind. The default is deliberate: the container is reached from the LAN. Narrow it if you bind to one interface. |
| `BIOSEASY_PORT` | `8080` | Port to serve on. |
| `BIOSEASY_BASE_URL` | unset | The public URL bioseasy is reached at, for example `https://backup.example.net`. Required for single sign-on (it builds the redirect URI) and used wherever bioseasy has to name itself, such as the pairing hand-off command. |
| `BIOSEASY_SECURE_COOKIES` | `true` | Session cookies carry the `Secure` flag. Set to `false` only if you deliberately serve plain HTTP - otherwise the browser throws the cookie away and signing in appears to do nothing. |
| `BIOSEASY_SESSION_HOURS` | `12` | How long a signed-in session lasts. |
| `BIOSEASY_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Which proxy addresses `X-Forwarded-*` headers are trusted from. Set it to your reverse proxy's address when the proxy is not on the same host. |

## HTTPS without a reverse proxy

The documented setup puts a reverse proxy in front, and that proxy owns TLS. These settings are
for an installation that has none. See [Installation](install.md) for what a self-signed
certificate does and does not buy you.

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_TLS` | unset (off) | `self-signed` makes and renews its own certificate. Any other non-empty value serves the certificate named below. |
| `BIOSEASY_TLS_NAMES` | - | Required with `self-signed`: every host name and IP address the server is opened at, comma separated, for example `backup.lan,192.168.1.10`. A certificate carrying none of the names in use matches nothing. |
| `BIOSEASY_TLS_CERT`, `BIOSEASY_TLS_KEY` | - | A certificate and key you already have. Give both. |
| `BIOSEASY_TLS_DIR` | `<data dir>/tls` | Where a self-signed certificate is kept and renewed. |

## Single sign-on (OIDC)

Optional. A sign-in is matched to a local account by its **email address**, which is why every
account here has one; the provider has to report that address as verified. The first sign-in that
matches also records the provider's stable identity for that account, and every later one is
recognised by that rather than by the address.

Register `<BIOSEASY_BASE_URL>/login/oidc/callback` as the redirect URI with your provider.

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_OIDC_ISSUER` | unset | The provider's issuer URL. Discovery is read from `<issuer>/.well-known/openid-configuration`. Setting this, `BIOSEASY_OIDC_CLIENT_ID` and `BIOSEASY_BASE_URL` is what turns single sign-on on. |
| `BIOSEASY_OIDC_CLIENT_ID` | unset | The client id from the provider. |
| `BIOSEASY_OIDC_CLIENT_SECRET` | unset | The client secret. Optional for a public client using PKCE. |
| `BIOSEASY_OIDC_NAME` | `single sign-on` | The label on the sign-in button. |
| `BIOSEASY_OIDC_SCOPES` | `openid profile email` | What to ask the provider for. Keycloak needs `roles` added here for its role claims; authentik ships groups with `profile`. |
| `BIOSEASY_OIDC_ALLOW_REGISTRATION` | `false` | A sign-in matching no account creates one - always as a member, never an admin. Switching this on means everyone the provider lets in has an account here. |
| `BIOSEASY_OIDC_REQUIRED_GROUP` | unset | A group or role required to sign in and to register. Compared case-insensitively. At Entra ID this is a group's object id, not its name. |
| `BIOSEASY_OIDC_GROUPS_CLAIM` | `groups` | Where that membership arrives. A dotted path works for a provider that nests it, for example `realm_access.roles` for Keycloak realm roles. |
| `BIOSEASY_OIDC_REQUIRE_VERIFIED_EMAIL` | `true` | Only match an address the provider marks as verified. Turn it off only for a provider that never sends `email_verified` at all, and only if you trust it to keep addresses under control. |

### Provider notes

- **authentik** reports `email_verified` as false by default since 2025.10, and bioseasy then
  refuses the sign-in. Mark the address as verified at authentik rather than switching
  `BIOSEASY_OIDC_REQUIRE_VERIFIED_EMAIL` off.
- **authentik** serves group membership with the default `profile` scope, but keeps it out of the
  ID token unless "Include claims in id_token" is on; bioseasy then reads it from the userinfo
  endpoint instead.
- **Keycloak** has no group claim by default. Add a mapper, or use `realm_access.roles` and make
  sure it reaches the ID token.
- **Entra ID** sends group object ids, and above 200 groups it sends none at all. Restrict the
  groups the app registration emits, or the sign-in is refused rather than silently let through.

## Pairing helper downloads

The pairing page offers a download of the helper app when you tell it where one is. bioseasy
hosts nothing itself and hard-codes no URL.

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_HELPER_URL_MACOS` | unset | Download URL for the macOS build. |
| `BIOSEASY_HELPER_URL_LINUX` | unset | Download URL for the Linux build. |
| `BIOSEASY_HELPER_URL_WINDOWS` | unset | Download URL for the Windows build. |

## Demo deployment

Only for a throwaway demo (`docker-compose.demo.yml`). Both are ignored unless the demo engine is
running.

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_DEMO_SEED` | `false` | Create demo devices, generations and a demo account on start. The credentials are in `src/bioseasy/demo_seed.py` and are marked as demo credentials; nothing real belongs next to them. |
| `BIOSEASY_DEMO_AUTOLOGIN` | `false` | Visitors arrive signed in as the demo user. Never switch this on anywhere that holds real data. |

## Set at build time, not by you

| Variable | What it does |
|---|---|
| `BIOSEASY_REVISION` | The commit the image was built from, baked in by the build pipeline through the Dockerfile `GITHUB_SHA` build argument and shown in the footer. Unset in a local build, and the footer then omits it rather than showing a blank. |
| `BIOSEASY_DOCS_DIR` | Where the rendered `docs/` tree lives. Falls back to the folder shipped next to the package, which is what the image uses; overridable so tests can point it at a fixture. |

## Compose-level variables

These are read by `docker-compose.yml` itself, not by bioseasy.

| Variable | Default | What it does |
|---|---|---|
| `BIOSEASY_IMAGE` | see `.env.example` | Which image to run. |
| `DATA_DIR`, `BACKUP_ROOT` | `./data`, `./backups` | Host paths mounted into the container. |
| `PUID`, `PGID` | `1000` | The user and group that own those directories on the host (`id -u`, `id -g`). |
