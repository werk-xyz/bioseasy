# Status API

This page is for anyone comfortable with URLs and tokens who wants to reach bioseasy from outside
its own web UI -- an iOS Shortcut, a script, or Home Assistant.

A slim HTTP API so you, a script or Home Assistant can query the status of your own devices, and,
with a token scoped for it, start a backup of one of them -- for example from an iOS Shortcuts
automation (see `docs/setup.md`, "Start a backup from iOS Shortcuts").

## Authentication

Every route except `/api/v1/health` needs a personal API token, sent as a bearer token:

```
Authorization: Bearer bse_<prefix>_<secret>
```

Create a token under **Settings -> API tokens** in the web UI, choosing its scope:

- **Read-only** (default): the read routes below.
- **Read and start backups**: the read routes, plus `POST /api/v1/devices/{udid}/backup`.

The full token is shown exactly once, right after creation; only a hash of it is stored, so it
cannot be shown again or recovered if lost. Create a new one and revoke the old one instead. A
token stays valid until you revoke it; nothing else (a password change, a role change) revokes it
automatically.

Session cookies are never accepted here, only the bearer token above.

## Endpoints

### `GET /api/v1/health`

No authentication needed.

```json
{"status": "ok"}
```

### `GET /api/v1/devices`

The devices belonging to the token's owner. An admin's token returns every device on the server, not only
their own.

Returns a JSON array of device objects (shape below).

### `GET /api/v1/devices/{udid}`

One device by UDID. Returns 404, with the same body as any other 404, when the UDID does not
exist or belongs to someone else -- the two cases are indistinguishable on purpose, so a token
cannot be used to discover which UDIDs exist.

### `POST /api/v1/devices/{udid}/backup`

Starts a backup of one of the devices belonging to the token's owner, the same way the web UI's "Back up now"
button does: enqueued at once, run by the worker process. Needs a token scoped **"Read and start
backups"**; a read-only token gets 403.

Returns 202 with the device object (shape below) reflecting the just-started run.

```json
{"udid": "00008110-000000000000001E", "state": "running", ...}
```

| Status | When |
|---|---|
| 403 | The token is read-only. |
| 404 | The UDID does not exist or belongs to someone else -- same rule as the read routes. |
| 409 | A backup (or the wait for the passcode) is already running for this device. |

The device still asks for its passcode on the device itself, exactly like any other backup; this
route only queues the run, it does not enter the passcode for you.

## Device object

The same shape `status.to_public` produces for the web UI and for MQTT. No
secrets and no locations: no notification URLs, no fixed address, no pair record, no backup path.

```json
{
  "udid": "00008110-000000000000001E",
  "name": "Anna's iPhone",
  "model": "iPhone15,2",
  "os_version": "18.4",
  "state": "ok",
  "last_success_at": "2026-09-14T22:03:11Z",
  "next_due_at": "2026-09-15T22:03:11Z",
  "last_run_status": "succeeded",
  "last_run_at": "2026-09-14T22:01:02Z",
  "progress_percent": null,
  "backup_complete": true,
  "encrypted": true
}
```

`state` is one of `running`, `waiting_for_passcode`, `never`, `incomplete`, `overdue`, `due`,
`ok`. Timestamps are UTC, `YYYY-MM-DDTHH:MM:SSZ`, or `null` when not known yet.

## Errors

All responses are JSON, errors included, as `{"detail": "..."}`.

| Status | When |
|---|---|
| 401 | Missing, malformed, unknown or revoked token. The body and status are the same for all four cases, and the response carries `WWW-Authenticate: Bearer`. |
| 404 | `/api/v1/devices/{udid}` for a UDID that does not exist or is not yours. |
| 429 | Rate limit exceeded (see below). The response carries `Retry-After` (seconds). |

## Rate limit

60 requests per minute, enforced per token and per client IP address, whichever is hit first.

## curl example

```sh
# Replace <token> with the value shown once at creation under Settings.
curl -H "Authorization: Bearer <token>" https://your-bioseasy-server/api/v1/devices
```

## OpenAPI schema

`GET /api/v1/openapi.json` serves the schema for this API only; the rest of the app has no
interactive docs, as before.

## Home Assistant

Home Assistant can read this API with its RESTful sensor or command_line integration. The simpler
route is usually the MQTT connector (see [Notifications](notifications.md)), whose discovery
messages make the entities appear on their own.
