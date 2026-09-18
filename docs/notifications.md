# Notifications

This page is for whoever owns a device or administers this bioseasy install and wants to be told
about it when something needs attention.

bioseasy sends alerts (backup succeeded, failed, overdue, waiting for the passcode, storage
problems) through [Apprise](https://github.com/caronc/apprise). Pasting a raw Apprise URL still
works and stays available as an advanced option, but the device settings page and
**Admin -> Notifications** also offer forms for the two most common services: email and Telegram. Every device's alerts go out to that device's own connectors plus every admin-scope
connector; each connector can be switched off without deleting it, and has its own "Send test
message" button.

## Email

Fields: SMTP host, port, security (None, STARTTLS or TLS), an optional username and password, a
from address, and one or more recipient addresses. The connector builds an Apprise `mailto://`
URL at send time; it is never stored ready-made.

## Telegram

Fields: the bot token from [BotFather](https://core.telegram.org/bots#botfather), a chat id
(numeric, or `@channelname`), and an optional topic id for a forum-style group. Builds an Apprise
`tgram://` URL at send time.

## Browser popups and push

The header's activity indicator already toasts alerts to any open bioseasy tab (no setup needed).
**Settings -> Browser notifications** adds real push: the same events (failed, overdue, due, storage
problems, waiting for the passcode) reach a subscribed browser even with no bioseasy tab open, per
user, off by default, and revocable like an API token.

**iOS and iPadOS constraint, stated plainly wherever the feature is offered:** Safari there only
delivers Web Push to a web app that has been added to the Home Screen (Share, "Add to Home
Screen"); a plain Safari tab cannot subscribe. This has been the case since iOS/iPadOS 16.4
(released 2023-03) and is not a bioseasy limitation. bioseasy already ships a Home Screen web app
for the phone-first flow, so the case that matters here -- an iPhone or iPad user who installed
it -- is covered.

Server side: VAPID keys are generated once and stored at `<data_dir>/vapid_key.pem`, mode 0600,
next to `connector.key`; never logged or rendered. A missing or unreadable key file disables the
feature with a plain message instead of crashing anything (`webpush.py`). A subscription the
browser has revoked (the push service answers 404 or 410) is removed automatically on the next
send attempt. Sending goes through the same off-thread path as email and Telegram
(`runtime.py`'s `notify_event`/`notify_storage_failed`), so a slow or broken push service can
never delay or fail a backup.

## Advanced: raw Apprise URL

For any of the [services Apprise supports](https://github.com/caronc/apprise/wiki) that has no
form of its own here. The URL is validated with Apprise's own parsing, and is itself the
connector's one secret (see below).

## Secrets at rest

The one secret part of each connector - an SMTP password, a Telegram bot token, or a whole raw
Apprise URL - is encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) (symmetric,
authenticated) under a key file, `connector.key`, written into the data directory on first use
with permissions `0600` and kept separate from `bioseasy.db`.

**Honest limit:** this protects a copied or shared database file - a backup, a support
attachment - because the key needed to read the secret columns does not travel with the database
file alone. It does **not** protect an attacker who can already read the whole data volume: the
key file sits right next to the database there, and reads it the same way the application does.
Restricting who can read `/data` on the host is what actually protects a live installation; see
[Installation](install.md), "`/data` must stay on local disk".

Secrets are write-only in the UI: once set, a connector's form shows "set; leave blank to keep
it" and an empty field, never the stored value. Leaving the field blank on save keeps the secret
that is already stored; typing a new value replaces it. Nothing in the application logs a secret,
returns one in an error message, or renders one back into a page.

## Home Assistant (MQTT)

**Admin -> Notifications** also has a "Home Assistant (MQTT)" section: one broker
configuration (host, port, TLS, optional username and password, base topic, discovery prefix),
saved in the `settings` table. The password is encrypted at rest the same way a connector secret
is (see "Secrets at rest" above) and is write-only in the UI.

Once enabled, bioseasy publishes each device's backup state to `<base topic>/device/<id>/state`
as JSON, built from the same status model the read-only API uses, plus Home Assistant MQTT
discovery messages under `<discovery prefix>/...` so four entities per device (backup status,
last successful backup, backup age in hours, overdue) appear in Home Assistant without a custom
integration. The device id in these topics is a short hash of the UDID, never the UDID itself.
Publishing happens after every backup finishes and on every scheduled tick, from the worker
process; a broker that is unreachable is logged by its exception type only and never stops a
backup or a tick. A "Send test state" button on the settings page publishes once on demand,
synchronously from the web process, for immediate feedback.
