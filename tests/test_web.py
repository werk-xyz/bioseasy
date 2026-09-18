# SPDX-License-Identifier: GPL-3.0-or-later
import re
import time
from contextlib import closing

import pytest
from fastapi.testclient import TestClient
from fixtures import write_realistic_backup

from bioseasy import auth, db
from bioseasy.app import create_app, valid_fixed_address
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine

PHONE = DEMO_DEVICES[0]
PASSWORD = "correct horse battery"


@pytest.fixture
def env(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def make_admin_with_device(client, settings):
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        # The Add page reads seen_devices instead of calling engine.discover() itself;
        # seed it here the way a completed scan would, since PHONE is
        # already paired in DEMO_DEVICES and this helper only needs the fast "Add" path.
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
    login(client, "admin")
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    assert r.status_code == 303


def _group_labels(page_text):
    return [m.strip() for m in re.findall(r'<h2 class="owner-group">\s*([^<]+)', page_text)]


def test_overview_groups_own_devices_first_then_every_other_owner(env):
    """An admin sees their own devices at the top, then everyone
    else's grouped under the owning user's name. Unowned devices come last - "no owner" is a state to
    fix, not a person, so it does not sort in among the usernames."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAA', 'Admin iPad', ?)", (admin.id,))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('BBB', 'Alice iPhone', ?)", (alice.id,))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('CCC', 'Unassigned spare', NULL)")
        conn.commit()

    login(client, "admin")
    page = client.get("/").text
    assert _group_labels(page) == ["Your devices", "alice", "No owner yet"]
    # Order on the page, not just in the list of labels: own devices really are above the rest.
    assert page.index("Admin iPad") < page.index("Alice iPhone") < page.index("Unassigned spare")


def test_a_member_sees_only_their_own_group_and_no_foreign_owner_name(env):
    """The grouping must not become a way to learn who else exists: a member sees one group with
    their own devices, never another owner's heading, name or device."""
    client, settings = env
    with conn_for(settings) as conn:
        admin = auth.create_user(conn, "admin", PASSWORD, "admin")
        alice = auth.create_user(conn, "alice", PASSWORD, "member")
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('AAA', 'Admin iPad', ?)", (admin.id,))
        conn.execute("INSERT INTO devices (udid, name, owner_id) VALUES ('BBB', 'Alice iPhone', ?)", (alice.id,))
        conn.commit()

    login(client, "alice")
    page = client.get("/").text
    assert _group_labels(page) == ["Your devices"]
    assert "Alice iPhone" in page
    assert "Admin iPad" not in page
    assert "admin" not in _group_labels(page)


def test_setup_needs_the_token_from_the_log(env):
    client, settings = env
    assert "Create the admin account" in client.get("/").text
    # An address is required for every account, the first admin included.
    form = {"username": "admin", "password": PASSWORD, "password2": PASSWORD, "email": "admin@example.test"}

    r = client.post("/setup", data={**form, "csrf": csrf(client, "/setup"), "token": "guessed"})
    assert "not valid" in r.text
    with conn_for(settings) as conn:
        assert not auth.has_users(conn)

    token = (settings.data_dir / "setup_token").read_text()
    r = client.post("/setup", data={**form, "csrf": csrf(client, "/setup"), "token": token})
    assert r.status_code == 303
    assert not (settings.data_dir / "setup_token").exists()
    assert client.get("/setup").headers["location"] == "/login"


def test_forms_without_csrf_token_are_refused(env):
    client, _ = env
    client.get("/login")
    assert client.post("/login", data={"username": "x", "password": "y"}).status_code == 403


def test_wrong_password_is_refused(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    r = client.post("/login", data={"csrf": csrf(client, "/login"), "username": "admin", "password": "nope"})
    assert r.status_code == 200 and "wrong" in r.text
    assert "Sign out" not in client.get("/").text


def test_member_cannot_reach_a_foreign_device(env):
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    token = csrf(client, "/")
    assert PHONE.udid not in client.get("/").text
    assert client.get(f"/devices/{PHONE.udid}").status_code == 404
    assert client.get(f"/devices/{PHONE.udid}/status").status_code == 404
    assert client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": token}).status_code == 404
    assert client.get("/admin/storage").status_code == 404
    assert client.get("/add").status_code == 404


def test_backup_now_runs_to_a_complete_backup(env):
    client, settings = env
    make_admin_with_device(client, settings)
    r = client.post(f"/devices/{PHONE.udid}/backup", data={"csrf": csrf(client, f"/devices/{PHONE.udid}")})
    assert r.status_code == 303
    deadline = time.monotonic() + 10
    while "Backup running" in client.get(f"/devices/{PHONE.udid}/status").text and time.monotonic() < deadline:
        time.sleep(0.05)
    page = client.get("/").text
    assert "Backed up" in page
    assert (settings.backup_root / PHONE.udid / "Status.plist").is_file()


def test_status_reads_progress_from_the_runs_row(env):
    # device_summary must read percent/phase from the runs row, not from JobManager.state():
    # insert a "running" row directly, without ever calling jobs.start(), and check the page
    # reflects it. jobs.state(PHONE.udid) is guaranteed None here, so this only passes if the
    # read genuinely goes through the database.
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase, percent, progress_message) "
            "VALUES (?, 'manual', '2026-09-15T12:00:00Z', 'running', 'transferring', 42, 'Copying files')",
            (PHONE.udid,),
        )
    page = client.get(f"/devices/{PHONE.udid}/status").text
    assert "42" in page
    assert "Transferring" in page
    assert "Backup running" in client.get("/").text


def test_password_change_ends_existing_sessions(env):
    client, settings = env
    with conn_for(settings) as conn:
        user = auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    assert client.get("/").status_code == 200
    with conn_for(settings) as conn:
        auth.change_password(conn, user.id, "another long password")
    assert "Sign out" not in client.get("/").text


def test_login_throttle_returns_429_without_checking_the_password(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    for _ in range(5):  # LoginThrottle's default free-attempt budget
        r = client.post("/login", data={"csrf": csrf(client, "/login"), "username": "admin", "password": "wrong"})
        assert r.status_code == 200

    r = client.post("/login", data={"csrf": csrf(client, "/login"), "username": "admin", "password": PASSWORD})
    assert r.status_code == 429
    assert "Too many attempts" in r.text

    # A different account is throttled too because the IP-keyed throttle also applies.
    with conn_for(settings) as conn:
        auth.create_user(conn, "other", PASSWORD, "member")
    r = client.post("/login", data={"csrf": csrf(client, "/login"), "username": "other", "password": PASSWORD})
    assert r.status_code == 429


def test_device_settings_rejects_bad_input_with_400_and_keeps_it_out_of_the_database(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    bad = {
        "csrf": csrf(client, url),
        "name": "",  # empty: violates the 1..64 rule
        "owner_label": "",
        "interval_mode": "custom",
        "interval_hours": "0",  # out of the 1..720 range
        "retention_mode": "default",
        "window_mode": "custom",
        "window_start": "9:00",  # not HH:MM
        "window_end": "",
        "overdue_mode": "default",
    }
    r = client.post(url, data=bad)
    assert r.status_code == 400
    assert "1 to 64" in r.text
    assert "between 1 and 720" in r.text
    assert "Set both the window" in r.text
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["interval_hours"] is None  # unchanged (inherits the global default), never saved


def test_device_settings_saves_good_input(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    good = {
        "csrf": csrf(client, url),
        "name": "Anna's iPhone",
        "owner_label": "Anna",
        "interval_mode": "custom",
        "interval_hours": "12",
        "retention_mode": "default",
        "window_mode": "custom",
        "window_start": "22:00",
        "window_end": "06:00",
        "charging_mode": "custom",
        "only_when_charging": "1",
        "overdue_mode": "custom",
        "overdue_days": "5",
    }
    r = client.post(url, data=good)
    assert r.status_code == 303
    assert r.headers["location"] == f"/devices/{PHONE.udid}/settings?saved=1"
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["name"] == "Anna's iPhone"
    assert row["interval_hours"] == 12
    assert row["only_when_charging"] == 1
    # "default" mode stores NULL in every retention column (snapshots.resolve_policy then falls
    # back to the server defaults), not the resolved numbers.
    for field in ("keep_last", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"):
        assert row[field] is None


def test_device_settings_saves_custom_retention_override(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    good = {
        "csrf": csrf(client, url),
        "name": "Anna's iPhone",
        "owner_label": "",
        "interval_hours": "24",
        "retention_mode": "custom",
        "keep_last": "10",
        "keep_daily": "0",
        "keep_weekly": "0",
        "keep_monthly": "0",
        "keep_yearly": "0",
        "window_start": "",
        "window_end": "",
        "overdue_days": "3",
    }
    r = client.post(url, data=good)
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT * FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert (row["keep_last"], row["keep_daily"], row["keep_weekly"], row["keep_monthly"], row["keep_yearly"]) == (
        10,
        0,
        0,
        0,
        0,
    )


def test_device_settings_custom_retention_with_every_rule_zero_is_rejected(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    bad = {
        "csrf": csrf(client, url),
        "name": "Anna's iPhone",
        "owner_label": "",
        "interval_hours": "24",
        "retention_mode": "custom",
        "keep_last": "0",
        "keep_daily": "0",
        "keep_weekly": "0",
        "keep_monthly": "0",
        "keep_yearly": "0",
        "window_start": "",
        "window_end": "",
        "overdue_days": "3",
    }
    r = client.post(url, data=bad)
    assert r.status_code == 400
    assert "At least one retention rule must be greater than 0" in r.text
    with conn_for(settings) as conn:
        row = conn.execute("SELECT keep_last FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["keep_last"] is None  # unchanged, the bad submission was never saved


def test_device_settings_custom_retention_out_of_range_is_rejected(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    bad = {
        "csrf": csrf(client, url),
        "name": "Anna's iPhone",
        "owner_label": "",
        "interval_hours": "24",
        "retention_mode": "custom",
        "keep_last": "1001",  # out of the 0..1000 range
        "keep_daily": "0",
        "keep_weekly": "0",
        "keep_monthly": "0",
        "keep_yearly": "0",
        "window_start": "",
        "window_end": "",
        "overdue_days": "3",
    }
    r = client.post(url, data=bad)
    assert r.status_code == 400
    assert "must be between 0 and 1000" in r.text


def test_device_settings_page_shows_effective_policy_and_preview(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"

    # Fresh device, no generations yet, default mode: the page names the server defaults and
    # says there is nothing to prune.
    page = client.get(url).text
    assert "3 latest" in page and "7 daily" in page and "4 weekly" in page and "6 monthly" in page
    assert "No generations yet." in page

    # Switch to a custom, very small keep_last: the preview must reflect the *posted* value on
    # the error re-render, not the previously stored one.
    r = client.post(
        url,
        data={
            "csrf": csrf(client, url),
            "name": "",  # invalid: forces the 400 re-render path
            "owner_label": "",
            "interval_hours": "24",
            "retention_mode": "custom",
            "keep_last": "1",
            "keep_daily": "0",
            "keep_weekly": "0",
            "keep_monthly": "0",
            "keep_yearly": "0",
            "window_start": "",
            "window_end": "",
            "overdue_days": "3",
        },
    )
    assert r.status_code == 400
    assert "No generations yet." in r.text  # still true: nothing was ever backed up


def test_member_cannot_open_a_foreign_devices_settings(env):
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    assert client.get(f"/devices/{PHONE.udid}/settings").status_code == 404
    token = csrf(client, "/")
    assert client.post(f"/devices/{PHONE.udid}/settings", data={"csrf": token, "name": "x"}).status_code == 404


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.42", True),
        ("10.0.0.1", True),
        ("::1", True),
        ("2001:db8::1", True),
        ("iphone.local", True),
        ("backup-server", True),
        ("a.b-c.example.com", True),
        ("", False),  # blank means "clear", handled by the caller, not itself a valid address
        ("http://192.168.1.42", False),  # URL
        ("192.168.1.42:62078", False),  # port
        ("[::1]:62078", False),  # bracketed IPv6 with port
        (" 192.168.1.42", False),  # leading whitespace
        ("192.168.1.42 ", False),  # trailing whitespace
        ("192.168.1.42/24", False),  # CIDR
        ("-badstart.example.com", False),  # label starting with a hyphen
        ("bad-.example.com", False),  # label ending with a hyphen
        ("a" * 254, False),  # over the 253-char limit
        ("not a host", False),  # internal whitespace
    ],
)
def test_valid_fixed_address(value, expected):
    assert valid_fixed_address(value) is expected


def test_device_settings_saves_and_clears_a_fixed_address(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    good = {
        "csrf": csrf(client, url),
        "name": PHONE.name,
        "owner_label": "",
        "interval_hours": "24",
        "window_start": "",
        "window_end": "",
        "overdue_days": "3",
        "host": "192.168.50.7",
    }
    r = client.post(url, data=good)
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT host FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["host"] == "192.168.50.7"

    cleared = {**good, "csrf": csrf(client, url), "host": ""}
    r = client.post(url, data=cleared)
    assert r.status_code == 303
    with conn_for(settings) as conn:
        row = conn.execute("SELECT host FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["host"] is None


def test_device_settings_rejects_a_bad_fixed_address(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    bad = {
        "csrf": csrf(client, url),
        "name": PHONE.name,
        "owner_label": "",
        "interval_hours": "24",
        "window_start": "",
        "window_end": "",
        "overdue_days": "3",
        "host": "http://192.168.50.7:62078",
    }
    r = client.post(url, data=bad)
    assert r.status_code == 400
    assert "Fixed address" in r.text
    with conn_for(settings) as conn:
        row = conn.execute("SELECT host FROM devices WHERE udid = ?", (PHONE.udid,)).fetchone()
    assert row["host"] is None  # unchanged, the bad submission was never saved


def test_device_settings_test_notification_never_sends_a_real_message(env, monkeypatch):
    client, settings = env
    make_admin_with_device(client, settings)
    sent = {}

    def fake_send(urls, title, body):
        sent["urls"], sent["title"], sent["body"] = urls, title, body
        from bioseasy.notify import NotifyResult

        return NotifyResult(ok=True)

    monkeypatch.setattr("bioseasy.app.notify.send", fake_send)
    url = f"/devices/{PHONE.udid}/settings"
    # Notifications go through notification_connectors only now (docs/notifications.md); add one
    # rather than a legacy free-text field.
    client.post(
        f"/devices/{PHONE.udid}/connectors/apprise",
        data={"csrf": csrf(client, url), "label": "Raw webhook", "url": "json://localhost"},
    )
    r = client.post(f"/devices/{PHONE.udid}/settings/test-notification", data={"csrf": csrf(client, url)})
    assert r.status_code == 200
    assert "Test message sent" in r.text
    assert sent["urls"] == ["json://localhost"]


def test_member_cannot_reach_admin_settings(env):
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        auth.create_user(conn, "member", PASSWORD, "member")
    client.cookies.clear()
    login(client, "member")
    assert client.get("/admin/defaults").status_code == 404


# --- home screen web app (add to home screen, for the phone-first flow) ------------------------


def test_manifest_is_served_with_the_manifest_content_type(env):
    client, _ = env
    r = client.get("/static/manifest.webmanifest")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/manifest+json")
    body = r.json()
    assert body["name"] == "bioseasy"
    assert body["short_name"] == "bioseasy"
    assert body["start_url"] == "/"
    assert body["scope"] == "/"
    assert body["display"] == "standalone"
    sizes = {icon["sizes"] for icon in body["icons"]}
    assert sizes == {"180x180", "192x192", "512x512"}
    for icon in body["icons"]:
        assert client.get(icon["src"]).status_code == 200


def test_head_carries_the_ios_home_screen_tags(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    # /login needs no session, and base.html's <head> is the same on every page.
    text = client.get("/login").text
    assert '<link rel="manifest" href="/static/manifest.webmanifest">' in text
    assert '<link rel="apple-touch-icon" href="/static/icon-180.png">' in text
    assert '<meta name="apple-mobile-web-app-title" content="bioseasy">' in text
    assert '<meta name="apple-mobile-web-app-capable" content="yes">' in text
    assert 'name="theme-color" media="(prefers-color-scheme: light)"' in text
    assert 'name="theme-color" media="(prefers-color-scheme: dark)"' in text


def test_ios_home_hint_markup_is_present_but_hidden_by_default(env):
    client, settings = env
    make_admin_with_device(client, settings)
    text = client.get(f"/devices/{PHONE.udid}").text
    assert '<p id="ios-home-hint" class="flash" hidden>' in text
    assert "Add bioseasy to your Home Screen" in text
    assert "Add to Home Screen" in text
    assert 'id="ios-home-hint-dismiss"' in text


def test_a_device_that_is_backing_up_is_not_told_to_finish_its_setup(env):
    """The two timestamps say bioseasy switched Wi-Fi backups and encryption on, or confirmed them.

    They can be empty on a device that is plainly fine - a pair record survives a recreated
    database (docs/setup.md, "Adding a device again") - and the overview then told that device to
    finish a setup it had finished, right next to the backup that proves otherwise. Unconfirmed is
    a third state, not the same as open.
    """
    client, settings = env
    make_admin_with_device(client, settings)
    write_realistic_backup(settings.backup_root / PHONE.udid, PHONE, encrypted=True)
    with conn_for(settings) as conn:
        conn.execute(
            "UPDATE devices SET wifi_enabled_at = NULL, encryption_enabled_at = NULL WHERE udid = ?",
            (PHONE.udid,),
        )

    page = client.get("/").text

    assert "Check setup" in page
    assert "Finish setup" not in page


def test_login_says_the_session_cookie_will_be_dropped_over_plain_http_on_the_lan(tmp_path):
    """The quick start sends people to http://<server>:8080. With secure cookies on (the default)
    the browser drops the session cookie there and setup fails with "form expired" and no reason.
    The page must say why before that happens - and must not say it where the cookie is kept."""
    from bioseasy.config import Settings
    from bioseasy.engine.demo import DemoEngine

    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    secure = Settings(data, root, "demo", "test-secret", True, 3600, schedule_minutes=0)
    app = create_app(secure, DemoEngine(step_seconds=0))
    warning = "your browser will not keep it"
    with TestClient(app, base_url="http://192.0.2.10:8080", follow_redirects=False) as lan:
        assert warning in lan.get("/setup").text
    with TestClient(app, base_url="http://localhost:8080", follow_redirects=False) as local:
        assert warning not in local.get("/setup").text  # browsers treat localhost as secure
    with TestClient(app, base_url="https://backup.example.net", follow_redirects=False) as tls:
        assert warning not in tls.get("/setup").text
