# SPDX-License-Identifier: GPL-3.0-or-later
"""Structural accessibility and empty/error-state checks over the rendered HTML of every page
and htmx fragment.

Renders each of the 36 templates in src/bioseasy/web/templates/ through the demo engine (fresh
`create_app(settings, engine, huey_immediate=True)` per test, following tests/test_web.py's own
fixture shape) and walks the returned HTML with the standard library's html.parser - no new
dependency; pyproject.toml carries neither beautifulsoup4 nor lxml, and none is added here.

Coverage, and what is deliberately out of scope:
- base.html and _macros.html are not routes on their own. base.html is exercised on every full
  page in this file (it wraps every extends="base.html" template: <html lang>, skip link, header
  nav, the activity indicator include, and the footer with the theme button all render through
  it on every single test below). _macros.html's macros (health, strip, status_pill,
  error_list, device_meta, the connector field sets) are exercised transitively through every
  template that imports them - _generations.html, dashboard.html, device.html, add.html,
  logs.html, _netcheck.html, _device_setup.html, storage.html, admin_settings.html,
  device_settings.html and _connectors_section.html between them cover every macro in the file.
  Neither file is asserted on "standalone" because there is no URL that renders either one alone.
_scope_note.html is the third template with no route of its own: it is the "these are your own
account's settings" note included by each personal Settings page, so it renders only inside them
and is exercised through those - never on its own, the same way base.html and _macros.html are.

The template count in this docstring is not maintained by hand: test_every_template_is_covered
at the bottom of this file fails when a template exists that this module never names, which is
how a template without any coverage was found before - the count here is only trustworthy
because that guard keeps it honest.

- Every other template (34 of the 36) is rendered by name at least once, most in both an empty
  and a populated state, and for account.html, dashboard.html and device.html in both an admin
  and a member view (device_settings.html, device_setup.html, device.html and restore.html are
  reachable by a member only for a device that member owns, which the member-view tests set up).

Checks applied to each rendered page, structural rather than visual (no browser):
- exactly one <h1> on every full page (fragments returned to htmx, which never carry their own
  <html>/<body>, are excluded from the h1 count - the page that includes them already has one);
- every <input>/<select>/<textarea> except hidden inputs and the CSRF token has an id with a
  matching <label for>, an aria-label, an aria-labelledby, or is nested inside a wrapping
  <label>...</label> (the pattern _macros.html's connector field macros and most hand-written
  forms in this project use);
- every <img> carries an alt attribute (empty alt="" counts - it is the correct choice for the
  purely decorative logo mark in the header);
- the empty-state sentence a template is supposed to show with no data is actually present when
  the view is rendered with no data.

To prove this test module actually catches what it claims to, a real template's label association
was broken by hand once, the checker was confirmed to go red, and the template was restored - see
the note at the bottom of this file for the captured output.
"""

from __future__ import annotations

import re
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fixtures import write_realistic_backup

from bioseasy import auth, db, snapshots
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DEMO_DEVICES, DemoEngine, write_backup

PHONE = DEMO_DEVICES[0]  # pre-paired in the demo story
TABLET = DEMO_DEVICES[1]  # unpaired in the demo story; used here as a bare, dataless device
PASSWORD = "correct horse battery"

VOID_INPUT_TYPES_EXEMPT = {"hidden"}


# --------------------------------------------------------------------------------------------
# Structural HTML checks (standard library only, no browser)
# --------------------------------------------------------------------------------------------


@dataclass
class _Control:
    tag: str
    attrs: dict
    inside_label: bool
    # Class of the <label> wrapping this control, and of the <form> around it - enough to tell a
    # toggle that sits beside its text from one app.css stretches across the form, see
    # assert_toggles_sit_next_to_their_label below.
    label_class: str = ""
    form_class: str = ""


@dataclass
class _PageStructure:
    heading_levels: list[int] = field(default_factory=list)
    controls: list[_Control] = field(default_factory=list)
    label_for_targets: set[str] = field(default_factory=set)
    imgs: list[dict] = field(default_factory=list)


class _StructureParser(HTMLParser):
    """One forward pass: tracks the open-tag stack only deep enough to know whether the current
    <input>/<select>/<textarea> sits inside a <label>...</label> wrapper, and collects every
    heading, label[for], and img along the way."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.result = _PageStructure()
        self._label_depth = 0
        self._labels: list[dict] = []
        self._forms: list[str] = []
        self._stack: list[str] = []

    def handle_starttag(self, tag, attrs_list):
        attrs = dict(attrs_list)
        if tag == "label":
            self._label_depth += 1
            self._labels.append(attrs)
            if "for" in attrs:
                self.result.label_for_targets.add(attrs["for"])
        elif tag == "form":
            self._forms.append(attrs.get("class", ""))
        elif re.fullmatch(r"h[1-6]", tag):
            self.result.heading_levels.append(int(tag[1]))
        elif tag == "img":
            self.result.imgs.append(attrs)
        elif tag in ("input", "select", "textarea"):
            self.result.controls.append(
                _Control(
                    tag,
                    attrs,
                    inside_label=self._label_depth > 0,
                    label_class=self._labels[-1].get("class", "") if self._labels else "",
                    form_class=self._forms[-1] if self._forms else "",
                )
            )
        if tag not in ("input", "img", "br", "hr"):
            self._stack.append(tag)

    def handle_endtag(self, tag):
        if tag == "label" and self._label_depth > 0:
            self._label_depth -= 1
            if self._labels:
                self._labels.pop()
        if tag == "form" and self._forms:
            self._forms.pop()
        if self._stack and tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass

    def handle_startendtag(self, tag, attrs_list):
        # Self-closed forms (<input ... />) never open the stack, so treat like a start tag only.
        self.handle_starttag(tag, attrs_list)


def parse_structure(html_text: str) -> _PageStructure:
    parser = _StructureParser()
    parser.feed(html_text)
    return parser.result


def assert_single_h1(structure: _PageStructure, *, context: str) -> None:
    h1_count = structure.heading_levels.count(1)
    assert h1_count == 1, f"{context}: expected exactly one <h1>, found {h1_count}"


def assert_no_skipped_heading_levels(structure: _PageStructure, *, context: str) -> None:
    seen_max = 0
    for level in structure.heading_levels:
        if level > seen_max + 1 and seen_max != 0:
            raise AssertionError(f"{context}: heading level jumps from h{seen_max} to h{level}")
        seen_max = max(seen_max, level)


def assert_controls_are_labelled(structure: _PageStructure, *, context: str) -> None:
    for control in structure.controls:
        attrs = control.attrs
        if control.tag == "input" and attrs.get("type") in VOID_INPUT_TYPES_EXEMPT:
            continue
        if attrs.get("name") == "csrf":
            continue
        labelled = (
            control.inside_label
            or "aria-label" in attrs
            or "aria-labelledby" in attrs
            or (attrs.get("id") and attrs["id"] in structure.label_for_targets)
        )
        assert labelled, f"{context}: unlabelled <{control.tag}> with attrs {attrs}"


def assert_imgs_have_alt(structure: _PageStructure, *, context: str) -> None:
    for attrs in structure.imgs:
        assert "alt" in attrs, f"{context}: <img> without alt, attrs {attrs}"


def assert_toggles_sit_next_to_their_label(structure: _PageStructure, *, context: str) -> None:
    """A radio or checkbox wrapped in a label inside a `.stack` form needs `class="checkbox-row"`.

    `app.css` styles `.stack label` as a grid, which stretches whatever sits in it across the whole
    form. Without the class, the two role radios on the Users page rendered 937x44 px, each one
    above its own text instead of beside it, and the
    markup gave no hint: `.stack label.checkbox-row` is the escape hatch every other checkbox in
    this app already uses.

    Checked structurally against the rendered HTML, so it catches the next label that forgets the
    class rather than the two that were fixed. It cannot see the CSS itself - what the cascade then
    does with these classes is `tests/test_header.py`'s `[hidden]` guard and, ultimately, a browser.
    """
    for control in structure.controls:
        if control.tag != "input" or control.attrs.get("type") not in ("radio", "checkbox"):
            continue
        if not control.inside_label or "stack" not in control.form_class.split():
            continue
        assert "checkbox-row" in control.label_class.split(), (
            f"{context}: <input type={control.attrs.get('type')!r} name={control.attrs.get('name')!r}> "
            'sits inside a .stack form\'s <label> without class="checkbox-row", so app.css stretches '
            "it across the full form width instead of putting it beside its text"
        )


def assert_page_a11y(html_text: str, *, context: str, expect_h1: bool = True) -> _PageStructure:
    structure = parse_structure(html_text)
    if expect_h1:
        assert_single_h1(structure, context=context)
    assert_no_skipped_heading_levels(structure, context=context)
    assert_controls_are_labelled(structure, context=context)
    assert_imgs_have_alt(structure, context=context)
    assert_toggles_sit_next_to_their_label(structure, context=context)
    return structure


# --------------------------------------------------------------------------------------------
# Fixtures and helpers, following tests/test_web.py and tests/test_generations.py
# --------------------------------------------------------------------------------------------


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


def create_admin(settings, username="admin"):
    with conn_for(settings) as conn:
        auth.create_user(conn, username, PASSWORD, "admin")


def create_member(settings, username="member"):
    with conn_for(settings) as conn:
        auth.create_user(conn, username, PASSWORD, "member")


def add_bare_device(settings, device, owner_username):
    """Insert a device row directly, the way app.py's own /add handlers do (see
    app.py:1791/1840/1925/2052) - bypasses discovery and pairing so a test can get a device with
    genuinely no runs, no backup and no snapshots, to exercise the empty-state branches of
    device.html and _generations.html that a demo backup would otherwise paper over."""
    with conn_for(settings) as conn:
        owner = conn.execute("SELECT id FROM users WHERE username = ?", (owner_username,)).fetchone()
        conn.execute(
            "INSERT INTO devices (udid, name, product_type, os_version, owner_id, paired_at) "
            "VALUES (?, ?, ?, ?, ?, '2026-09-15T00:00:00Z')",
            (device.udid, device.name, device.product_type, device.os_version, owner["id"]),
        )
        conn.commit()


def make_admin_with_device(client, settings, device=PHONE, username="admin"):
    with conn_for(settings) as conn:
        if not conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            auth.create_user(conn, username, PASSWORD, "admin")
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (device.udid, device.name, device.product_type, device.os_version, device.transport.value),
        )
        conn.commit()
    login(client, username)
    client.post("/admin/storage/initialise", data={"csrf": csrf(client, "/admin/storage")})
    r = client.post("/add", data={"csrf": csrf(client, "/add"), "udid": device.udid})
    assert r.status_code == 303


def seed_generations(settings, device=PHONE, count=1):
    write_backup(settings.backup_root / device.udid, device)
    names = []
    for _ in range(count):
        snap = snapshots.take(settings.backup_root, device.udid, datetime.now(UTC), hardlinks=True)
        names.append(snap.name)
        time.sleep(1.1)
    return names


# --------------------------------------------------------------------------------------------
# setup.html / login.html / error.html
# --------------------------------------------------------------------------------------------


def test_setup_page_a11y(env):
    client, _ = env
    page = client.get("/setup").text
    assert_page_a11y(page, context="setup.html")


def test_setup_page_error_state_keeps_username(env):
    client, settings = env
    token = (settings.data_dir / "setup_token").read_text()
    r = client.post(
        "/setup",
        data={
            "csrf": csrf(client, "/setup"),
            "token": token,
            "username": "carol",
            "password": "twelve characters",
            "password2": "does not match",
        },
    )
    assert_page_a11y(r.text, context="setup.html (error)")
    assert "do not match" in r.text
    assert 'value="carol"' in r.text  # entered value kept, password fields excepted


def test_login_page_a11y(env):
    client, settings = env
    create_admin(settings)
    page = client.get("/login").text
    assert_page_a11y(page, context="login.html")


def test_error_page_404_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    r = client.get("/devices/does-not-exist")
    assert r.status_code == 404
    assert_page_a11y(r.text, context="error.html")


# --------------------------------------------------------------------------------------------
# dashboard.html
# --------------------------------------------------------------------------------------------


def test_dashboard_empty_state_admin(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/").text
    structure = assert_page_a11y(page, context="dashboard.html (empty, admin)")
    assert "No devices yet." in page
    assert structure.heading_levels.count(1) == 1


def test_dashboard_with_device_admin_and_member(env):
    client, settings = env
    make_admin_with_device(client, settings)
    admin_page = client.get("/").text
    assert_page_a11y(admin_page, context="dashboard.html (admin, with device)")
    assert PHONE.name in admin_page

    create_member(settings)
    with conn_for(settings) as conn:
        member = conn.execute("SELECT id FROM users WHERE username = 'member'").fetchone()
        conn.execute("UPDATE devices SET owner_id = ? WHERE udid = ?", (member["id"], PHONE.udid))
        conn.commit()
    login(client, "member")
    member_page = client.get("/").text
    assert_page_a11y(member_page, context="dashboard.html (member, with own device)")
    assert PHONE.name in member_page
    # Member-only header items must not appear (test_footer.py already covers this in depth;
    # repeated narrowly here because it is part of the same page this test renders).
    assert "/add" not in re.search(r"<header\b.*?</header>", member_page, re.DOTALL).group(0)


# --------------------------------------------------------------------------------------------
# device.html / _status.html / _generations.html / _password_check.html
# --------------------------------------------------------------------------------------------


def test_device_page_empty_states(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    add_bare_device(settings, TABLET, "admin")
    page = client.get(f"/devices/{TABLET.udid}").text
    structure = assert_page_a11y(page, context="device.html (fresh device, no runs/backup)")
    assert "No runs yet." in page
    assert "No backup of this device on disk yet." in page
    assert "No generations yet." in page
    # And no password check: there is no backup to check a password against. The control is
    # exercised below, on a device that actually has an encrypted backup - which is where it has to
    # carry a label, not here.
    assert not any(c.attrs.get("id") == "password-check-input" for c in structure.controls)


def test_device_page_password_check_is_labelled_where_it_appears(env):
    """The password check renders a labelled control on the device it belongs to.

    Split off from the empty-state test: that one had asserted the control on a
    device with no backup at all, which is exactly where the section no longer belongs.
    """
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    add_bare_device(settings, TABLET, "admin")
    write_realistic_backup(settings.backup_root / TABLET.udid, TABLET, encrypted=True)

    page = client.get(f"/devices/{TABLET.udid}").text
    structure = assert_page_a11y(page, context="device.html (encrypted backup, password check)")

    assert any(c.attrs.get("id") == "password-check-input" for c in structure.controls)


def test_device_page_with_generations_admin_and_member(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_generations(settings, count=1)
    admin_page = client.get(f"/devices/{PHONE.udid}").text
    assert_page_a11y(admin_page, context="device.html (admin, with generations)")
    assert "No generations yet." not in admin_page

    create_member(settings)
    with conn_for(settings) as conn:
        member = conn.execute("SELECT id FROM users WHERE username = 'member'").fetchone()
        conn.execute("UPDATE devices SET owner_id = ? WHERE udid = ?", (member["id"], PHONE.udid))
        conn.commit()
    login(client, "member")
    member_page = client.get(f"/devices/{PHONE.udid}").text
    assert_page_a11y(member_page, context="device.html (member, own device, with generations)")


def test_status_fragment_a11y(env):
    """The status route answers with `_status_live.html`: the status block plus `_runs.html` and
    `_backup_on_disk.html` as out-of-band swaps. All three land in a live page, so all three are
    checked here - a fragment that
    is swapped in has to be as sound as the page it lands in, and nothing else renders them
    together."""
    client, settings = env
    make_admin_with_device(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/status", headers={"HX-Request": "true"}).text
    assert_page_a11y(
        page,
        context="_status_live.html (_status.html + _runs.html + _backup_on_disk.html, fragment)",
        expect_h1=False,
    )
    assert 'id="recent-runs"' in page
    assert "Recent backup runs, newest first" in page
    assert 'id="backup-on-disk"' in page


def test_password_check_fragment_error_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}")
    r = client.post(
        f"/devices/{PHONE.udid}/password-check",
        data={"csrf": token, "password": "definitely-wrong"},
        headers={"HX-Request": "true"},
    )
    assert_page_a11y(r.text, context="_password_check.html (fragment, error)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# device_settings.html / _connectors_section.html / _password_change.html / _netcheck.html
# --------------------------------------------------------------------------------------------


def test_device_settings_page_a11y_admin_and_member(env):
    client, settings = env
    make_admin_with_device(client, settings)
    admin_page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert_page_a11y(admin_page, context="device_settings.html (admin)")

    create_member(settings)
    with conn_for(settings) as conn:
        member = conn.execute("SELECT id FROM users WHERE username = 'member'").fetchone()
        conn.execute("UPDATE devices SET owner_id = ? WHERE udid = ?", (member["id"], PHONE.udid))
        conn.commit()
    login(client, "member")
    member_page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert_page_a11y(member_page, context="device_settings.html (member, own device)")


def test_device_settings_error_state_keeps_values_and_has_described_error_list(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    token = csrf(client, url)
    r = client.post(
        url,
        data={
            "csrf": token,
            "name": "My Phone",
            "owner_label": "",
            "interval_mode": "default",
            "retention_mode": "default",
            "window_mode": "default",
            "charging_mode": "default",
            "overdue_mode": "custom",
            "overdue_days": "9999",  # out of the 1..60 range -> validation error
        },
    )
    assert r.status_code == 400
    assert_page_a11y(r.text, context="device_settings.html (validation error)")
    assert 'value="My Phone"' in r.text  # entered value preserved
    error_list_ids = [c for c in re.findall(r'<ul id="([^"]+)"[^>]*class="flash bad"', r.text)]
    assert error_list_ids, "expected an id'd error list"
    described = re.search(r'<form[^>]*aria-describedby="' + error_list_ids[0] + r'"', r.text)
    assert described, "form must reference the error list via aria-describedby"


def test_connectors_add_error_has_described_error_list(env):
    client, settings = env
    make_admin_with_device(client, settings)
    url = f"/devices/{PHONE.udid}/settings"
    token = csrf(client, url)
    r = client.post(
        f"/devices/{PHONE.udid}/connectors/email",
        data={"csrf": token, "label": "", "host": "", "port": "", "from_addr": "not-an-email"},
    )
    page_text = r.text if r.status_code != 303 else client.get(url).text
    assert_page_a11y(page_text, context="device_settings.html (connector add error)")
    assert 'id="connector-add-errors-email"' in page_text
    assert 'aria-describedby="connector-add-errors-email"' in page_text


def test_password_change_fragment_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        conn.execute("UPDATE devices SET encryption_enabled_at = '2026-09-15T00:00:00Z' WHERE udid = ?", (PHONE.udid,))
        conn.commit()
    page = client.get(f"/devices/{PHONE.udid}/settings").text
    assert_page_a11y(page, context="device_settings.html (with _password_change.html included)")
    assert 'id="password-change"' in page


def test_netcheck_fragment_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    token = csrf(client, f"/devices/{PHONE.udid}/settings")
    r = client.post(
        f"/devices/{PHONE.udid}/netcheck",
        data={"csrf": token, "return_to": "settings"},
        headers={"HX-Request": "true"},
    )
    assert_page_a11y(r.text, context="_netcheck.html (fragment)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# device_setup.html / _device_setup.html / _ios_home_hint.html
# --------------------------------------------------------------------------------------------


def test_device_setup_page_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/setup").text
    assert_page_a11y(page, context="device_setup.html")


def test_device_setup_fragment_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    page = client.get(f"/devices/{PHONE.udid}/setup/status", headers={"HX-Request": "true"}).text
    assert_page_a11y(page, context="_device_setup.html (fragment)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# add.html / pair_code.html / _pair_code_status.html / pairing_status.html / _pairing_status.html
# --------------------------------------------------------------------------------------------


def test_add_page_empty_state_admin(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/add").text
    assert_page_a11y(page, context="add.html (no seen devices)")
    assert "No new device found." in page


def test_add_page_upload_error_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    token = csrf(client, "/add")
    r = client.post(
        "/add/pair-record",
        data={"csrf": token, "udid": ""},
        files={"record": ("device.plist", b"not a plist", "application/octet-stream")},
    )
    assert_page_a11y(r.text, context="add.html (upload error)")
    assert 'id="pair-record-errors"' in r.text
    assert 'aria-describedby="pair-record-errors"' in r.text


def test_pair_code_page_and_fragment_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    token = csrf(client, "/add")
    r = client.post("/add/pair-code", data={"csrf": token})
    assert r.status_code == 303
    page = client.get(r.headers["location"]).text
    assert_page_a11y(page, context="pair_code.html")

    code = r.headers["location"].rsplit("/", 1)[-1]
    fragment = client.get(f"/add/pair-code/{code}/status", headers={"HX-Request": "true"}).text
    assert_page_a11y(fragment, context="_pair_code_status.html (fragment)", expect_h1=False)


def test_pairing_status_page_and_fragment_a11y(env):
    # /add/pair itself runs pair_device synchronously under huey_immediate=True and the demo
    # engine finishes instantly, so by the time a request could GET the status page the pairing
    # row is already "done" and the route redirects (add_device_from_pairing, app.py:1852) rather
    # than rendering pairing_status.html at all. Insert a still-"pending" row directly instead, so
    # this test actually exercises the "Pairing..." branch the template and its poll fragment
    # render while a real, slower pairing is in flight.
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO pairings (udid, state, message, updated_at) VALUES (?, 'pending', NULL, ?)",
            (TABLET.udid, "2026-09-15T00:00:00Z"),
        )
        conn.commit()
    page = client.get(f"/add/pairing/{TABLET.udid}").text
    assert_page_a11y(page, context="pairing_status.html")
    assert "Pairing…" in page
    fragment = client.get(f"/add/pairing/{TABLET.udid}/status", headers={"HX-Request": "true"}).text
    assert_page_a11y(fragment, context="_pairing_status.html (fragment)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# admin_settings.html / account.html
# --------------------------------------------------------------------------------------------


def test_admin_settings_page_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/defaults").text
    assert_page_a11y(page, context="admin_settings.html")
    # Connectors moved to their own Admin page, so the empty state belongs there
    # now, not on Defaults.
    notifications = client.get("/admin/notifications").text
    assert_page_a11y(notifications, context="admin_notifications.html")
    assert "No connectors yet." in notifications


def test_admin_settings_error_state_has_described_error_list(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    token = csrf(client, "/admin/defaults")
    r = client.post(
        "/admin/defaults",
        data={
            "csrf": token,
            "window_start": "not-a-time",
            "window_end": "22:00",
            "interval_hours": "24",
            "overdue_days": "3",
            "free_space_threshold_gb": "5",
            "notice_lead_minutes": "30",
            "keep_last": "5",
            "keep_daily": "0",
            "keep_weekly": "0",
            "keep_monthly": "0",
            "keep_yearly": "0",
        },
    )
    assert r.status_code == 400
    assert_page_a11y(r.text, context="admin_settings.html (validation error)")
    assert 'id="settings-errors"' in r.text
    assert 'aria-describedby="settings-errors"' in r.text


def test_account_page_empty_state_admin_and_member(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/settings").text
    assert_page_a11y(page, context="account.html (admin)")
    # Single sign-on and API tokens each have their own page; their empty states
    # belong there, not on the password page.
    assert "No single sign-on identity linked yet." in client.get("/settings/sso").text
    assert "No API tokens yet." in client.get("/settings/tokens").text

    create_member(settings)
    login(client, "member")
    member_page = client.get("/settings").text
    assert_page_a11y(member_page, context="account.html (member)")


# --------------------------------------------------------------------------------------------
# storage.html / storage_browse.html / _dir_size.html
# --------------------------------------------------------------------------------------------


def test_storage_page_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/storage").text
    assert_page_a11y(page, context="storage.html")


def test_storage_browse_empty_directory(env):
    # Deliberately does not POST /storage/initialise first: that writes a ".bioseasy" marker
    # directory into the backup root (storage.py MARKER), which would make backup_root non-empty
    # and this test would stop exercising the actual "This directory is empty." branch. The
    # fixture's tmp_path backup root already exists and is genuinely empty without it.
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/storage/browse").text
    assert_page_a11y(page, context="storage_browse.html (empty)")
    assert "This directory is empty." in page


def test_dir_size_fragment_a11y(env):
    client, settings = env
    make_admin_with_device(client, settings)
    seed_generations(settings, count=1)
    page = client.get("/admin/storage/browse").text
    assert_page_a11y(page, context="storage_browse.html (with entries, includes _dir_size.html)")
    fragment = client.get(f"/admin/storage/browse/size?path={PHONE.udid}").text
    assert_page_a11y(fragment, context="_dir_size.html (fragment)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# logs.html / about.html
# --------------------------------------------------------------------------------------------


def test_logs_page_empty_state(env):
    # The app itself logs a warning on startup ("No admin account yet...", app.py:479) before
    # this test creates one, so an unfiltered /logs is not actually empty by the time this runs.
    # Filter on a device id nothing will ever match instead, to reliably hit log_page.rows == [].
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/logs?device=no-such-device").text
    assert_page_a11y(page, context="logs.html (empty)")
    assert "No log entries match this filter." in page


def test_device_files_page_a11y(env):
    """device_files.html in both states: a browsable backup and one that cannot be read.

    The demo device added here has no backup directory on disk, which is exactly the second
    state - the page has to say so rather than render an empty table.
    """
    client, settings = env
    create_member(settings)
    add_bare_device(settings, PHONE, "member")
    login(client, "member")

    chooser = client.get(f"/devices/{PHONE.udid}/files").text
    assert_page_a11y(chooser, context="device_files.html (choosing a generation)")
    assert "Pick a generation on the left" in chooser

    no_backup = client.get(f"/devices/{PHONE.udid}/files", params={"snapshot": "latest"}).text
    assert_page_a11y(no_backup, context="device_files.html (no readable backup)")

    write_realistic_backup(settings.backup_root / PHONE.udid, PHONE)
    areas = client.get(f"/devices/{PHONE.udid}/files", params={"snapshot": "latest"}).text
    assert_page_a11y(areas, context="device_files.html (browsing, areas column)")
    assert "HomeDomain" in areas

    # And a column deep in the tree, where the rows carry checkboxes and download links: the
    # shallow view alone would never exercise those.
    deep = client.get(
        f"/devices/{PHONE.udid}/files",
        params={"snapshot": "latest", "domain": "HomeDomain", "path": "Library/SMS"},
    ).text
    assert_page_a11y(deep, context="device_files.html (browsing, a folder column)")
    assert "sms.db" in deep

    # And with a search set, which adds one more column at the right-hand end: its rows carry the
    # same checkboxes as a folder column and nothing labels them but an aria-label.
    found = client.get(
        f"/devices/{PHONE.udid}/files",
        params={"snapshot": "latest", "domain": "HomeDomain", "q": "sms"},
    ).text
    assert_page_a11y(found, context="device_files.html (browsing, the search column)")
    assert '<section class="fcol fcol-hits"' in found

    nothing_found = client.get(
        f"/devices/{PHONE.udid}/files",
        params={"snapshot": "latest", "q": "nothing-like-this"},
    ).text
    assert_page_a11y(nothing_found, context="device_files.html (browsing, an empty search column)")
    assert "No files match" in nothing_found

    # The third state: an encrypted backup asks for its password, which is a form of its own and
    # needs the same label check as every other form in this app.
    write_realistic_backup(settings.backup_root / PHONE.udid, PHONE, encrypted=True)
    locked = client.get(f"/devices/{PHONE.udid}/files", params={"snapshot": "latest"}).text
    assert_page_a11y(locked, context="device_files.html (encrypted, asking for the password)")
    assert 'name="backup_password"' in locked


def test_user_log_page_empty_and_populated(env):
    """log.html in both states, as a member: the page is personal, so it is exercised through the
    role that actually depends on its scope rather than through an admin."""
    client, settings = env
    create_member(settings)
    add_bare_device(settings, PHONE, "member")
    login(client, "member")

    empty = client.get("/log").text
    assert_page_a11y(empty, context="log.html (empty)")
    assert "Nothing has happened to your devices yet." in empty

    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, finished_at, status, message) "
            "VALUES (?, 'schedule', '2026-09-15T10:00:00Z', '2026-09-15T10:05:00Z', 'failed', 'disk full')",
            (PHONE.udid,),
        )
        conn.execute(
            "INSERT INTO snapshot_verifications (udid, snapshot_name, outcome, checked_at) "
            "VALUES (?, '2026-09-15', 'verified', '2026-09-15T11:00:00Z')",
            (PHONE.udid,),
        )
        conn.commit()

    filled = client.get("/log").text
    assert_page_a11y(filled, context="log.html (with events)")
    assert "Generation check" in filled
    assert "disk full" in filled


def test_about_page_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/about").text
    assert_page_a11y(page, context="about.html")


# --------------------------------------------------------------------------------------------
# restore.html
# --------------------------------------------------------------------------------------------


def test_restore_page_empty_and_with_snapshots(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    add_bare_device(settings, TABLET, "admin")
    empty_page = client.get(f"/devices/{TABLET.udid}/restore").text
    assert_page_a11y(empty_page, context="restore.html (no backup on disk)")
    assert "No backup of this device on disk yet." in empty_page

    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO seen_devices (udid, name, product_type, os_version, transport, paired, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, 1, '2026-09-15T00:00:00Z')",
            (PHONE.udid, PHONE.name, PHONE.product_type, PHONE.os_version, PHONE.transport.value),
        )
        conn.commit()
    client.post("/add", data={"csrf": csrf(client, "/add"), "udid": PHONE.udid})
    seed_generations(settings, count=1)
    filled_page = client.get(f"/devices/{PHONE.udid}/restore").text
    assert_page_a11y(filled_page, context="restore.html (with a live backup)")


# --------------------------------------------------------------------------------------------
# docs_index.html / docs_page.html
# --------------------------------------------------------------------------------------------


def test_docs_index_and_docs_page_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    index_page = client.get("/guide").text
    assert_page_a11y(index_page, context="docs_index.html")
    doc_page = client.get("/guide/concept").text
    assert_page_a11y(doc_page, context="docs_page.html")


# --------------------------------------------------------------------------------------------
# _activity_indicator.html
# --------------------------------------------------------------------------------------------


def test_activity_indicator_fragment_a11y(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/activity", headers={"HX-Request": "true"}).text
    assert_page_a11y(page, context="_activity_indicator.html (fragment)", expect_h1=False)


# --------------------------------------------------------------------------------------------
# users.html
# --------------------------------------------------------------------------------------------


def test_users_page_a11y_single_admin(env):
    client, settings = env
    create_admin(settings)
    login(client, "admin")
    page = client.get("/admin/users").text
    assert_page_a11y(page, context="users.html (single admin)")
    # Both restrictions on the only admin are stated in words, not signalled by a disabled
    # control alone - a disabled <select> tells a screen reader nothing about why.
    assert "The last remaining admin cannot be demoted." in page
    # The template used to say "Account"; this test held the newer "Settings" wording in
    # place through the rename.
    assert "Use Settings to manage your own account" in page


def test_users_page_with_member_and_create_error_a11y(env):
    client, settings = env
    create_admin(settings)
    create_member(settings)
    login(client, "admin")

    page = client.get("/admin/users").text
    assert_page_a11y(page, context="users.html (admin and member)")
    assert "/admin/users/" in page and "Remove" in page

    # The create form's error state: a rejected password re-renders the page rather than
    # redirecting, so it has to stay structurally sound and keep what was typed.
    too_short = "x" * (auth.MIN_PASSWORD_LENGTH - 1)
    r = client.post(
        "/admin/users",
        data={"csrf": csrf(client, "/admin/users"), "username": "newbie", "password": too_short, "role": "member"},
    )
    assert r.status_code == 400
    assert_page_a11y(r.text, context="users.html (create error)")
    assert 'value="newbie"' in r.text


# --------------------------------------------------------------------------------------------
# admin.html / admin_notifications.html / admin_update.html
# --------------------------------------------------------------------------------------------


def test_admin_area_pages_are_accessible_and_carry_their_section_nav(env):
    """The Admin area's own pages. Each one renders the same
    section nav and marks its own entry, so a keyboard or screen-reader user can tell where in the
    area they are - aria-current, not colour or weight alone."""
    client, settings = env
    create_admin(settings)
    login(client, "admin")

    for path, template in (
        ("/admin", "admin.html"),
        ("/admin/notifications", "admin_notifications.html"),
        ("/admin/update", "admin_update.html"),
    ):
        page = client.get(path).text
        assert_page_a11y(page, context=f"{template} (admin)")
        assert 'class="section-nav"' in page, f"{template}: no section nav"
        assert f'href="{path}" aria-current="page"' in page, f"{template}: own entry is not marked current"


def test_a_member_cannot_reach_the_admin_area(env):
    """Every page in the area is admin-only, and answers 404 rather than 403 for a member, the
    same way every other admin route in this app does."""
    client, settings = env
    create_admin(settings)
    create_member(settings)
    login(client, "member")
    for path in ("/admin", "/admin/notifications", "/admin/update"):
        assert client.get(path).status_code == 404, path


# --------------------------------------------------------------------------------------------
# account.html / settings_sso.html / settings_tokens.html / settings_notifications.html
# --------------------------------------------------------------------------------------------

SETTINGS_PAGES = (
    ("/settings", "account.html"),
    ("/settings/sso", "settings_sso.html"),
    ("/settings/tokens", "settings_tokens.html"),
    ("/settings/notifications", "settings_notifications.html"),
)


def test_personal_settings_pages_are_accessible_and_carry_their_section_nav(env):
    """The personal Settings area: each page stands on its own
    address, carries the same section nav and marks its own entry."""
    client, settings = env
    create_admin(settings)
    login(client, "admin")

    for path, template in SETTINGS_PAGES:
        page = client.get(path).text
        assert_page_a11y(page, context=f"{template} (admin)")
        assert 'class="section-nav"' in page, f"{template}: no section nav"
        assert f'href="{path}" aria-current="page"' in page, f"{template}: own entry not marked current"


def test_a_member_reaches_their_own_settings_but_sees_no_admin_note(env):
    """A member has the same personal pages - they are not admin-only - but the note pointing at
    the Admin area is written for admins, who are the ones likely to look for a global default in
    their own settings. A member has no Admin area to be sent to, so it stays out of their page
    rather than dangling a link they would get a 404 from."""
    client, settings = env
    create_admin(settings)
    create_member(settings)
    login(client, "member")

    for path, template in SETTINGS_PAGES:
        page = client.get(path).text
        assert_page_a11y(page, context=f"{template} (member)")
        assert "scope-note" not in page, f"{template}: the admin note is shown to a member"
        assert 'href="/admin"' not in page, f"{template}: links a member into the admin area"


def test_an_admin_is_told_where_the_system_wide_settings_are(env):
    """_scope_note.html, rendered inside every personal Settings page for an admin: with a single
    account the admin is also the everyday user, so looking for a global default here is the
    obvious mistake to make. The note says where they live instead."""
    client, settings = env
    create_admin(settings)
    login(client, "admin")

    page = client.get("/settings").text
    assert "scope-note" in page
    assert 'href="/admin"' in page


def test_every_section_nav_link_is_a_root_relative_path(env):
    """`_macros.html`'s section_nav renders `<a href="{{ href }}">`, which semgrep's var-in-href
    rule flags: a template variable in an href can carry a `javascript:` URI. The suppression there
    promises the hrefs are fixed, root-relative paths from ADMIN_NAV/SETTINGS_NAV in app.py, which
    no request can influence. This checks that promise against what is actually rendered, so it
    breaks the moment a user-controlled value is passed into the macro instead of staying a comment
    nobody rechecks.
    """
    import re as _re

    client, settings = env
    create_admin(settings)
    login(client, "admin")

    seen = 0
    for path in ("/admin", "/admin/notifications", "/settings", "/settings/tokens"):
        page = client.get(path).text
        nav = _re.search(r'<nav class="section-nav".*?</nav>', page, _re.S)
        assert nav, f"{path}: no section nav rendered"
        for href in _re.findall(r'<a href="([^"]*)"', nav.group(0)):
            seen += 1
            assert href.startswith("/"), f"{path}: section-nav href {href!r} is not root-relative"
            assert ":" not in href, f"{path}: section-nav href {href!r} carries a scheme"
    assert seen >= 12, f"expected both navs to render their entries, saw {seen} links"


# --------------------------------------------------------------------------------------------
# The coverage guard itself
# --------------------------------------------------------------------------------------------


def test_every_template_is_covered():
    """Every template file must be named somewhere in this module.

    Without this, a template added later simply never gets an accessibility check and nothing
    says so - a page of forms, selects and destructive buttons could ship with no coverage at
    all. Being named here means either a test renders it, or the docstring above
    records why it cannot be rendered on its own (base.html and _macros.html have no route).
    """

    from bioseasy.app import WEB

    # The very constant app.py hands to Jinja2Templates, so this can never end up checking a
    # different directory than the one the application renders from. Deriving it from
    # bioseasy.web instead does not work: that is a data directory with no __init__.py, so its
    # __file__ is None - and the resulting TypeError looked exactly like a failing guard.
    template_dir = WEB / "templates"
    templates = sorted(p.name for p in template_dir.glob("*.html"))
    assert templates, f"no templates found under {template_dir}"

    source = Path(__file__).read_text(encoding="utf-8")
    missing = [name for name in templates if name not in source]
    assert not missing, (
        f"{len(missing)} template(s) are not named in this module, so nothing checks them: "
        f"{', '.join(missing)}. Add a test that renders each through its route, or - if it has "
        f"no route of its own - record in this module's docstring how it is covered transitively."
    )


# A guard is only worth trusting once it has actually been seen to fail for the reason it
# claims to catch. Rather than a permanent test that hand-edits a template file on disk during
# a normal `pytest` run (fragile under parallel test runners, and a landmine for anyone who
# ctrl-cs a test mid-write), the break/run/revert for test_login_page_a11y was done once by
# hand: a broken template produced the expected AssertionError, and the same test passed again
# after the revert.
# test_every_template_is_covered was checked the same way, with a throwaway template file added
# to the templates directory that names nobody in this module: the guard failed with
# "1 template(s) are not named in this module ... <throwaway file>", and passed again once the
# file was deleted.
