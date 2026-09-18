# SPDX-License-Identifier: GPL-3.0-or-later
"""Screen readers hear backup phase changes through one persistent live region on the device page."""

import re

from test_web import PHONE, conn_for, env, make_admin_with_device  # noqa: F401 (env is a fixture)


def _announce(html):
    return re.search(r'id="status"[^>]*data-announce="([^"]*)"', html).group(1)


def test_device_page_has_one_persistent_live_region_outside_the_polled_section(env):  # noqa: F811
    client, settings = env
    make_admin_with_device(client, settings)
    page = client.get(f"/devices/{PHONE.udid}").text
    assert page.count('aria-live="polite"') == 1
    region = page.index('id="status-announce"')
    assert region > page.index("</section>", page.index('id="status"'))
    assert _announce(page) == "No backup running."


def test_polled_status_carries_the_phase_sentence_without_the_percentage(env):  # noqa: F811
    client, settings = env
    make_admin_with_device(client, settings)
    with conn_for(settings) as conn:
        conn.execute(
            "INSERT INTO runs (udid, trigger, started_at, status, phase, percent) "
            "VALUES (?, 'manual', '2026-09-15T12:00:00Z', 'running', 'waiting_for_passcode', NULL)",
            (PHONE.udid,),
        )
    assert _announce(client.get(f"/devices/{PHONE.udid}/status").text) == "Unlock the device and enter its passcode."
    with conn_for(settings) as conn:
        conn.execute("UPDATE runs SET phase = 'transferring', percent = 42 WHERE udid = ?", (PHONE.udid,))
    assert _announce(client.get(f"/devices/{PHONE.udid}/status").text) == "Transferring the backup."
