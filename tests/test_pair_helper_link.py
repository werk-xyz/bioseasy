# SPDX-License-Identifier: GPL-3.0-or-later
"""The pairing code page offers the no-install macOS helper app before the uv command.

See docs/pairing.md ("Pair from my computer") and helper/README.md.
"""

import re
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"
REPO_ROOT = Path(__file__).resolve().parent.parent


def make_client(tmp_path, helper_url_macos=None, helper_url_linux=None, helper_url_windows=None):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(
        data,
        root,
        "demo",
        "test-secret",
        False,
        3600,
        schedule_minutes=0,
        helper_url_macos=helper_url_macos,
        helper_url_linux=helper_url_linux,
        helper_url_windows=helper_url_windows,
    )
    client = TestClient(create_app(settings, DemoEngine(step_seconds=0)), follow_redirects=False)
    return client, settings, data


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client):
    client.post("/login", data={"csrf": csrf(client, "/login"), "username": "admin", "password": PASSWORD})


def create_code(client) -> str:
    r = client.post("/add/pair-code", data={"csrf": csrf(client, "/add")})
    assert r.status_code == 303
    return r.headers["location"].rsplit("/", 1)[-1]


def get_pair_code_page(client, data_dir, helper_url_macos=None, helper_url_linux=None):
    """Signs an admin in, creates a pairing code, and returns the rendered code page."""
    with closing(db.connect(data_dir / "bioseasy.db")) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client)
    code = create_code(client)
    return code, client.get(f"/add/pair-code/{code}")


@pytest.fixture
def helper_url():
    return "https://example.test/releases/helper-v1.0.0/bioseasy-pair-macos-arm64.zip"


@pytest.fixture
def helper_url_linux():
    return "https://example.test/releases/helper-v1.0.0/bioseasy-pair-linux-x64"


def test_helper_section_shown_with_download_link_when_setting_is_set(tmp_path, helper_url):
    client, _, data_dir = make_client(tmp_path, helper_url_macos=helper_url)
    with client:
        code, page = get_pair_code_page(client, data_dir, helper_url_macos=helper_url)
    assert page.status_code == 200
    assert "Use the bioseasy pairing app" in page.text
    assert f'href="{helper_url}"' in page.text
    assert "Privacy" in page.text and "Security" in page.text
    # Helper app section comes first, the uv command second.
    helper_pos = page.text.index("Use the bioseasy pairing app")
    uv_pos = page.text.index("Or run one command")
    assert helper_pos < uv_pos
    assert code in page.text


def test_helper_section_shown_without_link_when_setting_is_unset(tmp_path):
    client, _, data_dir = make_client(tmp_path, helper_url_macos=None)
    with client:
        code, page = get_pair_code_page(client, data_dir)
    assert page.status_code == 200
    assert "Use the bioseasy pairing app" in page.text
    assert "helper/" in page.text
    assert "Not available on this server" in page.text
    # No download link/steps when nothing is configured.
    section = page.text.split("Or run one command")[0].split("Use the bioseasy pairing app")[1]
    assert "<a href=" not in section
    assert code in page.text


def test_linux_row_shown_with_download_link_when_setting_is_set(tmp_path, helper_url_linux):
    client, _, data_dir = make_client(tmp_path, helper_url_linux=helper_url_linux)
    with client:
        code, page = get_pair_code_page(client, data_dir, helper_url_linux=helper_url_linux)
    assert page.status_code == 200
    assert "Linux (x64)" in page.text
    assert f'href="{helper_url_linux}"' in page.text
    assert "usbmuxd" in page.text
    assert code in page.text


def test_both_platform_links_shown_when_both_are_set(tmp_path, helper_url, helper_url_linux):
    client, _, data_dir = make_client(tmp_path, helper_url_macos=helper_url, helper_url_linux=helper_url_linux)
    with client:
        code, page = get_pair_code_page(client, data_dir)
    assert page.status_code == 200
    assert f'href="{helper_url}"' in page.text
    assert f'href="{helper_url_linux}"' in page.text
    assert code in page.text


def test_windows_row_links_its_download_when_set(tmp_path):
    """Windows is built by its own runner (PyInstaller cannot cross-build, and
    the Windows runner builds it natively), so it is a platform like the other two now."""
    url = "https://example.test/releases/helper-v1.0.0/bioseasy-pair-windows-x64.exe"
    client, _, data_dir = make_client(tmp_path, helper_url_windows=url)
    with client:
        _code, page = get_pair_code_page(client, data_dir)
    windows_row = page.text.split("Windows (x64)")[1].split("</tr>")[0]
    assert f'href="{url}"' in windows_row
    assert "No download is configured yet" not in page.text


def test_windows_row_is_never_a_dead_link_when_unset(tmp_path, helper_url, helper_url_linux):
    client, _, data_dir = make_client(tmp_path, helper_url_macos=helper_url, helper_url_linux=helper_url_linux)
    with client:
        _code, page = get_pair_code_page(client, data_dir)
    windows_row = page.text.split("Windows (x64)")[1].split("</tr>")[0]
    assert "Not available on this server" in windows_row
    assert "<a href=" not in windows_row


def test_address_and_code_shown_in_both_cases(tmp_path, helper_url):
    for i, helper in enumerate((helper_url, None)):
        base = tmp_path / f"case-{i}"
        base.mkdir()
        client, _, data_dir = make_client(base, helper_url_macos=helper)
        with client:
            code, page = get_pair_code_page(client, data_dir, helper_url_macos=helper)
        assert code in page.text
        # base_url is shown as the address to type.
        assert "testserver" in page.text


def test_uv_command_still_present(tmp_path, helper_url):
    client, _, data_dir = make_client(tmp_path, helper_url_macos=helper_url)
    with client:
        code, page = get_pair_code_page(client, data_dir, helper_url_macos=helper_url)
    assert "uv run" in page.text
    assert f"/pair/{code}/bioseasy-pair.py" in page.text


def test_no_hardcoded_release_package_url_in_src():
    hits = []
    for path in (REPO_ROOT / "src").rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "example.test/releases" in text.lower():
            hits.append(path)
    assert hits == [], f"src/ must not hard-code the release download URL, found in: {hits}"


def test_an_expired_code_says_so_and_offers_a_new_one(tmp_path):
    """A code is valid for ten minutes. When it runs out, the page must say so and point at a new
    one - not leave a dead code on screen that fails only when somebody has already unlocked their
    device and tapped Trust for nothing."""
    client, settings, data_dir = make_client(tmp_path)
    with client:
        code, page = get_pair_code_page(client, data_dir)
        assert "expired" not in page.text.lower()
        with closing(db.connect(data_dir / "bioseasy.db")) as conn:
            conn.execute("UPDATE pairing_codes SET expires_at = '2020-01-01T00:00:00Z'")
            conn.commit()
        after = client.get(f"/add/pair-code/{code}")
        assert "This code expired before it was used." in after.text
        assert 'href="/add"' in after.text
        # And the poll stops: a fragment that keeps asking would never change its answer.
        status = client.get(f"/add/pair-code/{code}/status")
        assert "This code expired before it was used." in status.text
        assert "hx-trigger" not in status.text
