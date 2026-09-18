# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from bioseasy.config import load


def _env(tmp_path, **overrides) -> dict[str, str]:
    env = {"BIOSEASY_DATA_DIR": str(tmp_path)}
    env.update(overrides)
    return env


def test_revision_env_var_is_read_through(tmp_path):
    settings = load(_env(tmp_path, BIOSEASY_REVISION="a1b2c3d4e5f6"))
    assert settings.revision == "a1b2c3d4e5f6"


def test_revision_defaults_to_none_when_unset(tmp_path):
    settings = load(_env(tmp_path))
    assert settings.revision is None


@pytest.mark.parametrize("value", ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.org/app.zip"])
def test_helper_download_url_must_be_http_or_https(tmp_path, value):
    with pytest.raises(SystemExit, match="BIOSEASY_HELPER_URL_MACOS"):
        load(_env(tmp_path, BIOSEASY_HELPER_URL_MACOS=value))


def test_helper_download_url_accepts_https(tmp_path):
    url = "https://example.org/bioseasy-pair.zip"
    assert load(_env(tmp_path, BIOSEASY_HELPER_URL_MACOS=url)).helper_url_macos == url


@pytest.mark.parametrize("value", ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.org/app"])
def test_linux_helper_download_url_must_be_http_or_https(tmp_path, value):
    with pytest.raises(SystemExit, match="BIOSEASY_HELPER_URL_LINUX"):
        load(_env(tmp_path, BIOSEASY_HELPER_URL_LINUX=value))


def test_linux_helper_download_url_accepts_https(tmp_path):
    url = "https://example.org/bioseasy-pair-linux-x64"
    assert load(_env(tmp_path, BIOSEASY_HELPER_URL_LINUX=url)).helper_url_linux == url


def test_linux_helper_download_url_defaults_to_none(tmp_path):
    assert load(_env(tmp_path)).helper_url_linux is None


# Windows goes through the same check: the value ends up in an href like the other two.
@pytest.mark.parametrize("value", ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.org/app"])
def test_windows_helper_download_url_must_be_http_or_https(tmp_path, value):
    with pytest.raises(SystemExit, match="BIOSEASY_HELPER_URL_WINDOWS"):
        load(_env(tmp_path, BIOSEASY_HELPER_URL_WINDOWS=value))


def test_windows_helper_download_url_accepts_https_and_defaults_to_none(tmp_path):
    url = "https://example.org/bioseasy-pair-windows-x64.exe"
    assert load(_env(tmp_path, BIOSEASY_HELPER_URL_WINDOWS=url)).helper_url_windows == url
    assert load(_env(tmp_path)).helper_url_windows is None


# Secure cookies default to true. Guarded in both directions, because either way round is a
# security-relevant change that would otherwise be invisible in a diff of one string literal.
def test_secure_cookies_default_to_true(tmp_path):
    assert load(_env(tmp_path)).secure_cookies is True


def test_secure_cookies_can_be_switched_off_for_a_plain_http_installation(tmp_path):
    assert load(_env(tmp_path, BIOSEASY_SECURE_COOKIES="false")).secure_cookies is False
