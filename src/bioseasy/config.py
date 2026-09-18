# SPDX-License-Identifier: GPL-3.0-or-later
"""Runtime configuration from BIOSEASY_* environment variables.

Only what must be known before the app starts lives here. Everything a user changes in the web
UI is stored in the database instead.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    backup_root: Path
    engine: str
    secret_key: str
    secure_cookies: bool
    session_max_age: int
    timezone: str = "UTC"
    schedule_minutes: int = 5
    demo_seed: bool = False
    demo_autologin: bool = False
    # OIDC fields go last with defaults so existing positional Settings(...) calls (tests
    # included) keep working unchanged.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_name: str = "single sign-on"
    # Scopes asked of the provider. Configurable because the group claim lives behind a different
    # scope per provider: authentik ships group membership in `profile`, Keycloak needs `roles`.
    oidc_scopes: str = "openid profile email"
    # Where group or role membership arrives, as a claim name or a dotted path into a nested claim
    # (Keycloak: realm_access.roles). Only read when oidc_required_group is set.
    oidc_groups_claim: str = "groups"
    # Membership required for signing in and for self-registration; unset means no such check.
    # Compared case-insensitively against each value of the claim, which is a name at authentik
    # and Keycloak and a group GUID at Entra ID.
    oidc_required_group: str | None = None
    # An identity that matches no account creates one, always as a member (oidc.py). Off by
    # default: switching it on means everyone the provider lets in has an account here.
    oidc_allow_registration: bool = False
    # Only match an address the provider marks as verified. On by default and only worth turning
    # off for a provider that never sends `email_verified` at all - see oidc.claimed_email.
    oidc_require_verified_email: bool = True
    base_url: str | None = None
    # Baked into the image at build time via a Dockerfile ARG (BIOSEASY_REVISION); empty locally
    # and whenever the build pipeline did not pass one, in which case the footer omits it
    # entirely rather than showing a blank or fabricated revision.
    revision: str | None = None
    # Where the no-install helper app (helper/README.md) can be downloaded, per platform. Unset by
    # default: this project hosts nothing and hard-codes no build's URL anywhere in code.
    helper_url_macos: str | None = None
    helper_url_linux: str | None = None
    helper_url_windows: str | None = None
    # Where the rendered docs/ tree lives (/guide, /guide/<page>). Unset by default: docs.py falls
    # back to the docs/ folder next to the installed package (docs.default_docs_dir()), which is
    # /app/docs in the image (Dockerfile) and the real docs/ folder in an editable dev checkout.
    # Overridable so tests can point it at a small fixture tree instead.
    docs_dir: Path | None = None

    @property
    def oidc_enabled(self) -> bool:
        # The client secret is deliberately not required here: PKCE lets a public client sign
        # in without one, and a provider that needs it will simply fail the token exchange.
        return bool(self.oidc_issuer and self.oidc_client_id and self.base_url)


def _secret_key(data_dir: Path, configured: str | None) -> str:
    if configured:
        return configured
    # Generated once and kept in the data volume, so sessions survive restarts without the
    # user having to invent a key.
    path = data_dir / "secret_key"
    if path.is_file():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.touch(mode=0o600)
    path.write_text(key)
    return key


def load(env: dict[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    data_dir = Path(env.get("BIOSEASY_DATA_DIR", "/data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        data_dir=data_dir,
        backup_root=Path(env.get("BIOSEASY_BACKUP_ROOT", "/backups")),
        engine=env.get("BIOSEASY_ENGINE", "pymobiledevice3"),
        secret_key=_secret_key(data_dir, env.get("BIOSEASY_SECRET_KEY")),
        # Secure by default: the documented setup puts bioseasy behind an HTTPS reverse proxy, so
        # the session cookie carries the Secure flag unless someone deliberately opts out. The
        # cost is deliberate and belongs in the install docs: served over plain HTTP, the browser
        # then refuses to store the session cookie and sign-in appears to do nothing, until
        # BIOSEASY_SECURE_COOKIES=false is set.
        secure_cookies=env.get("BIOSEASY_SECURE_COOKIES", "true").lower() == "true",
        session_max_age=int(env.get("BIOSEASY_SESSION_HOURS", "12")) * 3600,
        # TZ is the usual container convention; time windows are local times.
        timezone=env.get("BIOSEASY_TIMEZONE") or env.get("TZ") or "UTC",
        schedule_minutes=int(env.get("BIOSEASY_SCHEDULE_MINUTES", "5")),
        # Only honoured together with the demo engine; see demo_seed.py.
        demo_seed=env.get("BIOSEASY_DEMO_SEED", "false").lower() == "true",
        # Sign every visitor in as the demo user; only with the demo engine and demo seed.
        demo_autologin=env.get("BIOSEASY_DEMO_AUTOLOGIN", "false").lower() == "true",
        oidc_issuer=env.get("BIOSEASY_OIDC_ISSUER") or None,
        oidc_client_id=env.get("BIOSEASY_OIDC_CLIENT_ID") or None,
        oidc_client_secret=env.get("BIOSEASY_OIDC_CLIENT_SECRET") or None,
        oidc_name=env.get("BIOSEASY_OIDC_NAME") or "single sign-on",
        oidc_scopes=env.get("BIOSEASY_OIDC_SCOPES") or "openid profile email",
        oidc_groups_claim=env.get("BIOSEASY_OIDC_GROUPS_CLAIM") or "groups",
        oidc_required_group=env.get("BIOSEASY_OIDC_REQUIRED_GROUP") or None,
        oidc_allow_registration=env.get("BIOSEASY_OIDC_ALLOW_REGISTRATION", "false").lower() == "true",
        oidc_require_verified_email=env.get("BIOSEASY_OIDC_REQUIRE_VERIFIED_EMAIL", "true").lower() == "true",
        base_url=env.get("BIOSEASY_BASE_URL") or None,
        revision=env.get("BIOSEASY_REVISION") or None,
        helper_url_macos=_http_url(env.get("BIOSEASY_HELPER_URL_MACOS"), "BIOSEASY_HELPER_URL_MACOS"),
        helper_url_linux=_http_url(env.get("BIOSEASY_HELPER_URL_LINUX"), "BIOSEASY_HELPER_URL_LINUX"),
        helper_url_windows=_http_url(env.get("BIOSEASY_HELPER_URL_WINDOWS"), "BIOSEASY_HELPER_URL_WINDOWS"),
        docs_dir=Path(env["BIOSEASY_DOCS_DIR"]) if env.get("BIOSEASY_DOCS_DIR") else None,
    )


def _http_url(value: str | None, name: str) -> str | None:
    """An optional http(s) URL from the environment; it ends up in an href, so javascript: and
    other schemes stop startup instead of reaching a page."""
    if not value:
        return None
    if not (value.startswith("https://") or value.startswith("http://")):
        raise SystemExit(f"{name} must start with https:// or http://")
    return value
