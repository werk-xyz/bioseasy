# SPDX-License-Identifier: GPL-3.0-or-later
"""Every URL the browser is told to call must be a route the app actually has.

A route moved from `/account/...` to `/settings/...` and the push-subscription script kept posting
to the old path: the server answered 404, the browser said "could not save", and browser
notifications could not be switched on at all - while every server-side test stayed green,
because none of them ran the JavaScript. So the literal URLs in the static scripts and in the
templates' forms and htmx attributes are checked against the app's own routing table.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.routing import Match

from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

WEB = Path(__file__).resolve().parents[1] / "src" / "bioseasy" / "web"

# A literal, absolute, same-site path: starts with "/", no template expression inside it.
_JS_CALL = re.compile(r"""fetch\(\s*["'`](/[^"'`${}]*)["'`]""")
_FORM = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ACTION = re.compile(r"""\baction="(/[^"{}]*)\"""")
_METHOD = re.compile(r"""\bmethod="(\w+)\"""", re.IGNORECASE)
_HTMX = re.compile(r"""\bhx-(get|post|delete)="(/[^"{}]*)\"""")


def _urls() -> list[tuple[str, str, str]]:
    found = []
    for path in sorted(WEB.rglob("*.js")):
        for url in _JS_CALL.findall(path.read_text()):
            found.append((str(path.relative_to(WEB)), url, "POST"))
    for path in sorted(WEB.rglob("*.html")):
        text = path.read_text()
        for tag in _FORM.findall(text):
            action = _ACTION.search(tag)
            if action:
                method = _METHOD.search(tag)
                # An HTML form without a method attribute submits with GET.
                verb = method.group(1).upper() if method else "GET"
                found.append((str(path.relative_to(WEB)), action.group(1).split("?")[0], verb))
        for verb, url in _HTMX.findall(text):
            found.append((str(path.relative_to(WEB)), url.split("?")[0], verb.upper()))
    return found


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    data = tmp_path_factory.mktemp("data")
    backups = tmp_path_factory.mktemp("backups")
    return create_app(Settings(data, backups, "demo", "test-secret", False, 3600), DemoEngine(step_seconds=0))


def _matches(app, url: str, method: str) -> bool:
    scope = {"type": "http", "path": url, "method": method, "root_path": ""}
    return any(route.matches(scope)[0] == Match.FULL for route in app.router.routes)


def test_the_scan_finds_the_urls_it_is_meant_to_check():
    """A scan that finds nothing would pass forever; make sure it sees the known callers."""
    urls = {url for _file, url, _method in _urls()}
    assert "/settings/notifications/push/subscribe" in urls
    assert "/login" in urls


@pytest.mark.parametrize(("source", "url", "method"), _urls())
def test_every_url_the_browser_calls_is_a_real_route(app, source, url, method):
    assert _matches(app, url, method), f"{source} calls {method} {url}, which no route serves"
