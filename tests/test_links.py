# SPDX-License-Identifier: GPL-3.0-or-later
"""Every internal link has to lead somewhere.

The recurring defect in this repository is a statement that no longer matches reality, and a link
is the cheapest kind to leave behind: a route gets renamed, the template that points at it keeps
rendering, and nothing goes red until someone clicks. The same holds for the docs, where a page
can be renamed while three other pages still name the old file.

What it does not cover, measured once: 126 of the 141 link attributes in the
templates. The other fifteen are external URLs or values that are one whole Jinja expression
(`{{ base_url }}/connectors/email`, `{{ '/add' if d.paired else '/add/pair' }}`), where the
path only exists at render time. They are skipped, not silently passed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.routing import Mount

from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "src" / "bioseasy" / "web" / "templates"
STATIC = ROOT / "src" / "bioseasy" / "web" / "static"
DOCS = ROOT / "docs"

LINK_ATTRIBUTE = re.compile(r'(?:href|action|hx-get|hx-post)="([^"]*)"')
JINJA_EXPRESSION = re.compile(r"\{\{.*?\}\}")
JINJA_BLOCK = re.compile(r"\{%.*?%\}")
# A Jinja expression can stand for any single path segment, so it is normalised to this marker and
# then matched against a route's own {parameter} segments.
ANY = "\x00"


def route_paths(app) -> set[str]:
    """Every path the app serves, the JSON sub-application's own routes included."""
    found: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        if isinstance(route, Mount):
            found.add(path)
            found.update(path + sub.path for sub in getattr(route.app, "routes", []) if hasattr(sub, "path"))
        elif path:
            found.add(path)
    return found


def normalise(link: str) -> str | None:
    """The comparable shape of a link, or None when it is not ours to check."""
    link = JINJA_BLOCK.sub("", link).strip()
    if not link.startswith("/"):
        return None  # external, mailto, a bare fragment, or a whole-value Jinja expression
    link = link.split("?", 1)[0].split("#", 1)[0]
    return JINJA_EXPRESSION.sub(ANY, link).rstrip("/") or "/"


def matches(link: str, route: str) -> bool:
    link_parts, route_parts = link.split("/"), (route.rstrip("/") or "/").split("/")
    if len(link_parts) != len(route_parts):
        return False
    return all(
        left == right or left == ANY or right.startswith("{")
        for left, right in zip(link_parts, route_parts, strict=True)
    )


def template_links() -> list[tuple[Path, str]]:
    return [
        (path, link) for path in sorted(TEMPLATES.rglob("*.html")) for link in LINK_ATTRIBUTE.findall(path.read_text())
    ]


@pytest.fixture
def app(tmp_path):
    data, root = tmp_path / "data", tmp_path / "backups"
    data.mkdir()
    root.mkdir()
    settings = Settings(data, root, "demo", "test-secret", False, 3600)
    return create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True)


def test_every_internal_link_in_a_template_leads_to_a_route_or_a_file(app):
    routes = {r.rstrip("/") or "/" for r in route_paths(app)}
    dead: list[str] = []
    for path, raw in template_links():
        link = normalise(raw)
        if link is None:
            continue
        if link.startswith("/static/"):
            if not (STATIC / link[len("/static/") :]).exists():
                dead.append(f"{path.name}: {raw} (no such file under web/static)")
            continue
        if not any(matches(link, route) for route in routes):
            dead.append(f"{path.name}: {raw} (no route serves this)")
    assert not dead, "links pointing nowhere: " + "; ".join(dead)


DOC_LINK = re.compile(r"\]\(([^)\s]+\.md)(?:#[^)\s]*)?\)")


def test_every_link_between_documents_resolves():
    dead = []
    for path in sorted(DOCS.rglob("*.md")) + [ROOT / "README.md", ROOT / "CHANGELOG.md"]:
        for target in DOC_LINK.findall(path.read_text()):
            if target.startswith(("http://", "https://")):
                continue
            if not (path.parent / target).resolve().is_file():
                dead.append(f"{path.name} -> {target}")
    assert not dead, "document links pointing nowhere: " + "; ".join(dead)


# --- Anchors: (file.md#anchor) and (#anchor) must land on a heading that really exists. ---

ANCHOR_LINK = re.compile(r"\]\(([^)\s#]+\.md)?(#[^)\s]*)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE = re.compile(r"^(```|~~~)")
NOT_SLUG_CHAR = re.compile(r"[^\w\s-]")
WHITESPACE = re.compile(r"\s+")


def markdown_headings(path: Path) -> list[str]:
    """Heading text in document order, skipping anything inside a fenced code block (a shell
    comment starting with '#' is not a heading)."""
    headings = []
    in_fence = False
    for line in path.read_text().splitlines():
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        found = HEADING.match(line)
        if found:
            headings.append(found.group(2))
    return headings


def slugify(heading: str) -> str:
    """GitHub's own heading-to-anchor rule: lowercase, strip everything but word characters,
    spaces and hyphens, then turn spaces into hyphens. Checked against the anchors already in use
    in docs/install.md and docs/troubleshooting.md (e.g. "## 1. Requirements" -> "1-requirements",
    '## A run ended as "Not confirmed"' -> "a-run-ended-as-not-confirmed")."""
    text = heading.strip().lower()
    text = re.sub(r"[`*_]", "", text)
    text = NOT_SLUG_CHAR.sub("", text)
    text = WHITESPACE.sub("-", text).strip("-")
    return text


def anchors_for(path: Path) -> set[str]:
    """Every anchor a Markdown renderer would generate for this file's headings, duplicates
    disambiguated the way GitHub does it (a second "foo" heading becomes "foo-1")."""
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    for heading in markdown_headings(path):
        base = slugify(heading)
        count = seen.get(base, 0)
        seen[base] = count + 1
        slugs.add(base if count == 0 else f"{base}-{count}")
    return slugs


def test_every_anchor_link_points_to_a_heading_that_exists():
    dead = []
    checked = 0
    for path in sorted(DOCS.rglob("*.md")) + [ROOT / "README.md", ROOT / "CHANGELOG.md"]:
        for file_target, anchor in ANCHOR_LINK.findall(path.read_text()):
            anchor_name = anchor[1:]  # drop the leading '#'
            if not anchor_name:
                continue  # a bare "#" is not a link to a heading
            checked += 1
            target_path = (path.parent / file_target).resolve() if file_target else path
            if not target_path.is_file():
                dead.append(f"{path.name} -> {file_target or ''}#{anchor_name} (no such document)")
                continue
            if anchor_name not in anchors_for(target_path):
                dead.append(f"{path.name} -> {file_target or ''}#{anchor_name} (no such heading)")
    # Measured once: this is all there is. A handful of cases is not much of a sample,
    # so a change that breaks anchor links elsewhere may still slip through unseen.
    assert checked, "no anchor links found at all - nothing for this guard to check"
    assert not dead, "anchor links pointing at a heading that does not exist: " + "; ".join(dead)


@pytest.mark.parametrize(
    ("heading", "expected"),
    [
        ("1. Requirements", "1-requirements"),
        ('A run ended as "Not confirmed"', "a-run-ended-as-not-confirmed"),
        ("(c) Device in another network or subnet", "c-device-in-another-network-or-subnet"),
        ("First sign-in", "first-sign-in"),
        ("5. Storage", "5-storage"),
    ],
)
def test_slugify_matches_the_anchors_already_used_in_the_docs(heading, expected):
    """The real headings these link targets were written against, so the algorithm is checked
    against reality rather than an assumption about how it works."""
    assert slugify(heading) == expected


@pytest.mark.parametrize(
    ("link", "route", "expected"),
    [
        ("/devices/\x00/files", "/devices/{udid}/files", True),
        ("/devices/\x00/file", "/devices/{udid}/files", False),
        ("/devices/\x00", "/devices/{udid}/files", False),
        ("/admin/storage/browse", "/admin/storage/browse", True),
        ("/", "/", True),
    ],
)
def test_matches_compares_segment_by_segment(link, route, expected):
    """The matcher itself, so a guard that accepts everything cannot pass unnoticed."""
    assert matches(link, route) is expected
