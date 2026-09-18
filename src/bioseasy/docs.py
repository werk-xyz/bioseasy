# SPDX-License-Identifier: GPL-3.0-or-later
"""Renders the project's own `docs/*.md` files inside the web UI (`/guide`, `/guide/<page>`; not
`/docs`, which the app already reserves for "no interactive OpenAPI explorer here", see app.py).

Deliberately not a general file server: `PAGES` is a closed allowlist of slug -> filename, read
once at import time. A route only ever opens `docs_dir() / PAGES[slug]` after `slug` has been
found as a literal key in that dict, so no request-supplied string ever reaches the filesystem as
a path component; there is nothing to traverse. `_within` below is a second, defensive check
(never expected to trip, given the above), kept because a path check that never ran red proves
nothing on its own otherwise (see CONTRIBUTING.md, "a test that has never failed proves nothing").

Raw HTML in the source is neutralised before conversion, not filtered from the rendered output:
the library does not disable inline HTML passthrough on its own since its normal (non-web) use
case is trusted document authoring, and this project would rather show a literal "<script>" as
text than decide, case by case, which tags are safe. The neutralising step (`_escape_tags`) only
escapes substrings shaped like an actual HTML tag ("<", then a letter or "/", up to the matching
">"); a plain "<" or ">" that is not part of a tag is left alone, because blanket-escaping every
angle bracket (an earlier version of this module did exactly that) also breaks Markdown's own use
of a leading ">" for blockquotes, which docs/install.md relies on for its "Status" note and its
sqlite.org quote. Since docs/ is a fixed set of files shipped in the image, this is defence in
depth against a future editing mistake, not a defence against a live attacker.

Not every file in docs/ is listed here. `design.md` and `building.md` are read and kept out on
purpose; `docs/README.md` is the map that says which document is for whom:
- `design.md` is the CSS token and type-scale reference for whoever edits `static/app.css`;
  nothing in it helps a user back up a phone.
- `building.md` is for contributors working on this project, not for an end user operating it.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from pathlib import Path

import markdown as _markdown
from markupsafe import Markup

# slug -> (filename in docs/, title shown in the nav and the page). Order here is nav order.
PAGES: dict[str, tuple[str, str]] = {
    "first-backup": ("first-backup.md", "Your first backup"),
    "concept": ("concept.md", "Concept"),
    "install": ("install.md", "Installation"),
    "configuration": ("configuration.md", "Configuration"),
    "setup": ("setup.md", "Setup wizard"),
    "pairing": ("pairing.md", "Pairing a device"),
    "restore": ("restore.md", "Restoring a backup"),
    "notifications": ("notifications.md", "Notifications"),
    "troubleshooting": ("troubleshooting.md", "Troubleshooting"),
    "api": ("api.md", "Status API"),
}

# Matches a Markdown link target that is a bare relative .md filename (optionally with a
# "#anchor"), the only link shape actually used between files in docs/ today (checked: every
# cross-link in docs/*.md is "(name.md)" or "(name.md#anchor)", never "(docs/name.md)" or an
# absolute URL). Deliberately narrow: anything else (http(s) URLs, mailto:, plain "#anchor",
# a path with a "/") is left exactly as written.
_MD_LINK_RE = re.compile(r'href="([a-zA-Z0-9_-]+)\.md(#[^"]*)?"')

_SLUG_BY_FILENAME = {filename: slug for slug, (filename, _title) in PAGES.items()}

# An opening tag, closing tag, or self-closing tag - "<script>", "</script>", "<br/>", "<a href=...>"
# - but not a lone "<" or ">" such as Markdown's blockquote marker or a stray comparison symbol.
_HTML_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>")

# Matches the "tables" extension's exact output: an opening "<table>" with no attributes (Python-
# Markdown never adds any) up to the matching "</table>", non-greedy so two tables on one page are
# wrapped separately rather than as one span. docs/*.md tables are never nested inside another
# table, so a non-greedy match is sufficient without a real HTML parser.
_TABLE_RE = re.compile(r"<table>.*?</table>", re.DOTALL)


@dataclass(frozen=True)
class DocPage:
    slug: str
    title: str
    html: str


def default_docs_dir() -> Path:
    """docs/ next to the installed package. In the image this is `/app/docs` (see Dockerfile,
    which copies docs/ there and sets BIOSEASY_DOCS_DIR); in a `uv sync` dev checkout the project
    is installed editable, so `bioseasy/__file__` still lives under `src/bioseasy/` inside the
    repository and this resolves to the real `docs/` at the repository root."""
    return Path(__file__).resolve().parents[2] / "docs"


def _rewrite_links(rendered: str) -> str:
    def replace(m: re.Match[str]) -> str:
        filename = f"{m.group(1)}.md"
        anchor = m.group(2) or ""
        slug = _SLUG_BY_FILENAME.get(filename)
        if slug is None:
            # Points at a real docs/ file that is not published through the web UI; leave the
            # link text as plain, inert text rather than a 404 link.
            return f'href="#{anchor.lstrip("#") or filename}"'
        return f'href="/guide/{slug}{anchor}"'

    return _MD_LINK_RE.sub(replace, rendered)


def _wrap_tables(rendered: str) -> str:
    """Give every rendered table its own horizontal-scroll container (docs/design.md: only
    tables, diagrams and code blocks may exceed the page width, each inside its own scrolling
    container - the page body must never scroll sideways). docs/*.md leans on wide tables
    (environment variables, routes, platforms) that do not fit a phone-width viewport."""
    return _TABLE_RE.sub(lambda m: f'<div class="table-scroll">{m.group(0)}</div>', rendered)


def _escape_tags(source: str) -> str:
    return _HTML_TAG_RE.sub(lambda m: html.escape(m.group(0), quote=False), source)


def render(docs_dir: Path, slug: str) -> DocPage | None:
    """The rendered page for `slug`, or None if it is not in the allowlist or the file is
    missing (a stale entry in PAGES pointing at a file docs/ no longer has)."""
    entry = PAGES.get(slug)
    if entry is None:
        return None
    filename, title = entry
    path = docs_dir / filename
    if not _within(docs_dir, path) or not path.is_file():
        return None
    source = path.read_text(encoding="utf-8")
    escaped = _escape_tags(source)
    converter = _markdown.Markdown(extensions=["fenced_code", "tables", "toc"], output_format="html")
    body = converter.convert(escaped)
    # Marked safe here, not with "| safe" in the template: semgrep ignores suppressions inside
    # Jinja comments, and this is the one place that knows why it is safe (allowlisted files
    # shipped in the image, raw HTML tags escaped above, no user input).
    safe_html = Markup(_wrap_tables(_rewrite_links(body)))  # noqa: S704  nosemgrep: explicit-unescape-with-markup
    return DocPage(slug=slug, title=title, html=safe_html)


def _within(root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


# What each page answers, in the reader's words rather than the file's. A title alone ("Concept",
# "Setup wizard") tells someone who already knows the product which page they want; it tells a new
# operator nothing, which is what a flat list of links used to do.
DESCRIPTIONS: dict[str, str] = {
    "first-backup": "The whole path in five steps, from an empty server to a finished backup.",
    "concept": "What bioseasy backs up, what it cannot, and why every backup needs the device passcode.",
    "troubleshooting": (
        "A device that does not appear, a failed or unconfirmed run, storage problems - and how to collect a report."
    ),
    "install": (
        "Run the stack with Docker, point it at storage, put it behind HTTPS - "
        "and what to check when something does not work."
    ),
    "configuration": "Every environment variable the container reads, with its default and what it changes.",
    "pairing": "Let a device trust this server. Needed once per device, and it needs a computer with a cable.",
    "setup": "Turn on Wi-Fi backups and encryption for a device you have paired.",
    "restore": "Download one file out of a backup, or put a whole device back with Finder or iMazing.",
    "notifications": "Be told when a backup fails: email, Telegram, Home Assistant, or a browser notification.",
    "api": "Read device status or start a backup from a script, a cron job or an iOS Shortcut.",
}

# Three groups, in the order a reader meets them, each answering a different question: what is
# this and how do I get it running, how do I use it, how do I automate it. The grouping is here
# rather than in the template so that a page added to PAGES without a home fails a test instead of
# quietly disappearing from the index.
SECTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Start here",
        "Begin with the five-step path; the rest is detail for when a step does not go as described.",
        ("first-backup", "concept", "install", "configuration", "pairing", "setup"),
    ),
    ("Everyday use", "The two things you will come back for.", ("restore", "notifications")),
    ("When something does not work", "Symptoms first, not subsystems.", ("troubleshooting",)),
    ("Automation", "For scripts and Shortcuts.", ("api",)),
)


def nav() -> list[tuple[str, str]]:
    """(slug, title) pairs in nav order, for the docs index and the sidebar."""
    return [(slug, title) for slug, (_filename, title) in PAGES.items()]


def sections() -> list[dict]:
    """The docs index, grouped, with a sentence per page.

    Every slug in `SECTIONS` must exist in `PAGES`, and every page in `PAGES` must appear in
    exactly one section - `tests/test_docs.py` checks both, so adding a page without placing it
    is a failing test rather than a page nobody can find.
    """
    return [
        {
            "label": label,
            "intro": intro,
            "pages": [
                {"slug": slug, "title": PAGES[slug][1], "description": DESCRIPTIONS.get(slug, "")} for slug in slugs
            ],
        }
        for label, intro, slugs in SECTIONS
    ]
